"""
brain/processor.py — Aegis-Brain AI Enrichment Layer.

Fetches unprocessed rows from raw_intel, sends each article to Claude with a
structured CTI analyst prompt, validates the STIX 2.1 JSON response, and
persists the enriched data back to the database.

Failure handling
────────────────
- On JSON parse failure a single retry is issued with a stricter prompt.
- If the retry also fails the row is marked is_processed = -1 (permanently
  skipped) so the next run does not attempt it again.

Structured logging
──────────────────
Every significant event is emitted as a JSON log line via common.logger so
the enrichment pipeline produces a searchable, audit-quality trail.
Key ``action`` values: enrich_start, enrich_row, stix_success, stix_retry,
stix_failed, api_error, enrich_complete.

Usage:
    python -m brain.processor
    from brain.processor import run_processing
    count = run_processing(batch_size=5)
"""

import json
from datetime import datetime, timezone

import anthropic

from common.db import get_connection
from common.logger import get_logger

logger = get_logger("aegis.brain")

# ── Model configuration ───────────────────────────────────────────────────────
MODEL = "claude-opus-4-6"
MAX_TOKENS = 4096
# Slice raw_text to avoid exceeding context limits. DFIR Report articles are
# typically 3 000–8 000 words; 12 000 characters is generous headroom.
MAX_TEXT_CHARS = 12_000

# ── System prompt ─────────────────────────────────────────────────────────────
_SYSTEM_PROMPT = """You are an expert cyber threat intelligence (CTI) analyst with deep knowledge of STIX 2.1, MITRE ATT&CK, and malware analysis. Given an article text from a threat-intelligence report, you will:

1. Extract ALL Indicators of Compromise (IoCs):
   - IPv4 and IPv6 addresses
   - Domain names and hostnames
   - MD5, SHA-1, and SHA-256 file hashes
   - URLs (if present)

2. Map all observed adversary behaviors to MITRE ATT&CK techniques (e.g., T1059, T1486).

3. Return ONLY a valid STIX 2.1 JSON bundle. The response MUST:
   - Start with '{' and end with '}'
   - Be parseable by json.loads() with no surrounding text, no markdown code fences, no commentary
   - Conform to the STIX 2.1 specification
   - Include a "bundle" object containing a "report", one or more "indicator" objects for each IoC, and one or more "attack-pattern" objects for each MITRE technique
   - Use standard STIX 2.1 pattern strings for indicators:
       IPv4 : [ipv4-addr:value = '<ip>']
       Domain: [domain-name:value = '<domain>']
       MD5   : [file:hashes.MD5 = '<hash>']
       SHA256: [file:hashes.'SHA-256' = '<hash>']

If no IoCs or techniques are identified, return a minimal but valid bundle with only the report object."""

# ── Retry prompt (stricter) ───────────────────────────────────────────────────
_RETRY_SYSTEM_PROMPT = (
    _SYSTEM_PROMPT
    + "\n\nCRITICAL: Your previous response could not be parsed as JSON. "
    "Output the raw JSON object ONLY. Do not include any text before '{' or after '}'."
)


# ── STIX bundle validation ────────────────────────────────────────────────────

def _validate_stix_bundle(raw: str) -> dict:
    """
    Parse and minimally validate a STIX 2.1 bundle JSON string.

    Raises:
        ValueError: if the string is not valid JSON or missing required fields.
        json.JSONDecodeError: if json.loads() fails.
    """
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("STIX response is not a JSON object")
    if data.get("type") != "bundle":
        raise ValueError(f"Expected type='bundle', got {data.get('type')!r}")
    if data.get("spec_version") != "2.1":
        raise ValueError(f"Expected spec_version='2.1', got {data.get('spec_version')!r}")
    if "objects" not in data or not isinstance(data["objects"], list):
        raise ValueError("STIX bundle missing 'objects' array")
    return data


# ── Claude API interaction ────────────────────────────────────────────────────

def _call_claude(title: str, raw_text: str, *, retry: bool = False) -> str:
    """
    Send the article to Claude and return the raw text response.

    Args:
        title:    Article headline.
        raw_text: Article body (sliced to MAX_TEXT_CHARS).
        retry:    If True, uses the stricter retry system prompt.
    """
    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env

    user_message = (
        f"Article Title: {title}\n\n"
        f"Article Text:\n{raw_text[:MAX_TEXT_CHARS]}"
    )

    response = client.messages.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        system=_RETRY_SYSTEM_PROMPT if retry else _SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    return response.content[0].text


# ── Database helpers ──────────────────────────────────────────────────────────

def _fetch_unprocessed(conn, batch_size: int) -> list:
    """Return up to *batch_size* rows awaiting enrichment."""
    return conn.execute(
        """
        SELECT id, title, raw_text
        FROM   raw_intel
        WHERE  is_processed = 0
          AND  raw_text IS NOT NULL
          AND  raw_text != ''
        ORDER  BY pub_date ASC
        LIMIT  ?
        """,
        (batch_size,),
    ).fetchall()


def _mark_success(conn, row_id: int, stix_json: str) -> None:
    conn.execute(
        """
        UPDATE raw_intel
        SET    stix_json    = ?,
               processed_at = ?,
               is_processed = 1
        WHERE  id = ?
        """,
        (stix_json, datetime.now(timezone.utc).isoformat(), row_id),
    )
    conn.commit()


def _mark_failed(conn, row_id: int) -> None:
    conn.execute(
        """
        UPDATE raw_intel
        SET    is_processed = -1,
               processed_at = ?
        WHERE  id = ?
        """,
        (datetime.now(timezone.utc).isoformat(), row_id),
    )
    conn.commit()


# ── Public entry point ────────────────────────────────────────────────────────

def run_processing(batch_size: int = 10) -> int:
    """
    Enrich unprocessed raw_intel rows with STIX 2.1 data from Claude.

    Args:
        batch_size: Maximum number of rows to process per call.

    Returns:
        Number of rows successfully enriched in this run.
    """
    logger.info(
        "Enrichment run started",
        extra={"action": "enrich_start", "batch_size": batch_size, "model": MODEL},
    )

    with get_connection() as conn:
        rows = _fetch_unprocessed(conn, batch_size)

    if not rows:
        logger.info(
            "No unprocessed rows found",
            extra={"action": "enrich_start", "queued": 0},
        )
        return 0

    logger.info(
        "Rows queued for enrichment",
        extra={"action": "enrich_start", "queued": len(rows)},
    )

    processed = 0

    for row in rows:
        row_id: int = row["id"]
        title: str = row["title"]
        raw_text: str = row["raw_text"]

        logger.info(
            "Processing article",
            extra={"action": "enrich_row", "row_id": row_id, "title": title},
        )

        # ── First attempt ────────────────────────────────────────────────────
        try:
            raw_response = _call_claude(title, raw_text, retry=False)
            stix_data = _validate_stix_bundle(raw_response)

        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning(
                "STIX parse failed on first attempt — retrying",
                extra={
                    "action": "stix_retry",
                    "row_id": row_id,
                    "error": str(exc),
                },
            )

            # ── Retry with stricter prompt ────────────────────────────────
            try:
                raw_response = _call_claude(title, raw_text, retry=True)
                stix_data = _validate_stix_bundle(raw_response)

            except (json.JSONDecodeError, ValueError) as retry_exc:
                logger.error(
                    "STIX parse failed on retry — marking as permanently failed",
                    extra={
                        "action": "stix_failed",
                        "row_id": row_id,
                        "error": str(retry_exc),
                    },
                )
                with get_connection() as conn:
                    _mark_failed(conn, row_id)
                continue

        except anthropic.APIError as api_exc:
            logger.error(
                "Claude API error — skipping row",
                extra={"action": "api_error", "row_id": row_id, "error": str(api_exc)},
            )
            continue

        # ── Persist normalised STIX JSON ──────────────────────────────────
        stix_json_str = json.dumps(stix_data, ensure_ascii=False)
        object_count = len(stix_data.get("objects", []))

        with get_connection() as conn:
            _mark_success(conn, row_id, stix_json_str)

        logger.info(
            "Article enriched successfully",
            extra={
                "action": "stix_success",
                "row_id": row_id,
                "title": title,
                "stix_objects": object_count,
            },
        )
        processed += 1

    logger.info(
        "Enrichment run complete",
        extra={
            "action": "enrich_complete",
            "processed": processed,
            "total": len(rows),
            "failed": len(rows) - processed,
        },
    )
    return processed


if __name__ == "__main__":
    count = run_processing()
    print(f"Enrichment complete: {count} row(s) successfully processed.")
