"""
bridge/server.py — Aegis-Bridge MCP Server.

Exposes three MCP tools for threat intelligence investigation:

  fetch_threat_leads       — Query enriched STIX 2.1 intelligence by keyword
                             or MITRE technique. Read-only; safe to call freely.

  draft_threat_analysis    — Generate a draft YARA detection rule and structured
                             TTP mapping for a given article, then save it to the
                             draft_analysis staging table with status
                             'pending_review'. The investigator reviews the draft
                             in their LLM context before it becomes operational.

  confirm_threat_analysis  — Approve or reject a pending draft. On approval the
                             artifact is committed; on rejection it is archived
                             with the investigator's notes. This closes the
                             human-in-the-loop feedback cycle.

Human-in-the-loop flow
──────────────────────
  1. Investigator calls ``fetch_threat_leads`` to surface relevant articles.
  2. Investigator calls ``draft_threat_analysis(raw_intel_id=<N>)`` — the LLM
     presents the draft YARA rule and TTP mapping for review.
  3. Investigator decides and calls ``confirm_threat_analysis(draft_id=<M>,
     decision="approved"|"rejected", reviewer_notes="…")``.
  4. The decision is persisted with a full audit trail (who, when, notes).

Architecture
────────────
- All SQL parameters are bound parameters (never interpolated).
- Fresh short-lived connections per call; timeout=10 for interactive use.
- Falls back from staged_leads view to raw_intel if DBT has not run yet.
- Structured JSON logs via common.logger create a searchable audit trail.
"""

import asyncio
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

import anthropic
from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

from common.db import get_connection
from common.logger import get_logger

load_dotenv()
logger = get_logger("aegis.bridge")

# ── MCP server instance ───────────────────────────────────────────────────────
server = Server("aegis-bridge")

# ── Claude model for draft generation ────────────────────────────────────────
_DRAFT_MODEL = "claude-opus-4-6"
_DRAFT_MAX_TOKENS = 2048

# ── Tool: fetch_threat_leads ──────────────────────────────────────────────────
_FETCH_DESCRIPTION = (
    "Query the Aegis threat intelligence database. "
    "Returns structured STIX 2.1 JSON bundles enriched from The DFIR Report and other sources. "
    "Filter by freetext keyword, MITRE ATT&CK technique ID (e.g. 'T1059'), "
    "and/or urgency level (HIGH = Ransomware/Exploit reports)."
)

_FETCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "keyword": {
            "type": "string",
            "description": (
                "Freetext keyword to search in the article title or STIX JSON. "
                "Examples: 'Cobalt Strike', 'LockBit', 'lateral movement'."
            ),
        },
        "mitre_technique": {
            "type": "string",
            "description": (
                "MITRE ATT&CK technique ID to filter by. Substring-based, "
                "so 'T1059' also matches 'T1059.001'. Examples: 'T1059', 'T1486'."
            ),
        },
        "urgency": {
            "type": "string",
            "enum": ["HIGH", "NORMAL", "ALL"],
            "description": (
                "Urgency level set by Aegis-Analytics. "
                "HIGH = report title or STIX content contains 'Ransomware' or 'Exploit'. "
                "Defaults to 'ALL' when omitted."
            ),
        },
        "limit": {
            "type": "integer",
            "description": "Maximum number of results to return. Default 10, maximum 50.",
            "minimum": 1,
            "maximum": 50,
        },
    },
    "additionalProperties": False,
}

# ── Tool: draft_threat_analysis ───────────────────────────────────────────────
_DRAFT_DESCRIPTION = (
    "Generate a DRAFT YARA detection rule and MITRE TTP mapping for a specific "
    "threat intelligence article. The draft is saved to a staging table with "
    "status 'pending_review' and returned for investigator review. "
    "Call confirm_threat_analysis to approve or reject the draft."
)

_DRAFT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["raw_intel_id"],
    "properties": {
        "raw_intel_id": {
            "type": "integer",
            "description": (
                "ID of the raw_intel row to analyse. Use fetch_threat_leads to "
                "find relevant article IDs first."
            ),
        },
    },
    "additionalProperties": False,
}

# ── Tool: confirm_threat_analysis ─────────────────────────────────────────────
_CONFIRM_DESCRIPTION = (
    "Approve or reject a pending YARA/TTP draft produced by draft_threat_analysis. "
    "Approved drafts are committed as operational intelligence. "
    "Rejected drafts are archived with the investigator's notes. "
    "Both decisions are written to the audit log."
)

_CONFIRM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["draft_id", "decision"],
    "properties": {
        "draft_id": {
            "type": "integer",
            "description": "ID returned by a previous call to draft_threat_analysis.",
        },
        "decision": {
            "type": "string",
            "enum": ["approved", "rejected"],
            "description": "'approved' commits the draft as operational; 'rejected' archives it.",
        },
        "reviewer_notes": {
            "type": "string",
            "description": (
                "Optional investigator notes explaining the decision. "
                "Especially useful on rejection to document why the draft was inadequate."
            ),
        },
    },
    "additionalProperties": False,
}


# ── Shared DB helpers ─────────────────────────────────────────────────────────

def _view_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type IN ('view','table') AND name = ?",
        (name,),
    ).fetchone()
    return row is not None


def _open_conn() -> sqlite3.Connection:
    """Open a short-lived read/write connection; raise RuntimeError on lock."""
    try:
        return get_connection(timeout=10)
    except sqlite3.OperationalError as exc:
        raise RuntimeError(f"Database unavailable: {exc}") from exc


# ── fetch_threat_leads implementation ────────────────────────────────────────

def _build_fetch_query(
    keyword: str,
    technique: str,
    urgency: str,
    limit: int,
    use_view: bool,
) -> tuple[str, list]:
    if use_view:
        table = "staged_leads"
        cols = "id, title, pub_date, source_url, stix_json, urgency_flag"
        where = []
    else:
        table = "raw_intel"
        cols = "id, title, pub_date, source_url, stix_json, 'N/A' AS urgency_flag"
        where = ["is_processed = 1", "stix_json IS NOT NULL"]

    params: list = []

    if keyword:
        where.append("(title LIKE ? OR stix_json LIKE ?)")
        params += [f"%{keyword}%", f"%{keyword}%"]
    if technique:
        where.append("stix_json LIKE ?")
        params.append(f"%{technique}%")
    if urgency == "HIGH" and use_view:
        where.append("urgency_flag = 'HIGH_URGENCY'")
    elif urgency == "NORMAL" and use_view:
        where.append("urgency_flag = 'NORMAL'")

    where_clause = (" WHERE " + " AND ".join(where)) if where else ""
    sql = f"SELECT {cols} FROM {table}{where_clause} ORDER BY pub_date DESC LIMIT ?"
    params.append(limit)
    return sql, params


def _run_fetch(keyword: str, technique: str, urgency: str, limit: int) -> list[dict]:
    conn = _open_conn()
    try:
        use_view = _view_exists(conn, "staged_leads")
        if not use_view:
            logger.warning(
                "staged_leads view absent — using raw_intel fallback",
                extra={"action": "view_fallback"},
            )
        sql, params = _build_fetch_query(keyword, technique, urgency, limit, use_view)
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError as exc:
        if "locked" in str(exc).lower():
            raise RuntimeError(
                "Database is locked by another process. Retry in a few seconds."
            ) from exc
        raise
    finally:
        conn.close()


# ── draft_threat_analysis implementation ─────────────────────────────────────

_DRAFT_SYSTEM_PROMPT = """You are a senior threat detection engineer and CTI analyst. Given a STIX 2.1 intelligence bundle from a threat report, produce two artefacts:

1. A YARA detection rule that:
   - Is named with the prefix "AegisLink_" followed by a descriptive threat name
   - Has a metadata block with: description, author = "Aegis-Brain", date (today), reference (source URL if present), mitre_attack (comma-separated technique IDs)
   - Defines $string variables for malware family names, C2 paths, unique registry keys, mutex names, or other artefacts found in the STIX bundle
   - Uses file hashes (MD5, SHA-256) in the condition when available
   - Has a clear, correct condition block

2. A TTP mapping as a JSON array where each element has:
   - "technique_id": MITRE ATT&CK ID (e.g. "T1059")
   - "technique_name": Full technique name
   - "description": One sentence describing how this technique was observed in the report

Return ONLY a JSON object with exactly two keys:
  "yara_rule"  — the complete YARA rule as a string (including all line breaks)
  "ttp_mapping" — the JSON array described above

No markdown fences, no preamble, no commentary. Start with '{' and end with '}'."""


def _call_claude_draft(title: str, stix_json: str, source_url: str) -> dict:
    """
    Ask Claude to generate a YARA rule and TTP mapping from a STIX bundle.

    Returns a dict with keys 'yara_rule' (str) and 'ttp_mapping' (list).
    Raises ValueError on malformed response.
    """
    client = anthropic.Anthropic()

    user_msg = (
        f"Article Title: {title}\n"
        f"Source URL: {source_url}\n\n"
        f"STIX 2.1 Bundle:\n{stix_json}"
    )

    response = client.messages.create(
        model=_DRAFT_MODEL,
        max_tokens=_DRAFT_MAX_TOKENS,
        system=_DRAFT_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_msg}],
    )

    raw = response.content[0].text
    data = json.loads(raw)

    if "yara_rule" not in data or "ttp_mapping" not in data:
        raise ValueError(
            f"Draft response missing required keys. Got: {list(data.keys())}"
        )
    if not isinstance(data["ttp_mapping"], list):
        raise ValueError("ttp_mapping must be a JSON array")

    return data


def _save_draft(raw_intel_id: int, yara_rule: str, ttp_mapping: list) -> int:
    """Insert a new pending draft and return its id."""
    conn = _open_conn()
    try:
        cursor = conn.execute(
            """
            INSERT INTO draft_analysis
                (raw_intel_id, draft_yara, draft_ttp_map, status, created_at)
            VALUES (?, ?, ?, 'pending_review', ?)
            """,
            (
                raw_intel_id,
                yara_rule,
                json.dumps(ttp_mapping, ensure_ascii=False),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


# ── confirm_threat_analysis implementation ───────────────────────────────────

def _apply_decision(draft_id: int, decision: str, notes: str) -> dict:
    """
    Persist an investigator decision on a pending draft.

    Returns a summary dict for the audit log / MCP response.
    Raises RuntimeError if the draft is not found or already decided.
    """
    conn = _open_conn()
    try:
        row = conn.execute(
            "SELECT id, raw_intel_id, status FROM draft_analysis WHERE id = ?",
            (draft_id,),
        ).fetchone()

        if row is None:
            raise RuntimeError(f"Draft id={draft_id} not found.")
        if row["status"] != "pending_review":
            raise RuntimeError(
                f"Draft id={draft_id} is already '{row['status']}' "
                "and cannot be re-decided."
            )

        conn.execute(
            """
            UPDATE draft_analysis
            SET    status         = ?,
                   reviewer_notes = ?,
                   reviewed_at    = ?
            WHERE  id = ?
            """,
            (decision, notes or None, datetime.now(timezone.utc).isoformat(), draft_id),
        )
        conn.commit()

        return {
            "draft_id": draft_id,
            "raw_intel_id": row["raw_intel_id"],
            "decision": decision,
            "reviewer_notes": notes or "",
            "reviewed_at": datetime.now(timezone.utc).isoformat(),
        }
    finally:
        conn.close()


# ── MCP handlers ──────────────────────────────────────────────────────────────

@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="fetch_threat_leads",
            description=_FETCH_DESCRIPTION,
            inputSchema=_FETCH_SCHEMA,
        ),
        types.Tool(
            name="draft_threat_analysis",
            description=_DRAFT_DESCRIPTION,
            inputSchema=_DRAFT_SCHEMA,
        ),
        types.Tool(
            name="confirm_threat_analysis",
            description=_CONFIRM_DESCRIPTION,
            inputSchema=_CONFIRM_SCHEMA,
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if name == "fetch_threat_leads":
        return await _handle_fetch(arguments)
    if name == "draft_threat_analysis":
        return await _handle_draft(arguments)
    if name == "confirm_threat_analysis":
        return await _handle_confirm(arguments)

    return [
        types.TextContent(
            type="text",
            text=(
                f"Unknown tool: {name!r}. "
                "Available: fetch_threat_leads, draft_threat_analysis, confirm_threat_analysis"
            ),
        )
    ]


# ── fetch_threat_leads handler ────────────────────────────────────────────────

async def _handle_fetch(arguments: dict) -> list[types.TextContent]:
    keyword: str = str(arguments.get("keyword", "")).strip()
    technique: str = str(arguments.get("mitre_technique", "")).strip()
    urgency: str = str(arguments.get("urgency", "ALL")).upper()
    if urgency not in {"HIGH", "NORMAL", "ALL"}:
        urgency = "ALL"
    limit: int = min(int(arguments.get("limit", 10)), 50)

    logger.info(
        "Tool invoked",
        extra={
            "action": "tool_called",
            "tool": "fetch_threat_leads",
            "keyword": keyword,
            "technique": technique,
            "urgency": urgency,
            "limit": limit,
        },
    )

    try:
        rows = _run_fetch(keyword, technique, urgency, limit)
    except RuntimeError as exc:
        return [types.TextContent(type="text", text=str(exc))]

    if not rows:
        filters = []
        if keyword:
            filters.append(f"keyword={keyword!r}")
        if technique:
            filters.append(f"mitre_technique={technique!r}")
        if urgency != "ALL":
            filters.append(f"urgency={urgency!r}")
        return [
            types.TextContent(
                type="text",
                text=(
                    f"No threat leads found ({', '.join(filters) or 'no filters'}). "
                    "Try broader search terms or run Aegis-Pulse and Aegis-Brain first."
                ),
            )
        ]

    output = []
    for row in rows:
        entry: dict = {
            "id": row["id"],
            "title": row["title"],
            "pub_date": row["pub_date"],
            "source_url": row["source_url"],
            "urgency_flag": row.get("urgency_flag", "N/A"),
        }
        try:
            entry["stix_bundle"] = json.loads(row["stix_json"])
        except (TypeError, json.JSONDecodeError):
            entry["stix_bundle"] = None
        output.append(entry)

    logger.info(
        "Threat leads returned",
        extra={"action": "fetch_result", "result_count": len(output)},
    )

    return [
        types.TextContent(
            type="text",
            text=json.dumps(output, indent=2, ensure_ascii=False),
        )
    ]


# ── draft_threat_analysis handler ────────────────────────────────────────────

async def _handle_draft(arguments: dict) -> list[types.TextContent]:
    raw_intel_id: int = int(arguments["raw_intel_id"])

    logger.info(
        "Tool invoked",
        extra={
            "action": "tool_called",
            "tool": "draft_threat_analysis",
            "raw_intel_id": raw_intel_id,
        },
    )

    # ── Fetch the source article ──────────────────────────────────────────
    conn = _open_conn()
    try:
        row = conn.execute(
            "SELECT id, title, stix_json, source_url FROM raw_intel WHERE id = ?",
            (raw_intel_id,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return [
            types.TextContent(
                type="text",
                text=f"Article id={raw_intel_id} not found in raw_intel.",
            )
        ]

    if not row["stix_json"]:
        return [
            types.TextContent(
                type="text",
                text=(
                    f"Article id={raw_intel_id} has not been enriched yet. "
                    "Run Aegis-Brain first to generate its STIX bundle."
                ),
            )
        ]

    # ── Generate draft via Claude ─────────────────────────────────────────
    try:
        draft_data = _call_claude_draft(
            title=row["title"],
            stix_json=row["stix_json"],
            source_url=row["source_url"],
        )
    except (json.JSONDecodeError, ValueError) as exc:
        logger.error(
            "Draft generation failed",
            extra={"action": "draft_error", "raw_intel_id": raw_intel_id, "error": str(exc)},
        )
        return [
            types.TextContent(
                type="text",
                text=f"Draft generation failed: {exc}. Please retry.",
            )
        ]
    except anthropic.APIError as api_exc:
        return [
            types.TextContent(
                type="text",
                text=f"Claude API error during draft generation: {api_exc}",
            )
        ]

    # ── Persist draft with status = pending_review ────────────────────────
    draft_id = _save_draft(
        raw_intel_id=raw_intel_id,
        yara_rule=draft_data["yara_rule"],
        ttp_mapping=draft_data["ttp_mapping"],
    )

    logger.info(
        "Draft created — awaiting investigator review",
        extra={
            "action": "draft_created",
            "draft_id": draft_id,
            "raw_intel_id": raw_intel_id,
            "status": "pending_review",
        },
    )

    # ── Return draft for human review ─────────────────────────────────────
    response = {
        "status": "DRAFT — PENDING INVESTIGATOR REVIEW",
        "draft_id": draft_id,
        "raw_intel_id": raw_intel_id,
        "article_title": row["title"],
        "next_step": (
            "Review the draft_yara and ttp_mapping below. "
            "Then call confirm_threat_analysis with draft_id, "
            "decision ('approved' or 'rejected'), and optional reviewer_notes."
        ),
        "draft_yara": draft_data["yara_rule"],
        "ttp_mapping": draft_data["ttp_mapping"],
    }

    return [
        types.TextContent(
            type="text",
            text=json.dumps(response, indent=2, ensure_ascii=False),
        )
    ]


# ── confirm_threat_analysis handler ──────────────────────────────────────────

async def _handle_confirm(arguments: dict) -> list[types.TextContent]:
    draft_id: int = int(arguments["draft_id"])
    decision: str = str(arguments["decision"]).lower()
    reviewer_notes: str = str(arguments.get("reviewer_notes", "")).strip()

    if decision not in {"approved", "rejected"}:
        return [
            types.TextContent(
                type="text",
                text="decision must be 'approved' or 'rejected'.",
            )
        ]

    logger.info(
        "Tool invoked",
        extra={
            "action": "tool_called",
            "tool": "confirm_threat_analysis",
            "draft_id": draft_id,
            "decision": decision,
        },
    )

    try:
        summary = _apply_decision(draft_id, decision, reviewer_notes)
    except RuntimeError as exc:
        return [types.TextContent(type="text", text=str(exc))]

    logger.info(
        "Investigator decision recorded",
        extra={
            "action": "draft_confirmed",
            "draft_id": draft_id,
            "decision": decision,
            "raw_intel_id": summary["raw_intel_id"],
            "reviewer_notes": reviewer_notes or None,
        },
    )

    verb = "approved and committed" if decision == "approved" else "rejected and archived"
    response = {
        "status": f"Draft {verb} successfully.",
        "audit_trail": summary,
        "tip": (
            "Approved YARA rules are queryable with: "
            "SELECT id, draft_yara FROM draft_analysis WHERE status = 'approved'"
        ) if decision == "approved" else (
            "Rejected drafts are archived and can be reviewed with: "
            "SELECT id, reviewer_notes FROM draft_analysis WHERE status = 'rejected'"
        ),
    }

    return [
        types.TextContent(
            type="text",
            text=json.dumps(response, indent=2, ensure_ascii=False),
        )
    ]


# ── Server startup ────────────────────────────────────────────────────────────

async def main() -> None:
    logger.info(
        "Aegis-Bridge MCP server starting",
        extra={"action": "server_start", "transport": "stdio"},
    )
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
