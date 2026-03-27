"""
pulse/collector.py — Aegis-Pulse Collection Layer.

Scrapes The DFIR Report RSS feed, extracts the full article text, validates
each item with a Pydantic model, and persists new rows to the raw_intel table.

Idempotency
───────────
Each article URL is normalised and SHA-256 hashed before storage. The
``url_hash`` column carries a UNIQUE constraint, so re-running the collector
against an already-seen URL is a silent no-op (INSERT OR IGNORE). This is
the canonical dedup key; ``source_url`` carries its own UNIQUE constraint as
a human-readable fallback.

Structured logging
──────────────────
All log output is emitted as newline-delimited JSON via ``common.logger`` so
the audit trail is grep-able and ingestible by any log aggregator.

Usage:
    python -m pulse.collector          # run from project root
    from pulse.collector import run_collection
    count = run_collection()
"""

import hashlib
import time as _time
from datetime import datetime, timezone
from typing import Optional

import feedparser
import requests
from bs4 import BeautifulSoup
from pydantic import BaseModel, HttpUrl, field_validator

from common.db import get_connection
from common.logger import get_logger

logger = get_logger("aegis.pulse")

# ── Constants ─────────────────────────────────────────────────────────────────
FEED_URL = "https://thedfirreport.com/feed/"
REQUEST_TIMEOUT = 20  # seconds per article fetch
REQUEST_HEADERS = {
    "User-Agent": (
        "AegisLink/1.0 (Threat Intelligence Collector; "
        "https://github.com/nddmars/aegis-link)"
    )
}

# BeautifulSoup CSS selectors tried in priority order to locate the article body.
_BODY_SELECTORS = [
    "article",
    "div.entry-content",
    "div.post-content",
    "div.article-content",
    "main",
    "body",
]


# ── URL normalisation & hashing ───────────────────────────────────────────────

def _hash_url(url: str) -> str:
    """
    Return a deterministic SHA-256 hex digest of the normalised URL.

    Normalisation strips trailing slashes and lowercases the scheme and host
    so that ``http://Example.com/foo/`` and ``http://example.com/foo`` produce
    the same hash. The path and query string are preserved case-sensitively
    because they can be meaningful on some platforms.
    """
    try:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url.strip())
        normalised = urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path.rstrip("/"),
            parsed.params,
            parsed.query,
            "",  # drop fragment
        ))
    except Exception:
        normalised = url.strip()

    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()


# ── Pydantic model ────────────────────────────────────────────────────────────

class RawIntelItem(BaseModel):
    """Validated representation of a single threat-intelligence article."""

    source_url: HttpUrl
    title: str
    pub_date: datetime
    raw_text: str

    @field_validator("pub_date", mode="before")
    @classmethod
    def _parse_date(cls, value):
        """
        Accept a ``time.struct_time`` (returned by feedparser) or an ISO-8601
        string.
        """
        if isinstance(value, _time.struct_time):
            return datetime(*value[:6], tzinfo=timezone.utc)
        if isinstance(value, str):
            for fmt in (
                "%a, %d %b %Y %H:%M:%S %z",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S",
            ):
                try:
                    return datetime.strptime(value, fmt)
                except ValueError:
                    continue
            raise ValueError(f"Cannot parse date string: {value!r}")
        return value

    @field_validator("raw_text")
    @classmethod
    def _text_not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("raw_text must not be empty")
        return value.strip()


# ── Article extraction ────────────────────────────────────────────────────────

def _fetch_article_text(url: str) -> Optional[str]:
    """
    Download the article at *url* and return its cleaned body text.

    Tries a priority chain of CSS selectors to locate the article body. Falls
    back to ``<body>`` if nothing more specific matches. Returns ``None`` on
    any network or parsing error.
    """
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS)
        response.raise_for_status()
    except requests.RequestException as exc:
        logger.warning(
            "Article fetch failed",
            extra={"action": "fetch_error", "url": url, "error": str(exc)},
        )
        return None

    soup = BeautifulSoup(response.text, "lxml")

    # Remove navigation, headers, footers, and script noise before extraction.
    for tag in soup(["nav", "header", "footer", "script", "style", "aside"]):
        tag.decompose()

    for selector in _BODY_SELECTORS:
        element = soup.select_one(selector)
        if element:
            text = element.get_text(separator="\n", strip=True)
            if len(text) > 200:  # skip boilerplate-only matches
                logger.debug(
                    "Article body located",
                    extra={"action": "selector_match", "selector": selector, "url": url},
                )
                return text

    logger.warning(
        "Could not extract meaningful text from article",
        extra={"action": "extraction_failed", "url": url},
    )
    return None


# ── Database persistence ──────────────────────────────────────────────────────

def _save_item(item: RawIntelItem) -> bool:
    """
    Insert a validated RawIntelItem into raw_intel.

    The SHA-256 hash of the normalised URL (``url_hash``) is computed here and
    used as the primary idempotency key. ``INSERT OR IGNORE`` silently skips
    any row whose ``url_hash`` or ``source_url`` already exists in the table.

    Returns:
        True  — a new row was created.
        False — the article already existed; nothing was written.
    """
    url_str = str(item.source_url)
    url_hash = _hash_url(url_str)

    sql = """
        INSERT OR IGNORE INTO raw_intel
            (url_hash, source_url, title, pub_date, raw_text)
        VALUES
            (?, ?, ?, ?, ?)
    """
    with get_connection() as conn:
        cursor = conn.execute(
            sql,
            (
                url_hash,
                url_str,
                item.title,
                item.pub_date.isoformat(),
                item.raw_text,
            ),
        )
        conn.commit()
        return cursor.rowcount == 1


# ── Public entry point ────────────────────────────────────────────────────────

def run_collection() -> int:
    """
    Scrape The DFIR Report RSS feed and persist new articles.

    Returns:
        Number of new rows inserted into raw_intel.
    """
    logger.info(
        "Collection run started",
        extra={"action": "collection_start", "feed_url": FEED_URL},
    )

    feed = feedparser.parse(FEED_URL)
    if feed.bozo and not feed.entries:
        logger.error(
            "RSS feed parse error",
            extra={"action": "feed_error", "error": str(feed.bozo_exception)},
        )
        return 0

    logger.info(
        "Feed parsed successfully",
        extra={"action": "feed_parsed", "entry_count": len(feed.entries)},
    )

    inserted = 0
    for entry in feed.entries:
        url: str = getattr(entry, "link", "")
        title: str = getattr(entry, "title", "").strip()
        pub_date = getattr(entry, "published_parsed", None)

        if not url or not title:
            logger.warning(
                "Skipping entry with missing url or title",
                extra={"action": "entry_skipped", "reason": "missing_fields"},
            )
            continue

        raw_text = _fetch_article_text(url)
        if not raw_text:
            continue

        try:
            item = RawIntelItem(
                source_url=url,
                title=title,
                pub_date=pub_date or _time.gmtime(),
                raw_text=raw_text,
            )
        except Exception as exc:
            logger.warning(
                "Pydantic validation failed for entry",
                extra={"action": "validation_error", "url": url, "error": str(exc)},
            )
            continue

        if _save_item(item):
            inserted += 1
            logger.info(
                "New article saved",
                extra={
                    "action": "article_saved",
                    "url": url,
                    "title": title,
                    "url_hash": _hash_url(str(item.source_url)),
                },
            )
        else:
            logger.debug(
                "Article already exists, skipped",
                extra={"action": "article_duplicate", "url": url},
            )

    logger.info(
        "Collection run complete",
        extra={"action": "collection_complete", "new_articles": inserted},
    )
    return inserted


if __name__ == "__main__":
    count = run_collection()
    print(f"Collection complete: {count} new article(s) saved.")
