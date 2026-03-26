"""
pulse/collector.py — Aegis-Pulse Collection Layer.

Scrapes The DFIR Report RSS feed, extracts the full article text, validates
each item with a Pydantic model, and persists new rows to the raw_intel table.

Usage:
    python -m pulse.collector          # run from project root
    # or import and call:
    from pulse.collector import run_collection
    count = run_collection()
"""

import logging
import time as _time
from datetime import datetime, timezone
from typing import Optional

import feedparser
import requests
from bs4 import BeautifulSoup
from pydantic import BaseModel, HttpUrl, field_validator

from common.db import get_connection

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("aegis.pulse")

# ── Constants ─────────────────────────────────────────────────────────────────
FEED_URL = "https://thedfirreport.com/feed/"
REQUEST_TIMEOUT = 20  # seconds per article fetch
REQUEST_HEADERS = {
    "User-Agent": (
        "AegisLink/1.0 (Threat Intelligence Collector; "
        "https://github.com/nddmars/aegis-link)"
    )
}

# BeautifulSoup CSS selectors tried in priority order to find the article body.
_BODY_SELECTORS = [
    "article",
    "div.entry-content",
    "div.post-content",
    "div.article-content",
    "main",
    "body",
]


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
        Accept either a ``time.struct_time`` (returned by feedparser) or any
        value that ``datetime`` can already handle.
        """
        if isinstance(value, _time.struct_time):
            return datetime(*value[:6], tzinfo=timezone.utc)
        if isinstance(value, str):
            # Attempt common ISO-8601 and RFC-2822 formats.
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
        logger.warning("Failed to fetch article %s: %s", url, exc)
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
                logger.debug("Article body found via selector %r for %s", selector, url)
                return text

    logger.warning("Could not extract meaningful text from %s", url)
    return None


# ── Database persistence ──────────────────────────────────────────────────────

def _save_item(item: RawIntelItem) -> bool:
    """
    Insert a validated RawIntelItem into raw_intel.

    Uses INSERT OR IGNORE so re-runs are fully idempotent (duplicate source_url
    is silently skipped). Returns True if a new row was created, False if the
    URL already existed.
    """
    sql = """
        INSERT OR IGNORE INTO raw_intel (source_url, title, pub_date, raw_text)
        VALUES (?, ?, ?, ?)
    """
    with get_connection() as conn:
        cursor = conn.execute(
            sql,
            (
                str(item.source_url),
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
    logger.info("Aegis-Pulse: starting collection from %s", FEED_URL)

    feed = feedparser.parse(FEED_URL)
    if feed.bozo and not feed.entries:
        logger.error("Feed parse error: %s", feed.bozo_exception)
        return 0

    logger.info("Feed contains %d entries", len(feed.entries))

    inserted = 0
    for entry in feed.entries:
        url: str = getattr(entry, "link", "")
        title: str = getattr(entry, "title", "").strip()
        pub_date = getattr(entry, "published_parsed", None)

        if not url or not title:
            logger.warning("Skipping entry with missing url or title: %r", entry)
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
        except Exception as exc:  # pydantic ValidationError or date parse error
            logger.warning("Validation failed for %s: %s", url, exc)
            continue

        if _save_item(item):
            inserted += 1
            logger.info("Saved new article: %r", title)
        else:
            logger.debug("Already exists, skipping: %r", title)

    logger.info("Aegis-Pulse: collection complete — %d new articles saved", inserted)
    return inserted


if __name__ == "__main__":
    count = run_collection()
    print(f"Collection complete: {count} new article(s) saved.")
