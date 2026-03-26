"""
common/db.py — Aegis Link shared SQLite foundation.

Provides a single get_connection() factory and a bootstrap_schema() call that
every other module imports. WAL journal mode is enabled so Aegis-Brain's
write-heavy processing and Aegis-Bridge's concurrent reads do not deadlock.
"""

import os
import sqlite3
import threading
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# ── Database path ─────────────────────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
DB_PATH: str = os.environ.get(
    "AEGIS_DB_PATH",
    str(_PROJECT_ROOT / "aegis_intel.db"),
)

# ── Thread-safety for connection creation ─────────────────────────────────────
_lock = threading.Lock()

# ── DDL ───────────────────────────────────────────────────────────────────────
_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS raw_intel (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source_url    TEXT    NOT NULL UNIQUE,
    title         TEXT    NOT NULL,
    pub_date      TEXT,
    raw_text      TEXT,
    stix_json     TEXT,
    processed_at  TEXT,
    is_processed  INTEGER NOT NULL DEFAULT 0
        CHECK (is_processed IN (-1, 0, 1))
);

CREATE INDEX IF NOT EXISTS idx_raw_intel_is_processed
    ON raw_intel (is_processed);

CREATE INDEX IF NOT EXISTS idx_raw_intel_pub_date
    ON raw_intel (pub_date);
"""


def get_connection(timeout: int = 30) -> sqlite3.Connection:
    """
    Return a new sqlite3.Connection to DB_PATH.

    Each call creates a fresh connection. Callers are responsible for closing
    it (or using it as a context manager). row_factory is set to sqlite3.Row
    so columns are accessible by name.

    Args:
        timeout: Seconds to wait when the database is locked before raising
                 OperationalError. Default 30 suits Brain's long processing
                 windows; Bridge passes timeout=10 for fast interactive use.
    """
    with _lock:
        conn = sqlite3.connect(DB_PATH, timeout=timeout, check_same_thread=False)

    conn.row_factory = sqlite3.Row

    # Enable WAL mode: readers don't block writers and vice-versa.
    conn.execute("PRAGMA journal_mode=WAL;")
    # Enforce foreign-key constraints for future schema additions.
    conn.execute("PRAGMA foreign_keys=ON;")

    return conn


def bootstrap_schema() -> None:
    """
    Create the raw_intel table and its indexes if they do not exist.

    Safe to call multiple times (all statements use IF NOT EXISTS).
    Called automatically when this module is imported, so any module that
    does `from common.db import get_connection` will also ensure the schema
    is present.
    """
    with get_connection() as conn:
        conn.executescript(_SCHEMA_SQL)
        conn.commit()


# ── Auto-bootstrap on import ──────────────────────────────────────────────────
bootstrap_schema()
