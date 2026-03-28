"""
vulnops/db.py — aegis-vulnops database schema extension.

Bootstraps four new tables into the shared SQLite database:
  vuln_findings      — one row per vulnerability finding (idempotent by finding_id)
  vuln_tracking_ids  — multiple external ticket IDs per finding
  vuln_actions       — immutable audit log of every agent action
  vuln_tickets       — created Jira/ServiceNow tickets with their external IDs

Usage:
    from vulnops.db import bootstrap_vuln_schema
    bootstrap_vuln_schema()   # called automatically on import
"""

import sys
from pathlib import Path

# Allow running from project root without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.db import get_connection  # noqa: E402
from common.logger import get_logger  # noqa: E402

logger = get_logger("aegis.vulnops.db")

# ── DDL ───────────────────────────────────────────────────────────────────────

_FINDINGS_DDL = """
CREATE TABLE IF NOT EXISTS vuln_findings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Canonical dedup key: DefectDojo finding_id or Excel row hash.
    finding_id        INTEGER NOT NULL UNIQUE,
    title             TEXT    NOT NULL,
    severity          TEXT    NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    scanner_type      TEXT    NOT NULL DEFAULT '',
    component_name    TEXT    NOT NULL DEFAULT '',
    component_version TEXT    NOT NULL DEFAULT '',
    target_host       TEXT    NOT NULL DEFAULT '',
    repo_url          TEXT    NOT NULL DEFAULT '',
    due_date          TEXT,
    status            TEXT    NOT NULL DEFAULT 'Open',
    source            TEXT    NOT NULL DEFAULT 'defectdojo',
    raw_json          TEXT,
    fetched_at        TEXT    NOT NULL,
    updated_at        TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vuln_findings_finding_id
    ON vuln_findings (finding_id);

CREATE INDEX IF NOT EXISTS idx_vuln_findings_severity
    ON vuln_findings (severity);

CREATE INDEX IF NOT EXISTS idx_vuln_findings_due_date
    ON vuln_findings (due_date);
"""

_TRACKING_IDS_DDL = """
CREATE TABLE IF NOT EXISTS vuln_tracking_ids (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES vuln_findings(finding_id),
    system     TEXT    NOT NULL,   -- 'jira', 'servicenow', 'checkmarx', 'ba'
    ticket_id  TEXT    NOT NULL,
    UNIQUE (finding_id, system)
);

CREATE INDEX IF NOT EXISTS idx_vuln_tracking_finding_id
    ON vuln_tracking_ids (finding_id);
"""

_ACTIONS_DDL = """
CREATE TABLE IF NOT EXISTS vuln_actions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,   -- Not a FK so orphan records are preserved
    action     TEXT    NOT NULL,   -- e.g. 'verify_ssh', 'remediate_ai', 'ticket_created'
    result     TEXT    NOT NULL,   -- 'success', 'failure', 'skipped'
    detail     TEXT,               -- Free-form JSON or text
    created_at TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vuln_actions_finding_id
    ON vuln_actions (finding_id);

CREATE INDEX IF NOT EXISTS idx_vuln_actions_action
    ON vuln_actions (action);
"""

_TICKETS_DDL = """
CREATE TABLE IF NOT EXISTS vuln_tickets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL,
    ticket_type TEXT    NOT NULL,   -- 'jira_security', 'jira_dev', 'change_request'
    external_id TEXT,               -- Jira issue key or ServiceNow CR number
    payload     TEXT,               -- Full rendered ticket body (JSON)
    created_at  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vuln_tickets_finding_id
    ON vuln_tickets (finding_id);
"""


# ── Public API ────────────────────────────────────────────────────────────────

def bootstrap_vuln_schema() -> None:
    """
    Create all vulnops tables and indexes if they do not exist.

    Safe to call multiple times (all statements use IF NOT EXISTS).
    """
    with get_connection() as conn:
        conn.executescript(_FINDINGS_DDL)
        conn.executescript(_TRACKING_IDS_DDL)
        conn.executescript(_ACTIONS_DDL)
        conn.executescript(_TICKETS_DDL)
        conn.commit()

    logger.info(
        "VulnOps schema bootstrapped",
        extra={"action": "schema_bootstrap", "tables": ["vuln_findings", "vuln_tracking_ids", "vuln_actions", "vuln_tickets"]},
    )


# ── Auto-bootstrap on import ──────────────────────────────────────────────────
bootstrap_vuln_schema()
