"""
vulnops/models.py — Pydantic data models for aegis-vulnops.

All domain objects are defined here so every module imports from one place.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator


# ── Tracking IDs ──────────────────────────────────────────────────────────────

class TrackingIds(BaseModel):
    """Multiple external ticket references attached to one vulnerability finding."""

    jira_id: Optional[str] = None
    servicenow_id: Optional[str] = None
    checkmarx_id: Optional[str] = None
    ba_ticket_id: Optional[str] = None

    def as_dict(self) -> dict[str, str]:
        """Return only the non-None IDs."""
        return {k: v for k, v in self.model_dump().items() if v is not None}


# ── Finding ───────────────────────────────────────────────────────────────────

SeverityLevel = Literal["critical", "high", "medium", "low", "info"]
SourceType = Literal["defectdojo", "excel"]


class Finding(BaseModel):
    """A single vulnerability finding, normalised from any source."""

    finding_id: int
    title: str
    severity: SeverityLevel
    scanner_type: str = Field(description="e.g. 'qualys', 'prisma', 'checkmarx'")
    component_name: str = ""
    component_version: str = ""
    target_host: str = ""
    repo_url: str = ""
    due_date: Optional[str] = None        # ISO-8601 date string, e.g. "2026-04-01"
    status: str = "Open"
    tracking_ids: TrackingIds = Field(default_factory=TrackingIds)
    raw_json: Optional[str] = None        # Original JSON/row serialised as string
    source: SourceType = "defectdojo"

    @field_validator("severity", mode="before")
    @classmethod
    def normalise_severity(cls, v: str) -> str:
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "moderate": "medium",
            "low": "low",
            "informational": "info",
            "info": "info",
        }
        return mapping.get(str(v).lower(), "info")

    @property
    def is_overdue(self) -> bool:
        if not self.due_date:
            return False
        try:
            return date.fromisoformat(self.due_date) < date.today()
        except ValueError:
            return False

    @property
    def severity_weight(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
            self.severity, 0
        )


# ── Verification ──────────────────────────────────────────────────────────────

class VerificationResult(BaseModel):
    """Outcome of a verifier's check against the target system or repo."""

    confirmed: bool
    evidence: str = ""
    method: str = ""       # "ssh", "git", "manual", "skipped"
    host: str = ""
    timestamp: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )

    def summary(self) -> str:
        status = "CONFIRMED" if self.confirmed else "NOT CONFIRMED"
        return (
            f"[{status}] via {self.method} on {self.host or 'n/a'} "
            f"at {self.timestamp}\nEvidence: {self.evidence[:500]}"
        )


# ── Remediation Proposal ──────────────────────────────────────────────────────

TargetTeam = Literal["dev", "ba", "security", "ops", "unknown"]


class RemediationProposal(BaseModel):
    """AI-generated remediation plan for a confirmed vulnerability."""

    can_fix: bool
    proposed_fix: Optional[str] = None     # Human-readable fix description
    diff: Optional[str] = None             # Unified diff if available
    confidence: float = 0.0                # 0.0–1.0
    target_team: TargetTeam = "security"
    rationale: str = ""

    @field_validator("confidence", mode="before")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        return max(0.0, min(1.0, float(v)))

    def summary(self) -> str:
        if self.can_fix:
            return (
                f"[AUTO-FIX PROPOSED | confidence={self.confidence:.0%}]\n"
                f"{self.proposed_fix or ''}"
                + (f"\n\nDiff:\n```diff\n{self.diff}\n```" if self.diff else "")
            )
        return (
            f"[MANUAL REMEDIATION REQUIRED → team={self.target_team}]\n"
            f"{self.rationale}"
        )


# ── Ticket Payload ────────────────────────────────────────────────────────────

class TicketPayload(BaseModel):
    """Rendered ticket ready for submission to Jira or ServiceNow."""

    ticket_type: str                       # "jira_security", "jira_dev", "change_request"
    summary: str
    description: str
    priority: str = "High"
    labels: list[str] = Field(default_factory=list)
    external_id: Optional[str] = None     # Filled after ticket is created

    def to_jira_body(self, project_key: str, issue_type: str = "Bug") -> dict[str, Any]:
        return {
            "fields": {
                "project": {"key": project_key},
                "summary": self.summary,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": self.description}],
                        }
                    ],
                },
                "issuetype": {"name": issue_type},
                "priority": {"name": self.priority},
                "labels": self.labels,
            }
        }


# ── Excel Column Map ──────────────────────────────────────────────────────────

class ExcelColumnMap(BaseModel):
    """
    Maps spreadsheet column headers to Finding fields.

    Each field holds one or more candidate header names (case-insensitive match).
    The first matching header in the spreadsheet is used.
    """

    title: list[str] = ["Title", "Vulnerability", "Finding", "Name"]
    severity: list[str] = ["Severity", "Risk", "Risk Level", "CVSS Severity"]
    scanner_type: list[str] = ["Scanner", "Source", "Tool", "Scanner Type"]
    component_name: list[str] = ["Component", "Package", "Library", "Asset"]
    component_version: list[str] = ["Version", "Pkg Version", "Component Version"]
    target_host: list[str] = ["Host", "Target", "IP", "Hostname", "Server"]
    repo_url: list[str] = ["Repo", "Repository", "Git URL", "Repo URL"]
    due_date: list[str] = ["Due Date", "SLA Date", "Fix By", "Deadline", "Due"]
    status: list[str] = ["Status", "State", "Finding Status"]
    jira_id: list[str] = ["Jira", "Jira ID", "Jira Ticket", "JIRA"]
    servicenow_id: list[str] = ["ServiceNow", "CR", "Change Request", "Snow"]
    ba_ticket_id: list[str] = ["BA Ticket", "BA", "Business Analyst", "BA ID"]
    checkmarx_id: list[str] = ["Checkmarx", "CX", "Checkmarx ID", "SAST ID"]
    finding_id: list[str] = ["ID", "Finding ID", "Vuln ID", "Issue ID"]

    def resolve(self, available_headers: list[str]) -> dict[str, Optional[str]]:
        """
        Return a map of {field_name: matched_header} for every field.
        Fields with no matching header map to None.
        """
        normalised = {h.strip().lower(): h for h in available_headers}
        result: dict[str, Optional[str]] = {}
        for field_name, candidates in self.model_dump().items():
            matched = next(
                (normalised[c.lower()] for c in candidates if c.lower() in normalised),
                None,
            )
            result[field_name] = matched
        return result
