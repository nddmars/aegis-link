"""
vulnops/ticketing.py — Jinja2 template engine + Jira/ServiceNow ticket creator.

Routes a confirmed finding to the right team using pre-rendered templates and
submits the ticket to Jira (fully implemented) or ServiceNow (stub interface).

Usage:
    engine = TicketingEngine()
    ticket_id = await engine.route_to_team(finding, proposal, verification)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader, select_autoescape

from common.logger import get_logger
from vulnops.models import Finding, RemediationProposal, TicketPayload, VerificationResult

load_dotenv()

logger = get_logger("aegis.vulnops.ticketing")

_JIRA_URL: Optional[str] = os.environ.get("JIRA_URL", "").rstrip("/") or None
_JIRA_USER: Optional[str] = os.environ.get("JIRA_USER") or None
_JIRA_TOKEN: Optional[str] = os.environ.get("JIRA_TOKEN") or None
_JIRA_PROJECT: str = os.environ.get("JIRA_PROJECT_KEY", "SEC")

_TEMPLATES_DIR = Path(__file__).parent / "templates"


# ── Template Engine ───────────────────────────────────────────────────────────

class TicketingEngine:
    """
    Renders Jinja2 templates and submits tickets to external systems.

    All external calls are optional — if JIRA_URL / JIRA_TOKEN are not
    configured the ticket is rendered and logged locally but not submitted.
    """

    def __init__(self, templates_dir: Optional[Path] = None) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(templates_dir or _TEMPLATES_DIR)),
            autoescape=select_autoescape(enabled_extensions=()),  # plain text
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._jira_enabled = bool(_JIRA_URL and _JIRA_USER and _JIRA_TOKEN)
        self._session = None  # aiohttp.ClientSession, lazy

        if not self._jira_enabled:
            logger.info(
                "Jira not configured — tickets will be rendered but not submitted",
                extra={"action": "ticketing_init_noop"},
            )

    # ── Public API ────────────────────────────────────────────────────────────

    def render_template(
        self,
        template_name: str,
        context: dict,
    ) -> str:
        """Render a named template with the provided context."""
        tmpl = self._env.get_template(template_name)
        return tmpl.render(**context)

    async def route_to_team(
        self,
        finding: Finding,
        proposal: RemediationProposal,
        verification: Optional[VerificationResult] = None,
    ) -> Optional[str]:
        """
        Select the correct template + ticket system based on the target team,
        render the ticket body, submit it, and return the external ticket ID.

        Returns None if submission is skipped or fails.
        """
        team = proposal.target_team if proposal else "security"
        ticket_type, template_name, issue_type = _select_template(team)

        context = {
            "finding": finding,
            "proposal": proposal,
            "verification": verification,
        }

        body = self.render_template(template_name, context)
        summary = _build_summary(finding)
        priority = _severity_to_jira_priority(finding.severity)
        labels = _build_labels(finding, team)

        payload = TicketPayload(
            ticket_type=ticket_type,
            summary=summary,
            description=body,
            priority=priority,
            labels=labels,
        )

        logger.info(
            "Routing finding to team",
            extra={"action": "route_to_team", "finding_id": finding.finding_id,
                   "team": team, "ticket_type": ticket_type},
        )

        if ticket_type == "change_request":
            external_id = await self._submit_change_request(finding, payload)
        else:
            external_id = await self._submit_jira(finding, payload, issue_type)

        if external_id:
            payload.external_id = external_id
            logger.info(
                "Ticket created",
                extra={"action": "ticket_created", "finding_id": finding.finding_id,
                       "ticket_type": ticket_type, "external_id": external_id},
            )

        return external_id

    # ── Jira ──────────────────────────────────────────────────────────────────

    async def _submit_jira(
        self,
        finding: Finding,
        payload: TicketPayload,
        issue_type: str = "Bug",
    ) -> Optional[str]:
        """POST to Jira API and return the created issue key (e.g. 'SEC-123')."""
        if not self._jira_enabled:
            logger.info(
                "Jira disabled — ticket not submitted",
                extra={"action": "jira_skip", "finding_id": finding.finding_id,
                       "summary": payload.summary[:80]},
            )
            return None

        import aiohttp
        import base64

        credentials = base64.b64encode(f"{_JIRA_USER}:{_JIRA_TOKEN}".encode()).decode()
        headers = {
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        body = payload.to_jira_body(_JIRA_PROJECT, issue_type)

        session = await self._get_session()
        url = f"{_JIRA_URL}/rest/api/3/issue"

        async with session.post(url, json=body, headers=headers) as resp:
            resp.raise_for_status()
            data = await resp.json()

        issue_key: str = data.get("key", "")

        # Link related Jira tickets if tracking IDs include a Jira reference
        if issue_key and finding.tracking_ids.jira_id:
            await self._link_jira_issues(issue_key, finding.tracking_ids.jira_id, headers, session)

        return issue_key

    async def _link_jira_issues(
        self,
        source_key: str,
        target_key: str,
        headers: dict,
        session,
    ) -> None:
        """Create a 'relates to' link between two Jira issues."""
        url = f"{_JIRA_URL}/rest/api/3/issueLink"
        body = {
            "type": {"name": "Relates"},
            "inwardIssue": {"key": source_key},
            "outwardIssue": {"key": target_key},
        }
        try:
            async with session.post(url, json=body, headers=headers) as resp:
                resp.raise_for_status()
        except Exception as exc:
            logger.warning(
                "Failed to link Jira issues",
                extra={"action": "jira_link_error", "source": source_key,
                       "target": target_key, "error": str(exc)},
            )

    async def add_jira_comment(
        self,
        issue_key: str,
        comment: str,
    ) -> bool:
        """Add a comment to an existing Jira issue."""
        if not self._jira_enabled or not issue_key:
            return False

        import base64
        credentials = base64.b64encode(f"{_JIRA_USER}:{_JIRA_TOKEN}".encode()).decode()
        headers = {
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/json",
        }
        body = {
            "body": {
                "type": "doc", "version": 1,
                "content": [{"type": "paragraph", "content": [{"type": "text", "text": comment}]}],
            }
        }
        session = await self._get_session()
        url = f"{_JIRA_URL}/rest/api/3/issue/{issue_key}/comment"
        async with session.post(url, json=body, headers=headers) as resp:
            resp.raise_for_status()

        return True

    # ── ServiceNow stub ───────────────────────────────────────────────────────

    async def _submit_change_request(
        self,
        finding: Finding,
        payload: TicketPayload,
    ) -> Optional[str]:
        """
        Submit a ServiceNow Change Request.

        Currently a stub — logs the rendered CR and returns None.
        Full implementation requires SERVICENOW_URL + SERVICENOW_TOKEN env vars
        and a POST to /api/now/table/change_request.
        """
        logger.info(
            "ServiceNow CR rendered (submission stub — configure SERVICENOW_URL to enable)",
            extra={"action": "cr_stub", "finding_id": finding.finding_id,
                   "summary": payload.summary[:80], "chars": len(payload.description)},
        )
        # TODO: implement when ServiceNow credentials are available:
        # POST {SERVICENOW_URL}/api/now/table/change_request
        # body: {"short_description": payload.summary, "description": payload.description, ...}
        return None

    # ── Session ───────────────────────────────────────────────────────────────

    async def _get_session(self):
        if self._session is None:
            import aiohttp
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            )
        return self._session

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _select_template(team: str) -> tuple[str, str, str]:
    """Return (ticket_type, template_name, jira_issue_type) for a given team."""
    if team == "ops":
        return ("change_request", "change_request.j2", "Task")
    if team == "dev":
        return ("jira_dev", "jira_dev.j2", "Task")
    # Default: security team Jira bug
    return ("jira_security", "jira_security.j2", "Bug")


def _build_summary(finding: Finding) -> str:
    prefix = f"[{finding.severity.upper()}]"
    title = finding.title[:100]
    if finding.component_name:
        return f"{prefix} {title} in {finding.component_name} {finding.component_version}".strip()
    return f"{prefix} {title}"


def _severity_to_jira_priority(severity: str) -> str:
    return {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Lowest",
    }.get(severity, "Medium")


def _build_labels(finding: Finding, team: str) -> list[str]:
    labels = ["aegis-vulnops", "security", finding.scanner_type, finding.severity]
    if finding.is_overdue:
        labels.append("overdue")
    labels.append(f"team-{team}")
    return [l.lower().replace(" ", "-") for l in labels if l]
