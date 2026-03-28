"""
vulnops/feedback.py — Post-action feedback loop.

Writes status updates back to:
  1. DefectDojo (via DefectDojoClient.add_note / update_finding_status)
  2. Checkmarx  (HTTP stub — full integration requires CHECKMARX_URL/TOKEN)
  3. SQLite     (vuln_actions audit table — always written)

All DefectDojo calls silently no-op when the client is not configured, so the
agent runs cleanly in Excel-only mode.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv

from common.db import get_connection
from common.logger import get_logger
from vulnops.models import Finding, RemediationProposal, VerificationResult

load_dotenv()

logger = get_logger("aegis.vulnops.feedback")

_CHECKMARX_URL: Optional[str] = os.environ.get("CHECKMARX_URL", "").rstrip("/") or None
_CHECKMARX_TOKEN: Optional[str] = os.environ.get("CHECKMARX_TOKEN") or None


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# ── FeedbackEngine ────────────────────────────────────────────────────────────

class FeedbackEngine:
    """
    Consolidates all outbound feedback calls for a processed finding.

    Pass a DefectDojoClient instance at construction time; it will be a no-op
    client if DefectDojo is not configured.
    """

    def __init__(self, dd_client) -> None:
        self._dd = dd_client
        self._cx_enabled = bool(_CHECKMARX_URL and _CHECKMARX_TOKEN)
        self._cx_session = None

    # ── Verification feedback ─────────────────────────────────────────────────

    async def post_verification_result(
        self,
        finding: Finding,
        verification: VerificationResult,
    ) -> None:
        """Post verification outcome to DefectDojo and audit log."""
        status_word = "CONFIRMED" if verification.confirmed else "NOT CONFIRMED"
        message = (
            f"[aegis-vulnops] Verification {status_word}\n"
            f"Method: {verification.method}\n"
            f"Host/Repo: {verification.host or 'N/A'}\n"
            f"Timestamp: {verification.timestamp}\n\n"
            f"Evidence (truncated to 1000 chars):\n{verification.evidence[:1000]}"
        )

        await self._post_defectdojo(finding.finding_id, message)
        await self._record(
            finding.finding_id,
            action="verify_" + verification.method,
            result="confirmed" if verification.confirmed else "not_confirmed",
            detail=json.dumps({"host": verification.host, "evidence_len": len(verification.evidence)}),
        )

        logger.info(
            "Verification feedback posted",
            extra={"action": "feedback_verify", "finding_id": finding.finding_id,
                   "confirmed": verification.confirmed, "method": verification.method},
        )

    # ── False positive ────────────────────────────────────────────────────────

    async def mark_false_positive(self, finding: Finding) -> None:
        """Update DefectDojo status and write audit record for a false positive."""
        await self._dd.update_finding_status(finding.finding_id, "false_positive")
        await self._post_defectdojo(
            finding.finding_id,
            "[aegis-vulnops] Verification result: NOT CONFIRMED — marking as false positive.",
        )
        await self._record(
            finding.finding_id,
            action="mark_false_positive",
            result="success",
            detail=None,
        )

        logger.info(
            "Finding marked as false positive",
            extra={"action": "false_positive", "finding_id": finding.finding_id},
        )

    # ── Remediation feedback ──────────────────────────────────────────────────

    async def post_remediation_result(
        self,
        finding: Finding,
        proposal: RemediationProposal,
        ticket_id: Optional[str] = None,
    ) -> None:
        """Post remediation outcome (fix diff or routing decision) to all systems."""
        if proposal.can_fix:
            message = (
                f"[aegis-vulnops] Automated fix proposed "
                f"(confidence: {proposal.confidence:.0%})\n\n"
                + proposal.summary()
            )
        else:
            ticket_ref = f"\n\nRouted to ticket: {ticket_id}" if ticket_id else ""
            message = (
                f"[aegis-vulnops] Manual remediation required → team: {proposal.target_team.upper()}\n\n"
                + proposal.summary()
                + ticket_ref
            )

        await self._post_defectdojo(finding.finding_id, message)

        # Post to Checkmarx if finding has a Checkmarx tracking ID
        if finding.tracking_ids.checkmarx_id:
            await self._post_checkmarx(finding.tracking_ids.checkmarx_id, message)

        # Post a comment to the Jira ticket (if ticket_id looks like a Jira key)
        if ticket_id and "-" in ticket_id:
            await self._post_jira_comment(finding, ticket_id, message)

        await self._record(
            finding.finding_id,
            action="remediate",
            result="fix_proposed" if proposal.can_fix else "routed",
            detail=json.dumps({
                "can_fix": proposal.can_fix,
                "team": proposal.target_team,
                "ticket_id": ticket_id,
                "confidence": proposal.confidence,
            }),
        )

        logger.info(
            "Remediation feedback posted",
            extra={"action": "feedback_remediate", "finding_id": finding.finding_id,
                   "can_fix": proposal.can_fix, "team": proposal.target_team,
                   "ticket_id": ticket_id},
        )

    # ── Ticket created feedback ───────────────────────────────────────────────

    async def record_ticket(
        self,
        finding: Finding,
        ticket_type: str,
        external_id: Optional[str],
        payload_json: str,
    ) -> None:
        """Write a created ticket to the vuln_tickets audit table."""
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO vuln_tickets (finding_id, ticket_type, external_id, payload, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (finding.finding_id, ticket_type, external_id, payload_json, _now()),
            )
            conn.commit()

        logger.info(
            "Ticket recorded in audit table",
            extra={"action": "ticket_recorded", "finding_id": finding.finding_id,
                   "ticket_type": ticket_type, "external_id": external_id},
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _post_defectdojo(self, finding_id: int, message: str) -> None:
        try:
            await self._dd.add_note(finding_id, message)
        except Exception as exc:
            logger.warning(
                "Failed to post DefectDojo note",
                extra={"action": "dd_note_error", "finding_id": finding_id, "error": str(exc)},
            )

    async def _post_checkmarx(self, cx_id: str, message: str) -> None:
        """
        Post a comment to Checkmarx.

        Currently a stub — logs the message.
        Full implementation: POST {CHECKMARX_URL}/cxrestapi/comments/...
        """
        if not self._cx_enabled:
            return

        logger.info(
            "Checkmarx comment (stub — configure CHECKMARX_URL to enable full posting)",
            extra={"action": "cx_comment_stub", "cx_id": cx_id, "chars": len(message)},
        )
        # TODO: implement when Checkmarx credentials are available.

    async def _post_jira_comment(
        self,
        finding: Finding,
        issue_key: str,
        message: str,
    ) -> None:
        """Add a status comment to the newly created Jira issue."""
        from vulnops.ticketing import TicketingEngine
        engine = TicketingEngine()
        try:
            await engine.add_jira_comment(issue_key, message)
        except Exception as exc:
            logger.warning(
                "Failed to post Jira comment",
                extra={"action": "jira_comment_error", "issue_key": issue_key, "error": str(exc)},
            )
        finally:
            await engine.close()

    async def _record(
        self,
        finding_id: int,
        action: str,
        result: str,
        detail: Optional[str],
    ) -> None:
        """Write an entry to the vuln_actions audit table."""
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO vuln_actions (finding_id, action, result, detail, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (finding_id, action, result, detail, _now()),
            )
            conn.commit()
