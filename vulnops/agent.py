"""
vulnops/agent.py — aegis-vulnops main orchestrating agent.

Pipeline for each finding:
  1. Ingest  — DefectDojo API or Excel/CSV file
  2. Persist — SQLite upsert (idempotent)
  3. Prioritise — overdue first, then by severity
  4. Verify  — SSH (Qualys) or Git (Prisma) confirmation
  5. Remediate — Claude proposes fix or routes to team
  6. Ticket  — Jira/ServiceNow ticket if manual remediation required
  7. Feedback — post comments back to DefectDojo, Checkmarx, Jira

Entry points:
    python -m vulnops.agent                                   # auto-detect source
    python -m vulnops.agent --source defectdojo               # DefectDojo polling
    python -m vulnops.agent --source excel --file data.xlsx   # one-shot Excel run
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# Allow running from the project root without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

load_dotenv()

from common.db import get_connection
from common.logger import get_logger
from vulnops.client import DefectDojoClient
from vulnops.feedback import FeedbackEngine
from vulnops.ingestor import BaseIngestor, ConfigError, ingestor_factory
from vulnops.models import Finding
from vulnops.remediator import AIRemediator
from vulnops.ticketing import TicketingEngine
from vulnops.verifier import verifier_factory

# Import DB bootstrap so tables are created before first run
import vulnops.db  # noqa: F401

logger = get_logger("aegis.vulnops.agent")

_POLL_INTERVAL: int = int(os.environ.get("VULNOPS_POLL_INTERVAL_SECONDS", "300"))


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# ── Agent ─────────────────────────────────────────────────────────────────────

class VulnOpsAgent:
    """
    Autonomous vulnerability lifecycle management agent.

    Attributes:
        source:      "defectdojo" | "excel"
        excel_path:  Path to .xlsx/.csv (required when source="excel")
        poll_interval: Seconds between DefectDojo polling cycles (ignored for Excel)
        dry_run:     If True, skip ticket creation and external API writes
    """

    def __init__(
        self,
        source: str = "auto",
        excel_path: Optional[str] = None,
        poll_interval: int = _POLL_INTERVAL,
        dry_run: bool = False,
    ) -> None:
        self.source = source
        self.excel_path = excel_path
        self.poll_interval = poll_interval
        self.dry_run = dry_run

        self._dd_client = DefectDojoClient()
        self._remediator = AIRemediator()
        self._ticketing = TicketingEngine()
        self._feedback = FeedbackEngine(self._dd_client)

    # ── Main loop ─────────────────────────────────────────────────────────────

    async def run(self) -> None:
        ingestor = ingestor_factory(self.source, file=self.excel_path)

        logger.info(
            "VulnOps agent starting",
            extra={"action": "agent_start", "source": self.source,
                   "dry_run": self.dry_run, "poll_interval": self.poll_interval},
        )

        try:
            while True:
                await self._cycle(ingestor)

                if self.source == "excel":
                    logger.info(
                        "Excel one-shot run complete — exiting",
                        extra={"action": "agent_complete", "source": "excel"},
                    )
                    break

                logger.info(
                    f"Sleeping {self.poll_interval}s before next cycle",
                    extra={"action": "agent_sleep", "seconds": self.poll_interval},
                )
                await asyncio.sleep(self.poll_interval)

        except asyncio.CancelledError:
            logger.info("Agent cancelled", extra={"action": "agent_cancelled"})
        finally:
            await self._shutdown()

    async def _cycle(self, ingestor: BaseIngestor) -> None:
        """Run one full ingest → prioritise → process cycle."""
        logger.info("Starting ingestion cycle", extra={"action": "cycle_start"})
        findings = await ingestor.ingest()
        await self._persist_findings(findings)

        prioritised = self._remediator.prioritize(findings)
        logger.info(
            "Processing findings",
            extra={"action": "cycle_process", "total": len(prioritised)},
        )

        for finding in prioritised:
            try:
                await self._process_finding(finding)
            except Exception as exc:
                logger.error(
                    "Unhandled error processing finding — skipping",
                    exc_info=True,
                    extra={"action": "process_error", "finding_id": finding.finding_id,
                           "error": str(exc)},
                )

        logger.info(
            "Ingestion cycle complete",
            extra={"action": "cycle_complete", "processed": len(prioritised)},
        )

    # ── Single finding pipeline ───────────────────────────────────────────────

    async def _process_finding(self, finding: Finding) -> None:
        logger.info(
            "Processing finding",
            extra={"action": "process_start", "finding_id": finding.finding_id,
                   "severity": finding.severity, "title": finding.title[:80],
                   "overdue": finding.is_overdue},
        )

        # ── Step 1: Verify ────────────────────────────────────────────────────
        verifier = verifier_factory(finding.scanner_type)
        verification = await verifier.verify(finding)

        if not self.dry_run:
            await self._feedback.post_verification_result(finding, verification)

        if not verification.confirmed:
            logger.info(
                "Finding not confirmed — marking as false positive",
                extra={"action": "false_positive_candidate", "finding_id": finding.finding_id},
            )
            if not self.dry_run:
                await self._feedback.mark_false_positive(finding)
            self._update_db_status(finding.finding_id, "false_positive")
            return

        # ── Step 2: AI Remediation ────────────────────────────────────────────
        proposal = await self._remediator.analyze(finding, verification)

        ticket_id: Optional[str] = None

        # ── Step 3a: Auto-fix proposed ────────────────────────────────────────
        if proposal.can_fix:
            logger.info(
                "Auto-fix proposed",
                extra={"action": "autofix_proposed", "finding_id": finding.finding_id,
                       "confidence": proposal.confidence},
            )
            self._update_db_status(finding.finding_id, "fix_proposed")

        # ── Step 3b: Manual routing ───────────────────────────────────────────
        else:
            logger.info(
                "Routing to team",
                extra={"action": "route_start", "finding_id": finding.finding_id,
                       "team": proposal.target_team},
            )
            if not self.dry_run:
                ticket_id = await self._ticketing.route_to_team(
                    finding, proposal, verification
                )
                if ticket_id:
                    await self._feedback.record_ticket(
                        finding,
                        ticket_type=_ticket_type_for_team(proposal.target_team),
                        external_id=ticket_id,
                        payload_json=json.dumps({
                            "summary": f"[{finding.severity.upper()}] {finding.title}",
                            "team": proposal.target_team,
                        }),
                    )

            self._update_db_status(finding.finding_id, "routed")

        # ── Step 4: Feedback ──────────────────────────────────────────────────
        if not self.dry_run:
            await self._feedback.post_remediation_result(finding, proposal, ticket_id)

        logger.info(
            "Finding processed",
            extra={"action": "process_complete", "finding_id": finding.finding_id,
                   "can_fix": proposal.can_fix, "ticket_id": ticket_id},
        )

    # ── Persistence ───────────────────────────────────────────────────────────

    async def _persist_findings(self, findings: list[Finding]) -> None:
        """Upsert all findings into vuln_findings + vuln_tracking_ids."""
        now = _now()

        with get_connection() as conn:
            for f in findings:
                conn.execute(
                    """
                    INSERT INTO vuln_findings
                        (finding_id, title, severity, scanner_type, component_name,
                         component_version, target_host, repo_url, due_date, status,
                         source, raw_json, fetched_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(finding_id) DO UPDATE SET
                        title             = excluded.title,
                        severity          = excluded.severity,
                        scanner_type      = excluded.scanner_type,
                        component_name    = excluded.component_name,
                        component_version = excluded.component_version,
                        target_host       = excluded.target_host,
                        repo_url          = excluded.repo_url,
                        due_date          = excluded.due_date,
                        status            = excluded.status,
                        raw_json          = excluded.raw_json,
                        updated_at        = excluded.updated_at
                    """,
                    (
                        f.finding_id, f.title, f.severity, f.scanner_type,
                        f.component_name, f.component_version, f.target_host,
                        f.repo_url, f.due_date, f.status, f.source,
                        f.raw_json, now, now,
                    ),
                )

                # Upsert tracking IDs
                for system, ticket_id in f.tracking_ids.as_dict().items():
                    conn.execute(
                        """
                        INSERT INTO vuln_tracking_ids (finding_id, system, ticket_id)
                        VALUES (?, ?, ?)
                        ON CONFLICT(finding_id, system) DO UPDATE SET
                            ticket_id = excluded.ticket_id
                        """,
                        (f.finding_id, system, ticket_id),
                    )

            conn.commit()

        logger.info(
            "Findings persisted",
            extra={"action": "persist_complete", "count": len(findings)},
        )

    def _update_db_status(self, finding_id: int, status: str) -> None:
        with get_connection() as conn:
            conn.execute(
                "UPDATE vuln_findings SET status = ?, updated_at = ? WHERE finding_id = ?",
                (status, _now(), finding_id),
            )
            conn.commit()

    # ── Shutdown ──────────────────────────────────────────────────────────────

    async def _shutdown(self) -> None:
        await self._dd_client.close()
        await self._ticketing.close()
        logger.info("Agent shut down cleanly", extra={"action": "agent_shutdown"})


# ── CLI ───────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="aegis-vulnops",
        description="Autonomous vulnerability lifecycle management agent.",
    )
    parser.add_argument(
        "--source",
        choices=["defectdojo", "excel", "auto"],
        default="auto",
        help="Ingestion source. 'auto' uses DefectDojo if configured, else fails with help.",
    )
    parser.add_argument(
        "--file",
        metavar="PATH",
        default=None,
        help="Path to findings .xlsx or .csv file (required with --source excel).",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=_POLL_INTERVAL,
        metavar="SECONDS",
        help=f"Seconds between DefectDojo polling cycles (default: {_POLL_INTERVAL}).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run the full pipeline without creating tickets or posting comments.",
    )
    return parser.parse_args()


async def _amain() -> None:
    args = _parse_args()
    agent = VulnOpsAgent(
        source=args.source,
        excel_path=args.file,
        poll_interval=args.poll_interval,
        dry_run=args.dry_run,
    )
    await agent.run()


def main() -> None:
    """Entry point for 'aegis-vulnops' console script."""
    try:
        asyncio.run(_amain())
    except ConfigError as exc:
        print(f"\nConfiguration error: {exc}\n", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ticket_type_for_team(team: str) -> str:
    return {"ops": "change_request", "dev": "jira_dev"}.get(team, "jira_security")
