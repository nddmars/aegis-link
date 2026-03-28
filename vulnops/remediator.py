"""
vulnops/remediator.py — AI-powered remediation engine.

Uses the Anthropic Claude API (same model as aegis-brain) to analyse a
confirmed vulnerability together with its verification evidence and propose:
  (a) A concrete code/config fix (unified diff when possible), or
  (b) The correct team to route the issue to, with full rationale.

Findings are prioritised by due_date (overdue first) then severity weight.
A single automatic retry is attempted when the JSON response cannot be parsed,
following the same pattern used in brain/processor.py.
"""

from __future__ import annotations

import json
import os
from datetime import date
from typing import Optional

import anthropic
from dotenv import load_dotenv

from common.logger import get_logger
from vulnops.models import Finding, RemediationProposal, TargetTeam, VerificationResult

load_dotenv()

logger = get_logger("aegis.vulnops.remediator")

MODEL = "claude-opus-4-6"
MAX_TOKENS = 4096

# ── System prompt ─────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """You are a senior application security engineer. You will be given:
1. A vulnerability finding (title, severity, component, version, scanner type)
2. Verification evidence collected from the target system or repository

Your task is to respond with a JSON object (no markdown, no surrounding text) with this exact schema:

{
  "can_fix": <boolean>,
  "proposed_fix": <string or null>,
  "diff": <string or null>,
  "confidence": <float 0.0-1.0>,
  "target_team": <"dev"|"ba"|"security"|"ops"|"unknown">,
  "rationale": <string>
}

Rules:
- Set can_fix=true ONLY if you can propose a concrete, safe code or configuration change (include a unified diff in the "diff" field when possible).
- Set can_fix=false when the fix requires human decisions (architectural change, business logic, procurement, vendor patch).
- proposed_fix: clear, actionable description of what to change. null if can_fix=false.
- diff: unified diff format starting with --- a/... and +++ b/... null if not applicable.
- confidence: your confidence that this is the correct fix (0.0 if can_fix=false).
- target_team: which team should own remediation if can_fix=false.
  - "dev"      — code change in the application
  - "ba"       — business process or third-party vendor decision
  "security" — security team investigation or WAF rule
  - "ops"      — infrastructure or configuration change
- rationale: 2-4 sentences explaining your decision.

Respond with ONLY the JSON object."""

_RETRY_PROMPT = (
    _SYSTEM_PROMPT
    + "\n\nCRITICAL: Your previous response could not be parsed as JSON. "
    "Output the raw JSON object ONLY. No text before '{' or after '}'."
)


# ── Remediator ────────────────────────────────────────────────────────────────

class AIRemediator:
    """
    Analyses findings and proposes fixes or routing decisions using Claude.

    Uses synchronous anthropic.Anthropic() consistent with brain/processor.py.
    Wrapped in asyncio.to_thread() inside agent.py for non-blocking use.
    """

    def __init__(self) -> None:
        self._client = anthropic.Anthropic()

    # ── Public API ────────────────────────────────────────────────────────────

    def prioritize(self, findings: list[Finding]) -> list[Finding]:
        """
        Sort findings: overdue first, then by severity weight descending,
        then by due_date ascending (soonest deadline first).
        """
        today = date.today()

        def sort_key(f: Finding) -> tuple:
            overdue = 0 if f.is_overdue else 1
            severity = -f.severity_weight
            due = f.due_date or "9999-12-31"
            return (overdue, severity, due)

        return sorted(findings, key=sort_key)

    async def analyze(
        self,
        finding: Finding,
        verification: VerificationResult,
    ) -> RemediationProposal:
        """
        Call Claude to propose a fix or identify the target team.

        Retries once on JSON parse failure.
        """
        import asyncio

        prompt = self._build_prompt(finding, verification)
        logger.info(
            "Starting AI analysis",
            extra={"action": "remediate_start", "finding_id": finding.finding_id,
                   "severity": finding.severity, "scanner": finding.scanner_type},
        )

        # Run synchronous Claude call in a thread to avoid blocking event loop
        try:
            raw = await asyncio.to_thread(self._call_claude, prompt, retry=False)
            proposal = _parse_proposal(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning(
                "AI response parse failed — retrying",
                extra={"action": "remediate_retry", "finding_id": finding.finding_id, "error": str(exc)},
            )
            try:
                raw = await asyncio.to_thread(self._call_claude, prompt, retry=True)
                proposal = _parse_proposal(raw)
            except Exception as retry_exc:
                logger.error(
                    "AI analysis failed after retry",
                    exc_info=True,
                    extra={"action": "remediate_failed", "finding_id": finding.finding_id, "error": str(retry_exc)},
                )
                proposal = RemediationProposal(
                    can_fix=False,
                    confidence=0.0,
                    target_team="security",
                    rationale=f"AI analysis failed: {retry_exc}. Manual review required.",
                )

        logger.info(
            "AI analysis complete",
            extra={"action": "remediate_complete", "finding_id": finding.finding_id,
                   "can_fix": proposal.can_fix, "team": proposal.target_team,
                   "confidence": proposal.confidence},
        )
        return proposal

    # ── Internal ──────────────────────────────────────────────────────────────

    def _call_claude(self, prompt: str, *, retry: bool = False) -> str:
        system = _RETRY_PROMPT if retry else _SYSTEM_PROMPT
        message = self._client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text.strip()

    @staticmethod
    def _build_prompt(finding: Finding, verification: VerificationResult) -> str:
        lines: list[str] = [
            "# Vulnerability Finding",
            f"Title: {finding.title}",
            f"Severity: {finding.severity.upper()}",
            f"Scanner: {finding.scanner_type}",
            f"Component: {finding.component_name} {finding.component_version}".strip(),
            f"Target Host: {finding.target_host or 'N/A'}",
            f"Repository: {finding.repo_url or 'N/A'}",
            f"Due Date: {finding.due_date or 'N/A'}",
            f"Status: {finding.status}",
        ]

        if finding.tracking_ids.as_dict():
            lines.append(f"Tracking IDs: {finding.tracking_ids.as_dict()}")

        lines += [
            "",
            "# Verification Evidence",
            f"Method: {verification.method}",
            f"Confirmed: {verification.confirmed}",
            f"Host/Repo: {verification.host or 'N/A'}",
            "",
            "Evidence:",
            verification.evidence[:3000] or "No evidence collected.",
        ]

        return "\n".join(lines)


# ── Parsing ───────────────────────────────────────────────────────────────────

def _parse_proposal(raw: str) -> RemediationProposal:
    """Parse the Claude response into a RemediationProposal. Raises on failure."""
    # Strip markdown code fences if present
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = "\n".join(cleaned.split("\n")[1:])
    if cleaned.endswith("```"):
        cleaned = "\n".join(cleaned.split("\n")[:-1])
    cleaned = cleaned.strip()

    data = json.loads(cleaned)

    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object")

    target_team: TargetTeam = data.get("target_team", "unknown")
    valid_teams = {"dev", "ba", "security", "ops", "unknown"}
    if target_team not in valid_teams:
        target_team = "unknown"

    return RemediationProposal(
        can_fix=bool(data.get("can_fix", False)),
        proposed_fix=data.get("proposed_fix") or None,
        diff=data.get("diff") or None,
        confidence=float(data.get("confidence", 0.0)),
        target_team=target_team,
        rationale=str(data.get("rationale", "")),
    )
