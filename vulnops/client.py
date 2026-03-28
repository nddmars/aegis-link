"""
vulnops/client.py — DefectDojo async REST API client.

All methods are guarded by a ``_enabled`` flag that is set only when both
DEFECTDOJO_URL and DEFECTDOJO_API_TOKEN are present in the environment.
When not configured, every method returns a safe no-op value so the rest of
the pipeline can run from an Excel source without code changes.

DefectDojo API reference: https://demo.defectdojo.org/api/v2/doc/
"""

from __future__ import annotations

import os
from typing import Any, Optional

from dotenv import load_dotenv

from common.logger import get_logger
from vulnops.models import Finding, SeverityLevel, TrackingIds

load_dotenv()

logger = get_logger("aegis.vulnops.client")

_DEFECTDOJO_URL: Optional[str] = os.environ.get("DEFECTDOJO_URL", "").rstrip("/") or None
_DEFECTDOJO_TOKEN: Optional[str] = os.environ.get("DEFECTDOJO_API_TOKEN") or None


def _is_enabled() -> bool:
    return bool(_DEFECTDOJO_URL and _DEFECTDOJO_TOKEN)


class DefectDojoClient:
    """
    Async client for the DefectDojo REST API.

    Instantiate once and reuse across the agent lifecycle.
    Call ``await client.close()`` (or use as an async context manager) to
    release the underlying aiohttp session.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_token: Optional[str] = None,
    ) -> None:
        self._base_url = (base_url or _DEFECTDOJO_URL or "").rstrip("/")
        self._token = api_token or _DEFECTDOJO_TOKEN or ""
        self._enabled = bool(self._base_url and self._token)
        self._session: Any = None  # aiohttp.ClientSession, lazy-initialised

        if not self._enabled:
            logger.info(
                "DefectDojo not configured — client running in no-op mode",
                extra={"action": "client_init_noop"},
            )

    # ── Session management ────────────────────────────────────────────────────

    async def _get_session(self) -> Any:
        if self._session is None:
            import aiohttp  # deferred import so the module loads without aiohttp
            self._session = aiohttp.ClientSession(
                headers={
                    "Authorization": f"Token {self._token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=30),
            )
        return self._session

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def __aenter__(self) -> "DefectDojoClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    # ── Findings ──────────────────────────────────────────────────────────────

    async def fetch_findings(
        self,
        limit: int = 100,
        offset: int = 0,
        active: bool = True,
    ) -> list[Finding]:
        """Fetch one page of findings from DefectDojo."""
        if not self._enabled:
            return []

        session = await self._get_session()
        params = {"limit": limit, "offset": offset, "active": str(active).lower()}
        url = f"{self._base_url}/api/v2/findings/"

        logger.info(
            "Fetching findings",
            extra={"action": "fetch_findings", "url": url, "offset": offset, "limit": limit},
        )

        async with session.get(url, params=params) as resp:
            resp.raise_for_status()
            data = await resp.json()

        results = data.get("results", [])
        logger.info(
            "Received findings page",
            extra={"action": "findings_page", "count": len(results), "offset": offset},
        )
        return [self._parse_finding(r) for r in results]

    async def fetch_all_findings(self) -> list[Finding]:
        """Paginate through all active findings."""
        if not self._enabled:
            return []

        all_findings: list[Finding] = []
        offset = 0
        limit = 100

        while True:
            page = await self.fetch_findings(limit=limit, offset=offset)
            all_findings.extend(page)
            if len(page) < limit:
                break
            offset += limit

        logger.info(
            "Fetched all findings",
            extra={"action": "fetch_all_complete", "total": len(all_findings)},
        )
        return all_findings

    # ── Status & notes ────────────────────────────────────────────────────────

    async def update_finding_status(
        self, finding_id: int, status: str
    ) -> bool:
        """PATCH a finding's active/verified flags based on status string."""
        if not self._enabled:
            return False

        session = await self._get_session()
        url = f"{self._base_url}/api/v2/findings/{finding_id}/"
        payload: dict[str, Any] = {}

        if status == "false_positive":
            payload = {"false_p": True, "active": False}
        elif status == "mitigated":
            payload = {"mitigated": True, "active": False}
        elif status == "accepted":
            payload = {"risk_accepted": True, "active": False}

        if not payload:
            return False

        logger.info(
            "Updating finding status",
            extra={"action": "update_status", "finding_id": finding_id, "status": status},
        )

        async with session.patch(url, json=payload) as resp:
            resp.raise_for_status()

        return True

    async def add_note(self, finding_id: int, note_text: str) -> bool:
        """POST a note/comment to a DefectDojo finding."""
        if not self._enabled:
            logger.info(
                "DefectDojo disabled — skipping note post",
                extra={"action": "note_skipped", "finding_id": finding_id},
            )
            return False

        session = await self._get_session()
        url = f"{self._base_url}/api/v2/notes/"
        payload = {
            "entry": note_text,
            "finding": finding_id,
        }

        logger.info(
            "Posting note to finding",
            extra={"action": "add_note", "finding_id": finding_id, "chars": len(note_text)},
        )

        async with session.post(url, json=payload) as resp:
            resp.raise_for_status()

        return True

    # ── Parsing ───────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_finding(raw: dict[str, Any]) -> Finding:
        """Convert a raw DefectDojo API finding dict to a Finding model."""
        import json as _json

        # Extract tracking IDs from the finding's metadata/tags/notes.
        # DefectDojo stores external references in `jira_issue`, `test` notes,
        # or custom fields. We map what's available.
        tracking = TrackingIds(
            jira_id=_extract_jira_id(raw),
            checkmarx_id=raw.get("sonarqube_issue") or None,
        )

        # Normalise severity: DefectDojo uses "Critical", "High", etc.
        severity_raw: str = raw.get("severity", "Info")

        return Finding(
            finding_id=raw["id"],
            title=raw.get("title", ""),
            severity=severity_raw.lower(),  # normalised by validator
            scanner_type=_extract_scanner_type(raw),
            component_name=raw.get("component_name", ""),
            component_version=raw.get("component_version", ""),
            target_host=_extract_host(raw),
            repo_url=_extract_repo(raw),
            due_date=raw.get("sla_expiration_date") or raw.get("date"),
            status="Open" if raw.get("active") else "Closed",
            tracking_ids=tracking,
            raw_json=_json.dumps(raw),
            source="defectdojo",
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_jira_id(raw: dict[str, Any]) -> Optional[str]:
    jira = raw.get("jira_issue")
    if isinstance(jira, dict):
        return jira.get("jira_id") or jira.get("jira_key")
    if isinstance(jira, str):
        return jira
    return None


def _extract_scanner_type(raw: dict[str, Any]) -> str:
    # DefectDojo stores scanner info in the test's scan_type field
    test = raw.get("test", {})
    if isinstance(test, dict):
        test_type = test.get("test_type", {})
        if isinstance(test_type, dict):
            name: str = test_type.get("name", "").lower()
            if "qualys" in name:
                return "qualys"
            if "prisma" in name or "twistlock" in name:
                return "prisma"
            if "checkmarx" in name:
                return "checkmarx"
            return name
    return raw.get("scanner_confidence", "unknown").lower()


def _extract_host(raw: dict[str, Any]) -> str:
    endpoint = raw.get("endpoints", [])
    if isinstance(endpoint, list) and endpoint:
        first = endpoint[0]
        if isinstance(first, dict):
            return first.get("host", "") or first.get("ip_address", "")
        return str(first)
    return ""


def _extract_repo(raw: dict[str, Any]) -> str:
    engagement = raw.get("test", {})
    if isinstance(engagement, dict):
        eng = engagement.get("engagement", {})
        if isinstance(eng, dict):
            return eng.get("source_code_management_uri", "") or ""
    return ""
