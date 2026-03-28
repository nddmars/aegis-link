"""
vulnops/ingestor.py — Pluggable ingestion layer.

Two concrete ingestors:
  DefectDojoIngestor  — fetches from DefectDojo REST API (requires DEFECTDOJO_URL)
  ExcelIngestor       — parses .xlsx or .csv files (no external service needed)

Usage:
    from vulnops.ingestor import ingestor_factory
    ingestor = ingestor_factory("excel", file="findings.xlsx")
    findings = await ingestor.ingest()
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

from common.logger import get_logger
from vulnops.models import ExcelColumnMap, Finding, TrackingIds

load_dotenv()

logger = get_logger("aegis.vulnops.ingestor")


# ── Base ──────────────────────────────────────────────────────────────────────

class BaseIngestor(ABC):
    """Abstract base for all ingestion sources."""

    @abstractmethod
    async def ingest(self) -> list[Finding]:
        """Return a list of normalised Finding objects."""


# ── DefectDojo ────────────────────────────────────────────────────────────────

class DefectDojoIngestor(BaseIngestor):
    """Pulls findings from the DefectDojo REST API."""

    def __init__(self) -> None:
        from vulnops.client import DefectDojoClient
        self._client = DefectDojoClient()

        if not self._client._enabled:
            raise ConfigError(
                "DefectDojo is not configured. "
                "Set DEFECTDOJO_URL and DEFECTDOJO_API_TOKEN in your .env, "
                "or use --source excel to run without DefectDojo."
            )

    async def ingest(self) -> list[Finding]:
        logger.info("Starting DefectDojo ingestion", extra={"action": "ingest_start", "source": "defectdojo"})
        findings = await self._client.fetch_all_findings()
        logger.info(
            "DefectDojo ingestion complete",
            extra={"action": "ingest_complete", "source": "defectdojo", "count": len(findings)},
        )
        return findings

    async def close(self) -> None:
        await self._client.close()


# ── Excel / CSV ───────────────────────────────────────────────────────────────

class ExcelIngestor(BaseIngestor):
    """
    Parses an .xlsx or .csv file into Finding objects.

    Column detection is case-insensitive and uses ExcelColumnMap's candidate
    lists so it handles a wide range of real-world spreadsheet formats with
    no configuration required.
    """

    def __init__(
        self,
        file_path: str,
        column_map: Optional[ExcelColumnMap] = None,
    ) -> None:
        self._path = Path(file_path)
        if not self._path.exists():
            raise FileNotFoundError(f"Findings file not found: {self._path}")
        self._col_map = column_map or ExcelColumnMap()

    async def ingest(self) -> list[Finding]:
        logger.info(
            "Starting Excel ingestion",
            extra={"action": "ingest_start", "source": "excel", "file": str(self._path)},
        )

        suffix = self._path.suffix.lower()
        if suffix in (".xlsx", ".xls", ".xlsm"):
            rows, headers = self._read_xlsx()
        elif suffix == ".csv":
            rows, headers = self._read_csv()
        else:
            raise ValueError(
                f"Unsupported file format: {suffix!r}. Use .xlsx or .csv"
            )

        col_resolution = self._col_map.resolve(headers)
        findings = [
            self._row_to_finding(row, col_resolution, idx + 1)
            for idx, row in enumerate(rows)
            if any(str(v).strip() for v in row.values())  # skip blank rows
        ]

        logger.info(
            "Excel ingestion complete",
            extra={"action": "ingest_complete", "source": "excel", "count": len(findings)},
        )
        return findings

    # ── File readers ──────────────────────────────────────────────────────────

    def _read_xlsx(self) -> tuple[list[dict[str, str]], list[str]]:
        import openpyxl
        wb = openpyxl.load_workbook(str(self._path), read_only=True, data_only=True)
        ws = wb.active
        rows_iter = ws.iter_rows(values_only=True)

        header_row = next(rows_iter, None)
        if not header_row:
            return [], []

        headers = [str(c).strip() if c is not None else "" for c in header_row]
        data: list[dict[str, str]] = []

        for row in rows_iter:
            row_dict = {
                headers[i]: str(cell).strip() if cell is not None else ""
                for i, cell in enumerate(row)
                if i < len(headers)
            }
            data.append(row_dict)

        wb.close()
        return data, headers

    def _read_csv(self) -> tuple[list[dict[str, str]], list[str]]:
        rows: list[dict[str, str]] = []
        headers: list[str] = []

        with open(self._path, newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            headers = list(reader.fieldnames or [])
            for row in reader:
                rows.append(dict(row))

        return rows, headers

    # ── Row → Finding ─────────────────────────────────────────────────────────

    def _row_to_finding(
        self,
        row: dict[str, str],
        col_resolution: dict[str, Optional[str]],
        row_number: int,
    ) -> Finding:
        """Map a spreadsheet row to a Finding using the resolved column headers."""

        def get(field: str, default: str = "") -> str:
            header = col_resolution.get(field)
            if header and header in row:
                return str(row[header]).strip()
            return default

        # Derive a stable numeric finding_id: use the ID column if present,
        # otherwise hash the title + row_number so it is reproducible.
        raw_id = get("finding_id")
        if raw_id and raw_id.isdigit():
            finding_id = int(raw_id)
        else:
            title_str = get("title") or f"row-{row_number}"
            finding_id = int(hashlib.md5(f"{title_str}-{row_number}".encode()).hexdigest(), 16) % (10 ** 9)

        tracking = TrackingIds(
            jira_id=get("jira_id") or None,
            servicenow_id=get("servicenow_id") or None,
            ba_ticket_id=get("ba_ticket_id") or None,
            checkmarx_id=get("checkmarx_id") or None,
        )

        raw_json = json.dumps({k: v for k, v in row.items() if v})

        return Finding(
            finding_id=finding_id,
            title=get("title") or f"Finding row {row_number}",
            severity=get("severity") or "info",
            scanner_type=get("scanner_type") or "unknown",
            component_name=get("component_name"),
            component_version=get("component_version"),
            target_host=get("target_host"),
            repo_url=get("repo_url"),
            due_date=_normalise_date(get("due_date")) or None,
            status=get("status") or "Open",
            tracking_ids=tracking,
            raw_json=raw_json,
            source="excel",
        )


# ── Factory ───────────────────────────────────────────────────────────────────

class ConfigError(RuntimeError):
    """Raised when a required configuration variable is missing."""


def ingestor_factory(
    source: str,
    file: Optional[str] = None,
) -> BaseIngestor:
    """
    Return the appropriate BaseIngestor for the given source.

    Args:
        source: "defectdojo" | "excel" | "auto"
        file:   Path to .xlsx or .csv file (required for "excel" source).

    "auto" selects DefectDojo if the environment variables are present,
    otherwise raises ConfigError with a helpful message.
    """
    source = source.lower().strip()

    if source == "auto":
        dd_url = os.environ.get("DEFECTDOJO_URL", "")
        dd_token = os.environ.get("DEFECTDOJO_API_TOKEN", "")
        if dd_url and dd_token:
            source = "defectdojo"
        else:
            raise ConfigError(
                "Source is 'auto' but DEFECTDOJO_URL / DEFECTDOJO_API_TOKEN are not set. "
                "Either configure DefectDojo credentials or pass --source excel --file <path>."
            )

    if source == "defectdojo":
        return DefectDojoIngestor()

    if source == "excel":
        excel_path = file or os.environ.get("VULNOPS_EXCEL_FILE", "")
        if not excel_path:
            raise ConfigError(
                "Excel source requires a file path. "
                "Pass --file findings.xlsx or set VULNOPS_EXCEL_FILE."
            )
        return ExcelIngestor(excel_path)

    raise ValueError(f"Unknown source {source!r}. Use 'defectdojo', 'excel', or 'auto'.")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _normalise_date(raw: str) -> str:
    """
    Try to parse common date formats and return an ISO-8601 date string.
    Returns the raw string unchanged if parsing fails.
    """
    if not raw:
        return ""

    from datetime import datetime

    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%d-%m-%Y", "%m-%d-%Y", "%d.%m.%Y"):
        try:
            return datetime.strptime(raw.strip(), fmt).date().isoformat()
        except ValueError:
            continue

    return raw.strip()
