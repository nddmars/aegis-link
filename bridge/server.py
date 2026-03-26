"""
bridge/server.py — Aegis-Bridge MCP Server.

Exposes a single MCP tool, ``fetch_threat_leads``, that lets an LLM-powered
investigator query the Aegis threat intelligence database by keyword or MITRE
ATT&CK technique ID. Results are returned as structured STIX 2.1 JSON so the
LLM can reason over them directly.

Architecture
────────────
- Queries the ``staged_leads`` DBT view when available (deduplicated,
  urgency-flagged). Falls back to ``raw_intel WHERE is_processed = 1`` if the
  view does not yet exist (e.g., DBT has not been run).
- Uses a fresh, short-lived SQLite connection per tool invocation to avoid
  holding locks between MCP calls.
- All query parameters are passed as SQLite bound parameters — never
  interpolated — so there is no SQL injection risk.

Usage:
    python bridge/server.py          # starts MCP server on stdio
    # Register in your MCP client config as a stdio server.
"""

import asyncio
import json
import logging
import sqlite3
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

from common.db import get_connection

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("aegis.bridge")

# ── MCP server instance ───────────────────────────────────────────────────────
server = Server("aegis-bridge")

# ── Tool definition ───────────────────────────────────────────────────────────
_TOOL_DESCRIPTION = (
    "Query the Aegis threat intelligence database. "
    "Returns structured STIX 2.1 JSON bundles enriched from The DFIR Report and other sources. "
    "Filter by freetext keyword, MITRE ATT&CK technique ID (e.g. 'T1059'), "
    "and/or urgency level (HIGH = Ransomware/Exploit reports)."
)

_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "keyword": {
            "type": "string",
            "description": (
                "Freetext keyword to search in the article title or STIX JSON. "
                "Examples: 'Cobalt Strike', 'LockBit', 'lateral movement'."
            ),
        },
        "mitre_technique": {
            "type": "string",
            "description": (
                "MITRE ATT&CK technique ID to filter by. "
                "The search is substring-based, so 'T1059' also matches 'T1059.001'. "
                "Examples: 'T1059', 'T1486', 'T1071'."
            ),
        },
        "urgency": {
            "type": "string",
            "enum": ["HIGH", "NORMAL", "ALL"],
            "description": (
                "Urgency level set by Aegis-Analytics. "
                "HIGH = report title or STIX content contains 'Ransomware' or 'Exploit'. "
                "Defaults to 'ALL' when omitted."
            ),
        },
        "limit": {
            "type": "integer",
            "description": "Maximum number of results to return. Default 10, maximum 50.",
            "minimum": 1,
            "maximum": 50,
        },
    },
    "additionalProperties": False,
}


# ── Query helpers ─────────────────────────────────────────────────────────────

def _view_exists(conn: sqlite3.Connection, view_name: str) -> bool:
    """Return True if a view (or table) with *view_name* exists in the DB."""
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type IN ('view','table') AND name = ?",
        (view_name,),
    ).fetchone()
    return row is not None


def _build_query(
    keyword: str,
    technique: str,
    urgency: str,
    limit: int,
    use_view: bool,
) -> tuple[str, list]:
    """
    Build a parameterised SELECT statement and its bound values.

    Args:
        keyword:    Freetext search term (empty string = no filter).
        technique:  MITRE technique ID (empty string = no filter).
        urgency:    "HIGH" | "NORMAL" | "ALL".
        limit:      Row cap.
        use_view:   True → query staged_leads; False → query raw_intel directly.

    Returns:
        (sql_string, params_list)
    """
    if use_view:
        table = "staged_leads"
        base_cols = "title, pub_date, source_url, stix_json, urgency_flag"
        base_where = []  # staged_leads already filters is_processed=1
    else:
        table = "raw_intel"
        base_cols = "title, pub_date, source_url, stix_json, 'N/A' AS urgency_flag"
        base_where = ["is_processed = 1", "stix_json IS NOT NULL"]

    params: list = []

    if keyword:
        base_where.append("(title LIKE ? OR stix_json LIKE ?)")
        params += [f"%{keyword}%", f"%{keyword}%"]

    if technique:
        base_where.append("stix_json LIKE ?")
        params.append(f"%{technique}%")

    if urgency == "HIGH" and use_view:
        base_where.append("urgency_flag = 'HIGH_URGENCY'")
    elif urgency == "NORMAL" and use_view:
        base_where.append("urgency_flag = 'NORMAL'")

    where_clause = (" WHERE " + " AND ".join(base_where)) if base_where else ""
    sql = f"SELECT {base_cols} FROM {table}{where_clause} ORDER BY pub_date DESC LIMIT ?"
    params.append(limit)

    return sql, params


def _execute_query(
    keyword: str,
    technique: str,
    urgency: str,
    limit: int,
) -> list[dict]:
    """
    Run the threat-lead query and return a list of result dicts.

    Connects with timeout=10 (fast interactive use). Handles database-locked
    errors by raising a descriptive RuntimeError so the caller can return a
    user-friendly message instead of crashing the MCP server.
    """
    try:
        conn = get_connection(timeout=10)
    except sqlite3.OperationalError as exc:
        raise RuntimeError(f"Database unavailable: {exc}") from exc

    try:
        use_view = _view_exists(conn, "staged_leads")
        if not use_view:
            logger.warning(
                "staged_leads view not found — falling back to raw_intel. "
                "Run 'dbt run' from the models/ directory to create the view."
            )

        sql, params = _build_query(keyword, technique, urgency, limit, use_view)
        logger.debug("Query: %s | Params: %s", sql, params)

        rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    except sqlite3.OperationalError as exc:
        if "locked" in str(exc).lower():
            raise RuntimeError(
                "The database is locked by another process. "
                "Please retry in a few seconds."
            ) from exc
        raise
    finally:
        conn.close()


# ── MCP handlers ──────────────────────────────────────────────────────────────

@server.list_tools()
async def list_tools() -> list[types.Tool]:
    """Advertise the fetch_threat_leads tool to MCP clients."""
    return [
        types.Tool(
            name="fetch_threat_leads",
            description=_TOOL_DESCRIPTION,
            inputSchema=_INPUT_SCHEMA,
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    """
    Handle an MCP tool invocation.

    Returns a list containing a single TextContent block. On success this is
    a JSON array of threat lead objects. On failure (empty results, DB lock,
    unknown tool) a plain-text explanation is returned so the LLM context
    receives something actionable rather than a hard error.
    """
    if name != "fetch_threat_leads":
        return [
            types.TextContent(
                type="text",
                text=f"Unknown tool: {name!r}. Available tools: fetch_threat_leads",
            )
        ]

    # ── Parse and clamp arguments ─────────────────────────────────────────
    keyword: str = str(arguments.get("keyword", "")).strip()
    technique: str = str(arguments.get("mitre_technique", "")).strip()
    urgency: str = str(arguments.get("urgency", "ALL")).upper()
    if urgency not in {"HIGH", "NORMAL", "ALL"}:
        urgency = "ALL"
    limit: int = min(int(arguments.get("limit", 10)), 50)

    logger.info(
        "fetch_threat_leads called — keyword=%r, technique=%r, urgency=%s, limit=%d",
        keyword, technique, urgency, limit,
    )

    # ── Execute query ─────────────────────────────────────────────────────
    try:
        rows = _execute_query(keyword, technique, urgency, limit)
    except RuntimeError as exc:
        return [types.TextContent(type="text", text=str(exc))]

    # ── Handle empty results ──────────────────────────────────────────────
    if not rows:
        filters = []
        if keyword:
            filters.append(f"keyword={keyword!r}")
        if technique:
            filters.append(f"mitre_technique={technique!r}")
        if urgency != "ALL":
            filters.append(f"urgency={urgency!r}")
        filter_desc = ", ".join(filters) or "no filters"
        return [
            types.TextContent(
                type="text",
                text=(
                    f"No threat leads found matching the given criteria ({filter_desc}). "
                    "The database may be empty or no enriched articles match your query. "
                    "Try broadening your search terms or running Aegis-Pulse and Aegis-Brain first."
                ),
            )
        ]

    # ── Deserialise stix_json for richer output ───────────────────────────
    output = []
    for row in rows:
        entry: dict = {
            "title": row["title"],
            "pub_date": row["pub_date"],
            "source_url": row["source_url"],
            "urgency_flag": row.get("urgency_flag", "N/A"),
        }
        try:
            entry["stix_bundle"] = json.loads(row["stix_json"])
        except (TypeError, json.JSONDecodeError):
            entry["stix_bundle"] = None
        output.append(entry)

    logger.info("Returning %d threat lead(s)", len(output))

    return [
        types.TextContent(
            type="text",
            text=json.dumps(output, indent=2, ensure_ascii=False),
        )
    ]


# ── Server startup ────────────────────────────────────────────────────────────

async def main() -> None:
    """Start the MCP server over stdio transport."""
    logger.info("Aegis-Bridge MCP server starting on stdio…")
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
