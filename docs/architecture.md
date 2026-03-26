# Aegis Link — System Architecture

**Keywords:** architecture, overview, pipeline, components, data-flow, modules, design

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Component Map](#component-map)
3. [Data Flow](#data-flow)
4. [Database Schema](#database-schema)
5. [Human-in-the-Loop Flow](#human-in-the-loop-flow)
6. [Dependency Graph](#dependency-graph)

---

## System Overview

Aegis Link is a v0 production-grade autonomous threat intelligence ingestion and correlation engine. It automates the pipeline from raw threat reports (RSS/Web) to structured operational intelligence (STIX 2.1, YARA rules, MITRE TTPs) using the Model Context Protocol (MCP) as its investigator-facing interface.

**Design goals:**
- Fully automated ingestion with human-gated output artefacts
- Every action produces a searchable, structured audit log
- Idempotent by design — re-runs produce no duplicates
- MCP interface allows LLM-powered investigators to query, draft, and approve intelligence in a single conversational session

---

## Component Map

```
┌─────────────────────────────────────────────────────────────────────┐
│                          AEGIS LINK v0                              │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │ Aegis-Pulse  │    │ Aegis-Brain  │    │   Aegis-Analytics    │  │
│  │ (Collection) │───▶│ (Enrichment) │───▶│   (DBT Transform)   │  │
│  │              │    │              │    │                      │  │
│  │pulse/        │    │brain/        │    │models/               │  │
│  │collector.py  │    │processor.py  │    │staged_leads.sql      │  │
│  └──────────────┘    └──────────────┘    └──────────────────────┘  │
│          │                  │                       │              │
│          ▼                  ▼                       ▼              │
│  ┌───────────────────────────────────────────────────────────┐     │
│  │                  aegis_intel.db  (SQLite/WAL)             │     │
│  │  raw_intel (url_hash UNIQUE)  │  draft_analysis           │     │
│  └───────────────────────────────────────────────────────────┘     │
│                                    │                               │
│                          ┌─────────▼──────────┐                   │
│                          │   Aegis-Bridge      │                   │
│                          │   (MCP Server)      │                   │
│                          │                     │                   │
│                          │  fetch_threat_leads │                   │
│                          │  draft_threat_      │                   │
│                          │    analysis         │                   │
│                          │  confirm_threat_    │                   │
│                          │    analysis         │                   │
│                          └─────────┬──────────┘                   │
└────────────────────────────────────┼────────────────────────────--─┘
                                     │ MCP stdio
                                     ▼
                          ┌──────────────────────┐
                          │  LLM / Investigator  │
                          │  (Claude Desktop,    │
                          │   claude.ai/code,    │
                          │   custom MCP client) │
                          └──────────────────────┘
```

---

## Data Flow

### Stage 1 — Collection (Aegis-Pulse)
1. `feedparser` fetches the RSS feed from The DFIR Report.
2. For each entry, `requests` + `BeautifulSoup` downloads and parses the full article.
3. A Pydantic model validates title, publication date, and body text.
4. The URL is normalised and SHA-256 hashed → `url_hash`.
5. `INSERT OR IGNORE` on `url_hash` writes only genuinely new articles.

**Output table:** `raw_intel` (`is_processed = 0`)

### Stage 2 — Enrichment (Aegis-Brain)
1. Fetches rows where `is_processed = 0`.
2. Sends article to Claude with a CTI analyst system prompt.
3. Validates the STIX 2.1 JSON response (type, spec_version, objects).
4. On failure: retries once with a stricter prompt; marks `is_processed = -1` on double failure.
5. On success: writes STIX JSON and sets `is_processed = 1`.

**Output column:** `raw_intel.stix_json`

### Stage 3 — Transformation (Aegis-Analytics)
1. DBT materialises `staged_leads` as a SQL VIEW over `raw_intel`.
2. Deduplication: window function (`ROW_NUMBER OVER PARTITION BY source_url`) keeps the freshest row per URL.
3. Urgency flagging: LIKE-based keyword detection for `Ransomware` and `Exploit` in title and STIX JSON.

**Output view:** `staged_leads` (`urgency_flag IN ('HIGH_URGENCY', 'NORMAL')`)

### Stage 4 — Investigation (Aegis-Bridge / MCP)
See [Human-in-the-Loop Flow](#human-in-the-loop-flow).

---

## Database Schema

### Table: `raw_intel`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INTEGER | PK, AUTOINCREMENT | Row identifier |
| `url_hash` | TEXT | NOT NULL, UNIQUE | SHA-256 of normalised URL — canonical dedup key |
| `source_url` | TEXT | NOT NULL, UNIQUE | Human-readable article URL |
| `title` | TEXT | NOT NULL | Article headline |
| `pub_date` | TEXT | | ISO-8601 publication date |
| `raw_text` | TEXT | | Full article body, stripped HTML |
| `stix_json` | TEXT | | STIX 2.1 bundle JSON (NULL until enriched) |
| `processed_at` | TEXT | | ISO-8601 timestamp of last Brain update |
| `is_processed` | INTEGER | DEFAULT 0, CHECK IN (-1,0,1) | -1=failed, 0=pending, 1=enriched |

**Indexes:** `url_hash`, `is_processed`, `pub_date`

### Table: `draft_analysis`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INTEGER | PK, AUTOINCREMENT | Draft identifier |
| `raw_intel_id` | INTEGER | NOT NULL, FK→raw_intel(id) | Source article |
| `draft_yara` | TEXT | | YARA rule text generated by Claude |
| `draft_ttp_map` | TEXT | | JSON array of MITRE TTP objects |
| `status` | TEXT | DEFAULT 'pending_review' | pending_review / approved / rejected |
| `reviewer_notes` | TEXT | | Investigator comments on the decision |
| `created_at` | TEXT | NOT NULL | ISO-8601 draft creation timestamp |
| `reviewed_at` | TEXT | | ISO-8601 decision timestamp |

**Indexes:** `status`, `raw_intel_id`

### View: `staged_leads`

Managed by DBT (`models/staged_leads.sql`). Columns mirror `raw_intel` plus `urgency_flag TEXT` (`'HIGH_URGENCY'` or `'NORMAL'`).

---

## Human-in-the-Loop Flow

```
Investigator
    │
    │  1. "Show me high-urgency ransomware leads"
    ▼
fetch_threat_leads(urgency="HIGH", keyword="ransomware")
    │
    │  Returns list of articles with IDs
    ▼
Investigator reviews titles → picks article id=42
    │
    │  2. "Generate a detection rule for article 42"
    ▼
draft_threat_analysis(raw_intel_id=42)
    │
    │  Claude generates YARA rule + TTP mapping
    │  Draft saved: draft_analysis id=7, status='pending_review'
    │  Returns draft for review ──────────────────────────────────┐
    ▼                                                             │
Investigator reads draft YARA rule + TTP mapping ◀───────────────┘
    │
    │  3a. "Looks good, approve it"
    │      confirm_threat_analysis(draft_id=7, decision="approved",
    │                              reviewer_notes="Validated against sandbox")
    │
    │  3b. "YARA strings are too broad, reject"
    │      confirm_threat_analysis(draft_id=7, decision="rejected",
    │                              reviewer_notes="String '$a' too generic")
    ▼
Full audit trail written to draft_analysis.reviewed_at + reviewer_notes
```

---

## Dependency Graph

```
common/logger.py   ← no internal deps
common/db.py       ← common/logger (indirectly via env)
         │
         ├── pulse/collector.py
         ├── brain/processor.py
         └── bridge/server.py
                  └── (calls Anthropic API for drafts)

models/staged_leads.sql  ← depends on raw_intel table (via dbt source)
```

All pipeline stages read the same `aegis_intel.db`; WAL journal mode prevents read/write contention.
