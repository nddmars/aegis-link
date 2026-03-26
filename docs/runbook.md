# Aegis Link — Operations Runbook

**Keywords:** runbook, operations, setup, install, run, execute, cli, commands, environment, configuration, quickstart, getting-started

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Environment Configuration](#environment-configuration)
4. [Running the Pipeline](#running-the-pipeline)
5. [Running the MCP Server](#running-the-mcp-server)
6. [DBT Transformation](#dbt-transformation)
7. [Useful Database Queries](#useful-database-queries)
8. [Cron / Scheduling](#cron--scheduling)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- Python 3.11+
- pip
- An Anthropic API key (`sk-ant-...`)
- Optional: `dbt-core` + `dbt-sqlite` for the analytics layer

---

## Installation

```bash
# Clone the repository
git clone https://github.com/nddmars/aegis-link.git
cd aegis-link

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# Install runtime dependencies
pip install -r requirements.txt

# (Optional) Install DBT for the analytics layer
pip install dbt-core dbt-sqlite
```

---

## Environment Configuration

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env and set your values
# ANTHROPIC_API_KEY=sk-ant-...
# AEGIS_DB_PATH=/absolute/path/to/aegis_intel.db   # optional; defaults to project root
```

The database and all tables are created automatically on first run. No manual migration step is needed.

---

## Running the Pipeline

Run each stage in order from the **project root** directory.

### Stage 1 — Aegis-Pulse (Collection)

Scrapes The DFIR Report RSS feed and saves new articles to `raw_intel`.

```bash
python -m pulse.collector
```

Expected output (structured JSON log lines on stderr):
```json
{"timestamp":"2026-03-26T14:00:00Z","level":"INFO","action":"collection_start","feed_url":"https://thedfirreport.com/feed/"}
{"timestamp":"2026-03-26T14:00:02Z","level":"INFO","action":"article_saved","title":"BumbleBee Zeros in on Meterpreter","url_hash":"a3f9..."}
{"timestamp":"2026-03-26T14:00:10Z","level":"INFO","action":"collection_complete","new_articles":3}
```

**Re-run safety:** Fully idempotent. Duplicate URLs are skipped via `url_hash` UNIQUE constraint.

---

### Stage 2 — Aegis-Brain (Enrichment)

Sends unprocessed articles to Claude and writes STIX 2.1 JSON back to the database.

```bash
python -m brain.processor
```

```json
{"timestamp":"...","level":"INFO","action":"enrich_start","batch_size":10,"model":"claude-opus-4-6"}
{"timestamp":"...","level":"INFO","action":"stix_success","row_id":1,"stix_objects":14}
{"timestamp":"...","level":"INFO","action":"enrich_complete","processed":3,"total":3,"failed":0}
```

**Batch size control:**
```python
from brain.processor import run_processing
run_processing(batch_size=5)    # process 5 articles per call
```

**Failed rows** (is_processed = -1) are permanently skipped. To retry them manually:
```sql
UPDATE raw_intel SET is_processed = 0 WHERE id = <N>;
```

---

### Stage 3 — Aegis-Analytics (DBT)

Deduplicates and urgency-flags enriched articles into the `staged_leads` view.

```bash
cd models
dbt run --profiles-dir .
```

After running, verify the view exists:
```bash
sqlite3 ../aegis_intel.db ".tables"
# should list: raw_intel, draft_analysis, staged_leads (or main_staged_leads)
```

---

## Running the MCP Server

The MCP server listens on stdio and is designed to be registered in an MCP client config.

```bash
python bridge/server.py
```

### Claude Desktop registration (`~/Library/Application Support/Claude/claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "aegis-bridge": {
      "command": "/path/to/.venv/bin/python",
      "args": ["/path/to/aegis-link/bridge/server.py"],
      "env": {
        "ANTHROPIC_API_KEY": "sk-ant-...",
        "AEGIS_DB_PATH": "/path/to/aegis-link/aegis_intel.db"
      }
    }
  }
}
```

### claude.ai/code registration (`.mcp.json` in project root)

```json
{
  "mcpServers": {
    "aegis-bridge": {
      "command": "python",
      "args": ["bridge/server.py"]
    }
  }
}
```

---

## DBT Transformation

### First-time setup

```bash
cd models
# Verify the connection
dbt debug --profiles-dir .

# Run the model
dbt run --profiles-dir .

# Run dbt tests (if any are defined)
dbt test --profiles-dir .
```

### Profiles

`models/profiles.yml` contains the SQLite connection. The `schemas_and_paths.main` key must be an absolute path to `aegis_intel.db`. Update it if you moved the database.

---

## Useful Database Queries

### Pipeline status snapshot

```sql
SELECT
    is_processed,
    COUNT(*) AS count,
    CASE is_processed
        WHEN  0 THEN 'pending'
        WHEN  1 THEN 'enriched'
        WHEN -1 THEN 'failed'
    END AS status
FROM raw_intel
GROUP BY is_processed;
```

### All HIGH_URGENCY leads (requires DBT view)

```sql
SELECT title, pub_date, urgency_flag
FROM   staged_leads
WHERE  urgency_flag = 'HIGH_URGENCY'
ORDER  BY pub_date DESC
LIMIT  20;
```

### All approved YARA rules

```sql
SELECT d.id, r.title, d.draft_yara, d.reviewed_at, d.reviewer_notes
FROM   draft_analysis d
JOIN   raw_intel r ON r.id = d.raw_intel_id
WHERE  d.status = 'approved'
ORDER  BY d.reviewed_at DESC;
```

### All pending drafts awaiting review

```sql
SELECT d.id AS draft_id, r.title, d.created_at
FROM   draft_analysis d
JOIN   raw_intel r ON r.id = d.raw_intel_id
WHERE  d.status = 'pending_review'
ORDER  BY d.created_at DESC;
```

### Check for duplicate URL hashes (should return 0 rows)

```sql
SELECT url_hash, COUNT(*) AS n
FROM   raw_intel
GROUP  BY url_hash
HAVING n > 1;
```

---

## Cron / Scheduling

Run the collection and enrichment pipeline on a schedule:

```bash
# /etc/cron.d/aegis-link  (runs every 6 hours)
0 */6 * * * cd /path/to/aegis-link && /path/to/.venv/bin/python -m pulse.collector >> /var/log/aegis/pulse.log 2>&1
5 */6 * * * cd /path/to/aegis-link && /path/to/.venv/bin/python -m brain.processor >> /var/log/aegis/brain.log 2>&1
10 */6 * * * cd /path/to/aegis-link/models && /path/to/.venv/bin/dbt run --profiles-dir . >> /var/log/aegis/dbt.log 2>&1
```

Because all stages are idempotent, overlapping cron runs produce no duplicates and no data loss.

---

## Troubleshooting

### `database is locked`
- Cause: Brain is writing while Bridge is reading, or another process holds a write lock.
- Fix: WAL mode is already enabled. If the error persists, check for orphaned Python processes:
  ```bash
  fuser aegis_intel.db
  ```

### `staged_leads` view not found
- Cause: DBT has not been run yet.
- Fix: `cd models && dbt run --profiles-dir .`
- The Bridge falls back to `raw_intel` automatically in the meantime.

### `ANTHROPIC_API_KEY not set`
- Fix: Ensure `.env` exists in the project root with `ANTHROPIC_API_KEY=sk-ant-...` and that `python-dotenv` is installed.

### `is_processed = -1` rows accumulating
- Cause: Claude returned malformed STIX for those articles.
- Fix: Check the logs for the `stix_failed` action to see the parse error. To force a retry:
  ```sql
  UPDATE raw_intel SET is_processed = 0 WHERE is_processed = -1;
  ```

### Articles not found in `staged_leads` after DBT run
- Cause: Articles may still be `is_processed = 0` (not yet enriched by Brain).
- Fix: Run Aegis-Brain first, then re-run DBT.

### Searching logs for a specific event

Since all logs are JSON, use `jq`:
```bash
# All articles saved in the last run
python -m pulse.collector 2>&1 | jq 'select(.action == "article_saved")'

# All enrichment failures
cat brain.log | jq 'select(.action == "stix_failed")'

# All investigator decisions
cat bridge.log | jq 'select(.action == "draft_confirmed")'
```

Or with `grep` for quick searches:
```bash
grep '"action": "article_saved"' pulse.log
grep '"action": "stix_failed"'  brain.log
grep '"decision": "approved"'   bridge.log
```
