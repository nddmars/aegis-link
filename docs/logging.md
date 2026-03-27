# Aegis Link — Structured Logging Reference

**Keywords:** logging, audit, log, json, structured, searchable, jq, grep, events, actions, audit-trail, observability, monitoring

---

## Table of Contents

1. [Log Format](#log-format)
2. [Action Taxonomy](#action-taxonomy)
3. [Searching Logs](#searching-logs)
4. [Module-Specific Fields](#module-specific-fields)
5. [Log Level Guide](#log-level-guide)

---

## Log Format

Every log line is a single JSON object emitted to **stderr**. This makes logs:
- Parseable by `jq`, Python, or any log aggregator
- Directly ingestible by Splunk, Elastic, CloudWatch Logs Insights, Datadog, etc.
- Grep-able without a special schema

### Base fields (always present)

| Field | Type | Description |
|---|---|---|
| `timestamp` | ISO-8601 string | UTC event time with microsecond precision |
| `level` | string | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `logger` | string | Logger name: `aegis.pulse`, `aegis.brain`, `aegis.bridge` |
| `message` | string | Human-readable summary |
| `module` | string | Python module filename without `.py` |
| `line` | integer | Source line number |
| `action` | string | Machine-readable event type (see taxonomy below) |

### Extra fields

Additional context is attached per-event. All extra fields are documented in [Module-Specific Fields](#module-specific-fields).

### Example log line

```json
{
  "timestamp": "2026-03-26T14:05:01.234567+00:00",
  "level": "INFO",
  "logger": "aegis.pulse",
  "message": "New article saved",
  "module": "collector",
  "line": 202,
  "action": "article_saved",
  "url": "https://thedfirreport.com/2024/03/15/bumblebee/",
  "title": "BumbleBee Zeros in on Meterpreter",
  "url_hash": "a3f9c2e1..."
}
```

---

## Action Taxonomy

The `action` field is the primary key for log-based searches and alerting.

### Aegis-Pulse (`aegis.pulse`)

| Action | Level | Trigger |
|---|---|---|
| `collection_start` | INFO | `run_collection()` begins |
| `feed_parsed` | INFO | RSS feed successfully parsed; includes `entry_count` |
| `feed_error` | ERROR | `feedparser` returned a fatal parse error |
| `fetch_error` | WARNING | HTTP request for an article failed |
| `selector_match` | DEBUG | CSS selector that located the article body |
| `extraction_failed` | WARNING | No CSS selector produced meaningful text |
| `validation_error` | WARNING | Pydantic validation rejected an entry |
| `article_saved` | INFO | New article written to `raw_intel` |
| `article_duplicate` | DEBUG | Article already existed; skipped |
| `collection_complete` | INFO | `run_collection()` finished; includes `new_articles` count |

### Aegis-Brain (`aegis.brain`)

| Action | Level | Trigger |
|---|---|---|
| `enrich_start` | INFO | `run_processing()` begins; includes `batch_size`, `model`, `queued` |
| `enrich_row` | INFO | Processing starts for a specific `row_id` |
| `stix_success` | INFO | STIX JSON validated and saved; includes `stix_objects` count |
| `stix_retry` | WARNING | First Claude attempt failed; retrying with stricter prompt |
| `stix_failed` | ERROR | Both attempts failed; row marked `is_processed=-1` |
| `api_error` | ERROR | Anthropic API returned an error; row skipped |
| `enrich_complete` | INFO | Batch done; includes `processed`, `total`, `failed` |

### Aegis-Bridge (`aegis.bridge`)

| Action | Level | Trigger |
|---|---|---|
| `server_start` | INFO | MCP server process started |
| `view_fallback` | WARNING | `staged_leads` view absent; using `raw_intel` directly |
| `tool_called` | INFO | Any MCP tool invocation; includes tool name + all input args |
| `fetch_result` | INFO | `fetch_threat_leads` returned results; includes `result_count` |
| `draft_created` | INFO | `draft_threat_analysis` saved a new draft; includes `draft_id` |
| `draft_error` | ERROR | Claude returned malformed draft JSON |
| `draft_confirmed` | INFO | `confirm_threat_analysis` recorded a decision; includes `decision` |

---

## Searching Logs

### Using jq (recommended for structured inspection)

```bash
# All articles saved in a Pulse run
python -m pulse.collector 2>&1 | jq 'select(.action == "article_saved")'

# Just the titles and hashes
python -m pulse.collector 2>&1 | jq 'select(.action == "article_saved") | {title, url_hash}'

# All Brain enrichment failures
cat brain.log | jq 'select(.action == "stix_failed") | {row_id, error}'

# Every MCP tool invocation
cat bridge.log | jq 'select(.action == "tool_called")'

# All approved YARA drafts
cat bridge.log | jq 'select(.action == "draft_confirmed" and .decision == "approved")'

# ERROR and above only
cat brain.log | jq 'select(.level == "ERROR" or .level == "WARNING")'

# Time-range filter (events after a given timestamp)
cat bridge.log | jq 'select(.timestamp > "2026-03-26T12:00:00Z")'
```

### Using grep (quick searches)

```bash
# All article saves
grep '"action": "article_saved"' pulse.log

# All STIX failures
grep '"action": "stix_failed"' brain.log

# All approved decisions
grep '"decision": "approved"' bridge.log

# All ERROR-level events across all modules
grep '"level": "ERROR"' *.log
```

### Redirecting logs to files

```bash
# Capture structured logs per module
python -m pulse.collector  2>> logs/pulse.log
python -m brain.processor  2>> logs/brain.log
python bridge/server.py    2>> logs/bridge.log
```

### Piping into a monitoring tool

Since every line is valid JSON, you can pipe directly into any tool that accepts NDJSON:

```bash
# Kibana/Elastic via filebeat: point filebeat at logs/*.log
# CloudWatch Logs: use the CloudWatch agent with json parsing enabled
# Datadog: configure the Datadog agent with json source detection
```

---

## Module-Specific Fields

### Aegis-Pulse extra fields

| Field | Present on actions | Type | Description |
|---|---|---|---|
| `feed_url` | `collection_start` | string | RSS feed URL |
| `entry_count` | `feed_parsed` | integer | Number of RSS entries found |
| `error` | `feed_error`, `fetch_error`, `validation_error` | string | Exception message |
| `url` | `fetch_error`, `article_saved`, `article_duplicate`, `validation_error` | string | Article URL |
| `title` | `article_saved` | string | Article headline |
| `url_hash` | `article_saved` | string | SHA-256 hex of normalised URL |
| `selector` | `selector_match` | string | CSS selector that matched |
| `reason` | `entry_skipped` | string | Why the entry was skipped |
| `new_articles` | `collection_complete` | integer | Count of newly inserted rows |

### Aegis-Brain extra fields

| Field | Present on actions | Type | Description |
|---|---|---|---|
| `batch_size` | `enrich_start` | integer | Configured batch size |
| `model` | `enrich_start` | string | Claude model identifier |
| `queued` | `enrich_start` | integer | Rows found for processing |
| `row_id` | `enrich_row`, `stix_success`, `stix_retry`, `stix_failed`, `api_error` | integer | `raw_intel.id` |
| `title` | `enrich_row`, `stix_success` | string | Article headline |
| `stix_objects` | `stix_success` | integer | Count of objects in the STIX bundle |
| `error` | `stix_retry`, `stix_failed`, `api_error` | string | Exception message |
| `processed` | `enrich_complete` | integer | Successfully enriched rows |
| `total` | `enrich_complete` | integer | Total rows attempted |
| `failed` | `enrich_complete` | integer | Rows that could not be enriched |

### Aegis-Bridge extra fields

| Field | Present on actions | Type | Description |
|---|---|---|---|
| `transport` | `server_start` | string | Transport type (always `"stdio"`) |
| `tool` | `tool_called`, `draft_created`, `draft_confirmed` | string | Tool name |
| `keyword` | `tool_called` (fetch) | string | Search keyword |
| `technique` | `tool_called` (fetch) | string | MITRE technique filter |
| `urgency` | `tool_called` (fetch) | string | Urgency filter |
| `limit` | `tool_called` (fetch) | integer | Result cap |
| `result_count` | `fetch_result` | integer | Number of rows returned |
| `raw_intel_id` | `tool_called` (draft), `draft_created`, `draft_confirmed` | integer | Source article ID |
| `draft_id` | `draft_created`, `draft_confirmed` | integer | `draft_analysis.id` |
| `status` | `draft_created` | string | Always `"pending_review"` |
| `decision` | `tool_called` (confirm), `draft_confirmed` | string | `"approved"` or `"rejected"` |
| `reviewer_notes` | `draft_confirmed` | string \| null | Investigator's notes |
| `error` | `draft_error` | string | Exception message |

---

## Log Level Guide

| Level | Usage in Aegis Link |
|---|---|
| `DEBUG` | Verbose diagnostic events (CSS selector matches, duplicate skips). Not emitted by default (handler threshold is INFO). Enable by lowering handler level in `common/logger.py`. |
| `INFO` | Normal pipeline progress: run start/complete, articles saved, enrichments succeeded, tool invocations. |
| `WARNING` | Recoverable issues: HTTP fetch failures, Pydantic validation errors, STIX first-attempt failures, missing DBT view. |
| `ERROR` | Unrecoverable per-row failures: double STIX parse failure, Claude API error, draft generation failure. The overall pipeline continues; only the specific row/draft is affected. |
