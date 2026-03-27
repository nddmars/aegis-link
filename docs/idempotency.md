# Aegis Link — Idempotency Design

**Keywords:** idempotency, deduplication, duplicate, url-hash, sha256, insert-or-ignore, re-run, safe, hash, fingerprint, uniqueness

---

## Overview

Every component of Aegis Link is designed to be **safely re-runnable** at any time with zero risk of data corruption or duplication. This is achieved through a layered idempotency strategy.

---

## Layer 1 — URL Hash (Aegis-Pulse)

The primary deduplication key is a **SHA-256 hash of the normalised article URL**, stored in `raw_intel.url_hash`.

### Why a hash instead of the raw URL?

| Problem | Solution |
|---|---|
| Trailing slashes differ (`/foo` vs `/foo/`) | Normalisation strips trailing slashes |
| Mixed case hostnames (`Example.com` vs `example.com`) | Normalisation lowercases scheme + host |
| Fragments differ (`/foo#section1` vs `/foo`) | Normalisation drops URL fragments |
| URL length limit risks in UNIQUE index | 64-char hex digest has constant length |

### Normalisation algorithm

```python
from urllib.parse import urlparse, urlunparse
import hashlib

def _hash_url(url: str) -> str:
    parsed = urlparse(url.strip())
    normalised = urlunparse((
        parsed.scheme.lower(),   # http/https lowercased
        parsed.netloc.lower(),   # hostname lowercased
        parsed.path.rstrip("/"), # trailing slash removed
        parsed.params,           # preserved
        parsed.query,            # preserved (path is case-sensitive)
        "",                      # fragment dropped
    ))
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()
```

### Database enforcement

```sql
-- Schema (from common/db.py)
url_hash  TEXT  NOT NULL UNIQUE
source_url TEXT NOT NULL UNIQUE

-- Insert statement (from pulse/collector.py)
INSERT OR IGNORE INTO raw_intel
    (url_hash, source_url, title, pub_date, raw_text)
VALUES
    (?, ?, ?, ?, ?)
```

`INSERT OR IGNORE` silently discards any row where either `url_hash` or `source_url` already exists. Zero exceptions are raised; the collector simply moves to the next entry.

### Verification

Check that no duplicates exist after any number of Pulse runs:

```sql
-- Should return 0 rows
SELECT url_hash, COUNT(*) AS n
FROM   raw_intel
GROUP  BY url_hash
HAVING n > 1;

-- Likewise for source_url
SELECT source_url, COUNT(*) AS n
FROM   raw_intel
GROUP  BY source_url
HAVING n > 1;
```

---

## Layer 2 — Processing State (Aegis-Brain)

Brain filters by `is_processed = 0`, so it only touches rows that genuinely need enrichment. Successfully enriched rows (`is_processed = 1`) and permanently-failed rows (`is_processed = -1`) are never re-processed unless manually reset.

| `is_processed` | Meaning | Brain action |
|---|---|---|
| `0` | Awaiting enrichment | Selected for processing |
| `1` | Enriched successfully | Skipped |
| `-1` | Enrichment permanently failed | Skipped |

To force a retry of a specific row:
```sql
UPDATE raw_intel SET is_processed = 0 WHERE id = <N>;
```

---

## Layer 3 — Deduplication View (Aegis-Analytics)

The `staged_leads` DBT view applies a second deduplication pass using a window function. For each `source_url`, only the most-recently-processed row is surfaced:

```sql
ROW_NUMBER() OVER (
    PARTITION BY source_url
    ORDER BY processed_at DESC NULLS LAST, id DESC
) AS row_num
-- WHERE row_num = 1
```

This ensures that even if two rows somehow share a URL (e.g. due to a manual migration), the Aegis-Bridge only sees one.

---

## Layer 4 — Draft Deduplication (Aegis-Bridge)

The `draft_threat_analysis` tool does **not** prevent multiple drafts for the same `raw_intel_id`. This is intentional: investigators may want to regenerate a draft after a rejection. However, `confirm_threat_analysis` enforces that each draft is decided exactly once:

```python
if row["status"] != "pending_review":
    raise RuntimeError(
        f"Draft id={draft_id} is already '{row['status']}' and cannot be re-decided."
    )
```

---

## Safe Re-run Checklist

| Scenario | Safe? | Notes |
|---|---|---|
| Run `pulse.collector` twice in a row | ✅ Yes | `INSERT OR IGNORE` on `url_hash` |
| Run `brain.processor` on an already-enriched database | ✅ Yes | Selects only `is_processed = 0` |
| Run `dbt run` multiple times | ✅ Yes | View is replaced in-place; no data loss |
| Call `draft_threat_analysis` for the same article twice | ✅ Yes | Creates two independent drafts |
| Call `confirm_threat_analysis` twice on the same draft | ❌ No | Second call returns an error; draft is immutable once decided |
| Delete and recreate `aegis_intel.db` | ✅ Yes | Schema auto-bootstraps; Pulse will re-collect all articles |
