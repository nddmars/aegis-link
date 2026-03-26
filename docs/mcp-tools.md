# Aegis Link — MCP Tools Reference

**Keywords:** mcp, tools, api, fetch_threat_leads, draft_threat_analysis, confirm_threat_analysis, investigator, query, yara, ttp, stix, human-in-the-loop, review, approve, reject

---

## Table of Contents

1. [Overview](#overview)
2. [Tool: fetch_threat_leads](#tool-fetch_threat_leads)
3. [Tool: draft_threat_analysis](#tool-draft_threat_analysis)
4. [Tool: confirm_threat_analysis](#tool-confirm_threat_analysis)
5. [End-to-End Investigation Example](#end-to-end-investigation-example)
6. [Error Reference](#error-reference)

---

## Overview

Aegis-Bridge exposes three MCP tools over stdio transport. They are designed to be called sequentially by an LLM acting as an investigator's assistant:

| Tool | Purpose | Side Effects |
|---|---|---|
| `fetch_threat_leads` | Read-only query of enriched intelligence | None |
| `draft_threat_analysis` | Generate YARA + TTP draft for an article | Writes to `draft_analysis` (status: pending_review) |
| `confirm_threat_analysis` | Approve or reject a pending draft | Updates `draft_analysis` (status: approved / rejected) |

All three tools handle database lock errors and empty results gracefully, returning descriptive text rather than crashing.

---

## Tool: `fetch_threat_leads`

Query the Aegis threat intelligence database for enriched articles.

### Input Schema

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `keyword` | string | No | `""` | Freetext search in title or STIX JSON. E.g. `"Cobalt Strike"`, `"LockBit"` |
| `mitre_technique` | string | No | `""` | MITRE ATT&CK ID (substring match). E.g. `"T1059"`, `"T1486"` |
| `urgency` | `"HIGH"` \| `"NORMAL"` \| `"ALL"` | No | `"ALL"` | Filter by urgency flag set by Aegis-Analytics |
| `limit` | integer (1–50) | No | `10` | Maximum rows to return |

### Output

A JSON array of threat lead objects. Each object includes:

```json
[
  {
    "id": 42,
    "title": "BumbleBee Zeros in on Meterpreter",
    "pub_date": "2024-03-15T00:00:00+00:00",
    "source_url": "https://thedfirreport.com/...",
    "urgency_flag": "HIGH_URGENCY",
    "stix_bundle": {
      "type": "bundle",
      "spec_version": "2.1",
      "objects": [ ... ]
    }
  }
]
```

### Examples

**Get all HIGH urgency leads:**
```json
{ "urgency": "HIGH" }
```

**Search for Cobalt Strike reports:**
```json
{ "keyword": "Cobalt Strike", "limit": 5 }
```

**Filter by MITRE technique T1486 (Data Encrypted for Impact):**
```json
{ "mitre_technique": "T1486" }
```

**Combined filter:**
```json
{ "keyword": "LockBit", "urgency": "HIGH", "mitre_technique": "T1059", "limit": 3 }
```

---

## Tool: `draft_threat_analysis`

Generate a draft YARA rule and structured MITRE TTP mapping for a specific article. The draft is saved to `draft_analysis` with `status = 'pending_review'` and returned for investigator review.

**This tool intentionally does NOT auto-approve.** The investigator must call `confirm_threat_analysis` to commit or reject the output.

### Input Schema

| Parameter | Type | Required | Description |
|---|---|---|---|
| `raw_intel_id` | integer | **Yes** | `id` from a `fetch_threat_leads` result |

### Output

A JSON object containing:

```json
{
  "status": "DRAFT — PENDING INVESTIGATOR REVIEW",
  "draft_id": 7,
  "raw_intel_id": 42,
  "article_title": "BumbleBee Zeros in on Meterpreter",
  "next_step": "Review the draft_yara and ttp_mapping below. Then call confirm_threat_analysis...",
  "draft_yara": "rule AegisLink_BumbleBee {\n    meta:\n        description = \"...\"\n        author = \"Aegis-Brain\"\n        date = \"2026-03-26\"\n        mitre_attack = \"T1059, T1547\"\n    strings:\n        $s1 = \"BumbleBee\" nocase\n        $h1 = { AB CD EF ... }\n    condition:\n        any of them\n}",
  "ttp_mapping": [
    {
      "technique_id": "T1059",
      "technique_name": "Command and Scripting Interpreter",
      "description": "PowerShell was used to download and execute the BumbleBee loader."
    },
    {
      "technique_id": "T1547",
      "technique_name": "Boot or Logon Autostart Execution",
      "description": "Registry run key was set to persist the loader across reboots."
    }
  ]
}
```

### Common Errors

| Response | Cause | Fix |
|---|---|---|
| `Article id=N not found in raw_intel.` | ID does not exist | Use a valid ID from `fetch_threat_leads` |
| `Article id=N has not been enriched yet.` | `is_processed != 1` | Run Aegis-Brain first |
| `Draft generation failed: ...` | Claude returned malformed JSON | Retry the call |

---

## Tool: `confirm_threat_analysis`

Record an investigator's approval or rejection of a pending draft. Closes the human-in-the-loop feedback cycle and writes a full audit trail.

### Input Schema

| Parameter | Type | Required | Description |
|---|---|---|---|
| `draft_id` | integer | **Yes** | `draft_id` from a `draft_threat_analysis` response |
| `decision` | `"approved"` \| `"rejected"` | **Yes** | The investigator's verdict |
| `reviewer_notes` | string | No | Notes explaining the decision (especially useful on rejection) |

### Output — Approval

```json
{
  "status": "Draft approved and committed successfully.",
  "audit_trail": {
    "draft_id": 7,
    "raw_intel_id": 42,
    "decision": "approved",
    "reviewer_notes": "Validated against sandbox run, hashes confirmed.",
    "reviewed_at": "2026-03-26T14:32:11+00:00"
  },
  "tip": "Approved YARA rules are queryable with: SELECT id, draft_yara FROM draft_analysis WHERE status = 'approved'"
}
```

### Output — Rejection

```json
{
  "status": "Draft rejected and archived successfully.",
  "audit_trail": {
    "draft_id": 7,
    "raw_intel_id": 42,
    "decision": "rejected",
    "reviewer_notes": "YARA strings too generic — $s1 matches benign software.",
    "reviewed_at": "2026-03-26T14:35:02+00:00"
  },
  "tip": "Rejected drafts are archived and can be reviewed with: SELECT id, reviewer_notes FROM draft_analysis WHERE status = 'rejected'"
}
```

### Common Errors

| Response | Cause |
|---|---|
| `Draft id=N not found.` | Invalid `draft_id` |
| `Draft id=N is already 'approved'...` | Draft was already decided; cannot re-decide |

---

## End-to-End Investigation Example

```
Investigator: "Show me the latest ransomware leads"

→ fetch_threat_leads(urgency="HIGH", keyword="ransomware")
← Returns: [{ "id": 42, "title": "LockBit 3.0 Incident...", ... }]

Investigator: "Generate a detection rule for article 42"

→ draft_threat_analysis(raw_intel_id=42)
← Returns: { "draft_id": 7, "draft_yara": "rule AegisLink_LockBit3...", "ttp_mapping": [...] }

[Investigator reads YARA rule — notices it uses confirmed IOCs]

Investigator: "This looks accurate, approve it with notes"

→ confirm_threat_analysis(
     draft_id=7,
     decision="approved",
     reviewer_notes="Hashes match VirusTotal samples from 2024-03"
   )
← Returns: { "status": "Draft approved and committed successfully.", "audit_trail": {...} }
```

---

## Error Reference

| Error Text | Tool | Cause |
|---|---|---|
| `Database is locked by another process.` | All | Brain is writing; retry in a few seconds |
| `Database unavailable: ...` | All | DB file missing or corrupted |
| `No threat leads found (...)` | `fetch_threat_leads` | No matching rows; broaden filters |
| `Article id=N not found` | `draft_threat_analysis` | Wrong ID |
| `Article id=N has not been enriched yet` | `draft_threat_analysis` | Run Brain first |
| `Draft generation failed` | `draft_threat_analysis` | Claude API or JSON parse error; retry |
| `Draft id=N not found` | `confirm_threat_analysis` | Wrong draft_id |
| `Draft id=N is already '...'` | `confirm_threat_analysis` | Already confirmed; cannot re-decide |
| `decision must be 'approved' or 'rejected'` | `confirm_threat_analysis` | Invalid decision value |
