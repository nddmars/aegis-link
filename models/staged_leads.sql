-- models/staged_leads.sql — Aegis-Analytics DBT Model
--
-- Purpose:
--   1. Deduplicates raw_intel by source_url, keeping the most recently
--      processed version of each article.
--   2. Flags "HIGH_URGENCY" reports whose title or extracted STIX content
--      contains threat keywords (Ransomware, Exploit).
--   3. Produces a clean, indexed view for Aegis-Bridge to query.
--
-- Materialization: view
--   The model is a VIEW so it always reflects the live state of raw_intel
--   without requiring a separate ETL table refresh. All dedup and flagging
--   logic runs at query time, keeping the pipeline lightweight.
--
-- Run:
--   cd models && dbt run --profiles-dir .
--   cd models && dbt test --profiles-dir .   (if tests are added)

{{ config(materialized='view') }}

WITH deduped AS (

    SELECT
        id,
        source_url,
        title,
        pub_date,
        raw_text,
        stix_json,
        processed_at,
        is_processed,
        -- Deduplicate: for each unique URL, keep the row with the most recent
        -- processed_at timestamp (in case an article was re-processed after a
        -- failed first attempt).  NULLS LAST ensures a NULL processed_at never
        -- displaces a legitimate processed row.
        ROW_NUMBER() OVER (
            PARTITION BY source_url
            ORDER BY processed_at DESC NULLS LAST, id DESC
        ) AS row_num

    FROM {{ source('aegis_raw', 'raw_intel') }}

    -- Only surface rows that have been successfully enriched by Aegis-Brain.
    WHERE is_processed = 1
      AND stix_json IS NOT NULL
      AND stix_json != ''

),

flagged AS (

    SELECT
        id,
        source_url,
        title,
        pub_date,
        raw_text,
        stix_json,
        processed_at,

        -- Urgency flag: SQLite LIKE is case-insensitive for ASCII so
        -- 'Ransomware' also matches 'ransomware', 'RANSOMWARE', etc.
        -- The check covers both the human-readable title and the machine-
        -- generated STIX JSON so that threat keywords extracted by Claude
        -- (e.g. a ransomware family name in an indicator label) also trigger
        -- the flag even when absent from the article title.
        CASE
            WHEN title     LIKE '%Ransomware%'
              OR title     LIKE '%Exploit%'
              OR stix_json LIKE '%Ransomware%'
              OR stix_json LIKE '%Exploit%'
            THEN 'HIGH_URGENCY'
            ELSE 'NORMAL'
        END AS urgency_flag

    FROM deduped
    WHERE row_num = 1

)

SELECT
    id,
    source_url,
    title,
    pub_date,
    raw_text,
    stix_json,
    processed_at,
    urgency_flag
FROM flagged
