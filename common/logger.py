"""
common/logger.py — Aegis Link structured JSON logging factory.

Every module in the pipeline calls ``get_logger(__name__)`` instead of
``logging.getLogger``.  Each log record is emitted as a single-line JSON
object to stderr, making the output grep-able, jq-parseable, and ingestible
by any log aggregation stack (Splunk, Elastic, CloudWatch Logs Insights, etc.)

Log record shape
────────────────
{
  "timestamp":  "2026-03-26T14:05:01.234567+00:00",   // UTC ISO-8601
  "level":      "INFO",
  "logger":     "aegis.pulse",
  "message":    "Saved new article",
  "module":     "collector",
  "line":       202,
  // ...any extra fields passed via extra={} on the log call:
  "action":     "article_saved",
  "url":        "https://thedfirreport.com/...",
  "title":      "BumbleBee Zeros in on Meterpreter"
}

Usage
─────
    from common.logger import get_logger
    logger = get_logger("aegis.pulse")

    logger.info("Saved new article", extra={"action": "article_saved", "url": url})
    logger.warning("Fetch failed", extra={"action": "fetch_error", "url": url, "error": str(exc)})
    logger.error("Enrichment failed", exc_info=True, extra={"action": "enrich_error", "row_id": 42})
"""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

# Built-in LogRecord attributes that should NOT be forwarded as extra fields.
# This set is derived from the CPython source for logging.LogRecord.__init__.
_BUILTIN_KEYS = frozenset({
    "name", "msg", "args", "created", "filename", "funcName", "levelname",
    "levelno", "lineno", "module", "msecs", "message", "pathname",
    "process", "processName", "relativeCreated", "stack_info", "taskName",
    "thread", "threadName", "exc_info", "exc_text",
})


class _JSONFormatter(logging.Formatter):
    """Format each LogRecord as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        # Populate record.message so extra parsers see a clean string.
        record.message = record.getMessage()

        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level":     record.levelname,
            "logger":    record.name,
            "message":   record.message,
            "module":    record.module,
            "line":      record.lineno,
        }

        # Merge any caller-supplied extra={...} fields into the payload.
        for key, value in record.__dict__.items():
            if key not in _BUILTIN_KEYS and not key.startswith("_"):
                payload[key] = value

        # Append formatted exception traceback if present.
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str, ensure_ascii=False)


def get_logger(name: str, level: int = logging.DEBUG) -> logging.Logger:
    """
    Return a Logger that emits structured JSON to stderr.

    Calling this function multiple times with the same *name* is safe — the
    handler is only attached once, preventing duplicate log lines.

    Args:
        name:  Logger name, e.g. ``"aegis.pulse"`` or ``__name__``.
        level: Minimum severity level. Defaults to DEBUG (all messages pass;
               the StreamHandler decides what to emit at INFO by default).

    Returns:
        A configured ``logging.Logger`` instance.
    """
    logger = logging.getLogger(name)

    # Guard: if handlers are already attached (e.g. module re-imported in
    # tests or notebooks), skip re-configuration to avoid duplicate output.
    if logger.handlers:
        return logger

    logger.setLevel(level)
    logger.propagate = False  # don't double-emit via the root logger

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.INFO)   # emit INFO and above by default
    handler.setFormatter(_JSONFormatter())
    logger.addHandler(handler)

    return logger
