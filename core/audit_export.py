"""
Reading the audit log out of Jnvoy: date filters and three formats (JSON, CSV, NDJSON).

The audit log holds counts and types only, never text. An export is meant for a compliance team
or a log system, so two things matter beyond the data itself:
  * NDJSON (one JSON object per line) is what log tools such as Splunk, Elastic and Datadog ingest;
  * a CSV opened in a spreadsheet must not run a formula. The model name in a row is chosen by the
    caller, so a value like =HYPERLINK(...) is neutralised with a leading apostrophe.
"""

import csv
import io
import json
from datetime import date, datetime, time, timedelta, timezone
from typing import Optional

from fastapi import HTTPException
from fastapi.responses import Response

MAX_JSON_ROWS = 1000
MAX_EXPORT_ROWS = 5000
FORMATS = ("json", "csv", "ndjson")

CSV_COLUMNS = ["audit_id", "timestamp", "provider", "model", "latency_ms", "cache_hit",
               "total_pii", "pii_detected", "reply_findings", "sensitive_data_transmitted"]


def bad_request(error: str, message: str) -> HTTPException:
    return HTTPException(status_code=422, detail={"error": error, "message": message})


def parse_when(value: Optional[str], name: str, end_of_day: bool = False) -> Optional[datetime]:
    """
    A date ("2026-10-01") or a date and time ("2026-10-01T09:30:00Z"). Times without a zone are UTC.
    A bare date used as an upper bound means the end of that day, so `to=2026-10-31` includes the 31st.
    """
    if value is None or not str(value).strip():
        return None
    text = str(value).strip()
    try:
        if len(text) == 10:
            day = date.fromisoformat(text)
            moment = datetime.combine(day, time.min, tzinfo=timezone.utc)
            return moment + timedelta(days=1) - timedelta(microseconds=1) if end_of_day else moment
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise bad_request("invalid_date", f"'{name}' must be a date like 2026-10-01 or a time like "
                                          "2026-10-01T09:30:00Z.")
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def parse_range(since: Optional[str], until: Optional[str]):
    start = parse_when(since, "from")
    end = parse_when(until, "to", end_of_day=True)
    if start and end and start > end:
        raise bad_request("invalid_range", "'from' must not be later than 'to'.")
    return start, end


def check_format(fmt: str) -> str:
    fmt = (fmt or "json").lower()
    if fmt not in FORMATS:
        raise bad_request("invalid_format", "format must be json, csv or ndjson")
    return fmt


def clamp_limit(limit: int, fmt: str) -> int:
    return max(1, min(limit, MAX_JSON_ROWS if fmt == "json" else MAX_EXPORT_ROWS))


def in_range(entry: dict, start: Optional[datetime], end: Optional[datetime]) -> bool:
    """For the in-memory log, which is used when no database is configured."""
    if start is None and end is None:
        return True
    try:
        when = datetime.fromisoformat(str(entry.get("timestamp")))
    except ValueError:
        return False
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (start is None or when >= start) and (end is None or when <= end)


def csv_safe(value):
    """Stops a spreadsheet from running text as a formula."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def event(entry: dict) -> dict:
    """One audit entry as a flat event, the same shape in every format that is not plain JSON."""
    return {
        "event": "jnvoy.audit",
        "audit_id": entry.get("audit_id"),
        "timestamp": entry.get("timestamp"),
        "provider": entry.get("provider"),
        "model": entry.get("model"),
        "latency_ms": entry.get("latency_ms"),
        "cache_hit": bool(entry.get("cache_hit")),
        "total_pii": entry.get("total_pii", entry.get("total_pii_instances", 0)),
        "pii_detected": entry.get("pii_detected") or {},
        "reply_findings": entry.get("output_detected") or {},
        "sensitive_data_transmitted": bool(entry.get("sensitive_data_transmitted", False)),
    }


def to_csv(entries: list) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(CSV_COLUMNS)
    for e in entries:
        ev = event(e)
        writer.writerow([
            csv_safe(ev["audit_id"]), csv_safe(ev["timestamp"]), csv_safe(ev["provider"]),
            csv_safe(ev["model"]), ev["latency_ms"], ev["cache_hit"], ev["total_pii"],
            json.dumps(ev["pii_detected"], sort_keys=True),
            json.dumps(ev["reply_findings"], sort_keys=True),
            ev["sensitive_data_transmitted"],
        ])
    return out.getvalue()


def to_ndjson(entries: list) -> str:
    return "".join(json.dumps(event(e), sort_keys=True, ensure_ascii=False) + "\n" for e in entries)


def respond(data: dict, fmt: str, basename: str = "jnvoy_audit_log"):
    """
    The answer for a page of audit entries. JSON keeps its existing shape. CSV and NDJSON are
    downloads; X-Total-Count says how many entries match and X-Next-Offset where the next page
    starts (absent on the last page), so a script can fetch everything page by page.
    """
    if fmt == "json":
        return data
    entries = data["entries"]
    body = to_csv(entries) if fmt == "csv" else to_ndjson(entries)
    headers = {
        "Content-Disposition": f'attachment; filename="{basename}.{fmt}"',
        "X-Total-Count": str(data.get("total", len(entries))),
        "Cache-Control": "no-store",
    }
    next_offset = data.get("offset", 0) + len(entries)
    if next_offset < data.get("total", 0):
        headers["X-Next-Offset"] = str(next_offset)
    media = "text/csv" if fmt == "csv" else "application/x-ndjson"
    return Response(body, media_type=media, headers=headers)
