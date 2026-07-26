from __future__ import annotations

import csv
import io
from datetime import datetime

from ..models import DomainDetail, FileDetail, IpDetail, Report, UrlDetail

COLUMNS = [
    "indicator",
    "ioc_type",
    "verdict",
    "detections",
    "engines",
    "reputation",
    "tags",
    "first_seen",
    "last_seen",
    "context",
    "top_detection",
    "source_link",
    "retrieved_at",
]


def _isoformat(value: datetime | None) -> str:
    return value.isoformat(timespec="seconds") if value else ""


def _context(report: Report) -> str:
    detail = report.detail
    if isinstance(detail, FileDetail):
        parts = [detail.type_description, detail.threat_label]
        if detail.size is not None:
            parts.append(f"{detail.size} bytes")
        return " | ".join(part for part in parts if part)
    if isinstance(detail, IpDetail):
        parts = [detail.as_owner, detail.country, detail.network]
        if detail.abuseipdb:
            parts.append(f"AbuseIPDB {detail.abuseipdb.confidence_score}%")
        return " | ".join(part for part in parts if part)
    if isinstance(detail, DomainDetail):
        parts = [detail.registrar]
        if detail.created_at:
            parts.append(f"registered {detail.created_at.date().isoformat()}")
        return " | ".join(part for part in parts if part)
    if isinstance(detail, UrlDetail):
        parts = [detail.title, detail.final_url]
        if detail.response_code is not None:
            parts.append(f"HTTP {detail.response_code}")
        return " | ".join(part for part in parts if part)
    return ""


def _top_detection(report: Report) -> str:
    for vendor in report.vendors:
        if vendor.category in ("malicious", "suspicious") and vendor.result:
            return f"{vendor.engine}: {vendor.result}"
    return ""


def reports_to_csv(reports: list[Report]) -> str:
    """Render `reports` as CSV, one row per indicator.

    Args:
        reports: The reports to export, in the order they should appear.

    Returns:
        The CSV document, including its header row.
    """
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()

    for report in reports:
        writer.writerow(
            {
                "indicator": report.indicator,
                "ioc_type": report.ioc_type.value,
                "verdict": report.verdict.value,
                "detections": report.stats.flagged,
                "engines": report.stats.total,
                "reputation": report.reputation,
                "tags": ", ".join(report.tags),
                "first_seen": _isoformat(report.first_seen),
                "last_seen": _isoformat(report.last_seen),
                "context": _context(report),
                "top_detection": _top_detection(report),
                "source_link": report.source_link,
                "retrieved_at": _isoformat(report.retrieved_at),
            }
        )

    return buffer.getvalue()
