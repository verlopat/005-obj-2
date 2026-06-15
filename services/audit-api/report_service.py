"""Compliance report generation service."""
import csv
import hashlib
import io
import json
import logging
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import requests

from config import config
from query_service import query_service
from schemas import ComplianceReport, ComplianceStandard, EventRecord

logger = logging.getLogger(__name__)


class ReportService:
    def generate_report(
        self,
        standard: ComplianceStandard,
        start_time: datetime,
        end_time: datetime,
        asset_ids: Optional[List[str]] = None,
    ) -> ComplianceReport:
        """Generate a compliance report for the given standard and time window."""
        events: List[EventRecord] = []

        if asset_ids:
            for asset_id in asset_ids:
                events += query_service.query_audit_trail(
                    asset_id=asset_id, start_time=start_time, end_time=end_time,
                    page_size=config.max_query_results,
                )
        else:
            for severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                events += query_service.query_by_severity(
                    severity=severity, start_time=start_time, end_time=end_time,
                    page_size=config.max_query_results,
                )

        severity_counts = dict(Counter(e.severity for e in events))
        category_counts = dict(Counter(e.attack_category for e in events))
        high_conf = sum(1 for e in events if e.detection_confidence >= 0.9)

        report_dict = {
            "standard": standard.value,
            "generated_at": datetime.utcnow().isoformat(),
            "period_start": start_time.isoformat(),
            "period_end": end_time.isoformat(),
            "total_events": len(events),
            "events_by_severity": severity_counts,
            "events_by_category": category_counts,
            "high_confidence_events": high_conf,
            "integrity_violations": 0,
            "events": [e.dict() for e in events],
        }
        sha256 = hashlib.sha256(
            json.dumps(report_dict, sort_keys=True, default=str).encode()
        ).hexdigest()

        report = ComplianceReport(
            **{k: v for k, v in report_dict.items() if k != "events"},
            events=events,
            report_sha256=sha256,
            generated_at=datetime.utcnow(),
            period_start=start_time,
            period_end=end_time,
        )

        self._save_report(report, standard)
        return report

    def _save_report(self, report: ComplianceReport, standard: ComplianceStandard):
        output_dir = Path(config.reports_output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        filename = output_dir / f"{standard.value}_{report.generated_at.strftime('%Y%m%d_%H%M%S')}.json"
        with filename.open("w") as f:
            json.dump(report.dict(), f, indent=2, default=str)
        logger.info("Saved compliance report to %s", filename)

    def export_csv(self, events: List[EventRecord]) -> str:
        buf = io.StringIO()
        if not events:
            return ""
        writer = csv.DictWriter(buf, fieldnames=events[0].dict().keys())
        writer.writeheader()
        for e in events:
            writer.writerow(e.dict())
        return buf.getvalue()


report_service = ReportService()
