"""Compliance report generation service."""
import csv
import json
import logging
import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import List

from config import config
from schemas import AuditEventRecord, ComplianceReport, ComplianceFramework

logger = logging.getLogger(__name__)


class ReportService:
    def __init__(self):
        self.output_dir = Path(config.report_output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        framework: ComplianceFramework,
        events: List[AuditEventRecord],
        period_start: datetime,
        period_end: datetime,
    ) -> ComplianceReport:
        by_severity: dict = defaultdict(int)
        by_category: dict = defaultdict(int)
        by_asset: dict = defaultdict(int)

        for e in events:
            by_severity[e.severity] += 1
            by_category[e.attack_category] += 1
            by_asset[e.asset_id] += 1

        report = ComplianceReport(
            framework=framework.value,
            generated_at=datetime.utcnow(),
            period_start=period_start,
            period_end=period_end,
            total_events=len(events),
            by_severity=dict(by_severity),
            by_category=dict(by_category),
            by_asset=dict(by_asset),
            integrity_pass_rate=1.0,
            events=events,
        )

        report_path = self._save_report(report, framework)
        report.report_path = str(report_path)
        logger.info("Generated %s report: %s events -> %s",
                    framework.value, len(events), report_path)
        return report

    def _save_report(self, report: ComplianceReport, framework: ComplianceFramework) -> Path:
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        stem = f"{framework.value}_{ts}"

        json_path = self.output_dir / f"{stem}.json"
        with json_path.open("w") as f:
            json.dump(report.dict(), f, indent=2, default=str)

        csv_path = self.output_dir / f"{stem}.csv"
        if report.events:
            keys = report.events[0].dict().keys()
            with csv_path.open("w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                for e in report.events:
                    writer.writerow(e.dict())

        return json_path


report_service = ReportService()
