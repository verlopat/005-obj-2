"""Compliance report generator: ISO 27001, SOC 2, NIST SP 800-92."""
import csv
import io
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Literal

logger = logging.getLogger(__name__)

Framework = Literal["ISO27001", "SOC2", "NIST_SP_800_92", "GENERIC"]


def _iso_section(severity: str) -> str:
    mapping = {"CRITICAL": "A.16.1.4", "HIGH": "A.16.1.5", "MEDIUM": "A.16.1.1", "LOW": "A.16.1.2"}
    return mapping.get(severity.upper(), "A.16.1.1")


def _soc2_criteria(category: str) -> str:
    mapping = {"INTRUSION": "CC6.8", "DATA_EXFILTRATION": "CC6.6", "DDOS": "A1.2",
               "RANSOMWARE": "CC9.2", "PRIVILEGE_ESCALATION": "CC6.3", "LATERAL_MOVEMENT": "CC6.7"}
    return mapping.get(category.upper(), "CC7.2")


class ReportGenerator:
    def generate(
        self,
        events: List[Dict[str, Any]],
        framework: Framework,
        start_time: str,
        end_time: str,
        fmt: Literal["json", "csv"] = "json",
    ) -> bytes:
        annotated = [self._annotate(e, framework) for e in events]
        meta = {
            "framework": framework,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "period_start": start_time,
            "period_end": end_time,
            "total_events": len(annotated),
            "critical_count": sum(1 for e in events if e.get("severity") == "CRITICAL"),
            "high_count":     sum(1 for e in events if e.get("severity") == "HIGH"),
        }
        if fmt == "json":
            return json.dumps({"metadata": meta, "events": annotated},
                              indent=2, default=str).encode("utf-8")
        # CSV
        buf = io.StringIO()
        fieldnames = list(meta.keys()) + ["event_id", "asset_id", "severity",
                                          "attack_category", "timestamp",
                                          "framework_control", "description"]
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        for ev in annotated:
            row = {**meta, **{k: ev.get(k, "") for k in fieldnames if k not in meta}}
            writer.writerow(row)
        return buf.getvalue().encode("utf-8")

    def _annotate(self, event: Dict, framework: Framework) -> Dict:
        ev = dict(event)
        sev = ev.get("severity", "").upper()
        cat = ev.get("attackCategory", ev.get("attack_category", "")).upper()
        if framework == "ISO27001":
            ev["framework_control"] = _iso_section(sev)
        elif framework == "SOC2":
            ev["framework_control"] = _soc2_criteria(cat)
        elif framework == "NIST_SP_800_92":
            ev["framework_control"] = f"IR-{sev[:2]}"
        else:
            ev["framework_control"] = "N/A"
        return ev


report_generator = ReportGenerator()
