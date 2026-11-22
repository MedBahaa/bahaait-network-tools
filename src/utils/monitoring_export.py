import csv
import json
from datetime import datetime
from typing import Any, Dict, List, Tuple

from core.monitoring_state import MonitoringPolicyConfig


def _fmt_dt(val: Any) -> str:
    if isinstance(val, datetime):
        return val.strftime("%Y-%m-%d %H:%M:%S")
    return str(val or "")


def export_incidents_csv(incidents: List[Dict[str, Any]], file_path: str) -> Tuple[bool, str]:
    try:
        headers = [
            "Incident UID",
            "Host Name",
            "IP Address",
            "Type",
            "Severity",
            "Status",
            "Start Time",
            "End Time",
            "Duration (s)",
            "Failed Probes",
            "Packet Loss (%)",
            "Pre-Outage Latency (ms)",
            "Recovery Latency (ms)",
            "Acknowledged",
            "Comments",
        ]
        with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for inc in incidents:
                writer.writerow([
                    inc.get("incident_uid", ""),
                    inc.get("host_name", ""),
                    inc.get("host_address", ""),
                    inc.get("incident_type", ""),
                    inc.get("severity", ""),
                    inc.get("status", ""),
                    _fmt_dt(inc.get("start_time")),
                    _fmt_dt(inc.get("end_time")),
                    round(float(inc.get("duration_seconds", 0.0)), 2),
                    inc.get("failed_probes", 0),
                    round(float(inc.get("packet_loss_pct", 0.0)), 2),
                    round(float(inc.get("avg_latency_before_ms", 0.0)), 2),
                    "" if inc.get("recovery_latency_ms") is None else round(float(inc["recovery_latency_ms"]), 2),
                    "Yes" if inc.get("acknowledged") else "No",
                    (inc.get("comments") or "").replace("\n", " | "),
                ])
        return True, ""
    except Exception as e:
        return False, str(e)


def export_incidents_pdf(incidents: List[Dict[str, Any]], file_path: str) -> Tuple[bool, str]:
    try:
        from utils.pdf_generator import PDFReportGenerator
        ok, res = PDFReportGenerator().generate_incidents_report(incidents, save_path=file_path)
        if ok:
            return True, ""
        return False, str(res)
    except Exception as e:
        return False, str(e)


def export_monitoring_config(
    global_policy: Dict[str, Any],
    host_policies: Dict[str, Dict[str, Any]],
    file_path: str,
) -> Tuple[bool, str]:
    try:
        payload = {
            "schema_version": "3.4.0",
            "exported_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "global_policy": global_policy,
            "host_policies": host_policies,
        }
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=4)
        return True, ""
    except Exception as e:
        return False, str(e)


def import_monitoring_config(file_path: str) -> Tuple[bool, Dict[str, Any], str]:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if not isinstance(raw, dict) or "global_policy" not in raw:
            return False, {}, "Invalid monitoring configuration file format."

        gp_cfg = MonitoringPolicyConfig.from_dict(raw["global_policy"])
        gp_cfg.validate()

        validated_hosts: Dict[str, Dict[str, Any]] = {}
        host_map = raw.get("host_policies", {})
        if not isinstance(host_map, dict):
            return False, {}, "Invalid host_policies section in configuration file."
        for addr, p_dict in host_map.items():
            cfg = MonitoringPolicyConfig.from_dict(p_dict)
            cfg.validate()
            validated_hosts[str(addr)] = cfg.to_dict()

        return True, {
            "global_policy": gp_cfg.to_dict(),
            "host_policies": validated_hosts,
        }, ""
    except Exception as e:
        return False, {}, str(e)
