from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
import threading
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from core.anomaly_detector import StatisticalAnomalyDetector
from core.device_health import resolve_temperature_thresholds
from core.snmp_profiles import get_profile
from utils.db import DatabaseManager


_OPEN_ANOMALY_STATUSES = ("ACTIVE", "ACKNOWLEDGED")


@dataclass
class CorrelatedFinding:
    event_type: str
    title: str
    severity: str
    confidence: str
    probable_cause: str
    evidence: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    device_id: Optional[int] = None
    device_name: str = ""
    device_ip: str = ""
    detected_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _source_domain(source_tag: str) -> str:
    tag = str(source_tag or "").upper()
    if tag.startswith("SNMP"):
        return "SNMP"
    if tag.startswith("SYSLOG"):
        return "SYSLOG"
    if tag.startswith("PING"):
        return "PING"
    return tag or "OTHER"


def _compute_confidence(sources: List[str], strong_single: bool = False) -> str:
    unique = [s for s in dict.fromkeys(sources) if s]
    domains = {_source_domain(s) for s in unique}
    if len(unique) >= 3:
        return "HIGH"
    if len(unique) == 2:
        return "HIGH" if len(domains) >= 2 else "MEDIUM"
    if len(unique) == 1:
        return "MEDIUM" if strong_single else "LOW"
    return "LOW"


def _fmt_ts(ts: Any) -> str:
    if isinstance(ts, datetime):
        return ts.strftime("%Y-%m-%d %H:%M:%S")
    return str(ts or "")


class IntelligenceEngine:
    """Multi-source Network Intelligence & root-cause correlation engine (v3.5.0)."""

    def __init__(
        self,
        db: DatabaseManager,
        anomaly_detector: Optional[StatisticalAnomalyDetector] = None,
        correlation_window_minutes: int = 15,
        auto_resolve: bool = True,
    ) -> None:
        self.db = db
        self.detector = anomaly_detector or StatisticalAnomalyDetector()
        self.correlation_window_minutes = int(correlation_window_minutes)
        self.auto_resolve = bool(auto_resolve)
        self._lock = threading.RLock()

    def _gather_device_context(
        self,
        dev: Dict[str, Any],
        now_utc: datetime,
        snmp_snapshot: Optional[Dict[str, Any]] = None,
        ping_snapshot: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        dev_id = int(dev["id"])
        ip = str(dev["ip_address"])
        window_start = now_utc - timedelta(minutes=self.correlation_window_minutes)

        # 1. SNMP metrics (historical window + live snapshot merge)
        metric_rows = self.db.get_snmp_metrics(dev_id, since=window_start, limit=1000)
        latest_metrics: Dict[str, float] = {}
        for mr in metric_rows:
            if mr.get("metric_value") is not None:
                latest_metrics[mr["metric_name"]] = float(mr["metric_value"])

        if snmp_snapshot:
            for mk, mv in (snmp_snapshot.get("metrics") or {}).items():
                if isinstance(mv, (int, float)) and not isinstance(mv, bool):
                    latest_metrics[mk] = float(mv)

        # 2. SNMP interfaces + latest per-interface measurement
        iface_metas = self.db.get_snmp_interfaces(dev_id)
        iface_meas_rows = self.db.get_interface_measurements(device_id=dev_id, since=window_start, limit=500)
        latest_meas_by_iid: Dict[int, Dict[str, Any]] = {}
        for im in iface_meas_rows:
            latest_meas_by_iid[int(im["interface_id"])] = im

        interfaces: List[Dict[str, Any]] = []
        if snmp_snapshot and (snmp_snapshot.get("collector_snapshots") or {}).get("interfaces"):
            interfaces = list(snmp_snapshot["collector_snapshots"]["interfaces"])
        else:
            for meta in iface_metas:
                iid = int(meta["id"])
                m = latest_meas_by_iid.get(iid, {})
                interfaces.append({
                    "interface_id": iid,
                    "if_index": meta["if_index"],
                    "name": meta["name"] or meta["description"] or f"if{meta['if_index']}",
                    "admin_status": meta["admin_status"],
                    "oper_status": m.get("oper_status", meta["oper_status"]),
                    "in_mbps": float(m.get("in_mbps", 0.0) or 0.0),
                    "out_mbps": float(m.get("out_mbps", 0.0) or 0.0),
                    "utilization_pct": float(m.get("utilization_pct", 0.0) or 0.0),
                    "in_errors": int(m.get("in_errors", 0) or 0),
                    "out_errors": int(m.get("out_errors", 0) or 0),
                    "in_discards": int(m.get("in_discards", 0) or 0),
                    "out_discards": int(m.get("out_discards", 0) or 0),
                    "crc_errors": int(m.get("crc_errors", 0) or 0),
                })

        # 3. Syslog events in window
        syslog_rows = self.db.get_syslog_events(source_ip=ip, since=window_start, limit=200)

        # 4. Ping v3.4.0 measurements & incidents in window
        ping_rows = self.db.get_measurements(ip, since=window_start, limit=200)
        active_incident = self.db.get_active_incident(ip)

        ping_total = len(ping_rows)
        ping_failed = sum(1 for r in ping_rows if str(r.get("status", "")).upper() != "UP")
        valid_lats = [float(r["latency_ms"]) for r in ping_rows if r.get("latency_ms") is not None]
        ping_avg_lat = (sum(valid_lats) / len(valid_lats)) if valid_lats else 0.0
        ping_jitter = 0.0
        if len(valid_lats) >= 2:
            diffs = [abs(valid_lats[i] - valid_lats[i - 1]) for i in range(1, len(valid_lats))]
            ping_jitter = sum(diffs) / len(diffs)
        ping_loss_pct = (ping_failed / ping_total * 100.0) if ping_total > 0 else 0.0
        ping_state = "UNKNOWN"

        if ping_snapshot:
            ping_state = str(ping_snapshot.get("state", "UNKNOWN")).upper()
            if "packet_loss_pct" in ping_snapshot and ping_snapshot["packet_loss_pct"] is not None:
                ping_loss_pct = max(ping_loss_pct, float(ping_snapshot["packet_loss_pct"]))
            if "avg_latency_ms" in ping_snapshot and ping_snapshot["avg_latency_ms"] is not None:
                ping_avg_lat = max(ping_avg_lat, float(ping_snapshot["avg_latency_ms"]))
            if "jitter_ms" in ping_snapshot and ping_snapshot["jitter_ms"] is not None:
                ping_jitter = max(ping_jitter, float(ping_snapshot["jitter_ms"]))

        return {
            "device": dev,
            "now_utc": now_utc,
            "window_start": window_start,
            "metrics": latest_metrics,
            "interfaces": interfaces,
            "syslog": syslog_rows,
            "ping": {
                "state": ping_state,
                "total": ping_total,
                "failed": ping_failed,
                "loss_pct": round(ping_loss_pct, 2),
                "avg_latency_ms": round(ping_avg_lat, 2),
                "jitter_ms": round(ping_jitter, 2),
                "active_incident": active_incident,
            },
            "snmp_snapshot": snmp_snapshot or {},
        }

    def evaluate_device_findings(
        self,
        dev: Dict[str, Any],
        now_utc: Optional[datetime] = None,
        snmp_snapshot: Optional[Dict[str, Any]] = None,
        ping_snapshot: Optional[Dict[str, Any]] = None,
    ) -> List[CorrelatedFinding]:
        """Evaluate multi-source observed telemetry on a device without writing to DB."""
        ts = now_utc or datetime.utcnow()
        ctx = self._gather_device_context(dev, ts, snmp_snapshot=snmp_snapshot, ping_snapshot=ping_snapshot)

        dev_id = int(dev["id"])
        dev_name = str(dev.get("name") or dev["ip_address"])
        dev_ip = str(dev["ip_address"])
        metrics = ctx["metrics"]
        interfaces = ctx["interfaces"]
        syslog_rows = ctx["syslog"]
        ping_info = ctx["ping"]

        profile = get_profile(dev.get("profile_name", "generic_switch"))
        thresholds = dict(dev.get("thresholds") or {})
        cpu_warn = float(thresholds.get("cpu_warn_pct", profile.cpu_warn_pct))
        cpu_crit = float(thresholds.get("cpu_crit_pct", profile.cpu_crit_pct))
        mem_warn = float(thresholds.get("mem_warn_pct", profile.mem_warn_pct))
        mem_crit = float(thresholds.get("mem_crit_pct", profile.mem_crit_pct))
        temp_warn, temp_crit = resolve_temperature_thresholds(
            profile, str(dev.get("model") or ""), thresholds
        )
        poe_warn = float(thresholds.get("poe_warn_pct", 80.0))
        poe_crit = float(thresholds.get("poe_crit_pct", 90.0))

        # Index Syslog events by category (also determine active unresolved link downs vs newer link ups)
        syslog_by_cat: Dict[str, List[Dict[str, Any]]] = {}
        latest_link_up_ts: Optional[datetime] = None
        for ev in syslog_rows:
            cat = str(ev.get("event_category", "GENERAL")).upper()
            syslog_by_cat.setdefault(cat, []).append(ev)
            if cat == "LINK_UP":
                ev_ts = ev.get("timestamp")
                if isinstance(ev_ts, datetime) and (latest_link_up_ts is None or ev_ts > latest_link_up_ts):
                    latest_link_up_ts = ev_ts

        raw_link_down = syslog_by_cat.get("LINK_DOWN", []) + syslog_by_cat.get("FIREWALL_IF_DOWN", [])
        active_syslog_link_down: List[Dict[str, Any]] = []
        for ev in raw_link_down:
            ev_ts = ev.get("timestamp")
            if (
                latest_link_up_ts is not None
                and isinstance(ev_ts, datetime)
                and latest_link_up_ts > ev_ts
            ):
                # Only treat as superseded if no down interface exists in SNMP
                down_snmp_exist = any(
                    str(i.get("admin_status", "")).upper() == "UP"
                    and str(i.get("oper_status", "")).upper() == "DOWN"
                    for i in interfaces
                )
                if not down_snmp_exist:
                    continue
            active_syslog_link_down.append(ev)

        findings: List[CorrelatedFinding] = []

        # ── Rule 1: PHYSICAL_LINK_FAILURE ────────────────────────────────────────
        down_ifaces = [
            i
            for i in interfaces
            if str(i.get("admin_status", "")).upper() == "UP"
            and str(i.get("oper_status", "")).upper() == "DOWN"
        ]
        err_ifaces = [
            i
            for i in interfaces
            if (int(i.get("crc_errors") or 0) > 0)
            or (
                int(i.get("in_errors") or 0)
                + int(i.get("out_errors") or 0)
                + int(i.get("in_discards") or 0)
                + int(i.get("out_discards") or 0)
                >= 5
            )
        ]

        if down_ifaces or active_syslog_link_down:
            sources: List[str] = []
            evidence: List[str] = []

            if down_ifaces:
                sources.append("SNMP_INTERFACE")
                for i in down_ifaces[:5]:
                    evidence.append(
                        f"SNMP interface '{i['name']}' (ifIndex {i['if_index']}) observed "
                        f"admin_status=UP, oper_status=DOWN."
                    )

            if active_syslog_link_down:
                sources.append("SYSLOG")
                for ev in active_syslog_link_down[:5]:
                    evidence.append(
                        f"Syslog [{_fmt_ts(ev.get('timestamp'))}] {ev.get('event_category')}: {ev.get('message')}"
                    )

            if err_ifaces:
                sources.append("SNMP_ERRORS")
                for i in err_ifaces[:5]:
                    evidence.append(
                        f"SNMP interface '{i['name']}' counters observed: crc_errors={i.get('crc_errors', 0)}, "
                        f"in_errors={i.get('in_errors', 0)}, out_errors={i.get('out_errors', 0)}."
                    )

            has_ping_issue = (
                ping_info["loss_pct"] >= 20.0
                or ping_info["active_incident"] is not None
                or ping_info["state"] in ("DOWN", "DEGRADED")
            )
            if has_ping_issue:
                sources.append("PING")
                evidence.append(
                    f"Ping telemetry on {dev_ip}: packet_loss={ping_info['loss_pct']:.1f}% "
                    f"({ping_info['failed']}/{ping_info['total']} failed), avg_rtt={ping_info['avg_latency_ms']:.1f} ms."
                )

            is_fw_down = any(e.get("event_category") == "FIREWALL_IF_DOWN" for e in active_syslog_link_down)
            if (down_ifaces and (active_syslog_link_down or has_ping_issue)) or len(down_ifaces) >= 2 or is_fw_down:
                sev = "CRITICAL"
            else:
                sev = "WARNING"

            target_port = (
                down_ifaces[0]["name"]
                if down_ifaces
                else "interface"
            )
            confidence = _compute_confidence(sources, strong_single=bool(down_ifaces or is_fw_down))
            findings.append(
                CorrelatedFinding(
                    event_type="PHYSICAL_LINK_FAILURE",
                    title=f"Physical link failure detected on {dev_name} ({target_port})",
                    severity=sev,
                    confidence=confidence,
                    probable_cause=(
                        f"Probable physical link loss, disconnected/damaged cabling, faulty SFP transceiver, "
                        f"or peer port shutdown impacting {dev_name} ({target_port})."
                    ),
                    evidence=evidence,
                    recommended_actions=[
                        "Inspect physical cable patch connections and optical SFP RX/TX power levels.",
                        "Verify peer switch/firewall interface state and speed/duplex negotiation.",
                        "Check for CRC/FCS error increments or STP blocking in the Device Interfaces tab.",
                    ],
                    sources=sources,
                    device_id=dev_id,
                    device_name=dev_name,
                    device_ip=dev_ip,
                    detected_at=ts,
                )
            )

        # ── Rule 2: SWITCH_OVERLOAD ──────────────────────────────────────────────
        cpu_pct = metrics.get("cpu_pct")
        mem_pct = metrics.get("memory_pct")
        temp_c = metrics.get("temperature_max_c")
        max_util = metrics.get("max_interface_util_pct")
        syslog_overload = syslog_by_cat.get("HIGH_CPU", []) + syslog_by_cat.get("HARDWARE_THERMAL", [])

        overload_sources: List[str] = []
        overload_evidence: List[str] = []
        stress_count = 0

        if cpu_pct is not None and cpu_pct >= cpu_warn:
            overload_sources.append("SNMP_CPU")
            stress_count += 1
            overload_evidence.append(
                f"SNMP CPU utilization observed at {cpu_pct:.1f}% (warn={cpu_warn:.0f}%, crit={cpu_crit:.0f}%)."
            )
        if mem_pct is not None and mem_pct >= mem_warn:
            overload_sources.append("SNMP_MEMORY")
            stress_count += 1
            overload_evidence.append(
                f"SNMP memory utilization observed at {mem_pct:.1f}% (warn={mem_warn:.0f}%, crit={mem_crit:.0f}%)."
            )
        if temp_c is not None and temp_c >= temp_warn:
            overload_sources.append("SNMP_TEMP")
            stress_count += 1
            overload_evidence.append(
                f"SNMP max chassis temperature observed at {temp_c:.1f}°C (warn={temp_warn:.0f}°C, crit={temp_crit:.0f}°C)."
            )
        if max_util is not None and max_util >= 80.0:
            overload_sources.append("SNMP_TRAFFIC")
            stress_count += 1
            overload_evidence.append(
                f"SNMP peak interface utilization observed at {max_util:.1f}% (>= 80% threshold)."
            )
        if syslog_overload:
            overload_sources.append("SYSLOG")
            for ev in syslog_overload[:3]:
                overload_evidence.append(
                    f"Syslog [{_fmt_ts(ev.get('timestamp'))}] {ev.get('event_category')}: {ev.get('message')}"
                )
        if (
            ping_info["avg_latency_ms"] >= 100.0
            or ping_info["jitter_ms"] >= 30.0
            or (ping_info["total"] > 0 and ping_info["loss_pct"] >= 10.0)
        ):
            overload_sources.append("PING")
            overload_evidence.append(
                f"Ping response degradation on {dev_ip}: avg_rtt={ping_info['avg_latency_ms']:.1f} ms, "
                f"jitter={ping_info['jitter_ms']:.1f} ms, loss={ping_info['loss_pct']:.1f}%."
            )

        cpu_critical = cpu_pct is not None and cpu_pct >= cpu_crit
        mem_critical = mem_pct is not None and mem_pct >= mem_crit
        has_non_syslog_stress = stress_count >= 1 or ("PING" in overload_sources)
        trigger_overload = (
            (stress_count >= 2)
            or cpu_critical
            or mem_critical
            or (bool(syslog_overload) and has_non_syslog_stress)
        )

        if trigger_overload:
            if cpu_critical or mem_critical or len(overload_sources) >= 3:
                sev = "CRITICAL"
            else:
                sev = "WARNING"
            confidence = _compute_confidence(overload_sources, strong_single=(cpu_critical or mem_critical))
            findings.append(
                CorrelatedFinding(
                    event_type="SWITCH_OVERLOAD",
                    title=f"Resource / traffic overload on {dev_name}",
                    severity=sev,
                    confidence=confidence,
                    probable_cause=(
                        f"Probable control-plane overload, traffic saturation, or thermal stress "
                        f"impacting forwarding performance on {dev_name}."
                    ),
                    evidence=overload_evidence,
                    recommended_actions=[
                        "Inspect top CPU processes, spanning-tree topology churn, or broadcast/multicast storms.",
                        "Identify congested uplinks in the Device Interfaces & Traffic tabs.",
                        "Verify chassis cooling/airflow if temperature thresholds were breached.",
                    ],
                    sources=overload_sources,
                    device_id=dev_id,
                    device_name=dev_name,
                    device_ip=dev_ip,
                    detected_at=ts,
                )
            )

        # ── Rule 3: POE_BUDGET_EXHAUSTION ────────────────────────────────────────
        poe_util = metrics.get("poe_utilization_pct")
        poe_budget = metrics.get("poe_budget_watts")
        poe_consumed = metrics.get("poe_consumed_watts")
        poe_snap = (ctx["snmp_snapshot"].get("collector_snapshots") or {}).get("poe") or {}
        poe_snap_overload = bool(poe_snap.get("overload", False))
        syslog_poe = syslog_by_cat.get("POE_OVERLOAD", [])

        poe_breach = (poe_util is not None and poe_util >= poe_warn) or poe_snap_overload
        if poe_breach or syslog_poe:
            poe_sources: List[str] = []
            poe_evidence: List[str] = []
            if poe_breach:
                poe_sources.append("SNMP_POE")
                if poe_budget is not None and poe_consumed is not None and poe_util is not None:
                    poe_evidence.append(
                        f"SNMP PoE consumption observed at {poe_consumed:.1f}W / {poe_budget:.1f}W "
                        f"({poe_util:.1f}%, warn={poe_warn:.0f}%, crit={poe_crit:.0f}%)."
                    )
                elif poe_snap_overload:
                    poe_evidence.append("SNMP PoE collector reported PSE overload or port fault.")
            if syslog_poe:
                poe_sources.append("SYSLOG")
                for ev in syslog_poe[:4]:
                    poe_evidence.append(
                        f"Syslog [{_fmt_ts(ev.get('timestamp'))}] POE_OVERLOAD: {ev.get('message')}"
                    )

            sev = (
                "CRITICAL"
                if ((poe_util is not None and poe_util >= poe_crit) or poe_snap_overload or bool(syslog_poe))
                else "WARNING"
            )
            confidence = _compute_confidence(poe_sources, strong_single=True)
            findings.append(
                CorrelatedFinding(
                    event_type="POE_BUDGET_EXHAUSTION",
                    title=f"PoE power budget exhaustion / overload on {dev_name}",
                    severity=sev,
                    confidence=confidence,
                    probable_cause=(
                        f"Probable PoE power budget saturation or faulty powered device (PD) draw "
                        f"causing power denial or port shutdowns on {dev_name}."
                    ),
                    evidence=poe_evidence,
                    recommended_actions=[
                        "Inspect per-port PoE power draw and fault status in the Device PoE tab.",
                        "Verify PoE power priorities (critical/high/low) and shed non-essential PDs or relocate APs/cameras.",
                    ],
                    sources=poe_sources,
                    device_id=dev_id,
                    device_name=dev_name,
                    device_ip=dev_ip,
                    detected_at=ts,
                )
            )

        # ── Rule 4: UNEXPECTED_REBOOT ────────────────────────────────────────────
        last_reboot_at = ctx["snmp_snapshot"].get("last_reboot_at") or dev.get("last_reboot_at")
        snmp_reboot_flag = bool(
            (ctx["snmp_snapshot"].get("collector_snapshots") or {}).get("health", {}).get("reboot_detected")
        )
        snmp_reboot_recent = snmp_reboot_flag or (
            isinstance(last_reboot_at, datetime)
            and (ts - last_reboot_at).total_seconds() <= (self.correlation_window_minutes * 60.0)
            and (ts - last_reboot_at).total_seconds() >= -60.0
        )
        syslog_reboots = syslog_by_cat.get("REBOOT", [])

        if snmp_reboot_recent or syslog_reboots:
            rb_sources: List[str] = []
            rb_evidence: List[str] = []
            if snmp_reboot_recent:
                rb_sources.append("SNMP_UPTIME")
                uptime_sec = metrics.get("uptime_sec")
                rb_evidence.append(
                    f"SNMP sysUpTime drop / reboot recorded at {_fmt_ts(last_reboot_at or ts)}"
                    + (f" (current uptime={uptime_sec:.0f}s)." if uptime_sec is not None else ".")
                )
            if syslog_reboots:
                rb_sources.append("SYSLOG")
                for ev in syslog_reboots[:3]:
                    rb_evidence.append(
                        f"Syslog [{_fmt_ts(ev.get('timestamp'))}] REBOOT: {ev.get('message')}"
                    )
            if ping_info["failed"] > 0 or ping_info["active_incident"] is not None:
                rb_sources.append("PING")
                rb_evidence.append(
                    f"Ping telemetry observed {ping_info['failed']}/{ping_info['total']} failed probes "
                    f"({ping_info['loss_pct']:.1f}% loss) on {dev_ip}."
                )

            confidence = _compute_confidence(rb_sources, strong_single=True)
            findings.append(
                CorrelatedFinding(
                    event_type="UNEXPECTED_REBOOT",
                    title=f"Unexpected device reboot detected on {dev_name}",
                    severity="CRITICAL",
                    confidence=confidence,
                    probable_cause=(
                        f"Probable unscheduled power interruption, watchdog crash, or manual reload "
                        f"causing a sysUpTime reset on {dev_name}."
                    ),
                    evidence=rb_evidence,
                    recommended_actions=[
                        "Verify UPS/PSU power redundancy and check Syslog reload reason.",
                        "Inspect crashinfo/coredump files and running configuration persistence (saved vs running).",
                    ],
                    sources=rb_sources,
                    device_id=dev_id,
                    device_name=dev_name,
                    device_ip=dev_ip,
                    detected_at=ts,
                )
            )

        # ── Rule 5: INTERFACE_ERROR_DEGRADATION ──────────────────────────────────
        active_err_up_ifaces = [
            i for i in err_ifaces if str(i.get("oper_status", "")).upper() != "DOWN"
        ]
        syslog_topo = syslog_by_cat.get("PORT_SECURITY", []) + syslog_by_cat.get("STP_CHANGE", [])
        if active_err_up_ifaces or syslog_topo:
            er_sources: List[str] = []
            er_evidence: List[str] = []
            if active_err_up_ifaces:
                er_sources.append("SNMP_ERRORS")
                for i in active_err_up_ifaces[:4]:
                    er_evidence.append(
                        f"SNMP interface '{i['name']}' (oper={i.get('oper_status')}) observed "
                        f"crc_errors={i.get('crc_errors', 0)}, in_errors={i.get('in_errors', 0)}, "
                        f"in_discards={i.get('in_discards', 0)}."
                    )
            if syslog_topo:
                er_sources.append("SYSLOG")
                for ev in syslog_topo[:4]:
                    er_evidence.append(
                        f"Syslog [{_fmt_ts(ev.get('timestamp'))}] {ev.get('event_category')}: {ev.get('message')}"
                    )
            if ping_info["loss_pct"] >= 5.0 or ping_info["jitter_ms"] >= 30.0:
                er_sources.append("PING")
                er_evidence.append(
                    f"Ping quality degradation on {dev_ip}: loss={ping_info['loss_pct']:.1f}%, "
                    f"jitter={ping_info['jitter_ms']:.1f} ms."
                )

            sev = "CRITICAL" if any(e.get("event_category") == "PORT_SECURITY" for e in syslog_topo) else "WARNING"
            confidence = _compute_confidence(er_sources, strong_single=bool(syslog_topo or len(active_err_up_ifaces) > 0))
            findings.append(
                CorrelatedFinding(
                    event_type="INTERFACE_ERROR_DEGRADATION",
                    title=f"Interface errors / Layer-2 anomaly on {dev_name}",
                    severity=sev,
                    confidence=confidence,
                    probable_cause=(
                        f"Probable duplex mismatch, marginal cabling/optics, STP topology churn, "
                        f"or port-security violation degrading packet integrity on {dev_name}."
                    ),
                    evidence=er_evidence,
                    recommended_actions=[
                        "Check affected interface speed/duplex and replace suspect patch cords or SFPs.",
                        "Review spanning-tree root bridge changes or MAC address violations in Syslog.",
                    ],
                    sources=er_sources,
                    device_id=dev_id,
                    device_name=dev_name,
                    device_ip=dev_ip,
                    detected_at=ts,
                )
            )

        # ── Rule 6: SYSLOG_SECURITY_BURST ────────────────────────────────────────
        auth_fails = syslog_by_cat.get("AUTH_FAIL", [])
        critical_syslogs = [
            ev
            for ev in syslog_rows
            if int(ev.get("severity", 6)) <= 2
            and str(ev.get("event_category", "GENERAL"))
            not in ("LINK_DOWN", "FIREWALL_IF_DOWN", "POE_OVERLOAD", "REBOOT", "PORT_SECURITY", "STP_CHANGE")
        ]
        if len(auth_fails) >= 5 or len(critical_syslogs) >= 3:
            sec_evidence: List[str] = []
            if len(auth_fails) >= 5:
                sec_evidence.append(
                    f"Observed {len(auth_fails)} authentication failure Syslog events from {dev_ip} "
                    f"within {self.correlation_window_minutes} min."
                )
            for ev in (auth_fails + critical_syslogs)[:4]:
                sec_evidence.append(
                    f"Syslog [{_fmt_ts(ev.get('timestamp'))}] sev={ev.get('severity_name')}: {ev.get('message')}"
                )
            sev = "CRITICAL" if len(auth_fails) >= 10 or any(int(e.get("severity", 6)) == 0 for e in critical_syslogs) else "WARNING"
            findings.append(
                CorrelatedFinding(
                    event_type="SYSLOG_SECURITY_BURST",
                    title=f"Security / critical Syslog burst on {dev_name}",
                    severity=sev,
                    confidence=_compute_confidence(["SYSLOG"], strong_single=True),
                    probable_cause=(
                        f"Probable brute-force login attempt, misconfigured management polling credential, "
                        f"or critical subsystem fault reported via Syslog on {dev_name}."
                    ),
                    evidence=sec_evidence,
                    recommended_actions=[
                        "Identify offending source IP/username in the Syslog Monitor view.",
                        "Verify SSH/TACACS+/RADIUS ACLs and credential rotation.",
                    ],
                    sources=["SYSLOG"],
                    device_id=dev_id,
                    device_name=dev_name,
                    device_ip=dev_ip,
                    detected_at=ts,
                )
            )

        return findings

    def _persist_or_update_finding(
        self,
        finding_dict: Dict[str, Any],
        open_by_type: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        etype = finding_dict["event_type"]
        existing = open_by_type.get(etype)
        if existing is not None:
            updated = self.db.update_network_anomaly(
                existing["id"],
                {
                    "title": finding_dict["title"],
                    "severity": finding_dict["severity"],
                    "confidence": finding_dict["confidence"],
                    "probable_cause": finding_dict["probable_cause"],
                    "evidence": finding_dict["evidence"],
                    "recommended_actions": finding_dict["recommended_actions"],
                },
            )
            return updated or existing

        created = self.db.create_network_anomaly({
            "anomaly_uid": f"ANOM-{uuid.uuid4().hex[:10].upper()}",
            "device_id": finding_dict.get("device_id"),
            "device_name": finding_dict.get("device_name", ""),
            "device_ip": finding_dict.get("device_ip", ""),
            "event_type": etype,
            "title": finding_dict["title"],
            "severity": finding_dict["severity"],
            "confidence": finding_dict["confidence"],
            "probable_cause": finding_dict["probable_cause"],
            "evidence": finding_dict["evidence"],
            "recommended_actions": finding_dict["recommended_actions"],
            "status": "ACTIVE",
            "detected_at": finding_dict.get("detected_at") or datetime.utcnow(),
        })
        open_by_type[etype] = created
        return created

    def ingest_metric_sample(
        self,
        device: Dict[str, Any],
        metric_name: str,
        value: float,
        timestamp: Optional[datetime] = None,
    ) -> Optional[Dict[str, Any]]:
        """Evaluate a numeric metric through the statistical anomaly detector and persist if confirmed."""
        dev_id = int(device["id"])
        enabled = bool(device.get("anomaly_detection_enabled", True))
        self.detector.set_device_enabled(dev_id, enabled)

        anom = self.detector.evaluate_sample(
            device_id=dev_id,
            metric_name=metric_name,
            value=value,
            device_name=str(device.get("name") or device["ip_address"]),
            device_ip=str(device["ip_address"]),
            timestamp=timestamp,
            thresholds_override=device.get("thresholds"),
        )
        if anom is None:
            return None

        event_type = f"ANOMALY_{metric_name.upper()}"
        with self._lock:
            existing_rows = self.db.get_network_anomalies(device_id=dev_id, limit=200)
            open_by_type = {
                r["event_type"]: r
                for r in existing_rows
                if r["status"] in _OPEN_ANOMALY_STATUSES
            }
            return self._persist_or_update_finding(
                {
                    "device_id": dev_id,
                    "device_name": anom.device_name,
                    "device_ip": anom.device_ip,
                    "event_type": event_type,
                    "title": anom.title,
                    "severity": anom.severity,
                    "confidence": "MEDIUM",
                    "probable_cause": anom.probable_cause,
                    "evidence": anom.evidence,
                    "recommended_actions": anom.recommended_actions,
                    "detected_at": anom.detected_at,
                },
                open_by_type,
            )

    def correlate_device(
        self,
        device_id: int,
        now_utc: Optional[datetime] = None,
        snmp_snapshot: Optional[Dict[str, Any]] = None,
        ping_snapshot: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Run multi-source correlation on one SNMP device with deduplication and optional auto-resolve."""
        dev = self.db.get_snmp_device(int(device_id))
        if dev is None:
            return []

        ts = now_utc or datetime.utcnow()
        findings = self.evaluate_device_findings(
            dev, now_utc=ts, snmp_snapshot=snmp_snapshot, ping_snapshot=ping_snapshot
        )

        with self._lock:
            existing_rows = self.db.get_network_anomalies(device_id=int(device_id), limit=200)
            open_by_type = {
                r["event_type"]: r
                for r in existing_rows
                if r["status"] in _OPEN_ANOMALY_STATUSES
            }

            persisted: List[Dict[str, Any]] = []
            seen_types: Set[str] = set()
            for f in findings:
                seen_types.add(f.event_type)
                persisted.append(self._persist_or_update_finding(f.to_dict(), open_by_type))

            if self.auto_resolve:
                for etype, row in open_by_type.items():
                    if etype.startswith("ANOMALY_"):
                        continue
                    if etype not in seen_types:
                        self.db.update_network_anomaly(
                            row["id"], {"status": "RESOLVED", "resolved_at": ts}
                        )

            return persisted

    def correlate_all_devices(
        self,
        now_utc: Optional[datetime] = None,
        snmp_snapshots: Optional[Dict[int, Dict[str, Any]]] = None,
        ping_snapshots: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """Run correlation across all enabled SNMP devices."""
        ts = now_utc or datetime.utcnow()
        devices = self.db.get_snmp_devices(enabled_only=True)
        snaps = snmp_snapshots or {}
        pings = ping_snapshots or {}
        all_persisted: List[Dict[str, Any]] = []
        for dev in devices:
            dev_id = int(dev["id"])
            res = self.correlate_device(
                dev_id,
                now_utc=ts,
                snmp_snapshot=snaps.get(dev_id),
                ping_snapshot=pings.get(dev["ip_address"]),
            )
            all_persisted.extend(res)
        return all_persisted

    def acknowledge_anomaly(self, anomaly_id: int) -> Optional[Dict[str, Any]]:
        return self.db.update_network_anomaly(int(anomaly_id), {"status": "ACKNOWLEDGED"})

    def resolve_anomaly(self, anomaly_id: int) -> Optional[Dict[str, Any]]:
        return self.db.update_network_anomaly(
            int(anomaly_id), {"status": "RESOLVED", "resolved_at": datetime.utcnow()}
        )

    def get_infrastructure_summary(self) -> Dict[str, Any]:
        rows = self.db.get_network_anomalies(limit=500)
        open_rows = [r for r in rows if r["status"] in _OPEN_ANOMALY_STATUSES]
        by_type: Dict[str, int] = {}
        affected: Set[str] = set()
        crit_cnt = 0
        warn_cnt = 0
        info_cnt = 0

        for r in open_rows:
            sev = str(r.get("severity", "INFO")).upper()
            if sev == "CRITICAL":
                crit_cnt += 1
            elif sev == "WARNING":
                warn_cnt += 1
            else:
                info_cnt += 1
            et = str(r.get("event_type", "GENERAL"))
            by_type[et] = by_type.get(et, 0) + 1
            if r.get("device_ip"):
                affected.add(str(r["device_ip"]))

        return {
            "total_active": len(open_rows),
            "critical_count": crit_cnt,
            "warning_count": warn_cnt,
            "info_count": info_cnt,
            "affected_devices": len(affected),
            "by_event_type": by_type,
            "recent_anomalies": open_rows[:50],
        }
