from dataclasses import asdict, dataclass, field
from datetime import datetime
import threading
from typing import Any, Dict, List, Optional, Tuple

from core.snmp_client import SNMPClient, SNMPError
from core.snmp_profiles import STD_OIDS, SNMPVendorProfile
from utils.snmp_credentials import SNMPCredentials


POE_DETECTION_STATUS_MAP: Dict[int, str] = {
    1: "DISABLED",
    2: "SEARCHING",
    3: "DELIVERING",
    4: "FAULT",
    5: "TEST",
    6: "OTHER_FAULT",
}

POE_MAIN_STATUS_MAP: Dict[int, str] = {
    1: "ON",
    2: "OFF",
    3: "FAULTY",
}

POE_PRIORITY_MAP: Dict[int, str] = {
    1: "CRITICAL",
    2: "HIGH",
    3: "LOW",
}


@dataclass
class PoEPortStatus:
    port_key: str
    group_id: int
    port_id: int
    admin_enabled: bool = True
    detection_status: str = "DISABLED"
    priority: str = "LOW"
    power_watts: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PoESnapshot:
    device_id: int
    timestamp: datetime
    supported: bool = False
    budget_watts: float = 0.0
    consumed_watts: float = 0.0
    remaining_watts: float = 0.0
    utilization_pct: float = 0.0
    warn_pct: float = 80.0
    crit_pct: float = 90.0
    status: str = "UNSUPPORTED"
    overload: bool = False
    faulty_groups: List[int] = field(default_factory=list)
    active_ports: int = 0
    total_ports: int = 0
    ports: List[PoEPortStatus] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["ports"] = [p.to_dict() for p in self.ports]
        return data


def _to_float(val: Any) -> Optional[float]:
    if isinstance(val, bool) or val is None:
        return None
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def _parse_group_port(oid: str, base_oid: str) -> Tuple[int, int, str]:
    clean_oid = str(oid).lstrip(".")
    clean_base = str(base_oid).lstrip(".")
    if clean_oid.startswith(clean_base + "."):
        suffix = clean_oid[len(clean_base) + 1 :]
    else:
        suffix = clean_oid
    parts = [p for p in suffix.split(".") if p.isdigit()]
    if len(parts) >= 2:
        g = int(parts[-2])
        p = int(parts[-1])
        return g, p, f"{g}.{p}"
    if len(parts) == 1:
        p = int(parts[0])
        return 1, p, f"1.{p}"
    return 1, 0, suffix


class PoEMonitorCollector:
    """SNMP collector for POWER-ETHERNET-MIB and vendor-specific PoE power delivery metrics."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_snapshots: Dict[int, PoESnapshot] = {}

    def get_last_snapshot(self, device_id: int) -> Optional[PoESnapshot]:
        with self._lock:
            return self._last_snapshots.get(int(device_id))

    async def _walk_safe(
        self,
        client: SNMPClient,
        ip: str,
        port: int,
        creds: SNMPCredentials,
        base_oid: str,
        timeout_sec: float,
        retries: int,
    ) -> List[Tuple[str, Any]]:
        clean = str(base_oid).strip().lstrip(".")
        try:
            if clean.endswith(".0"):
                res = await client.get_oids(
                    ip, creds, [clean], port=port, timeout_sec=timeout_sec, retries=retries
                )
                return list(res.items())
            return await client.walk_oid(
                ip, creds, clean, port=port, timeout_sec=timeout_sec, retries=retries
            )
        except SNMPError:
            return []

    async def collect_poe(
        self,
        device_id: int,
        client: SNMPClient,
        ip: str,
        port: int,
        creds: SNMPCredentials,
        profile: SNMPVendorProfile,
        thresholds: Optional[Dict[str, Any]] = None,
        timeout_sec: float = 2.0,
        retries: int = 1,
        now_utc: Optional[datetime] = None,
    ) -> PoESnapshot:
        ts = now_utc or datetime.utcnow()
        thresh = dict(thresholds or {})

        budget_oids = list(profile.poe_budget_oids) or [STD_OIDS["pethMainPsePower"]]
        consumed_oids = list(profile.poe_consumed_oids) or [STD_OIDS["pethMainPseConsumptionPower"]]

        budget_watts = 0.0
        has_budget = False
        for oid in budget_oids:
            rows = await self._walk_safe(client, ip, port, creds, oid, timeout_sec, retries)
            vals = [v for _o, r in rows if (v := _to_float(r)) is not None and v >= 0]
            if vals and sum(vals) > 0:
                budget_watts = round(sum(vals), 2)
                has_budget = True
                break

        consumed_watts = 0.0
        has_consumed = False
        for oid in consumed_oids:
            rows = await self._walk_safe(client, ip, port, creds, oid, timeout_sec, retries)
            vals = [v for _o, r in rows if (v := _to_float(r)) is not None and v >= 0]
            if vals:
                consumed_watts = round(sum(vals), 2)
                has_consumed = True
                break

        oper_rows = await self._walk_safe(
            client, ip, port, creds, STD_OIDS["pethMainPseOperStatus"], timeout_sec, retries
        )
        faulty_groups: List[int] = []
        for oid_k, val in oper_rows:
            if (iv := _to_float(val)) is not None and int(iv) == 3:
                try:
                    faulty_groups.append(int(str(oid_k).rsplit(".", 1)[-1]))
                except ValueError:
                    pass

        thresh_rows = await self._walk_safe(
            client, ip, port, creds, STD_OIDS["pethMainPseUsageThreshold"], timeout_sec, retries
        )
        device_thresh_vals = [
            v for _o, r in thresh_rows if (v := _to_float(r)) is not None and 1.0 <= v <= 100.0
        ]
        device_usage_threshold = max(device_thresh_vals) if device_thresh_vals else None

        # Per-port PoE status & mW power consumption
        admin_rows = await self._walk_safe(
            client, ip, port, creds, STD_OIDS["pethPsePortAdminEnable"], timeout_sec, retries
        )
        detect_rows = await self._walk_safe(
            client, ip, port, creds, STD_OIDS["pethPsePortDetectionStatus"], timeout_sec, retries
        )
        prio_rows = await self._walk_safe(
            client, ip, port, creds, STD_OIDS["pethPsePortPowerPriority"], timeout_sec, retries
        )

        port_map: Dict[str, Dict[str, Any]] = {}
        port_id_to_keys: Dict[int, List[str]] = {}

        def _ensure_port(g: int, p: int, key: str) -> Dict[str, Any]:
            if key not in port_map:
                port_map[key] = {
                    "port_key": key,
                    "group_id": g,
                    "port_id": p,
                    "admin_enabled": True,
                    "detection_status": "DISABLED",
                    "priority": "LOW",
                    "power_watts": None,
                }
                port_id_to_keys.setdefault(p, []).append(key)
            return port_map[key]

        for oid_k, val in admin_rows:
            g, p, key = _parse_group_port(oid_k, STD_OIDS["pethPsePortAdminEnable"])
            entry = _ensure_port(g, p, key)
            if (iv := _to_float(val)) is not None:
                entry["admin_enabled"] = int(iv) == 1

        for oid_k, val in detect_rows:
            g, p, key = _parse_group_port(oid_k, STD_OIDS["pethPsePortDetectionStatus"])
            entry = _ensure_port(g, p, key)
            if (iv := _to_float(val)) is not None:
                entry["detection_status"] = POE_DETECTION_STATUS_MAP.get(int(iv), "DISABLED")

        for oid_k, val in prio_rows:
            g, p, key = _parse_group_port(oid_k, STD_OIDS["pethPsePortPowerPriority"])
            entry = _ensure_port(g, p, key)
            if (iv := _to_float(val)) is not None:
                entry["priority"] = POE_PRIORITY_MAP.get(int(iv), "LOW")

        for mw_oid in profile.poe_port_power_mw_oids:
            mw_rows = await self._walk_safe(client, ip, port, creds, mw_oid, timeout_sec, retries)
            if not mw_rows:
                continue
            for oid_k, val in mw_rows:
                mw = _to_float(val)
                if mw is None or mw < 0:
                    continue
                g, p, key = _parse_group_port(oid_k, mw_oid)
                if key in port_map:
                    port_map[key]["power_watts"] = round(mw / 1000.0, 2)
                elif p in port_id_to_keys and len(port_id_to_keys[p]) == 1:
                    port_map[port_id_to_keys[p][0]]["power_watts"] = round(mw / 1000.0, 2)
                else:
                    entry = _ensure_port(g, p, key)
                    entry["power_watts"] = round(mw / 1000.0, 2)
            break

        # Strict non-fabrication: if neither PoE budget nor any PoE port exists -> unsupported
        if not has_budget and not port_map:
            return PoESnapshot(device_id=device_id, timestamp=ts, supported=False, status="UNSUPPORTED")

        ports = [
            PoEPortStatus(**port_map[k])
            for k in sorted(port_map.keys(), key=lambda s: (port_map[s]["group_id"], port_map[s]["port_id"]))
        ]

        if not has_consumed and ports:
            port_watts = [p.power_watts for p in ports if p.power_watts is not None]
            if port_watts:
                consumed_watts = round(sum(port_watts), 2)

        remaining_watts = max(0.0, round(budget_watts - consumed_watts, 2)) if budget_watts > 0 else 0.0
        utilization_pct = round((consumed_watts / budget_watts) * 100.0, 2) if budget_watts > 0 else 0.0

        warn_pct = float(
            thresh.get("poe_warn_pct", device_usage_threshold if device_usage_threshold is not None else 80.0)
        )
        crit_pct = float(thresh.get("poe_crit_pct", 90.0))

        faulty_port = any(p.detection_status in ("FAULT", "OTHER_FAULT") for p in ports)
        overload = (utilization_pct >= crit_pct) or bool(faulty_groups) or faulty_port

        if overload:
            status = "CRITICAL"
        elif utilization_pct >= warn_pct:
            status = "WARNING"
        else:
            status = "NORMAL"

        active_ports = sum(
            1 for p in ports if p.detection_status == "DELIVERING" or (p.power_watts is not None and p.power_watts > 0)
        )

        return PoESnapshot(
            device_id=device_id,
            timestamp=ts,
            supported=True,
            budget_watts=budget_watts,
            consumed_watts=consumed_watts,
            remaining_watts=remaining_watts,
            utilization_pct=utilization_pct,
            warn_pct=warn_pct,
            crit_pct=crit_pct,
            status=status,
            overload=overload,
            faulty_groups=sorted(set(faulty_groups)),
            active_ports=active_ports,
            total_ports=len(ports),
            ports=ports,
        )

    async def collect(self, ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
        device_id = int(ctx["device_id"])
        due_flags: Dict[str, bool] = dict(ctx.get("due_flags") or {"poe": True})
        now_utc: datetime = ctx.get("now_utc") or datetime.utcnow()

        if not due_flags.get("poe", True):
            prev = self.get_last_snapshot(device_id)
            if prev is not None and prev.supported:
                ctx.setdefault("collector_snapshots", {})["poe"] = prev.to_dict()
                if prev.overload:
                    ctx.setdefault("degraded_reasons", []).append(
                        f"PoE CRITICAL/OVERLOAD: {prev.utilization_pct:.1f}% ({prev.consumed_watts:.1f}/{prev.budget_watts:.1f}W)"
                    )
                elif prev.status == "WARNING":
                    ctx.setdefault("degraded_reasons", []).append(
                        f"PoE WARNING: {prev.utilization_pct:.1f}%"
                    )
            return []

        snap = await self.collect_poe(
            device_id=device_id,
            client=ctx["client"],
            ip=ctx["ip_address"],
            port=int(ctx["port"]),
            creds=ctx["credentials"],
            profile=ctx["profile"],
            thresholds=ctx.get("thresholds"),
            timeout_sec=float(ctx.get("timeout_sec", 2.0)),
            retries=int(ctx.get("retries", 1)),
            now_utc=now_utc,
        )

        with self._lock:
            self._last_snapshots[device_id] = snap

        ctx.setdefault("collector_snapshots", {})["poe"] = snap.to_dict()
        if not snap.supported:
            return []

        if snap.overload:
            reason = (
                f"PoE CRITICAL/OVERLOAD: {snap.utilization_pct:.1f}% "
                f"({snap.consumed_watts:.1f}/{snap.budget_watts:.1f}W)"
            )
            ctx.setdefault("degraded_reasons", []).append(reason)
            ctx.setdefault("collector_events", []).append({
                "device_id": device_id,
                "ip_address": ctx["ip_address"],
                "event_type": "POE_OVERLOAD",
                "severity": "CRITICAL",
                "utilization_pct": snap.utilization_pct,
                "consumed_watts": snap.consumed_watts,
                "budget_watts": snap.budget_watts,
                "message": reason,
                "timestamp": now_utc,
            })
        elif snap.status == "WARNING":
            reason = (
                f"PoE WARNING: {snap.utilization_pct:.1f}% "
                f"({snap.consumed_watts:.1f}/{snap.budget_watts:.1f}W)"
            )
            ctx.setdefault("degraded_reasons", []).append(reason)
            ctx.setdefault("collector_events", []).append({
                "device_id": device_id,
                "ip_address": ctx["ip_address"],
                "event_type": "POE_WARNING",
                "severity": "WARNING",
                "utilization_pct": snap.utilization_pct,
                "consumed_watts": snap.consumed_watts,
                "budget_watts": snap.budget_watts,
                "message": reason,
                "timestamp": now_utc,
            })

        return [
            {
                "device_id": device_id,
                "metric_name": "poe_budget_watts",
                "metric_value": float(snap.budget_watts),
                "unit": "W",
                "timestamp": now_utc,
            },
            {
                "device_id": device_id,
                "metric_name": "poe_consumed_watts",
                "metric_value": float(snap.consumed_watts),
                "unit": "W",
                "timestamp": now_utc,
            },
            {
                "device_id": device_id,
                "metric_name": "poe_remaining_watts",
                "metric_value": float(snap.remaining_watts),
                "unit": "W",
                "timestamp": now_utc,
            },
            {
                "device_id": device_id,
                "metric_name": "poe_utilization_pct",
                "metric_value": float(snap.utilization_pct),
                "unit": "%",
                "timestamp": now_utc,
            },
            {
                "device_id": device_id,
                "metric_name": "poe_active_ports",
                "metric_value": float(snap.active_ports),
                "unit": "count",
                "timestamp": now_utc,
            },
        ]
