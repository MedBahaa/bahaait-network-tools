from datetime import datetime, timedelta
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.snmp_client import SNMPClient, SNMPError, octet_to_mac
from core.snmp_profiles import STD_OIDS
from utils.db import DatabaseManager
from utils.snmp_credentials import SNMPCredentials


COUNTER32_MAX = 2**32
COUNTER64_MAX = 2**64

OPER_STATUS_MAP: Dict[int, str] = {
    1: "UP",
    2: "DOWN",
    3: "TESTING",
    4: "UNKNOWN",
    5: "DORMANT",
    6: "NOT_PRESENT",
    7: "DOWN",  # lowerLayerDown
}

ADMIN_STATUS_MAP: Dict[int, str] = {
    1: "UP",
    2: "DOWN",
    3: "TESTING",
}


def normalize_oper_status(raw: Any) -> str:
    """Normalize IF-MIB ifOperStatus into one of 6 canonical states."""
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        return OPER_STATUS_MAP.get(int(raw), "UNKNOWN")
    text = str(raw or "").strip().upper()
    if text.isdigit():
        return OPER_STATUS_MAP.get(int(text), "UNKNOWN")
    aliases = {
        "UP": "UP",
        "DOWN": "DOWN",
        "LOWERLAYERDOWN": "DOWN",
        "LOWER_LAYER_DOWN": "DOWN",
        "TESTING": "TESTING",
        "UNKNOWN": "UNKNOWN",
        "DORMANT": "DORMANT",
        "NOTPRESENT": "NOT_PRESENT",
        "NOT_PRESENT": "NOT_PRESENT",
    }
    return aliases.get(text, "UNKNOWN")


def normalize_admin_status(raw: Any) -> str:
    """Normalize IF-MIB ifAdminStatus into UP, DOWN, TESTING, or UNKNOWN."""
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        return ADMIN_STATUS_MAP.get(int(raw), "UNKNOWN")
    text = str(raw or "").strip().upper()
    if text.isdigit():
        return ADMIN_STATUS_MAP.get(int(text), "UNKNOWN")
    if text in ("UP", "DOWN", "TESTING"):
        return text
    return "UNKNOWN"


def _to_int(val: Any) -> Optional[int]:
    if isinstance(val, bool) or val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def compute_counter_delta(
    prev_val: Optional[int],
    curr_val: Optional[int],
    elapsed_sec: float,
    is_64bit: bool,
    speed_bps: int = 0,
    device_rebooted: bool = False,
    counter_discontinuity: bool = False,
) -> Tuple[Optional[int], str]:
    """Compute safe octet counter delta with strict 32/64-bit rollover, reset, and reboot guards."""
    if prev_val is None or curr_val is None:
        return None, "FIRST_SAMPLE"
    if elapsed_sec <= 0:
        return None, "INVALID_ELAPSED"
    if device_rebooted:
        return None, "REBOOT"
    if counter_discontinuity:
        return None, "DISCONTINUITY"

    if curr_val >= prev_val:
        return int(curr_val - prev_val), "OK"

    # Counter decreased without an explicit reboot/discontinuity: distinguish genuine rollover vs reset
    max_val = COUNTER64_MAX if is_64bit else COUNTER32_MAX
    wrap_delta = (max_val - prev_val) + curr_val

    if speed_bps > 0:
        max_plausible = max(1_000_000, int((speed_bps / 8.0) * elapsed_sec * 1.15))
    else:
        max_plausible = COUNTER32_MAX // 2

    if prev_val >= int(0.75 * max_val) and wrap_delta <= max_plausible:
        return int(wrap_delta), "ROLLOVER"

    return None, "COUNTER_RESET"


def compute_non_negative_error_delta(
    prev_val: Optional[int],
    curr_val: Optional[int],
    device_rebooted: bool = False,
    counter_discontinuity: bool = False,
) -> int:
    """Compute non-negative error/discard/CRC counter delta, suppressing resets and reboots."""
    if prev_val is None or curr_val is None or device_rebooted or counter_discontinuity:
        return 0
    if curr_val < prev_val:
        return 0
    return int(curr_val - prev_val)


def compute_traffic_mbps(delta_octets: Optional[int], elapsed_sec: float) -> float:
    """Convert octet delta over elapsed_sec into Mbps."""
    if delta_octets is None or delta_octets < 0 or elapsed_sec <= 0:
        return 0.0
    return round((delta_octets * 8.0) / float(elapsed_sec) / 1_000_000.0, 4)


def compute_utilization_pct(in_mbps: float, out_mbps: float, speed_bps: int) -> float:
    """Compute peak directional link utilization percentage relative to speed_bps."""
    if speed_bps <= 0:
        return 0.0
    speed_mbps = speed_bps / 1_000_000.0
    if speed_mbps <= 0:
        return 0.0
    return min(100.0, round((max(float(in_mbps), float(out_mbps)) / speed_mbps) * 100.0, 2))


def filter_interfaces(
    interfaces: List[Dict[str, Any]],
    mode: str = "ALL",
    high_util_pct: float = 80.0,
) -> List[Dict[str, Any]]:
    """Filter interface snapshot dicts by UI/analytical mode."""
    m = str(mode or "ALL").strip().upper()
    if m == "ALL":
        return list(interfaces)
    if m == "UP":
        return [i for i in interfaces if str(i.get("oper_status", "")).upper() == "UP"]
    if m == "DOWN":
        return [i for i in interfaces if str(i.get("oper_status", "")).upper() == "DOWN"]
    if m == "HIGH_UTILIZATION":
        return [i for i in interfaces if float(i.get("utilization_pct") or 0.0) >= float(high_util_pct)]
    if m == "ERRORS":
        return [
            i
            for i in interfaces
            if (
                int(i.get("in_errors") or 0)
                + int(i.get("out_errors") or 0)
                + int(i.get("in_discards") or 0)
                + int(i.get("out_discards") or 0)
                + int(i.get("crc_errors") or 0)
            )
            > 0
        ]
    if m == "OTHER":
        return [
            i
            for i in interfaces
            if str(i.get("oper_status", "")).upper() in ("TESTING", "DORMANT", "UNKNOWN", "NOT_PRESENT")
        ]
    return list(interfaces)


class InterfaceMonitorCollector:
    """Collector for IF-MIB + 64-bit ifXTable + EtherLike-MIB interface metrics and state transitions."""

    def __init__(self, clock_fn: Callable[[], float] = time.monotonic) -> None:
        self._clock_fn = clock_fn
        self._lock = threading.RLock()
        self._prev_state: Dict[Tuple[int, int], Dict[str, Any]] = {}
        self._last_snapshots: Dict[int, List[Dict[str, Any]]] = {}

    def get_last_snapshot(self, device_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._last_snapshots.get(int(device_id), [])]

    async def _walk_indexed(
        self,
        client: SNMPClient,
        ip: str,
        port: int,
        creds: SNMPCredentials,
        base_oid: str,
        timeout_sec: float,
        retries: int,
    ) -> Dict[int, Any]:
        try:
            rows = await client.walk_oid(
                ip, creds, base_oid, port=port, timeout_sec=timeout_sec, retries=retries
            )
        except SNMPError:
            return {}
        out: Dict[int, Any] = {}
        for oid_key, val in rows:
            try:
                idx = int(str(oid_key).rsplit(".", 1)[-1])
                out[idx] = val
            except (TypeError, ValueError):
                continue
        return out

    async def collect(self, ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
        device_id = int(ctx["device_id"])
        client: SNMPClient = ctx["client"]
        db: DatabaseManager = ctx["db"]
        ip: str = ctx["ip_address"]
        port: int = int(ctx["port"])
        creds: SNMPCredentials = ctx["credentials"]
        thresholds: Dict[str, Any] = dict(ctx.get("thresholds") or {})
        timeout_sec: float = float(ctx.get("timeout_sec", 2.0))
        retries: int = int(ctx.get("retries", 1))
        now_utc: datetime = ctx.get("now_utc") or datetime.utcnow()
        now_mono: float = float(self._clock_fn())
        uptime_ticks: Optional[int] = ctx.get("uptime_ticks")
        device_rebooted: bool = bool(ctx.get("reboot_detected", False))

        util_warn_pct = float(thresholds.get("iface_util_warn_pct", 80.0))
        util_crit_pct = float(thresholds.get("iface_util_crit_pct", 90.0))
        err_warn_delta = int(thresholds.get("iface_error_warn_delta", 5))
        crc_warn_delta = int(thresholds.get("iface_crc_warn_delta", 1))

        # Walk metadata & status tables
        if_index_map = await self._walk_indexed(client, ip, port, creds, STD_OIDS["ifIndex"], timeout_sec, retries)
        if_descr_map = await self._walk_indexed(client, ip, port, creds, STD_OIDS["ifDescr"], timeout_sec, retries)
        if_name_map = await self._walk_indexed(client, ip, port, creds, STD_OIDS["ifName"], timeout_sec, retries)
        if_oper_map = await self._walk_indexed(client, ip, port, creds, STD_OIDS["ifOperStatus"], timeout_sec, retries)
        if_admin_map = await self._walk_indexed(client, ip, port, creds, STD_OIDS["ifAdminStatus"], timeout_sec, retries)

        indices = sorted(
            set(if_index_map.keys())
            | set(if_descr_map.keys())
            | set(if_name_map.keys())
            | set(if_oper_map.keys())
            | set(if_admin_map.keys())
        )
        if not indices:
            with self._lock:
                self._last_snapshots[device_id] = []
            ctx.setdefault("collector_snapshots", {})["interfaces"] = []
            return []

        if_alias_map = await self._walk_indexed(client, ip, port, creds, STD_OIDS["ifAlias"], timeout_sec, retries)
        if_mac_map = await self._walk_indexed(client, ip, port, creds, STD_OIDS["ifPhysAddress"], timeout_sec, retries)
        if_speed_map = await self._walk_indexed(client, ip, port, creds, STD_OIDS["ifSpeed"], timeout_sec, retries)
        if_high_speed_map = await self._walk_indexed(client, ip, port, creds, STD_OIDS["ifHighSpeed"], timeout_sec, retries)
        if_last_chg_map = await self._walk_indexed(client, ip, port, creds, STD_OIDS["ifLastChange"], timeout_sec, retries)
        if_disc_map = await self._walk_indexed(
            client, ip, port, creds, STD_OIDS["ifCounterDiscontinuityTime"], timeout_sec, retries
        )

        # Prefer 64-bit counters; fall back to 32-bit where 64-bit is unavailable
        hc_in_map = await self._walk_indexed(client, ip, port, creds, STD_OIDS["ifHCInOctets"], timeout_sec, retries)
        hc_out_map = await self._walk_indexed(client, ip, port, creds, STD_OIDS["ifHCOutOctets"], timeout_sec, retries)
        in32_map = await self._walk_indexed(client, ip, port, creds, STD_OIDS["ifInOctets"], timeout_sec, retries)
        out32_map = await self._walk_indexed(client, ip, port, creds, STD_OIDS["ifOutOctets"], timeout_sec, retries)

        in_err_map = await self._walk_indexed(client, ip, port, creds, STD_OIDS["ifInErrors"], timeout_sec, retries)
        out_err_map = await self._walk_indexed(client, ip, port, creds, STD_OIDS["ifOutErrors"], timeout_sec, retries)
        in_disc_map = await self._walk_indexed(client, ip, port, creds, STD_OIDS["ifInDiscards"], timeout_sec, retries)
        out_disc_map = await self._walk_indexed(client, ip, port, creds, STD_OIDS["ifOutDiscards"], timeout_sec, retries)
        crc_map = await self._walk_indexed(client, ip, port, creds, STD_OIDS["dot3StatsFCSErrors"], timeout_sec, retries)

        meta_rows: List[Dict[str, Any]] = []
        computed_rows: List[Dict[str, Any]] = []
        iface_name_lookup: Dict[int, str] = {}
        degraded_reasons: List[str] = []
        events: List[Dict[str, Any]] = []

        up_count = 0
        down_count = 0
        total_in_mbps = 0.0
        total_out_mbps = 0.0
        total_errors_sum = 0
        max_util_pct = 0.0

        for idx in indices:
            descr = str(if_descr_map.get(idx, "") or "").strip()
            name = str(if_name_map.get(idx, "") or "").strip() or descr or f"if{idx}"
            alias = str(if_alias_map.get(idx, "") or "").strip()
            mac = octet_to_mac(if_mac_map.get(idx))
            admin_status = normalize_admin_status(if_admin_map.get(idx))
            oper_status = normalize_oper_status(if_oper_map.get(idx))

            high_mbps = _to_int(if_high_speed_map.get(idx)) or 0
            raw_speed_bps = _to_int(if_speed_map.get(idx)) or 0
            if high_mbps > 0:
                speed_bps = high_mbps * 1_000_000
                negotiated_mbps: Optional[float] = float(high_mbps)
            else:
                speed_bps = max(0, raw_speed_bps)
                negotiated_mbps = round(speed_bps / 1_000_000.0, 2) if speed_bps > 0 else None

            last_chg_ticks = _to_int(if_last_chg_map.get(idx))
            last_change_at: Optional[datetime] = None
            if uptime_ticks is not None and last_chg_ticks is not None and uptime_ticks >= last_chg_ticks:
                last_change_at = now_utc - timedelta(seconds=(uptime_ticks - last_chg_ticks) / 100.0)

            curr_in_64 = idx in hc_in_map and _to_int(hc_in_map.get(idx)) is not None
            curr_out_64 = idx in hc_out_map and _to_int(hc_out_map.get(idx)) is not None
            curr_in_octets = _to_int(hc_in_map.get(idx)) if curr_in_64 else _to_int(in32_map.get(idx))
            curr_out_octets = _to_int(hc_out_map.get(idx)) if curr_out_64 else _to_int(out32_map.get(idx))

            curr_in_err = _to_int(in_err_map.get(idx))
            curr_out_err = _to_int(out_err_map.get(idx))
            curr_in_disc = _to_int(in_disc_map.get(idx))
            curr_out_disc = _to_int(out_disc_map.get(idx))
            curr_crc = _to_int(crc_map.get(idx))
            curr_disc_ticks = _to_int(if_disc_map.get(idx))

            iface_name_lookup[idx] = name
            meta_rows.append({
                "if_index": idx,
                "name": name,
                "description": descr or name,
                "alias": alias,
                "mac_address": mac,
                "admin_status": admin_status,
                "oper_status": oper_status,
                "speed_bps": speed_bps,
                "negotiated_speed_mbps": negotiated_mbps,
                "last_change_ticks": last_chg_ticks,
                "last_change_at": last_change_at,
            })

            cache_key = (device_id, idx)
            with self._lock:
                prev = self._prev_state.get(cache_key)

            in_mbps = 0.0
            out_mbps = 0.0
            in_reason = "FIRST_SAMPLE"
            out_reason = "FIRST_SAMPLE"
            in_err_delta = 0
            out_err_delta = 0
            in_disc_delta = 0
            out_disc_delta = 0
            crc_delta = 0

            if prev is not None:
                utc_elapsed = (now_utc - prev["sample_utc"]).total_seconds()
                mono_elapsed = now_mono - prev["sample_mono"]
                elapsed_sec = max(mono_elapsed, utc_elapsed)

                prev_disc_ticks = prev.get("discontinuity_ticks")
                has_discontinuity = bool(
                    curr_disc_ticks is not None
                    and prev_disc_ticks is not None
                    and curr_disc_ticks != prev_disc_ticks
                    and curr_disc_ticks > 0
                )

                in_width_changed = prev.get("in_is_64bit") != curr_in_64
                out_width_changed = prev.get("out_is_64bit") != curr_out_64

                in_delta, in_reason = compute_counter_delta(
                    prev.get("in_octets"),
                    curr_in_octets,
                    elapsed_sec,
                    is_64bit=curr_in_64,
                    speed_bps=speed_bps,
                    device_rebooted=device_rebooted,
                    counter_discontinuity=has_discontinuity or in_width_changed,
                )
                out_delta, out_reason = compute_counter_delta(
                    prev.get("out_octets"),
                    curr_out_octets,
                    elapsed_sec,
                    is_64bit=curr_out_64,
                    speed_bps=speed_bps,
                    device_rebooted=device_rebooted,
                    counter_discontinuity=has_discontinuity or out_width_changed,
                )

                in_mbps = compute_traffic_mbps(in_delta, elapsed_sec)
                out_mbps = compute_traffic_mbps(out_delta, elapsed_sec)

                in_err_delta = compute_non_negative_error_delta(
                    prev.get("in_errors"), curr_in_err, device_rebooted, has_discontinuity
                )
                out_err_delta = compute_non_negative_error_delta(
                    prev.get("out_errors"), curr_out_err, device_rebooted, has_discontinuity
                )
                in_disc_delta = compute_non_negative_error_delta(
                    prev.get("in_discards"), curr_in_disc, device_rebooted, has_discontinuity
                )
                out_disc_delta = compute_non_negative_error_delta(
                    prev.get("out_discards"), curr_out_disc, device_rebooted, has_discontinuity
                )
                crc_delta = compute_non_negative_error_delta(
                    prev.get("crc_errors"), curr_crc, device_rebooted, has_discontinuity
                )

                prev_oper = prev.get("oper_status", "UNKNOWN")
                if prev_oper == "UP" and oper_status == "DOWN" and admin_status == "UP":
                    reason = f"Interface {name} unexpected link DOWN"
                    degraded_reasons.append(reason)
                    events.append({
                        "device_id": device_id,
                        "ip_address": ip,
                        "if_index": idx,
                        "interface_name": name,
                        "event_type": "INTERFACE_DOWN",
                        "severity": "CRITICAL",
                        "message": reason,
                        "timestamp": now_utc,
                    })
                elif prev_oper == "DOWN" and oper_status == "UP":
                    events.append({
                        "device_id": device_id,
                        "ip_address": ip,
                        "if_index": idx,
                        "interface_name": name,
                        "event_type": "INTERFACE_UP",
                        "severity": "INFO",
                        "message": f"Interface {name} recovered UP",
                        "timestamp": now_utc,
                    })

            util_pct = compute_utilization_pct(in_mbps, out_mbps, speed_bps)

            if util_pct >= util_warn_pct:
                sev = "CRITICAL" if util_pct >= util_crit_pct else "WARNING"
                reason = f"Interface {name} congestion ({util_pct:.1f}%)"
                degraded_reasons.append(reason)
                events.append({
                    "device_id": device_id,
                    "ip_address": ip,
                    "if_index": idx,
                    "interface_name": name,
                    "event_type": "INTERFACE_CONGESTION",
                    "severity": sev,
                    "utilization_pct": util_pct,
                    "message": reason,
                    "timestamp": now_utc,
                })

            port_err_sum = in_err_delta + out_err_delta + in_disc_delta + out_disc_delta + crc_delta
            if crc_delta >= crc_warn_delta or (in_err_delta + out_err_delta + in_disc_delta + out_disc_delta) >= err_warn_delta:
                reason = f"Interface {name} errors/CRC detected (+{port_err_sum})"
                degraded_reasons.append(reason)
                events.append({
                    "device_id": device_id,
                    "ip_address": ip,
                    "if_index": idx,
                    "interface_name": name,
                    "event_type": "INTERFACE_ERRORS",
                    "severity": "WARNING",
                    "errors_delta": port_err_sum,
                    "crc_delta": crc_delta,
                    "message": reason,
                    "timestamp": now_utc,
                })

            with self._lock:
                self._prev_state[cache_key] = {
                    "sample_mono": now_mono,
                    "sample_utc": now_utc,
                    "in_octets": curr_in_octets,
                    "out_octets": curr_out_octets,
                    "in_is_64bit": curr_in_64,
                    "out_is_64bit": curr_out_64,
                    "in_errors": curr_in_err,
                    "out_errors": curr_out_err,
                    "in_discards": curr_in_disc,
                    "out_discards": curr_out_disc,
                    "crc_errors": curr_crc,
                    "oper_status": oper_status,
                    "discontinuity_ticks": curr_disc_ticks,
                }

            if oper_status == "UP":
                up_count += 1
            elif oper_status == "DOWN":
                down_count += 1

            total_in_mbps += in_mbps
            total_out_mbps += out_mbps
            total_errors_sum += port_err_sum
            if util_pct > max_util_pct:
                max_util_pct = util_pct

            computed_rows.append({
                "device_id": device_id,
                "if_index": idx,
                "name": name,
                "description": descr or name,
                "alias": alias,
                "mac_address": mac,
                "admin_status": admin_status,
                "oper_status": oper_status,
                "speed_bps": speed_bps,
                "negotiated_speed_mbps": negotiated_mbps,
                "in_mbps": in_mbps,
                "out_mbps": out_mbps,
                "utilization_pct": util_pct,
                "in_errors": in_err_delta,
                "out_errors": out_err_delta,
                "in_discards": in_disc_delta,
                "out_discards": out_disc_delta,
                "crc_errors": crc_delta,
                "in_delta_reason": in_reason,
                "out_delta_reason": out_reason,
                "last_change_ticks": last_chg_ticks,
                "last_change_at": last_change_at,
                "timestamp": now_utc,
            })

        id_map = db.upsert_snmp_interfaces(device_id, meta_rows)
        meas_rows: List[Dict[str, Any]] = []
        for item in computed_rows:
            iface_db_id = id_map.get(item["if_index"])
            item["interface_id"] = iface_db_id
            if iface_db_id is not None:
                meas_rows.append({
                    "interface_id": iface_db_id,
                    "device_id": device_id,
                    "in_mbps": item["in_mbps"],
                    "out_mbps": item["out_mbps"],
                    "utilization_pct": item["utilization_pct"],
                    "in_errors": item["in_errors"],
                    "out_errors": item["out_errors"],
                    "in_discards": item["in_discards"],
                    "out_discards": item["out_discards"],
                    "crc_errors": item["crc_errors"],
                    "oper_status": item["oper_status"],
                    "timestamp": now_utc,
                })
        db.save_interface_measurements_batch(meas_rows)

        with self._lock:
            self._last_snapshots[device_id] = [dict(r) for r in computed_rows]

        ctx.setdefault("interface_name_map", {}).update(iface_name_lookup)
        ctx.setdefault("degraded_reasons", []).extend(degraded_reasons)
        ctx.setdefault("collector_events", []).extend(events)
        ctx.setdefault("collector_snapshots", {})["interfaces"] = [dict(r) for r in computed_rows]

        return [
            {
                "device_id": device_id,
                "metric_name": "total_in_mbps",
                "metric_value": round(total_in_mbps, 4),
                "unit": "Mbps",
                "timestamp": now_utc,
            },
            {
                "device_id": device_id,
                "metric_name": "total_out_mbps",
                "metric_value": round(total_out_mbps, 4),
                "unit": "Mbps",
                "timestamp": now_utc,
            },
            {
                "device_id": device_id,
                "metric_name": "interfaces_up",
                "metric_value": float(up_count),
                "unit": "count",
                "timestamp": now_utc,
            },
            {
                "device_id": device_id,
                "metric_name": "interfaces_down",
                "metric_value": float(down_count),
                "unit": "count",
                "timestamp": now_utc,
            },
            {
                "device_id": device_id,
                "metric_name": "interfaces_total",
                "metric_value": float(len(computed_rows)),
                "unit": "count",
                "timestamp": now_utc,
            },
            {
                "device_id": device_id,
                "metric_name": "interface_errors_total",
                "metric_value": float(total_errors_sum),
                "unit": "count",
                "timestamp": now_utc,
            },
            {
                "device_id": device_id,
                "metric_name": "max_interface_util_pct",
                "metric_value": float(max_util_pct),
                "unit": "%",
                "timestamp": now_utc,
            },
        ]
