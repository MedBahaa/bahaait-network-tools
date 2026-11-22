from dataclasses import asdict, dataclass, field
from datetime import datetime
import threading
from typing import Any, Dict, List, Optional, Tuple

from core.snmp_client import SNMPClient, SNMPError
from core.snmp_profiles import STD_OIDS, SNMPVendorProfile
from utils.db import DatabaseManager
from utils.snmp_credentials import SNMPCredentials


# Model-specific temperature warning/critical thresholds (°C).
# Longer/more specific keys are matched first against the device model string.
MODEL_TEMP_THRESHOLDS: Dict[str, Tuple[float, float]] = {
    "C2960": (58.0, 68.0),
    "C9200": (60.0, 72.0),
    "C9300": (62.0, 75.0),
    "WS-C": (58.0, 68.0),
    "ICX7150": (65.0, 80.0),
    "ICX7": (65.0, 80.0),
    "FORTIGATE-60": (68.0, 82.0),
    "FORTIGATE-100": (70.0, 85.0),
    "FORTIGATE-200": (72.0, 86.0),
    "FORTIGATE": (70.0, 85.0),
}

_KIB_TOTAL_OIDS = frozenset(
    {
        "1.3.6.1.4.1.12356.101.4.1.5.0",  # fgSysMemCapacity (KB)
        "1.3.6.1.4.1.2021.4.5.0",         # memTotalReal (KB)
        STD_OIDS["hrMemorySize"],         # hrMemorySize (KBytes)
    }
)
_KIB_FREE_OIDS = frozenset(
    {
        "1.3.6.1.4.1.2021.4.6.0",         # memAvailReal (KB)
    }
)
_NON_TEMP_KEYWORDS = ("fan", "rpm", "volt", "vcc", "psu", "power", "amp")


@dataclass
class TemperatureSensor:
    sensor_id: str
    label: str
    temp_c: float
    warn_c: float
    crit_c: float
    status: str = "NORMAL"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DeviceHealthSnapshot:
    device_id: int
    timestamp: datetime
    cpu_pct: Optional[float] = None
    cpu_status: str = "UNSUPPORTED"
    cpu_warn_pct: float = 75.0
    cpu_crit_pct: float = 90.0
    memory_supported: bool = False
    memory_total_bytes: Optional[int] = None
    memory_used_bytes: Optional[int] = None
    memory_available_bytes: Optional[int] = None
    memory_pct: Optional[float] = None
    memory_status: str = "UNSUPPORTED"
    mem_warn_pct: float = 80.0
    mem_crit_pct: float = 90.0
    temperature_supported: bool = False
    temperatures: List[TemperatureSensor] = field(default_factory=list)
    max_temp_c: Optional[float] = None
    temp_status: str = "UNSUPPORTED"
    temp_warn_c: float = 65.0
    temp_crit_c: float = 80.0
    uptime_ticks: Optional[int] = None
    uptime_sec: Optional[float] = None
    uptime_human: str = "N/A"
    reboot_detected: bool = False
    degraded_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["temperatures"] = [t.to_dict() for t in self.temperatures]
        return data


def _to_float(val: Any) -> Optional[float]:
    if isinstance(val, bool) or val is None:
        return None
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def _classify_threshold(value: float, warn: float, crit: float) -> str:
    if value >= crit:
        return "CRITICAL"
    if value >= warn:
        return "WARNING"
    return "NORMAL"


def resolve_temperature_thresholds(
    profile: SNMPVendorProfile,
    model: str = "",
    thresholds_override: Optional[Dict[str, Any]] = None,
) -> Tuple[float, float]:
    """Resolve model/profile-specific temperature thresholds with explicit per-device override support."""
    warn_c = float(profile.default_temp_warn_c)
    crit_c = float(profile.default_temp_crit_c)

    model_upper = str(model or "").strip().upper()
    if model_upper:
        for key in sorted(MODEL_TEMP_THRESHOLDS.keys(), key=len, reverse=True):
            if key in model_upper:
                warn_c, crit_c = MODEL_TEMP_THRESHOLDS[key]
                break

    if thresholds_override:
        if thresholds_override.get("temp_warn_c") is not None:
            warn_c = float(thresholds_override["temp_warn_c"])
        if thresholds_override.get("temp_crit_c") is not None:
            crit_c = float(thresholds_override["temp_crit_c"])

    return float(warn_c), float(crit_c)


def format_uptime(uptime_ticks: Optional[int]) -> str:
    """Format SNMP TimeTicks (1/100 s) into human-readable duration."""
    if uptime_ticks is None or uptime_ticks < 0:
        return "N/A"
    total_sec = int(uptime_ticks) // 100
    days, rem = divmod(total_sec, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    if days > 0:
        return f"{days}d {hours:02d}h {minutes:02d}m"
    if hours > 0:
        return f"{hours}h {minutes:02d}m {seconds:02d}s"
    if minutes > 0:
        return f"{minutes}m {seconds:02d}s"
    return f"{seconds}s"


def compute_cpu_average(
    db: DatabaseManager,
    device_id: int,
    since: Optional[datetime] = None,
) -> Optional[float]:
    """Compute average historical CPU utilization from persisted SNMP metrics."""
    rows = db.get_snmp_metrics(device_id, metric_name="cpu_pct", since=since, limit=2000)
    vals = [float(r["metric_value"]) for r in rows if r.get("metric_value") is not None]
    if not vals:
        return None
    return round(sum(vals) / len(vals), 2)


class DeviceHealthCollector:
    """Vendor-independent SNMP collector for CPU, memory, temperature sensors, and uptime."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_snapshots: Dict[int, DeviceHealthSnapshot] = {}

    def get_last_snapshot(self, device_id: int) -> Optional[DeviceHealthSnapshot]:
        with self._lock:
            return self._last_snapshots.get(int(device_id))

    @staticmethod
    def _oid_suffix(oid: str, base_oid: str) -> str:
        clean_oid = str(oid).lstrip(".")
        clean_base = str(base_oid).lstrip(".")
        if clean_oid.startswith(clean_base + "."):
            return clean_oid[len(clean_base) + 1 :]
        return clean_oid.rsplit(".", 1)[-1]

    async def _query_oid(
        self,
        client: SNMPClient,
        ip: str,
        port: int,
        creds: SNMPCredentials,
        oid: str,
        timeout_sec: float,
        retries: int,
    ) -> List[Tuple[str, Any]]:
        clean = str(oid).strip().lstrip(".")
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

    async def collect_cpu(
        self,
        client: SNMPClient,
        ip: str,
        port: int,
        creds: SNMPCredentials,
        profile: SNMPVendorProfile,
        timeout_sec: float = 2.0,
        retries: int = 1,
    ) -> Optional[float]:
        candidates = list(profile.cpu_oids)
        if STD_OIDS["hrProcessorLoad"] not in candidates:
            candidates.append(STD_OIDS["hrProcessorLoad"])

        for oid in candidates:
            rows = await self._query_oid(client, ip, port, creds, oid, timeout_sec, retries)
            vals: List[float] = []
            for _row_oid, raw in rows:
                num = _to_float(raw)
                if num is None or num < 0.0 or num > 100.0:
                    continue
                if oid.lstrip(".") == "1.3.6.1.4.1.2021.11.11.0":
                    num = max(0.0, min(100.0, 100.0 - num))
                vals.append(num)
            if vals:
                return round(sum(vals) / len(vals), 2)
        return None

    async def collect_memory(
        self,
        client: SNMPClient,
        ip: str,
        port: int,
        creds: SNMPCredentials,
        profile: SNMPVendorProfile,
        timeout_sec: float = 2.0,
        retries: int = 1,
    ) -> Dict[str, Any]:
        # Priority 1: Direct percentage OIDs (+ optional total capacity OID)
        for pct_oid in profile.memory_pct_oids:
            rows = await self._query_oid(client, ip, port, creds, pct_oid, timeout_sec, retries)
            pct_vals = [
                v for _o, r in rows if (v := _to_float(r)) is not None and 0.0 <= v <= 100.0
            ]
            if pct_vals:
                pct = round(sum(pct_vals) / len(pct_vals), 2)
                total_bytes: Optional[int] = None
                used_bytes: Optional[int] = None
                avail_bytes: Optional[int] = None

                total_candidates = list(profile.memory_total_oids)
                if STD_OIDS["hrMemorySize"] not in total_candidates:
                    total_candidates.append(STD_OIDS["hrMemorySize"])
                for tot_oid in total_candidates:
                    tot_rows = await self._query_oid(client, ip, port, creds, tot_oid, timeout_sec, retries)
                    tot_nums = [v for _o, r in tot_rows if (v := _to_float(r)) is not None and v > 0]
                    if tot_nums:
                        mult = 1024 if tot_oid.lstrip(".") in _KIB_TOTAL_OIDS else 1
                        total_bytes = int(round(sum(tot_nums) * mult))
                        used_bytes = int(round(total_bytes * (pct / 100.0)))
                        avail_bytes = max(0, total_bytes - used_bytes)
                        break

                return {
                    "supported": True,
                    "total_bytes": total_bytes,
                    "used_bytes": used_bytes,
                    "available_bytes": avail_bytes,
                    "pct": pct,
                }

        # Priority 2: Used + Free pools (e.g., Cisco ciscoMemoryPoolUsed / Free in bytes)
        if profile.memory_used_oids and profile.memory_free_oids:
            used_total = 0.0
            free_total = 0.0
            has_used = False
            has_free = False
            for used_oid in profile.memory_used_oids:
                rows = await self._query_oid(client, ip, port, creds, used_oid, timeout_sec, retries)
                nums = [v for _o, r in rows if (v := _to_float(r)) is not None and v >= 0]
                if nums:
                    used_total = sum(nums)
                    has_used = True
                    break
            for free_oid in profile.memory_free_oids:
                rows = await self._query_oid(client, ip, port, creds, free_oid, timeout_sec, retries)
                nums = [v for _o, r in rows if (v := _to_float(r)) is not None and v >= 0]
                if nums:
                    free_total = sum(nums)
                    has_free = True
                    break
            if has_used and has_free and (used_total + free_total) > 0:
                total_b = int(round(used_total + free_total))
                used_b = int(round(used_total))
                avail_b = int(round(free_total))
                return {
                    "supported": True,
                    "total_bytes": total_b,
                    "used_bytes": used_b,
                    "available_bytes": avail_b,
                    "pct": round((used_b / total_b) * 100.0, 2),
                }

        # Priority 3: Total + Free OIDs (e.g., UCD-SNMP memTotalReal / memAvailReal in KiB)
        if profile.memory_total_oids and profile.memory_free_oids:
            total_b = None
            free_b = None
            for tot_oid in profile.memory_total_oids:
                rows = await self._query_oid(client, ip, port, creds, tot_oid, timeout_sec, retries)
                nums = [v for _o, r in rows if (v := _to_float(r)) is not None and v > 0]
                if nums:
                    mult = 1024 if tot_oid.lstrip(".") in _KIB_TOTAL_OIDS else 1
                    total_b = int(round(sum(nums) * mult))
                    break
            for free_oid in profile.memory_free_oids:
                rows = await self._query_oid(client, ip, port, creds, free_oid, timeout_sec, retries)
                nums = [v for _o, r in rows if (v := _to_float(r)) is not None and v >= 0]
                if nums:
                    mult = 1024 if free_oid.lstrip(".") in _KIB_FREE_OIDS else 1
                    free_b = int(round(sum(nums) * mult))
                    break
            if total_b is not None and free_b is not None and total_b > 0:
                used_b = max(0, total_b - free_b)
                return {
                    "supported": True,
                    "total_bytes": total_b,
                    "used_bytes": used_b,
                    "available_bytes": free_b,
                    "pct": round((used_b / total_b) * 100.0, 2),
                }

        # Priority 4: Standard HOST-RESOURCES-MIB hrStorageTable fallback
        type_rows = await self._query_oid(client, ip, port, creds, STD_OIDS["hrStorageType"], timeout_sec, retries)
        descr_rows = await self._query_oid(client, ip, port, creds, STD_OIDS["hrStorageDescr"], timeout_sec, retries)
        unit_rows = await self._query_oid(
            client, ip, port, creds, STD_OIDS["hrStorageAllocationUnits"], timeout_sec, retries
        )
        size_rows = await self._query_oid(client, ip, port, creds, STD_OIDS["hrStorageSize"], timeout_sec, retries)
        used_rows = await self._query_oid(client, ip, port, creds, STD_OIDS["hrStorageUsed"], timeout_sec, retries)

        if size_rows and used_rows:
            type_map = {
                self._oid_suffix(o, STD_OIDS["hrStorageType"]): str(v).lstrip(".")
                for o, v in type_rows
            }
            descr_map = {
                self._oid_suffix(o, STD_OIDS["hrStorageDescr"]): str(v).lower()
                for o, v in descr_rows
            }
            unit_map = {
                self._oid_suffix(o, STD_OIDS["hrStorageAllocationUnits"]): (_to_float(v) or 1.0)
                for o, v in unit_rows
            }
            size_map = {
                self._oid_suffix(o, STD_OIDS["hrStorageSize"]): _to_float(v)
                for o, v in size_rows
            }
            used_map = {
                self._oid_suffix(o, STD_OIDS["hrStorageUsed"]): _to_float(v)
                for o, v in used_rows
            }

            ram_total = 0
            ram_used = 0
            for idx, size_val in size_map.items():
                used_val = used_map.get(idx)
                if size_val is None or used_val is None or size_val <= 0:
                    continue
                stype = type_map.get(idx, "")
                sdescr = descr_map.get(idx, "")
                is_ram = stype == "1.3.6.1.2.1.25.2.1.2" or (
                    ("physical memory" in sdescr or "real memory" in sdescr or "ram" in sdescr)
                    and "virtual" not in sdescr
                    and "swap" not in sdescr
                )
                if is_ram:
                    alloc = max(1.0, unit_map.get(idx, 1.0))
                    ram_total += int(round(size_val * alloc))
                    ram_used += int(round(max(0.0, used_val) * alloc))

            if ram_total > 0:
                avail_b = max(0, ram_total - ram_used)
                return {
                    "supported": True,
                    "total_bytes": ram_total,
                    "used_bytes": ram_used,
                    "available_bytes": avail_b,
                    "pct": round((ram_used / ram_total) * 100.0, 2),
                }

        return {
            "supported": False,
            "total_bytes": None,
            "used_bytes": None,
            "available_bytes": None,
            "pct": None,
        }

    async def collect_temperatures(
        self,
        client: SNMPClient,
        ip: str,
        port: int,
        creds: SNMPCredentials,
        profile: SNMPVendorProfile,
        model: str = "",
        thresholds_override: Optional[Dict[str, Any]] = None,
        timeout_sec: float = 2.0,
        retries: int = 1,
    ) -> Tuple[List[TemperatureSensor], float, float]:
        warn_c, crit_c = resolve_temperature_thresholds(profile, model, thresholds_override)
        value_oids = list(profile.temperature_value_oids)
        name_oids = list(profile.temperature_name_oids)

        for idx, val_oid in enumerate(value_oids):
            val_rows = await self._query_oid(client, ip, port, creds, val_oid, timeout_sec, retries)
            if not val_rows:
                continue

            # Resolve corresponding sensor label table
            label_map: Dict[str, str] = {}
            label_oid = name_oids[idx] if idx < len(name_oids) else (name_oids[0] if name_oids else "")
            if label_oid:
                label_rows = await self._query_oid(client, ip, port, creds, label_oid, timeout_sec, retries)
                for l_oid, l_val in label_rows:
                    suf = self._oid_suffix(l_oid, label_oid)
                    txt = str(l_val or "").strip()
                    if txt:
                        label_map[suf] = txt
                        label_map[str(l_oid).lstrip(".").rsplit(".", 1)[-1]] = txt

            clean_val_oid = val_oid.lstrip(".")
            sensor_types: Dict[str, int] = {}
            sensor_prec: Dict[str, int] = {}
            if clean_val_oid == STD_OIDS["entPhySensorValue"]:
                t_rows = await self._query_oid(
                    client, ip, port, creds, STD_OIDS["entPhySensorType"], timeout_sec, retries
                )
                for toid, tval in t_rows:
                    if (tf := _to_float(tval)) is not None:
                        suf = self._oid_suffix(toid, STD_OIDS["entPhySensorType"])
                        sensor_types[suf] = int(tf)
                        sensor_types[str(toid).lstrip(".").rsplit(".", 1)[-1]] = int(tf)

                p_rows = await self._query_oid(
                    client, ip, port, creds, STD_OIDS["entPhySensorPrecision"], timeout_sec, retries
                )
                for poid, pval in p_rows:
                    if (pf := _to_float(pval)) is not None:
                        suf = self._oid_suffix(poid, STD_OIDS["entPhySensorPrecision"])
                        sensor_prec[suf] = int(pf)
                        sensor_prec[str(poid).lstrip(".").rsplit(".", 1)[-1]] = int(pf)

                if not label_map:
                    for fallback_name_oid in (STD_OIDS["entPhysicalName"], STD_OIDS["entPhysicalDescr"]):
                        f_rows = await self._query_oid(
                            client, ip, port, creds, fallback_name_oid, timeout_sec, retries
                        )
                        for f_oid, f_val in f_rows:
                            suf = self._oid_suffix(f_oid, fallback_name_oid)
                            txt = str(f_val or "").strip()
                            if txt:
                                label_map[suf] = txt
                                label_map[str(f_oid).lstrip(".").rsplit(".", 1)[-1]] = txt
                        if label_map:
                            break

            sensors: List[TemperatureSensor] = []
            for row_oid, raw in val_rows:
                raw_num = _to_float(raw)
                if raw_num is None:
                    continue

                suf = self._oid_suffix(row_oid, clean_val_oid)
                last_comp = str(row_oid).lstrip(".").rsplit(".", 1)[-1]
                label = label_map.get(suf) or label_map.get(last_comp) or f"Sensor-{suf}"
                lbl_low = label.lower()

                if clean_val_oid == STD_OIDS["entPhySensorValue"]:
                    if sensor_types:
                        stype = sensor_types.get(suf, sensor_types.get(last_comp))
                        if stype is not None and stype != 8:  # 8 == celsius in ENTITY-SENSOR-MIB
                            continue
                    prec = sensor_prec.get(suf, sensor_prec.get(last_comp, 0))
                    temp_c = round(raw_num * (10.0 ** -prec), 2) if prec > 0 else round(raw_num, 1)
                elif clean_val_oid == "1.3.6.1.4.1.1991.1.1.2.13.1.1.4":  # Ruckus ICX (0.5 C)
                    temp_c = round(raw_num / 2.0, 1)
                elif clean_val_oid == "1.3.6.1.4.1.2021.13.16.2.1.3":  # lmTempSensorsValue (mC)
                    temp_c = round(raw_num / 1000.0, 1) if abs(raw_num) > 200.0 else round(raw_num, 1)
                elif clean_val_oid == "1.3.6.1.4.1.12356.101.4.3.2.1.3":  # fgHwSensorEntValue
                    if any(k in lbl_low for k in _NON_TEMP_KEYWORDS) and "temp" not in lbl_low and "thermal" not in lbl_low:
                        continue
                    temp_c = round(raw_num, 1)
                else:
                    temp_c = round(raw_num, 1)

                if temp_c <= -50.0 or temp_c >= 200.0:
                    continue

                sensors.append(
                    TemperatureSensor(
                        sensor_id=suf,
                        label=label,
                        temp_c=temp_c,
                        warn_c=warn_c,
                        crit_c=crit_c,
                        status=_classify_threshold(temp_c, warn_c, crit_c),
                    )
                )

            if sensors:
                return sensors, warn_c, crit_c

        return [], warn_c, crit_c

    async def collect(self, ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
        device_id = int(ctx["device_id"])
        client: SNMPClient = ctx["client"]
        ip: str = ctx["ip_address"]
        port: int = int(ctx["port"])
        creds: SNMPCredentials = ctx["credentials"]
        profile: SNMPVendorProfile = ctx["profile"]
        model: str = str(ctx.get("model") or "")
        thresholds: Dict[str, Any] = dict(ctx.get("thresholds") or {})
        timeout_sec: float = float(ctx.get("timeout_sec", 2.0))
        retries: int = int(ctx.get("retries", 1))
        due_flags: Dict[str, bool] = dict(ctx.get("due_flags") or {"temp": True})
        now_utc: datetime = ctx.get("now_utc") or datetime.utcnow()
        uptime_ticks: Optional[int] = ctx.get("uptime_ticks")
        reboot_detected: bool = bool(ctx.get("reboot_detected", False))

        cpu_warn = float(thresholds.get("cpu_warn_pct", profile.cpu_warn_pct))
        cpu_crit = float(thresholds.get("cpu_crit_pct", profile.cpu_crit_pct))
        mem_warn = float(thresholds.get("mem_warn_pct", profile.mem_warn_pct))
        mem_crit = float(thresholds.get("mem_crit_pct", profile.mem_crit_pct))

        cpu_pct = await self.collect_cpu(client, ip, port, creds, profile, timeout_sec, retries)
        mem = await self.collect_memory(client, ip, port, creds, profile, timeout_sec, retries)

        metrics_out: List[Dict[str, Any]] = []
        degraded_reasons: List[str] = []
        events: List[Dict[str, Any]] = []

        if cpu_pct is not None:
            cpu_status = _classify_threshold(cpu_pct, cpu_warn, cpu_crit)
            metrics_out.append({
                "device_id": device_id,
                "metric_name": "cpu_pct",
                "metric_value": float(cpu_pct),
                "unit": "%",
                "timestamp": now_utc,
            })
            if cpu_status in ("WARNING", "CRITICAL"):
                reason = f"CPU {cpu_status}: {cpu_pct:.1f}%"
                degraded_reasons.append(reason)
                events.append({
                    "device_id": device_id,
                    "ip_address": ip,
                    "event_type": f"CPU_{cpu_status}",
                    "severity": cpu_status,
                    "value": cpu_pct,
                    "threshold": cpu_crit if cpu_status == "CRITICAL" else cpu_warn,
                    "message": reason,
                    "timestamp": now_utc,
                })
        else:
            cpu_status = "UNSUPPORTED"

        mem_pct = mem["pct"]
        if mem["supported"] and mem_pct is not None:
            mem_status = _classify_threshold(mem_pct, mem_warn, mem_crit)
            metrics_out.append({
                "device_id": device_id,
                "metric_name": "memory_pct",
                "metric_value": float(mem_pct),
                "unit": "%",
                "timestamp": now_utc,
            })
            if mem["used_bytes"] is not None:
                metrics_out.append({
                    "device_id": device_id,
                    "metric_name": "memory_used_bytes",
                    "metric_value": float(mem["used_bytes"]),
                    "unit": "B",
                    "timestamp": now_utc,
                })
            if mem["total_bytes"] is not None:
                metrics_out.append({
                    "device_id": device_id,
                    "metric_name": "memory_total_bytes",
                    "metric_value": float(mem["total_bytes"]),
                    "unit": "B",
                    "timestamp": now_utc,
                })
            if mem["available_bytes"] is not None:
                metrics_out.append({
                    "device_id": device_id,
                    "metric_name": "memory_available_bytes",
                    "metric_value": float(mem["available_bytes"]),
                    "unit": "B",
                    "timestamp": now_utc,
                })
            if mem_status in ("WARNING", "CRITICAL"):
                reason = f"Memory {mem_status}: {mem_pct:.1f}%"
                degraded_reasons.append(reason)
                events.append({
                    "device_id": device_id,
                    "ip_address": ip,
                    "event_type": f"MEMORY_{mem_status}",
                    "severity": mem_status,
                    "value": mem_pct,
                    "threshold": mem_crit if mem_status == "CRITICAL" else mem_warn,
                    "message": reason,
                    "timestamp": now_utc,
                })
        else:
            mem_status = "UNSUPPORTED"

        # Temperature polling (respects scheduler due_flags["temp"])
        prev_snap = self.get_last_snapshot(device_id)
        if due_flags.get("temp", True):
            sensors, temp_warn, temp_crit = await self.collect_temperatures(
                client, ip, port, creds, profile, model, thresholds, timeout_sec, retries
            )
            temp_supported = bool(sensors)
            max_temp = max((s.temp_c for s in sensors), default=None)
            temp_status = _classify_threshold(max_temp, temp_warn, temp_crit) if max_temp is not None else "UNSUPPORTED"
            for s in sensors:
                metrics_out.append({
                    "device_id": device_id,
                    "metric_name": "temperature_c",
                    "metric_value": float(s.temp_c),
                    "unit": "C",
                    "sensor_label": s.label,
                    "timestamp": now_utc,
                })
            if max_temp is not None:
                metrics_out.append({
                    "device_id": device_id,
                    "metric_name": "temperature_max_c",
                    "metric_value": float(max_temp),
                    "unit": "C",
                    "timestamp": now_utc,
                })
                if temp_status in ("WARNING", "CRITICAL"):
                    reason = f"Temperature {temp_status}: {max_temp:.1f}°C"
                    degraded_reasons.append(reason)
                    events.append({
                        "device_id": device_id,
                        "ip_address": ip,
                        "event_type": f"TEMP_{temp_status}",
                        "severity": temp_status,
                        "value": max_temp,
                        "threshold": temp_crit if temp_status == "CRITICAL" else temp_warn,
                        "message": reason,
                        "timestamp": now_utc,
                    })
        elif prev_snap is not None and prev_snap.temperature_supported:
            sensors = list(prev_snap.temperatures)
            temp_warn = prev_snap.temp_warn_c
            temp_crit = prev_snap.temp_crit_c
            temp_supported = True
            max_temp = prev_snap.max_temp_c
            temp_status = prev_snap.temp_status
            if temp_status in ("WARNING", "CRITICAL") and max_temp is not None:
                degraded_reasons.append(f"Temperature {temp_status}: {max_temp:.1f}°C")
        else:
            temp_warn, temp_crit = resolve_temperature_thresholds(profile, model, thresholds)
            sensors = []
            temp_supported = False
            max_temp = None
            temp_status = "UNSUPPORTED"

        uptime_sec = round(uptime_ticks / 100.0, 2) if uptime_ticks is not None else None
        snapshot = DeviceHealthSnapshot(
            device_id=device_id,
            timestamp=now_utc,
            cpu_pct=cpu_pct,
            cpu_status=cpu_status,
            cpu_warn_pct=cpu_warn,
            cpu_crit_pct=cpu_crit,
            memory_supported=bool(mem["supported"]),
            memory_total_bytes=mem["total_bytes"],
            memory_used_bytes=mem["used_bytes"],
            memory_available_bytes=mem["available_bytes"],
            memory_pct=mem_pct,
            memory_status=mem_status,
            mem_warn_pct=mem_warn,
            mem_crit_pct=mem_crit,
            temperature_supported=temp_supported,
            temperatures=sensors,
            max_temp_c=max_temp,
            temp_status=temp_status,
            temp_warn_c=temp_warn,
            temp_crit_c=temp_crit,
            uptime_ticks=uptime_ticks,
            uptime_sec=uptime_sec,
            uptime_human=format_uptime(uptime_ticks),
            reboot_detected=reboot_detected,
            degraded_reasons=list(degraded_reasons),
        )

        with self._lock:
            self._last_snapshots[device_id] = snapshot

        ctx.setdefault("degraded_reasons", []).extend(degraded_reasons)
        ctx.setdefault("collector_events", []).extend(events)
        ctx.setdefault("collector_snapshots", {})["health"] = snapshot.to_dict()

        return metrics_out
