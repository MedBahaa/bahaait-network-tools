import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import threading
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional

from PySide6.QtCore import QThread, Signal

from core.snmp_client import SNMPAuthError, SNMPClient, SNMPError
from core.snmp_profiles import STD_OIDS, SNMPVendorProfile, get_profile
from utils.db import DatabaseManager
from utils.snmp_credentials import SNMPCredentials, decrypt_credentials, scrub_secrets


_MAX_TIMETICKS_32 = 4_294_967_295
_ROLLOVER_PREV_HIGH = 4_000_000_000
_ROLLOVER_CURR_LOW = 10_000_000

CollectorFunc = Callable[[Dict[str, Any]], Awaitable[List[Dict[str, Any]]]]


@dataclass
class _SNMPDeviceRuntime:
    device_id: int
    name: str
    ip_address: str
    port: int
    credentials: SNMPCredentials
    profile: SNMPVendorProfile
    model: str = ""
    enabled: bool = True
    anomaly_detection_enabled: bool = True
    timeout_sec: float = 2.0
    retries: int = 1
    poll_interval_sec: int = 30
    temp_interval_sec: int = 60
    poe_interval_sec: int = 60
    sysinfo_interval_sec: int = 300
    capabilities: Dict[str, bool] = field(default_factory=dict)
    thresholds: Dict[str, Any] = field(default_factory=dict)
    status: str = "UNKNOWN"
    last_uptime_ticks: Optional[int] = None
    last_reboot_at: Optional[datetime] = None
    last_poll: Optional[datetime] = None
    last_error: str = ""
    last_metrics: Dict[str, Any] = field(default_factory=dict)
    last_collector_snapshots: Dict[str, Any] = field(default_factory=dict)
    next_due_mono: Dict[str, float] = field(
        default_factory=lambda: {"main": 0.0, "temp": 0.0, "poe": 0.0, "sysinfo": 0.0}
    )
    in_flight: bool = False


class AsyncSNMPEngine(QThread):
    """Concurrent asynchronous SNMP monitoring scheduler running on an isolated QThread."""

    device_updated = Signal(dict)
    device_status_changed = Signal(dict)
    device_reboot_detected = Signal(dict)
    metrics_collected = Signal(int, list)
    collector_event = Signal(dict)
    engine_error = Signal(str)

    def __init__(
        self,
        db: DatabaseManager,
        client: Optional[SNMPClient] = None,
        clock_fn: Callable[[], float] = time.monotonic,
        scheduler_tick_sec: float = 0.5,
        batch_flush_interval_sec: float = 3.0,
        max_concurrent: int = 50,
    ):
        super().__init__()
        self.db = db
        self.client = client or SNMPClient()
        self._clock_fn = clock_fn
        self._scheduler_tick_sec = float(scheduler_tick_sec)
        self._batch_flush_interval_sec = float(batch_flush_interval_sec)
        self._max_concurrent = int(max_concurrent)

        self._lock = threading.RLock()
        self._devices: Dict[int, _SNMPDeviceRuntime] = {}
        self._snapshots: Dict[int, Dict[str, Any]] = {}
        self._metric_buffer: List[Dict[str, Any]] = []
        self._collectors: Dict[str, CollectorFunc] = {}

        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stop_event: Optional[asyncio.Event] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._active_tasks: set = set()
        self._running: bool = False

    def register_collector(self, name: str, fn: CollectorFunc) -> None:
        """Register an async metric/state collector invoked during scheduled device polls."""
        with self._lock:
            self._collectors[name] = fn

    def reload_from_db(self) -> int:
        rows = self.db.get_snmp_devices(enabled_only=False)
        count = 0
        for row in rows:
            try:
                creds = decrypt_credentials(row["encrypted_credentials"])
                self.add_or_update_device_record(row, creds)
                count += 1
            except Exception as e:
                self.engine_error.emit(f"Failed to load SNMP device {row.get('ip_address')}: {e}")
        return count

    def add_or_update_device_record(self, dev_row: Dict[str, Any], creds: SNMPCredentials) -> None:
        dev_id = int(dev_row["id"])
        profile = get_profile(dev_row.get("profile_name", "generic_switch"))
        with self._lock:
            existing = self._devices.get(dev_id)
            if existing is not None:
                existing.name = dev_row.get("name", existing.name)
                existing.ip_address = dev_row["ip_address"]
                existing.port = int(dev_row.get("port", 161))
                existing.credentials = creds
                existing.profile = profile
                existing.model = dev_row.get("model", existing.model)
                existing.enabled = bool(dev_row.get("enabled", True))
                existing.anomaly_detection_enabled = bool(dev_row.get("anomaly_detection_enabled", True))
                existing.timeout_sec = float(dev_row.get("timeout_sec", 2.0))
                existing.retries = int(dev_row.get("retries", 1))
                existing.poll_interval_sec = int(dev_row.get("poll_interval_sec", 30))
                existing.temp_interval_sec = int(dev_row.get("temp_interval_sec", 60))
                existing.poe_interval_sec = int(dev_row.get("poe_interval_sec", 60))
                existing.sysinfo_interval_sec = int(dev_row.get("sysinfo_interval_sec", 300))
                existing.capabilities = dict(dev_row.get("capabilities") or {})
                existing.thresholds = dict(dev_row.get("thresholds") or {})
                rt = existing
            else:
                rt = _SNMPDeviceRuntime(
                    device_id=dev_id,
                    name=dev_row.get("name") or dev_row["ip_address"],
                    ip_address=dev_row["ip_address"],
                    port=int(dev_row.get("port", 161)),
                    credentials=creds,
                    profile=profile,
                    model=dev_row.get("model", ""),
                    enabled=bool(dev_row.get("enabled", True)),
                    anomaly_detection_enabled=bool(dev_row.get("anomaly_detection_enabled", True)),
                    timeout_sec=float(dev_row.get("timeout_sec", 2.0)),
                    retries=int(dev_row.get("retries", 1)),
                    poll_interval_sec=int(dev_row.get("poll_interval_sec", 30)),
                    temp_interval_sec=int(dev_row.get("temp_interval_sec", 60)),
                    poe_interval_sec=int(dev_row.get("poe_interval_sec", 60)),
                    sysinfo_interval_sec=int(dev_row.get("sysinfo_interval_sec", 300)),
                    capabilities=dict(dev_row.get("capabilities") or {}),
                    thresholds=dict(dev_row.get("thresholds") or {}),
                    status=dev_row.get("status", "UNKNOWN"),
                    last_uptime_ticks=dev_row.get("last_uptime_ticks"),
                    last_reboot_at=dev_row.get("last_reboot_at"),
                    last_poll=dev_row.get("last_poll"),
                )
                self._devices[dev_id] = rt
            self._snapshots[dev_id] = self._build_snapshot(rt)

    def remove_device(self, device_id: int) -> None:
        with self._lock:
            self._devices.pop(int(device_id), None)
            self._snapshots.pop(int(device_id), None)

    def get_snapshot(self, device_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            snap = self._snapshots.get(int(device_id))
            return dict(snap) if snap is not None else None

    def get_all_snapshots(self) -> Dict[int, Dict[str, Any]]:
        with self._lock:
            return {k: dict(v) for k, v in self._snapshots.items()}

    def flush_now(self) -> int:
        with self._lock:
            if not self._metric_buffer:
                return 0
            batch = self._metric_buffer
            self._metric_buffer = []
        return self.db.save_snmp_metrics_batch(batch)

    def stop(self, timeout_ms: int = 3000) -> None:
        self._running = False
        loop = self._loop
        if loop is not None and self._stop_event is not None:
            try:
                loop.call_soon_threadsafe(self._stop_event.set)
            except RuntimeError:
                pass
        if self.isRunning():
            self.wait(timeout_ms)

    def _build_snapshot(self, rt: _SNMPDeviceRuntime) -> Dict[str, Any]:
        return {
            "device_id": rt.device_id,
            "name": rt.name,
            "ip_address": rt.ip_address,
            "port": rt.port,
            "snmp_version": rt.credentials.version,
            "vendor": rt.profile.vendor,
            "device_type": rt.profile.device_type,
            "profile_name": rt.profile.name,
            "model": rt.model,
            "enabled": rt.enabled,
            "status": rt.status,
            "last_uptime_ticks": rt.last_uptime_ticks,
            "last_reboot_at": rt.last_reboot_at,
            "last_poll": rt.last_poll,
            "last_error": rt.last_error,
            "capabilities": dict(rt.capabilities),
            "metrics": dict(rt.last_metrics),
            "collector_snapshots": dict(rt.last_collector_snapshots),
        }

    @staticmethod
    def is_uptime_reboot(prev_ticks: Optional[int], curr_ticks: Optional[int]) -> bool:
        """Detect an unexpected device reboot via sysUpTime drop, ignoring 32-bit TimeTicks wraparound."""
        if prev_ticks is None or curr_ticks is None:
            return False
        if curr_ticks >= prev_ticks:
            return False
        if prev_ticks > _ROLLOVER_PREV_HIGH and curr_ticks < _ROLLOVER_CURR_LOW:
            return False
        return True

    def run(self) -> None:
        self._running = True
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._async_main())
        except Exception as e:
            self.engine_error.emit(str(e))
        finally:
            self.flush_now()
            try:
                self._loop.close()
            except Exception:
                pass
            self._loop = None
            self._stop_event = None

    async def _async_main(self) -> None:
        self._stop_event = asyncio.Event()
        self._semaphore = asyncio.Semaphore(self._max_concurrent)

        if not self._running:
            self._stop_event.set()
            return

        scheduler_task = self._loop.create_task(self._scheduler_loop(), name="snmp_scheduler")
        flusher_task = self._loop.create_task(self._batch_flusher_loop(), name="snmp_flusher")

        try:
            await self._stop_event.wait()
        finally:
            self._running = False
            tasks = [scheduler_task, flusher_task] + list(self._active_tasks)
            for t in tasks:
                if not t.done():
                    t.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            self._active_tasks.clear()

    async def _batch_flusher_loop(self) -> None:
        try:
            while self._running:
                await asyncio.sleep(self._batch_flush_interval_sec)
                self.flush_now()
        except asyncio.CancelledError:
            pass

    async def _scheduler_loop(self) -> None:
        try:
            while self._running:
                now_mono = self._clock_fn()
                with self._lock:
                    candidates = [
                        rt
                        for rt in self._devices.values()
                        if rt.enabled and not rt.in_flight and now_mono >= rt.next_due_mono["main"]
                    ]
                    for rt in candidates:
                        rt.in_flight = True

                for rt in candidates:
                    if not self._running:
                        with self._lock:
                            rt.in_flight = False
                        break
                    task = self._loop.create_task(
                        self._poll_device_guarded(rt), name=f"snmp:{rt.ip_address}"
                    )
                    self._active_tasks.add(task)
                    task.add_done_callback(self._active_tasks.discard)

                await asyncio.sleep(self._scheduler_tick_sec)
        except asyncio.CancelledError:
            pass

    async def _poll_device_guarded(self, rt: _SNMPDeviceRuntime) -> None:
        try:
            if self._semaphore is not None:
                async with self._semaphore:
                    await self.poll_device(rt)
            else:
                await self.poll_device(rt)
        finally:
            with self._lock:
                rt.in_flight = False

    async def poll_device_by_id(self, device_id: int) -> Optional[Dict[str, Any]]:
        """Explicitly poll a single device asynchronously without overlapping any in-flight poll."""
        with self._lock:
            rt = self._devices.get(int(device_id))
            if rt is None or rt.in_flight:
                return None
            rt.in_flight = True
        try:
            await self.poll_device(rt)
            return self.get_snapshot(device_id)
        finally:
            with self._lock:
                rt.in_flight = False

    async def poll_device(self, rt: _SNMPDeviceRuntime) -> None:
        now_mono = self._clock_fn()
        now_utc = datetime.utcnow()

        due_flags = {
            "main": True,
            "temp": now_mono >= rt.next_due_mono["temp"],
            "poe": now_mono >= rt.next_due_mono["poe"],
            "sysinfo": now_mono >= rt.next_due_mono["sysinfo"],
        }

        rt.next_due_mono["main"] = now_mono + max(5, int(rt.poll_interval_sec))
        if due_flags["temp"]:
            rt.next_due_mono["temp"] = now_mono + max(10, int(rt.temp_interval_sec))
        if due_flags["poe"]:
            rt.next_due_mono["poe"] = now_mono + max(10, int(rt.poe_interval_sec))
        if due_flags["sysinfo"]:
            rt.next_due_mono["sysinfo"] = now_mono + max(30, int(rt.sysinfo_interval_sec))

        oids_to_query = [STD_OIDS["sysUpTime"]]
        if due_flags["sysinfo"]:
            oids_to_query.extend([
                STD_OIDS["sysDescr"],
                STD_OIDS["sysName"],
                STD_OIDS["sysLocation"],
            ])

        collected_metrics: List[Dict[str, Any]] = []
        prev_status = rt.status
        try:
            sys_res = await self.client.get_oids(
                rt.ip_address,
                rt.credentials,
                oids_to_query,
                port=rt.port,
                timeout_sec=rt.timeout_sec,
                retries=rt.retries,
            )
            if not sys_res:
                raise SNMPError("Empty MIB-II System response from device.")

            uptime_raw = sys_res.get(STD_OIDS["sysUpTime"])
            curr_ticks = int(uptime_raw) if uptime_raw is not None else None
            prev_uptime_ticks = rt.last_uptime_ticks
            rebooted = self.is_uptime_reboot(prev_uptime_ticks, curr_ticks)

            if curr_ticks is not None:
                uptime_sec = round(curr_ticks / 100.0, 2)
                rt.last_metrics["uptime_sec"] = uptime_sec
                collected_metrics.append({
                    "device_id": rt.device_id,
                    "metric_name": "uptime_sec",
                    "metric_value": uptime_sec,
                    "unit": "s",
                    "timestamp": now_utc,
                })

            collected_metrics.append({
                "device_id": rt.device_id,
                "metric_name": "availability",
                "metric_value": 1.0,
                "unit": "bool",
                "timestamp": now_utc,
            })

            new_status = "ONLINE"
            dev_updates: Dict[str, Any] = {
                "status": new_status,
                "last_poll": now_utc,
            }
            if curr_ticks is not None:
                dev_updates["last_uptime_ticks"] = curr_ticks
            if due_flags["sysinfo"]:
                if STD_OIDS["sysDescr"] in sys_res:
                    dev_updates["sys_descr"] = str(sys_res[STD_OIDS["sysDescr"]])
                if STD_OIDS["sysName"] in sys_res:
                    dev_updates["sys_name"] = str(sys_res[STD_OIDS["sysName"]])
                if STD_OIDS["sysLocation"] in sys_res:
                    dev_updates["sys_location"] = str(sys_res[STD_OIDS["sysLocation"]])

            if rebooted and curr_ticks is not None:
                est_reboot = now_utc - timedelta(seconds=curr_ticks / 100.0)
                rt.last_reboot_at = est_reboot
                dev_updates["last_reboot_at"] = est_reboot
                self.device_reboot_detected.emit({
                    "device_id": rt.device_id,
                    "name": rt.name,
                    "ip_address": rt.ip_address,
                    "previous_uptime_ticks": rt.last_uptime_ticks,
                    "current_uptime_ticks": curr_ticks,
                    "estimated_reboot_utc": est_reboot,
                    "detected_at": now_utc,
                })

            rt.last_uptime_ticks = curr_ticks if curr_ticks is not None else rt.last_uptime_ticks
            rt.last_poll = now_utc
            rt.last_error = ""

            # Run registered Lot 2+ metric/interface/PoE/VLAN collectors
            with self._lock:
                collectors_items = list(self._collectors.items())

            if collectors_items:
                ctx = {
                    "device_id": rt.device_id,
                    "name": rt.name,
                    "ip_address": rt.ip_address,
                    "port": rt.port,
                    "credentials": rt.credentials,
                    "profile": rt.profile,
                    "model": rt.model,
                    "capabilities": rt.capabilities,
                    "thresholds": rt.thresholds,
                    "timeout_sec": rt.timeout_sec,
                    "retries": rt.retries,
                    "due_flags": due_flags,
                    "now_utc": now_utc,
                    "uptime_ticks": curr_ticks,
                    "previous_uptime_ticks": prev_uptime_ticks,
                    "reboot_detected": rebooted,
                    "client": self.client,
                    "db": self.db,
                    "degraded_reasons": [],
                    "interface_name_map": {},
                    "collector_snapshots": {},
                    "collector_events": [],
                }
                for _cname, cfunc in collectors_items:
                    try:
                        extra_metrics = await cfunc(ctx)
                        if extra_metrics:
                            for m in extra_metrics:
                                collected_metrics.append(m)
                                rt.last_metrics[m["metric_name"]] = m["metric_value"]
                    except Exception as ce:
                        self.engine_error.emit(
                            f"SNMP collector error ({rt.ip_address}): {scrub_secrets(str(ce), rt.credentials)}"
                        )
                if ctx["collector_snapshots"]:
                    rt.last_collector_snapshots.update(ctx["collector_snapshots"])
                for cevent in ctx["collector_events"]:
                    self.collector_event.emit(cevent)
                if ctx["degraded_reasons"]:
                    new_status = "DEGRADED"
                    dev_updates["status"] = new_status
                    rt.last_error = "; ".join(ctx["degraded_reasons"])

            rt.status = new_status
            self.db.update_snmp_device(rt.device_id, dev_updates)

        except Exception as e:
            safe_err = scrub_secrets(str(e), rt.credentials)
            rt.last_error = safe_err
            rt.last_poll = now_utc
            rt.status = "OFFLINE"
            collected_metrics.append({
                "device_id": rt.device_id,
                "metric_name": "availability",
                "metric_value": 0.0,
                "unit": "bool",
                "timestamp": now_utc,
            })
            self.db.update_snmp_device(rt.device_id, {"status": "OFFLINE", "last_poll": now_utc})

        with self._lock:
            self._metric_buffer.extend(collected_metrics)
            snap = self._build_snapshot(rt)
            self._snapshots[rt.device_id] = snap

        self.device_updated.emit(snap)
        if collected_metrics:
            self.metrics_collected.emit(rt.device_id, list(collected_metrics))
        if prev_status != rt.status:
            self.device_status_changed.emit({
                "device_id": rt.device_id,
                "name": rt.name,
                "ip_address": rt.ip_address,
                "previous_status": prev_status,
                "new_status": rt.status,
                "error": rt.last_error,
                "timestamp": now_utc,
            })


def attach_standard_collectors(
    engine: AsyncSNMPEngine,
    clock_fn: Optional[Callable[[], float]] = None,
) -> Dict[str, Any]:
    """Instantiate and register standard Lot 2 collectors (health, interfaces, PoE, VLANs)."""
    from core.device_health import DeviceHealthCollector
    from core.interface_monitor import InterfaceMonitorCollector
    from core.poe_monitor import PoEMonitorCollector
    from core.vlan_monitor import VLANMonitorCollector

    health = DeviceHealthCollector()
    interfaces = InterfaceMonitorCollector(clock_fn=clock_fn or time.monotonic)
    poe = PoEMonitorCollector()
    vlans = VLANMonitorCollector()

    engine.register_collector("health", health.collect)
    engine.register_collector("interfaces", interfaces.collect)
    engine.register_collector("poe", poe.collect)
    engine.register_collector("vlans", vlans.collect)

    return {
        "health": health,
        "interfaces": interfaces,
        "poe": poe,
        "vlans": vlans,
    }
