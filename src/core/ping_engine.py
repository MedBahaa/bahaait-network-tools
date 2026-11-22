import asyncio
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from PySide6.QtCore import QThread, Signal
from icmplib import NameLookupError, SocketPermissionError, async_ping

from core.alert_manager import AlertManager
from core.incident_manager import IncidentManager
from core.monitoring_state import (
    HostState,
    HostStateMachine,
    MonitoringPolicyConfig,
    ProbeOutcome,
    validate_target_address,
)
from core.network_quality import NetworkQualityAnalyzer, ProbeSample, QualitySnapshot
from core.wan_monitor import WANMonitor
from utils.db import DatabaseManager


ProbeFunc = Callable[[str, float], Awaitable[Tuple[ProbeOutcome, Optional[float], str]]]


@dataclass
class _HostRuntime:
    host_id: Optional[int]
    address: str
    clean_address: str
    label: str
    active: bool
    policy: MonitoringPolicyConfig
    analyzer: NetworkQualityAnalyzer
    state_machine: HostStateMachine
    task: Optional[asyncio.Task] = None
    last_detail: str = ""
    last_inc_sync_mono: float = 0.0
    category: str = "General"
    profile: str = "Standard"
    probe_count: int = 0
    last_scheduled_drift_ms: float = 0.0


class AsyncPingEngine(QThread):
    """Asynchronous multi-host ICMP monitoring engine running on an isolated QThread."""

    host_updated = Signal(dict)
    state_changed = Signal(dict)
    incident_updated = Signal(dict)
    alert_triggered = Signal(dict)
    wan_updated = Signal(dict)
    engine_error = Signal(str)

    def __init__(
        self,
        db: DatabaseManager,
        global_policy: Optional[MonitoringPolicyConfig] = None,
        alert_manager: Optional[AlertManager] = None,
        incident_manager: Optional[IncidentManager] = None,
        wan_monitor: Optional[WANMonitor] = None,
        probe_func: Optional[ProbeFunc] = None,
        clock_fn: Callable[[], float] = time.monotonic,
        wan_interval_sec: float = 10.0,
        batch_flush_interval_sec: float = 3.0,
        max_concurrent: int = 150,
    ):
        super().__init__()
        self.db = db
        self.global_policy = global_policy or MonitoringPolicyConfig()
        self.incident_manager = incident_manager or IncidentManager(db)
        self.alert_manager = alert_manager or AlertManager(db)
        self.wan_monitor = wan_monitor
        self._probe_func = probe_func or self._default_probe
        self._clock_fn = clock_fn
        self._wan_interval_sec = float(wan_interval_sec)
        self._batch_flush_interval_sec = float(batch_flush_interval_sec)
        self._max_concurrent = int(max_concurrent)

        self._lock = threading.RLock()
        self._hosts: Dict[str, _HostRuntime] = {}
        self._snapshots: Dict[str, Dict[str, Any]] = {}
        self._measurement_buffer: List[Dict[str, Any]] = []

        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stop_event: Optional[asyncio.Event] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._wan_task: Optional[asyncio.Task] = None
        self._wan_enabled: bool = False
        self._running: bool = False

    @staticmethod
    async def _default_probe(target: str, timeout_sec: float) -> Tuple[ProbeOutcome, Optional[float], str]:
        try:
            res = await async_ping(target, count=1, timeout=timeout_sec)
            if res.is_alive:
                rtt = max(0.1, round(float(res.avg_rtt), 2))
                return ProbeOutcome.SUCCESS, rtt, f"Reply from {res.address}: time={rtt:.1f}ms"
            return ProbeOutcome.TIMEOUT, None, "Request timed out."
        except NameLookupError:
            return ProbeOutcome.DNS_ERROR, None, "Could not resolve host name."
        except (SocketPermissionError, PermissionError, OSError) as e:
            return ProbeOutcome.ENGINE_ERROR, None, f"Local network/socket error: {e}"
        except asyncio.TimeoutError:
            return ProbeOutcome.TIMEOUT, None, "Request timed out."
        except Exception as e:
            return ProbeOutcome.ENGINE_ERROR, None, str(e)

    def add_host(
        self,
        address: str,
        label: Optional[str] = None,
        active: bool = True,
        policy: Optional[MonitoringPolicyConfig] = None,
        host_id: Optional[int] = None,
        category: str = "General",
        profile: str = "Standard",
    ) -> Tuple[bool, str]:
        ok, cleaned = validate_target_address(address)
        if not ok:
            return False, cleaned

        eff_policy = policy or MonitoringPolicyConfig(**self.global_policy.to_dict())
        initial_state = HostState.UNKNOWN if active else HostState.PAUSED

        with self._lock:
            existing = self._hosts.get(address)
            if existing is not None:
                if label is not None:
                    existing.label = label
                existing.category = category
                existing.profile = profile
                if host_id is not None:
                    existing.host_id = host_id
                if policy is not None:
                    existing.policy = eff_policy
                    existing.state_machine.update_policy(eff_policy)
                    existing.analyzer.set_window_sec(eff_policy.rolling_window_sec)
                if active and not existing.active:
                    self.resume_host(address)
                elif not active and existing.active:
                    self.pause_host(address)
                return True, ""

            rt = _HostRuntime(
                host_id=host_id,
                address=address,
                clean_address=cleaned,
                label=label or address,
                active=active,
                policy=eff_policy,
                analyzer=NetworkQualityAnalyzer(window_sec=eff_policy.rolling_window_sec),
                state_machine=HostStateMachine(address, policy=eff_policy, initial_state=initial_state),
                category=category,
                profile=profile,
            )
            self._hosts[address] = rt
            self._snapshots[address] = self._build_snapshot(rt, rt.analyzer.get_snapshot())
            loop = self._loop

        if loop is not None and self._running and active:
            loop.call_soon_threadsafe(self._ensure_host_task, rt)
        return True, ""

    def remove_host(self, address: str) -> None:
        with self._lock:
            rt = self._hosts.pop(address, None)
            self._snapshots.pop(address, None)
            loop = self._loop
        if rt is not None and loop is not None:
            loop.call_soon_threadsafe(self._cancel_host_task, rt)

    def pause_host(self, address: str) -> None:
        now_mono = self._clock_fn()
        now_utc = datetime.utcnow()
        with self._lock:
            rt = self._hosts.get(address)
            loop = self._loop
            if rt is None:
                return
            rt.active = False
            transition = rt.state_machine.pause(now_mono, now_utc)
            snap_q = rt.analyzer.get_snapshot()
            snap_dict = self._build_snapshot(rt, snap_q)
            self._snapshots[address] = snap_dict

        if loop is not None:
            loop.call_soon_threadsafe(self._cancel_host_task, rt)
        self.alert_manager.evaluate_transition(
            rt.host_id, rt.label, rt.address, transition, snap_q, rt.policy, now_mono=now_mono
        )
        self.host_updated.emit(snap_dict)
        if transition.changed:
            self.state_changed.emit({
                "host": rt.address,
                "label": rt.label,
                "previous_state": transition.previous_state.value,
                "new_state": transition.new_state.value,
                "reason": transition.reason,
                "details": transition.details,
                "timestamp": now_utc,
            })

    def resume_host(self, address: str) -> None:
        now_mono = self._clock_fn()
        now_utc = datetime.utcnow()
        with self._lock:
            rt = self._hosts.get(address)
            loop = self._loop
            if rt is None:
                return
            rt.active = True
            transition = rt.state_machine.resume(now_mono, now_utc)
            snap_q = rt.analyzer.get_snapshot()
            snap_dict = self._build_snapshot(rt, snap_q)
            self._snapshots[address] = snap_dict

        self.alert_manager.evaluate_transition(
            rt.host_id, rt.label, rt.address, transition, snap_q, rt.policy, now_mono=now_mono
        )
        self.host_updated.emit(snap_dict)
        if loop is not None and self._running:
            loop.call_soon_threadsafe(self._ensure_host_task, rt)

    def update_host_policy(self, address: str, policy: MonitoringPolicyConfig) -> None:
        policy.validate()
        with self._lock:
            rt = self._hosts.get(address)
            if rt is not None:
                rt.policy = policy
                rt.state_machine.update_policy(policy)
                rt.analyzer.set_window_sec(policy.rolling_window_sec)

    def update_global_policy(
        self,
        policy: MonitoringPolicyConfig,
        propagate_non_overridden: bool = True,
    ) -> None:
        policy.validate()
        self.global_policy = policy
        if not propagate_non_overridden:
            return

        with self._lock:
            host_ids = [(addr, rt.host_id) for addr, rt in self._hosts.items()]

        overridden_addrs = set()
        for addr, hid in host_ids:
            if hid is not None and self.db.get_policy(hid) is not None:
                overridden_addrs.add(addr)

        with self._lock:
            for addr, rt in self._hosts.items():
                if addr in overridden_addrs:
                    continue
                eff = MonitoringPolicyConfig(**policy.to_dict())
                rt.policy = eff
                rt.state_machine.update_policy(eff)
                rt.analyzer.set_window_sec(eff.rolling_window_sec)

    def enable_wan_monitor(self, enabled: bool) -> None:
        with self._lock:
            self._wan_enabled = bool(enabled)
            loop = self._loop
        if loop is not None and self._running:
            loop.call_soon_threadsafe(self._sync_wan_task)

    def set_wan_interval(self, interval_sec: float) -> None:
        with self._lock:
            self._wan_interval_sec = max(5.0, float(interval_sec))

    def is_wan_enabled(self) -> bool:
        with self._lock:
            return bool(self._wan_enabled)

    def get_all_snapshots(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return {k: dict(v) for k, v in self._snapshots.items()}

    def get_host_snapshot(self, address: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            snap = self._snapshots.get(address)
            return dict(snap) if snap is not None else None

    def flush_now(self) -> int:
        with self._lock:
            if not self._measurement_buffer:
                return 0
            batch = self._measurement_buffer
            self._measurement_buffer = []
        return self.db.save_measurements_batch(batch)

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

    def _build_snapshot(self, rt: _HostRuntime, quality: QualitySnapshot) -> Dict[str, Any]:
        active_inc = self.incident_manager.get_active_incident(rt.address)
        return {
            "host_id": rt.host_id,
            "host": rt.address,
            "label": rt.label,
            "category": rt.category,
            "profile": rt.profile,
            "active": rt.active,
            "state": rt.state_machine.state.value,
            "degraded_reason": rt.state_machine.degraded_reason,
            "current_latency_ms": quality.current_latency_ms,
            "min_latency_ms": quality.min_latency_ms,
            "max_latency_ms": quality.max_latency_ms,
            "avg_latency_ms": quality.avg_latency_ms,
            "p95_latency_ms": quality.p95_latency_ms,
            "jitter_ms": quality.jitter_ms,
            "packet_loss_pct": quality.packet_loss_pct,
            "uptime_pct": quality.uptime_pct,
            "consecutive_successes": quality.consecutive_successes,
            "consecutive_failures": quality.consecutive_failures,
            "last_success_utc": quality.last_success_utc,
            "last_failure_utc": quality.last_failure_utc,
            "total_probes": quality.total_probes,
            "valid_probes": quality.valid_probes,
            "timeout_count": quality.timeout_count,
            "dns_error_count": quality.dns_error_count,
            "engine_error_count": quality.engine_error_count,
            "active_incident_uid": active_inc["incident_uid"] if active_inc else None,
            "active_incident_id": active_inc["id"] if active_inc else None,
            "last_detail": rt.last_detail,
            "probe_count": rt.probe_count,
        }

    def _ensure_host_task(self, rt: _HostRuntime) -> None:
        if not self._running or self._loop is None:
            return
        if rt.task is not None and not rt.task.done():
            return  # Prevent duplicate/overlapping monitoring task for the same host
        rt.task = self._loop.create_task(self._host_loop(rt), name=f"ping:{rt.address}")

    @staticmethod
    def _cancel_host_task(rt: _HostRuntime) -> None:
        if rt.task is not None and not rt.task.done():
            rt.task.cancel()
        rt.task = None

    def _sync_wan_task(self) -> None:
        if self._wan_enabled and self.wan_monitor is not None:
            if self._wan_task is None or self._wan_task.done():
                self._wan_task = self._loop.create_task(self._wan_loop(), name="wan_monitor")
        elif self._wan_task is not None and not self._wan_task.done():
            self._wan_task.cancel()
            self._wan_task = None

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

        with self._lock:
            initial_hosts = [rt for rt in self._hosts.values() if rt.active]

        for idx, rt in enumerate(initial_hosts):
            # Subtle initial stagger across large fleets (e.g. 100 hosts) to smooth bursts
            self._ensure_host_task(rt)

        if self._wan_enabled and self.wan_monitor is not None:
            self._sync_wan_task()

        flusher_task = self._loop.create_task(self._batch_flusher_loop(), name="db_flusher")

        try:
            await self._stop_event.wait()
        finally:
            self._running = False
            tasks_to_cancel: List[asyncio.Task] = [flusher_task]
            if self._wan_task is not None and not self._wan_task.done():
                tasks_to_cancel.append(self._wan_task)
            with self._lock:
                for rt in self._hosts.values():
                    if rt.task is not None and not rt.task.done():
                        tasks_to_cancel.append(rt.task)
                        rt.task = None

            for t in tasks_to_cancel:
                if not t.done():
                    t.cancel()
            if tasks_to_cancel:
                await asyncio.gather(*tasks_to_cancel, return_exceptions=True)

    async def _batch_flusher_loop(self) -> None:
        try:
            while self._running:
                await asyncio.sleep(self._batch_flush_interval_sec)
                self.flush_now()
        except asyncio.CancelledError:
            pass

    async def _wan_loop(self) -> None:
        try:
            while self._running and self._wan_enabled and self.wan_monitor is not None:
                try:
                    verdict = await self.wan_monitor.run_check(include_secondary_checks=True)
                    self.wan_updated.emit(verdict.to_dict())
                except Exception as e:
                    self.engine_error.emit(f"WAN Monitor error: {e}")
                await asyncio.sleep(self._wan_interval_sec)
        except asyncio.CancelledError:
            pass

    async def _host_loop(self, rt: _HostRuntime) -> None:
        # Stagger initial delay deterministically up to min(0.25s, interval*0.25) so 100 hosts don't spike simultaneously
        interval_sec = max(0.02, rt.policy.probe_interval_ms / 1000.0)
        stagger = (hash(rt.address) % 20) * (min(0.2, interval_sec * 0.5) / 20.0)
        if stagger > 0:
            await asyncio.sleep(stagger)

        next_tick = self._clock_fn()
        try:
            while self._running and rt.active and self._hosts.get(rt.address) is rt:
                interval_sec = max(0.02, rt.policy.probe_interval_ms / 1000.0)
                timeout_sec = max(0.05, rt.policy.timeout_ms / 1000.0)
                now_mono = self._clock_fn()
                drift = now_mono - next_tick
                overload_thresh = max(0.5, interval_sec * 0.75)

                if drift > overload_thresh:
                    # Scheduler overload detected: log as ENGINE_ERROR, never count as packet loss
                    rt.last_scheduled_drift_ms = round(drift * 1000.0, 2)
                    try:
                        self._handle_probe_result(
                            rt,
                            ProbeOutcome.ENGINE_ERROR,
                            None,
                            f"Scheduler overload detected (lag={drift:.2f}s); probe skipped",
                            now_mono,
                            datetime.utcnow(),
                        )
                    except Exception as e:
                        self.engine_error.emit(f"Host processing error ({rt.address}): {e}")
                    next_tick = self._clock_fn() + interval_sec
                    await asyncio.sleep(interval_sec)
                    continue

                rt.last_scheduled_drift_ms = round(max(0.0, drift) * 1000.0, 2)
                outcome = ProbeOutcome.ENGINE_ERROR
                latency_ms: Optional[float] = None
                detail = ""

                try:
                    async with self._semaphore:
                        outcome, latency_ms, detail = await asyncio.wait_for(
                            self._probe_func(rt.clean_address, timeout_sec),
                            timeout=timeout_sec + 0.5,
                        )
                except asyncio.CancelledError:
                    raise
                except asyncio.TimeoutError:
                    outcome = ProbeOutcome.TIMEOUT
                    detail = "Probe timed out."
                except Exception as e:
                    outcome = ProbeOutcome.ENGINE_ERROR
                    detail = f"Probe execution error: {e}"

                if not self._running or not rt.active or self._hosts.get(rt.address) is not rt:
                    break

                probe_mono = self._clock_fn()
                probe_utc = datetime.utcnow()
                try:
                    self._handle_probe_result(rt, outcome, latency_ms, detail, probe_mono, probe_utc)
                except Exception as e:
                    self.engine_error.emit(f"Host processing error ({rt.address}): {e}")

                next_tick += interval_sec
                sleep_for = next_tick - self._clock_fn()
                if sleep_for < 0:
                    # Probe took close to/longer than interval without hitting overload_thresh; realign softly
                    sleep_for = max(0.01, interval_sec * 0.1)
                    next_tick = self._clock_fn() + sleep_for
                await asyncio.sleep(sleep_for)
        except asyncio.CancelledError:
            pass

    def _handle_probe_result(
        self,
        rt: _HostRuntime,
        outcome: ProbeOutcome,
        latency_ms: Optional[float],
        detail: str,
        now_mono: float,
        now_utc: datetime,
    ) -> None:
        rt.last_detail = detail
        rt.probe_count += 1
        sample = ProbeSample(
            timestamp_mono=now_mono,
            timestamp_utc=now_utc,
            outcome=outcome,
            latency_ms=latency_ms,
            detail=detail,
        )
        quality = rt.analyzer.add_sample(sample)
        window_samples = rt.analyzer.get_window_samples()
        transition = rt.state_machine.process_probe(
            outcome=outcome,
            quality_snapshot=quality,
            now_mono=now_mono,
            now_utc=now_utc,
            window_samples=window_samples,
        )

        # Queue PingMeasurement for batch SQLite persistence
        meas_status = "UP" if outcome == ProbeOutcome.SUCCESS else outcome.value
        is_valid = outcome in (ProbeOutcome.SUCCESS, ProbeOutcome.TIMEOUT)
        err_type = None if outcome == ProbeOutcome.SUCCESS else outcome.value

        flush_batch = None
        with self._lock:
            self._measurement_buffer.append({
                "host_id": rt.host_id,
                "host_address": rt.address,
                "timestamp": now_utc,
                "status": meas_status,
                "latency_ms": latency_ms,
                "is_valid_probe": is_valid,
                "error_type": err_type,
                "detail": detail,
            })
            if len(self._measurement_buffer) >= 200:
                flush_batch = self._measurement_buffer
                self._measurement_buffer = []

        if flush_batch:
            self.db.save_measurements_batch(flush_batch)

        # Incident lifecycle & metrics
        incident_record = None
        if transition.changed:
            incident_record = self.incident_manager.handle_transition(
                host_id=rt.host_id,
                host_name=rt.label,
                host_address=rt.address,
                transition=transition,
                quality=quality,
            )
            if incident_record is not None:
                self.incident_updated.emit(incident_record)
            self.state_changed.emit({
                "host": rt.address,
                "label": rt.label,
                "previous_state": transition.previous_state.value,
                "new_state": transition.new_state.value,
                "reason": transition.reason,
                "details": transition.details,
                "timestamp": now_utc,
            })
        else:
            incident_record = self.incident_manager.get_active_incident(rt.address)
            if incident_record and (now_mono - rt.last_inc_sync_mono) >= 5.0:
                rt.last_inc_sync_mono = now_mono
                updated_inc = self.incident_manager.update_active_incident_metrics(rt.address, quality, now_utc)
                if updated_inc:
                    incident_record = updated_inc

        # Alert evaluation
        alerts = self.alert_manager.evaluate_transition(
            host_id=rt.host_id,
            host_name=rt.label,
            host_address=rt.address,
            transition=transition,
            quality=quality,
            policy=rt.policy,
            incident=incident_record,
            now_mono=now_mono,
        )
        for evt in alerts:
            self.alert_triggered.emit(evt)

        snap_dict = self._build_snapshot(rt, quality)
        with self._lock:
            self._snapshots[rt.address] = snap_dict
        self.host_updated.emit(snap_dict)
