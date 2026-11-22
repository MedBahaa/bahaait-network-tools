import asyncio
from collections import deque
import csv
from datetime import datetime
import json
import socket
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from PySide6.QtCore import QThread, Signal

from core.syslog_classifier import classify_syslog_event
from core.syslog_parser import DEFAULT_MAX_MESSAGE_BYTES, parse_syslog_message
from utils.db import DatabaseManager


def get_windows_firewall_guidance(port: int = 514) -> Dict[str, Any]:
    """Return Windows Firewall command suggestions and privilege guidance for UDP Syslog ingestion."""
    p = int(port)
    return {
        "port": p,
        "requires_admin": p < 1024,
        "recommended_non_admin_port": 5514,
        "powershell_cmd": (
            f'New-NetFirewallRule -DisplayName "BahaaIT Syslog UDP {p}" '
            f'-Direction Inbound -Protocol UDP -LocalPort {p} -Action Allow'
        ),
        "netsh_cmd": (
            f'netsh advfirewall firewall add rule name="BahaaIT Syslog UDP {p}" '
            f'dir=in action=allow protocol=UDP localport={p}'
        ),
    }


def _format_ts(val: Any, iso: bool = False) -> str:
    if isinstance(val, datetime):
        return val.isoformat() if iso else val.strftime("%Y-%m-%d %H:%M:%S")
    return "" if val is None else str(val)


def export_syslog_csv(events: List[Dict[str, Any]], file_path: str) -> int:
    """Export Syslog event records to UTF-8-SIG CSV and return exported row count."""
    fieldnames = [
        "timestamp",
        "source_ip",
        "hostname",
        "facility_name",
        "severity",
        "severity_name",
        "app_name",
        "event_category",
        "message",
    ]
    with open(file_path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for ev in events:
            writer.writerow({
                "timestamp": _format_ts(ev.get("timestamp"), iso=False),
                "source_ip": ev.get("source_ip", ""),
                "hostname": ev.get("hostname", ""),
                "facility_name": ev.get("facility_name", ""),
                "severity": ev.get("severity", ""),
                "severity_name": ev.get("severity_name", ""),
                "app_name": ev.get("app_name", ""),
                "event_category": ev.get("event_category", "GENERAL"),
                "message": ev.get("message", ""),
            })
    return len(events)


def export_syslog_json(events: List[Dict[str, Any]], file_path: str) -> int:
    """Export Syslog event records to formatted UTF-8 JSON and return exported row count."""
    serializable: List[Dict[str, Any]] = []
    for ev in events:
        item = dict(ev)
        if "timestamp" in item:
            item["timestamp"] = _format_ts(item["timestamp"], iso=True)
        serializable.append(item)
    with open(file_path, "w", encoding="utf-8") as fh:
        json.dump(serializable, fh, indent=2, ensure_ascii=False)
    return len(serializable)


class _TokenBucket:
    """Thread/loop-local token bucket rate limiter with injectable monotonic clock."""

    def __init__(
        self,
        rate_per_sec: float,
        capacity: Optional[float] = None,
        clock_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        self.rate_per_sec = max(0.0, float(rate_per_sec))
        self.capacity = max(1.0, float(capacity if capacity is not None else self.rate_per_sec))
        self.tokens = self.capacity
        self._clock_fn = clock_fn
        self.last_refill = float(self._clock_fn())

    def configure(self, rate_per_sec: float, capacity: Optional[float] = None) -> None:
        self.rate_per_sec = max(0.0, float(rate_per_sec))
        self.capacity = max(1.0, float(capacity if capacity is not None else self.rate_per_sec))
        self.tokens = min(self.tokens, self.capacity)

    def allow(self, cost: float = 1.0) -> bool:
        now = float(self._clock_fn())
        elapsed = max(0.0, now - self.last_refill)
        self.last_refill = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_per_sec)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


class _SyslogDatagramProtocol(asyncio.DatagramProtocol):
    """Non-blocking UDP datagram receiver with anti-flood protection and bounded queue backpressure."""

    def __init__(self, server: "SyslogServer") -> None:
        self.server = server
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        sock = transport.get_extra_info("socket")
        if sock is not None:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            except OSError:
                pass

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        self.server._handle_datagram(data, addr)

    def error_received(self, exc: Exception) -> None:
        self.server.server_error.emit(f"UDP socket error: {exc}")


class SyslogServer(QThread):
    """Centralized asynchronous UDP Syslog listener with flood protection and batch DB persistence."""

    event_received = Signal(dict)
    events_batch_received = Signal(list)
    stats_updated = Signal(dict)
    flood_detected = Signal(dict)
    server_started = Signal(str, int)
    server_stopped = Signal()
    server_error = Signal(str)

    def __init__(
        self,
        db: DatabaseManager,
        bind_address: str = "0.0.0.0",
        port: int = 514,
        max_packet_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
        max_packets_per_sec: int = 2000,
        max_per_ip_per_sec: int = 500,
        max_queue_size: int = 10_000,
        batch_size: int = 200,
        batch_flush_interval_sec: float = 0.5,
        max_memory_events: int = 5000,
        flood_alert_cooldown_sec: float = 5.0,
        emit_individual_events: bool = True,
        clock_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__()
        self.db = db
        self.bind_address = bind_address
        self.port = int(port)
        self.max_packet_bytes = int(max_packet_bytes)
        self.max_packets_per_sec = int(max_packets_per_sec)
        self.max_per_ip_per_sec = int(max_per_ip_per_sec)
        self.max_queue_size = int(max_queue_size)
        self.batch_size = int(batch_size)
        self.batch_flush_interval_sec = float(batch_flush_interval_sec)
        self.max_memory_events = int(max_memory_events)
        self.flood_alert_cooldown_sec = float(flood_alert_cooldown_sec)
        self.emit_individual_events = bool(emit_individual_events)
        self._clock_fn = clock_fn

        self._lock = threading.RLock()
        self._ready_event = threading.Event()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stop_event: Optional[asyncio.Event] = None
        self._queue: Optional[asyncio.Queue] = None
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._running = False
        self._listening = False
        self._bound_port = 0
        self._last_error = ""

        self._global_bucket = _TokenBucket(self.max_packets_per_sec, clock_fn=self._clock_fn)
        self._ip_buckets: Dict[str, _TokenBucket] = {}
        self._last_flood_alert_mono = -1e9

        self._recent_events: deque = deque(maxlen=self.max_memory_events)
        self._db_batch: List[Dict[str, Any]] = []
        self._stats: Dict[str, Any] = {
            "received_packets": 0,
            "processed_events": 0,
            "persisted_events": 0,
            "malformed_packets": 0,
            "truncated_packets": 0,
            "dropped_rate_limit": 0,
            "dropped_queue_full": 0,
        }
        self._top_talkers: Dict[str, int] = {}

    @property
    def bound_port(self) -> int:
        with self._lock:
            return self._bound_port or self.port

    @property
    def is_listening(self) -> bool:
        with self._lock:
            return self._listening

    def wait_until_ready(self, timeout_sec: float = 3.0) -> bool:
        signaled = self._ready_event.wait(timeout_sec)
        return signaled and self.is_listening

    def get_last_error(self) -> str:
        with self._lock:
            return self._last_error

    def reconfigure(
        self,
        bind_address: Optional[str] = None,
        port: Optional[int] = None,
        max_packets_per_sec: Optional[int] = None,
        max_per_ip_per_sec: Optional[int] = None,
    ) -> None:
        with self._lock:
            if bind_address is not None:
                self.bind_address = bind_address
            if port is not None:
                self.port = int(port)
            if max_packets_per_sec is not None:
                self.max_packets_per_sec = int(max_packets_per_sec)
                self._global_bucket.configure(self.max_packets_per_sec)
            if max_per_ip_per_sec is not None:
                self.max_per_ip_per_sec = int(max_per_ip_per_sec)
                for bucket in self._ip_buckets.values():
                    bucket.configure(self.max_per_ip_per_sec)

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            q_depth = self._queue.qsize() if self._queue is not None else 0
            sorted_talkers = dict(
                sorted(self._top_talkers.items(), key=lambda kv: kv[1], reverse=True)[:25]
            )
            return {
                "running": self._listening,
                "bind_address": self.bind_address,
                "port": self._bound_port or self.port,
                "received_packets": self._stats["received_packets"],
                "processed_events": self._stats["processed_events"],
                "persisted_events": self._stats["persisted_events"],
                "malformed_packets": self._stats["malformed_packets"],
                "truncated_packets": self._stats["truncated_packets"],
                "dropped_rate_limit": self._stats["dropped_rate_limit"],
                "dropped_queue_full": self._stats["dropped_queue_full"],
                "queue_depth": q_depth,
                "top_talkers": sorted_talkers,
            }

    def get_recent_events(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Return recent Syslog events from memory ring buffer (newest first)."""
        with self._lock:
            items = list(self._recent_events)
        return [dict(it) for it in items[: max(0, int(limit))]]

    def flush_now(self) -> int:
        with self._lock:
            if not self._db_batch:
                return 0
            batch = self._db_batch
            self._db_batch = []
        written = self.db.save_syslog_events_batch(batch)
        with self._lock:
            self._stats["persisted_events"] += written
        return written

    def _emit_throttled_flood(self, source_ip: str, reason: str) -> None:
        now = float(self._clock_fn())
        with self._lock:
            if (now - self._last_flood_alert_mono) < self.flood_alert_cooldown_sec:
                return
            self._last_flood_alert_mono = now
            dropped_rl = self._stats["dropped_rate_limit"]
            dropped_qf = self._stats["dropped_queue_full"]

        self.flood_detected.emit({
            "source_ip": source_ip,
            "reason": reason,
            "dropped_rate_limit": dropped_rl,
            "dropped_queue_full": dropped_qf,
            "timestamp": datetime.utcnow(),
        })

    def _handle_datagram(self, data: bytes, addr: Tuple[str, int]) -> None:
        source_ip = addr[0] if addr else ""
        drop_reason: Optional[str] = None
        with self._lock:
            self._stats["received_packets"] += 1
            self._top_talkers[source_ip] = self._top_talkers.get(source_ip, 0) + 1

            # Global rate limit check
            if self.max_packets_per_sec > 0 and not self._global_bucket.allow():
                self._stats["dropped_rate_limit"] += 1
                drop_reason = "GLOBAL_RATE_LIMIT"
            elif self.max_per_ip_per_sec > 0:
                if source_ip not in self._ip_buckets:
                    if len(self._ip_buckets) >= 2000:
                        keys_to_drop = list(self._ip_buckets.keys())[:1000]
                        for k in keys_to_drop:
                            self._ip_buckets.pop(k, None)
                    self._ip_buckets[source_ip] = _TokenBucket(
                        self.max_per_ip_per_sec, clock_fn=self._clock_fn
                    )
                if not self._ip_buckets[source_ip].allow():
                    self._stats["dropped_rate_limit"] += 1
                    drop_reason = "PER_IP_RATE_LIMIT"

        if drop_reason is not None:
            self._emit_throttled_flood(source_ip, drop_reason)
            return

        # Bound queued payload size while preserving 1 extra byte to flag truncation in parser
        bounded_data = data[: self.max_packet_bytes + 1] if len(data) > self.max_packet_bytes else data

        if self._queue is not None:
            try:
                self._queue.put_nowait((bounded_data, source_ip, datetime.utcnow()))
            except asyncio.QueueFull:
                with self._lock:
                    self._stats["dropped_queue_full"] += 1
                self._emit_throttled_flood(source_ip, "QUEUE_FULL")

    def _process_items(self, items: List[Tuple[bytes, str, datetime]]) -> None:
        if not items:
            return
        processed_events: List[Dict[str, Any]] = []
        malformed_inc = 0
        truncated_inc = 0

        for raw_bytes, source_ip, recv_utc in items:
            parsed = parse_syslog_message(
                raw_bytes,
                source_ip=source_ip,
                received_at=recv_utc,
                max_bytes=self.max_packet_bytes,
            )
            cls = classify_syslog_event(parsed)
            if parsed.malformed:
                malformed_inc += 1
            if parsed.truncated:
                truncated_inc += 1

            ev = {
                "source_ip": parsed.source_ip,
                "hostname": parsed.hostname,
                "timestamp": parsed.timestamp,
                "facility": parsed.facility,
                "facility_name": parsed.facility_name,
                "severity": parsed.severity,
                "severity_name": parsed.severity_name,
                "app_name": parsed.app_name,
                "event_category": cls.event_category,
                "message": parsed.message,
                "raw_message": parsed.raw_message,
                "vendor": cls.vendor,
                "interface_name": cls.interface_name,
                "username": cls.username,
                "tags": list(cls.tags),
                "rfc_version": parsed.rfc_version,
                "malformed": parsed.malformed,
                "truncated": parsed.truncated,
            }
            processed_events.append(ev)

        flush_batch: Optional[List[Dict[str, Any]]] = None
        with self._lock:
            for ev in processed_events:
                self._recent_events.appendleft(ev)
                self._db_batch.append(ev)
            self._stats["processed_events"] += len(processed_events)
            self._stats["malformed_packets"] += malformed_inc
            self._stats["truncated_packets"] += truncated_inc
            if len(self._db_batch) >= self.batch_size:
                flush_batch = self._db_batch
                self._db_batch = []

        if flush_batch:
            written = self.db.save_syslog_events_batch(flush_batch)
            with self._lock:
                self._stats["persisted_events"] += written

        self.events_batch_received.emit(processed_events)
        if self.emit_individual_events and len(processed_events) <= 50:
            for ev in processed_events:
                self.event_received.emit(ev)
        self.stats_updated.emit(self.get_stats())

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

    def run(self) -> None:
        self._ready_event.clear()
        with self._lock:
            self._last_error = ""
            self._running = True
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._async_main())
        except Exception as e:
            err_msg = f"Syslog server error: {e}"
            with self._lock:
                self._last_error = err_msg
            self.server_error.emit(err_msg)
        finally:
            self.flush_now()
            with self._lock:
                self._listening = False
            try:
                self._loop.close()
            except Exception:
                pass
            self._loop = None
            self._stop_event = None
            self.server_stopped.emit()
            self._ready_event.set()

    async def _async_main(self) -> None:
        self._stop_event = asyncio.Event()
        self._queue = asyncio.Queue(maxsize=self.max_queue_size)

        try:
            transport, _protocol = await self._loop.create_datagram_endpoint(
                lambda: _SyslogDatagramProtocol(self),
                local_addr=(self.bind_address, int(self.port)),
            )
        except PermissionError:
            guidance = get_windows_firewall_guidance(self.port)
            err = (
                f"Permission denied binding UDP {self.bind_address}:{self.port}. "
                f"Run as Administrator or use non-privileged port {guidance['recommended_non_admin_port']}."
            )
            with self._lock:
                self._last_error = err
                self._listening = False
            self.server_error.emit(err)
            self._ready_event.set()
            return
        except OSError as e:
            guidance = get_windows_firewall_guidance(self.port)
            err = (
                f"Failed to bind UDP {self.bind_address}:{self.port} ({e}). "
                f"Try another port such as {guidance['recommended_non_admin_port']}."
            )
            with self._lock:
                self._last_error = err
                self._listening = False
            self.server_error.emit(err)
            self._ready_event.set()
            return

        self._transport = transport  # type: ignore[assignment]
        sock = transport.get_extra_info("socket")
        actual_port = int(sock.getsockname()[1]) if sock is not None else int(self.port)

        with self._lock:
            self._bound_port = actual_port
            self._listening = True
        self.server_started.emit(self.bind_address, actual_port)
        self._ready_event.set()

        consumer_task = self._loop.create_task(self._consumer_loop(), name="syslog_consumer")
        flusher_task = self._loop.create_task(self._flusher_loop(), name="syslog_flusher")

        try:
            await self._stop_event.wait()
        finally:
            self._running = False
            try:
                transport.close()
            except Exception:
                pass
            self._transport = None

            # Allow any already-delivered OS loop callbacks one turn before draining
            await asyncio.sleep(0)

            for task in (consumer_task, flusher_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(consumer_task, flusher_task, return_exceptions=True)

            # Drain remaining queued datagrams so accepted packets are never lost on clean stop
            drain_deadline = time.monotonic() + 1.0
            while self._queue is not None and not self._queue.empty() and time.monotonic() < drain_deadline:
                chunk: List[Tuple[bytes, str, datetime]] = []
                while not self._queue.empty() and len(chunk) < 256:
                    try:
                        chunk.append(self._queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                if chunk:
                    self._process_items(chunk)

            self.flush_now()

    async def _consumer_loop(self) -> None:
        assert self._queue is not None
        try:
            while self._running:
                try:
                    first = await asyncio.wait_for(self._queue.get(), timeout=0.25)
                except asyncio.TimeoutError:
                    continue
                batch = [first]
                while len(batch) < 100 and not self._queue.empty():
                    try:
                        batch.append(self._queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                self._process_items(batch)
        except asyncio.CancelledError:
            pass

    async def _flusher_loop(self) -> None:
        try:
            while self._running:
                await asyncio.sleep(self.batch_flush_interval_sec)
                if self.flush_now() > 0:
                    self.stats_updated.emit(self.get_stats())
        except asyncio.CancelledError:
            pass
