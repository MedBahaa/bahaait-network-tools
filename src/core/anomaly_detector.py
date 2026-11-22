from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
import math
import statistics
import threading
from typing import Any, Deque, Dict, List, Optional, Tuple

from utils.db import DatabaseManager


METRIC_ANOMALY_PROFILES: Dict[str, Dict[str, float]] = {
    "cpu_pct": {"min_std": 2.5, "min_abs_delta": 15.0, "z_warn": 3.0, "z_crit": 4.5, "abs_floor": 50.0},
    "memory_pct": {"min_std": 2.0, "min_abs_delta": 10.0, "z_warn": 3.0, "z_crit": 4.5, "abs_floor": 65.0},
    "temperature_max_c": {"min_std": 1.5, "min_abs_delta": 8.0, "z_warn": 3.0, "z_crit": 4.5, "abs_floor": 50.0},
    "poe_utilization_pct": {"min_std": 2.0, "min_abs_delta": 10.0, "z_warn": 3.0, "z_crit": 4.5, "abs_floor": 70.0},
    "total_in_mbps": {"min_std": 1.0, "min_abs_delta": 20.0, "z_warn": 3.0, "z_crit": 4.5, "abs_floor": 20.0},
    "total_out_mbps": {"min_std": 1.0, "min_abs_delta": 20.0, "z_warn": 3.0, "z_crit": 4.5, "abs_floor": 20.0},
    "max_interface_util_pct": {"min_std": 2.0, "min_abs_delta": 15.0, "z_warn": 3.0, "z_crit": 4.5, "abs_floor": 60.0},
    "interface_errors_total": {"min_std": 1.0, "min_abs_delta": 5.0, "z_warn": 2.5, "z_crit": 4.0, "abs_floor": 5.0},
    "ping_latency_ms": {"min_std": 2.0, "min_abs_delta": 20.0, "z_warn": 3.0, "z_crit": 4.5, "abs_floor": 30.0},
    "ping_packet_loss_pct": {"min_std": 1.5, "min_abs_delta": 10.0, "z_warn": 2.5, "z_crit": 4.0, "abs_floor": 10.0},
    "syslog_rate_per_min": {"min_std": 2.0, "min_abs_delta": 15.0, "z_warn": 3.0, "z_crit": 4.5, "abs_floor": 20.0},
}

_DEFAULT_METRIC_PROFILE: Dict[str, float] = {
    "min_std": 1.0,
    "min_abs_delta": 5.0,
    "z_warn": 3.0,
    "z_crit": 4.5,
    "abs_floor": 0.0,
}

_METRIC_UNITS: Dict[str, str] = {
    "cpu_pct": "%",
    "memory_pct": "%",
    "temperature_max_c": "°C",
    "poe_utilization_pct": "%",
    "total_in_mbps": "Mbps",
    "total_out_mbps": "Mbps",
    "max_interface_util_pct": "%",
    "interface_errors_total": "errors",
    "ping_latency_ms": "ms",
    "ping_packet_loss_pct": "%",
    "syslog_rate_per_min": "msg/min",
}


@dataclass
class AnomalyDetectorConfig:
    baseline_window_size: int = 30
    min_baseline_samples: int = 8
    persistence_samples: int = 2
    dedup_cooldown_sec: float = 300.0
    z_warn_multiplier: float = 1.0
    z_crit_multiplier: float = 1.0


@dataclass
class StatisticalAnomaly:
    device_id: int
    device_name: str
    device_ip: str
    metric_name: str
    current_value: float
    baseline_mean: float
    baseline_std: float
    z_score: float
    severity: str
    consecutive_samples: int
    detected_at: datetime
    title: str
    evidence: List[str] = field(default_factory=list)
    probable_cause: str = ""
    recommended_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class _MetricTrackState:
    def __init__(self, maxlen: int) -> None:
        self.baseline: Deque[float] = deque(maxlen=max(1, int(maxlen)))
        self.breach_streak: int = 0
        self.last_emit_ts: Optional[datetime] = None
        self.active_severity: Optional[str] = None


def _recommended_actions_for_metric(metric_name: str) -> List[str]:
    if metric_name == "cpu_pct":
        return [
            "Inspect top CPU-consuming processes, routing updates, or spanning-tree churn on the device.",
            "Check Syslog events and interface counters for traffic storms or control-plane floods.",
        ]
    if metric_name == "memory_pct":
        return [
            "Review active sessions, routing/NAT tables, and memory pool allocations.",
            "Check firmware version for known memory leak advisories.",
        ]
    if metric_name == "temperature_max_c":
        return [
            "Inspect chassis fans, airflow obstructions, and rack ambient cooling.",
            "Verify PSU fan status and temperature sensors in the Device Health tab.",
        ]
    if metric_name in ("total_in_mbps", "total_out_mbps", "max_interface_util_pct"):
        return [
            "Identify high-utilization interfaces and inspect top traffic sources or broadcast storms.",
            "Verify QoS policies and uplink capacity.",
        ]
    if metric_name == "interface_errors_total":
        return [
            "Check physical cabling, SFP/transceiver optical levels, and speed/duplex negotiation.",
            "Correlate CRC/input error increments with recent link flaps.",
        ]
    return [
        f"Review historical trend for '{metric_name}' against recent configuration changes.",
        "Correlate timing with Syslog and Ping telemetry on the affected host.",
    ]


class StatisticalAnomalyDetector:
    """Lightweight, dependency-free rolling baseline & z-score anomaly detector with persistence and dedup."""

    def __init__(self, config: Optional[AnomalyDetectorConfig] = None) -> None:
        self.config = config or AnomalyDetectorConfig()
        self._lock = threading.RLock()
        self._tracks: Dict[Tuple[int, str], _MetricTrackState] = {}
        self._device_enabled: Dict[int, bool] = {}

    def _get_track(self, device_id: int, metric_name: str) -> _MetricTrackState:
        key = (int(device_id), str(metric_name))
        track = self._tracks.get(key)
        if track is None:
            track = _MetricTrackState(self.config.baseline_window_size)
            self._tracks[key] = track
        return track

    def set_device_enabled(self, device_id: int, enabled: bool) -> None:
        with self._lock:
            self._device_enabled[int(device_id)] = bool(enabled)

    def is_device_enabled(self, device_id: int) -> bool:
        with self._lock:
            return self._device_enabled.get(int(device_id), True)

    def seed_baseline(self, device_id: int, metric_name: str, values: List[float]) -> None:
        with self._lock:
            track = self._get_track(device_id, metric_name)
            track.baseline.clear()
            track.breach_streak = 0
            for v in values:
                if isinstance(v, bool):
                    continue
                try:
                    fv = float(v)
                except (TypeError, ValueError):
                    continue
                if math.isfinite(fv):
                    track.baseline.append(fv)

    def seed_baseline_from_db(
        self,
        db: DatabaseManager,
        device_id: int,
        metric_name: str,
        limit: Optional[int] = None,
    ) -> int:
        fetch_limit = int(limit if limit is not None else self.config.baseline_window_size)
        rows = db.get_snmp_metrics(device_id, metric_name=metric_name, limit=fetch_limit)
        vals = [float(r["metric_value"]) for r in rows if r.get("metric_value") is not None]
        self.seed_baseline(device_id, metric_name, vals)
        return len(vals)

    def get_baseline_stats(self, device_id: int, metric_name: str) -> Optional[Dict[str, float]]:
        with self._lock:
            track = self._tracks.get((int(device_id), str(metric_name)))
            if track is None or not track.baseline:
                return None
            vals = list(track.baseline)
            return {
                "mean": round(statistics.fmean(vals), 4),
                "std": round(statistics.pstdev(vals), 4),
                "count": float(len(vals)),
                "min": min(vals),
                "max": max(vals),
            }

    def clear_device(self, device_id: int) -> None:
        dev_id = int(device_id)
        with self._lock:
            keys = [k for k in self._tracks if k[0] == dev_id]
            for k in keys:
                self._tracks.pop(k, None)
            self._device_enabled.pop(dev_id, None)

    def evaluate_sample(
        self,
        device_id: int,
        metric_name: str,
        value: float,
        device_name: str = "",
        device_ip: str = "",
        timestamp: Optional[datetime] = None,
        thresholds_override: Optional[Dict[str, Any]] = None,
    ) -> Optional[StatisticalAnomaly]:
        if isinstance(value, bool):
            return None
        try:
            val = float(value)
        except (TypeError, ValueError):
            return None
        if not math.isfinite(val):
            return None

        ts = timestamp or datetime.utcnow()
        dev_id = int(device_id)
        prof = METRIC_ANOMALY_PROFILES.get(metric_name, _DEFAULT_METRIC_PROFILE)
        ov = dict(thresholds_override or {})

        z_warn = float(ov.get("z_warn", prof["z_warn"])) * self.config.z_warn_multiplier
        z_crit = float(ov.get("z_crit", prof["z_crit"])) * self.config.z_crit_multiplier
        min_abs_delta = float(ov.get("min_abs_delta", prof["min_abs_delta"]))
        abs_floor = float(ov.get("abs_floor", prof["abs_floor"]))
        min_std = float(ov.get("min_std", prof["min_std"]))

        with self._lock:
            track = self._get_track(dev_id, metric_name)
            if len(track.baseline) < self.config.min_baseline_samples:
                track.baseline.append(val)
                track.breach_streak = 0
                return None

            mean = statistics.fmean(track.baseline)
            raw_std = statistics.pstdev(track.baseline)
            effective_std = max(raw_std, min_std)
            delta = val - mean
            z_score = delta / effective_std

            is_anomalous = (delta >= min_abs_delta) and (val >= abs_floor) and (z_score >= z_warn)
            if not is_anomalous:
                track.baseline.append(val)
                track.breach_streak = 0
                track.active_severity = None
                return None

            # Do NOT fold sustained spikes into baseline so genuine anomalies don't mask themselves
            if not self._device_enabled.get(dev_id, True):
                return None

            track.breach_streak += 1
            if track.breach_streak < max(1, int(self.config.persistence_samples)):
                return None

            severity = "CRITICAL" if z_score >= z_crit else "WARNING"
            if track.last_emit_ts is not None:
                elapsed = (ts - track.last_emit_ts).total_seconds()
                escalated = (track.active_severity == "WARNING") and (severity == "CRITICAL")
                if 0.0 <= elapsed < self.config.dedup_cooldown_sec and not escalated:
                    return None

            track.last_emit_ts = ts
            track.active_severity = severity
            streak = track.breach_streak
            base_count = len(track.baseline)

        unit = _METRIC_UNITS.get(metric_name, "")
        unit_suffix = f" {unit}" if unit else ""
        label = device_name or device_ip or f"Device#{dev_id}"

        evidence = [
            f"Metric '{metric_name}' observed at {val:.2f}{unit_suffix} on {label} ({device_ip or 'N/A'}).",
            f"Rolling baseline ({base_count} normal samples): mean={mean:.2f}{unit_suffix}, std={raw_std:.2f}{unit_suffix}, delta=+{delta:.2f}{unit_suffix}.",
            f"Statistical deviation: z-score={z_score:.2f} sustained across {streak} consecutive samples.",
        ]
        probable_cause = (
            f"Inferred sustained statistical surge in {metric_name} (+{delta:.2f}{unit_suffix}, z={z_score:.2f}) "
            f"significantly exceeding the device's normal operating baseline."
        )

        return StatisticalAnomaly(
            device_id=dev_id,
            device_name=label,
            device_ip=device_ip,
            metric_name=metric_name,
            current_value=round(val, 4),
            baseline_mean=round(mean, 4),
            baseline_std=round(raw_std, 4),
            z_score=round(z_score, 2),
            severity=severity,
            consecutive_samples=streak,
            detected_at=ts,
            title=f"Statistical anomaly on {metric_name}: {val:.1f}{unit_suffix} (baseline {mean:.1f}{unit_suffix})",
            evidence=evidence,
            probable_cause=probable_cause,
            recommended_actions=_recommended_actions_for_metric(metric_name),
        )
