"""Network quality calculation engine for Intelligent Ping Monitoring.

Jitter Method (IPDV - Inter-Packet Delay Variation / Mean Absolute Successive Difference):
    Given chronological successful probe latencies [L_0, L_1, ..., L_{n-1}] inside
    the active rolling window, jitter is computed as:
        jitter_ms = mean(|L_i - L_{i-1}| for i in 1 .. n-1)
    Returns 0.0 when fewer than 2 successful probes exist in the window.

Packet Loss Separation:
    Packet Loss (%) = (TIMEOUT probes / Valid network probes) * 100
    where Valid network probes = SUCCESS probes + TIMEOUT probes.
    DNS_ERROR and ENGINE_ERROR samples are tracked separately and NEVER
    counted toward network packet loss.
"""

from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Deque, Iterable, List, Optional

from core.monitoring_state import ProbeOutcome


@dataclass
class ProbeSample:
    timestamp_mono: float
    timestamp_utc: datetime
    outcome: ProbeOutcome
    latency_ms: Optional[float] = None
    detail: str = ""


@dataclass
class QualitySnapshot:
    current_latency_ms: Optional[float]
    min_latency_ms: float
    max_latency_ms: float
    avg_latency_ms: float
    p95_latency_ms: float
    jitter_ms: float
    packet_loss_pct: float
    consecutive_successes: int
    consecutive_failures: int
    uptime_pct: float
    last_success_utc: Optional[datetime]
    last_failure_utc: Optional[datetime]
    total_probes: int
    valid_probes: int
    timeout_count: int
    dns_error_count: int
    engine_error_count: int


def compute_percentile(sorted_values: List[float], percentile: float) -> float:
    """Compute linear-interpolated percentile from a pre-sorted non-empty list."""
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    pos = (percentile / 100.0) * (len(sorted_values) - 1)
    low = int(pos)
    high = min(low + 1, len(sorted_values) - 1)
    frac = pos - low
    return float(sorted_values[low] + (sorted_values[high] - sorted_values[low]) * frac)


def compute_ipdv_jitter(latencies: List[float]) -> float:
    """Compute Mean Absolute Successive Difference (IPDV) jitter in ms."""
    if len(latencies) < 2:
        return 0.0
    diffs = [abs(latencies[i] - latencies[i - 1]) for i in range(1, len(latencies))]
    return round(sum(diffs) / len(diffs), 2)


class NetworkQualityAnalyzer:
    """Rolling-window and session-lifetime quality metrics calculator per host."""

    def __init__(self, window_sec: float = 60.0, max_samples: int = 3600):
        self.window_sec = float(window_sec)
        self.max_samples = int(max_samples)
        self._samples: Deque[ProbeSample] = deque()
        self.consecutive_successes: int = 0
        self.consecutive_failures: int = 0
        self.last_success_utc: Optional[datetime] = None
        self.last_failure_utc: Optional[datetime] = None
        self.current_latency_ms: Optional[float] = None
        self.session_valid_probes: int = 0
        self.session_success_probes: int = 0

    def set_window_sec(self, window_sec: float) -> None:
        self.window_sec = float(window_sec)

    def get_window_samples(self) -> List[ProbeSample]:
        return list(self._samples)

    def add_sample(self, sample: ProbeSample) -> QualitySnapshot:
        self._samples.append(sample)

        # Prune samples outside the rolling monotonic time window or exceeding cap
        cutoff_mono = sample.timestamp_mono - self.window_sec
        while self._samples and (
            self._samples[0].timestamp_mono < cutoff_mono or len(self._samples) > self.max_samples
        ):
            self._samples.popleft()

        if sample.outcome == ProbeOutcome.SUCCESS:
            self.consecutive_successes += 1
            self.consecutive_failures = 0
            self.last_success_utc = sample.timestamp_utc
            self.current_latency_ms = sample.latency_ms
            self.session_valid_probes += 1
            self.session_success_probes += 1
        elif sample.outcome == ProbeOutcome.TIMEOUT:
            self.consecutive_failures += 1
            self.consecutive_successes = 0
            self.last_failure_utc = sample.timestamp_utc
            self.current_latency_ms = None
            self.session_valid_probes += 1
        elif sample.outcome == ProbeOutcome.DNS_ERROR:
            self.consecutive_failures += 1
            self.consecutive_successes = 0
            self.last_failure_utc = sample.timestamp_utc
            self.current_latency_ms = None
        # ProbeOutcome.ENGINE_ERROR intentionally does not alter network streaks or valid probe counters

        return self.get_snapshot()

    def get_snapshot(self) -> QualitySnapshot:
        return self.compute_metrics(
            self._samples,
            current_latency_ms=self.current_latency_ms,
            consecutive_successes=self.consecutive_successes,
            consecutive_failures=self.consecutive_failures,
            last_success_utc=self.last_success_utc,
            last_failure_utc=self.last_failure_utc,
            session_valid_probes=self.session_valid_probes,
            session_success_probes=self.session_success_probes,
        )

    @staticmethod
    def compute_metrics(
        samples: Iterable[ProbeSample],
        current_latency_ms: Optional[float] = None,
        consecutive_successes: int = 0,
        consecutive_failures: int = 0,
        last_success_utc: Optional[datetime] = None,
        last_failure_utc: Optional[datetime] = None,
        session_valid_probes: Optional[int] = None,
        session_success_probes: Optional[int] = None,
    ) -> QualitySnapshot:
        sample_list = list(samples)
        latencies: List[float] = []
        success_count = 0
        timeout_count = 0
        dns_error_count = 0
        engine_error_count = 0

        for s in sample_list:
            if s.outcome == ProbeOutcome.SUCCESS:
                success_count += 1
                if s.latency_ms is not None:
                    latencies.append(float(s.latency_ms))
            elif s.outcome == ProbeOutcome.TIMEOUT:
                timeout_count += 1
            elif s.outcome == ProbeOutcome.DNS_ERROR:
                dns_error_count += 1
            elif s.outcome == ProbeOutcome.ENGINE_ERROR:
                engine_error_count += 1

        valid_probes = success_count + timeout_count
        total_probes = len(sample_list)
        packet_loss_pct = round((timeout_count / valid_probes) * 100.0, 2) if valid_probes > 0 else 0.0

        if latencies:
            sorted_lat = sorted(latencies)
            min_lat = round(sorted_lat[0], 2)
            max_lat = round(sorted_lat[-1], 2)
            avg_lat = round(sum(latencies) / len(latencies), 2)
            p95_lat = round(compute_percentile(sorted_lat, 95.0), 2)
            jitter = compute_ipdv_jitter(latencies)
        else:
            min_lat = max_lat = avg_lat = p95_lat = jitter = 0.0

        if session_valid_probes is not None and session_valid_probes > 0 and session_success_probes is not None:
            uptime_pct = round((session_success_probes / session_valid_probes) * 100.0, 2)
        elif valid_probes > 0:
            uptime_pct = round((success_count / valid_probes) * 100.0, 2)
        else:
            uptime_pct = 100.0

        return QualitySnapshot(
            current_latency_ms=round(current_latency_ms, 2) if current_latency_ms is not None else None,
            min_latency_ms=min_lat,
            max_latency_ms=max_lat,
            avg_latency_ms=avg_lat,
            p95_latency_ms=p95_lat,
            jitter_ms=jitter,
            packet_loss_pct=packet_loss_pct,
            consecutive_successes=consecutive_successes,
            consecutive_failures=consecutive_failures,
            uptime_pct=uptime_pct,
            last_success_utc=last_success_utc,
            last_failure_utc=last_failure_utc,
            total_probes=total_probes,
            valid_probes=valid_probes,
            timeout_count=timeout_count,
            dns_error_count=dns_error_count,
            engine_error_count=engine_error_count,
        )
