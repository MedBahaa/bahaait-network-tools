from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from core.monitoring_state import ProbeOutcome
from core.network_quality import compute_ipdv_jitter, compute_percentile
from utils.db import DatabaseManager


PERIOD_CONFIG: Dict[str, Tuple[timedelta, int]] = {
    "1m": (timedelta(minutes=1), 5),
    "5m": (timedelta(minutes=5), 15),
    "15m": (timedelta(minutes=15), 30),
    "1h": (timedelta(hours=1), 60),
    "24h": (timedelta(hours=24), 900),
}

GRANULARITY_SECONDS: Dict[str, int] = {
    "1m": 60,
    "5m": 300,
    "15m": 900,
    "1h": 3600,
    "24h": 86400,
}


def _status_to_outcome(status_str: str) -> ProbeOutcome:
    s = (status_str or "").upper()
    if s == "UP":
        return ProbeOutcome.SUCCESS
    if s == "DNS_ERROR":
        return ProbeOutcome.DNS_ERROR
    if s == "ENGINE_ERROR":
        return ProbeOutcome.ENGINE_ERROR
    return ProbeOutcome.TIMEOUT


class MonitoringStatisticsService:
    """Aggregates raw PingMeasurement data into multi-period rollups and chart series."""

    def __init__(self, db: DatabaseManager):
        self.db = db

    @staticmethod
    def _bucketize(ts: datetime, bucket_sec: int) -> datetime:
        epoch = int(ts.timestamp())
        aligned = epoch - (epoch % bucket_sec)
        return datetime.fromtimestamp(aligned)

    @staticmethod
    def _aggregate_bucket(host_address: str, granularity: str, bucket_start: datetime, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        latencies: List[float] = []
        success_count = 0
        timeout_count = 0

        for r in rows:
            outcome = _status_to_outcome(r.get("status", ""))
            if outcome == ProbeOutcome.SUCCESS:
                success_count += 1
                lat = r.get("latency_ms")
                if lat is not None:
                    latencies.append(float(lat))
            elif outcome == ProbeOutcome.TIMEOUT:
                timeout_count += 1

        valid_probes = success_count + timeout_count
        total_probes = len(rows)
        packet_loss_pct = round((timeout_count / valid_probes) * 100.0, 2) if valid_probes > 0 else 0.0
        uptime_pct = round((success_count / valid_probes) * 100.0, 2) if valid_probes > 0 else 100.0

        if latencies:
            sorted_lat = sorted(latencies)
            min_lat = round(sorted_lat[0], 2)
            max_lat = round(sorted_lat[-1], 2)
            avg_lat = round(sum(latencies) / len(latencies), 2)
            p95_lat = round(compute_percentile(sorted_lat, 95.0), 2)
            jitter = compute_ipdv_jitter(latencies)
        else:
            min_lat = max_lat = avg_lat = p95_lat = jitter = 0.0

        return {
            "host_address": host_address,
            "bucket_start": bucket_start,
            "granularity": granularity,
            "total_probes": total_probes,
            "valid_probes": valid_probes,
            "failed_probes": timeout_count,
            "packet_loss_pct": packet_loss_pct,
            "min_latency_ms": min_lat,
            "avg_latency_ms": avg_lat,
            "max_latency_ms": max_lat,
            "p95_latency_ms": p95_lat,
            "jitter_ms": jitter,
            "uptime_pct": uptime_pct,
        }

    def aggregate_measurements(
        self,
        host_address: str,
        granularity: str = "1m",
        since: Optional[datetime] = None,
        bucket_seconds_override: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        bucket_sec = bucket_seconds_override or GRANULARITY_SECONDS.get(granularity, 60)
        measurements = self.db.get_measurements(host_address, since=since, limit=100000)
        if not measurements:
            return []

        buckets: Dict[datetime, List[Dict[str, Any]]] = defaultdict(list)
        for m in measurements:
            ts = m["timestamp"]
            b_start = self._bucketize(ts, bucket_sec)
            buckets[b_start].append(m)

        aggregated = [
            self._aggregate_bucket(host_address, granularity, b_start, buckets[b_start])
            for b_start in sorted(buckets.keys())
        ]
        return aggregated

    def persist_rollups(
        self,
        host_address: str,
        granularity: str = "1m",
        since: Optional[datetime] = None,
    ) -> int:
        rows = self.aggregate_measurements(host_address, granularity=granularity, since=since)
        if not rows:
            return 0
        return self.db.save_statistics_batch(rows)

    def get_chart_series(self, host_address: str, period: str = "5m") -> List[Dict[str, Any]]:
        window_td, bucket_sec = PERIOD_CONFIG.get(period, PERIOD_CONFIG["5m"])
        since = datetime.utcnow() - window_td

        buckets = self.aggregate_measurements(
            host_address,
            granularity=period,
            since=since,
            bucket_seconds_override=bucket_sec,
        )

        # Fallback to persisted rollups if raw measurements were pruned or absent
        if not buckets:
            persisted_granularity = "1h" if period == "24h" else ("5m" if period in ("15m", "1h") else "1m")
            rollups = self.db.get_statistics(host_address, persisted_granularity, since=since)
            buckets = rollups

        return [
            {
                "timestamp": b["bucket_start"],
                "latency_ms": b["avg_latency_ms"],
                "min_latency_ms": b["min_latency_ms"],
                "max_latency_ms": b["max_latency_ms"],
                "p95_latency_ms": b["p95_latency_ms"],
                "packet_loss_pct": b["packet_loss_pct"],
                "jitter_ms": b["jitter_ms"],
                "uptime_pct": b["uptime_pct"],
            }
            for b in buckets
        ]

    @staticmethod
    def get_global_summary(
        host_snapshots: Dict[str, Dict[str, Any]],
        active_incidents_count: int = 0,
    ) -> Dict[str, Any]:
        total = len(host_snapshots)
        online = 0
        degraded = 0
        offline = 0
        recovering = 0
        paused = 0
        latencies: List[float] = []
        losses: List[float] = []
        uptimes: List[float] = []

        for snap in host_snapshots.values():
            st = str(snap.get("state", "UNKNOWN")).upper()
            if st == "UP":
                online += 1
            elif st == "DEGRADED":
                degraded += 1
            elif st == "DOWN":
                offline += 1
            elif st == "RECOVERING":
                recovering += 1
            elif st == "PAUSED":
                paused += 1

            if st != "PAUSED":
                lat = snap.get("current_latency_ms")
                if lat is None or lat <= 0:
                    lat = snap.get("avg_latency_ms", 0.0)
                if lat and lat > 0:
                    latencies.append(float(lat))
                losses.append(float(snap.get("packet_loss_pct", 0.0)))
                uptimes.append(float(snap.get("uptime_pct", 100.0)))

        return {
            "total_hosts": total,
            "online_hosts": online,
            "degraded_hosts": degraded,
            "offline_hosts": offline,
            "recovering_hosts": recovering,
            "paused_hosts": paused,
            "active_incidents": active_incidents_count,
            "avg_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0.0,
            "global_packet_loss_pct": round(sum(losses) / len(losses), 2) if losses else 0.0,
            "global_uptime_pct": round(sum(uptimes) / len(uptimes), 2) if uptimes else 100.0,
        }
