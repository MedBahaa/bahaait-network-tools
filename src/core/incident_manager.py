import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from core.monitoring_state import HostState, StateTransition
from core.network_quality import QualitySnapshot
from utils.db import DatabaseManager


class IncidentStatus(str, Enum):
    DETECTED = "DETECTED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RECOVERED = "RECOVERED"
    CLOSED = "CLOSED"


class IncidentSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class IncidentManager:
    """Manages lifecycle, deduplication, and persistence of monitoring incidents."""

    def __init__(self, db: DatabaseManager):
        self.db = db
        self._active_by_host: Dict[str, Dict[str, Any]] = {}
        self._load_open_incidents()

    def _load_open_incidents(self) -> None:
        try:
            open_rows = self.db.get_incidents(status=IncidentStatus.DETECTED.value) + self.db.get_incidents(
                status=IncidentStatus.ACKNOWLEDGED.value
            )
            for inc in open_rows:
                addr = inc["host_address"]
                if addr not in self._active_by_host:
                    self._active_by_host[addr] = inc
        except Exception:
            pass

    @staticmethod
    def _generate_uid(now_utc: Optional[datetime] = None) -> str:
        dt = now_utc or datetime.utcnow()
        short_hex = uuid.uuid4().hex[:6].upper()
        return f"INC-{dt.strftime('%Y%m%d')}-{short_hex}"

    def get_active_incident(self, host_address: str) -> Optional[Dict[str, Any]]:
        """O(1) in-memory lookup of currently open incident for a host."""
        return self._active_by_host.get(host_address)

    def get_active_incidents(self) -> List[Dict[str, Any]]:
        return list(self._active_by_host.values())

    def handle_transition(
        self,
        host_id: Optional[int],
        host_name: str,
        host_address: str,
        transition: StateTransition,
        quality: QualitySnapshot,
    ) -> Optional[Dict[str, Any]]:
        new_state = transition.new_state
        now_utc = transition.timestamp_utc
        active = self.get_active_incident(host_address)

        if new_state == HostState.DOWN:
            if active:
                duration = max(0.0, (now_utc - active["start_time"]).total_seconds())
                updates = {
                    "severity": IncidentSeverity.CRITICAL.value,
                    "incident_type": "OUTAGE",
                    "failed_probes": max(active.get("failed_probes", 0), quality.consecutive_failures),
                    "packet_loss_pct": quality.packet_loss_pct,
                    "duration_seconds": round(duration, 2),
                }
                updated = self.db.update_incident(active["id"], updates)
                if updated:
                    self._active_by_host[host_address] = updated
                return updated

            inc_data = {
                "incident_uid": self._generate_uid(now_utc),
                "host_id": host_id,
                "host_name": host_name or host_address,
                "host_address": host_address,
                "incident_type": "OUTAGE",
                "severity": IncidentSeverity.CRITICAL.value,
                "start_time": now_utc,
                "duration_seconds": 0.0,
                "failed_probes": quality.consecutive_failures,
                "packet_loss_pct": quality.packet_loss_pct,
                "avg_latency_before_ms": quality.avg_latency_ms,
                "status": IncidentStatus.DETECTED.value,
                "acknowledged": False,
                "comments": "",
            }
            created = self.db.create_incident(inc_data)
            self._active_by_host[host_address] = created
            return created

        if new_state == HostState.DEGRADED:
            if active:
                duration = max(0.0, (now_utc - active["start_time"]).total_seconds())
                updates = {
                    "failed_probes": max(active.get("failed_probes", 0), quality.consecutive_failures),
                    "packet_loss_pct": max(active.get("packet_loss_pct", 0.0), quality.packet_loss_pct),
                    "duration_seconds": round(duration, 2),
                }
                updated = self.db.update_incident(active["id"], updates)
                if updated:
                    self._active_by_host[host_address] = updated
                return updated

            inc_data = {
                "incident_uid": self._generate_uid(now_utc),
                "host_id": host_id,
                "host_name": host_name or host_address,
                "host_address": host_address,
                "incident_type": transition.reason or "DEGRADED",
                "severity": IncidentSeverity.WARNING.value,
                "start_time": now_utc,
                "duration_seconds": 0.0,
                "failed_probes": max(quality.consecutive_failures, quality.timeout_count),
                "packet_loss_pct": quality.packet_loss_pct,
                "avg_latency_before_ms": quality.avg_latency_ms,
                "status": IncidentStatus.DETECTED.value,
                "acknowledged": False,
                "comments": transition.details,
            }
            created = self.db.create_incident(inc_data)
            self._active_by_host[host_address] = created
            return created

        if new_state == HostState.RECOVERING:
            if active:
                duration = max(0.0, (now_utc - active["start_time"]).total_seconds())
                updated = self.db.update_incident(active["id"], {"duration_seconds": round(duration, 2)})
                if updated:
                    self._active_by_host[host_address] = updated
                return updated
            return None

        if new_state == HostState.UP:
            if active:
                duration = max(0.0, (now_utc - active["start_time"]).total_seconds())
                updates = {
                    "status": IncidentStatus.RECOVERED.value,
                    "end_time": now_utc,
                    "duration_seconds": round(duration, 2),
                    "recovery_latency_ms": quality.current_latency_ms,
                }
                updated = self.db.update_incident(active["id"], updates)
                self._active_by_host.pop(host_address, None)
                return updated

        return None

    def update_active_incident_metrics(
        self,
        host_address: str,
        quality: QualitySnapshot,
        now_utc: Optional[datetime] = None,
    ) -> Optional[Dict[str, Any]]:
        active = self._active_by_host.get(host_address)
        if not active:
            return None
        ts = now_utc or datetime.utcnow()
        duration = max(0.0, (ts - active["start_time"]).total_seconds())
        updates = {
            "duration_seconds": round(duration, 2),
            "failed_probes": max(active.get("failed_probes", 0), quality.consecutive_failures),
            "packet_loss_pct": max(active.get("packet_loss_pct", 0.0), quality.packet_loss_pct),
        }
        updated = self.db.update_incident(active["id"], updates)
        if updated:
            self._active_by_host[host_address] = updated
        return updated

    def acknowledge_incident(self, incident_id: int, comment: str = "") -> Optional[Dict[str, Any]]:
        existing = self.db.get_incident_by_id(incident_id)
        if not existing:
            return None
        now_utc = datetime.utcnow()
        updates: Dict[str, Any] = {
            "acknowledged": True,
            "acknowledged_at": now_utc,
        }
        if existing["status"] == IncidentStatus.DETECTED.value:
            updates["status"] = IncidentStatus.ACKNOWLEDGED.value
        if comment.strip():
            prev_comments = (existing.get("comments") or "").strip()
            stamp = now_utc.strftime("%Y-%m-%d %H:%M:%S")
            new_line = f"[{stamp}] {comment.strip()}"
            updates["comments"] = f"{prev_comments}\n{new_line}".strip()
        updated = self.db.update_incident(incident_id, updates)
        if updated and updated["host_address"] in self._active_by_host:
            self._active_by_host[updated["host_address"]] = updated
        return updated

    def add_comment(self, incident_id: int, comment: str) -> Optional[Dict[str, Any]]:
        existing = self.db.get_incident_by_id(incident_id)
        if not existing or not comment.strip():
            return existing
        prev_comments = (existing.get("comments") or "").strip()
        stamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        new_line = f"[{stamp}] {comment.strip()}"
        updated_comments = f"{prev_comments}\n{new_line}".strip()
        updated = self.db.update_incident(incident_id, {"comments": updated_comments})
        if updated and updated["host_address"] in self._active_by_host:
            self._active_by_host[updated["host_address"]] = updated
        return updated

    def close_incident(self, incident_id: int, comment: str = "") -> Optional[Dict[str, Any]]:
        existing = self.db.get_incident_by_id(incident_id)
        if not existing:
            return None
        now_utc = datetime.utcnow()
        updates: Dict[str, Any] = {
            "status": IncidentStatus.CLOSED.value,
        }
        if existing.get("end_time") is None:
            updates["end_time"] = now_utc
            updates["duration_seconds"] = round(
                max(0.0, (now_utc - existing["start_time"]).total_seconds()), 2
            )
        if comment.strip():
            prev_comments = (existing.get("comments") or "").strip()
            stamp = now_utc.strftime("%Y-%m-%d %H:%M:%S")
            new_line = f"[{stamp}] {comment.strip()}"
            updates["comments"] = f"{prev_comments}\n{new_line}".strip()
        updated = self.db.update_incident(incident_id, updates)
        if updated:
            self._active_by_host.pop(updated["host_address"], None)
        return updated

    def delete_incident(self, incident_id: int) -> bool:
        existing = self.db.get_incident_by_id(incident_id)
        if not existing:
            return False
        deleted = self.db.delete_incident(incident_id)
        if deleted:
            active = self._active_by_host.get(existing["host_address"])
            if active and active.get("id") == incident_id:
                self._active_by_host.pop(existing["host_address"], None)
        return deleted

    def get_incidents(
        self,
        severity: Optional[str] = None,
        host_address: Optional[str] = None,
        status: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        return self.db.get_incidents(
            severity=severity,
            host_address=host_address,
            status=status,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
        )
