import csv
from datetime import datetime
import getpass
import json
from typing import Any, Dict, Iterable, List, Optional
import uuid

from utils.db import DatabaseManager, InfrastructureAudit
from utils.infra_security import compute_sha256, redact_dict, redact_sensitive_text


class AuditLogger:
    """Append-only tamper-evident audit logger backed by infrastructure_audit."""

    def __init__(self, db: DatabaseManager, auth_manager: Any = None) -> None:
        self.db = db
        self.auth_manager = auth_manager

    def resolve_current_user(self) -> str:
        if self.auth_manager is not None and getattr(self.auth_manager, "user", None) is not None:
            email = getattr(self.auth_manager.user, "email", None)
            if email:
                return str(email)
        try:
            return getpass.getuser() or "system"
        except Exception:
            return "system"

    @staticmethod
    def _compute_record_hash(payload: Dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return compute_sha256(canonical)

    @staticmethod
    def _row_to_dict(row: InfrastructureAudit) -> Dict[str, Any]:
        return {
            "id": row.id,
            "event_uid": row.event_uid,
            "timestamp": row.timestamp,
            "username": row.username or "",
            "site_id": row.site_id,
            "site_name": row.site_name or "",
            "device_id": row.device_id,
            "device_name": row.device_name or "",
            "device_ip": row.device_ip or "",
            "operation": row.operation,
            "command_tier": row.command_tier or "SYSTEM",
            "previous_value": json.loads(row.previous_value_json or "{}"),
            "new_value": json.loads(row.new_value_json or "{}"),
            "result": row.result or "SUCCESS",
            "ticket_ref": row.ticket_ref or "",
            "detail": row.detail or "",
            "record_hash": row.record_hash or "",
        }

    def record_event(
        self,
        operation: str,
        result: str = "SUCCESS",
        device_id: Optional[int] = None,
        device_name: str = "",
        device_ip: str = "",
        site_id: Optional[int] = None,
        site_name: str = "",
        command_tier: str = "SYSTEM",
        previous_value: Optional[Dict[str, Any]] = None,
        new_value: Optional[Dict[str, Any]] = None,
        ticket_ref: str = "",
        detail: str = "",
        username: Optional[str] = None,
        extra_secrets: Iterable[str] = (),
        timestamp: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        ts = timestamp or datetime.utcnow()
        actor = username or self.resolve_current_user()
        event_uid = f"AUD-{ts.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8].upper()}"

        def _clean_val(v: Any) -> Dict[str, Any]:
            if v is None or v == "":
                return {}
            if isinstance(v, dict):
                return redact_dict(v, extra_secrets=extra_secrets)
            return {"value": redact_sensitive_text(str(v), extra_secrets=extra_secrets)}

        clean_prev = _clean_val(previous_value)
        clean_new = _clean_val(new_value)
        clean_detail = redact_sensitive_text(detail, extra_secrets=extra_secrets)

        prev_json = json.dumps(clean_prev, sort_keys=True, default=str)
        new_json = json.dumps(clean_new, sort_keys=True, default=str)

        hash_input = {
            "event_uid": event_uid,
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "username": actor,
            "site_id": site_id,
            "device_id": device_id,
            "device_ip": device_ip,
            "operation": operation,
            "command_tier": command_tier,
            "previous_value_json": prev_json,
            "new_value_json": new_json,
            "result": result,
            "detail": clean_detail,
        }
        rec_hash = self._compute_record_hash(hash_input)

        with self.db.Session() as session:
            row = InfrastructureAudit(
                event_uid=event_uid,
                timestamp=ts,
                username=actor,
                site_id=site_id,
                site_name=site_name or "",
                device_id=device_id,
                device_name=device_name or "",
                device_ip=device_ip or "",
                operation=operation,
                command_tier=command_tier,
                previous_value_json=prev_json,
                new_value_json=new_json,
                result=result,
                ticket_ref=ticket_ref or "",
                detail=clean_detail,
                record_hash=rec_hash,
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return self._row_to_dict(row)

    def verify_record_integrity(self, record: Dict[str, Any]) -> bool:
        ts = record.get("timestamp")
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S.%f") if isinstance(ts, datetime) else str(ts or "")
        hash_input = {
            "event_uid": record.get("event_uid", ""),
            "timestamp": ts_str,
            "username": record.get("username", ""),
            "site_id": record.get("site_id"),
            "device_id": record.get("device_id"),
            "device_ip": record.get("device_ip", ""),
            "operation": record.get("operation", ""),
            "command_tier": record.get("command_tier", "SYSTEM"),
            "previous_value_json": json.dumps(record.get("previous_value", {}), sort_keys=True, default=str),
            "new_value_json": json.dumps(record.get("new_value", {}), sort_keys=True, default=str),
            "result": record.get("result", ""),
            "detail": record.get("detail", ""),
        }
        return self._compute_record_hash(hash_input) == str(record.get("record_hash", ""))

    def query_events(
        self,
        search: str = "",
        username: str = "",
        site_id: Optional[int] = None,
        device_id: Optional[int] = None,
        operation: str = "",
        result: str = "",
        command_tier: str = "",
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        with self.db.Session() as session:
            q = session.query(InfrastructureAudit)
            if username:
                q = q.filter(InfrastructureAudit.username == username)
            if site_id is not None:
                q = q.filter(InfrastructureAudit.site_id == int(site_id))
            if device_id is not None:
                q = q.filter(InfrastructureAudit.device_id == int(device_id))
            if operation:
                q = q.filter(InfrastructureAudit.operation == operation)
            if result:
                q = q.filter(InfrastructureAudit.result == result)
            if command_tier:
                q = q.filter(InfrastructureAudit.command_tier == command_tier)
            if since is not None:
                q = q.filter(InfrastructureAudit.timestamp >= since)
            if until is not None:
                q = q.filter(InfrastructureAudit.timestamp <= until)
            rows = q.order_by(InfrastructureAudit.timestamp.desc(), InfrastructureAudit.id.desc()).limit(limit).all()
            items = [self._row_to_dict(r) for r in rows]

        term = str(search or "").strip().lower()
        if not term:
            return items
        return [
            ev
            for ev in items
            if (
                term in ev["event_uid"].lower()
                or term in ev["username"].lower()
                or term in ev["site_name"].lower()
                or term in ev["device_name"].lower()
                or term in ev["device_ip"].lower()
                or term in ev["operation"].lower()
                or term in ev["detail"].lower()
                or term in ev["ticket_ref"].lower()
            )
        ]

    @staticmethod
    def export_csv(events: List[Dict[str, Any]], file_path: str) -> None:
        headers = [
            "Event ID",
            "Timestamp",
            "User",
            "Site",
            "Device",
            "IP",
            "Operation",
            "Command Tier",
            "Previous Value",
            "New Value",
            "Result",
            "Ticket Ref",
            "Detail",
        ]
        with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for ev in events:
                ts = ev.get("timestamp")
                ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime) else str(ts or "")
                writer.writerow([
                    ev.get("event_uid", ""),
                    ts_str,
                    ev.get("username", ""),
                    ev.get("site_name", ""),
                    ev.get("device_name", ""),
                    ev.get("device_ip", ""),
                    ev.get("operation", ""),
                    ev.get("command_tier", ""),
                    json.dumps(ev.get("previous_value", {}), ensure_ascii=False),
                    json.dumps(ev.get("new_value", {}), ensure_ascii=False),
                    ev.get("result", ""),
                    ev.get("ticket_ref", ""),
                    ev.get("detail", ""),
                ])

    @staticmethod
    def export_json(events: List[Dict[str, Any]], file_path: str) -> None:
        serializable = []
        for ev in events:
            item = dict(ev)
            if isinstance(item.get("timestamp"), datetime):
                item["timestamp"] = item["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            serializable.append(item)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2, ensure_ascii=False)
