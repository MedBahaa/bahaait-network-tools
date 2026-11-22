from datetime import datetime, timedelta
import json
import os
from typing import Any, Callable, Dict, List, Optional, Tuple
import uuid

from core.audit_logger import AuditLogger
from core.backup_adapters import (
    ADAPTER_REGISTRY,
    BaseBackupAdapter,
    resolve_backup_adapter,
)
from core.config_diff import compute_config_diff
from utils.db import (
    ConfigurationBackup,
    ConfigurationChange,
    DatabaseManager,
    InfrastructureDevice,
    SSHProfile,
)
from utils.infra_security import (
    decrypt_secret,
    load_encrypted_backup,
    redact_sensitive_text,
    save_encrypted_backup,
    verify_sha256,
)


def _default_backup_dir() -> str:
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    path = os.path.join(base, "BahaaIT_Network_Tools", "config_backups")
    os.makedirs(path, exist_ok=True)
    return path


class BackupManager:
    """Encrypted network configuration backup, integrity verification, diffing & controlled restore."""

    def __init__(
        self,
        db: DatabaseManager,
        audit_logger: Optional[AuditLogger] = None,
        base_dir: Optional[str] = None,
    ) -> None:
        self.db = db
        self.audit = audit_logger or AuditLogger(db)
        self.base_dir = base_dir or _default_backup_dir()
        os.makedirs(self.base_dir, exist_ok=True)

    def _resolve_device_credentials(self, session: Any, dev: InfrastructureDevice) -> Dict[str, Any]:
        creds: Dict[str, Any] = {"port": 22}
        if dev.ssh_profile_id:
            prof = session.query(SSHProfile).filter_by(id=dev.ssh_profile_id).first()
            if prof:
                creds = {
                    "port": int(prof.port or 22),
                    "username": prof.username or "",
                    "password": decrypt_secret(prof.encrypted_secret or ""),
                    "private_key_path": prof.private_key_path or None,
                }
        return creds

    @staticmethod
    def _dev_to_dict(dev: InfrastructureDevice) -> Dict[str, Any]:
        return {
            "id": dev.id,
            "hostname": dev.hostname,
            "management_ip": dev.management_ip,
            "vendor": dev.vendor or "Generic",
            "model": dev.model or "",
            "firmware_version": dev.firmware_version or "",
            "category": dev.category or "Other",
            "management_protocol": dev.management_protocol or "SSH",
            "site_id": dev.site_id,
        }

    def backup_device(
        self,
        device_id: int,
        *,
        triggered_by: str = "manual",
        status_tag: str = "SUCCESS",
        credentials: Optional[Dict[str, Any]] = None,
        ssh_transport: Optional[Callable[..., Tuple[int, str, str]]] = None,
        api_transport: Optional[Callable[..., Dict[str, Any]]] = None,
        adapter_override: Optional[BaseBackupAdapter] = None,
    ) -> Dict[str, Any]:
        """Collect, DPAPI-encrypt, SHA-256 hash and store device config + track changes."""
        with self.db.Session() as session:
            dev = session.query(InfrastructureDevice).filter_by(id=int(device_id)).first()
            if not dev:
                raise ValueError(f"Infrastructure device {device_id} not found.")
            dev_dict = self._dev_to_dict(dev)
            creds = credentials if credentials is not None else self._resolve_device_credentials(session, dev)

        adapter = adapter_override or resolve_backup_adapter(
            vendor=dev_dict["vendor"],
            model=dev_dict["model"],
            category=dev_dict["category"],
            protocol=dev_dict["management_protocol"],
        )

        backup_uid = f"BKP-{uuid.uuid4().hex[:12].upper()}"
        now = datetime.utcnow()
        safe_host = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in dev_dict["hostname"])[:40]
        file_name = f"{safe_host}_{now.strftime('%Y%m%d_%H%M%S')}_{backup_uid}.bhitbkp"
        dest_path = os.path.join(self.base_dir, file_name)

        try:
            res = adapter.fetch_running_config(
                dev_dict,
                credentials=creds,
                ssh_transport=ssh_transport,
                api_transport=api_transport,
            )
            cfg_text = str(res.get("config_text") or "")
            if not cfg_text.strip():
                raise ValueError("Device returned empty configuration.")
            size_bytes, sha256_hex = save_encrypted_backup(cfg_text, dest_path)

            with self.db.Session() as session:
                prev = (
                    session.query(ConfigurationBackup)
                    .filter(
                        ConfigurationBackup.device_id == dev_dict["id"],
                        ConfigurationBackup.status.in_(["SUCCESS", "VERIFIED", "PRE_RESTORE"]),
                    )
                    .order_by(ConfigurationBackup.id.desc())
                    .first()
                )
                row = ConfigurationBackup(
                    backup_uid=backup_uid,
                    device_id=dev_dict["id"],
                    device_hostname=dev_dict["hostname"],
                    device_ip=dev_dict["management_ip"],
                    device_model=dev_dict["model"],
                    firmware_version=res.get("firmware_hint") or dev_dict["firmware_version"],
                    vendor_adapter=res.get("adapter") or adapter.adapter_name,
                    backup_method=res.get("method") or adapter.backup_method,
                    file_path=dest_path,
                    is_encrypted=True,
                    file_size_bytes=size_bytes,
                    sha256_checksum=sha256_hex,
                    status=status_tag,
                    triggered_by=triggered_by,
                    timestamp=now,
                )
                session.add(row)
                session.flush()

                # Compute automatic change delta against previous good backup if present
                change_summary = "Initial baseline backup"
                if prev and prev.file_path and os.path.exists(prev.file_path):
                    try:
                        prev_text = load_encrypted_backup(prev.file_path, expected_sha256=prev.sha256_checksum)
                        diff = compute_config_diff(
                            prev_text,
                            cfg_text,
                            label_a=prev.backup_uid,
                            label_b=backup_uid,
                            redact=True,
                        )
                        if diff["has_changes"]:
                            change_summary = diff["diff_summary"]
                            session.add(
                                ConfigurationChange(
                                    device_id=dev_dict["id"],
                                    previous_backup_id=prev.id,
                                    current_backup_id=row.id,
                                    added_lines=diff["added_lines"],
                                    removed_lines=diff["removed_lines"],
                                    changed_sections_json=json.dumps(diff["changed_sections"]),
                                    diff_summary=diff["diff_summary"],
                                    unified_diff_redacted=diff["unified_diff"][:20000],
                                    detected_at=now,
                                )
                            )
                        else:
                            change_summary = "Unchanged from previous backup"
                    except Exception:
                        pass

                session.commit()
                rec = self._backup_to_dict(row)
                rec["change_summary"] = change_summary

        except Exception as exc:
            err_msg = str(exc)
            with self.db.Session() as session:
                fail_row = ConfigurationBackup(
                    backup_uid=backup_uid,
                    device_id=dev_dict["id"],
                    device_hostname=dev_dict["hostname"],
                    device_ip=dev_dict["management_ip"],
                    device_model=dev_dict["model"],
                    firmware_version=dev_dict["firmware_version"],
                    vendor_adapter=adapter.adapter_name,
                    backup_method=adapter.backup_method,
                    file_path="",
                    is_encrypted=False,
                    file_size_bytes=0,
                    sha256_checksum="",
                    status="FAILED",
                    error_detail=err_msg[:500],
                    triggered_by=triggered_by,
                    timestamp=now,
                )
                session.add(fail_row)
                session.commit()
                rec = self._backup_to_dict(fail_row)

            self.audit.record_event(
                operation="BACKUP_FAILED",
                result="FAILURE",
                device_id=dev_dict["id"],
                device_name=dev_dict["hostname"],
                device_ip=dev_dict["management_ip"],
                site_id=dev_dict["site_id"],
                command_tier="READ_ONLY",
                detail=err_msg[:400],
            )
            return rec

        self.audit.record_event(
            operation="BACKUP_CREATED",
            result="SUCCESS",
            device_id=dev_dict["id"],
            device_name=dev_dict["hostname"],
            device_ip=dev_dict["management_ip"],
            site_id=dev_dict["site_id"],
            command_tier="READ_ONLY",
            new_value=f"{backup_uid} | sha256={sha256_hex[:16]}...",
            detail=f"Adapter={rec['vendor_adapter']} | {change_summary}",
        )
        return rec

    def backup_devices(
        self,
        device_ids: List[int],
        *,
        triggered_by: str = "batch",
        credentials_by_device: Optional[Dict[int, Dict[str, Any]]] = None,
        ssh_transport: Optional[Callable[..., Tuple[int, str, str]]] = None,
        api_transport: Optional[Callable[..., Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Run isolated per-device backups; one device failure never aborts remaining devices."""
        results: List[Dict[str, Any]] = []
        ok_cnt = 0
        fail_cnt = 0
        for did in device_ids:
            creds = (credentials_by_device or {}).get(did)
            res = self.backup_device(
                did,
                triggered_by=triggered_by,
                credentials=creds,
                ssh_transport=ssh_transport,
                api_transport=api_transport,
            )
            results.append(res)
            if res["status"] == "FAILED":
                fail_cnt += 1
            else:
                ok_cnt += 1
        return {"total": len(device_ids), "succeeded": ok_cnt, "failed": fail_cnt, "results": results}

    def backup_site(
        self,
        site_id: Optional[int],
        *,
        triggered_by: str = "site_batch",
        ssh_transport: Optional[Callable[..., Tuple[int, str, str]]] = None,
        api_transport: Optional[Callable[..., Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        with self.db.Session() as session:
            q = session.query(InfrastructureDevice.id)
            if site_id is not None:
                q = q.filter(InfrastructureDevice.site_id == int(site_id))
            ids = [row[0] for row in q.all()]
        return self.backup_devices(
            ids,
            triggered_by=triggered_by,
            ssh_transport=ssh_transport,
            api_transport=api_transport,
        )

    @staticmethod
    def _backup_to_dict(r: ConfigurationBackup) -> Dict[str, Any]:
        return {
            "id": r.id,
            "backup_uid": r.backup_uid,
            "device_id": r.device_id,
            "device_hostname": r.device_hostname or "",
            "device_ip": r.device_ip or "",
            "device_model": r.device_model or "",
            "firmware_version": r.firmware_version or "",
            "vendor_adapter": r.vendor_adapter or "generic_ssh",
            "backup_method": r.backup_method or "SSH",
            "file_path": r.file_path or "",
            "is_encrypted": bool(r.is_encrypted),
            "file_size_bytes": int(r.file_size_bytes or 0),
            "sha256_checksum": r.sha256_checksum or "",
            "status": r.status or "SUCCESS",
            "error_detail": r.error_detail or "",
            "triggered_by": r.triggered_by or "manual",
            "timestamp": r.timestamp,
        }

    def list_backups(
        self,
        device_id: Optional[int] = None,
        site_id: Optional[int] = None,
        status: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        with self.db.Session() as session:
            q = session.query(ConfigurationBackup)
            if device_id is not None:
                q = q.filter(ConfigurationBackup.device_id == int(device_id))
            elif site_id is not None:
                site_dev_ids = [
                    d.id for d in session.query(InfrastructureDevice.id).filter_by(site_id=int(site_id)).all()
                ]
                q = q.filter(ConfigurationBackup.device_id.in_(site_dev_ids or [-1]))
            if status:
                q = q.filter(ConfigurationBackup.status == status)
            rows = q.order_by(ConfigurationBackup.id.desc()).limit(limit).all()
            return [self._backup_to_dict(r) for r in rows]

    def verify_backup_integrity(self, backup_id: int) -> Tuple[bool, str]:
        with self.db.Session() as session:
            row = session.query(ConfigurationBackup).filter_by(id=int(backup_id)).first()
            if not row:
                return False, "Backup record not found."
            if row.status == "FAILED" or not row.file_path:
                return False, "Backup failed and has no stored artifact."
            if not os.path.exists(row.file_path):
                return False, f"Encrypted backup file missing: {row.file_path}"
            try:
                load_encrypted_backup(row.file_path, expected_sha256=row.sha256_checksum)
                return True, f"SHA-256 verified ({row.sha256_checksum[:16]}...)"
            except Exception as exc:
                return False, f"Integrity check failed: {exc}"

    def get_backup_content(self, backup_id: int, *, redact: bool = True) -> str:
        with self.db.Session() as session:
            row = session.query(ConfigurationBackup).filter_by(id=int(backup_id)).first()
            if not row:
                raise ValueError(f"Backup {backup_id} not found.")
            if not row.file_path or not os.path.exists(row.file_path):
                raise FileNotFoundError("Backup file is missing on disk.")
            fp = row.file_path
            sha = row.sha256_checksum

        plaintext = load_encrypted_backup(fp, expected_sha256=sha)
        return redact_sensitive_text(plaintext) if redact else plaintext

    def export_backup(self, backup_id: int, dest_path: str, *, redacted: bool = True) -> None:
        content = self.get_backup_content(backup_id, redact=redacted)
        with open(dest_path, "w", encoding="utf-8") as fh:
            fh.write(content)

    def compare_backups(self, backup_id_a: int, backup_id_b: int) -> Dict[str, Any]:
        with self.db.Session() as session:
            ra = session.query(ConfigurationBackup).filter_by(id=int(backup_id_a)).first()
            rb = session.query(ConfigurationBackup).filter_by(id=int(backup_id_b)).first()
            if not ra or not rb:
                raise ValueError("Both baseline and candidate backup records must exist.")
            label_a = f"{ra.device_hostname} | {ra.backup_uid}"
            label_b = f"{rb.device_hostname} | {rb.backup_uid}"

        text_a = self.get_backup_content(backup_id_a, redact=True)
        text_b = self.get_backup_content(backup_id_b, redact=True)
        return compute_config_diff(text_a, text_b, label_a=label_a, label_b=label_b, redact=True)

    def list_changes(self, device_id: Optional[int] = None, limit: int = 100) -> List[Dict[str, Any]]:
        with self.db.Session() as session:
            q = session.query(ConfigurationChange)
            if device_id is not None:
                q = q.filter(ConfigurationChange.device_id == int(device_id))
            rows = q.order_by(ConfigurationChange.id.desc()).limit(limit).all()
            return [
                {
                    "id": c.id,
                    "device_id": c.device_id,
                    "previous_backup_id": c.previous_backup_id,
                    "current_backup_id": c.current_backup_id,
                    "added_lines": c.added_lines,
                    "removed_lines": c.removed_lines,
                    "changed_sections": json.loads(c.changed_sections_json or "{}"),
                    "diff_summary": c.diff_summary,
                    "unified_diff_redacted": c.unified_diff_redacted,
                    "detected_at": c.detected_at,
                }
                for c in rows
            ]

    def prepare_restore_plan(self, backup_id: int, target_device_id: int) -> Dict[str, Any]:
        """Verify backup integrity, device identity and vendor adapter compatibility before restore."""
        ok_int, msg_int = self.verify_backup_integrity(backup_id)
        if not ok_int:
            raise ValueError(f"Cannot prepare restore: {msg_int}")

        with self.db.Session() as session:
            bkp = session.query(ConfigurationBackup).filter_by(id=int(backup_id)).first()
            dev = session.query(InfrastructureDevice).filter_by(id=int(target_device_id)).first()
            if not bkp or not dev:
                raise ValueError("Backup or target device not found.")
            bkp_dict = self._backup_to_dict(bkp)
            dev_dict = self._dev_to_dict(dev)

        target_adapter = resolve_backup_adapter(
            vendor=dev_dict["vendor"],
            model=dev_dict["model"],
            category=dev_dict["category"],
            protocol=dev_dict["management_protocol"],
        )
        if bkp_dict["vendor_adapter"] != target_adapter.adapter_name:
            raise ValueError(
                f"Incompatible backup adapter '{bkp_dict['vendor_adapter']}' for target device "
                f"'{dev_dict['hostname']}' ({target_adapter.adapter_name}). Restore blocked."
            )
        if not target_adapter.supports_restore:
            raise ValueError(f"Adapter '{target_adapter.adapter_name}' does not support automated push restore.")

        warnings: List[str] = []
        if bkp_dict["device_id"] != dev_dict["id"]:
            warnings.append(
                f"Backup originated from {bkp_dict['device_hostname']} ({bkp_dict['device_ip']}), "
                f"restoring onto {dev_dict['hostname']} ({dev_dict['management_ip']}). Verify interface layout!"
            )

        redacted_preview = self.get_backup_content(backup_id, redact=True)
        return {
            "backup_id": int(backup_id),
            "backup_uid": bkp_dict["backup_uid"],
            "target_device_id": dev_dict["id"],
            "target_hostname": dev_dict["hostname"],
            "target_ip": dev_dict["management_ip"],
            "site_id": dev_dict["site_id"],
            "vendor_adapter": target_adapter.adapter_name,
            "sha256_checksum": bkp_dict["sha256_checksum"],
            "warnings": warnings,
            "redacted_preview": redacted_preview,
            "requires_confirmation": True,
        }

    def restore_backup(
        self,
        restore_plan: Dict[str, Any],
        *,
        confirmed: bool = False,
        credentials: Optional[Dict[str, Any]] = None,
        ssh_transport: Optional[Callable[..., Tuple[int, str, str]]] = None,
        ticket_ref: str = "",
    ) -> Dict[str, Any]:
        """Apply controlled restore ONLY after explicit confirmation & mandatory pre-restore backup."""
        backup_id = int(restore_plan["backup_id"])
        target_id = int(restore_plan["target_device_id"])

        if not confirmed:
            self.audit.record_event(
                operation="CONFIG_RESTORE",
                result="BLOCKED",
                device_id=target_id,
                device_name=restore_plan.get("target_hostname", ""),
                device_ip=restore_plan.get("target_ip", ""),
                site_id=restore_plan.get("site_id"),
                command_tier="DESTRUCTIVE",
                ticket_ref=ticket_ref,
                detail=f"Restore of {restore_plan.get('backup_uid')} refused without explicit confirmation.",
            )
            raise PermissionError("Configuration restore requires explicit confirmation.")

        # Re-verify integrity immediately before execution
        ok_int, msg_int = self.verify_backup_integrity(backup_id)
        if not ok_int:
            raise ValueError(f"Pre-execution integrity check failed: {msg_int}")

        # Mandatory pre-restore safety snapshot
        pre_bkp = self.backup_device(
            target_id,
            triggered_by="pre_restore_guard",
            status_tag="PRE_RESTORE",
            credentials=credentials,
            ssh_transport=ssh_transport,
        )
        if pre_bkp.get("status") == "FAILED":
            raise RuntimeError(
                f"Mandatory pre-restore backup failed ({pre_bkp.get('error_detail')}); restore aborted safely."
            )

        with self.db.Session() as session:
            dev = session.query(InfrastructureDevice).filter_by(id=target_id).first()
            dev_dict = self._dev_to_dict(dev)
            creds = credentials if credentials is not None else self._resolve_device_credentials(session, dev)

        adapter = ADAPTER_REGISTRY[restore_plan["vendor_adapter"]]
        plaintext_cfg = self.get_backup_content(backup_id, redact=False)
        ok, out = adapter.apply_restore_config(
            dev_dict,
            plaintext_cfg,
            credentials=creds,
            ssh_transport=ssh_transport,
        )
        res_tag = "SUCCESS" if ok else "FAILURE"

        self.audit.record_event(
            operation="CONFIG_RESTORE",
            result=res_tag,
            device_id=target_id,
            device_name=dev_dict["hostname"],
            device_ip=dev_dict["management_ip"],
            site_id=dev_dict["site_id"],
            command_tier="DESTRUCTIVE",
            previous_value=pre_bkp["backup_uid"],
            new_value=restore_plan["backup_uid"],
            ticket_ref=ticket_ref,
            detail=f"Restored {restore_plan['backup_uid']} after PRE_RESTORE={pre_bkp['backup_uid']} | Output={str(out)[:300]}",
        )
        return {
            "status": res_tag,
            "pre_restore_backup": pre_bkp,
            "restored_backup_uid": restore_plan["backup_uid"],
            "output": out,
        }

    def apply_retention_policy(self, max_age_days: int = 90, keep_min_per_device: int = 3) -> int:
        cutoff = datetime.utcnow() - timedelta(days=int(max_age_days))
        removed = 0
        with self.db.Session() as session:
            dev_ids = [r[0] for r in session.query(ConfigurationBackup.device_id).distinct().all()]
            for did in dev_ids:
                rows = (
                    session.query(ConfigurationBackup)
                    .filter_by(device_id=did)
                    .order_by(ConfigurationBackup.id.desc())
                    .all()
                )
                for idx, row in enumerate(rows):
                    if idx < keep_min_per_device:
                        continue
                    if row.timestamp and row.timestamp < cutoff:
                        if row.file_path and os.path.exists(row.file_path):
                            try:
                                os.remove(row.file_path)
                            except OSError:
                                pass
                        session.delete(row)
                        removed += 1
            session.commit()
        return removed
