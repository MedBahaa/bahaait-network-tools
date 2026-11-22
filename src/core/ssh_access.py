import os
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from core.audit_logger import AuditLogger
from core.vlan_manager import detect_vlan_vendor_profile
from utils.db import DatabaseManager, SSHProfile
from utils.infra_security import (
    KnownHostsStore,
    StrictVerifyHostKeyPolicy,
    decrypt_secret,
    encrypt_secret,
    redact_sensitive_text,
)

COMMAND_TIERS = ("READ_ONLY", "MODIFYING", "DESTRUCTIVE")

_VALID_HOST_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")
_SHELL_CHAIN_RE = re.compile(r"(?:;|&&|\|\||`|\$\(|>{1,2})")

_DESTRUCTIVE_PATTERNS: Tuple[re.Pattern, ...] = (
    re.compile(r"^(?:do\s+)?(?:reload|reboot|poweroff|halt|reset)\b", re.IGNORECASE),
    re.compile(r"\b(?:write\s+erase|erase\s+startup|erase\s+all|format\s+|delete\s+/|factoryreset)\b", re.IGNORECASE),
    re.compile(r"^no\s+(?:vlan|router|interface|ip\s+route)\b", re.IGNORECASE),
    re.compile(r"^(?:default\s+interface|shutdown)\b", re.IGNORECASE),
    re.compile(r"^clear\s+(?:counters|arp|mac|bgp|ospf|config)\b", re.IGNORECASE),
    re.compile(r"\b(?:rm\s+-rf|rm\s+-f|mkfs\.|dd\s+if=|systemctl\s+(?:stop|disable)|shutdown\s+-h)\b", re.IGNORECASE),
    re.compile(r"^\s*delete\s+", re.IGNORECASE),
)

_READ_ONLY_PATTERNS: Tuple[re.Pattern, ...] = (
    re.compile(r"^(?:do\s+)?(?:show|display|get|diagnose)\b", re.IGNORECASE),
    re.compile(r"^(?:ping|traceroute|tracert|nslookup|dig|arp\s+-a)\b", re.IGNORECASE),
    re.compile(r"^(?:terminal\s+length\s+\d+|skip-page-display|exit|logout|quit)\b", re.IGNORECASE),
    re.compile(r"^(?:uname|uptime|whoami|pwd|ls|cat|head|tail|ps|df|free|ip\s+(?:addr|route)\s+show)\b", re.IGNORECASE),
)

VENDOR_QUICK_COMMANDS: Dict[str, List[Tuple[str, str]]] = {
    "cisco_ios": [
        ("Show Version", "show version"),
        ("IP Interfaces", "show ip interface brief"),
        ("VLANs", "show vlan brief"),
        ("LLDP Neighbors", "show lldp neighbors"),
        ("CDP Neighbors", "show cdp neighbors"),
        ("Running Config", "show running-config"),
    ],
    "ruckus_icx": [
        ("Show Version", "show version"),
        ("Interfaces Brief", "show interfaces brief"),
        ("Show VLANs", "show vlan"),
        ("LLDP Neighbors", "show lldp neighbors"),
        ("Running Config", "show running-config"),
    ],
    "fortinet_fortigate": [
        ("System Status", "get system status"),
        ("Interfaces", "get system interface"),
        ("Routing Table", "get router info routing-table all"),
        ("Config Interfaces", "show system interface"),
    ],
    "generic_ssh": [
        ("Show Version", "show version"),
        ("Kernel / OS", "uname -a"),
        ("IP Addresses", "ip addr show"),
        ("Uptime", "uptime"),
    ],
}


def classify_command_tier(command: str, vendor_profile: str = "generic_ssh") -> Tuple[str, str]:
    """Classify a CLI command into READ_ONLY, MODIFYING, or DESTRUCTIVE conservatively."""
    cmd = str(command or "").strip()
    if not cmd:
        return "READ_ONLY", "Empty command"

    if _SHELL_CHAIN_RE.search(cmd):
        for pat in _DESTRUCTIVE_PATTERNS:
            if pat.search(cmd):
                return "DESTRUCTIVE", "Chained command matches destructive rule"
        return "MODIFYING", "Shell redirection or chained command requires confirmation"

    for pat in _DESTRUCTIVE_PATTERNS:
        if pat.search(cmd):
            return "DESTRUCTIVE", f"Matches destructive command rule ({vendor_profile})"

    for pat in _READ_ONLY_PATTERNS:
        if pat.search(cmd):
            return "READ_ONLY", f"Read-only diagnostic/inspection command ({vendor_profile})"

    return "MODIFYING", "Configuration or unrecognized command defaults to MODIFYING guard"


class SSHProfileManager:
    """CRUD manager for reusable SSH credential profiles with DPAPI secret encryption."""

    def __init__(self, db: DatabaseManager, audit_logger: Optional[AuditLogger] = None) -> None:
        self.db = db
        self.audit = audit_logger or AuditLogger(db)

    @staticmethod
    def _to_dict(p: SSHProfile, include_secret: bool = False) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "id": p.id,
            "name": p.name,
            "vendor_profile": p.vendor_profile or "generic_ssh",
            "protocol": p.protocol or "SSH",
            "port": int(p.port or 22),
            "username": p.username or "",
            "auth_method": p.auth_method or "PASSWORD",
            "private_key_path": p.private_key_path or "",
            "timeout_sec": int(p.timeout_sec or 15),
            "host_key_policy": p.host_key_policy or "STRICT",
            "expected_fingerprint": p.expected_fingerprint or "",
            "has_secret": bool(p.encrypted_secret),
            "created_at": p.created_at,
        }
        if include_secret:
            out["secret"] = decrypt_secret(p.encrypted_secret or "") if p.encrypted_secret else ""
        return out

    def create_profile(self, data: Dict[str, Any]) -> Dict[str, Any]:
        name = str(data.get("name") or "").strip()
        if not name:
            raise ValueError("SSH Profile name is required.")
        port = int(data.get("port") or 22)
        if not (1 <= port <= 65535):
            raise ValueError("Port must be between 1 and 65535.")

        raw_secret = str(data.get("secret") or data.get("password") or "")
        enc_secret = encrypt_secret(raw_secret) if raw_secret else ""
        policy = str(data.get("host_key_policy") or "STRICT").upper()
        if policy not in ("STRICT", "TOFU_CONFIRM"):
            policy = "STRICT"

        with self.db.Session() as session:
            if session.query(SSHProfile).filter_by(name=name).first():
                raise ValueError(f"SSH Profile '{name}' already exists.")
            prof = SSHProfile(
                name=name,
                vendor_profile=str(data.get("vendor_profile") or "generic_ssh"),
                protocol=str(data.get("protocol") or "SSH").upper(),
                port=port,
                username=str(data.get("username") or "").strip(),
                auth_method=str(data.get("auth_method") or "PASSWORD").upper(),
                encrypted_secret=enc_secret,
                private_key_path=str(data.get("private_key_path") or "").strip(),
                timeout_sec=int(data.get("timeout_sec") or 15),
                host_key_policy=policy,
                expected_fingerprint=str(data.get("expected_fingerprint") or "").strip(),
            )
            session.add(prof)
            session.commit()
            session.refresh(prof)
            res = self._to_dict(prof, include_secret=False)

        self.audit.record_event(
            operation="SSH_PROFILE_CREATED",
            result="SUCCESS",
            command_tier="SYSTEM",
            new_value={"name": name, "username": res["username"], "auth_method": res["auth_method"]},
            detail=f"Policy={policy}, port={port}",
            extra_secrets=(raw_secret,) if raw_secret else (),
        )
        return res

    def list_profiles(self) -> List[Dict[str, Any]]:
        with self.db.Session() as session:
            rows = session.query(SSHProfile).order_by(SSHProfile.name.asc()).all()
            return [self._to_dict(r, include_secret=False) for r in rows]

    def get_profile(self, profile_id: int, include_secret: bool = False) -> Optional[Dict[str, Any]]:
        with self.db.Session() as session:
            row = session.query(SSHProfile).filter_by(id=int(profile_id)).first()
            return self._to_dict(row, include_secret=include_secret) if row else None

    def update_profile(self, profile_id: int, patch: Dict[str, Any]) -> Dict[str, Any]:
        raw_secret = str(patch.get("secret") or patch.get("password") or "")
        with self.db.Session() as session:
            prof = session.query(SSHProfile).filter_by(id=int(profile_id)).first()
            if not prof:
                raise ValueError(f"SSH Profile {profile_id} not found.")
            for fld in ("name", "vendor_profile", "protocol", "username", "auth_method", "private_key_path", "host_key_policy", "expected_fingerprint"):
                if fld in patch and patch[fld] is not None:
                    setattr(prof, fld, str(patch[fld]).strip())
            if "port" in patch and patch["port"] is not None:
                p = int(patch["port"])
                if not (1 <= p <= 65535):
                    raise ValueError("Port must be between 1 and 65535.")
                prof.port = p
            if "timeout_sec" in patch and patch["timeout_sec"] is not None:
                prof.timeout_sec = int(patch["timeout_sec"])
            if raw_secret:
                prof.encrypted_secret = encrypt_secret(raw_secret)
            session.commit()
            session.refresh(prof)
            res = self._to_dict(prof, include_secret=False)
        self.audit.record_event(
            operation="SSH_PROFILE_UPDATED",
            result="SUCCESS",
            command_tier="SYSTEM",
            new_value={"id": profile_id, "name": res["name"]},
            extra_secrets=(raw_secret,) if raw_secret else (),
        )
        return res

    def delete_profile(self, profile_id: int) -> bool:
        with self.db.Session() as session:
            prof = session.query(SSHProfile).filter_by(id=int(profile_id)).first()
            if not prof:
                return False
            name = prof.name
            session.delete(prof)
            session.commit()
        self.audit.record_event(
            operation="SSH_PROFILE_DELETED",
            result="SUCCESS",
            command_tier="DESTRUCTIVE",
            previous_value={"id": profile_id, "name": name},
        )
        return True


class DeviceAccessService:
    """Guarded SSH/RDP/Web administration engine enforcing host-key verification, tiers & audit."""

    def __init__(
        self,
        db: DatabaseManager,
        audit_logger: Optional[AuditLogger] = None,
        known_hosts_path: Optional[str] = None,
    ) -> None:
        self.db = db
        self.audit = audit_logger or AuditLogger(db)
        self.known_hosts = KnownHostsStore(known_hosts_path)

    def create_host_key_policy(
        self,
        policy_mode: str = "TOFU_CONFIRM",
        confirm_callback: Optional[Callable[[str, int, str, str], bool]] = None,
        port: int = 22,
    ) -> StrictVerifyHostKeyPolicy:
        mode = str(policy_mode or "STRICT").upper()
        if mode not in ("STRICT", "TOFU_CONFIRM"):
            mode = "STRICT"
        return StrictVerifyHostKeyPolicy(
            self.known_hosts,
            policy_mode=mode,
            confirm_callback=confirm_callback,
            port=int(port or 22),
        )

    def record_host_key_trust(self, host: str, port: int, key_type: str, fingerprint: str, accepted: bool) -> None:
        self.audit.record_event(
            operation="SSH_HOST_KEY_TRUSTED" if accepted else "SSH_HOST_KEY_REJECTED",
            result="SUCCESS" if accepted else "BLOCKED",
            device_ip=host,
            command_tier="SYSTEM",
            new_value={"host": host, "port": port, "key_type": key_type, "fingerprint": fingerprint},
            detail=f"Operator {'trusted' if accepted else 'rejected'} SSH host key fingerprint.",
        )

    def execute_command_guarded(
        self,
        device: Dict[str, Any],
        command: str,
        *,
        confirmed: bool = False,
        executor: Optional[Callable[[Dict[str, Any], str], Tuple[bool, str]]] = None,
        ticket_ref: str = "",
        extra_secrets: Iterable[str] = (),
    ) -> Dict[str, Any]:
        vendor_prof = detect_vlan_vendor_profile(
            device.get("vendor", ""),
            device.get("model", ""),
            device.get("role", ""),
        )
        if vendor_prof == "unsupported":
            vendor_prof = "generic_ssh"
        tier, reason = classify_command_tier(command, vendor_profile=vendor_prof)
        dev_id = device.get("id")
        dev_name = str(device.get("hostname") or "")
        dev_ip = str(device.get("management_ip") or "")
        secrets_tuple = tuple(extra_secrets)

        if tier != "READ_ONLY" and not confirmed:
            self.audit.record_event(
                operation="SSH_COMMAND_BLOCKED",
                result="BLOCKED",
                device_id=dev_id,
                device_name=dev_name,
                device_ip=dev_ip,
                site_id=device.get("site_id"),
                command_tier=tier,
                new_value={"command": command},
                ticket_ref=ticket_ref,
                detail=reason,
                extra_secrets=secrets_tuple,
            )
            raise PermissionError(f"[{tier}] Command blocked without explicit confirmation: {reason}")

        if executor is None:
            raise ValueError("No active device session/executor connected.")

        ok, raw_output = executor(device, command)
        clean_out = redact_sensitive_text(raw_output or "", extra_secrets=secrets_tuple)
        res_tag = "SUCCESS" if ok else "FAILURE"

        self.audit.record_event(
            operation="SSH_COMMAND_EXECUTED",
            result=res_tag,
            device_id=dev_id,
            device_name=dev_name,
            device_ip=dev_ip,
            site_id=device.get("site_id"),
            command_tier=tier,
            new_value={"command": command, "output_preview": clean_out[:500]},
            ticket_ref=ticket_ref,
            detail=reason,
            extra_secrets=secrets_tuple,
        )
        return {"tier": tier, "reason": reason, "status": res_tag, "output": clean_out}

    @staticmethod
    def build_rdp_launch_args(host: str, port: int = 3389) -> List[str]:
        clean_host = str(host or "").strip()
        if not clean_host or not _VALID_HOST_RE.match(clean_host):
            raise ValueError(f"Invalid target host for RDP launch: '{host}'.")
        p = int(port or 3389)
        if not (1 <= p <= 65535):
            raise ValueError("RDP port must be between 1 and 65535.")
        target = clean_host if p == 3389 else f"{clean_host}:{p}"
        return ["mstsc", f"/v:{target}"]

    @staticmethod
    def build_web_admin_url(host: str, port: int = 443, https: bool = True) -> str:
        clean_host = str(host or "").strip()
        if not clean_host or not _VALID_HOST_RE.match(clean_host):
            raise ValueError(f"Invalid target host for Web Admin URL: '{host}'.")
        scheme = "https" if https else "http"
        default_p = 443 if https else 80
        p = int(port or default_p)
        if p == default_p:
            return f"{scheme}://{clean_host}"
        return f"{scheme}://{clean_host}:{p}"

    @staticmethod
    def export_session_log(lines: List[str], dest_path: str, extra_secrets: Iterable[str] = ()) -> str:
        raw = "\n".join(lines)
        clean = redact_sensitive_text(raw, extra_secrets=extra_secrets)
        with open(dest_path, "w", encoding="utf-8") as fh:
            fh.write(clean)
        return clean
