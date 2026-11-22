import json
from typing import Any, Callable, Dict, List, Optional, Tuple
import urllib.error
import urllib.request
import ssl

import paramiko

from utils.infra_security import KnownHostsStore, StrictVerifyHostKeyPolicy


class BackupAdapterError(RuntimeError):
    """Raised when a device backup or restore transport operation fails."""


def _default_ssh_exec(
    host: str,
    port: int,
    username: str,
    password: str,
    pkey_path: Optional[str],
    commands: List[str],
    known_hosts_path: Optional[str] = None,
    timeout: float = 15.0,
) -> Tuple[int, str, str]:
    """Execute read/config commands via Paramiko with strict known_hosts verification (never auto-trusts unknown keys)."""
    store = KnownHostsStore(known_hosts_path)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(StrictVerifyHostKeyPolicy(store, policy_mode="STRICT", port=port))
    try:
        connect_kwargs: Dict[str, Any] = {
            "hostname": host,
            "port": int(port or 22),
            "username": username,
            "timeout": timeout,
            "look_for_keys": bool(not password and not pkey_path),
            "allow_agent": False,
        }
        if password:
            connect_kwargs["password"] = password
        if pkey_path:
            connect_kwargs["key_filename"] = pkey_path

        client.connect(**connect_kwargs)
        combined_out: List[str] = []
        combined_err: List[str] = []
        for cmd in commands:
            _stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            combined_out.append(stdout.read().decode("utf-8", errors="replace"))
            combined_err.append(stderr.read().decode("utf-8", errors="replace"))
        return 0, "\n".join(combined_out), "\n".join(combined_err)
    except Exception as exc:
        raise BackupAdapterError(f"SSH error to {host}:{port}: {exc}") from exc
    finally:
        client.close()


class BaseBackupAdapter:
    adapter_name: str = "generic_ssh"
    vendor_label: str = "Generic"
    backup_method: str = "SSH"
    supports_restore: bool = False

    def fetch_running_config(
        self,
        device: Dict[str, Any],
        credentials: Optional[Dict[str, Any]] = None,
        ssh_transport: Optional[Callable[..., Tuple[int, str, str]]] = None,
        api_transport: Optional[Callable[..., Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        raise NotImplementedError

    def apply_restore_config(
        self,
        device: Dict[str, Any],
        config_text: str,
        credentials: Optional[Dict[str, Any]] = None,
        ssh_transport: Optional[Callable[..., Tuple[int, str, str]]] = None,
        api_transport: Optional[Callable[..., Dict[str, Any]]] = None,
    ) -> Tuple[bool, str]:
        raise NotImplementedError("Automatic restore is not supported for this adapter.")


class CiscoIOSAdapter(BaseBackupAdapter):
    adapter_name = "cisco_ios"
    vendor_label = "Cisco"
    backup_method = "SSH"
    supports_restore = True

    def fetch_running_config(
        self,
        device: Dict[str, Any],
        credentials: Optional[Dict[str, Any]] = None,
        ssh_transport: Optional[Callable[..., Tuple[int, str, str]]] = None,
        api_transport: Optional[Callable[..., Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        creds = dict(credentials or {})
        runner = ssh_transport or _default_ssh_exec
        rc, out, err = runner(
            device["management_ip"],
            int(creds.get("port", 22)),
            creds.get("username", ""),
            creds.get("password", ""),
            creds.get("private_key_path"),
            ["terminal length 0", "show running-config"],
            creds.get("known_hosts_path"),
        )
        if rc != 0 or not str(out or "").strip():
            raise BackupAdapterError(f"Empty or failed Cisco config backup: {err or out}")
        return {
            "config_text": out,
            "method": self.backup_method,
            "adapter": self.adapter_name,
            "firmware_hint": _extract_hint(out, "version "),
        }

    def apply_restore_config(
        self,
        device: Dict[str, Any],
        config_text: str,
        credentials: Optional[Dict[str, Any]] = None,
        ssh_transport: Optional[Callable[..., Tuple[int, str, str]]] = None,
        api_transport: Optional[Callable[..., Dict[str, Any]]] = None,
    ) -> Tuple[bool, str]:
        creds = dict(credentials or {})
        runner = ssh_transport or _default_ssh_exec
        lines = [ln.strip() for ln in config_text.splitlines() if ln.strip() and not ln.strip().startswith("!")]
        cmds = ["configure terminal", *lines, "end"]
        rc, out, err = runner(
            device["management_ip"],
            int(creds.get("port", 22)),
            creds.get("username", ""),
            creds.get("password", ""),
            creds.get("private_key_path"),
            cmds,
            creds.get("known_hosts_path"),
        )
        return (rc == 0), (out or err)


class RuckusICXAdapter(BaseBackupAdapter):
    adapter_name = "ruckus_icx"
    vendor_label = "Ruckus"
    backup_method = "SSH"
    supports_restore = True

    def fetch_running_config(
        self,
        device: Dict[str, Any],
        credentials: Optional[Dict[str, Any]] = None,
        ssh_transport: Optional[Callable[..., Tuple[int, str, str]]] = None,
        api_transport: Optional[Callable[..., Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        creds = dict(credentials or {})
        runner = ssh_transport or _default_ssh_exec
        rc, out, err = runner(
            device["management_ip"],
            int(creds.get("port", 22)),
            creds.get("username", ""),
            creds.get("password", ""),
            creds.get("private_key_path"),
            ["skip-page-display", "show running-config"],
            creds.get("known_hosts_path"),
        )
        if rc != 0 or not str(out or "").strip():
            raise BackupAdapterError(f"Empty or failed Ruckus ICX config backup: {err or out}")
        return {
            "config_text": out,
            "method": self.backup_method,
            "adapter": self.adapter_name,
            "firmware_hint": _extract_hint(out, "ver "),
        }

    def apply_restore_config(
        self,
        device: Dict[str, Any],
        config_text: str,
        credentials: Optional[Dict[str, Any]] = None,
        ssh_transport: Optional[Callable[..., Tuple[int, str, str]]] = None,
        api_transport: Optional[Callable[..., Dict[str, Any]]] = None,
    ) -> Tuple[bool, str]:
        creds = dict(credentials or {})
        runner = ssh_transport or _default_ssh_exec
        lines = [ln.strip() for ln in config_text.splitlines() if ln.strip() and not ln.strip().startswith("!")]
        cmds = ["configure terminal", *lines, "end"]
        rc, out, err = runner(
            device["management_ip"],
            int(creds.get("port", 22)),
            creds.get("username", ""),
            creds.get("password", ""),
            creds.get("private_key_path"),
            cmds,
            creds.get("known_hosts_path"),
        )
        return (rc == 0), (out or err)


class RuckusSmartZoneAdapter(BaseBackupAdapter):
    adapter_name = "ruckus_smartzone_api"
    vendor_label = "Ruckus SmartZone"
    backup_method = "API"
    supports_restore = False

    def fetch_running_config(
        self,
        device: Dict[str, Any],
        credentials: Optional[Dict[str, Any]] = None,
        ssh_transport: Optional[Callable[..., Tuple[int, str, str]]] = None,
        api_transport: Optional[Callable[..., Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        creds = dict(credentials or {})
        ip = device["management_ip"]
        port = int(creds.get("api_port", 8443))
        if api_transport is not None:
            payload = api_transport(device, creds)
        else:
            url = f"https://{ip}:{port}/wsg/api/public/v11_1/controller"
            req = urllib.request.Request(url, method="GET")
            if creds.get("api_token"):
                req.add_header("Authorization", f"Bearer {creds['api_token']}")
            ctx = ssl.create_default_context()
            try:
                with urllib.request.urlopen(req, timeout=12, context=ctx) as resp:
                    payload = json.loads(resp.read().decode("utf-8", errors="replace"))
            except Exception as exc:
                raise BackupAdapterError(f"SmartZone API backup failed for {ip}:{port}: {exc}") from exc

        cfg_text = payload if isinstance(payload, str) else json.dumps(payload, indent=2, sort_keys=True)
        return {
            "config_text": cfg_text,
            "method": self.backup_method,
            "adapter": self.adapter_name,
            "firmware_hint": str(payload.get("version", "")) if isinstance(payload, dict) else "",
        }


class FortiGateAdapter(BaseBackupAdapter):
    adapter_name = "fortinet_fortigate"
    vendor_label = "Fortinet"
    backup_method = "SSH"
    supports_restore = True

    def fetch_running_config(
        self,
        device: Dict[str, Any],
        credentials: Optional[Dict[str, Any]] = None,
        ssh_transport: Optional[Callable[..., Tuple[int, str, str]]] = None,
        api_transport: Optional[Callable[..., Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        creds = dict(credentials or {})
        if str(device.get("management_protocol", "")).upper() == "API" and api_transport is not None:
            payload = api_transport(device, creds)
            text = payload if isinstance(payload, str) else json.dumps(payload, indent=2)
            return {"config_text": text, "method": "API", "adapter": self.adapter_name, "firmware_hint": ""}

        runner = ssh_transport or _default_ssh_exec
        rc, out, err = runner(
            device["management_ip"],
            int(creds.get("port", 22)),
            creds.get("username", ""),
            creds.get("password", ""),
            creds.get("private_key_path"),
            ["show full-configuration"],
            creds.get("known_hosts_path"),
        )
        if rc != 0 or not str(out or "").strip():
            raise BackupAdapterError(f"Empty or failed FortiGate config backup: {err or out}")
        return {
            "config_text": out,
            "method": "SSH",
            "adapter": self.adapter_name,
            "firmware_hint": _extract_hint(out, "#config-version="),
        }

    def apply_restore_config(
        self,
        device: Dict[str, Any],
        config_text: str,
        credentials: Optional[Dict[str, Any]] = None,
        ssh_transport: Optional[Callable[..., Tuple[int, str, str]]] = None,
        api_transport: Optional[Callable[..., Dict[str, Any]]] = None,
    ) -> Tuple[bool, str]:
        creds = dict(credentials or {})
        runner = ssh_transport or _default_ssh_exec
        lines = [ln for ln in config_text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        rc, out, err = runner(
            device["management_ip"],
            int(creds.get("port", 22)),
            creds.get("username", ""),
            creds.get("password", ""),
            creds.get("private_key_path"),
            lines,
            creds.get("known_hosts_path"),
        )
        return (rc == 0), (out or err)


class GenericSSHAdapter(BaseBackupAdapter):
    adapter_name = "generic_ssh"
    vendor_label = "Generic"
    backup_method = "SSH"
    supports_restore = False

    def fetch_running_config(
        self,
        device: Dict[str, Any],
        credentials: Optional[Dict[str, Any]] = None,
        ssh_transport: Optional[Callable[..., Tuple[int, str, str]]] = None,
        api_transport: Optional[Callable[..., Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        creds = dict(credentials or {})
        cmd = creds.get("backup_command") or "show running-config"
        runner = ssh_transport or _default_ssh_exec
        rc, out, err = runner(
            device["management_ip"],
            int(creds.get("port", 22)),
            creds.get("username", ""),
            creds.get("password", ""),
            creds.get("private_key_path"),
            [cmd],
            creds.get("known_hosts_path"),
        )
        if rc != 0 or not str(out or "").strip():
            raise BackupAdapterError(f"Generic SSH config backup failed: {err or out}")
        return {"config_text": out, "method": "SSH", "adapter": self.adapter_name, "firmware_hint": ""}


def _extract_hint(text: str, prefix: str) -> str:
    low_pref = prefix.lower()
    for line in str(text or "").splitlines()[:40]:
        if low_pref in line.lower():
            return line.strip()[:80]
    return ""


ADAPTER_REGISTRY: Dict[str, BaseBackupAdapter] = {
    "cisco_ios": CiscoIOSAdapter(),
    "ruckus_icx": RuckusICXAdapter(),
    "ruckus_smartzone_api": RuckusSmartZoneAdapter(),
    "fortinet_fortigate": FortiGateAdapter(),
    "generic_ssh": GenericSSHAdapter(),
}


def resolve_backup_adapter(
    vendor: str = "",
    model: str = "",
    category: str = "",
    protocol: str = "",
) -> BaseBackupAdapter:
    blob = f"{vendor} {model} {category}".lower()
    if "smartzone" in blob or "wireless controller" in blob or ("ruckus" in blob and protocol.upper() == "API"):
        return ADAPTER_REGISTRY["ruckus_smartzone_api"]
    if "ruckus" in blob or "brocade" in blob or "icx" in blob:
        return ADAPTER_REGISTRY["ruckus_icx"]
    if "forti" in blob:
        return ADAPTER_REGISTRY["fortinet_fortigate"]
    if "cisco" in blob or "catalyst" in blob or "ios" in blob:
        return ADAPTER_REGISTRY["cisco_ios"]
    return ADAPTER_REGISTRY["generic_ssh"]
