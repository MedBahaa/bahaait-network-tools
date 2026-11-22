import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.audit_logger import AuditLogger
from core.vlan_manager import detect_vlan_vendor_profile

_UNSAFE_PARAM_RE = re.compile(r"[;\r\n|`$&><]")

VENDOR_TEMPLATES: List[Dict[str, Any]] = [
    {
        "id": "cisco_base_hardening",
        "name": "Cisco IOS Base Hardening (SSHv2 + NTP + Logging)",
        "vendor_profile": "cisco_ios",
        "risk_tier": "MODIFYING",
        "description": "Configures SSH v2, service password-encryption, NTP server and syslog host.",
        "parameters": [
            {"key": "domain_name", "label": "Domain Name", "default": "corp.local", "required": True},
            {"key": "ntp_server", "label": "NTP Server IP", "default": "10.0.0.10", "required": True},
            {"key": "syslog_server", "label": "Syslog Server IP", "default": "10.0.0.20", "required": True},
        ],
        "commands": [
            "configure terminal",
            "ip domain-name {domain_name}",
            "ip ssh version 2",
            "service password-encryption",
            "ntp server {ntp_server}",
            "logging host {syslog_server}",
            "logging trap informational",
            "end",
        ],
    },
    {
        "id": "cisco_vlan_trunk_uplink",
        "name": "Cisco IOS Trunk Uplink Standard",
        "vendor_profile": "cisco_ios",
        "risk_tier": "MODIFYING",
        "description": "Configures 802.1Q trunk interface with explicit allowed VLANs and native VLAN.",
        "parameters": [
            {"key": "interface", "label": "Trunk Interface", "default": "Gi1/0/48", "required": True},
            {"key": "allowed_vlans", "label": "Allowed VLANs", "default": "10,20,30", "required": True},
            {"key": "native_vlan", "label": "Native VLAN", "default": "99", "required": True},
        ],
        "commands": [
            "configure terminal",
            "interface {interface}",
            "description UPLINK_TRUNK_STANDARD",
            "switchport trunk encapsulation dot1q",
            "switchport mode trunk",
            "switchport trunk native vlan {native_vlan}",
            "switchport trunk allowed vlan {allowed_vlans}",
            "end",
        ],
    },
    {
        "id": "cisco_snmpv3_monitor",
        "name": "Cisco IOS SNMPv3 Read-Only Monitoring",
        "vendor_profile": "cisco_ios",
        "risk_tier": "MODIFYING",
        "description": "Creates an SNMPv3 AuthPriv group and read-only view (credentials supplied at runtime).",
        "parameters": [
            {"key": "group_name", "label": "SNMP Group", "default": "MON_RO_GRP", "required": True},
            {"key": "username", "label": "SNMPv3 User", "default": "bahaait_ro", "required": True},
            {"key": "auth_pass", "label": "Auth Passphrase (>=8)", "default": "", "required": True, "secret": True},
            {"key": "priv_pass", "label": "Priv Passphrase (>=8)", "default": "", "required": True, "secret": True},
        ],
        "commands": [
            "configure terminal",
            "snmp-server view RO_VIEW iso included",
            "snmp-server group {group_name} v3 priv read RO_VIEW",
            "snmp-server user {username} {group_name} v3 auth sha {auth_pass} priv aes 128 {priv_pass}",
            "end",
        ],
    },
    {
        "id": "ruckus_icx_base",
        "name": "Ruckus ICX Base Management (NTP + Syslog + SSH)",
        "vendor_profile": "ruckus_icx",
        "risk_tier": "MODIFYING",
        "description": "Applies standard NTP, Syslog target and SSH timeout on Ruckus FastIron / ICX.",
        "parameters": [
            {"key": "ntp_server", "label": "SNTP Server IP", "default": "10.0.0.10", "required": True},
            {"key": "syslog_server", "label": "Syslog Host IP", "default": "10.0.0.20", "required": True},
            {"key": "ssh_timeout", "label": "SSH Idle Timeout (min)", "default": "15", "required": True},
        ],
        "commands": [
            "configure terminal",
            "sntp server {ntp_server}",
            "logging host {syslog_server}",
            "ip ssh idle-time {ssh_timeout}",
            "end",
        ],
    },
    {
        "id": "ruckus_icx_access_poe",
        "name": "Ruckus ICX Access Port + PoE + BPDU Guard",
        "vendor_profile": "ruckus_icx",
        "risk_tier": "MODIFYING",
        "description": "Assigns port to untagged VLAN, enables PoE inline-power and STP BPDU guard.",
        "parameters": [
            {"key": "vlan_id", "label": "Access VLAN ID", "default": "20", "required": True},
            {"key": "port", "label": "Ethernet Port", "default": "1/1/10", "required": True},
        ],
        "commands": [
            "configure terminal",
            "vlan {vlan_id}",
            "untagged ethernet {port}",
            "interface ethernet {port}",
            "inline power",
            "stp-bpdu-guard",
            "end",
        ],
    },
    {
        "id": "fortigate_syslog_ntp",
        "name": "FortiGate Syslog + NTP Standard",
        "vendor_profile": "fortinet_fortigate",
        "risk_tier": "MODIFYING",
        "description": "Enables NTP sync and syslogd remote logging to BahaaIT collector.",
        "parameters": [
            {"key": "ntp_server", "label": "Custom NTP IP", "default": "10.0.0.10", "required": True},
            {"key": "syslog_server", "label": "Syslog Server IP", "default": "10.0.0.20", "required": True},
        ],
        "commands": [
            "config system ntp",
            "set type custom",
            "config ntpserver",
            "edit 1",
            f"set server {{ntp_server}}",
            "next",
            "end",
            "end",
            "config log syslogd setting",
            "set status enable",
            "set server {syslog_server}",
            "set port 514",
            "end",
        ],
    },
    {
        "id": "fortigate_vlan_subif",
        "name": "FortiGate VLAN Sub-Interface",
        "vendor_profile": "fortinet_fortigate",
        "risk_tier": "MODIFYING",
        "description": "Creates a tagged IEEE 802.1Q VLAN interface on a FortiGate physical/aggregate port.",
        "parameters": [
            {"key": "if_name", "label": "VLAN IF Name", "default": "corp_vlan20", "required": True},
            {"key": "parent_if", "label": "Parent Interface", "default": "port1", "required": True},
            {"key": "vlan_id", "label": "VLAN ID", "default": "20", "required": True},
            {"key": "ip_cidr", "label": "IP/Mask", "default": "10.20.0.1 255.255.255.0", "required": True},
        ],
        "commands": [
            "config system interface",
            'edit "{if_name}"',
            'set interface "{parent_if}"',
            "set vlanid {vlan_id}",
            "set ip {ip_cidr}",
            "set allowaccess ping https ssh snmp",
            "next",
            "end",
        ],
    },
    {
        "id": "generic_readonly_health_audit",
        "name": "Cross-Platform Read-Only Baseline Check",
        "vendor_profile": "all",
        "risk_tier": "READ_ONLY",
        "description": "Non-intrusive read-only version check safe across Cisco/Ruckus/FortiGate SSH.",
        "parameters": [
            {"key": "check_cmd", "label": "Show Command", "default": "show version", "required": True},
        ],
        "commands": ["{check_cmd}"],
    },
]


def list_templates(vendor_profile: Optional[str] = None) -> List[Dict[str, Any]]:
    if not vendor_profile or vendor_profile == "all":
        return list(VENDOR_TEMPLATES)
    return [t for t in VENDOR_TEMPLATES if t["vendor_profile"] in (vendor_profile, "all")]


def get_template(template_id: str) -> Dict[str, Any]:
    for tpl in VENDOR_TEMPLATES:
        if tpl["id"] == template_id:
            return tpl
    raise ValueError(f"Unknown template id: '{template_id}'.")


def render_template_preview(
    template_id: str,
    device: Dict[str, Any],
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Validate vendor compatibility and parameter safety before rendering CLI commands."""
    tpl = get_template(template_id)
    dev_profile = detect_vlan_vendor_profile(
        device.get("vendor", ""),
        device.get("model", ""),
        device.get("role", ""),
    )
    if tpl["vendor_profile"] != "all" and tpl["vendor_profile"] != dev_profile:
        raise ValueError(
            f"Template '{tpl['name']}' requires vendor profile '{tpl['vendor_profile']}', "
            f"but device '{device.get('hostname')}' resolves to '{dev_profile}'."
        )

    supplied = dict(params or {})
    clean_params: Dict[str, str] = {}
    secrets: List[str] = []
    for pdef in tpl["parameters"]:
        key = pdef["key"]
        val = str(supplied.get(key, pdef.get("default", ""))).strip()
        if pdef.get("required") and not val:
            raise ValueError(f"Template parameter '{pdef['label']}' ({key}) is required.")
        if _UNSAFE_PARAM_RE.search(val):
            raise ValueError(f"Unsafe control character in parameter '{key}'.")
        if pdef.get("secret"):
            if len(val) < 8:
                raise ValueError(f"Passphrase '{key}' must be at least 8 characters.")
            secrets.append(val)
        clean_params[key] = val

    commands = [cmd.format(**clean_params) for cmd in tpl["commands"]]
    return {
        "template_id": tpl["id"],
        "template_name": tpl["name"],
        "device_id": int(device["id"]),
        "device_hostname": device.get("hostname", ""),
        "device_ip": device.get("management_ip", ""),
        "site_id": device.get("site_id"),
        "vendor_profile": tpl["vendor_profile"],
        "risk_tier": tpl["risk_tier"],
        "commands": commands,
        "rendered_text": "\n".join(commands),
        "secret_values": secrets,
        "requires_confirmation": tpl["risk_tier"] != "READ_ONLY",
    }


def apply_template(
    preview: Dict[str, Any],
    *,
    confirmed: bool = False,
    backup_manager: Any = None,
    executor: Optional[Callable[[Dict[str, Any], List[str]], Tuple[bool, str]]] = None,
    audit_logger: Optional[AuditLogger] = None,
    ticket_ref: str = "",
) -> Dict[str, Any]:
    """Execute a rendered template ONLY after explicit confirmation (unless READ_ONLY)."""
    risk = str(preview.get("risk_tier") or "MODIFYING").upper()
    dev_id = int(preview["device_id"])
    secrets = tuple(preview.get("secret_values") or ())
    cmds = list(preview.get("commands") or [])

    if risk != "READ_ONLY" and not confirmed:
        if audit_logger:
            audit_logger.record_event(
                operation=f"TEMPLATE_{preview['template_id'].upper()}",
                result="BLOCKED",
                device_id=dev_id,
                device_name=preview.get("device_hostname", ""),
                device_ip=preview.get("device_ip", ""),
                site_id=preview.get("site_id"),
                command_tier=risk,
                new_value=preview.get("rendered_text", ""),
                ticket_ref=ticket_ref,
                detail="Template application refused: explicit confirmation required.",
                extra_secrets=secrets,
            )
        raise PermissionError("Template execution requires explicit confirmation.")

    pre_backup = None
    if risk != "READ_ONLY" and backup_manager is not None:
        try:
            pre_backup = backup_manager.backup_device(dev_id, triggered_by="pre_template", status_tag="PRE_RESTORE")
        except Exception:
            pre_backup = None

    if executor is None:
        raise ValueError("No SSH/API execution callback provided to apply template.")

    ok, out = executor(preview, cmds)
    result_tag = "SUCCESS" if ok else "FAILURE"

    if audit_logger:
        audit_logger.record_event(
            operation=f"TEMPLATE_{preview['template_id'].upper()}",
            result=result_tag,
            device_id=dev_id,
            device_name=preview.get("device_hostname", ""),
            device_ip=preview.get("device_ip", ""),
            site_id=preview.get("site_id"),
            command_tier=risk,
            new_value=preview.get("rendered_text", ""),
            ticket_ref=ticket_ref,
            detail=str(out)[:400],
            extra_secrets=secrets,
        )

    return {
        "status": result_tag,
        "executed": True,
        "pre_backup": pre_backup,
        "output": out,
    }
