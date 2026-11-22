from dataclasses import asdict, dataclass, field
import re
from typing import Any, Dict, List

from core.syslog_parser import ParsedSyslogMessage


_CISCO_MNEM_DETECT_RE = re.compile(r"%[A-Z0-9_]+-\d-[A-Z0-9_]+")
_RUCKUS_IF_RE = re.compile(r"\b(ethernet\s+\d+/\d+/\d+|lag\s+\d+)\b", re.IGNORECASE)
_CISCO_IF_RE = re.compile(
    r"\b(TenGigabitEthernet\d+(?:/\d+){1,2}|GigabitEthernet\d+(?:/\d+){1,2}|"
    r"FastEthernet\d+(?:/\d+){1,2}|Port-channel\d+|Vlan\d+|"
    r"(?:Gi|Te|Fa|Po|Eth)\d+/\d+(?:/\d+)?)\b",
    re.IGNORECASE,
)
_GENERIC_IF_RE = re.compile(
    r"\b(wan\d+|lan\d*|dmz\d*|port\d+|eth\d+|ens\d+|enp\d+s\d+|bond\d+)\b",
    re.IGNORECASE,
)
_USER_RE = re.compile(
    r"(?:\buser(?:name)?\s*[:=]\s*|\bfor\s+(?:invalid\s+)?user\s+|\bby\s+)[\"']?([A-Za-z0-9_.@-]+)[\"']?",
    re.IGNORECASE,
)


@dataclass
class SyslogClassification:
    event_category: str = "GENERAL"
    vendor: str = "Generic"
    interface_name: str = ""
    username: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _flatten_sd(sd: Dict[str, Any]) -> Dict[str, str]:
    flat: Dict[str, str] = {}
    for k, v in (sd or {}).items():
        if isinstance(v, dict):
            for sk, sv in v.items():
                flat[str(sk).lower()] = str(sv)
        else:
            flat[str(k).lower()] = str(v)
    return flat


def _extract_interface_name(parsed: ParsedSyslogMessage, sd_flat: Dict[str, str], category: str) -> str:
    for key in ("interface", "port", "dstintf", "srcintf"):
        val = sd_flat.get(key, "").strip()
        if val:
            return val

    text = f"{parsed.message} {parsed.raw_message}"
    for pattern in (_CISCO_IF_RE, _RUCKUS_IF_RE, _GENERIC_IF_RE):
        m = pattern.search(text)
        if m:
            return m.group(1)

    if category in ("LINK_DOWN", "LINK_UP", "FIREWALL_IF_DOWN", "PORT_SECURITY", "POE_OVERLOAD"):
        name_val = sd_flat.get("name", "").strip()
        if name_val:
            return name_val
    return ""


def _extract_username(parsed: ParsedSyslogMessage, sd_flat: Dict[str, str]) -> str:
    for key in ("user", "username", "usr"):
        val = sd_flat.get(key, "").strip()
        if val:
            return val

    for source in (parsed.message, parsed.raw_message):
        m = _USER_RE.search(source)
        if m:
            candidate = m.group(1).strip(",;")
            if candidate.lower() not in ("vty", "console", "ssh", "unknown", "none"):
                return candidate
    return ""


def classify_syslog_event(parsed: ParsedSyslogMessage) -> SyslogClassification:
    """Classify a parsed Syslog event into normalized vendor, category, interface, username, and tags."""
    sd_flat = _flatten_sd(parsed.structured_data)
    raw_and_app = f"{parsed.app_name} {parsed.raw_message}"
    hay = f"{parsed.app_name} {parsed.message} {parsed.raw_message}".lower()
    msg_only = f"{parsed.app_name} {parsed.message}".lower()
    host_low = (parsed.hostname or "").lower()
    sd_vendor = sd_flat.get("vendor", "").lower()

    # 1. Vendor identification
    if (
        "devid" in sd_flat
        or "logid" in sd_flat
        or "fortinet" in sd_vendor
        or "fortigate" in hay
        or "fortios" in hay
        or "fortinet" in hay
    ):
        vendor = "Fortinet"
    elif "cisco" in sd_vendor or _CISCO_MNEM_DETECT_RE.search(raw_and_app) or "cisco" in hay:
        vendor = "Cisco"
    elif (
        "ruckus" in sd_vendor
        or "ruckus" in hay
        or "icx" in hay
        or "fastiron" in hay
        or "zoneflex" in hay
        or "icx" in host_low
        or _RUCKUS_IF_RE.search(raw_and_app)
    ):
        vendor = "Ruckus"
    else:
        vendor = "Generic"

    sd_action = sd_flat.get("action", "").lower()
    sd_status = sd_flat.get("status", "").lower()
    sd_type = sd_flat.get("type", "").lower()

    category = "GENERAL"
    tags: List[str] = []

    # 2. Classification precedence (most specific first)
    if (
        "%ilpower" in hay
        or "power denied" in hay
        or "power budget exceeded" in hay
        or "poe overload" in hay
        or "poe fault" in hay
        or "imax" in hay
        or ("inline power" in hay and any(w in hay for w in ("denied", "fault", "overload", "exceeded")))
    ):
        category = "POE_OVERLOAD"
        tags = ["POE", "HARDWARE"]

    elif (
        "%pm-4-err_disable" in hay
        or "%port_security" in hay
        or "psecure-violation" in hay
        or "port security violation" in hay
        or "port-security violation" in hay
        or "mac flapping" in hay
        or "mac-move" in hay
        or "err-disabled" in hay
        or "err-disable" in hay
    ):
        category = "PORT_SECURITY"
        tags = ["SECURITY", "INTERFACE"]

    elif (
        "%spantree" in hay
        or "spanning-tree" in hay
        or re.search(r"\br?stp\b", hay)
        or "bpduguard" in hay
        or "topology change" in hay
        or "root bridge" in hay
    ):
        category = "STP_CHANGE"
        tags = ["TOPOLOGY", "STP"]

    elif (
        "%sys-5-restart" in hay
        or "%sys-5-reload" in hay
        or "warm start" in hay
        or "cold start" in hay
        or "system is rebooting" in hay
        or "system rebooted" in hay
        or sd_action == "reboot"
        or "reloaded by" in hay
        or "system restart" in hay
        or "kernel: linux version" in hay
    ):
        category = "REBOOT"
        tags = ["REBOOT", "AVAILABILITY"]

    elif (vendor == "Fortinet" or "firewall" in hay or "fortigate" in hay) and (
        (sd_action == "interface-stat-change" and sd_status == "down")
        or ("link-monitor" in hay and ("dead" in hay or re.search(r"\bdown\b", hay)))
        or ("tunnel" in hay and re.search(r"\bdown\b", hay))
        or re.search(r"\bchanged state to down\b", hay)
        or bool(re.search(r"\b(?:interface|port|wan\d+|lan\d*|dmz\d*)\b.*\bdown\b", msg_only))
    ):
        category = "FIREWALL_IF_DOWN"
        tags = ["LINK_DOWN", "FIREWALL"]

    elif (
        re.search(r"\bchanged state to down\b", hay)
        or "administratively down" in hay
        or re.search(r"\blink[-_\s]+status[-_\s]+down\b", hay)
        or re.search(r"\bstate\s+down\b", hay)
        or re.search(r"\blink\s+down\b", hay)
        or "carrier lost" in hay
        or (sd_action == "interface-stat-change" and sd_status == "down")
        or bool(
            re.search(
                r"\b(?:interface|port|ethernet\s+\d+/\d+/\d+|(?:gi|te|fa|eth)\S*)\b.*\b(?:to\s+down|is\s+down|state\s+down|down)\b",
                msg_only,
            )
        )
    ):
        category = "LINK_DOWN"
        tags = ["LINK_DOWN", "INTERFACE"]

    elif (
        re.search(r"\bchanged state to up\b", hay)
        or re.search(r"\bstate\s+up\b", hay)
        or re.search(r"\blink\s+up\b", hay)
        or (sd_action == "interface-stat-change" and sd_status == "up")
        or bool(
            re.search(
                r"\b(?:interface|port|ethernet\s+\d+/\d+/\d+|(?:gi|te|fa|eth)\S*)\b.*\b(?:to\s+up|is\s+up|came\s+up)\b",
                msg_only,
            )
        )
    ):
        category = "LINK_UP"
        tags = ["LINK_UP", "INTERFACE"]

    elif (
        "%sec_login-4-login_failed" in hay
        or "%authmgr-5-fail" in hay
        or "login failed" in hay
        or "failed password" in hay
        or "authentication fail" in hay
        or "auth fail" in hay
        or "invalid user" in hay
        or "access denied" in hay
        or (sd_action in ("login", "admin-login") and sd_status in ("failed", "failure"))
    ):
        category = "AUTH_FAIL"
        tags = ["SECURITY", "AUTH"]

    elif (
        "%sys-5-config_i" in hay
        or "configured from" in hay
        or "configuration changed" in hay
        or "config changed" in hay
        or "cfgpath" in sd_flat
        or "running-config" in hay
        or (sd_action in ("edit", "config", "modify") and sd_type == "config")
    ):
        category = "CONFIG_CHANGE"
        tags = ["CONFIG", "AUDIT"]

    elif (
        "%sys-1-cpurisingthreshold" in hay
        or "cpu usage high" in hay
        or "high cpu" in hay
        or "conserve mode" in hay
        or "cpu threshold" in hay
    ):
        category = "HIGH_CPU"
        tags = ["PERFORMANCE", "CPU"]

    elif (
        "%envmon" in hay
        or "overheat" in hay
        or "temperature threshold" in hay
        or "thermal" in hay
        or "fan fail" in hay
        or "power supply fail" in hay
        or "psu fail" in hay
    ):
        category = "HARDWARE_THERMAL"
        tags = ["HARDWARE", "TEMPERATURE"]

    interface_name = _extract_interface_name(parsed, sd_flat, category)
    username = _extract_username(parsed, sd_flat) if category in ("AUTH_FAIL", "CONFIG_CHANGE", "REBOOT") else ""

    return SyslogClassification(
        event_category=category,
        vendor=vendor,
        interface_name=interface_name,
        username=username,
        tags=tags,
    )
