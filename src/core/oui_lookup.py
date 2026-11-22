import re
from typing import Dict

# Curated local IEEE OUI database for offline enterprise vendor identification.
# NOTE: MAC vendor identification NEVER guarantees device category/type.
OUI_VENDORS: Dict[str, str] = {
    # Cisco / Meraki / Linksys
    "00:00:0C": "Cisco", "00:01:42": "Cisco", "00:01:43": "Cisco", "00:01:63": "Cisco",
    "00:01:64": "Cisco", "00:01:96": "Cisco", "00:01:97": "Cisco", "00:02:16": "Cisco",
    "00:02:4A": "Cisco", "00:04:9A": "Cisco", "00:07:0D": "Cisco", "00:09:E8": "Cisco",
    "00:0A:8A": "Cisco", "00:0B:BE": "Cisco", "00:0C:29": "VMware", "00:0D:ED": "Cisco",
    "00:11:21": "Cisco", "00:12:00": "Cisco", "00:13:19": "Cisco", "00:14:1C": "Cisco",
    "00:15:62": "Cisco", "00:17:94": "Cisco", "00:18:BA": "Cisco", "00:1A:A1": "Cisco",
    "00:1B:D5": "Cisco", "00:1C:0E": "Cisco", "00:1D:70": "Cisco", "00:1E:13": "Cisco",
    "00:1E:F7": "Cisco", "00:21:55": "Cisco", "00:22:90": "Cisco", "00:23:AC": "Cisco",
    "00:24:97": "Cisco", "00:25:45": "Cisco", "00:26:0B": "Cisco", "00:3A:9A": "Cisco",
    "00:50:56": "VMware", "00:50:79": "VirtualBox",
    "00:18:0A": "Cisco Meraki", "0C:8D:DB": "Cisco Meraki", "E0:CB:BC": "Cisco Meraki",
    "34:56:FE": "Cisco Meraki", "AC:17:C8": "Cisco Meraki",
    # Ruckus / Brocade
    "00:05:1E": "Ruckus / Brocade", "00:1B:ED": "Ruckus / Brocade", "00:24:38": "Ruckus / Brocade",
    "00:25:C4": "Ruckus", "04:4F:AA": "Ruckus", "1C:B9:C4": "Ruckus",
    "24:C9:A1": "Ruckus", "2C:5D:93": "Ruckus", "30:87:D9": "Ruckus",
    "50:A7:33": "Ruckus", "58:B6:33": "Ruckus", "60:9C:9F": "Ruckus",
    "74:8E:F8": "Ruckus / Brocade", "74:91:1A": "Ruckus", "84:18:3A": "Ruckus",
    "94:F6:65": "Ruckus", "C0:C5:20": "Ruckus", "CC:8E:71": "Ruckus / Brocade",
    "D4:C1:9E": "Ruckus", "F0:B0:52": "Ruckus",
    # Fortinet
    "00:09:0F": "Fortinet", "08:5B:0E": "Fortinet", "70:4C:A5": "Fortinet",
    "90:6C:AC": "Fortinet", "E8:1C:BA": "Fortinet", "B4:8A:5F": "Fortinet",
    # Aruba / HPE
    "00:0B:86": "Aruba", "00:1A:1E": "Aruba", "00:24:6C": "Aruba",
    "18:64:72": "Aruba", "20:4C:03": "Aruba", "24:DE:C6": "Aruba",
    "6C:F3:7F": "Aruba", "94:B4:0F": "Aruba", "AC:A3:1E": "Aruba",
    "00:0F:20": "HPE", "00:17:A4": "HPE", "00:1E:0B": "HPE",
    "3C:4A:92": "HPE", "94:57:A5": "HPE", "D4:C9:EF": "HPE",
    # Juniper / Arista / Palo Alto / Huawei
    "00:05:85": "Juniper", "00:10:DB": "Juniper", "00:19:E2": "Juniper", "2C:6B:F5": "Juniper",
    "00:1C:73": "Arista", "28:99:3A": "Arista", "44:4C:A8": "Arista",
    "00:1B:17": "Palo Alto Networks", "7C:FE:90": "Palo Alto Networks", "D4:F4:BE": "Palo Alto Networks",
    "00:E0:FC": "Huawei", "00:25:9E": "Huawei", "48:46:FB": "Huawei",
    # MikroTik / Ubiquiti / Netgear / TP-Link / SonicWall
    "00:0C:42": "MikroTik", "4C:5E:0C": "MikroTik", "6C:3B:6B": "MikroTik",
    "74:4D:28": "MikroTik", "B8:69:F4": "MikroTik", "D4:CA:6D": "MikroTik",
    "00:27:22": "Ubiquiti", "04:18:D6": "Ubiquiti", "18:E8:29": "Ubiquiti",
    "24:A4:3C": "Ubiquiti", "44:D9:E7": "Ubiquiti", "74:83:C2": "Ubiquiti",
    "78:8A:20": "Ubiquiti", "F0:9F:C2": "Ubiquiti", "FC:EC:DA": "Ubiquiti",
    "00:09:5B": "Netgear", "28:C6:8E": "Netgear", "A0:40:A0": "Netgear",
    "14:CC:20": "TP-Link", "50:C7:BF": "TP-Link", "B0:4E:26": "TP-Link",
    "00:06:B1": "SonicWall", "18:B1:69": "SonicWall", "C0:EA:E4": "SonicWall",
    # Servers, Workstations, Printers, Storage, UPS
    "00:14:22": "Dell", "00:1E:C9": "Dell", "14:18:77": "Dell", "24:6E:96": "Dell", "F8:BC:12": "Dell",
    "00:1B:21": "Intel", "3C:97:0E": "Intel", "68:05:CA": "Intel", "A4:BF:01": "Intel",
    "00:03:93": "Apple", "3C:15:C2": "Apple", "A4:83:E7": "Apple", "F0:18:98": "Apple",
    "00:00:85": "Canon", "18:0C:AC": "Canon", "00:80:77": "Brother", "30:05:5C": "Brother",
    "00:00:AA": "Xerox", "00:00:74": "Ricoh", "00:26:73": "Ricoh",
    "00:11:32": "Synology", "24:5E:BE": "QNAP",
    "00:C0:B7": "APC", "00:20:85": "Eaton",
    "00:15:5D": "Microsoft Hyper-V", "52:54:00": "QEMU / KVM",
}

_HEX12_RE = re.compile(r"[^0-9A-Fa-f]")


def normalize_mac(mac: str) -> str:
    """Normalize MAC addresses (colon, hyphen, Cisco dot, raw hex) to AA:BB:CC:DD:EE:FF."""
    cleaned = _HEX12_RE.sub("", str(mac or ""))
    if len(cleaned) != 12:
        return ""
    up = cleaned.upper()
    return ":".join(up[i:i + 2] for i in range(0, 12, 2))


def lookup_vendor_by_mac(mac: str) -> str:
    """Resolve hardware vendor from MAC OUI without making device-type assumptions."""
    norm = normalize_mac(mac)
    if not norm:
        return "Unknown"
    prefix = norm[:8]
    return OUI_VENDORS.get(prefix, "Unknown")
