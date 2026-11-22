from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime
import errno
import ipaddress
import json
import platform
import re
import socket
import subprocess
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple
import uuid

from core.oui_lookup import lookup_vendor_by_mac, normalize_mac
from core.snmp_client import SNMPClient, SNMPError, octet_to_mac, oid_bytes_to_hex
from core.snmp_profiles import STD_OIDS, detect_vendor_and_profile
from utils.db import (
    DatabaseManager,
    DeviceInterface,
    Host,
    InfrastructureDevice,
    MonitoringLog,
    NetworkLink,
    SNMPDevice,
)
from utils.snmp_credentials import decrypt_credentials

# Standard LLDP-MIB (IEEE 802.1AB) & CISCO-CDP-MIB & BRIDGE-MIB & RFC1213 Routing OIDs
TOPO_OIDS: Dict[str, str] = {
    # LLDP Local & Remote
    "lldpLocChassisId": "1.0.8802.1.1.2.1.3.2.0",
    "lldpLocSysName": "1.0.8802.1.1.2.1.3.3.0",
    "lldpLocPortId": "1.0.8802.1.1.2.1.3.7.1.3",
    "lldpLocPortDesc": "1.0.8802.1.1.2.1.3.7.1.4",
    "lldpRemChassisId": "1.0.8802.1.1.2.1.4.1.1.5",
    "lldpRemPortId": "1.0.8802.1.1.2.1.4.1.1.7",
    "lldpRemPortDesc": "1.0.8802.1.1.2.1.4.1.1.8",
    "lldpRemSysName": "1.0.8802.1.1.2.1.4.1.1.9",
    "lldpRemSysDesc": "1.0.8802.1.1.2.1.4.1.1.10",
    "lldpRemSysCapEnabled": "1.0.8802.1.1.2.1.4.1.1.12",
    "lldpRemManAddrIfId": "1.0.8802.1.1.2.1.4.2.1.4",
    # Cisco CDP
    "cdpCacheAddress": "1.3.6.1.4.1.9.9.23.1.2.1.1.4",
    "cdpCacheVersion": "1.3.6.1.4.1.9.9.23.1.2.1.1.5",
    "cdpCacheDeviceId": "1.3.6.1.4.1.9.9.23.1.2.1.1.6",
    "cdpCacheDevicePort": "1.3.6.1.4.1.9.9.23.1.2.1.1.7",
    "cdpCachePlatform": "1.3.6.1.4.1.9.9.23.1.2.1.1.8",
    "cdpCacheCapabilities": "1.3.6.1.4.1.9.9.23.1.2.1.1.9",
    # BRIDGE-MIB MAC FDB
    "dot1dTpFdbAddress": "1.3.6.1.2.1.17.4.3.1.1",
    "dot1dTpFdbPort": "1.3.6.1.2.1.17.4.3.1.2",
    "dot1dTpFdbStatus": "1.3.6.1.2.1.17.4.3.1.3",
    "dot1qTpFdbPort": "1.3.6.1.2.1.17.7.1.2.2.1.2",
    # RFC 1213 IP Routing & ARP
    "ipRouteDest": "1.3.6.1.2.1.4.21.1.1",
    "ipRouteIfIndex": "1.3.6.1.2.1.4.21.1.2",
    "ipRouteNextHop": "1.3.6.1.2.1.4.21.1.7",
    "ipRouteType": "1.3.6.1.2.1.4.21.1.8",
    "ipNetToMediaPhysAddress": "1.3.6.1.2.1.4.22.1.2",
}


@dataclass
class DiscoveredNeighbor:
    protocol: str  # LLDP, CDP
    local_port: str
    remote_sys_name: str = ""
    remote_mgmt_ip: str = ""
    remote_chassis_mac: str = ""
    remote_port: str = ""
    remote_sys_descr: str = ""
    remote_platform: str = ""
    capabilities_bits: int = 0
    confidence: str = "HIGH"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _suffix_after_base(oid: str, base_oid: str) -> str:
    o = str(oid or "").strip().lstrip(".")
    b = str(base_oid or "").strip().lstrip(".")
    if o.startswith(b + "."):
        return o[len(b) + 1:]
    return o


def _bytes_to_ipv4(val: Any) -> str:
    raw = oid_bytes_to_hex(val)
    if len(raw) == 4:
        return ".".join(str(b) for b in raw)
    s = str(val or "").strip()
    try:
        ipaddress.IPv4Address(s)
        return s
    except Exception:
        return ""


def _to_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        raw = oid_bytes_to_hex(val)
        if raw:
            return int.from_bytes(raw[:2], "big")
        return default


def parse_system_arp_table(raw_output: str) -> List[Dict[str, str]]:
    """Parse Windows/Linux `arp -a` output into normalized IP/MAC/type entries."""
    entries: List[Dict[str, str]] = []
    seen: Set[Tuple[str, str]] = set()
    for line in str(raw_output or "").splitlines():
        m = re.search(
            r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})\s+(\S+)?",
            line,
        )
        if not m:
            continue
        ip_str = m.group(1)
        mac_norm = normalize_mac(m.group(2))
        if not mac_norm or mac_norm in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
            continue
        if mac_norm.startswith("01:00:5E") or ip_str.endswith(".255") or ip_str.startswith("224."):
            continue
        try:
            ip_obj = ipaddress.IPv4Address(ip_str)
            if ip_obj.is_multicast:
                continue
        except Exception:
            continue
        key = (ip_str, mac_norm)
        if key in seen:
            continue
        seen.add(key)
        entries.append({
            "ip": ip_str,
            "mac": mac_norm,
            "vendor": lookup_vendor_by_mac(mac_norm),
            "entry_type": str(m.group(3) or "dynamic").lower(),
        })
    return entries


_UNREACHABLE_PING_MARKERS = (
    "unreachable",
    "impossible de joindre",
    "timed out",
    "attente dépassé",
    "attente depasse",
    "general failure",
    "défaillance générale",
    "transmit failed",
)


def _is_valid_probe_ip(ip: str) -> bool:
    clean = str(ip or "").strip()
    if not clean or clean.startswith("UNKNOWN-IP-"):
        return False
    try:
        ip_obj = ipaddress.IPv4Address(clean)
        return not ip_obj.is_multicast and not ip_obj.is_unspecified
    except Exception:
        return False


def probe_host_reachability(ip: str, timeout_sec: float = 0.8) -> Tuple[str, Optional[float]]:
    """Probe real device reachability via ICMP + non-intrusive TCP stack check fallback."""
    clean_ip = str(ip or "").strip()
    if not _is_valid_probe_ip(clean_ip):
        return "UNKNOWN", None

    icmp_alive: Optional[bool] = None
    latency_ms: Optional[float] = None

    try:
        import icmplib
        res = icmplib.ping(clean_ip, count=1, timeout=timeout_sec, privileged=False)
        if getattr(res, "is_alive", False):
            icmp_alive = True
            latency_ms = float(round(float(getattr(res, "avg_rtt", 0.0)), 1))
        else:
            icmp_alive = False
    except Exception:
        icmp_alive = None

    if icmp_alive is None:
        is_win = platform.system().lower() == "windows"
        ms_timeout = max(300, int(timeout_sec * 1000))
        cmd = (
            ["ping", "-n", "1", "-w", str(ms_timeout), clean_ip]
            if is_win
            else ["ping", "-c", "1", "-W", str(max(1, int(round(timeout_sec)))), clean_ip]
        )
        kwargs: Dict[str, Any] = {"capture_output": True, "text": True, "timeout": timeout_sec + 1.5}
        if is_win:
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        try:
            proc = subprocess.run(cmd, **kwargs)
            stdout_txt = str(proc.stdout or "")
            low = stdout_txt.lower()
            if proc.returncode == 0 and not any(m in low for m in _UNREACHABLE_PING_MARKERS):
                m_lat = re.search(r"(?:time|temps)[=<]\s*([\d.]+)\s*ms", stdout_txt, re.IGNORECASE)
                if m_lat:
                    icmp_alive = True
                    latency_ms = float(m_lat.group(1))
                elif "ttl=" in low:
                    icmp_alive = True
                    latency_ms = 1.0
                else:
                    icmp_alive = False
            else:
                icmp_alive = False
        except Exception:
            icmp_alive = False

    if icmp_alive:
        if latency_ms is not None and latency_ms >= 200.0:
            return "DEGRADED", latency_ms
        return "ONLINE", latency_ms

    # ICMP blocked/filtered -> test TCP reachability (SYN-ACK=0 or active TCP RST=ECONNREFUSED proves host stack is alive)
    for port in (443, 80, 22, 445, 135, 3389):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(0.25)
            rc = sock.connect_ex((clean_ip, port))
            if rc == 0 or rc in (10061, errno.ECONNREFUSED):
                return "ONLINE", None
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    return "DOWN", None


def _probe_hosts_concurrently(
    ips: Iterable[str],
    probe_fn: Optional[Callable[[str], Tuple[str, Optional[float]]]] = None,
    max_workers: int = 24,
) -> Dict[str, Tuple[str, Optional[float]]]:
    unique_ips = list(dict.fromkeys(ip for ip in ips if _is_valid_probe_ip(ip)))
    if not unique_ips:
        return {}
    fn = probe_fn or probe_host_reachability
    results: Dict[str, Tuple[str, Optional[float]]] = {}
    with ThreadPoolExecutor(max_workers=min(max_workers, max(1, len(unique_ips)))) as pool:
        futures = {pool.submit(fn, ip): ip for ip in unique_ips}
        for fut, ip in futures.items():
            try:
                st, lat = fut.result(timeout=5.0)
                results[ip] = (str(st or "UNKNOWN").upper(), lat)
            except Exception:
                results[ip] = ("UNKNOWN", None)
    return results


def _detect_local_default_gateway() -> str:
    """Detect local host's default IPv4 gateway cleanly without blocking."""
    try:
        kwargs: Dict[str, Any] = {"capture_output": True, "text": True, "timeout": 3}
        if platform.system().lower() == "windows":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            res = subprocess.run(["route", "print", "0.0.0.0"], **kwargs)
            m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s+", res.stdout)
            if m:
                return m.group(1)
        else:
            res = subprocess.run(["ip", "route", "show", "default"], **kwargs)
            m = re.search(r"default via (\d{1,3}(?:\.\d{1,3}){3})", res.stdout)
            if m:
                return m.group(1)
    except Exception:
        pass
    return ""


def _resolve_hostname_fast(ip: str) -> str:
    if not _is_valid_probe_ip(ip):
        return ""
    try:
        host, _aliases, _addrs = socket.gethostbyaddr(ip)
        return str(host or "").strip()
    except Exception:
        return ""


def read_local_arp_table() -> List[Dict[str, str]]:
    """Execute local OS `arp -a` safely with CREATE_NO_WINDOW."""
    kwargs: Dict[str, Any] = {"capture_output": True, "text": True, "timeout": 5}
    if platform.system().lower() == "windows":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        res = subprocess.run(["arp", "-a"], **kwargs)
        return parse_system_arp_table(res.stdout)
    except Exception:
        return []


def parse_lldp_neighbors(
    loc_port_rows: List[Tuple[str, Any]],
    rem_chassis_rows: List[Tuple[str, Any]],
    rem_port_rows: List[Tuple[str, Any]],
    rem_port_desc_rows: Optional[List[Tuple[str, Any]]] = None,
    rem_sysname_rows: Optional[List[Tuple[str, Any]]] = None,
    rem_sysdesc_rows: Optional[List[Tuple[str, Any]]] = None,
    rem_manaddr_rows: Optional[List[Tuple[str, Any]]] = None,
    rem_caps_rows: Optional[List[Tuple[str, Any]]] = None,
    iface_name_map: Optional[Dict[int, str]] = None,
) -> List[DiscoveredNeighbor]:
    """Parse LLDP-MIB local & remote tables into normalized neighbor objects."""
    loc_ports: Dict[int, str] = {}
    for oid_k, val in loc_port_rows:
        suf = _suffix_after_base(oid_k, TOPO_OIDS["lldpLocPortId"])
        try:
            pnum = int(suf.rsplit(".", 1)[-1])
            txt = str(val or "").strip()
            if txt:
                loc_ports[pnum] = txt
        except ValueError:
            pass

    if iface_name_map:
        for pnum, iname in iface_name_map.items():
            loc_ports.setdefault(int(pnum), iname)

    neighbors_by_key: Dict[str, Dict[str, Any]] = {}

    def _entry(suffix: str) -> Optional[Dict[str, Any]]:
        parts = suffix.split(".")
        if len(parts) < 3:
            return None
        key = ".".join(parts[:3])
        if key not in neighbors_by_key:
            try:
                loc_pnum = int(parts[1])
            except ValueError:
                loc_pnum = 0
            neighbors_by_key[key] = {
                "local_port": loc_ports.get(loc_pnum, f"Port-{loc_pnum}" if loc_pnum else "Unknown"),
                "remote_sys_name": "",
                "remote_mgmt_ip": "",
                "remote_chassis_mac": "",
                "remote_port": "",
                "remote_sys_descr": "",
                "capabilities_bits": 0,
            }
        return neighbors_by_key[key]

    for oid_k, val in rem_chassis_rows:
        ent = _entry(_suffix_after_base(oid_k, TOPO_OIDS["lldpRemChassisId"]))
        if ent is not None:
            mac = octet_to_mac(val) or normalize_mac(str(val or ""))
            if mac:
                ent["remote_chassis_mac"] = mac

    for oid_k, val in rem_port_rows:
        ent = _entry(_suffix_after_base(oid_k, TOPO_OIDS["lldpRemPortId"]))
        if ent is not None:
            txt = str(val or "").strip()
            if txt:
                ent["remote_port"] = txt

    for oid_k, val in (rem_port_desc_rows or []):
        ent = _entry(_suffix_after_base(oid_k, TOPO_OIDS["lldpRemPortDesc"]))
        if ent is not None and not ent["remote_port"]:
            txt = str(val or "").strip()
            if txt:
                ent["remote_port"] = txt

    for oid_k, val in (rem_sysname_rows or []):
        ent = _entry(_suffix_after_base(oid_k, TOPO_OIDS["lldpRemSysName"]))
        if ent is not None:
            ent["remote_sys_name"] = str(val or "").strip()

    for oid_k, val in (rem_sysdesc_rows or []):
        ent = _entry(_suffix_after_base(oid_k, TOPO_OIDS["lldpRemSysDesc"]))
        if ent is not None:
            ent["remote_sys_descr"] = str(val or "").strip()

    for oid_k, val in (rem_caps_rows or []):
        ent = _entry(_suffix_after_base(oid_k, TOPO_OIDS["lldpRemSysCapEnabled"]))
        if ent is not None:
            ent["capabilities_bits"] = _to_int(val, 0)

    # LLDP Management Address table index: timeMark.localPort.remIdx.addrSubtype(1).addrLen(4).A.B.C.D
    for oid_k, _val in (rem_manaddr_rows or []):
        suf = _suffix_after_base(oid_k, TOPO_OIDS["lldpRemManAddrIfId"])
        parts = suf.split(".")
        if len(parts) >= 9 and parts[3] == "1" and parts[4] == "4":
            key = ".".join(parts[:3])
            if key in neighbors_by_key:
                neighbors_by_key[key]["remote_mgmt_ip"] = ".".join(parts[5:9])

    results: List[DiscoveredNeighbor] = []
    for data in neighbors_by_key.values():
        if not (data["remote_sys_name"] or data["remote_mgmt_ip"] or data["remote_chassis_mac"]):
            continue
        results.append(
            DiscoveredNeighbor(
                protocol="LLDP",
                local_port=data["local_port"],
                remote_sys_name=data["remote_sys_name"],
                remote_mgmt_ip=data["remote_mgmt_ip"],
                remote_chassis_mac=data["remote_chassis_mac"],
                remote_port=data["remote_port"],
                remote_sys_descr=data["remote_sys_descr"],
                capabilities_bits=data["capabilities_bits"],
                confidence="HIGH",
            )
        )
    return results


def parse_cdp_neighbors(
    addr_rows: List[Tuple[str, Any]],
    dev_id_rows: List[Tuple[str, Any]],
    dev_port_rows: List[Tuple[str, Any]],
    platform_rows: Optional[List[Tuple[str, Any]]] = None,
    cap_rows: Optional[List[Tuple[str, Any]]] = None,
    version_rows: Optional[List[Tuple[str, Any]]] = None,
    iface_name_map: Optional[Dict[int, str]] = None,
) -> List[DiscoveredNeighbor]:
    """Parse CISCO-CDP-MIB cache rows into normalized neighbor objects."""
    by_idx: Dict[str, Dict[str, Any]] = {}

    def _entry(oid_k: str, base_oid: str) -> Optional[Dict[str, Any]]:
        suf = _suffix_after_base(oid_k, base_oid)
        parts = suf.split(".")
        if len(parts) < 2:
            return None
        key = ".".join(parts[:2])
        if key not in by_idx:
            try:
                if_idx = int(parts[0])
            except ValueError:
                if_idx = 0
            local_name = (iface_name_map or {}).get(if_idx, f"if{if_idx}" if if_idx else "Unknown")
            by_idx[key] = {
                "local_port": local_name,
                "remote_sys_name": "",
                "remote_mgmt_ip": "",
                "remote_port": "",
                "remote_platform": "",
                "remote_sys_descr": "",
                "capabilities_bits": 0,
            }
        return by_idx[key]

    for oid_k, val in addr_rows:
        ent = _entry(oid_k, TOPO_OIDS["cdpCacheAddress"])
        if ent is not None:
            ent["remote_mgmt_ip"] = _bytes_to_ipv4(val)

    for oid_k, val in dev_id_rows:
        ent = _entry(oid_k, TOPO_OIDS["cdpCacheDeviceId"])
        if ent is not None:
            # Strip domain suffix if desired? Keep raw name cleanly
            ent["remote_sys_name"] = str(val or "").strip()

    for oid_k, val in dev_port_rows:
        ent = _entry(oid_k, TOPO_OIDS["cdpCacheDevicePort"])
        if ent is not None:
            ent["remote_port"] = str(val or "").strip()

    for oid_k, val in (platform_rows or []):
        ent = _entry(oid_k, TOPO_OIDS["cdpCachePlatform"])
        if ent is not None:
            ent["remote_platform"] = str(val or "").strip()

    for oid_k, val in (version_rows or []):
        ent = _entry(oid_k, TOPO_OIDS["cdpCacheVersion"])
        if ent is not None:
            ent["remote_sys_descr"] = str(val or "").strip()

    for oid_k, val in (cap_rows or []):
        ent = _entry(oid_k, TOPO_OIDS["cdpCacheCapabilities"])
        if ent is not None:
            ent["capabilities_bits"] = _to_int(val, 0)

    out: List[DiscoveredNeighbor] = []
    for data in by_idx.values():
        if not (data["remote_sys_name"] or data["remote_mgmt_ip"]):
            continue
        out.append(
            DiscoveredNeighbor(
                protocol="CDP",
                local_port=data["local_port"],
                remote_sys_name=data["remote_sys_name"],
                remote_mgmt_ip=data["remote_mgmt_ip"],
                remote_port=data["remote_port"],
                remote_sys_descr=data["remote_sys_descr"] or data["remote_platform"],
                remote_platform=data["remote_platform"],
                capabilities_bits=data["capabilities_bits"],
                confidence="HIGH",
            )
        )
    return out


def parse_mac_fdb(
    fdb_port_rows: List[Tuple[str, Any]],
    bp_to_if: Dict[int, int],
    iface_name_map: Dict[int, str],
    qbridge_fdb_rows: Optional[List[Tuple[str, Any]]] = None,
) -> Dict[str, List[Dict[str, str]]]:
    """Parse BRIDGE-MIB dot1dTpFdbPort / Q-BRIDGE dot1qTpFdbPort into {port_name: [{mac, vlan}]}."""
    learned: Dict[str, List[Dict[str, str]]] = {}
    seen: Set[Tuple[str, str]] = set()

    def _add(bp: int, mac_bytes: List[str], vlan: str = "") -> None:
        if len(mac_bytes) != 6 or bp <= 0:
            return
        try:
            mac = ":".join(f"{int(b):02X}" for b in mac_bytes)
        except ValueError:
            return
        if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            return
        if_idx = bp_to_if.get(bp, bp)
        pname = iface_name_map.get(if_idx, f"if{if_idx}")
        if (pname, mac) in seen:
            return
        seen.add((pname, mac))
        learned.setdefault(pname, []).append({"mac": mac, "vlan": vlan})

    for oid_k, val in fdb_port_rows:
        suf = _suffix_after_base(oid_k, TOPO_OIDS["dot1dTpFdbPort"])
        parts = suf.split(".")
        _add(_to_int(val, 0), parts[-6:])

    for oid_k, val in (qbridge_fdb_rows or []):
        suf = _suffix_after_base(oid_k, TOPO_OIDS["dot1qTpFdbPort"])
        parts = suf.split(".")
        if len(parts) >= 7:
            _add(_to_int(val, 0), parts[-6:], vlan=parts[0])

    return learned


def parse_routing_next_hops(
    route_if_rows: List[Tuple[str, Any]],
    route_nexthop_rows: List[Tuple[str, Any]],
    route_type_rows: Optional[List[Tuple[str, Any]]] = None,
    iface_name_map: Optional[Dict[int, str]] = None,
) -> List[Dict[str, str]]:
    """Parse RFC 1213 ipRouteTable indirect next-hops for logical topology edges."""
    if_by_dest: Dict[str, int] = {}
    nh_by_dest: Dict[str, str] = {}
    type_by_dest: Dict[str, int] = {}

    for oid_k, val in route_if_rows:
        dest = _suffix_after_base(oid_k, TOPO_OIDS["ipRouteIfIndex"])
        if_by_dest[dest] = _to_int(val, 0)

    for oid_k, val in route_nexthop_rows:
        dest = _suffix_after_base(oid_k, TOPO_OIDS["ipRouteNextHop"])
        ip_nh = _bytes_to_ipv4(val)
        if ip_nh and ip_nh != "0.0.0.0":
            nh_by_dest[dest] = ip_nh

    for oid_k, val in (route_type_rows or []):
        dest = _suffix_after_base(oid_k, TOPO_OIDS["ipRouteType"])
        type_by_dest[dest] = _to_int(val, 0)

    hops: List[Dict[str, str]] = []
    seen_nhs: Set[str] = set()
    for dest, nh in nh_by_dest.items():
        if type_by_dest and dest in type_by_dest and type_by_dest[dest] not in (4, 0):
            continue
        if nh in seen_nhs or nh.startswith("127."):
            continue
        seen_nhs.add(nh)
        if_idx = if_by_dest.get(dest, 0)
        hops.append({
            "dest_network": dest,
            "next_hop_ip": nh,
            "local_interface": (iface_name_map or {}).get(if_idx, f"if{if_idx}" if if_idx else ""),
        })
    return hops


def classify_device_identity(
    mac: str = "",
    sys_descr: str = "",
    sys_object_id: str = "",
    sys_services: int = 0,
    cdp_caps: int = 0,
    lldp_caps: int = 0,
    existing_category: str = "",
    existing_vendor: str = "",
) -> Tuple[str, str]:
    """Identify vendor and device category safely without ever guessing type from MAC OUI."""
    vendor = existing_vendor.strip() if existing_vendor and existing_vendor not in ("Unknown", "Generic") else ""
    category = existing_category.strip() if existing_category and existing_category != "Other" else ""

    if sys_descr or sys_object_id or sys_services:
        hint = detect_vendor_and_profile(sys_object_id=sys_object_id, sys_descr=sys_descr, sys_services=sys_services)
        if not vendor and hint.get("vendor") and hint["vendor"] != "Generic":
            vendor = hint["vendor"]
        descr_low = sys_descr.lower()
        if not category:
            if "fortigate" in descr_low or "firewall" in descr_low or "palo alto" in descr_low or "asa" in descr_low:
                category = "Firewall"
            elif "smartzone" in descr_low or "controller" in descr_low or "wlc" in descr_low:
                category = "Wireless Controller"
            elif "access point" in descr_low or "zoneflex" in descr_low or "unifi ap" in descr_low or (lldp_caps & 0x08):
                category = "Wireless Access Point"
            elif "core" in descr_low and ("switch" in descr_low or "catalyst" in descr_low or "icx" in descr_low):
                category = "Core Switch"
            elif "catalyst" in descr_low or "icx" in descr_low or "switch" in descr_low or (cdp_caps & 0x08) or (lldp_caps & 0x04):
                category = "Access Switch"
            elif "router" in descr_low or "mikrotik" in descr_low or (cdp_caps & 0x01) or (lldp_caps & 0x10) or ((sys_services & 0x04) and not (sys_services & 0x02)):
                category = "Router"
            elif "ups" in descr_low or "smart-ups" in descr_low or "eaton" in descr_low:
                category = "UPS"
            elif "printer" in descr_low or "laserjet" in descr_low or "multifunction" in descr_low:
                category = "Printer"
            elif "linux" in descr_low or "windows" in descr_low or "server" in descr_low or "vmware" in descr_low:
                category = "Server"

    # MAC OUI strictly supplies Vendor ONLY — never Category/Type
    if not vendor and mac:
        oui_vendor = lookup_vendor_by_mac(mac)
        if oui_vendor != "Unknown":
            vendor = oui_vendor

    return (vendor or "Unknown"), (category or "Other")


class TopologyDiscoveryEngine:
    """Evidence-driven network topology discovery engine combining SNMP, LLDP, CDP, FDB, Routing & ARP."""

    def __init__(self, db: DatabaseManager, snmp_client: Optional[SNMPClient] = None) -> None:
        self.db = db
        self.client = snmp_client or SNMPClient()

    def _find_or_create_device(
        self,
        session: Any,
        ip: str = "",
        mac: str = "",
        hostname: str = "",
        vendor: str = "Unknown",
        category: str = "Other",
        role: str = "",
        model: str = "",
        firmware: str = "",
        site_id: Optional[int] = None,
        discovery_source: str = "TOPOLOGY_DISCOVERY",
        status: str = "UNKNOWN",
        snmp_device_id: Optional[int] = None,
    ) -> InfrastructureDevice:
        clean_ip = str(ip or "").strip()
        clean_mac = normalize_mac(mac)
        clean_host = str(hostname or "").strip()

        dev: Optional[InfrastructureDevice] = None
        if clean_ip:
            dev = session.query(InfrastructureDevice).filter_by(management_ip=clean_ip).first()
        if dev is None and clean_mac:
            dev = session.query(InfrastructureDevice).filter_by(mac_address=clean_mac).first()
        if dev is None and clean_host:
            dev = session.query(InfrastructureDevice).filter_by(hostname=clean_host).first()

        now = datetime.utcnow()
        if dev is not None:
            if clean_mac and not dev.mac_address:
                dev.mac_address = clean_mac
            if clean_host and (not dev.hostname or dev.hostname == dev.management_ip):
                dev.hostname = clean_host
            if vendor != "Unknown" and (not dev.vendor or dev.vendor == "Unknown"):
                dev.vendor = vendor
            if category != "Other" and (not dev.category or dev.category == "Other"):
                dev.category = category
            if role and not dev.role:
                dev.role = role
            if model and not dev.model:
                dev.model = model
            if firmware and not dev.firmware_version:
                dev.firmware_version = firmware
            if status != "UNKNOWN":
                dev.status = status
            if snmp_device_id is not None and dev.snmp_device_id is None:
                dev.snmp_device_id = snmp_device_id
            dev.last_discovery = now
            return dev

        target_ip = clean_ip or f"UNKNOWN-IP-{clean_mac or uuid.uuid4().hex[:6]}"
        target_host = clean_host or clean_ip or (f"Device-{clean_mac[-5:]}" if clean_mac else "Unknown-Device")
        dev = InfrastructureDevice(
            device_uid=f"DEV-{uuid.uuid4().hex[:10].upper()}",
            site_id=site_id,
            snmp_device_id=snmp_device_id,
            hostname=target_host,
            management_ip=target_ip,
            mac_address=clean_mac,
            vendor=vendor,
            model=model,
            firmware_version=firmware,
            category=category,
            role=role,
            discovery_source=discovery_source,
            status=status,
            last_discovery=now,
        )
        session.add(dev)
        session.flush()
        return dev

    @staticmethod
    def _upsert_link(
        session: Any,
        src_id: int,
        dst_id: int,
        src_if: str,
        dst_if: str,
        link_type: str,
        discovery_method: str,
        confidence: str,
        evidence: List[str],
        vlan_ids: Optional[List[int]] = None,
    ) -> NetworkLink:
        if src_id == dst_id:
            raise ValueError("Self-loop links are not allowed.")
        # Check either direction for deduplication
        existing = (
            session.query(NetworkLink)
            .filter(
                ((NetworkLink.source_device_id == src_id) & (NetworkLink.dest_device_id == dst_id))
                | ((NetworkLink.source_device_id == dst_id) & (NetworkLink.dest_device_id == src_id))
            )
            .filter(
                (NetworkLink.source_interface == src_if) | (NetworkLink.dest_interface == src_if) | (NetworkLink.source_interface == "")
            )
            .first()
        )
        now = datetime.utcnow()
        rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        if existing is not None:
            if rank.get(confidence, 1) >= rank.get(existing.confidence, 1):
                existing.discovery_method = discovery_method
                existing.confidence = confidence
                existing.link_type = link_type
                if existing.source_device_id == src_id:
                    existing.source_interface = src_if or existing.source_interface
                    existing.dest_interface = dst_if or existing.dest_interface
                else:
                    existing.source_interface = dst_if or existing.source_interface
                    existing.dest_interface = src_if or existing.dest_interface
            existing.last_observed = now
            prev_ev = json.loads(existing.evidence_json or "[]")
            merged = list(dict.fromkeys([*prev_ev, *evidence]))
            existing.evidence_json = json.dumps(merged)
            if vlan_ids:
                prev_v = json.loads(existing.vlan_ids_json or "[]")
                existing.vlan_ids_json = json.dumps(sorted(set(prev_v) | set(vlan_ids)))
            return existing

        link = NetworkLink(
            source_device_id=src_id,
            dest_device_id=dst_id,
            source_interface=src_if or "",
            dest_interface=dst_if or "",
            link_type=link_type,
            discovery_method=discovery_method,
            confidence=confidence,
            status="UP",
            vlan_ids_json=json.dumps(sorted(set(vlan_ids or []))),
            evidence_json=json.dumps(list(evidence)),
            last_observed=now,
        )
        session.add(link)
        return link

    async def discover_topology(
        self,
        include_local_arp: bool = True,
        arp_entries: Optional[List[Dict[str, str]]] = None,
        site_id: Optional[int] = None,
        probe_icmp: bool = True,
        icmp_probe_fn: Optional[Callable[[str], Tuple[str, Optional[float]]]] = None,
        resolve_hostnames: bool = False,
    ) -> Dict[str, Any]:
        """Run multi-source topology discovery across registered SNMP devices, Hosts and ARP, with live status verification."""
        summary = {
            "devices_discovered": 0,
            "online_devices": 0,
            "degraded_devices": 0,
            "down_devices": 0,
            "links_discovered": 0,
            "unknown_endpoints": 0,
            "inferred_unmanaged": 0,
        }
        snmp_rows = self.db.get_snmp_devices(enabled_only=True)

        async def _safe_walk(ip: str, port: int, creds: Any, oid: str, timeout: float, retries: int) -> List[Tuple[str, Any]]:
            try:
                return await self.client.walk_oid(ip, creds, oid, port=port, timeout_sec=timeout, retries=retries)
            except SNMPError:
                return []

        per_device_findings: List[Dict[str, Any]] = []
        snmp_responsive_ips: Set[str] = set()
        for srow in snmp_rows:
            creds = decrypt_credentials(srow["encrypted_credentials"])
            ip = srow["ip_address"]
            port = int(srow.get("port", 161))
            timeout = float(srow.get("timeout_sec", 2.0))
            retries = int(srow.get("retries", 1))

            # Build interface name & bridge-port mapping
            if_name_map: Dict[int, str] = {}
            for oid_k, val in await _safe_walk(ip, port, creds, STD_OIDS["ifDescr"], timeout, retries):
                try:
                    if_name_map[int(str(oid_k).rsplit(".", 1)[-1])] = str(val or "").strip()
                except ValueError:
                    pass
            bp_to_if: Dict[int, int] = {}
            for oid_k, val in await _safe_walk(ip, port, creds, STD_OIDS["dot1dBasePortIfIndex"], timeout, retries):
                try:
                    bp_to_if[int(str(oid_k).rsplit(".", 1)[-1])] = int(val)
                except (ValueError, TypeError):
                    pass

            # LLDP
            lldp = parse_lldp_neighbors(
                loc_port_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["lldpLocPortId"], timeout, retries),
                rem_chassis_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["lldpRemChassisId"], timeout, retries),
                rem_port_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["lldpRemPortId"], timeout, retries),
                rem_port_desc_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["lldpRemPortDesc"], timeout, retries),
                rem_sysname_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["lldpRemSysName"], timeout, retries),
                rem_sysdesc_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["lldpRemSysDesc"], timeout, retries),
                rem_manaddr_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["lldpRemManAddrIfId"], timeout, retries),
                rem_caps_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["lldpRemSysCapEnabled"], timeout, retries),
                iface_name_map=if_name_map,
            )
            # CDP
            cdp = parse_cdp_neighbors(
                addr_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["cdpCacheAddress"], timeout, retries),
                dev_id_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["cdpCacheDeviceId"], timeout, retries),
                dev_port_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["cdpCacheDevicePort"], timeout, retries),
                platform_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["cdpCachePlatform"], timeout, retries),
                cap_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["cdpCacheCapabilities"], timeout, retries),
                version_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["cdpCacheVersion"], timeout, retries),
                iface_name_map=if_name_map,
            )
            # MAC FDB & Routing & SNMP ARP table
            mac_fdb = parse_mac_fdb(
                fdb_port_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["dot1dTpFdbPort"], timeout, retries),
                bp_to_if=bp_to_if,
                iface_name_map=if_name_map,
                qbridge_fdb_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["dot1qTpFdbPort"], timeout, retries),
            )
            routes = parse_routing_next_hops(
                route_if_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["ipRouteIfIndex"], timeout, retries),
                route_nexthop_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["ipRouteNextHop"], timeout, retries),
                route_type_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["ipRouteType"], timeout, retries),
                iface_name_map=if_name_map,
            )
            snmp_arp: Dict[str, str] = {}
            for oid_k, val in await _safe_walk(ip, port, creds, TOPO_OIDS["ipNetToMediaPhysAddress"], timeout, retries):
                parts = str(oid_k).split(".")
                if len(parts) >= 4:
                    a_ip = ".".join(parts[-4:])
                    a_mac = octet_to_mac(val)
                    if a_mac:
                        snmp_arp[a_mac] = a_ip

            if if_name_map or lldp or cdp or mac_fdb or routes or snmp_arp:
                snmp_responsive_ips.add(ip)

            per_device_findings.append({
                "snmp_row": srow,
                "neighbors": lldp + cdp,
                "mac_fdb": mac_fdb,
                "routes": routes,
                "snmp_arp": snmp_arp,
                "if_name_map": if_name_map,
            })

        arp_list = list(arp_entries) if arp_entries is not None else (read_local_arp_table() if include_local_arp else [])
        arp_ip_by_mac = {e["mac"]: e["ip"] for e in arp_list if e.get("mac") and e.get("ip")}
        gateway_ip = _detect_local_default_gateway() if include_local_arp else ""

        with self.db.Session() as session:
            # Map existing monitored Host statuses by IP so known monitored hosts stay accurate
            host_rows = {h.id: h for h in session.query(Host).all()}
            host_status_by_ip: Dict[str, Tuple[str, str]] = {}
            for hid, hobj in host_rows.items():
                last_log = (
                    session.query(MonitoringLog)
                    .filter(MonitoringLog.host_id == hid)
                    .order_by(MonitoringLog.id.desc())
                    .first()
                )
                hst = str(last_log.status).upper() if last_log and last_log.status else "UNKNOWN"
                if hst == "UP":
                    hst = "ONLINE"
                host_status_by_ip[hobj.address] = (hst, hobj.label or hobj.address)

            # Map FDB MAC -> IP across SNMP ARP & Local ARP
            for finding in per_device_findings:
                arp_ip_by_mac.update(finding["snmp_arp"])

            # 1. Ensure each SNMP device exists in infrastructure_devices
            dev_by_ip: Dict[str, InfrastructureDevice] = {}
            for finding in per_device_findings:
                srow = finding["snmp_row"]
                vendor, cat = classify_device_identity(
                    sys_descr=srow.get("sys_descr", ""),
                    sys_object_id=srow.get("sys_object_id", ""),
                    existing_vendor=srow.get("vendor", ""),
                    existing_category="",
                )
                if cat == "Other" and srow.get("device_type"):
                    from core.inventory_manager import _norm_category
                    cat = _norm_category(srow["device_type"])

                init_status = "ONLINE" if srow["ip_address"] in snmp_responsive_ips else str(srow.get("status") or "UNKNOWN").upper()
                local_dev = self._find_or_create_device(
                    session,
                    ip=srow["ip_address"],
                    hostname=srow.get("sys_name") or srow.get("name") or srow["ip_address"],
                    vendor=vendor,
                    category=cat,
                    model=srow.get("model", ""),
                    firmware=srow.get("firmware", ""),
                    site_id=site_id,
                    discovery_source="SNMP_TOPOLOGY",
                    status=init_status,
                    snmp_device_id=srow["id"],
                )
                dev_by_ip[local_dev.management_ip] = local_dev
                summary["devices_discovered"] += 1

            # 2. Process LLDP & CDP direct neighbors (HIGH confidence)
            ports_with_direct_neighbor: Dict[Tuple[int, str], bool] = {}
            for finding in per_device_findings:
                src_dev = dev_by_ip[finding["snmp_row"]["ip_address"]]
                for nb in finding["neighbors"]:
                    ports_with_direct_neighbor[(src_dev.id, nb.local_port)] = True
                    n_vendor, n_cat = classify_device_identity(
                        mac=nb.remote_chassis_mac,
                        sys_descr=nb.remote_sys_descr,
                        cdp_caps=nb.capabilities_bits if nb.protocol == "CDP" else 0,
                        lldp_caps=nb.capabilities_bits if nb.protocol == "LLDP" else 0,
                    )
                    dst_dev = self._find_or_create_device(
                        session,
                        ip=nb.remote_mgmt_ip or arp_ip_by_mac.get(nb.remote_chassis_mac, ""),
                        mac=nb.remote_chassis_mac,
                        hostname=nb.remote_sys_name,
                        vendor=n_vendor,
                        category=n_cat,
                        model=nb.remote_platform,
                        site_id=src_dev.site_id,
                        discovery_source=nb.protocol,
                    )
                    if dst_dev.management_ip.startswith("UNKNOWN-IP-") and n_cat == "Other":
                        summary["unknown_endpoints"] += 1
                    ltype = "PHYSICAL"
                    if "Switch" in src_dev.category and "Switch" in dst_dev.category:
                        ltype = "UPLINK"
                    elif dst_dev.category == "Wireless Access Point":
                        ltype = "AP_UPLINK"
                    self._upsert_link(
                        session,
                        src_id=src_dev.id,
                        dst_id=dst_dev.id,
                        src_if=nb.local_port,
                        dst_if=nb.remote_port,
                        link_type=ltype,
                        discovery_method=nb.protocol,
                        confidence=nb.confidence,
                        evidence=[f"{nb.protocol}: {src_dev.hostname}:{nb.local_port} -> {dst_dev.hostname}:{nb.remote_port or '?'} "],
                    )
                    summary["links_discovered"] += 1

            # 3. Process Routing next-hops (LOGICAL / L3)
            for finding in per_device_findings:
                src_dev = dev_by_ip[finding["snmp_row"]["ip_address"]]
                for hop in finding["routes"]:
                    nh_ip = hop["next_hop_ip"]
                    dst_dev = session.query(InfrastructureDevice).filter_by(management_ip=nh_ip).first()
                    if dst_dev is None:
                        dst_dev = self._find_or_create_device(
                            session,
                            ip=nh_ip,
                            hostname=nh_ip,
                            category="Router",
                            site_id=src_dev.site_id,
                            discovery_source="ROUTING_TABLE",
                        )
                    self._upsert_link(
                        session,
                        src_id=src_dev.id,
                        dst_id=dst_dev.id,
                        src_if=hop["local_interface"],
                        dst_if="",
                        link_type="LOGICAL",
                        discovery_method="ROUTING",
                        confidence="MEDIUM",
                        evidence=[f"Route next-hop {nh_ip} for {hop['dest_network']} via {hop['local_interface'] or 'routed'}"],
                    )
                    summary["links_discovered"] += 1

            # 4. Process MAC FDB (connect endpoints; infer unmanaged switch ONLY when >=2 endpoints share a non-LLDP/CDP access port)
            for finding in per_device_findings:
                src_dev = dev_by_ip[finding["snmp_row"]["ip_address"]]
                for pname, mac_entries in finding["mac_fdb"].items():
                    if ports_with_direct_neighbor.get((src_dev.id, pname)):
                        continue  # Port already has authoritative LLDP/CDP link (e.g. uplink/trunk)
                    if not mac_entries:
                        continue
                    parent_id = src_dev.id
                    parent_port = pname
                    if len(mac_entries) >= 2:
                        # Infer unmanaged switch only with multi-MAC corroboration on non-LLDP port
                        unm_host = f"Unmanaged-Switch-{src_dev.hostname}-{pname}"
                        unm_dev = self._find_or_create_device(
                            session,
                            hostname=unm_host,
                            category="Access Switch",
                            role="Unmanaged Switch (Inferred)",
                            site_id=src_dev.site_id,
                            discovery_source="BRIDGE_FDB_INFERRED",
                            status="UNKNOWN",
                        )
                        self._upsert_link(
                            session,
                            src_id=src_dev.id,
                            dst_id=unm_dev.id,
                            src_if=pname,
                            dst_if="Uplink",
                            link_type="PHYSICAL",
                            discovery_method="BRIDGE_FDB",
                            confidence="MEDIUM",
                            evidence=[f"{len(mac_entries)} downstream MACs learned on {src_dev.hostname}:{pname} without LLDP/CDP neighbor"],
                        )
                        summary["inferred_unmanaged"] += 1
                        summary["links_discovered"] += 1
                        parent_id = unm_dev.id
                        parent_port = "Access"

                    for m_ent in mac_entries:
                        ep_mac = m_ent["mac"]
                        ep_ip = arp_ip_by_mac.get(ep_mac, "")
                        ep_vendor, ep_cat = classify_device_identity(mac=ep_mac)
                        ep_dev = self._find_or_create_device(
                            session,
                            ip=ep_ip,
                            mac=ep_mac,
                            hostname=ep_ip or f"Unknown-{ep_mac[-5:]}",
                            vendor=ep_vendor,
                            category=ep_cat,
                            site_id=src_dev.site_id,
                            discovery_source="BRIDGE_FDB",
                        )
                        if ep_cat == "Other":
                            summary["unknown_endpoints"] += 1
                        vlans = [int(m_ent["vlan"])] if str(m_ent.get("vlan", "")).isdigit() else []
                        self._upsert_link(
                            session,
                            src_id=parent_id,
                            dst_id=ep_dev.id,
                            src_if=parent_port,
                            dst_if="eth0",
                            link_type="PHYSICAL",
                            discovery_method="BRIDGE_FDB",
                            confidence="MEDIUM" if ep_ip else "LOW",
                            evidence=[f"MAC {ep_mac} learned on {src_dev.hostname}:{pname}"],
                            vlan_ids=vlans,
                        )
                        summary["links_discovered"] += 1

            # 5. Standalone ARP devices not linked yet -> add as discovered nodes without inventing links
            for arp in arp_list:
                ep_vendor, ep_cat = classify_device_identity(mac=arp["mac"])
                if ep_cat == "Other" and gateway_ip and arp["ip"] == gateway_ip:
                    ep_cat = "Router"
                known_st, known_label = host_status_by_ip.get(arp["ip"], ("UNKNOWN", arp["ip"]))
                self._find_or_create_device(
                    session,
                    ip=arp["ip"],
                    mac=arp["mac"],
                    hostname=known_label,
                    vendor=ep_vendor,
                    category=ep_cat,
                    site_id=site_id,
                    discovery_source="ARP_TABLE",
                    status=known_st,
                )
                summary["devices_discovered"] += 1

            session.flush()

            # 6. Live reachability probing & optional reverse-DNS hostname enrichment across in-scope nodes
            q_scope = session.query(InfrastructureDevice)
            if site_id is not None:
                q_scope = q_scope.filter(InfrastructureDevice.site_id == int(site_id))
            scope_devs = q_scope.all()

            now_check = datetime.utcnow()
            if probe_icmp:
                to_probe = [
                    d.management_ip
                    for d in scope_devs
                    if _is_valid_probe_ip(d.management_ip) and d.management_ip not in snmp_responsive_ips
                ]
                probed_map = _probe_hosts_concurrently(to_probe, probe_fn=icmp_probe_fn)
                for d in scope_devs:
                    if d.management_ip in snmp_responsive_ips:
                        d.status = "ONLINE"
                        d.last_monitoring_check = now_check
                    elif d.management_ip in probed_map:
                        st_val, _lat = probed_map[d.management_ip]
                        if st_val != "UNKNOWN":
                            d.status = st_val
                        d.last_monitoring_check = now_check

            if resolve_hostnames:
                ips_needing_name = [
                    d.management_ip
                    for d in scope_devs
                    if _is_valid_probe_ip(d.management_ip) and (not d.hostname or d.hostname == d.management_ip)
                ]
                if ips_needing_name:
                    with ThreadPoolExecutor(max_workers=min(16, len(ips_needing_name))) as pool:
                        fmap = {pool.submit(_resolve_hostname_fast, ip): ip for ip in set(ips_needing_name)}
                        resolved_names: Dict[str, str] = {}
                        for fut, ip in fmap.items():
                            try:
                                rname = fut.result(timeout=2.0)
                                if rname:
                                    resolved_names[ip] = rname
                            except Exception:
                                pass
                    for d in scope_devs:
                        if (not d.hostname or d.hostname == d.management_ip) and d.management_ip in resolved_names:
                            d.hostname = resolved_names[d.management_ip]

            for d in scope_devs:
                st_up = str(d.status or "UNKNOWN").upper()
                if st_up in ("ONLINE", "UP", "OK"):
                    summary["online_devices"] += 1
                elif st_up in ("DEGRADED", "WARNING", "RECOVERING"):
                    summary["degraded_devices"] += 1
                elif st_up in ("DOWN", "OFFLINE", "CRITICAL"):
                    summary["down_devices"] += 1

            session.commit()
        return summary

    def refresh_live_statuses(
        self,
        site_id: Optional[int] = None,
        icmp_probe_fn: Optional[Callable[[str], Tuple[str, Optional[float]]]] = None,
    ) -> Dict[str, int]:
        """Probe live reachability of all IP-bearing infrastructure devices and persist updated statuses."""
        counts = {"probed": 0, "online": 0, "degraded": 0, "down": 0, "unknown": 0}
        with self.db.Session() as session:
            q = session.query(InfrastructureDevice)
            if site_id is not None:
                q = q.filter(InfrastructureDevice.site_id == int(site_id))
            devs = q.all()
            probe_ips = [d.management_ip for d in devs if _is_valid_probe_ip(d.management_ip)]
            probed_map = _probe_hosts_concurrently(probe_ips, probe_fn=icmp_probe_fn)
            now = datetime.utcnow()
            for d in devs:
                if d.management_ip in probed_map:
                    counts["probed"] += 1
                    st_val, _lat = probed_map[d.management_ip]
                    d.status = st_val
                    d.last_monitoring_check = now
                cur = str(d.status or "UNKNOWN").upper()
                if cur in ("ONLINE", "UP", "OK"):
                    counts["online"] += 1
                elif cur in ("DEGRADED", "WARNING", "RECOVERING"):
                    counts["degraded"] += 1
                elif cur in ("DOWN", "OFFLINE", "CRITICAL"):
                    counts["down"] += 1
                else:
                    counts["unknown"] += 1
            session.commit()
        return counts
