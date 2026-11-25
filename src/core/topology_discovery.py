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
    NetworkSite,
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


def detect_local_network_context() -> Dict[str, str]:
    """Detect local IPv4, MAC, hostname, netmask, CIDR and default gateway safely without blocking."""
    gateway_ip = _detect_local_default_gateway()
    local_ip = ""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(0.8)
        sock.connect((gateway_ip or "8.8.8.8", 80))
        local_ip = str(sock.getsockname()[0] or "").strip()
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass

    if not local_ip:
        try:
            local_ip = str(socket.gethostbyname(socket.gethostname()) or "").strip()
        except Exception:
            local_ip = ""

    local_hostname = ""
    try:
        local_hostname = str(socket.gethostname() or "").strip()
    except Exception:
        local_hostname = ""

    netmask = ""
    local_mac = ""
    if _is_valid_probe_ip(local_ip):
        try:
            import psutil
            af_link = getattr(psutil, "AF_LINK", None)
            af_packet = getattr(socket, "AF_PACKET", None)
            for _nic, addrs in psutil.net_if_addrs().items():
                matched_ip = False
                nic_mask = ""
                nic_mac = ""
                for addr in addrs:
                    if addr.family == socket.AF_INET and str(addr.address or "").strip() == local_ip:
                        matched_ip = True
                        nic_mask = str(addr.netmask or "").strip()
                    elif addr.family in (af_link, af_packet):
                        nic_mac = normalize_mac(str(addr.address or ""))
                if matched_ip:
                    netmask = nic_mask
                    local_mac = nic_mac
                    break
        except Exception:
            pass

    if not netmask:
        netmask = "255.255.255.0"

    subnet_cidr = ""
    scan_cidr = ""
    if _is_valid_probe_ip(local_ip):
        try:
            net_obj = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
            subnet_cidr = str(net_obj)
            if net_obj.prefixlen < 24:
                scan_cidr = str(ipaddress.IPv4Network(f"{local_ip}/24", strict=False))
            else:
                scan_cidr = subnet_cidr
        except Exception:
            try:
                scan_cidr = str(ipaddress.IPv4Network(f"{local_ip}/24", strict=False))
                subnet_cidr = scan_cidr
            except Exception:
                subnet_cidr = ""
                scan_cidr = ""

    return {
        "local_ip": local_ip,
        "local_mac": local_mac,
        "local_hostname": local_hostname or local_ip,
        "gateway_ip": gateway_ip,
        "netmask": netmask,
        "subnet_cidr": subnet_cidr,
        "scan_cidr": scan_cidr,
    }


def _sweep_local_subnet(
    scan_cidr: str,
    probe_fn: Optional[Callable[[str], Tuple[str, Optional[float]]]] = None,
    timeout_sec: float = 0.35,
    max_workers: int = 48,
) -> Dict[str, Tuple[str, Optional[float]]]:
    """Perform a fast concurrent sweep of up to 254 hosts in scan_cidr, returning alive hosts."""
    if not scan_cidr:
        return {}
    try:
        net_obj = ipaddress.IPv4Network(scan_cidr, strict=False)
        ips = [str(ip) for ip in net_obj.hosts()][:254]
    except Exception:
        return {}
    if not ips:
        return {}

    alive: Dict[str, Tuple[str, Optional[float]]] = {}
    if probe_fn is not None:
        raw = _probe_hosts_concurrently(ips, probe_fn=probe_fn, max_workers=max_workers)
        return {ip: val for ip, val in raw.items() if val[0] in ("ONLINE", "DEGRADED")}

    multiping_ok = False
    try:
        import icmplib
        responses = icmplib.multiping(ips, count=1, timeout=timeout_sec, privileged=False)
        multiping_ok = True
        for resp in responses:
            if getattr(resp, "is_alive", False):
                lat = float(round(float(getattr(resp, "avg_rtt", 0.0)), 1))
                st = "DEGRADED" if lat >= 200.0 else "ONLINE"
                alive[str(resp.address)] = (st, lat)
    except Exception:
        multiping_ok = False

    if not multiping_ok or not alive:
        raw = _probe_hosts_concurrently(
            ips,
            probe_fn=lambda ip: probe_host_reachability(ip, timeout_sec=timeout_sec),
            max_workers=max_workers,
        )
        for ip, val in raw.items():
            if val[0] in ("ONLINE", "DEGRADED"):
                alive.setdefault(ip, val)
    return alive


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

    async def _collect_snmp_findings(
        self, snmp_rows: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], Set[str]]:
        """Walk SNMP MIB-II, LLDP, CDP, BRIDGE/Q-BRIDGE FDB, Routing and ARP across rows."""
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
            cdp = parse_cdp_neighbors(
                addr_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["cdpCacheAddress"], timeout, retries),
                dev_id_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["cdpCacheDeviceId"], timeout, retries),
                dev_port_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["cdpCacheDevicePort"], timeout, retries),
                platform_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["cdpCachePlatform"], timeout, retries),
                cap_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["cdpCacheCapabilities"], timeout, retries),
                version_rows=await _safe_walk(ip, port, creds, TOPO_OIDS["cdpCacheVersion"], timeout, retries),
                iface_name_map=if_name_map,
            )
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

        return per_device_findings, snmp_responsive_ips

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
        per_device_findings, snmp_responsive_ips = await self._collect_snmp_findings(snmp_rows)

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

    async def discover_live_local_network(
        self,
        active_sweep: bool = True,
        include_snmp: bool = True,
        local_context: Optional[Dict[str, str]] = None,
        arp_entries: Optional[List[Dict[str, str]]] = None,
        icmp_probe_fn: Optional[Callable[[str], Tuple[str, Optional[float]]]] = None,
        resolve_hostnames: bool = True,
    ) -> Dict[str, Any]:
        """Discover ONLY devices currently alive on the active local network without mutating SQLite."""
        from core.topology_graph import TopologyGraphService, resolve_status_color

        ctx = dict(local_context or detect_local_network_context())
        local_ip = str(ctx.get("local_ip") or "").strip()
        local_mac = normalize_mac(ctx.get("local_mac", ""))
        local_hostname = str(ctx.get("local_hostname") or "").strip() or local_ip
        gateway_ip = str(ctx.get("gateway_ip") or "").strip()
        subnet_cidr = str(ctx.get("subnet_cidr") or "").strip()
        scan_cidr = str(ctx.get("scan_cidr") or subnet_cidr).strip()

        local_net: Optional[ipaddress.IPv4Network] = None
        if subnet_cidr:
            try:
                local_net = ipaddress.IPv4Network(subnet_cidr, strict=False)
            except Exception:
                local_net = None

        def _ip_in_scope(ip: str) -> bool:
            clean = str(ip or "").strip()
            if not _is_valid_probe_ip(clean):
                return False
            if clean == gateway_ip or clean == local_ip:
                return True
            if local_net is not None:
                try:
                    ip_obj = ipaddress.IPv4Address(clean)
                    if ip_obj.is_multicast or ip_obj.is_unspecified or clean.endswith(".255"):
                        return False
                    return ip_obj in local_net
                except Exception:
                    return False
            return True

        live_probed: Dict[str, Tuple[str, Optional[float]]] = {}
        if active_sweep and scan_cidr:
            live_probed = _sweep_local_subnet(scan_cidr, probe_fn=icmp_probe_fn)

        raw_arp = list(arp_entries) if arp_entries is not None else read_local_arp_table()
        scoped_arp = [
            e for e in raw_arp
            if _ip_in_scope(e.get("ip", "")) or str(e.get("ip") or "").strip() in live_probed
        ]
        arp_by_ip: Dict[str, Dict[str, str]] = {e["ip"]: e for e in scoped_arp if e.get("ip")}
        arp_ip_by_mac: Dict[str, str] = {e["mac"]: e["ip"] for e in scoped_arp if e.get("mac") and e.get("ip")}

        extra_probe_ips = [ip for ip in list(arp_by_ip.keys()) + ([gateway_ip] if _is_valid_probe_ip(gateway_ip) else []) if ip not in live_probed]
        probe_status_map: Dict[str, Tuple[str, Optional[float]]] = dict(live_probed)
        if extra_probe_ips:
            probe_status_map.update(_probe_hosts_concurrently(extra_probe_ips, probe_fn=icmp_probe_fn))

        # Keep only currently reachable ARP endpoints (plus gateway/local host/live sweep hits)
        alive_arp_ips: Set[str] = set(live_probed.keys())
        for ip_k, (st_k, _lat_k) in probe_status_map.items():
            if st_k in ("ONLINE", "DEGRADED"):
                alive_arp_ips.add(ip_k)
        if _is_valid_probe_ip(local_ip):
            alive_arp_ips.add(local_ip)

        per_device_findings: List[Dict[str, Any]] = []
        snmp_responsive_ips: Set[str] = set()
        if include_snmp:
            snmp_rows = self.db.get_snmp_devices(enabled_only=True)
            cand_snmp = [
                r for r in snmp_rows
                if _ip_in_scope(r.get("ip_address", ""))
                or r.get("ip_address") in live_probed
                or r.get("ip_address") in alive_arp_ips
            ]
            if cand_snmp:
                all_findings, snmp_responsive_ips = await self._collect_snmp_findings(cand_snmp)
                per_device_findings = [
                    f for f in all_findings if f["snmp_row"]["ip_address"] in snmp_responsive_ips
                ]
                for finding in per_device_findings:
                    arp_ip_by_mac.update(finding["snmp_arp"])

        # Read-only DB lookup for inventory/site recognition & Host friendly labels
        inv_by_ip: Dict[str, Dict[str, Any]] = {}
        inv_by_mac: Dict[str, Dict[str, Any]] = {}
        host_label_by_ip: Dict[str, str] = {}
        with self.db.Session() as session:
            site_map = {s.id: s.name for s in session.query(NetworkSite).all()}
            for d in session.query(InfrastructureDevice).all():
                snap = {
                    "id": d.id,
                    "device_uid": d.device_uid,
                    "site_id": d.site_id,
                    "site_name": site_map.get(d.site_id, "Unassigned") if d.site_id else "Unassigned",
                    "hostname": d.hostname,
                    "management_ip": d.management_ip,
                    "mac_address": normalize_mac(d.mac_address or ""),
                    "vendor": d.vendor or "Unknown",
                    "model": d.model or "",
                    "category": d.category or "Other",
                    "role": d.role or "",
                }
                if d.management_ip:
                    inv_by_ip[d.management_ip] = snap
                if snap["mac_address"]:
                    inv_by_mac[snap["mac_address"]] = snap
            for h in session.query(Host).all():
                if h.address and h.label:
                    host_label_by_ip[h.address] = h.label

        nodes: List[Dict[str, Any]] = []
        node_by_id: Dict[int, Dict[str, Any]] = {}
        node_by_ip: Dict[str, Dict[str, Any]] = {}
        node_by_mac: Dict[str, Dict[str, Any]] = {}
        node_by_host: Dict[str, Dict[str, Any]] = {}
        used_ids: Set[int] = set()
        next_temp_id = -1
        next_edge_id = -1

        def _alloc_id(preferred: Optional[int]) -> int:
            nonlocal next_temp_id
            if preferred is not None and preferred > 0 and preferred not in used_ids:
                used_ids.add(preferred)
                return preferred
            while next_temp_id in used_ids:
                next_temp_id -= 1
            used_ids.add(next_temp_id)
            tid = next_temp_id
            next_temp_id -= 1
            return tid

        def _match_existing(clean_ip: str, clean_mac: str) -> Optional[Dict[str, Any]]:
            if clean_mac and clean_mac in inv_by_mac:
                return inv_by_mac[clean_mac]
            if clean_ip and clean_ip in inv_by_ip:
                cand = inv_by_ip[clean_ip]
                # Guard against false cross-site collision when two offices share 192.168.1.x with different MACs
                if clean_mac and cand["mac_address"] and clean_mac != cand["mac_address"]:
                    return None
                return cand
            return None

        def _upsert_live_node(
            ip: str = "",
            mac: str = "",
            hostname: str = "",
            vendor: str = "Unknown",
            category: str = "Other",
            role: str = "",
            model: str = "",
            discovery_source: str = "LIVE_SCAN",
            status: str = "UNKNOWN",
            latency_ms: Optional[float] = None,
            is_gateway: bool = False,
            is_local_host: bool = False,
        ) -> Dict[str, Any]:
            clean_ip = str(ip or "").strip()
            clean_mac = normalize_mac(mac)
            clean_host = str(hostname or "").strip()

            existing_node: Optional[Dict[str, Any]] = None
            if clean_ip and clean_ip in node_by_ip:
                existing_node = node_by_ip[clean_ip]
            elif clean_mac and clean_mac in node_by_mac:
                existing_node = node_by_mac[clean_mac]
            elif clean_host and clean_host in node_by_host:
                existing_node = node_by_host[clean_host]

            if existing_node is not None:
                if clean_ip and existing_node["management_ip"].startswith("UNKNOWN-IP-"):
                    existing_node["management_ip"] = clean_ip
                    node_by_ip[clean_ip] = existing_node
                if clean_mac and not existing_node["mac_address"]:
                    existing_node["mac_address"] = clean_mac
                    node_by_mac[clean_mac] = existing_node
                if clean_host and (not existing_node["hostname"] or existing_node["hostname"] == existing_node["management_ip"]):
                    existing_node["hostname"] = clean_host
                    node_by_host[clean_host] = existing_node
                if vendor != "Unknown" and existing_node["vendor"] == "Unknown":
                    existing_node["vendor"] = vendor
                if category != "Other" and existing_node["category"] == "Other":
                    existing_node["category"] = category
                if role and not existing_node["role"]:
                    existing_node["role"] = role
                if model and not existing_node["model"]:
                    existing_node["model"] = model
                if status in ("ONLINE", "DEGRADED", "UP"):
                    existing_node["status"] = status
                    existing_node["color"] = resolve_status_color(status)
                if latency_ms is not None and existing_node.get("latency_ms") is None:
                    existing_node["latency_ms"] = latency_ms
                if is_gateway:
                    existing_node["is_gateway"] = True
                if is_local_host:
                    existing_node["is_local_host"] = True
                return existing_node

            inv_rec = _match_existing(clean_ip, clean_mac)
            nid = _alloc_id(inv_rec["id"] if inv_rec else None)
            target_ip = clean_ip or f"UNKNOWN-IP-{clean_mac or abs(nid)}"
            target_host = clean_host or (inv_rec["hostname"] if inv_rec else "") or host_label_by_ip.get(clean_ip, "") or target_ip
            final_vendor = vendor if vendor != "Unknown" else (inv_rec["vendor"] if inv_rec else "Unknown")
            final_cat = category if category != "Other" else (inv_rec["category"] if inv_rec else "Other")
            if is_gateway and final_cat == "Other":
                final_cat = "Router"
            final_role = role or (inv_rec["role"] if inv_rec else "")
            final_model = model or (inv_rec["model"] if inv_rec else "")

            node = {
                "id": nid,
                "db_device_id": inv_rec["id"] if inv_rec else None,
                "device_uid": inv_rec["device_uid"] if inv_rec else f"LIVE-{abs(nid)}",
                "hostname": target_host,
                "management_ip": target_ip,
                "mac_address": clean_mac or (inv_rec["mac_address"] if inv_rec else ""),
                "vendor": final_vendor,
                "model": final_model,
                "category": final_cat,
                "role": final_role,
                "site_id": inv_rec["site_id"] if inv_rec else None,
                "site_name": inv_rec["site_name"] if inv_rec else "Unassigned",
                "status": str(status or "UNKNOWN").upper(),
                "color": resolve_status_color(status),
                "latency_ms": latency_ms,
                "connected_count": 0,
                "discovery_source": discovery_source,
                "already_in_inventory": inv_rec is not None,
                "is_gateway": is_gateway,
                "is_local_host": is_local_host,
            }
            nodes.append(node)
            node_by_id[nid] = node
            node_by_ip[target_ip] = node
            if node["mac_address"]:
                node_by_mac[node["mac_address"]] = node
            node_by_host[node["hostname"]] = node
            return node

        edges: List[Dict[str, Any]] = []
        edge_seen: Set[Tuple[int, int, str, str]] = set()

        def _add_live_edge(
            src_id: int,
            dst_id: int,
            src_if: str,
            dst_if: str,
            link_type: str,
            method: str,
            confidence: str,
            evidence: List[str],
            vlan_ids: Optional[List[int]] = None,
            status: str = "UP",
        ) -> None:
            nonlocal next_edge_id
            if src_id == dst_id or src_id not in node_by_id or dst_id not in node_by_id:
                return
            key = (min(src_id, dst_id), max(src_id, dst_id), method, str(src_if or ""))
            if key in edge_seen:
                return
            edge_seen.add(key)
            edges.append({
                "id": next_edge_id,
                "source_device_id": src_id,
                "dest_device_id": dst_id,
                "source_interface": src_if or "",
                "dest_interface": dst_if or "",
                "link_type": link_type,
                "discovery_method": method,
                "confidence": confidence,
                "status": status,
                "vlan_ids": list(vlan_ids or []),
                "evidence": list(evidence),
            })
            next_edge_id -= 1

        # 1. Default Gateway node (anchor root when present)
        gateway_node: Optional[Dict[str, Any]] = None
        if _is_valid_probe_ip(gateway_ip):
            gw_arp = arp_by_ip.get(gateway_ip, {})
            gw_mac = gw_arp.get("mac", "")
            gw_vendor, _unused_cat = classify_device_identity(mac=gw_mac)
            gw_st, gw_lat = probe_status_map.get(gateway_ip, ("UNKNOWN", None))
            if gw_st not in ("ONLINE", "DEGRADED") and (gateway_ip in arp_by_ip or gateway_ip in snmp_responsive_ips):
                gw_st = "ONLINE"
            gateway_node = _upsert_live_node(
                ip=gateway_ip,
                mac=gw_mac,
                hostname=host_label_by_ip.get(gateway_ip, "") or gateway_ip,
                vendor=gw_vendor,
                category="Router",
                role="Default Gateway",
                discovery_source="GATEWAY",
                status=gw_st,
                latency_ms=gw_lat,
                is_gateway=True,
            )

        # 2. Local workstation node
        if _is_valid_probe_ip(local_ip):
            loc_vendor, _unused_cat = classify_device_identity(mac=local_mac)
            _upsert_live_node(
                ip=local_ip,
                mac=local_mac,
                hostname=local_hostname,
                vendor=loc_vendor,
                category="Other",
                role="Local Station",
                discovery_source="LOCAL_HOST",
                status="ONLINE",
                latency_ms=0.0,
                is_gateway=(local_ip == gateway_ip),
                is_local_host=True,
            )

        # 3. Responsive SNMP devices & their LLDP/CDP/FDB/Routing links
        snmp_node_by_ip: Dict[str, Dict[str, Any]] = {}
        for finding in per_device_findings:
            srow = finding["snmp_row"]
            sip = srow["ip_address"]
            smac = arp_by_ip.get(sip, {}).get("mac", "")
            vendor, cat = classify_device_identity(
                mac=smac,
                sys_descr=srow.get("sys_descr", ""),
                sys_object_id=srow.get("sys_object_id", ""),
                existing_vendor=srow.get("vendor", ""),
            )
            if cat == "Other" and srow.get("device_type"):
                from core.inventory_manager import _norm_category
                cat = _norm_category(srow["device_type"])
            _st, slat = probe_status_map.get(sip, ("ONLINE", None))
            snmp_node_by_ip[sip] = _upsert_live_node(
                ip=sip,
                mac=smac,
                hostname=srow.get("sys_name") or srow.get("name") or sip,
                vendor=vendor,
                category=cat,
                model=srow.get("model", ""),
                discovery_source="SNMP_LIVE",
                status="ONLINE",
                latency_ms=slat,
                is_gateway=(sip == gateway_ip),
            )

        ports_with_direct_neighbor: Dict[Tuple[int, str], bool] = {}
        for finding in per_device_findings:
            src_node = snmp_node_by_ip[finding["snmp_row"]["ip_address"]]
            for nb in finding["neighbors"]:
                ports_with_direct_neighbor[(src_node["id"], nb.local_port)] = True
                n_vendor, n_cat = classify_device_identity(
                    mac=nb.remote_chassis_mac,
                    sys_descr=nb.remote_sys_descr,
                    cdp_caps=nb.capabilities_bits if nb.protocol == "CDP" else 0,
                    lldp_caps=nb.capabilities_bits if nb.protocol == "LLDP" else 0,
                )
                nb_ip = nb.remote_mgmt_ip or arp_ip_by_mac.get(nb.remote_chassis_mac, "")
                nb_st, nb_lat = probe_status_map.get(nb_ip, ("ONLINE" if nb_ip in snmp_responsive_ips else "UNKNOWN", None))
                dst_node = _upsert_live_node(
                    ip=nb_ip,
                    mac=nb.remote_chassis_mac,
                    hostname=nb.remote_sys_name or nb_ip,
                    vendor=n_vendor,
                    category=n_cat,
                    model=nb.remote_platform,
                    discovery_source=nb.protocol,
                    status=nb_st,
                    latency_ms=nb_lat,
                    is_gateway=(bool(nb_ip) and nb_ip == gateway_ip),
                )
                ltype = "PHYSICAL"
                if "Switch" in src_node["category"] and "Switch" in dst_node["category"]:
                    ltype = "UPLINK"
                elif dst_node["category"] == "Wireless Access Point":
                    ltype = "AP_UPLINK"
                _add_live_edge(
                    src_id=src_node["id"],
                    dst_id=dst_node["id"],
                    src_if=nb.local_port,
                    dst_if=nb.remote_port,
                    link_type=ltype,
                    method=nb.protocol,
                    confidence=nb.confidence,
                    evidence=[f"{nb.protocol}: {src_node['hostname']}:{nb.local_port} -> {dst_node['hostname']}:{nb.remote_port or '?'}"],
                )

        for finding in per_device_findings:
            src_node = snmp_node_by_ip[finding["snmp_row"]["ip_address"]]
            for hop in finding["routes"]:
                nh_ip = hop["next_hop_ip"]
                if nh_ip not in node_by_ip and nh_ip not in alive_arp_ips:
                    continue
                nh_st, nh_lat = probe_status_map.get(nh_ip, ("UNKNOWN", None))
                dst_node = _upsert_live_node(
                    ip=nh_ip,
                    mac=arp_by_ip.get(nh_ip, {}).get("mac", ""),
                    hostname=nh_ip,
                    category="Router",
                    discovery_source="ROUTING_TABLE",
                    status=nh_st,
                    latency_ms=nh_lat,
                    is_gateway=(nh_ip == gateway_ip),
                )
                _add_live_edge(
                    src_id=src_node["id"],
                    dst_id=dst_node["id"],
                    src_if=hop["local_interface"],
                    dst_if="",
                    link_type="LOGICAL",
                    method="ROUTING",
                    confidence="MEDIUM",
                    evidence=[f"Route next-hop {nh_ip} for {hop['dest_network']}"],
                )

        for finding in per_device_findings:
            src_node = snmp_node_by_ip[finding["snmp_row"]["ip_address"]]
            for pname, mac_entries in finding["mac_fdb"].items():
                if ports_with_direct_neighbor.get((src_node["id"], pname)) or not mac_entries:
                    continue
                parent_id = src_node["id"]
                parent_port = pname
                if len(mac_entries) >= 2:
                    unm_node = _upsert_live_node(
                        hostname=f"Unmanaged-Switch-{src_node['hostname']}-{pname}",
                        category="Access Switch",
                        role="Unmanaged Switch (Inferred)",
                        discovery_source="BRIDGE_FDB_INFERRED",
                        status="ONLINE",
                    )
                    _add_live_edge(
                        src_id=src_node["id"],
                        dst_id=unm_node["id"],
                        src_if=pname,
                        dst_if="Uplink",
                        link_type="PHYSICAL",
                        method="BRIDGE_FDB",
                        confidence="MEDIUM",
                        evidence=[f"{len(mac_entries)} downstream MACs learned on {src_node['hostname']}:{pname}"],
                    )
                    parent_id = unm_node["id"]
                    parent_port = "Access"

                for m_ent in mac_entries:
                    ep_mac = m_ent["mac"]
                    ep_ip = arp_ip_by_mac.get(ep_mac, "")
                    ep_vendor, ep_cat = classify_device_identity(mac=ep_mac)
                    ep_st, ep_lat = probe_status_map.get(ep_ip, ("UNKNOWN", None))
                    ep_node = _upsert_live_node(
                        ip=ep_ip,
                        mac=ep_mac,
                        hostname=ep_ip or f"Host-{ep_mac[-5:]}",
                        vendor=ep_vendor,
                        category=ep_cat,
                        discovery_source="BRIDGE_FDB",
                        status=ep_st,
                        latency_ms=ep_lat,
                    )
                    vlans = [int(m_ent["vlan"])] if str(m_ent.get("vlan", "")).isdigit() else []
                    _add_live_edge(
                        src_id=parent_id,
                        dst_id=ep_node["id"],
                        src_if=parent_port,
                        dst_if="eth0",
                        link_type="PHYSICAL",
                        method="BRIDGE_FDB",
                        confidence="MEDIUM" if ep_ip else "LOW",
                        evidence=[f"MAC {ep_mac} learned on {src_node['hostname']}:{pname}"],
                        vlan_ids=vlans,
                    )

        # 4. Active live hosts from subnet sweep & verified live ARP entries
        for ip_k in sorted(alive_arp_ips):
            if ip_k in node_by_ip:
                continue
            arp_ent = arp_by_ip.get(ip_k, {})
            ep_mac = arp_ent.get("mac", "")
            ep_vendor, ep_cat = classify_device_identity(mac=ep_mac)
            st_k, lat_k = probe_status_map.get(ip_k, ("ONLINE", None))
            _upsert_live_node(
                ip=ip_k,
                mac=ep_mac,
                hostname=host_label_by_ip.get(ip_k, "") or ip_k,
                vendor=ep_vendor,
                category=ep_cat,
                discovery_source="ARP_LIVE" if ip_k in arp_by_ip else "ICMP_SWEEP",
                status=st_k,
                latency_ms=lat_k,
                is_gateway=(ip_k == gateway_ip),
                is_local_host=(ip_k == local_ip),
            )

        # 5. Connect unattached live subnet components directly to the Default Gateway ("qui donne a qui")
        if gateway_node is not None and len(nodes) > 1:
            gw_id = gateway_node["id"]
            adj_map: Dict[int, Set[int]] = {n["id"]: set() for n in nodes}
            for e in edges:
                adj_map[e["source_device_id"]].add(e["dest_device_id"])
                adj_map[e["dest_device_id"]].add(e["source_device_id"])

            gw_comp: Set[int] = {gw_id}
            stack = [gw_id]
            while stack:
                cur = stack.pop()
                for nxt in adj_map.get(cur, ()):
                    if nxt not in gw_comp:
                        gw_comp.add(nxt)
                        stack.append(nxt)

            infra_prio = {
                "Firewall": 0,
                "Router": 0,
                "Core Switch": 1,
                "Wireless Controller": 1,
                "Distribution Switch": 2,
                "Access Switch": 3,
                "Wireless Access Point": 4,
                "Server": 5,
                "UPS": 6,
                "Printer": 6,
                "Other": 7,
            }
            visited_other: Set[int] = set(gw_comp)
            for n in list(nodes):
                nid = n["id"]
                if nid in visited_other:
                    continue
                comp: List[Dict[str, Any]] = []
                q = [nid]
                visited_other.add(nid)
                while q:
                    cid = q.pop()
                    comp.append(node_by_id[cid])
                    for nxt in adj_map.get(cid, ()):
                        if nxt not in visited_other:
                            visited_other.add(nxt)
                            q.append(nxt)
                comp.sort(
                    key=lambda item: (
                        infra_prio.get(item.get("category", "Other"), 7),
                        -len(adj_map.get(item["id"], ())),
                        item["id"],
                    )
                )
                root_item = comp[0]
                dst_if = "Uplink" if ("Switch" in root_item["category"] or "Access Point" in root_item["category"]) else "IP"
                _add_live_edge(
                    src_id=gw_id,
                    dst_id=root_item["id"],
                    src_if="LAN",
                    dst_if=dst_if,
                    link_type="GATEWAY_UPLINK",
                    method="GATEWAY_ARP",
                    confidence="MEDIUM",
                    evidence=[f"Default gateway {gateway_ip} serves local subnet {subnet_cidr or scan_cidr}"],
                    status="UP" if root_item["status"] in ("ONLINE", "DEGRADED", "UP") else "DEGRADED",
                )

        # 6. Reverse DNS hostname enrichment for live IP-bearing nodes still showing raw IP
        if resolve_hostnames:
            ips_needing_name = [
                n["management_ip"]
                for n in nodes
                if _is_valid_probe_ip(n["management_ip"])
                and n["management_ip"] != local_ip
                and (not n["hostname"] or n["hostname"] == n["management_ip"])
            ]
            if ips_needing_name:
                with ThreadPoolExecutor(max_workers=min(16, len(ips_needing_name))) as pool:
                    fmap = {pool.submit(_resolve_hostname_fast, ip): ip for ip in set(ips_needing_name)}
                    resolved_names: Dict[str, str] = {}
                    for fut, ip in fmap.items():
                        try:
                            rname = fut.result(timeout=1.5)
                            if rname:
                                resolved_names[ip] = rname
                        except Exception:
                            pass
                for n in nodes:
                    if (not n["hostname"] or n["hostname"] == n["management_ip"]) and n["management_ip"] in resolved_names:
                        n["hostname"] = resolved_names[n["management_ip"]]

        # 7. Orient hierarchy Upstream -> Downstream and finalize summary
        nodes, edges = TopologyGraphService.enrich_graph_hierarchy(
            nodes,
            edges,
            gateway_ips={gateway_ip} if gateway_ip else set(),
        )

        online_cnt = sum(1 for n in nodes if n["status"] in ("ONLINE", "UP", "OK"))
        deg_cnt = sum(1 for n in nodes if n["status"] in ("DEGRADED", "WARNING", "RECOVERING"))
        down_cnt = sum(1 for n in nodes if n["status"] in ("DOWN", "OFFLINE", "CRITICAL"))
        return {
            "mode": "LIVE",
            "context": ctx,
            "gateway_ip": gateway_ip,
            "subnet_cidr": subnet_cidr or scan_cidr,
            "nodes": nodes,
            "edges": edges,
            "summary": {
                "devices_discovered": len(nodes),
                "new_unassigned": sum(1 for n in nodes if not n.get("site_id")),
                "already_saved": sum(1 for n in nodes if n.get("site_id")),
                "online_devices": online_cnt,
                "degraded_devices": deg_cnt,
                "down_devices": down_cnt,
                "links_discovered": len(edges),
            },
        }
