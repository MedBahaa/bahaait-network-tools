from datetime import datetime
import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple
import uuid

from core.audit_logger import AuditLogger
from utils.db import (
    DatabaseManager,
    DeviceInterface,
    InfrastructureDevice,
    InfrastructureVlan,
    NetworkLink,
    NetworkSite,
)

SUPPORTED_VLAN_OPERATIONS = (
    "CREATE_VLAN",
    "RENAME_VLAN",
    "DELETE_VLAN",
    "ASSIGN_ACCESS_PORT",
    "SET_PORT_TAGGING",
    "REVIEW_TRUNK",
)

DESTRUCTIVE_VLAN_OPERATIONS = {"DELETE_VLAN"}
READ_ONLY_VLAN_OPERATIONS = {"REVIEW_TRUNK"}

_UNSAFE_CLI_RE = re.compile(r"[;\r\n|`$&><\\]")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.\- ]{1,32}$")
_SAFE_PORT_RE = re.compile(r"^[A-Za-z0-9_./:\-]{1,48}$")


def detect_vlan_vendor_profile(vendor: str = "", model: str = "", sys_descr: str = "") -> str:
    """Resolve explicit vendor CLI profile; never assumes Cisco syntax for other vendors."""
    blob = f"{vendor} {model} {sys_descr}".lower()
    if "ruckus" in blob or "brocade" in blob or "icx" in blob or "fastiron" in blob:
        return "ruckus_icx"
    if "fortinet" in blob or "fortigate" in blob or "fortiswitch" in blob or "fortios" in blob:
        return "fortinet_fortigate"
    if "cisco" in blob or "catalyst" in blob or "ios" in blob or "nexus" in blob:
        return "cisco_ios"
    return "unsupported"


def _expand_port_tokens(tokens_str: str) -> List[str]:
    ports: List[str] = []
    for raw in str(tokens_str or "").replace(",", " ").split():
        cleaned = raw.strip().rstrip(",")
        if cleaned and cleaned != "None":
            ports.append(cleaned)
    return list(dict.fromkeys(ports))


def parse_cisco_show_vlan(raw_output: str) -> List[Dict[str, Any]]:
    """Parse Cisco IOS/IOS-XE `show vlan brief` / `show vlan` output safely."""
    vlans: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    in_trunk_section = False

    for line in str(raw_output or "").splitlines():
        low = line.strip().lower()
        if not line.strip() or set(line.strip()) <= {"-"}:
            continue
        if "port" in low and "vlans allowed on trunk" in low:
            in_trunk_section = True
            continue
        if in_trunk_section:
            m_tr = re.match(r"^\s*(\S+)\s+([0-9,\-]+)\s*$", line)
            if m_tr:
                p_name, vranges = m_tr.group(1), m_tr.group(2)
                for chunk in vranges.split(","):
                    if "-" in chunk:
                        a, b = chunk.split("-", 1)
                        if a.isdigit() and b.isdigit():
                            for vid in range(int(a), min(int(b), int(a) + 4094) + 1):
                                for v in vlans:
                                    if v["vlan_number"] == vid and p_name not in v["trunk_ports"]:
                                        v["trunk_ports"].append(p_name)
                    elif chunk.isdigit():
                        vid = int(chunk)
                        for v in vlans:
                            if v["vlan_number"] == vid and p_name not in v["trunk_ports"]:
                                v["trunk_ports"].append(p_name)
            continue

        m = re.match(r"^(\d{1,4})\s+(\S+)\s+(active|act/unsup|suspend|suspended|shut)\s*(.*)$", line, re.IGNORECASE)
        if m:
            vid = int(m.group(1))
            if not (1 <= vid <= 4094):
                continue
            current = {
                "vlan_number": vid,
                "vlan_name": m.group(2).strip(),
                "status": "ACTIVE" if "act" in m.group(3).lower() else m.group(3).upper(),
                "untagged_ports": _expand_port_tokens(m.group(4)),
                "tagged_ports": [],
                "trunk_ports": [],
                "discovery_source": "SSH_CISCO_CLI",
            }
            vlans.append(current)
        elif current is not None and re.match(r"^\s{12,}[A-Za-z]", line) and "enet" not in low:
            # Continuation line of port list
            extra = _expand_port_tokens(line)
            for p in extra:
                if p not in current["untagged_ports"]:
                    current["untagged_ports"].append(p)
        else:
            current = None
    return vlans


def parse_ruckus_show_vlan(raw_output: str) -> List[Dict[str, Any]]:
    """Parse Ruckus FastIron/ICX `show vlan` output safely."""
    vlans: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None

    for line in str(raw_output or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        m_hdr = re.match(
            r"^(?:PORT-VLAN|VLAN)\s+(\d{1,4})(?:,\s*Name\s+([^,]+))?",
            stripped,
            re.IGNORECASE,
        )
        if m_hdr:
            vid = int(m_hdr.group(1))
            vname = (m_hdr.group(2) or f"VLAN{vid}").strip().strip('"').replace("[None]", f"VLAN{vid}")
            current = {
                "vlan_number": vid,
                "vlan_name": vname,
                "status": "ACTIVE",
                "untagged_ports": [],
                "tagged_ports": [],
                "trunk_ports": [],
                "discovery_source": "SSH_RUCKUS_CLI",
            }
            vlans.append(current)
            continue

        if current is None:
            continue

        if stripped.lower().startswith("untagged ports"):
            after = stripped.split(":", 1)[-1]
            for m_tok in re.findall(r"ethe\s+(\S+)|\b(\d+/\d+/\d+)\b", after, re.IGNORECASE):
                p = (m_tok[0] or m_tok[1]).strip()
                if p and p not in current["untagged_ports"]:
                    current["untagged_ports"].append(p)
        elif stripped.lower().startswith("tagged ports"):
            after = stripped.split(":", 1)[-1]
            for m_tok in re.findall(r"ethe\s+(\S+)|\b(\d+/\d+/\d+)\b", after, re.IGNORECASE):
                p = (m_tok[0] or m_tok[1]).strip()
                if p and p not in current["tagged_ports"]:
                    current["tagged_ports"].append(p)
                    if p not in current["trunk_ports"]:
                        current["trunk_ports"].append(p)
    return vlans


def parse_fortigate_vlan(raw_output: str) -> List[Dict[str, Any]]:
    """Parse FortiGate `show system interface` / `get system interface` VLAN blocks."""
    vlans: List[Dict[str, Any]] = []
    block_name = ""
    vlan_id: Optional[int] = None
    parent_if = ""
    alias = ""
    status = "ACTIVE"

    def _flush() -> None:
        nonlocal block_name, vlan_id, parent_if, alias, status
        if vlan_id is not None and 1 <= vlan_id <= 4094:
            vlans.append({
                "vlan_number": vlan_id,
                "vlan_name": alias or block_name or f"VLAN{vlan_id}",
                "status": status,
                "untagged_ports": [],
                "tagged_ports": [parent_if] if parent_if else [],
                "trunk_ports": [parent_if] if parent_if else [],
                "discovery_source": "SSH_FORTIGATE_CLI",
            })
        block_name = ""
        vlan_id = None
        parent_if = ""
        alias = ""
        status = "ACTIVE"

    for line in str(raw_output or "").splitlines():
        s = line.strip()
        if s.startswith("edit "):
            _flush()
            block_name = s[5:].strip().strip('"')
        elif s.startswith("set vlanid "):
            try:
                vlan_id = int(s.split()[-1])
            except ValueError:
                vlan_id = None
        elif s.startswith("set interface "):
            parent_if = s[len("set interface "):].strip().strip('"')
        elif s.startswith("set alias "):
            alias = s[len("set alias "):].strip().strip('"')
        elif s.startswith("set status "):
            st = s.split()[-1].strip().lower()
            status = "INACTIVE" if st == "down" else "ACTIVE"
        elif s == "next":
            _flush()
    _flush()
    return vlans


def _validate_vlan_id(vlan_id: Any) -> int:
    try:
        vid = int(vlan_id)
    except (TypeError, ValueError):
        raise ValueError("VLAN ID must be an integer between 1 and 4094.")
    if not (1 <= vid <= 4094):
        raise ValueError(f"Invalid IEEE 802.1Q VLAN ID {vid}: must be in 1..4094.")
    return vid


def _validate_safe_text(val: str, pattern: re.Pattern, label: str) -> str:
    txt = str(val or "").strip()
    if not txt:
        raise ValueError(f"{label} is required.")
    if _UNSAFE_CLI_RE.search(txt) or not pattern.match(txt):
        raise ValueError(f"Invalid characters in {label}: '{txt}'.")
    return txt


class VLANManager:
    """Enterprise multi-vendor VLAN discovery, consistency analyzer, and confirmed change engine."""

    def __init__(self, db: DatabaseManager, audit_logger: Optional[AuditLogger] = None) -> None:
        self.db = db
        self.audit = audit_logger or AuditLogger(db)

    def sync_from_snmp(self, device_id: Optional[int] = None) -> Dict[str, int]:
        """Synchronize SNMP-collected VLAN snapshots (`snmp_vlans`) into `infrastructure_vlans`."""
        synced_vlans = 0
        devices_checked = 0
        with self.db.Session() as session:
            q = session.query(InfrastructureDevice).filter(InfrastructureDevice.snmp_device_id.isnot(None))
            if device_id is not None:
                q = q.filter(InfrastructureDevice.id == int(device_id))
            devs = q.all()

        for dev in devs:
            if dev.snmp_device_id is None:
                continue
            devices_checked += 1
            snmp_vlans = self.db.get_snmp_vlans(dev.snmp_device_id)
            if not snmp_vlans:
                continue
            normalized = [
                {
                    "vlan_number": int(v["vlan_id"]),
                    "vlan_name": v.get("name") or f"VLAN{v['vlan_id']}",
                    "status": v.get("status", "ACTIVE"),
                    "tagged_ports": v.get("tagged_ports", []),
                    "untagged_ports": v.get("untagged_ports", []),
                    "trunk_ports": v.get("trunk_ports", []),
                    "discovery_source": "SNMP_QBRIDGE",
                }
                for v in snmp_vlans
            ]
            synced_vlans += self._upsert_device_vlans(dev.id, normalized, site_id=dev.site_id)
        return {"devices_checked": devices_checked, "vlans_synced": synced_vlans}

    def _upsert_device_vlans(
        self,
        device_id: int,
        vlan_dicts: List[Dict[str, Any]],
        site_id: Optional[int] = None,
    ) -> int:
        now = datetime.utcnow()
        count = 0
        with self.db.Session() as session:
            dev = session.query(InfrastructureDevice).filter_by(id=device_id).first()
            if not dev:
                raise ValueError(f"Infrastructure device {device_id} not found.")
            eff_site_id = site_id if site_id is not None else dev.site_id

            for vd in vlan_dicts:
                vid = _validate_vlan_id(vd["vlan_number"])
                row = session.query(InfrastructureVlan).filter_by(device_id=device_id, vlan_number=vid).first()
                tagged = list(dict.fromkeys(vd.get("tagged_ports", [])))
                untagged = list(dict.fromkeys(vd.get("untagged_ports", [])))
                trunks = list(dict.fromkeys(vd.get("trunk_ports", [])))
                if row is None:
                    row = InfrastructureVlan(
                        device_id=device_id,
                        site_id=eff_site_id,
                        vlan_number=vid,
                        vlan_name=str(vd.get("vlan_name") or f"VLAN{vid}"),
                        status=str(vd.get("status") or "ACTIVE"),
                        tagged_ports_json=json.dumps(tagged),
                        untagged_ports_json=json.dumps(untagged),
                        trunk_ports_json=json.dumps(trunks),
                        discovery_source=str(vd.get("discovery_source") or "SNMP"),
                        last_discovery=now,
                    )
                    session.add(row)
                else:
                    row.site_id = eff_site_id
                    row.vlan_name = str(vd.get("vlan_name") or row.vlan_name)
                    row.status = str(vd.get("status") or row.status)
                    row.tagged_ports_json = json.dumps(tagged)
                    row.untagged_ports_json = json.dumps(untagged)
                    row.trunk_ports_json = json.dumps(trunks)
                    row.discovery_source = str(vd.get("discovery_source") or row.discovery_source)
                    row.last_discovery = now

                # Mirror port-to-VLAN assignment onto device_interfaces when known
                for pname in untagged:
                    if_row = session.query(DeviceInterface).filter_by(device_id=device_id, name=pname).first()
                    if if_row:
                        if_row.port_mode = "ACCESS"
                        if_row.access_vlan = vid
                for pname in set(tagged) | set(trunks):
                    if_row = session.query(DeviceInterface).filter_by(device_id=device_id, name=pname).first()
                    if if_row:
                        if_row.port_mode = "TRUNK"
                        cur_tv = json.loads(if_row.tagged_vlans_json or "[]")
                        if vid not in cur_tv:
                            cur_tv.append(vid)
                            if_row.tagged_vlans_json = json.dumps(sorted(cur_tv))
                count += 1
            session.commit()
        return count

    def import_cli_vlans(
        self,
        device_id: int,
        raw_output: str,
        vendor_profile: Optional[str] = None,
        persist: bool = True,
    ) -> List[Dict[str, Any]]:
        """Parse vendor CLI VLAN output using the appropriate parser and optionally persist."""
        with self.db.Session() as session:
            dev = session.query(InfrastructureDevice).filter_by(id=device_id).first()
            if not dev:
                raise ValueError(f"Infrastructure device {device_id} not found.")
            prof = vendor_profile or detect_vlan_vendor_profile(dev.vendor, dev.model, dev.role)
            site_id = dev.site_id

        if prof == "cisco_ios":
            parsed = parse_cisco_show_vlan(raw_output)
        elif prof == "ruckus_icx":
            parsed = parse_ruckus_show_vlan(raw_output)
        elif prof == "fortinet_fortigate":
            parsed = parse_fortigate_vlan(raw_output)
        else:
            raise ValueError(f"Unsupported vendor CLI profile for VLAN parsing: {prof}")

        if persist and parsed:
            self._upsert_device_vlans(device_id, parsed, site_id=site_id)
        return parsed

    def list_vlans(
        self,
        site_id: Optional[int] = None,
        device_id: Optional[int] = None,
        vlan_number: Optional[int] = None,
        search: str = "",
    ) -> List[Dict[str, Any]]:
        with self.db.Session() as session:
            site_map = {s.id: s.name for s in session.query(NetworkSite).all()}
            dev_map = {d.id: d for d in session.query(InfrastructureDevice).all()}
            q = session.query(InfrastructureVlan)
            if site_id is not None:
                q = q.filter(InfrastructureVlan.site_id == int(site_id))
            if device_id is not None:
                q = q.filter(InfrastructureVlan.device_id == int(device_id))
            if vlan_number is not None:
                q = q.filter(InfrastructureVlan.vlan_number == int(vlan_number))
            rows = q.order_by(InfrastructureVlan.vlan_number.asc(), InfrastructureVlan.device_id.asc()).all()

            term = str(search or "").strip().lower()
            out: List[Dict[str, Any]] = []
            for r in rows:
                d = dev_map.get(r.device_id)
                hostname = d.hostname if d else str(r.device_id)
                vendor = d.vendor if d else ""
                sname = site_map.get(r.site_id, "Unassigned") if r.site_id else "Unassigned"
                if term and not (
                    term in str(r.vlan_number)
                    or term in (r.vlan_name or "").lower()
                    or term in hostname.lower()
                    or term in sname.lower()
                ):
                    continue
                out.append({
                    "id": r.id,
                    "device_id": r.device_id,
                    "device_hostname": hostname,
                    "device_ip": d.management_ip if d else "",
                    "vendor": vendor,
                    "site_id": r.site_id,
                    "site_name": sname,
                    "vlan_number": r.vlan_number,
                    "vlan_name": r.vlan_name or f"VLAN{r.vlan_number}",
                    "status": r.status or "ACTIVE",
                    "untagged_ports": json.loads(r.untagged_ports_json or "[]"),
                    "tagged_ports": json.loads(r.tagged_ports_json or "[]"),
                    "trunk_ports": json.loads(r.trunk_ports_json or "[]"),
                    "discovery_source": r.discovery_source or "SNMP",
                    "last_discovery": r.last_discovery,
                })
            return out

    def detect_inconsistencies(self, site_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Detect real multi-switch VLAN inconsistencies (name mismatches & trunk/uplink VLAN gaps)."""
        vlans = self.list_vlans(site_id=site_id)
        warnings: List[Dict[str, Any]] = []

        # 1. Name mismatches across devices within the same site (or global when site_id is None)
        by_scope_vlan: Dict[Tuple[Optional[int], int], List[Dict[str, Any]]] = {}
        dev_vlans_map: Dict[int, Dict[int, Dict[str, Any]]] = {}
        for v in vlans:
            by_scope_vlan.setdefault((v["site_id"], v["vlan_number"]), []).append(v)
            dev_vlans_map.setdefault(v["device_id"], {})[v["vlan_number"]] = v
            if str(v["status"]).upper() not in ("ACTIVE", "UP") and (v["untagged_ports"] or v["tagged_ports"]):
                warnings.append({
                    "severity": "WARNING",
                    "kind": "INACTIVE_WITH_PORTS",
                    "vlan_number": v["vlan_number"],
                    "site_id": v["site_id"],
                    "site_name": v["site_name"],
                    "devices": [v["device_hostname"]],
                    "detail": (
                        f"VLAN {v['vlan_number']} ({v['vlan_name']}) is {v['status']} on {v['device_hostname']} "
                        f"but still has {len(v['untagged_ports']) + len(v['tagged_ports'])} assigned port(s)."
                    ),
                    "remediation": "Reassign active ports or activate the VLAN before decommissioning.",
                })

        for (sid, vid), entries in sorted(by_scope_vlan.items()):
            distinct_names = sorted({e["vlan_name"].strip() for e in entries if e["vlan_name"].strip()})
            if len(distinct_names) > 1:
                warnings.append({
                    "severity": "WARNING",
                    "kind": "NAME_MISMATCH",
                    "vlan_number": vid,
                    "site_id": sid,
                    "site_name": entries[0]["site_name"],
                    "devices": [e["device_hostname"] for e in entries],
                    "detail": (
                        f"VLAN {vid} has inconsistent names on {entries[0]['site_name']}: "
                        + ", ".join(f"{e['device_hostname']}='{e['vlan_name']}'" for e in entries)
                    ),
                    "remediation": "Standardize VLAN name across all switches sharing this L2 domain.",
                })

        # 2. Switch-to-switch UPLINK/TRUNK VLAN gap checks
        with self.db.Session() as session:
            dev_rows = {d.id: d for d in session.query(InfrastructureDevice).all()}
            links = session.query(NetworkLink).filter(NetworkLink.link_type.in_(["UPLINK", "TRUNK", "PHYSICAL"])).all()

        for lk in links:
            sdev = dev_rows.get(lk.source_device_id)
            ddev = dev_rows.get(lk.dest_device_id)
            if not sdev or not ddev:
                continue
            if "Switch" not in (sdev.category or "") or "Switch" not in (ddev.category or ""):
                continue
            if site_id is not None and sdev.site_id != int(site_id) and ddev.site_id != int(site_id):
                continue

            sv = dev_vlans_map.get(sdev.id, {})
            dv = dev_vlans_map.get(ddev.id, {})
            link_vids = set(json.loads(lk.vlan_ids_json or "[]"))

            # If a VLAN exists on source & carries over link (or on switch pair where link_vids lists it)
            for vid in sorted(link_vids):
                in_s = vid in sv
                in_d = vid in dv
                if in_s != in_d:
                    missing_dev = ddev.hostname if in_s else sdev.hostname
                    present_dev = sdev.hostname if in_s else ddev.hostname
                    warnings.append({
                        "severity": "CRITICAL",
                        "kind": "TRUNK_VLAN_GAP",
                        "vlan_number": vid,
                        "site_id": sdev.site_id,
                        "site_name": "",
                        "devices": [present_dev, missing_dev],
                        "detail": (
                            f"Trunk {sdev.hostname}:{lk.source_interface} <-> {ddev.hostname}:{lk.dest_interface} "
                            f"expects VLAN {vid}, present on {present_dev} but missing on {missing_dev}."
                        ),
                        "remediation": f"Create/allow VLAN {vid} on {missing_dev} or remove from trunk if unintended.",
                    })

        return warnings

    def get_vlan_summary_matrix(self, site_id: Optional[int] = None) -> List[Dict[str, Any]]:
        vlans = self.list_vlans(site_id=site_id)
        inconsistencies = self.detect_inconsistencies(site_id=site_id)
        warn_by_vid: Dict[int, List[Dict[str, Any]]] = {}
        for w in inconsistencies:
            warn_by_vid.setdefault(int(w["vlan_number"]), []).append(w)

        grouped: Dict[int, Dict[str, Any]] = {}
        for v in vlans:
            vid = int(v["vlan_number"])
            g = grouped.setdefault(
                vid,
                {
                    "vlan_number": vid,
                    "names": set(),
                    "devices": [],
                    "sites": set(),
                    "untagged_count": 0,
                    "tagged_count": 0,
                    "trunk_count": 0,
                },
            )
            g["names"].add(v["vlan_name"])
            g["devices"].append(v["device_hostname"])
            g["sites"].add(v["site_name"])
            g["untagged_count"] += len(v["untagged_ports"])
            g["tagged_count"] += len(v["tagged_ports"])
            g["trunk_count"] += len(v["trunk_ports"])

        matrix: List[Dict[str, Any]] = []
        for vid, g in sorted(grouped.items()):
            wlist = warn_by_vid.get(vid, [])
            matrix.append({
                "vlan_number": vid,
                "names": sorted(g["names"]),
                "device_count": len(set(g["devices"])),
                "devices": sorted(set(g["devices"])),
                "sites": sorted(g["sites"]),
                "untagged_count": g["untagged_count"],
                "tagged_count": g["tagged_count"],
                "trunk_count": g["trunk_count"],
                "warnings": wlist,
                "has_inconsistency": len(wlist) > 0,
            })
        return matrix

    def build_change_plan(
        self,
        device_id: int,
        operation: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate an explicit vendor-specific VLAN CLI preview without applying anything."""
        op = str(operation or "").upper().strip()
        if op not in SUPPORTED_VLAN_OPERATIONS:
            raise ValueError(f"Unsupported VLAN operation '{op}'. Supported: {SUPPORTED_VLAN_OPERATIONS}")
        p = dict(params or {})

        with self.db.Session() as session:
            dev = session.query(InfrastructureDevice).filter_by(id=int(device_id)).first()
            if not dev:
                raise ValueError(f"Infrastructure device {device_id} not found.")
            hostname = dev.hostname
            mgmt_ip = dev.management_ip
            site_id = dev.site_id
            vendor_prof = detect_vlan_vendor_profile(dev.vendor, dev.model, dev.role)

        if vendor_prof == "unsupported":
            raise ValueError(
                f"Device '{hostname}' ({dev.vendor or 'Unknown'}) has no verified VLAN CLI profile; "
                "cannot assume CLI command compatibility."
            )

        vid = _validate_vlan_id(p.get("vlan_id"))
        warnings: List[str] = []
        commands: List[str] = []
        risk_tier = "MODIFYING"

        if op in READ_ONLY_VLAN_OPERATIONS:
            risk_tier = "READ_ONLY"

        if op in DESTRUCTIVE_VLAN_OPERATIONS:
            risk_tier = "DESTRUCTIVE"
            if vid == 1:
                raise ValueError("Deleting default native VLAN 1 is prohibited.")

        if op in ("CREATE_VLAN", "RENAME_VLAN"):
            vname = _validate_safe_text(p.get("vlan_name", ""), _SAFE_NAME_RE, "VLAN name")
        else:
            vname = str(p.get("vlan_name") or "").strip()

        port = ""
        if op in ("ASSIGN_ACCESS_PORT", "SET_PORT_TAGGING"):
            port = _validate_safe_text(p.get("port", ""), _SAFE_PORT_RE, "Interface/Port")

        if vendor_prof == "cisco_ios":
            if op == "CREATE_VLAN" or op == "RENAME_VLAN":
                commands = ["configure terminal", f"vlan {vid}", f"name {vname}", "exit", "end"]
            elif op == "DELETE_VLAN":
                commands = ["configure terminal", f"no vlan {vid}", "end"]
                warnings.append("Ports still assigned to this VLAN may become inactive until reassigned.")
            elif op == "ASSIGN_ACCESS_PORT":
                commands = [
                    "configure terminal",
                    f"interface {port}",
                    "switchport mode access",
                    f"switchport access vlan {vid}",
                    "end",
                ]
            elif op == "SET_PORT_TAGGING":
                tagged_mode = str(p.get("tag_action", "add")).lower()
                if tagged_mode not in ("add", "remove"):
                    raise ValueError("tag_action must be 'add' or 'remove'.")
                commands = [
                    "configure terminal",
                    f"interface {port}",
                    "switchport mode trunk",
                    f"switchport trunk allowed vlan {tagged_mode} {vid}",
                    "end",
                ]
            elif op == "REVIEW_TRUNK":
                commands = ["show interfaces trunk", f"show vlan id {vid}"]

        elif vendor_prof == "ruckus_icx":
            if op in ("CREATE_VLAN", "RENAME_VLAN"):
                commands = ["configure terminal", f"vlan {vid} name {vname}", "end"]
            elif op == "DELETE_VLAN":
                commands = ["configure terminal", f"no vlan {vid}", "end"]
                warnings.append("Ruckus ICX requires ports to be untagged elsewhere before removing VLAN if still bound.")
            elif op == "ASSIGN_ACCESS_PORT":
                commands = ["configure terminal", f"vlan {vid}", f"untagged ethernet {port}", "end"]
            elif op == "SET_PORT_TAGGING":
                tagged_mode = str(p.get("tag_action", "add")).lower()
                if tagged_mode not in ("add", "remove"):
                    raise ValueError("tag_action must be 'add' or 'remove'.")
                cmd_verb = "tagged" if tagged_mode == "add" else "no tagged"
                commands = ["configure terminal", f"vlan {vid}", f"{cmd_verb} ethernet {port}", "end"]
            elif op == "REVIEW_TRUNK":
                commands = [f"show vlan {vid}", "show interfaces brief"]

        elif vendor_prof == "fortinet_fortigate":
            if op == "CREATE_VLAN":
                parent_if = _validate_safe_text(p.get("parent_interface", "port1"), _SAFE_PORT_RE, "Parent interface")
                if_name = _validate_safe_text(p.get("vlan_name", f"vlan{vid}"), _SAFE_NAME_RE, "Interface name").replace(" ", "_")
                commands = [
                    "config system interface",
                    f'edit "{if_name}"',
                    f'set interface "{parent_if}"',
                    f"set vlanid {vid}",
                    "next",
                    "end",
                ]
            elif op == "RENAME_VLAN":
                if_name = _validate_safe_text(p.get("interface_name") or vname, _SAFE_NAME_RE, "Interface name")
                commands = [
                    "config system interface",
                    f'edit "{if_name}"',
                    f'set alias "{vname}"',
                    "next",
                    "end",
                ]
            elif op == "DELETE_VLAN":
                if_name = _validate_safe_text(p.get("interface_name") or f"vlan{vid}", _SAFE_NAME_RE, "Interface name")
                commands = ["config system interface", f'delete "{if_name}"', "end"]
                warnings.append("FortiGate requires no firewall policies or DHCP scopes reference this VLAN interface before deletion.")
            elif op == "ASSIGN_ACCESS_PORT":
                sw_if = _validate_safe_text(p.get("switch_id", "fortiswitch"), _SAFE_PORT_RE, "FortiSwitch ID")
                commands = [
                    "config switch-controller managed-switch",
                    f'edit "{sw_if}"',
                    "config ports",
                    f'edit "{port}"',
                    f'set vlan "vlan{vid}"',
                    "next",
                    "end",
                    "next",
                    "end",
                ]
                warnings.append("FortiLink managed-switch profile syntax; verify VDOM context before apply.")
            elif op == "SET_PORT_TAGGING":
                sw_if = _validate_safe_text(p.get("switch_id", "fortiswitch"), _SAFE_PORT_RE, "FortiSwitch ID")
                tagged_mode = str(p.get("tag_action", "add")).lower()
                verb = "append" if tagged_mode == "add" else "unselect"
                commands = [
                    "config switch-controller managed-switch",
                    f'edit "{sw_if}"',
                    "config ports",
                    f'edit "{port}"',
                    f'{verb} allowed-vlans "vlan{vid}"',
                    "next",
                    "end",
                    "next",
                    "end",
                ]
            elif op == "REVIEW_TRUNK":
                commands = ["get system interface", "show system interface"]

        return {
            "plan_uid": f"VLAN-{uuid.uuid4().hex[:10].upper()}",
            "device_id": int(device_id),
            "device_hostname": hostname,
            "device_ip": mgmt_ip,
            "site_id": site_id,
            "vendor_profile": vendor_prof,
            "operation": op,
            "params": {**p, "vlan_id": vid, "vlan_name": vname, "port": port},
            "risk_tier": risk_tier,
            "warnings": warnings,
            "commands": commands,
            "requires_confirmation": risk_tier != "READ_ONLY",
        }

    def apply_change_plan(
        self,
        plan: Dict[str, Any],
        *,
        confirmed: bool = False,
        executor: Optional[Callable[[Dict[str, Any], List[str]], Tuple[bool, str]]] = None,
        pre_backup_fn: Optional[Callable[[int], Optional[Dict[str, Any]]]] = None,
        dry_run: bool = False,
        ticket_ref: str = "",
    ) -> Dict[str, Any]:
        """Execute a generated VLAN plan ONLY after explicit confirmation (unless READ_ONLY)."""
        op = str(plan.get("operation") or "").upper()
        risk = str(plan.get("risk_tier") or "MODIFYING").upper()
        device_id = int(plan["device_id"])
        hostname = str(plan.get("device_hostname") or "")
        ip = str(plan.get("device_ip") or "")
        commands = list(plan.get("commands") or [])

        if risk != "READ_ONLY" and not confirmed:
            self.audit.record_event(
                operation=f"VLAN_{op}",
                result="BLOCKED",
                device_id=device_id,
                device_name=hostname,
                device_ip=ip,
                site_id=plan.get("site_id"),
                command_tier=risk,
                new_value="\n".join(commands),
                ticket_ref=ticket_ref,
                detail="Execution refused: explicit operator confirmation not provided.",
            )
            raise PermissionError(
                f"VLAN operation '{op}' ({risk}) requires explicit confirmation before execution."
            )

        if dry_run:
            self.audit.record_event(
                operation=f"VLAN_{op}_PREVIEW",
                result="SUCCESS",
                device_id=device_id,
                device_name=hostname,
                device_ip=ip,
                site_id=plan.get("site_id"),
                command_tier="READ_ONLY",
                new_value="\n".join(commands),
                ticket_ref=ticket_ref,
                detail="Dry-run preview only; no device state modified.",
            )
            return {"status": "DRY_RUN", "executed": False, "commands": commands, "output": "Dry-run preview."}

        backup_info = None
        if risk != "READ_ONLY" and pre_backup_fn is not None:
            backup_info = pre_backup_fn(device_id)

        if executor is None:
            raise ValueError(
                "No SSH/API execution session supplied. Connect or supply a verified executor callback."
            )

        ok, output = executor(plan, commands)
        result_tag = "SUCCESS" if ok else "FAILURE"

        if ok and risk != "READ_ONLY":
            self._reflect_plan_in_db(plan)

        self.audit.record_event(
            operation=f"VLAN_{op}",
            result=result_tag,
            device_id=device_id,
            device_name=hostname,
            device_ip=ip,
            site_id=plan.get("site_id"),
            command_tier=risk,
            new_value="\n".join(commands),
            ticket_ref=ticket_ref,
            detail=f"Profile={plan.get('vendor_profile')} | Output={str(output)[:400]}",
        )
        return {
            "status": result_tag,
            "executed": True,
            "pre_backup": backup_info,
            "commands": commands,
            "output": output,
        }

    def _reflect_plan_in_db(self, plan: Dict[str, Any]) -> None:
        op = plan["operation"]
        p = plan.get("params") or {}
        vid = int(p["vlan_id"])
        dev_id = int(plan["device_id"])
        with self.db.Session() as session:
            row = session.query(InfrastructureVlan).filter_by(device_id=dev_id, vlan_number=vid).first()
            if op == "CREATE_VLAN":
                if row is None:
                    session.add(
                        InfrastructureVlan(
                            device_id=dev_id,
                            site_id=plan.get("site_id"),
                            vlan_number=vid,
                            vlan_name=p.get("vlan_name") or f"VLAN{vid}",
                            status="ACTIVE",
                            discovery_source="VLAN_MANAGER",
                            last_discovery=datetime.utcnow(),
                        )
                    )
            elif op == "RENAME_VLAN" and row is not None:
                row.vlan_name = p.get("vlan_name") or row.vlan_name
            elif op == "DELETE_VLAN" and row is not None:
                session.delete(row)
            elif op == "ASSIGN_ACCESS_PORT":
                port = p.get("port")
                if row is None:
                    row = InfrastructureVlan(
                        device_id=dev_id,
                        site_id=plan.get("site_id"),
                        vlan_number=vid,
                        vlan_name=f"VLAN{vid}",
                        status="ACTIVE",
                        untagged_ports_json=json.dumps([port] if port else []),
                        discovery_source="VLAN_MANAGER",
                    )
                    session.add(row)
                elif port:
                    cur = json.loads(row.untagged_ports_json or "[]")
                    if port not in cur:
                        cur.append(port)
                        row.untagged_ports_json = json.dumps(cur)
            elif op == "SET_PORT_TAGGING":
                port = p.get("port")
                action = str(p.get("tag_action", "add")).lower()
                if row is not None and port:
                    cur = json.loads(row.tagged_ports_json or "[]")
                    if action == "add" and port not in cur:
                        cur.append(port)
                    elif action == "remove" and port in cur:
                        cur.remove(port)
                    row.tagged_ports_json = json.dumps(cur)
            session.commit()
