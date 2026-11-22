from dataclasses import asdict, dataclass, field
from datetime import datetime
import threading
from typing import Any, Dict, List, Optional, Set, Tuple

from core.snmp_client import SNMPClient, SNMPError, oid_bytes_to_hex
from core.snmp_profiles import STD_OIDS, SNMPVendorProfile
from utils.db import DatabaseManager
from utils.snmp_credentials import SNMPCredentials


CISCO_VTP_VLAN_STATE_OID = "1.3.6.1.4.1.9.9.46.1.3.1.1.2.1"
CISCO_VTP_VLAN_NAME_OID = "1.3.6.1.4.1.9.9.46.1.3.1.1.4.1"
CISCO_TRUNK_DYN_STATUS_OID = "1.3.6.1.4.1.9.9.46.1.6.1.1.14"
CISCO_VM_VLAN_OID = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"
RUCKUS_VLAN_NAME_OID = "1.3.6.1.4.1.1991.1.1.3.2.7.1.21"

_CISCO_RESERVED_INTERNAL_VLANS = frozenset({1002, 1003, 1004, 1005})


@dataclass
class VLANInfo:
    vlan_id: int
    name: str = ""
    status: str = "ACTIVE"
    tagged_ports: List[str] = field(default_factory=list)
    untagged_ports: List[str] = field(default_factory=list)
    trunk_ports: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VLANSnapshot:
    device_id: int
    timestamp: datetime
    supported: bool = False
    vlans: List[VLANInfo] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "timestamp": self.timestamp,
            "supported": self.supported,
            "vlans": [v.to_dict() for v in self.vlans],
        }


def decode_port_list(val: Any) -> List[int]:
    """Decode an SNMP RFC 4363 PortList OCTET STRING bitmask into 1-based bridge port numbers."""
    raw = oid_bytes_to_hex(val)
    if not raw:
        return []
    ports: List[int] = []
    for byte_i, b in enumerate(raw):
        if b == 0:
            continue
        for bit_i in range(8):
            if b & (0x80 >> bit_i):
                ports.append(byte_i * 8 + bit_i + 1)
    return ports


def _to_int(val: Any) -> Optional[int]:
    if isinstance(val, bool) or val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


class VLANMonitorCollector:
    """SNMP collector for Q-BRIDGE-MIB and Cisco/Ruckus VLAN definitions and port memberships."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_snapshots: Dict[int, VLANSnapshot] = {}

    def get_last_snapshot(self, device_id: int) -> Optional[VLANSnapshot]:
        with self._lock:
            return self._last_snapshots.get(int(device_id))

    async def _walk_safe(
        self,
        client: SNMPClient,
        ip: str,
        port: int,
        creds: SNMPCredentials,
        base_oid: str,
        timeout_sec: float,
        retries: int,
    ) -> List[Tuple[str, Any]]:
        try:
            return await client.walk_oid(
                ip, creds, str(base_oid).lstrip("."), port=port, timeout_sec=timeout_sec, retries=retries
            )
        except SNMPError:
            return []

    @staticmethod
    def _bp_name(bp: int, bp_to_if: Dict[int, int], iface_name_map: Dict[int, str]) -> str:
        if_idx = bp_to_if.get(bp)
        if if_idx is not None:
            return iface_name_map.get(if_idx) or f"if{if_idx}"
        return iface_name_map.get(bp) or f"Port-{bp}"

    @staticmethod
    def _if_name(if_idx: int, iface_name_map: Dict[int, str]) -> str:
        return iface_name_map.get(if_idx) or f"if{if_idx}"

    async def _collect_qbridge(
        self,
        client: SNMPClient,
        ip: str,
        port: int,
        creds: SNMPCredentials,
        iface_name_map: Dict[int, str],
        timeout_sec: float,
        retries: int,
    ) -> List[VLANInfo]:
        name_rows = await self._walk_safe(
            client, ip, port, creds, STD_OIDS["dot1qVlanStaticName"], timeout_sec, retries
        )
        status_rows = await self._walk_safe(
            client, ip, port, creds, STD_OIDS["dot1qVlanStaticRowStatus"], timeout_sec, retries
        )
        egress_rows = await self._walk_safe(
            client, ip, port, creds, STD_OIDS["dot1qVlanCurrentEgressPorts"], timeout_sec, retries
        )
        untagged_rows = await self._walk_safe(
            client, ip, port, creds, STD_OIDS["dot1qVlanCurrentUntaggedPorts"], timeout_sec, retries
        )

        if not name_rows and not egress_rows:
            return []

        bp_rows = await self._walk_safe(
            client, ip, port, creds, STD_OIDS["dot1dBasePortIfIndex"], timeout_sec, retries
        )
        pvid_rows = await self._walk_safe(
            client, ip, port, creds, STD_OIDS["dot1qPvid"], timeout_sec, retries
        )

        bp_to_if: Dict[int, int] = {}
        for oid_k, val in bp_rows:
            if (if_idx := _to_int(val)) is not None:
                try:
                    bp = int(str(oid_k).rsplit(".", 1)[-1])
                    bp_to_if[bp] = if_idx
                except ValueError:
                    pass

        pvid_map: Dict[int, int] = {}
        for oid_k, val in pvid_rows:
            if (vid := _to_int(val)) is not None:
                try:
                    bp = int(str(oid_k).rsplit(".", 1)[-1])
                    pvid_map[bp] = vid
                except ValueError:
                    pass

        vlan_names: Dict[int, str] = {}
        for oid_k, val in name_rows:
            try:
                vid = int(str(oid_k).rsplit(".", 1)[-1])
                vlan_names[vid] = str(val or "").strip() or f"VLAN-{vid}"
            except ValueError:
                pass

        vlan_status: Dict[int, str] = {}
        for oid_k, val in status_rows:
            try:
                vid = int(str(oid_k).rsplit(".", 1)[-1])
                iv = _to_int(val)
                vlan_status[vid] = "ACTIVE" if iv in (None, 1) else "INACTIVE"
            except ValueError:
                pass

        egress_map: Dict[int, Set[int]] = {}
        for oid_k, val in egress_rows:
            try:
                vid = int(str(oid_k).rsplit(".", 1)[-1])
                egress_map.setdefault(vid, set()).update(decode_port_list(val))
            except ValueError:
                pass

        untagged_map: Dict[int, Set[int]] = {}
        for oid_k, val in untagged_rows:
            try:
                vid = int(str(oid_k).rsplit(".", 1)[-1])
                untagged_map.setdefault(vid, set()).update(decode_port_list(val))
            except ValueError:
                pass

        all_vids = sorted(set(vlan_names.keys()) | set(egress_map.keys()) | set(untagged_map.keys()))
        if not all_vids:
            return []

        bp_vlan_count: Dict[int, int] = {}
        for bps in egress_map.values():
            for bp in bps:
                bp_vlan_count[bp] = bp_vlan_count.get(bp, 0) + 1

        vlans: List[VLANInfo] = []
        for vid in all_vids:
            egress_bps = egress_map.get(vid, set())
            if vid in untagged_map:
                untagged_bps = set(untagged_map[vid])
            elif not egress_map and not untagged_map:
                untagged_bps = {bp for bp, pvid in pvid_map.items() if pvid == vid}
            else:
                untagged_bps = {bp for bp, pvid in pvid_map.items() if pvid == vid and bp in egress_bps}

            tagged_bps = egress_bps - untagged_bps
            trunk_bps = tagged_bps | {bp for bp in egress_bps if bp_vlan_count.get(bp, 0) >= 2}

            vlans.append(
                VLANInfo(
                    vlan_id=vid,
                    name=vlan_names.get(vid) or f"VLAN-{vid}",
                    status=vlan_status.get(vid, "ACTIVE"),
                    tagged_ports=[self._bp_name(bp, bp_to_if, iface_name_map) for bp in sorted(tagged_bps)],
                    untagged_ports=[self._bp_name(bp, bp_to_if, iface_name_map) for bp in sorted(untagged_bps)],
                    trunk_ports=[self._bp_name(bp, bp_to_if, iface_name_map) for bp in sorted(trunk_bps)],
                )
            )
        return vlans

    async def _collect_cisco(
        self,
        client: SNMPClient,
        ip: str,
        port: int,
        creds: SNMPCredentials,
        iface_name_map: Dict[int, str],
        timeout_sec: float,
        retries: int,
    ) -> List[VLANInfo]:
        vtp_names_rows = await self._walk_safe(client, ip, port, creds, CISCO_VTP_VLAN_NAME_OID, timeout_sec, retries)
        if not vtp_names_rows:
            return []

        vtp_state_rows = await self._walk_safe(client, ip, port, creds, CISCO_VTP_VLAN_STATE_OID, timeout_sec, retries)
        vm_vlan_rows = await self._walk_safe(client, ip, port, creds, CISCO_VM_VLAN_OID, timeout_sec, retries)
        trunk_rows = await self._walk_safe(client, ip, port, creds, CISCO_TRUNK_DYN_STATUS_OID, timeout_sec, retries)

        vlan_names: Dict[int, str] = {}
        for oid_k, val in vtp_names_rows:
            try:
                vid = int(str(oid_k).rsplit(".", 1)[-1])
                vlan_names[vid] = str(val or "").strip() or f"VLAN-{vid}"
            except ValueError:
                pass

        vlan_states: Dict[int, str] = {}
        for oid_k, val in vtp_state_rows:
            try:
                vid = int(str(oid_k).rsplit(".", 1)[-1])
                iv = _to_int(val)
                vlan_states[vid] = "ACTIVE" if iv in (None, 1) else "SUSPENDED"
            except ValueError:
                pass

        access_by_vid: Dict[int, Set[int]] = {}
        for oid_k, val in vm_vlan_rows:
            if (vid := _to_int(val)) is not None:
                try:
                    if_idx = int(str(oid_k).rsplit(".", 1)[-1])
                    access_by_vid.setdefault(vid, set()).add(if_idx)
                except ValueError:
                    pass

        trunk_if_indices: Set[int] = set()
        for oid_k, val in trunk_rows:
            if (iv := _to_int(val)) is not None and iv == 1:  # trunking(1)
                try:
                    trunk_if_indices.add(int(str(oid_k).rsplit(".", 1)[-1]))
                except ValueError:
                    pass

        vids = sorted(vlan_names.keys())
        non_reserved = [v for v in vids if v not in _CISCO_RESERVED_INTERNAL_VLANS]
        if non_reserved:
            vids = non_reserved

        sorted_trunk_names = [self._if_name(idx, iface_name_map) for idx in sorted(trunk_if_indices)]
        vlans: List[VLANInfo] = []
        for vid in vids:
            status = vlan_states.get(vid, "ACTIVE")
            untagged_names = [self._if_name(idx, iface_name_map) for idx in sorted(access_by_vid.get(vid, set()))]
            trunks = list(sorted_trunk_names) if status == "ACTIVE" else []
            vlans.append(
                VLANInfo(
                    vlan_id=vid,
                    name=vlan_names[vid],
                    status=status,
                    tagged_ports=list(trunks),
                    untagged_ports=untagged_names,
                    trunk_ports=trunks,
                )
            )
        return vlans

    async def collect_vlans(
        self,
        device_id: int,
        client: SNMPClient,
        db: DatabaseManager,
        ip: str,
        port: int,
        creds: SNMPCredentials,
        profile: SNMPVendorProfile,
        iface_name_map: Optional[Dict[int, str]] = None,
        timeout_sec: float = 2.0,
        retries: int = 1,
        now_utc: Optional[datetime] = None,
    ) -> VLANSnapshot:
        ts = now_utc or datetime.utcnow()

        name_map: Dict[int, str] = dict(iface_name_map or {})
        if not name_map:
            for row in db.get_snmp_interfaces(device_id):
                idx = int(row["if_index"])
                name_map[idx] = str(row.get("name") or row.get("description") or f"if{idx}")

        vlans: List[VLANInfo] = []
        if profile.name == "cisco_catalyst":
            vlans = await self._collect_cisco(client, ip, port, creds, name_map, timeout_sec, retries)
            if not vlans:
                vlans = await self._collect_qbridge(client, ip, port, creds, name_map, timeout_sec, retries)
        else:
            vlans = await self._collect_qbridge(client, ip, port, creds, name_map, timeout_sec, retries)
            if not vlans:
                vlans = await self._collect_cisco(client, ip, port, creds, name_map, timeout_sec, retries)

        # Ruckus legacy VLAN name fallback when standard Q-BRIDGE isn't populated
        if not vlans and (profile.name == "ruckus" or RUCKUS_VLAN_NAME_OID in profile.vlan_name_oids):
            rk_rows = await self._walk_safe(client, ip, port, creds, RUCKUS_VLAN_NAME_OID, timeout_sec, retries)
            for oid_k, val in rk_rows:
                try:
                    vid = int(str(oid_k).rsplit(".", 1)[-1])
                    vlans.append(
                        VLANInfo(
                            vlan_id=vid,
                            name=str(val or "").strip() or f"VLAN-{vid}",
                            status="ACTIVE",
                        )
                    )
                except ValueError:
                    pass
            vlans.sort(key=lambda v: v.vlan_id)

        if not vlans:
            return VLANSnapshot(device_id=device_id, timestamp=ts, supported=False, vlans=[])

        db.upsert_snmp_vlans(device_id, [v.to_dict() for v in vlans])
        return VLANSnapshot(device_id=device_id, timestamp=ts, supported=True, vlans=vlans)

    async def collect(self, ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
        device_id = int(ctx["device_id"])
        due_flags: Dict[str, bool] = dict(ctx.get("due_flags") or {"sysinfo": True})
        now_utc: datetime = ctx.get("now_utc") or datetime.utcnow()

        if not due_flags.get("sysinfo", True):
            prev = self.get_last_snapshot(device_id)
            if prev is not None and prev.supported:
                ctx.setdefault("collector_snapshots", {})["vlans"] = prev.to_dict()
            return []

        snap = await self.collect_vlans(
            device_id=device_id,
            client=ctx["client"],
            db=ctx["db"],
            ip=ctx["ip_address"],
            port=int(ctx["port"]),
            creds=ctx["credentials"],
            profile=ctx["profile"],
            iface_name_map=ctx.get("interface_name_map"),
            timeout_sec=float(ctx.get("timeout_sec", 2.0)),
            retries=int(ctx.get("retries", 1)),
            now_utc=now_utc,
        )

        with self._lock:
            self._last_snapshots[device_id] = snap

        ctx.setdefault("collector_snapshots", {})["vlans"] = snap.to_dict()
        if not snap.supported:
            return []

        return [
            {
                "device_id": device_id,
                "metric_name": "vlan_count",
                "metric_value": float(len(snap.vlans)),
                "unit": "count",
                "timestamp": now_utc,
            }
        ]
