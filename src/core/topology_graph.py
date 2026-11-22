from datetime import datetime
import json
import math
from typing import Any, Dict, List, Optional, Tuple

from utils.db import (
    DatabaseManager,
    InfrastructureDevice,
    InfrastructureVlan,
    NetworkLink,
    NetworkSite,
    TopologyLayout,
)

STATUS_COLOR_MAP: Dict[str, str] = {
    "UP": "#10B981",       # Green: healthy
    "ONLINE": "#10B981",
    "OK": "#10B981",
    "DEGRADED": "#F59E0B", # Orange: degraded
    "WARNING": "#F59E0B",
    "RECOVERING": "#F59E0B",
    "DOWN": "#F43F5E",     # Red: unavailable
    "OFFLINE": "#F43F5E",
    "CRITICAL": "#F43F5E",
    "UNKNOWN": "#94A3B8",  # Grey: unknown
    "SELECTED": "#3B82F6", # Blue: selected
}

VIEW_MODES = ("PHYSICAL", "LOGICAL", "VLAN", "SITE")

_LAYER_RANK: Dict[str, int] = {
    "Firewall": 0,
    "Router": 0,
    "Core Switch": 1,
    "Wireless Controller": 1,
    "Distribution Switch": 2,
    "Access Switch": 3,
    "Wireless Access Point": 4,
    "Server": 4,
    "UPS": 4,
    "Printer": 4,
    "Other": 4,
}


def resolve_status_color(status: str, selected: bool = False) -> str:
    if selected:
        return STATUS_COLOR_MAP["SELECTED"]
    return STATUS_COLOR_MAP.get(str(status or "UNKNOWN").upper(), STATUS_COLOR_MAP["UNKNOWN"])


class TopologyGraphService:
    """Builds multi-mode topology graphs (Physical/Logical/VLAN/Site) and persists layouts."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def build_graph(
        self,
        view_mode: str = "PHYSICAL",
        site_id: Optional[int] = None,
        category_filter: Optional[str] = None,
        search: str = "",
        vlan_number: Optional[int] = None,
    ) -> Dict[str, Any]:
        mode = str(view_mode or "PHYSICAL").upper()
        if mode not in VIEW_MODES:
            mode = "PHYSICAL"

        with self.db.Session() as session:
            site_map = {s.id: s.name for s in session.query(NetworkSite).all()}
            q_dev = session.query(InfrastructureDevice)
            if site_id is not None:
                q_dev = q_dev.filter(InfrastructureDevice.site_id == int(site_id))
            if category_filter:
                q_dev = q_dev.filter(InfrastructureDevice.category == category_filter)
            devs = q_dev.order_by(InfrastructureDevice.id.asc()).all()

            dev_by_id = {d.id: d for d in devs}
            raw_links = session.query(NetworkLink).all()
            vlan_rows = session.query(InfrastructureVlan).all()

        # Filter nodes by search if supplied while preserving directly connected neighbors if needed
        term = str(search or "").strip().lower()
        if term:
            matched_ids = {
                d.id
                for d in devs
                if (
                    term in (d.hostname or "").lower()
                    or term in (d.management_ip or "").lower()
                    or term in (d.vendor or "").lower()
                    or term in (d.category or "").lower()
                )
            }
        else:
            matched_ids = set(dev_by_id.keys())

        edges: List[Dict[str, Any]] = []
        degree_counts: Dict[int, int] = {}

        if mode in ("PHYSICAL", "LOGICAL"):
            allowed_types = {"PHYSICAL", "UPLINK", "AP_UPLINK", "TRUNK"} if mode == "PHYSICAL" else {"LOGICAL", "UPLINK"}
            for lk in raw_links:
                if lk.source_device_id not in dev_by_id or lk.dest_device_id not in dev_by_id:
                    continue
                if lk.source_device_id not in matched_ids and lk.dest_device_id not in matched_ids:
                    continue
                if mode == "PHYSICAL" and lk.link_type == "LOGICAL":
                    continue
                if mode == "LOGICAL" and lk.discovery_method == "BRIDGE_FDB" and lk.link_type not in allowed_types:
                    continue
                matched_ids.add(lk.source_device_id)
                matched_ids.add(lk.dest_device_id)
                degree_counts[lk.source_device_id] = degree_counts.get(lk.source_device_id, 0) + 1
                degree_counts[lk.dest_device_id] = degree_counts.get(lk.dest_device_id, 0) + 1
                edges.append({
                    "id": lk.id,
                    "source_device_id": lk.source_device_id,
                    "dest_device_id": lk.dest_device_id,
                    "source_interface": lk.source_interface or "",
                    "dest_interface": lk.dest_interface or "",
                    "link_type": lk.link_type,
                    "discovery_method": lk.discovery_method,
                    "confidence": lk.confidence,
                    "status": lk.status or "UP",
                    "vlan_ids": json.loads(lk.vlan_ids_json or "[]"),
                    "evidence": json.loads(lk.evidence_json or "[]"),
                    "last_observed": lk.last_observed,
                })

        elif mode == "VLAN":
            # Connect devices that share an observed VLAN or link carrying that VLAN
            devs_by_vlan: Dict[int, List[int]] = {}
            for vr in vlan_rows:
                if vr.device_id not in dev_by_id:
                    continue
                if vlan_number is not None and vr.vlan_number != int(vlan_number):
                    continue
                devs_by_vlan.setdefault(vr.vlan_number, []).append(vr.device_id)

            for lk in raw_links:
                if lk.source_device_id not in dev_by_id or lk.dest_device_id not in dev_by_id:
                    continue
                vids = json.loads(lk.vlan_ids_json or "[]")
                if vlan_number is not None and int(vlan_number) not in vids:
                    continue
                # Include links sharing a VLAN or physical uplink if VLAN spans both switches
                common = []
                for vid, dlist in devs_by_vlan.items():
                    if lk.source_device_id in dlist and lk.dest_device_id in dlist:
                        common.append(vid)
                shared = sorted(set(vids) | set(common))
                if not shared and vlan_number is not None:
                    continue
                if shared:
                    matched_ids.add(lk.source_device_id)
                    matched_ids.add(lk.dest_device_id)
                    degree_counts[lk.source_device_id] = degree_counts.get(lk.source_device_id, 0) + 1
                    degree_counts[lk.dest_device_id] = degree_counts.get(lk.dest_device_id, 0) + 1
                    edges.append({
                        "id": lk.id,
                        "source_device_id": lk.source_device_id,
                        "dest_device_id": lk.dest_device_id,
                        "source_interface": lk.source_interface or "",
                        "dest_interface": lk.dest_interface or "",
                        "link_type": f"VLAN {','.join(str(v) for v in shared[:3])}",
                        "discovery_method": lk.discovery_method,
                        "confidence": lk.confidence,
                        "status": lk.status or "UP",
                        "vlan_ids": shared,
                        "evidence": json.loads(lk.evidence_json or "[]"),
                        "last_observed": lk.last_observed,
                    })

        elif mode == "SITE":
            # Include all links; cross-site links are highlighted as INTER_SITE_WAN
            for lk in raw_links:
                if lk.source_device_id not in dev_by_id or lk.dest_device_id not in dev_by_id:
                    continue
                s_dev = dev_by_id[lk.source_device_id]
                d_dev = dev_by_id[lk.dest_device_id]
                is_inter_site = s_dev.site_id != d_dev.site_id
                degree_counts[lk.source_device_id] = degree_counts.get(lk.source_device_id, 0) + 1
                degree_counts[lk.dest_device_id] = degree_counts.get(lk.dest_device_id, 0) + 1
                edges.append({
                    "id": lk.id,
                    "source_device_id": lk.source_device_id,
                    "dest_device_id": lk.dest_device_id,
                    "source_interface": lk.source_interface or "",
                    "dest_interface": lk.dest_interface or "",
                    "link_type": "INTER_SITE" if is_inter_site else lk.link_type,
                    "discovery_method": lk.discovery_method,
                    "confidence": lk.confidence,
                    "status": lk.status or "UP",
                    "vlan_ids": json.loads(lk.vlan_ids_json or "[]"),
                    "evidence": json.loads(lk.evidence_json or "[]"),
                    "last_observed": lk.last_observed,
                })

        nodes: List[Dict[str, Any]] = []
        for did in sorted(matched_ids):
            d = dev_by_id.get(did)
            if not d:
                continue
            nodes.append({
                "id": d.id,
                "device_uid": d.device_uid,
                "hostname": d.hostname,
                "management_ip": d.management_ip,
                "mac_address": d.mac_address or "",
                "vendor": d.vendor or "Unknown",
                "model": d.model or "",
                "category": d.category or "Other",
                "role": d.role or "",
                "site_id": d.site_id,
                "site_name": site_map.get(d.site_id, "Unassigned") if d.site_id else "Unassigned",
                "status": str(d.status or "UNKNOWN").upper(),
                "color": resolve_status_color(d.status),
                "connected_count": degree_counts.get(d.id, 0),
                "discovery_source": d.discovery_source or "MANUAL",
                "layer_rank": _LAYER_RANK.get(d.category or "Other", 4),
            })

        return {"view_mode": mode, "nodes": nodes, "edges": edges}

    @staticmethod
    def compute_auto_layout(
        nodes: List[Dict[str, Any]],
        view_mode: str = "PHYSICAL",
        spacing_x: float = 175.0,
        spacing_y: float = 155.0,
    ) -> Dict[int, Tuple[float, float]]:
        """Deterministic layered/clustered layout supporting 200+ nodes in O(N log N)."""
        positions: Dict[int, Tuple[float, float]] = {}
        if not nodes:
            return positions

        if str(view_mode).upper() == "SITE":
            by_site: Dict[str, List[Dict[str, Any]]] = {}
            for n in nodes:
                by_site.setdefault(n.get("site_name", "Unassigned"), []).append(n)
            site_cols = max(1, math.ceil(math.sqrt(len(by_site))))
            for s_idx, (_sname, s_nodes) in enumerate(sorted(by_site.items())):
                cx = (s_idx % site_cols) * spacing_x * 3.2
                cy = (s_idx // site_cols) * spacing_y * 2.8
                sub_cols = max(1, math.ceil(math.sqrt(len(s_nodes))))
                for n_idx, node in enumerate(sorted(s_nodes, key=lambda x: (x["layer_rank"], x["hostname"]))):
                    nx = cx + (n_idx % sub_cols - (sub_cols - 1) / 2.0) * (spacing_x * 0.72)
                    ny = cy + (n_idx // sub_cols) * (spacing_y * 0.65)
                    positions[int(node["id"])] = (round(nx, 1), round(ny, 1))
            return positions

        by_layer: Dict[int, List[Dict[str, Any]]] = {}
        for n in nodes:
            by_layer.setdefault(int(n.get("layer_rank", 4)), []).append(n)

        max_per_row = 12
        y_cursor = 0.0
        for layer in sorted(by_layer.keys()):
            layer_nodes = sorted(by_layer[layer], key=lambda x: (x.get("site_name", ""), x.get("hostname", "")))
            for chunk_start in range(0, len(layer_nodes), max_per_row):
                row_items = layer_nodes[chunk_start:chunk_start + max_per_row]
                row_w = (len(row_items) - 1) * spacing_x
                for col_i, node in enumerate(row_items):
                    x = -row_w / 2.0 + col_i * spacing_x
                    positions[int(node["id"])] = (round(x, 1), round(y_cursor, 1))
                y_cursor += spacing_y
        return positions

    def save_layout(
        self,
        layout_name: str,
        positions: Dict[int, Tuple[float, float]],
        view_mode: str = "PHYSICAL",
        site_id: Optional[int] = None,
        zoom_level: float = 1.0,
    ) -> None:
        serializable = {str(k): [float(v[0]), float(v[1])] for k, v in positions.items()}
        with self.db.Session() as session:
            existing = session.query(TopologyLayout).filter_by(layout_name=layout_name).first()
            if existing:
                existing.view_mode = view_mode
                existing.site_id = site_id
                existing.positions_json = json.dumps(serializable)
                existing.zoom_level = float(zoom_level)
                existing.updated_at = datetime.utcnow()
            else:
                session.add(
                    TopologyLayout(
                        layout_name=layout_name,
                        view_mode=view_mode,
                        site_id=site_id,
                        positions_json=json.dumps(serializable),
                        zoom_level=float(zoom_level),
                    )
                )
            session.commit()

    def load_layout(self, layout_name: str) -> Tuple[Dict[int, Tuple[float, float]], float]:
        with self.db.Session() as session:
            row = session.query(TopologyLayout).filter_by(layout_name=layout_name).first()
            if not row:
                return {}, 1.0
            raw = json.loads(row.positions_json or "{}")
            pos = {int(k): (float(v[0]), float(v[1])) for k, v in raw.items() if isinstance(v, list) and len(v) == 2}
            return pos, float(row.zoom_level or 1.0)
