from collections import deque
from datetime import datetime
import json
import math
from typing import Any, Dict, List, Optional, Set, Tuple

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


def _format_port_link(src_if: str, dst_if: str) -> str:
    s = str(src_if or "").strip()
    d = str(dst_if or "").strip()
    if s and d:
        return f"{s} -> {d}"
    return s or d or "LAN"


def orient_topology_hierarchy(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    gateway_ips: Optional[Set[str]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Identify Gateways, compute tree depth from roots, and orient every edge Upstream -> Downstream."""
    gw_ip_set = {str(ip).strip() for ip in (gateway_ips or set()) if str(ip or "").strip()}
    node_by_id: Dict[int, Dict[str, Any]] = {}

    for n in nodes:
        nid = int(n["id"])
        node_by_id[nid] = n
        ip = str(n.get("management_ip") or "").strip()
        role_low = str(n.get("role") or "").lower()
        cat = str(n.get("category") or "Other")
        is_gw = bool(n.get("is_gateway")) or (ip in gw_ip_set) or ("gateway" in role_low) or ("passerelle" in role_low)
        n["is_gateway"] = is_gw
        n["is_local_host"] = bool(n.get("is_local_host", False))
        if "already_in_inventory" not in n:
            n["already_in_inventory"] = nid > 0
        if "db_device_id" not in n:
            n["db_device_id"] = nid if (nid > 0 and n["already_in_inventory"]) else None
        if "latency_ms" not in n:
            n["latency_ms"] = None
        n["layer_rank"] = 0 if is_gw else int(n.get("layer_rank", _LAYER_RANK.get(cat, 4)))

    valid_edges: List[Dict[str, Any]] = []
    adj: Dict[int, List[Tuple[int, Dict[str, Any]]]] = {nid: [] for nid in node_by_id}
    degree: Dict[int, int] = {nid: 0 for nid in node_by_id}

    for e in edges:
        sid = int(e.get("source_device_id", 0))
        did = int(e.get("dest_device_id", 0))
        if sid not in node_by_id or did not in node_by_id or sid == did:
            continue
        valid_edges.append(e)
        adj[sid].append((did, e))
        adj[did].append((sid, e))
        degree[sid] += 1
        degree[did] += 1

    for nid in adj:
        adj[nid].sort(
            key=lambda pair: (
                int(node_by_id[pair[0]]["layer_rank"]),
                -degree[pair[0]],
                str(node_by_id[pair[0]].get("hostname") or ""),
                pair[0],
            )
        )

    tree_depth: Dict[int, int] = {}
    parent_of: Dict[int, Optional[int]] = {}
    parent_edge_ports: Dict[int, str] = {}
    visited: Set[int] = set()
    queue: deque[int] = deque()

    gw_roots = sorted(
        [nid for nid, n in node_by_id.items() if n["is_gateway"]],
        key=lambda nid: (-degree[nid], str(node_by_id[nid].get("hostname") or ""), nid),
    )
    for gid in gw_roots:
        visited.add(gid)
        tree_depth[gid] = 0
        parent_of[gid] = None
        queue.append(gid)

    def _drain_bfs() -> None:
        while queue:
            u = queue.popleft()
            u_depth = tree_depth[u]
            for v, edge in adj[u]:
                if v in visited:
                    continue
                visited.add(v)
                tree_depth[v] = u_depth + 1
                parent_of[v] = u
                if int(edge["source_device_id"]) == u:
                    parent_edge_ports[v] = _format_port_link(edge.get("source_interface", ""), edge.get("dest_interface", ""))
                else:
                    parent_edge_ports[v] = _format_port_link(edge.get("dest_interface", ""), edge.get("source_interface", ""))
                queue.append(v)

    _drain_bfs()

    remaining = sorted(
        [nid for nid in node_by_id if nid not in visited],
        key=lambda nid: (
            int(node_by_id[nid]["layer_rank"]),
            -degree[nid],
            str(node_by_id[nid].get("hostname") or ""),
            nid,
        ),
    )
    for rid in remaining:
        if rid in visited:
            continue
        visited.add(rid)
        tree_depth[rid] = int(node_by_id[rid]["layer_rank"])
        parent_of[rid] = None
        queue.append(rid)
        _drain_bfs()

    # Orient every edge strictly Upstream -> Downstream
    uplinks_by_id: Dict[int, List[Dict[str, Any]]] = {nid: [] for nid in node_by_id}
    downlinks_by_id: Dict[int, List[Dict[str, Any]]] = {nid: [] for nid in node_by_id}

    for e in valid_edges:
        sid = int(e["source_device_id"])
        did = int(e["dest_device_id"])
        swap = False
        if parent_of.get(sid) == did:
            swap = True
        elif parent_of.get(did) == sid:
            swap = False
        else:
            s_score = (tree_depth[sid], int(node_by_id[sid]["layer_rank"]), -degree[sid], sid)
            d_score = (tree_depth[did], int(node_by_id[did]["layer_rank"]), -degree[did], did)
            if d_score < s_score:
                swap = True
        if swap:
            e["source_device_id"], e["dest_device_id"] = did, sid
            e["source_interface"], e["dest_interface"] = e.get("dest_interface", ""), e.get("source_interface", "")
            sid, did = did, sid
        e["flow_direction"] = "DOWNSTREAM"
        downlinks_by_id[sid].append(e)
        uplinks_by_id[did].append(e)

    for nid, n in node_by_id.items():
        ups = uplinks_by_id[nid]
        dns = downlinks_by_id[nid]
        p_id = parent_of.get(nid)
        if p_id is None and ups:
            first_up = ups[0]
            p_id = int(first_up["source_device_id"])
            up_ports = _format_port_link(first_up.get("source_interface", ""), first_up.get("dest_interface", ""))
        else:
            up_ports = parent_edge_ports.get(nid, "")

        if p_id is not None and p_id in node_by_id:
            n["upstream_device_id"] = p_id
            n["upstream_hostname"] = str(node_by_id[p_id].get("hostname") or p_id)
            n["upstream_port"] = up_ports
        elif n["is_gateway"]:
            n["upstream_device_id"] = None
            n["upstream_hostname"] = "Internet / WAN"
            n["upstream_port"] = "WAN"
        else:
            n["upstream_device_id"] = None
            n["upstream_hostname"] = ""
            n["upstream_port"] = ""

        dn_ids = list(dict.fromkeys(int(e["dest_device_id"]) for e in dns))
        n["tree_depth"] = int(tree_depth.get(nid, n["layer_rank"]))
        n["downstream_ids"] = dn_ids
        n["downstream_names"] = [str(node_by_id[cid].get("hostname") or cid) for cid in dn_ids if cid in node_by_id]
        n["downstream_count"] = len(dn_ids)
        n["uplink_count"] = len(ups)
        n["connected_count"] = len(ups) + len(dns)

    return nodes, valid_edges


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
            sites = session.query(NetworkSite).all()
            site_map = {s.id: s.name for s in sites}
            site_gateways = {str(s.default_gateway or "").strip() for s in sites if str(s.default_gateway or "").strip()}
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
            allowed_types = {"PHYSICAL", "UPLINK", "AP_UPLINK", "TRUNK", "GATEWAY_UPLINK"} if mode == "PHYSICAL" else {"LOGICAL", "UPLINK", "GATEWAY_UPLINK"}
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
                "db_device_id": d.id,
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
                "already_in_inventory": True,
                "layer_rank": _LAYER_RANK.get(d.category or "Other", 4),
            })

        nodes, edges = orient_topology_hierarchy(nodes, edges, gateway_ips=site_gateways)
        return {"view_mode": mode, "nodes": nodes, "edges": edges}

    @staticmethod
    def enrich_graph_hierarchy(
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        gateway_ips: Optional[Set[str]] = None,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        return orient_topology_hierarchy(nodes, edges, gateway_ips=gateway_ips)

    @staticmethod
    def compute_auto_layout(
        nodes: List[Dict[str, Any]],
        view_mode: str = "PHYSICAL",
        spacing_x: float = 248.0,
        spacing_y: float = 165.0,
        edges: Optional[List[Dict[str, Any]]] = None,
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
                for n_idx, node in enumerate(sorted(s_nodes, key=lambda x: (x.get("tree_depth", x["layer_rank"]), x["hostname"]))):
                    nx = cx + (n_idx % sub_cols - (sub_cols - 1) / 2.0) * (spacing_x * 0.92)
                    ny = cy + (n_idx // sub_cols) * (spacing_y * 0.85)
                    positions[int(node["id"])] = (round(nx, 1), round(ny, 1))
            return positions

        use_tree = any(n.get("upstream_device_id") is not None or n.get("is_gateway") for n in nodes)
        by_layer: Dict[int, List[Dict[str, Any]]] = {}
        for n in nodes:
            tier = int(n.get("tree_depth", n.get("layer_rank", 4))) if use_tree else int(n.get("layer_rank", 4))
            by_layer.setdefault(tier, []).append(n)

        max_per_row = 8 if len(nodes) <= 48 else 12
        y_cursor = 0.0
        for layer in sorted(by_layer.keys()):
            layer_nodes = sorted(
                by_layer[layer],
                key=lambda x: (
                    positions.get(int(x["upstream_device_id"]), (0.0, 0.0))[0]
                    if x.get("upstream_device_id") is not None
                    else 0.0,
                    0 if x.get("is_gateway") else 1,
                    int(x.get("layer_rank", 4)),
                    x.get("site_name", ""),
                    x.get("hostname", ""),
                ),
            )
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
