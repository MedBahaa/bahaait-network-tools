import asyncio
import os
import sys
import time

import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from core.inventory_manager import InventoryManager
from core.site_manager import SiteManager
from core.snmp_profiles import STD_OIDS
from core.topology_discovery import (
    TOPO_OIDS,
    TopologyDiscoveryEngine,
    classify_device_identity,
    parse_cdp_neighbors,
    parse_lldp_neighbors,
    parse_mac_fdb,
    parse_routing_next_hops,
    parse_system_arp_table,
)
from core.topology_graph import STATUS_COLOR_MAP, VIEW_MODES, TopologyGraphService
from ui.widgets.topology_view import TopologyView
from utils.db import DatabaseManager, InfrastructureVlan, NetworkLink
from utils.snmp_credentials import SNMPCredentials, encrypt_credentials


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app


class _MockSNMPWalkClient:
    """Deterministic async mock SNMPClient keyed by (ip, base_oid)."""

    def __init__(self, responses):
        self.responses = responses

    async def walk_oid(self, ip, creds, oid, port=161, timeout_sec=2.0, retries=1):
        return list(self.responses.get((ip, oid), []))


class TestPhase3NetworkTopology:
    def test_01_arp_parsing_and_no_category_guessing_from_oui(self):
        raw_arp = (
            "Interface: 10.10.0.50 --- 0x6\n"
            "  Internet Address      Physical Address      Type\n"
            "  10.10.0.1             00-11-21-ab-cd-ef     dynamic\n"
            "  10.10.0.255           ff-ff-ff-ff-ff-ff     static\n"
            "  224.0.0.22            01-00-5e-00-00-16     static\n"
            "  10.10.0.88            de-ad-be-ef-00-01     dynamic\n"
        )
        entries = parse_system_arp_table(raw_arp)
        assert len(entries) == 2
        assert entries[0]["ip"] == "10.10.0.1"
        assert entries[0]["mac"] == "00:11:21:AB:CD:EF"
        assert entries[0]["vendor"] == "Cisco"

        # Rule: MAC OUI supplies Vendor only — never guesses Category/Type
        vendor_only, cat_only = classify_device_identity(mac="00:11:21:AB:CD:EF")
        assert vendor_only == "Cisco"
        assert cat_only == "Other"

        # SNMP sysDescr/sysServices identify category properly
        fw_v, fw_c = classify_device_identity(
            sys_descr="FortiGate-100F v7.2.4, Firewall",
            mac="00:09:0F:11:22:33",
        )
        assert fw_c == "Firewall"

    def test_02_03_04_multi_source_discovery_lldp_cdp_fdb_routing_unmanaged_and_unknown(self, tmp_path):
        db = DatabaseManager(str(tmp_path / "topo.db"))
        sm = SiteManager(db)
        hq = sm.create_site({"name": "HQ Paris", "region": "EU"})

        enc = encrypt_credentials(SNMPCredentials(version="v2c", community="public"))
        db.add_snmp_device({
            "name": "CORE-C9300",
            "ip_address": "10.0.0.1",
            "snmp_version": "v2c",
            "encrypted_credentials": enc,
            "vendor": "Cisco",
            "model": "C9300-48P",
            "device_type": "Core Switch",
            "sys_descr": "Cisco IOS XE Core Switch C9300",
            "status": "ONLINE",
        })

        mock_client = _MockSNMPWalkClient({
            ("10.0.0.1", STD_OIDS["ifDescr"]): [
                (f"{STD_OIDS['ifDescr']}.1", "Gi1/0/1"),
                (f"{STD_OIDS['ifDescr']}.2", "Gi1/0/2"),
                (f"{STD_OIDS['ifDescr']}.3", "Gi1/0/3"),
            ],
            ("10.0.0.1", STD_OIDS["dot1dBasePortIfIndex"]): [
                (f"{STD_OIDS['dot1dBasePortIfIndex']}.1", 1),
                (f"{STD_OIDS['dot1dBasePortIfIndex']}.2", 2),
                (f"{STD_OIDS['dot1dBasePortIfIndex']}.3", 3),
            ],
            # LLDP neighbor on port 1 -> Ruckus ICX Access Switch 10.0.0.2
            ("10.0.0.1", TOPO_OIDS["lldpLocPortId"]): [
                (f"{TOPO_OIDS['lldpLocPortId']}.1", "Gi1/0/1"),
            ],
            ("10.0.0.1", TOPO_OIDS["lldpRemChassisId"]): [
                (f"{TOPO_OIDS['lldpRemChassisId']}.100.1.1", b"\x70\x4c\xa5\x11\x22\x33"),
            ],
            ("10.0.0.1", TOPO_OIDS["lldpRemPortId"]): [
                (f"{TOPO_OIDS['lldpRemPortId']}.100.1.1", "1/1/24"),
            ],
            ("10.0.0.1", TOPO_OIDS["lldpRemSysName"]): [
                (f"{TOPO_OIDS['lldpRemSysName']}.100.1.1", "ACC-ICX-01"),
            ],
            ("10.0.0.1", TOPO_OIDS["lldpRemSysDesc"]): [
                (f"{TOPO_OIDS['lldpRemSysDesc']}.100.1.1", "Ruckus ICX7150 Switch"),
            ],
            ("10.0.0.1", TOPO_OIDS["lldpRemManAddrIfId"]): [
                (f"{TOPO_OIDS['lldpRemManAddrIfId']}.100.1.1.1.4.10.0.0.2", 1),
            ],
            # CDP neighbor on port 2 -> Edge Router 10.0.0.254
            ("10.0.0.1", TOPO_OIDS["cdpCacheAddress"]): [
                (f"{TOPO_OIDS['cdpCacheAddress']}.2.1", b"\x0a\x00\x00\xfe"),
            ],
            ("10.0.0.1", TOPO_OIDS["cdpCacheDeviceId"]): [
                (f"{TOPO_OIDS['cdpCacheDeviceId']}.2.1", "EDGE-RTR-01"),
            ],
            ("10.0.0.1", TOPO_OIDS["cdpCacheDevicePort"]): [
                (f"{TOPO_OIDS['cdpCacheDevicePort']}.2.1", "Gi0/0/0"),
            ],
            ("10.0.0.1", TOPO_OIDS["cdpCachePlatform"]): [
                (f"{TOPO_OIDS['cdpCachePlatform']}.2.1", "ISR4331 Router"),
            ],
            ("10.0.0.1", TOPO_OIDS["cdpCacheCapabilities"]): [
                (f"{TOPO_OIDS['cdpCacheCapabilities']}.2.1", 1),
            ],
            # Bridge FDB on non-LLDP port 3 -> 2 MACs triggers Unmanaged Switch inference
            ("10.0.0.1", TOPO_OIDS["dot1dTpFdbPort"]): [
                (f"{TOPO_OIDS['dot1dTpFdbPort']}.170.187.204.1.2.3", 3),
                (f"{TOPO_OIDS['dot1dTpFdbPort']}.170.187.204.1.2.4", 3),
            ],
            # Routing table -> indirect next-hop 10.99.0.1 (Logical edge)
            ("10.0.0.1", TOPO_OIDS["ipRouteIfIndex"]): [
                (f"{TOPO_OIDS['ipRouteIfIndex']}.192.168.50.0", 2),
            ],
            ("10.0.0.1", TOPO_OIDS["ipRouteNextHop"]): [
                (f"{TOPO_OIDS['ipRouteNextHop']}.192.168.50.0", b"\x0a\x63\x00\x01"),
            ],
            ("10.0.0.1", TOPO_OIDS["ipRouteType"]): [
                (f"{TOPO_OIDS['ipRouteType']}.192.168.50.0", 4),
            ],
        })

        arp_entries = [
            {"ip": "10.0.1.50", "mac": "AA:BB:CC:01:02:03", "vendor": "Unknown", "entry_type": "dynamic"},
            {"ip": "10.0.1.99", "mac": "DE:AD:BE:EF:12:34", "vendor": "Unknown", "entry_type": "dynamic"},
        ]

        engine = TopologyDiscoveryEngine(db, snmp_client=mock_client)
        summary = asyncio.run(
            engine.discover_topology(
                include_local_arp=False,
                arp_entries=arp_entries,
                site_id=hq["id"],
                probe_icmp=True,
                icmp_probe_fn=lambda ip: ("ONLINE", 3.2) if ip != "10.0.1.99" else ("DOWN", None),
            )
        )

        assert summary["devices_discovered"] >= 3
        assert summary["inferred_unmanaged"] == 1
        assert summary["links_discovered"] >= 5

        inv = InventoryManager(db)
        all_devs = {d["hostname"]: d for d in inv.list_devices()}
        assert "CORE-C9300" in all_devs
        assert "ACC-ICX-01" in all_devs
        assert "EDGE-RTR-01" in all_devs
        assert any(h.startswith("Unmanaged-Switch-") for h in all_devs)
        # Standalone ARP device 10.0.1.99 exists as a node without fabricated links
        assert "10.0.1.99" in all_devs

        graph_svc = TopologyGraphService(db)
        phys = graph_svc.build_graph(view_mode="PHYSICAL")
        logical = graph_svc.build_graph(view_mode="LOGICAL")
        assert any(e["discovery_method"] == "LLDP" for e in phys["edges"])
        assert any(e["discovery_method"] == "CDP" for e in phys["edges"])
        assert any(e["link_type"] == "LOGICAL" and e["discovery_method"] == "ROUTING" for e in logical["edges"])
        # Standalone ARP-only host 10.0.1.99 must have 0 links (never invented)
        orphan = next(n for n in phys["nodes"] if n["hostname"] == "10.0.1.99")
        assert orphan["connected_count"] == 0

    def test_05_06_four_view_modes_and_interactive_topology_view(self, tmp_path, qapp):
        db = DatabaseManager(str(tmp_path / "topo_ui.db"))
        sm = SiteManager(db)
        s1 = sm.create_site({"name": "Site-Alpha", "region": "North"})
        s2 = sm.create_site({"name": "Site-Beta", "region": "South"})
        inv = InventoryManager(db, site_manager=sm)

        d1 = inv.add_device({"hostname": "ALPHA-CORE", "management_ip": "10.1.0.1", "category": "Core Switch", "site_id": s1["id"], "status": "UP"})
        d2 = inv.add_device({"hostname": "ALPHA-AP", "management_ip": "10.1.0.10", "category": "Wireless Access Point", "site_id": s1["id"], "status": "DEGRADED"})
        d3 = inv.add_device({"hostname": "BETA-RTR", "management_ip": "10.2.0.1", "category": "Router", "site_id": s2["id"], "status": "DOWN"})

        with db.Session() as session:
            session.add_all([
                NetworkLink(source_device_id=d1["id"], dest_device_id=d2["id"], source_interface="Gi1/0/5", dest_interface="eth0", link_type="AP_UPLINK", discovery_method="LLDP", confidence="HIGH", status="UP", vlan_ids_json="[10, 20]", evidence_json='["LLDP"]'),
                NetworkLink(source_device_id=d1["id"], dest_device_id=d3["id"], source_interface="Te1/1/1", dest_interface="Gi0/0", link_type="UPLINK", discovery_method="ROUTING", confidence="HIGH", status="DEGRADED", vlan_ids_json="[10]", evidence_json='["WAN"]'),
                InfrastructureVlan(device_id=d1["id"], vlan_number=10, vlan_name="CORP", status="ACTIVE"),
                InfrastructureVlan(device_id=d2["id"], vlan_number=10, vlan_name="CORP", status="ACTIVE"),
            ])
            session.commit()

        svc = TopologyGraphService(db)
        for m in VIEW_MODES:
            g = svc.build_graph(view_mode=m)
            assert g["view_mode"] == m
            assert len(g["nodes"]) == 3
        site_g = svc.build_graph(view_mode="SITE")
        assert any(e["link_type"] == "INTER_SITE" for e in site_g["edges"])
        vlan_g = svc.build_graph(view_mode="VLAN", vlan_number=10)
        assert len(vlan_g["edges"]) >= 1

        view = TopologyView(db=db)
        try:
            assert len(view.canvas.node_items) == 3
            assert STATUS_COLOR_MAP["UP"] == "#10B981"
            assert STATUS_COLOR_MAP["SELECTED"] == "#3B82F6"

            # Select node & verify inspector populates
            node_data = next(n for n in view._current_graph["nodes"] if n["id"] == d1["id"])
            view._on_node_selected(node_data)
            assert view.lbl_host.text() == "ALPHA-CORE"
            assert view.lbl_conn.text() == "2"
            assert view.links_table.rowCount() == 2

            # Move item and save layout, then reload a fresh TopologyView to confirm persistence
            view.canvas.node_items[d1["id"]].setPos(333.0, 222.0)
            view.save_current_layout()
        finally:
            view.shutdown()

        view2 = TopologyView(db=db)
        try:
            pos = view2.canvas.node_items[d1["id"]].pos()
            assert abs(pos.x() - 333.0) < 1.0
            assert abs(pos.y() - 222.0) < 1.0
        finally:
            view2.shutdown()

    def test_07_synthetic_200_node_topology_layout_benchmark(self, tmp_path):
        db = DatabaseManager(str(tmp_path / "topo_200.db"))
        inv = InventoryManager(db)
        for i in range(210):
            inv.add_device({
                "hostname": f"NODE-{i:03d}",
                "management_ip": f"10.50.{i // 200}.{(i % 200) + 1}",
                "category": "Core Switch" if i < 4 else ("Distribution Switch" if i < 20 else "Access Switch"),
                "status": "UP",
            })

        svc = TopologyGraphService(db)
        t0 = time.perf_counter()
        graph = svc.build_graph(view_mode="PHYSICAL")
        positions = svc.compute_auto_layout(graph["nodes"], view_mode="PHYSICAL")
        elapsed = time.perf_counter() - t0

        assert len(graph["nodes"]) == 210
        assert len(positions) == 210
        assert elapsed < 2.0

    def test_08_live_reachability_status_coloring_and_refresh(self, tmp_path, qapp):
        db = DatabaseManager(str(tmp_path / "topo_status.db"))
        inv = InventoryManager(db)
        # Pre-existing stale UNKNOWN devices with real IPs + an IP-less unmanaged placeholder
        d_ok = inv.add_device({"hostname": "GW-01", "management_ip": "10.90.0.1", "category": "Router", "status": "UNKNOWN"})
        d_deg = inv.add_device({"hostname": "WAN-02", "management_ip": "10.90.0.2", "category": "Firewall", "status": "UNKNOWN"})
        d_down = inv.add_device({"hostname": "SW-03", "management_ip": "10.90.0.3", "category": "Access Switch", "status": "UNKNOWN"})
        d_noip = inv.add_device({"hostname": "Unmanaged-01", "management_ip": "UNKNOWN-IP-UNM1", "category": "Access Switch", "status": "UNKNOWN"})

        fake_arp = [
            {"ip": "10.90.0.1", "mac": "00:11:21:00:00:01", "vendor": "Cisco", "entry_type": "dynamic"},
            {"ip": "10.90.0.4", "mac": "70:4C:A5:00:00:04", "vendor": "Ruckus", "entry_type": "dynamic"},
        ]

        def _probe(ip):
            if ip in ("10.90.0.1", "10.90.0.4"):
                return "ONLINE", 2.5
            if ip == "10.90.0.2":
                return "DEGRADED", 240.0
            return "DOWN", None

        engine = TopologyDiscoveryEngine(db)
        summary = asyncio.run(
            engine.discover_topology(
                include_local_arp=False,
                arp_entries=fake_arp,
                probe_icmp=True,
                icmp_probe_fn=_probe,
            )
        )
        assert summary["online_devices"] == 2
        assert summary["degraded_devices"] == 1
        assert summary["down_devices"] == 1

        graph = TopologyGraphService(db).build_graph(view_mode="PHYSICAL")
        by_id = {n["id"]: n for n in graph["nodes"]}
        assert by_id[d_ok["id"]]["status"] == "ONLINE"
        assert by_id[d_ok["id"]]["color"] == STATUS_COLOR_MAP["ONLINE"]  # Green #10B981
        assert by_id[d_deg["id"]]["status"] == "DEGRADED"
        assert by_id[d_deg["id"]]["color"] == STATUS_COLOR_MAP["DEGRADED"]  # Orange #F59E0B
        assert by_id[d_down["id"]]["status"] == "DOWN"
        assert by_id[d_down["id"]]["color"] == STATUS_COLOR_MAP["DOWN"]  # Red #F43F5E
        assert by_id[d_noip["id"]]["status"] == "UNKNOWN"
        assert by_id[d_noip["id"]]["color"] == STATUS_COLOR_MAP["UNKNOWN"]  # Grey #94A3B8

        # On-demand live refresh flips previously down device back ONLINE
        counts = engine.refresh_live_statuses(icmp_probe_fn=lambda ip: ("ONLINE", 1.2))
        assert counts["probed"] == 4
        assert counts["online"] == 4
        assert counts["down"] == 0

        # Ensure TopologyView mounts live check button cleanly
        view = TopologyView(db=db)
        try:
            assert hasattr(view, "check_status_btn")
            assert hasattr(view, "start_status_check")
            assert view.canvas.node_items[d_down["id"]].node_data["status"] == "ONLINE"
        finally:
            view.shutdown()

