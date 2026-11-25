import os
import sys
import time

import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from core.backup_manager import BackupManager
from core.inventory_manager import InventoryManager
from core.site_manager import SiteManager
from core.topology_graph import VIEW_MODES, TopologyGraphService
from utils.db import DatabaseManager, InfrastructureDevice
from utils.i18n import TranslationManager
from utils.updater import CURRENT_VERSION


class TestV360BenchmarksAndWiring:
    def test_synthetic_scale_benchmarks_1000_devices_250_nodes_25_sites_50_backups(self, tmp_path):
        db = DatabaseManager(str(tmp_path / "bench.db"))
        sm = SiteManager(db)
        inv = InventoryManager(db, site_manager=sm)

        # 1. Create 25 sites across 5 regions
        sites = []
        t0_sites = time.perf_counter()
        for i in range(25):
            sites.append(
                sm.create_site({
                    "name": f"Site-{i:02d}",
                    "organization": "BahaaGlobal",
                    "region": f"Region-{i % 5}",
                    "connectivity_mode": "VPN" if i else "LOCAL",
                })
            )
        t_sites_create = time.perf_counter() - t0_sites

        # 2. Bulk insert 1,000 inventory devices and time query + duplicate scan + CSV export
        t0_inv = time.perf_counter()
        with db.Session() as session:
            objs = [
                InfrastructureDevice(
                    device_uid=f"DEV-BENCH-{i:04d}",
                    site_id=sites[i % 25]["id"],
                    hostname=f"NODE-{i:04d}",
                    management_ip=f"10.{(i // 250) + 1}.{(i % 250) + 1}.{(i % 200) + 1}",
                    mac_address=f"00:11:21:{(i >> 16) & 0xFF:02X}:{(i >> 8) & 0xFF:02X}:{i & 0xFF:02X}",
                    vendor="Cisco",
                    category="Core Switch" if i < 10 else ("Distribution Switch" if i < 50 else "Access Switch"),
                    status="ONLINE" if i % 10 != 0 else "DEGRADED",
                )
                for i in range(1000)
            ]
            session.add_all(objs)
            session.commit()
        t_inv_insert = time.perf_counter() - t0_inv

        t0_q = time.perf_counter()
        res_devs = inv.list_devices(search="NODE-05", limit=1000)
        dup_ips = inv.find_duplicate_ips()
        csv_path = tmp_path / "bench_inv.csv"
        inv.export_csv(str(csv_path))
        t_inv_ops = time.perf_counter() - t0_q
        assert len(res_devs) >= 10
        assert isinstance(dup_ips, dict)
        assert csv_path.exists()

        # 3. 250-node Topology graph + layout benchmark across all 4 view modes
        svc = TopologyGraphService(db)
        with db.Session() as session:
            # Query limited 250 nodes via site filter (10 sites = 400 -> take 250 subset directly)
            g_all = svc.build_graph(view_mode="PHYSICAL")
        sample_250 = g_all["nodes"][:250]
        t0_topo = time.perf_counter()
        for m in VIEW_MODES:
            pos = svc.compute_auto_layout(sample_250, view_mode=m)
            assert len(pos) == 250
        t_topo_layout = time.perf_counter() - t0_topo

        # 4. 25-site multi-site comparison benchmark
        t0_cmp = time.perf_counter()
        comp = sm.compare_sites()
        t_site_cmp = time.perf_counter() - t0_cmp
        assert len(comp) == 25

        # 5. 50-device encrypted backup batch + SHA-256 verification benchmark
        dev_ids = [d["id"] for d in inv.list_devices(limit=50)]
        bm = BackupManager(db, base_dir=str(tmp_path / "bkpvault"))

        def _fast_ssh(host, port, user, pwd, key, cmds, kh):
            return 0, f"hostname DEV-{host}\nvlan 10\ninterface Gi1/0/1\n", ""

        t0_bkp = time.perf_counter()
        batch = bm.backup_devices(dev_ids, ssh_transport=_fast_ssh)
        t_bkp_batch = time.perf_counter() - t0_bkp
        assert batch["succeeded"] == 50

        print(
            f"[BENCHMARK v3.6.0] 1000-Dev Insert={t_inv_insert:.3f}s | Query+Dup+CSV={t_inv_ops:.3f}s | "
            f"250-Node 4-Mode Layout={t_topo_layout:.3f}s | 25-Site Compare={t_site_cmp:.3f}s (Create={t_sites_create:.3f}s) | "
            f"50-Dev DPAPI+SHA256 Backup={t_bkp_batch:.3f}s"
        )
        assert t_inv_insert < 5.0
        assert t_inv_ops < 5.0
        assert t_topo_layout < 2.0
        assert t_site_cmp < 5.0
        assert t_bkp_batch < 15.0

    def test_v360_i18n_parity_mainwindow_and_packaging(self):
        tm = TranslationManager()
        en_keys = set(tm.translations["en"].keys())
        fr_keys = set(tm.translations["fr"].keys())
        assert en_keys == fr_keys, f"i18n mismatch: en-fr={en_keys - fr_keys}, fr-en={fr_keys - en_keys}"

        assert CURRENT_VERSION == "v3.6.1"

        iss_path = os.path.join(ROOT_DIR, "build_scripts", "setup_compiler.iss")
        with open(iss_path, "r", encoding="utf-8") as fh:
            iss_txt = fh.read()
        assert "AppVersion=3.6.1" in iss_txt
        assert "OutputBaseFilename=Install_BahaaIT_v3.6.1" in iss_txt

        rn36 = os.path.join(ROOT_DIR, "RELEASE_NOTES_v3.6.0.md")
        assert os.path.exists(rn36)
        assert "Roadmap 03" in open(rn36, "r", encoding="utf-8").read()

        mw_path = os.path.join(ROOT_DIR, "src", "ui", "main_window.py")
        mw_txt = open(mw_path, "r", encoding="utf-8").read()
        assert "group_infrastructure" in mw_txt
        for idx, view_cls in [
            (14, "TopologyView"),
            (15, "InventoryView"),
            (16, "VLANView"),
            (17, "BackupView"),
            (18, "AuditView"),
        ]:
            assert f"elif index == {idx}" in mw_txt and view_cls in mw_txt
        assert "range(18)" in mw_txt
        assert "list(range(1, 19))" in mw_txt
