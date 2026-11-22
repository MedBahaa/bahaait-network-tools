import os
import sys

import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from core.audit_logger import AuditLogger
from core.backup_manager import BackupManager
from core.config_diff import compute_config_diff, export_diff_html, export_diff_text
from core.config_templates import apply_template, list_templates, render_template_preview
from core.inventory_manager import InventoryManager
from core.site_manager import SiteManager
from core.vlan_manager import (
    VLANManager,
    parse_cisco_show_vlan,
    parse_fortigate_vlan,
    parse_ruckus_show_vlan,
)
from ui.widgets.backup_view import BackupView
from ui.widgets.vlan_view import VLANView
from utils.db import DatabaseManager, NetworkLink
from utils.snmp_credentials import SNMPCredentials, encrypt_credentials


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app


class TestPhase4And5VlanBackupTemplates:
    def test_13_14_vlan_snmp_sync_vendor_parsers_and_inconsistencies(self, tmp_path):
        db = DatabaseManager(str(tmp_path / "vlan.db"))
        sm = SiteManager(db)
        site = sm.create_site({"name": "HQ Paris", "region": "EU"})
        inv = InventoryManager(db, site_manager=sm)

        # Linked SNMP switch -> sync_from_snmp
        enc = encrypt_credentials(SNMPCredentials(version="v2c", community="public"))
        snmp_id = db.add_snmp_device({
            "name": "CORE-C9300",
            "ip_address": "10.1.0.1",
            "snmp_version": "v2c",
            "encrypted_credentials": enc,
            "vendor": "Cisco",
            "status": "ONLINE",
        })["id"]
        db.upsert_snmp_vlans(snmp_id, [
            {"vlan_id": 10, "name": "CORP_USERS", "status": "ACTIVE", "untagged_ports": ["Gi1/0/1"], "tagged_ports": [], "trunk_ports": ["Gi1/0/48"]},
            {"vlan_id": 20, "name": "GUEST_WIFI", "status": "ACTIVE", "untagged_ports": [], "tagged_ports": ["Gi1/0/48"], "trunk_ports": ["Gi1/0/48"]},
        ])

        c9300 = inv.add_device({
            "hostname": "CORE-C9300",
            "management_ip": "10.1.0.1",
            "vendor": "Cisco",
            "category": "Core Switch",
            "site_id": site["id"],
            "snmp_device_id": snmp_id,
        })
        icx = inv.add_device({
            "hostname": "ACC-ICX-02",
            "management_ip": "10.1.0.2",
            "vendor": "Ruckus",
            "model": "ICX7150",
            "category": "Access Switch",
            "site_id": site["id"],
        })
        fgt = inv.add_device({
            "hostname": "FW-FGT-01",
            "management_ip": "10.1.0.254",
            "vendor": "Fortinet",
            "model": "FortiGate-100F",
            "category": "Firewall",
            "site_id": site["id"],
        })

        vm = VLANManager(db)
        sync = vm.sync_from_snmp()
        assert sync["vlans_synced"] == 2

        # Ruckus ICX CLI parse (note: VLAN 10 intentionally named differently to trigger NAME_MISMATCH)
        ruckus_cli = (
            "PORT-VLAN 10, Name USERS_ALT, Priority level0\n"
            " Untagged Ports: ethe 1/1/1 ethe 1/1/2\n"
            " Tagged Ports: ethe 1/1/24\n"
        )
        vm.import_cli_vlans(icx["id"], ruckus_cli)

        # FortiGate CLI parse
        fgt_cli = (
            "config system interface\n"
            '  edit "corp_vlan10"\n'
            '    set interface "port1"\n'
            "    set vlanid 10\n"
            "  next\n"
            '  edit "voice_vlan30"\n'
            '    set interface "port1"\n'
            "    set vlanid 30\n"
            "    set status down\n"
            "  next\n"
            "end\n"
        )
        fgt_parsed = parse_fortigate_vlan(fgt_cli)
        assert [x["vlan_number"] for x in fgt_parsed] == [10, 30]
        vm.import_cli_vlans(fgt["id"], fgt_cli)

        # Cisco CLI parser direct check
        cisco_parsed = parse_cisco_show_vlan(
            "10   CORP_USERS   active    Gi1/0/5, Gi1/0/6\n"
            "99   DEAD_VLAN    suspend   Gi1/0/9\n"
        )
        assert cisco_parsed[0]["untagged_ports"] == ["Gi1/0/5", "Gi1/0/6"]
        assert cisco_parsed[1]["status"] == "SUSPEND"

        # Add trunk link carrying VLAN 20 between CORE-C9300 (has 20) and ACC-ICX-02 (missing 20)
        with db.Session() as session:
            session.add(NetworkLink(
                source_device_id=c9300["id"],
                dest_device_id=icx["id"],
                source_interface="Gi1/0/48",
                dest_interface="1/1/24",
                link_type="TRUNK",
                discovery_method="LLDP",
                confidence="HIGH",
                vlan_ids_json="[10, 20]",
            ))
            session.commit()

        warns = vm.detect_inconsistencies(site_id=site["id"])
        kinds = {w["kind"] for w in warns}
        assert "NAME_MISMATCH" in kinds
        assert "TRUNK_VLAN_GAP" in kinds

    def test_15_16_vendor_vlan_plans_and_confirmation_enforcement(self, tmp_path):
        db = DatabaseManager(str(tmp_path / "vlan_plan.db"))
        audit = AuditLogger(db)
        inv = InventoryManager(db, audit_logger=audit)
        vm = VLANManager(db, audit_logger=audit)

        c_sw = inv.add_device({"hostname": "CISCO-01", "management_ip": "10.2.0.1", "vendor": "Cisco", "category": "Access Switch"})
        r_sw = inv.add_device({"hostname": "RUCKUS-01", "management_ip": "10.2.0.2", "vendor": "Ruckus", "category": "Access Switch"})
        unk = inv.add_device({"hostname": "MYSTERY-01", "management_ip": "10.2.0.9", "vendor": "Unknown", "category": "Other"})

        # Vendor-specific CLI plans must differ accurately
        plan_c = vm.build_change_plan(c_sw["id"], "ASSIGN_ACCESS_PORT", {"vlan_id": 25, "port": "Gi1/0/10"})
        plan_r = vm.build_change_plan(r_sw["id"], "ASSIGN_ACCESS_PORT", {"vlan_id": 25, "port": "1/1/10"})
        assert "switchport access vlan 25" in "\n".join(plan_c["commands"])
        assert "untagged ethernet 1/1/10" in "\n".join(plan_r["commands"])

        # Refuse unknown vendor compatibility assumption & VLAN 1 deletion & CLI injection
        with pytest.raises(ValueError, match="no verified VLAN CLI profile"):
            vm.build_change_plan(unk["id"], "CREATE_VLAN", {"vlan_id": 25, "vlan_name": "DATA"})
        with pytest.raises(ValueError, match="VLAN 1"):
            vm.build_change_plan(c_sw["id"], "DELETE_VLAN", {"vlan_id": 1})
        with pytest.raises(ValueError, match="Invalid characters"):
            vm.build_change_plan(c_sw["id"], "CREATE_VLAN", {"vlan_id": 30, "vlan_name": "DATA; reload"})

        # Unconfirmed execution must be refused & audited
        with pytest.raises(PermissionError):
            vm.apply_change_plan(plan_c, confirmed=False, executor=lambda _p, _c: (True, "OK"))
        blocked = [e for e in audit.query_events(device_id=c_sw["id"]) if e["result"] == "BLOCKED"]
        assert len(blocked) == 1

        # Confirmed execution succeeds and updates DB & audit
        executed = []
        res = vm.apply_change_plan(
            plan_c,
            confirmed=True,
            executor=lambda p, cmds: (executed.append(cmds) is None, "Configured"),
            ticket_ref="CHG-201",
        )
        assert res["status"] == "SUCCESS"
        assert len(executed) == 1
        vlans = vm.list_vlans(device_id=c_sw["id"], vlan_number=25)
        assert len(vlans) == 1 and "Gi1/0/10" in vlans[0]["untagged_ports"]

    def test_17_to_23_backups_encryption_tamper_diff_restore_and_templates(self, tmp_path):
        db = DatabaseManager(str(tmp_path / "bkp.db"))
        audit = AuditLogger(db)
        sm = SiteManager(db, audit_logger=audit)
        site = sm.create_site({"name": "DC-North", "region": "EU"})
        inv = InventoryManager(db, audit_logger=audit, site_manager=sm)

        c_sw = inv.add_device({"hostname": "DIST-C9200", "management_ip": "10.3.0.1", "vendor": "Cisco", "model": "C9200", "site_id": site["id"]})
        r_sw = inv.add_device({"hostname": "EDGE-ICX", "management_ip": "10.3.0.2", "vendor": "Ruckus", "model": "ICX7150", "site_id": site["id"]})
        down_sw = inv.add_device({"hostname": "OFFLINE-FGT", "management_ip": "10.3.0.3", "vendor": "Fortinet", "site_id": site["id"]})

        cfg_v1 = (
            "version 17.9\n"
            "hostname DIST-C9200\n"
            "enable secret 5 $1$abc$SecretHashValue123\n"
            "vlan 10\n"
            " name CORP\n"
            "interface GigabitEthernet1/0/1\n"
            " switchport access vlan 10\n"
            "snmp-server community MySuperSecretComm RO\n"
        )
        cfg_v2 = (
            "version 17.9\n"
            "hostname DIST-C9200\n"
            "enable secret 5 $1$abc$NewSecretHash999\n"
            "vlan 10\n"
            " name CORP\n"
            "vlan 20\n"
            " name VOICE\n"
            "interface GigabitEthernet1/0/1\n"
            " switchport access vlan 20\n"
            "ip route 0.0.0.0 0.0.0.0 10.3.0.254\n"
            "snmp-server community MySuperSecretComm RO\n"
        )
        state = {"cfg": cfg_v1, "restored": []}

        def _mock_ssh(host, port, user, pwd, key, cmds, kh):
            if host == "10.3.0.3":
                return 1, "", "Connection timed out"
            if any("show running-config" in c for c in cmds):
                if host == "10.3.0.2":
                    return 0, "ver 08.0.95\nhostname EDGE-ICX\nvlan 10\n", ""
                return 0, state["cfg"], ""
            state["restored"].append((host, cmds))
            return 0, "Applied", ""

        bm = BackupManager(db, audit_logger=audit, base_dir=str(tmp_path / "vault"))

        # Batch backup across site isolates unreachable 10.3.0.3 without failing others
        batch = bm.backup_site(site["id"], ssh_transport=_mock_ssh)
        assert batch["total"] == 3
        assert batch["succeeded"] == 2
        assert batch["failed"] == 1

        # Verify DPAPI encryption on disk (plaintext secret must never appear on disk!)
        b1 = bm.list_backups(device_id=c_sw["id"])[0]
        raw_disk = open(b1["file_path"], "rb").read()
        assert raw_disk.startswith(b"BHITENC1:")
        assert b"DIST-C9200" not in raw_disk
        assert b"MySuperSecretComm" not in raw_disk

        # Second backup with modified config records ConfigurationChange automatically & redacts secrets
        state["cfg"] = cfg_v2
        b2 = bm.backup_device(c_sw["id"], ssh_transport=_mock_ssh)
        changes = bm.list_changes(device_id=c_sw["id"])
        assert len(changes) == 1
        assert "MySuperSecretComm" not in changes[0]["unified_diff_redacted"]

        # Visual Diff + Export HTML/TXT
        diff = bm.compare_backups(b1["id"], b2["id"])
        assert diff["has_changes"] is True
        assert "VLANS" in diff["changed_sections"]
        assert "ROUTING" in diff["changed_sections"]
        assert "MySuperSecretComm" not in diff["unified_diff"]
        html_out = tmp_path / "diff.html"
        txt_out = tmp_path / "diff.txt"
        export_diff_html(diff, str(html_out))
        export_diff_text(diff, str(txt_out))
        assert "VLANS" in html_out.read_text(encoding="utf-8")
        assert "+vlan 20" in txt_out.read_text(encoding="utf-8")

        # Controlled Restore guards:
        # 1. Wrong vendor blocked
        with pytest.raises(ValueError, match="Incompatible backup adapter"):
            bm.prepare_restore_plan(b1["id"], r_sw["id"])

        # 2. Unconfirmed restore refused + audited
        plan = bm.prepare_restore_plan(b1["id"], c_sw["id"])
        with pytest.raises(PermissionError):
            bm.restore_backup(plan, confirmed=False, ssh_transport=_mock_ssh)

        # 3. Confirmed restore captures mandatory PRE_RESTORE snapshot first & restores
        res_r = bm.restore_backup(plan, confirmed=True, ssh_transport=_mock_ssh, ticket_ref="CHG-RES-1")
        assert res_r["status"] == "SUCCESS"
        assert res_r["pre_restore_backup"]["status"] == "PRE_RESTORE"
        assert len(state["restored"]) == 1

        # 4. Tamper detection on disk fails integrity & blocks restore
        with open(b1["file_path"], "ab") as fh:
            fh.write(b"TAMPER")
        ok_int, _msg = bm.verify_backup_integrity(b1["id"])
        assert ok_int is False
        with pytest.raises(ValueError, match="Integrity check failed"):
            bm.prepare_restore_plan(b1["id"], c_sw["id"])

        # Config Templates (Scenario 23)
        assert len(list_templates()) >= 8
        with pytest.raises(ValueError, match="requires vendor profile"):
            render_template_preview("ruckus_icx_base", c_sw, {})
        prev_tpl = render_template_preview(
            "cisco_snmpv3_monitor",
            c_sw,
            {"group_name": "MON", "username": "svc", "auth_pass": "SuperAuth99!", "priv_pass": "SuperPriv99!"},
        )
        assert "SuperAuth99!" in prev_tpl["rendered_text"]
        with pytest.raises(PermissionError):
            apply_template(prev_tpl, confirmed=False, executor=lambda _p, _c: (True, "OK"), audit_logger=audit)
        res_tpl = apply_template(
            prev_tpl,
            confirmed=True,
            executor=lambda _p, cmds: (True, "Done"),
            audit_logger=audit,
            ticket_ref="CHG-TPL-7",
        )
        assert res_tpl["status"] == "SUCCESS"
        # Audit logger must redact the SNMPv3 passphrases!
        tpl_events = [e for e in audit.query_events(device_id=c_sw["id"]) if "TEMPLATE_" in e["operation"]]
        assert tpl_events and "SuperAuth99!" not in str(tpl_events[0]["new_value"])

    def test_ui_vlan_and_backup_views(self, tmp_path, qapp):
        db = DatabaseManager(str(tmp_path / "ui_vb.db"))
        inv = InventoryManager(db)
        sw = inv.add_device({"hostname": "UI-SW-01", "management_ip": "10.9.0.1", "vendor": "Cisco", "category": "Access Switch"})

        vview = VLANView(db=db)
        try:
            vview.plan_vid_edit.setText("40")
            vview.plan_vname_edit.setText("SERVERS")
            plan = vview._generate_preview()
            assert plan is not None
            assert "vlan 40" in vview.plan_cli_box.toPlainText()
        finally:
            vview.shutdown()

        def _mock_ssh(host, port, user, pwd, key, cmds, kh):
            return 0, "hostname UI-SW-01\nvlan 40\n", ""

        bview = BackupView(db=db, base_dir=str(tmp_path / "uivault"), ssh_transport=_mock_ssh)
        try:
            bview.manager.backup_device(sw["id"], ssh_transport=_mock_ssh)
            bview.refresh()
            assert bview.bkp_table.rowCount() == 1
        finally:
            bview.shutdown()
