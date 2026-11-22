from datetime import date, datetime, timedelta
import json
import os
import sys

import paramiko
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from core.audit_logger import AuditLogger
from core.inventory_manager import DEVICE_CATEGORIES, InventoryManager
from core.oui_lookup import lookup_vendor_by_mac, normalize_mac
from core.site_manager import SiteManager
from utils.db import DatabaseManager, InfrastructureAudit
from utils.infra_security import (
    KnownHostsStore,
    StrictVerifyHostKeyPolicy,
    compute_sha256,
    decrypt_secret,
    encrypt_secret,
    load_encrypted_backup,
    redact_sensitive_text,
    save_encrypted_backup,
    verify_sha256,
)
from utils.snmp_credentials import SNMPCredentials, encrypt_credentials


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app


class TestPhase2InventorySitesAndSecurity:
    def test_08_device_crud_and_all_categories(self, tmp_path):
        db = DatabaseManager(str(tmp_path / "inv.db"))
        audit = AuditLogger(db)
        inv = InventoryManager(db, audit_logger=audit)

        assert len(DEVICE_CATEGORIES) == 11
        site = inv.site_manager.create_site({
            "name": "Paris HQ",
            "organization": "BahaaCorp",
            "region": "Europe-West",
            "address": "10 Rue du Reseau, Paris",
            "network_ranges": ["10.10.0.0/16"],
            "default_gateway": "10.10.0.1",
            "dns_servers": ["10.10.0.53", "1.1.1.1"],
            "isp_name": "Orange Pro",
        })

        created = inv.add_device({
            "hostname": "CORE-SW-01",
            "management_ip": "10.10.0.10",
            "mac_address": "0011.21ab.cdef",  # Cisco OUI in Cisco dot notation
            "model": "C9300-48P",
            "serial_number": "FCW2314A0BC",
            "firmware_version": "17.9.4a",
            "category": "Core Switch",
            "role": "Core Routing",
            "site_id": site["id"],
            "rack_location": "Rack-A1-U10",
            "management_protocol": "SNMP+SSH",
            "tags": ["core", "critical"],
            "device_group": "CoreInfra",
            "custom_fields": {"asset_tag": "IT-0042"},
            "purchase_date": "2024-01-15",
            "warranty_expiration": (date.today() + timedelta(days=15)).strftime("%Y-%m-%d"),
            "equipment_owner": "NetOps Team",
        })

        assert created["mac_address"] == "00:11:21:AB:CD:EF"
        assert created["vendor"] == "Cisco"
        assert created["category"] == "Core Switch"
        assert created["site_name"] == "Paris HQ"
        assert created["custom_fields"]["asset_tag"] == "IT-0042"

        # Maintenance reminders surface expiring warranty
        reminders = inv.get_maintenance_reminders(within_days=30)
        assert len(reminders) == 1
        assert reminders[0]["hostname"] == "CORE-SW-01"
        assert reminders[0]["reminder_kind"] == "WARRANTY"

        # Edit IP -> audit records IP_ADDRESS_MODIFIED
        updated = inv.update_device(created["id"], {"management_ip": "10.10.0.11", "rack_location": "Rack-A1-U12"})
        assert updated["management_ip"] == "10.10.0.11"
        assert updated["rack_location"] == "Rack-A1-U12"

        events = audit.query_events(device_id=created["id"])
        ops = [e["operation"] for e in events]
        assert "IP_ADDRESS_MODIFIED" in ops
        assert "DEVICE_CREATED" in ops
        for ev in events:
            assert audit.verify_record_integrity(ev)

        assert inv.delete_device(created["id"]) is True
        assert inv.get_device(created["id"]) is None
        ops_after = [e["operation"] for e in audit.query_events(device_id=created["id"])]
        assert "DEVICE_DELETED" in ops_after

    def test_09_10_11_csv_import_export_pdf_and_duplicate_detection(self, tmp_path):
        db = DatabaseManager(str(tmp_path / "csv_inv.db"))
        inv = InventoryManager(db)

        csv_in = tmp_path / "import.csv"
        csv_in.write_text(
            "Hostname,Management IP,MAC Address,Category,Site,Rack,Serial Number,Warranty Expiration\n"
            "DIST-SW-01,10.20.1.2,00:24:38:11:22:33,Distribution Switch,Lyon Site,R1,SN-101,2027-06-01\n"
            "ACC-SW-01,10.20.1.3,70:4C:A5:AA:BB:CC,Access Switch,Lyon Site,R2,SN-102,2027-06-01\n"
            "DUP-IP-SW,10.20.1.2,AA:BB:CC:11:22:33,Access Switch,Lyon Site,R3,SN-103,\n"
            ",10.20.1.99,,Other,Lyon Site,,,\n",
            encoding="utf-8",
        )
        res = inv.import_csv(str(csv_in), skip_duplicates=True)
        assert res["imported"] == 2
        assert res["skipped_duplicates"] == 1
        assert len(res["errors"]) == 1

        # Reject duplicate IP by default
        with pytest.raises(ValueError, match="Duplicate management IP"):
            inv.add_device({"hostname": "ROGUE", "management_ip": "10.20.1.2"})

        # Explicit duplicate detection when allow_duplicate_ip=True (e.g., NAT/overlapping lab import)
        inv.add_device(
            {"hostname": "NAT-DUP", "management_ip": "10.20.1.2", "mac_address": "00:24:38:11:22:33"},
            allow_duplicate_ip=True,
        )
        assert "10.20.1.2" in inv.find_duplicate_ips()
        assert "00:24:38:11:22:33" in inv.find_duplicate_macs()

        # Export CSV and PDF
        csv_out = tmp_path / "export.csv"
        pdf_out = tmp_path / "inventory.pdf"
        inv.export_csv(str(csv_out))
        assert csv_out.exists()
        csv_text = csv_out.read_text(encoding="utf-8-sig")
        assert "DIST-SW-01" in csv_text and "Lyon Site" in csv_text

        ok, _ = inv.export_pdf(str(pdf_out))
        assert ok is True
        assert pdf_out.read_bytes().startswith(b"%PDF-")

    def test_12_legacy_sites_migration_and_snmp_host_sync(self, tmp_path):
        db = DatabaseManager(str(tmp_path / "sync.db"))

        class _StubConfig:
            def get(self, key, default=None):
                if key == "sites":
                    return [
                        {"name": "HQ Router", "ip": "192.168.10.1", "site": "Main Office"},
                        {"name": "Branch FW", "ip": "192.168.20.1", "site": "Branch West"},
                    ]
                return default

        sm = SiteManager(db, config_manager=_StubConfig())
        mig1 = sm.migrate_legacy_config_sites()
        mig2 = sm.migrate_legacy_config_sites()  # idempotent
        assert mig1["sites_created"] == 2
        assert mig1["devices_created"] == 2
        assert mig2["sites_created"] == 0 and mig2["devices_created"] == 0

        enc = encrypt_credentials(SNMPCredentials(version="v2c", community="public"))
        db.add_snmp_device({
            "name": "ICX-7150",
            "ip_address": "192.168.10.20",
            "snmp_version": "v2c",
            "encrypted_credentials": enc,
            "vendor": "Ruckus",
            "model": "ICX7150-24P",
            "location": "Main Office",
            "status": "ONLINE",
        })
        db.add_host("8.8.8.8", "Google DNS", category="WAN")

        inv = InventoryManager(db, site_manager=sm)
        sync_res = inv.sync_from_snmp_and_hosts()
        assert sync_res["created"] == 2
        synced_icx = inv.get_device_by_ip("192.168.10.20")
        assert synced_icx is not None
        assert synced_icx["vendor"] == "Ruckus"
        assert synced_icx["site_name"] == "Main Office"
        assert synced_icx["status"] == "ONLINE"

    def test_28_to_31_multisite_hierarchy_dashboard_comparison_and_reports(self, tmp_path):
        db = DatabaseManager(str(tmp_path / "sites.db"))
        sm = SiteManager(db)
        inv = InventoryManager(db, site_manager=sm)

        s_eu = sm.create_site({
            "name": "Brussels Core",
            "organization": "BahaaGroup",
            "region": "EMEA",
            "connectivity_mode": "LOCAL",
            "default_gateway": "10.1.0.1",
            "isp_name": "Belnet",
            "wan_info": {"status": "UP", "bandwidth_mbps": 1000},
        })
        s_vpn = sm.create_site({
            "name": "Casablanca Agency",
            "organization": "BahaaGroup",
            "region": "MEA",
            "connectivity_mode": "VPN",
            "default_gateway": "10.2.0.1",
            "isp_name": "Maroc Telecom",
        })

        inv.add_device({"hostname": "BRU-GW", "management_ip": "10.1.0.1", "category": "Router", "site_id": s_eu["id"], "status": "ONLINE"})
        inv.add_device({"hostname": "BRU-SW1", "management_ip": "10.1.0.2", "category": "Access Switch", "site_id": s_eu["id"], "status": "ONLINE"})
        inv.add_device({"hostname": "CMN-FW", "management_ip": "10.2.0.1", "category": "Firewall", "site_id": s_vpn["id"], "status": "OFFLINE"})

        db.save_measurements_batch([
            {"host_address": "10.1.0.1", "status": "UP", "latency_ms": 4.0, "is_valid_probe": True, "timestamp": datetime.utcnow()},
            {"host_address": "10.1.0.2", "status": "UP", "latency_ms": 6.0, "is_valid_probe": True, "timestamp": datetime.utcnow()},
        ])
        db.create_incident({
            "incident_uid": "INC-CMN-1",
            "host_name": "CMN-FW",
            "host_address": "10.2.0.1",
            "incident_type": "DOWN",
            "severity": "CRITICAL",
            "start_time": datetime.utcnow(),
            "status": "DETECTED",
        })

        hierarchy = sm.get_site_hierarchy()
        assert "BahaaGroup" in hierarchy
        assert "EMEA" in hierarchy["BahaaGroup"] and "MEA" in hierarchy["BahaaGroup"]

        dash_eu = sm.get_site_dashboard(s_eu["id"])
        assert dash_eu["total_devices"] == 2
        assert dash_eu["online_devices"] == 2
        assert dash_eu["availability_pct"] == 100.0
        assert dash_eu["avg_latency_ms"] == 5.0
        assert dash_eu["wan_status"] == "UP"

        dash_vpn = sm.get_site_dashboard(s_vpn["id"])
        assert dash_vpn["offline_devices"] == 1
        assert dash_vpn["active_incidents"] == 1
        assert dash_vpn["connectivity_mode"] == "VPN"

        comp = sm.compare_sites()
        assert len(comp) == 2

        site_pdf = tmp_path / "bru_site.pdf"
        ok, _ = sm.export_site_pdf(s_eu["id"], str(site_pdf))
        assert ok is True and site_pdf.read_bytes().startswith(b"%PDF-")

    def test_32_33_34_dpapi_backup_encryption_known_hosts_redaction_and_audit_immutability(self, tmp_path):
        secret = "SuperS3cr3t!CiscoPass"
        enc = encrypt_secret(secret)
        assert enc.startswith("DPAPI:")
        assert secret not in enc
        assert decrypt_secret(enc) == secret

        # Encrypted backup at rest + SHA-256 tamper detection
        cfg_text = (
            "hostname CORE-RTR-01\n"
            "enable secret 5 $1$xyz$AbCdEfGhIj\n"
            "username netadmin privilege 15 secret MyRawPassword123\n"
            "snmp-server community TopSecretComm RO\n"
        )
        bkp_file = tmp_path / "core_rtr_01.cfg.enc"
        size_b, digest = save_encrypted_backup(cfg_text, str(bkp_file))
        assert size_b == len(cfg_text.encode("utf-8"))
        assert b"MyRawPassword123" not in bkp_file.read_bytes()
        assert b"TopSecretComm" not in bkp_file.read_bytes()
        assert load_encrypted_backup(str(bkp_file), expected_sha256=digest) == cfg_text
        assert verify_sha256(cfg_text + "!", digest) is False

        redacted = redact_sensitive_text(cfg_text, extra_secrets=["MyRawPassword123"])
        assert "MyRawPassword123" not in redacted
        assert "TopSecretComm" not in redacted
        assert "$1$xyz$AbCdEfGhIj" not in redacted

        # Strict SSH host key verification (reject unknown & mismatch, never AutoAddPolicy)
        kh = KnownHostsStore(str(tmp_path / "known_hosts"))
        key1 = paramiko.RSAKey.generate(2048)
        key2 = paramiko.RSAKey.generate(2048)
        assert kh.verify_host_key("10.1.0.1", 22, key1).status == "UNKNOWN"

        strict_policy = StrictVerifyHostKeyPolicy(kh, policy_mode="STRICT")
        dummy_client = paramiko.SSHClient()
        with pytest.raises(paramiko.SSHException, match="Unknown SSH host key"):
            strict_policy.missing_host_key(dummy_client, "10.1.0.1", key1)

        tofu_reject = StrictVerifyHostKeyPolicy(kh, policy_mode="TOFU_CONFIRM", confirm_callback=lambda *_: False)
        with pytest.raises(paramiko.SSHException):
            tofu_reject.missing_host_key(dummy_client, "10.1.0.1", key1)

        tofu_accept = StrictVerifyHostKeyPolicy(kh, policy_mode="TOFU_CONFIRM", confirm_callback=lambda *_: True)
        tofu_accept.missing_host_key(dummy_client, "10.1.0.1", key1)
        assert kh.verify_host_key("10.1.0.1", 22, key1).status == "TRUSTED"
        assert kh.verify_host_key("10.1.0.1", 22, key2).status == "MISMATCH"
        with pytest.raises(paramiko.SSHException, match="MISMATCH"):
            tofu_accept.missing_host_key(dummy_client, "10.1.0.1", key2)

        # Audit table immutability via SQLite triggers + online DB backup
        db_file = tmp_path / "audit_immut.db"
        db = DatabaseManager(str(db_file))
        audit = AuditLogger(db)
        ev = audit.record_event("DEVICE_CREATED", device_name="SW-1", device_ip="10.0.0.5")

        with pytest.raises((OperationalError, IntegrityError)):
            with db.engine.begin() as conn:
                conn.execute(text("UPDATE infrastructure_audit SET result='TAMPERED' WHERE id=:id"), {"id": ev["id"]})

        with pytest.raises((OperationalError, IntegrityError)):
            with db.engine.begin() as conn:
                conn.execute(text("DELETE FROM infrastructure_audit WHERE id=:id"), {"id": ev["id"]})

        db_snap = tmp_path / "db_snapshot.db"
        ok_bkp, _ = db.backup_database(str(db_snap))
        assert ok_bkp is True and db_snap.exists()

    def test_oui_mac_normalization_and_inventory_ui(self, tmp_path, qapp):
        assert normalize_mac("00-24-38-12-34-56") == "00:24:38:12:34:56"
        assert lookup_vendor_by_mac("70:4C:A5:01:02:03") == "Fortinet"
        assert lookup_vendor_by_mac("FF:EE:DD:CC:BB:AA") == "Unknown"

        from ui.widgets.inventory_view import DeviceEditorDialog, InventoryView

        db = DatabaseManager(str(tmp_path / "ui_inv.db"))
        view = InventoryView(logger=None, db=db)
        try:
            view.inventory.add_device({
                "hostname": "RTR-EDGE-1",
                "management_ip": "10.99.0.1",
                "category": "Router",
                "status": "ONLINE",
                "site_name": "DC-North",
            })
            view.refresh_data()
            assert view.table.rowCount() == 1
            assert view.kpi_total.text() == "1"
            assert view.kpi_online.text() == "1"

            view.search_edit.setText("NO-MATCH")
            assert view.table.rowCount() == 0
            view.search_edit.setText("RTR-EDGE")
            assert view.table.rowCount() == 1

            dlg = DeviceEditorDialog(sites=view.site_manager.list_sites(), ssh_profiles=[])
            dlg.hostname_edit.setText("AP-FLOOR2")
            dlg.ip_edit.setText("10.99.0.50")
            payload = dlg.get_payload()
            assert payload["hostname"] == "AP-FLOOR2"
            assert payload["management_ip"] == "10.99.0.50"
            dlg.close()
        finally:
            view.close()
