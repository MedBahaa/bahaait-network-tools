import os
import sys

import paramiko
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from core.audit_logger import AuditLogger
from core.inventory_manager import InventoryManager
from core.site_manager import SiteManager
from core.ssh_access import DeviceAccessService, SSHProfileManager, classify_command_tier
from ui.widgets.audit_view import AuditView
from ui.widgets.remote_view import RemoteView
from ui.widgets.sites_view import SitesView
from utils.db import DatabaseManager


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app


class TestPhase6To8AccessAuditAndSecurity:
    def test_24_25_command_classification_and_guarded_execution(self, tmp_path):
        db = DatabaseManager(str(tmp_path / "access.db"))
        audit = AuditLogger(db)
        inv = InventoryManager(db, audit_logger=audit)
        sw = inv.add_device({
            "hostname": "CORE-C9300",
            "management_ip": "10.4.0.1",
            "vendor": "Cisco",
            "category": "Core Switch",
        })
        svc = DeviceAccessService(db, audit_logger=audit, known_hosts_path=str(tmp_path / "kh"))

        # Classification accuracy & conservative default
        assert classify_command_tier("show version", "cisco_ios")[0] == "READ_ONLY"
        assert classify_command_tier("get system status", "fortinet_fortigate")[0] == "READ_ONLY"
        assert classify_command_tier("configure terminal", "cisco_ios")[0] == "MODIFYING"
        assert classify_command_tier("custom_unknown_cmd", "generic_ssh")[0] == "MODIFYING"
        assert classify_command_tier("reload", "cisco_ios")[0] == "DESTRUCTIVE"
        assert classify_command_tier("no vlan 10", "cisco_ios")[0] == "DESTRUCTIVE"
        assert classify_command_tier("show run; rm -rf /", "generic_ssh")[0] != "READ_ONLY"

        # READ_ONLY runs directly with automatic secret redaction in output & audit
        r_ro = svc.execute_command_guarded(
            sw,
            "show running-config",
            executor=lambda _d, _c: (True, "snmp-server community SecretCommRO RO\nenable secret 5 $1$xyz$Pass123"),
        )
        assert r_ro["status"] == "SUCCESS"
        assert "SecretCommRO" not in r_ro["output"]
        assert "$1$xyz$Pass123" not in r_ro["output"]

        # MODIFYING & DESTRUCTIVE refuse without explicit confirmation & write BLOCKED audit
        with pytest.raises(PermissionError, match="MODIFYING"):
            svc.execute_command_guarded(sw, "configure terminal", confirmed=False, executor=lambda _d, _c: (True, "OK"))
        with pytest.raises(PermissionError, match="DESTRUCTIVE"):
            svc.execute_command_guarded(sw, "reload", confirmed=False, executor=lambda _d, _c: (True, "OK"))

        blocked = audit.query_events(device_id=sw["id"], result="BLOCKED")
        assert len(blocked) == 2

        # Confirmed execution succeeds and records SHA-256 verified audit event
        r_ok = svc.execute_command_guarded(
            sw,
            "write memory",
            confirmed=True,
            executor=lambda _d, _c: (True, "Building configuration... [OK]"),
            ticket_ref="CHG-900",
        )
        assert r_ok["status"] == "SUCCESS"
        evs = audit.query_events(device_id=sw["id"], search="CHG-900")
        assert len(evs) == 1
        assert audit.verify_record_integrity(evs[0]) is True

    def test_26_ssh_profile_dpapi_known_hosts_rdp_and_no_autoadd(self, tmp_path):
        db = DatabaseManager(str(tmp_path / "prof.db"))
        audit = AuditLogger(db)
        pm = SSHProfileManager(db, audit_logger=audit)

        created = pm.create_profile({
            "name": "Cisco Core Admin",
            "vendor_profile": "cisco_ios",
            "port": 22,
            "username": "netops",
            "auth_method": "PASSWORD",
            "secret": "UltraSecretSSHPass!",
            "host_key_policy": "STRICT",
        })
        assert "secret" not in created
        assert created["has_secret"] is True
        listing = pm.list_profiles()
        assert len(listing) == 1 and "secret" not in listing[0]

        full = pm.get_profile(created["id"], include_secret=True)
        assert full["secret"] == "UltraSecretSSHPass!"
        # Audit log must never leak the SSH profile secret
        all_aud = audit.query_events()
        assert all("UltraSecretSSHPass!" not in str(a) for a in all_aud)

        # KnownHosts strict policy + MITM key mismatch rejection
        svc = DeviceAccessService(db, audit_logger=audit, known_hosts_path=str(tmp_path / "kh2"))
        key1 = paramiko.RSAKey.generate(2048)
        key2 = paramiko.RSAKey.generate(2048)
        svc.known_hosts.trust_host_key("10.10.1.1", 22, key1)
        assert svc.known_hosts.verify_host_key("10.10.1.1", 22, key1).status == "TRUSTED"
        assert svc.known_hosts.verify_host_key("10.10.1.1", 22, key2).status == "MISMATCH"

        strict = svc.create_host_key_policy("STRICT", port=22)
        with pytest.raises(paramiko.SSHException, match="MISMATCH"):
            strict.missing_host_key(paramiko.SSHClient(), "10.10.1.1", key2)

        # RDP arg builder & injection block + redacted log export
        assert svc.build_rdp_launch_args("10.10.1.50") == ["mstsc", "/v:10.10.1.50"]
        assert svc.build_rdp_launch_args("10.10.1.50", 3390) == ["mstsc", "/v:10.10.1.50:3390"]
        with pytest.raises(ValueError, match="Invalid target host"):
            svc.build_rdp_launch_args("10.10.1.50 & calc.exe")

        log_path = tmp_path / "sess.txt"
        svc.export_session_log(
            ["enable secret 5 $1$aa$SecretHash", "password MyInlinePass"],
            str(log_path),
            extra_secrets=["MyInlinePass"],
        )
        saved_log = log_path.read_text(encoding="utf-8")
        assert "SecretHash" not in saved_log and "MyInlinePass" not in saved_log

        # Static verification that AutoAddPolicy is never used anywhere in production SSH code
        for rel in ("src/ui/widgets/remote_view.py", "src/core/backup_adapters.py"):
            txt = open(os.path.join(ROOT_DIR, rel), "r", encoding="utf-8").read()
            assert "AutoAddPolicy" not in txt

    def test_27_ui_remote_sites_and_audit_views(self, tmp_path, qapp):
        db = DatabaseManager(str(tmp_path / "ui_rsa.db"))
        sm = SiteManager(db)
        site = sm.create_site({"name": "HQ Lyon", "organization": "BahaaOrg", "region": "EMEA"})
        inv = InventoryManager(db, site_manager=sm)
        dev = inv.add_device({"hostname": "LYON-SW01", "management_ip": "10.8.0.1", "vendor": "Cisco", "category": "Access Switch", "site_id": site["id"], "status": "ONLINE"})

        rv = RemoteView(db=db)
        try:
            rv.open_device(dev)
            assert rv.host_edit.text() == "10.8.0.1"
            assert rv.session_tabs.count() >= 1
        finally:
            rv.shutdown()

        sv = SitesView(db=db)
        try:
            assert sv.dev_table.rowCount() == 1
            assert sv.comp_table.rowCount() == 1
        finally:
            sv.shutdown()

        av = AuditView(db=db)
        try:
            assert av.table.rowCount() >= 2  # SITE_CREATED + DEVICE_CREATED
            assert av.table.item(0, 9).text() == "VALID"
        finally:
            av.shutdown()
