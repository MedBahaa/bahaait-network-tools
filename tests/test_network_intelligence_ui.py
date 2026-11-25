import csv
from datetime import datetime, timedelta
import json
import logging
import os
import socket
import sqlite3
import sys
import time
from unittest.mock import patch

import pytest
from PySide6.QtWidgets import QApplication, QLineEdit, QMessageBox

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.snmp_client import SNMPDiscoveryResult
from core.syslog_server import SyslogServer
from ui.widgets.dashboard_view import DashboardView
from ui.widgets.device_details_view import DeviceDetailsDialog
from ui.widgets.intelligence_view import IntelligenceView
from ui.widgets.snmp_view import AddSNMPDeviceDialog, SNMPView
from ui.widgets.syslog_view import SyslogView
from utils.config import ConfigManager
from utils.db import DatabaseManager
from utils.i18n import TranslationManager
from utils.snmp_credentials import SNMPCredentials, encrypt_credentials
from utils.updater import CURRENT_VERSION


_qapp = QApplication.instance() or QApplication(sys.argv)


def _dummy_logger() -> logging.Logger:
    return logging.getLogger("test_ni_ui")


class TestNetworkIntelligenceUI:
    def test_i18n_parity_en_fr_and_v350_keys(self):
        tm = TranslationManager()
        en_keys = set(tm.translations["en"].keys())
        fr_keys = set(tm.translations["fr"].keys())
        assert en_keys == fr_keys

        required_v350_keys = [
            "nav_snmp_infra",
            "nav_syslog_monitor",
            "nav_intelligence",
            "snmp_title",
            "devdet_tab_overview",
            "devdet_tab_poe",
            "devdet_tab_vlans",
            "syslog_title",
            "intel_title",
            "intel_panel_evidence",
            "intel_panel_cause",
            "dash_snmp_devices",
            "dash_chart_cpu",
        ]
        for k in required_v350_keys:
            assert k in en_keys and tm.translations["en"][k].strip()
            assert k in fr_keys and tm.translations["fr"][k].strip()

    def test_snmp_view_and_add_dialog_discovery_and_secret_masking(self, tmp_path):
        dlg = AddSNMPDeviceDialog()
        try:
            assert dlg.community_edit.echoMode() == QLineEdit.Password
            assert dlg.v3_auth_pass.echoMode() == QLineEdit.Password
            assert dlg.v3_priv_pass.echoMode() == QLineEdit.Password

            # Verify v2c vs v3 security level toggles cleanly
            dlg.version_combo.setCurrentText("v3")
            dlg.v3_sec_combo.setCurrentText("noAuthNoPriv")
            assert dlg.v3_auth_pass.isEnabled() is False
            assert dlg.v3_priv_pass.isEnabled() is False

            dlg.v3_sec_combo.setCurrentText("authNoPriv")
            assert dlg.v3_auth_pass.isEnabled() is True
            assert dlg.v3_priv_pass.isEnabled() is False

            dlg.v3_sec_combo.setCurrentText("authPriv")
            assert dlg.v3_auth_pass.isEnabled() is True
            assert dlg.v3_priv_pass.isEnabled() is True

            # Switch back to v2c, simulate discovery & verify zero credential leaks
            dlg.version_combo.setCurrentText("v2c")
            dlg.ip_edit.setText("10.80.1.10")
            dlg.community_edit.setText("SuperSecretVaultKey!")
            disc = SNMPDiscoveryResult(
                ip_address="10.80.1.10",
                port=161,
                snmp_version="v2c",
                reachable=True,
                rtt_ms=11.5,
                sys_descr="Cisco IOS Software, C9200L-48P",
                sys_object_id="1.3.6.1.4.1.9.1.2500",
                sys_name="SW-LAB-01",
                sys_location="Rack-B2",
                vendor="Cisco",
                model="C9200L-48P",
                firmware="17.6.3",
                device_type="Switch",
                profile_name="cisco_catalyst",
                capabilities={"interfaces": True, "cpu": True, "memory": True, "temperature": True, "poe": True, "vlans": True},
            )
            dlg._on_discovery_finished(disc)
            assert "Cisco" in dlg.disc_banner.text()
            assert "SuperSecretVaultKey!" not in dlg.disc_banner.text()
            assert dlg.name_edit.text() == "SW-LAB-01"

            dlg._on_save()
            payload = dlg.get_device_data()
            assert payload is not None
        finally:
            dlg.close()

        db_file = str(tmp_path / "snmp_ui.db")
        db = DatabaseManager(db_path=db_file)
        added_cisco = db.add_snmp_device(payload)
        assert added_cisco is not None

        conn = sqlite3.connect(db_file)
        raw_text = str(conn.execute("SELECT * FROM snmp_devices").fetchall())
        conn.close()
        assert "SuperSecretVaultKey!" not in raw_text

        # Seed second device + metrics + interfaces and test SNMPView
        lin_enc = encrypt_credentials(SNMPCredentials(version="v2c", community="srv_secret"))
        added_srv = db.add_snmp_device({
            "name": "SRV-APP-01",
            "ip_address": "10.80.1.20",
            "snmp_version": "v2c",
            "encrypted_credentials": lin_enc,
            "vendor": "Linux",
            "device_type": "Server",
            "profile_name": "snmp_server",
            "status": "DEGRADED",
        })
        now = datetime.utcnow()
        db.save_snmp_metrics_batch([
            {"device_id": added_cisco["id"], "metric_name": "cpu_pct", "metric_value": 24.0, "unit": "%", "timestamp": now},
            {"device_id": added_cisco["id"], "metric_name": "memory_pct", "metric_value": 48.0, "unit": "%", "timestamp": now},
            {"device_id": added_srv["id"], "metric_name": "cpu_pct", "metric_value": 84.0, "unit": "%", "timestamp": now},
            {"device_id": added_srv["id"], "metric_name": "memory_pct", "metric_value": 72.0, "unit": "%", "timestamp": now},
        ])
        db.upsert_snmp_interfaces(added_cisco["id"], [
            {"if_index": 1, "name": "Gi1/0/1", "admin_status": "UP", "oper_status": "UP", "speed_bps": 1_000_000_000}
        ])

        view = SNMPView(_dummy_logger(), db=db)
        try:
            view.refresh_devices()
            assert view.kpi_total.text() == "2"
            assert view.kpi_online.text() == "1"
            assert view.kpi_degraded.text() == "1"
            assert view.kpi_offline.text() == "0"
            assert view.kpi_cpu.text() == "54.0%"
            assert view.kpi_mem.text() == "60.0%"
            assert view.table.rowCount() == 2

            view.search_edit.setText("SRV-APP")
            assert view.table.rowCount() == 1
            view.search_edit.clear()
            idx_deg = view.status_filter.findData("DEGRADED")
            view.status_filter.setCurrentIndex(idx_deg)
            assert view.table.rowCount() == 1
        finally:
            view.shutdown()
            view.close()

    def test_device_details_dialog_10_tabs_and_capability_gating(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "dev_details.db"))
        now = datetime.utcnow()

        # Device A: Full PoE + VLAN Cisco switch
        creds_a = SNMPCredentials(version="v2c", community="VerySecretCommunityA!")
        dev_a = db.add_snmp_device({
            "name": "SW-POE-CORE",
            "ip_address": "10.81.0.1",
            "snmp_version": "v2c",
            "encrypted_credentials": encrypt_credentials(creds_a),
            "vendor": "Cisco",
            "model": "C9200L-48P",
            "profile_name": "cisco_catalyst",
            "status": "DEGRADED",
            "last_uptime_ticks": 864_000,
            "capabilities": {"interfaces": True, "cpu": True, "memory": True, "temperature": True, "poe": True, "vlans": True},
        })
        db.save_snmp_metrics_batch([
            {"device_id": dev_a["id"], "metric_name": "cpu_pct", "metric_value": 45.0, "unit": "%", "timestamp": now - timedelta(minutes=2)},
            {"device_id": dev_a["id"], "metric_name": "memory_pct", "metric_value": 55.0, "unit": "%", "timestamp": now - timedelta(minutes=2)},
            {"device_id": dev_a["id"], "metric_name": "temperature_c", "metric_value": 44.0, "unit": "C", "sensor_label": "Chassis", "timestamp": now},
            {"device_id": dev_a["id"], "metric_name": "temperature_max_c", "metric_value": 44.0, "unit": "C", "timestamp": now},
            {"device_id": dev_a["id"], "metric_name": "poe_budget_watts", "metric_value": 370.0, "unit": "W", "timestamp": now},
            {"device_id": dev_a["id"], "metric_name": "poe_consumed_watts", "metric_value": 185.0, "unit": "W", "timestamp": now},
            {"device_id": dev_a["id"], "metric_name": "poe_utilization_pct", "metric_value": 50.0, "unit": "%", "timestamp": now},
        ])
        id_map = db.upsert_snmp_interfaces(dev_a["id"], [
            {"if_index": 1, "name": "Gi1/0/1", "admin_status": "UP", "oper_status": "UP", "speed_bps": 1_000_000_000},
            {"if_index": 2, "name": "Gi1/0/2", "admin_status": "UP", "oper_status": "DOWN", "speed_bps": 1_000_000_000},
            {"if_index": 3, "name": "Gi1/0/3", "admin_status": "UP", "oper_status": "UP", "speed_bps": 1_000_000_000},
        ])
        db.save_interface_measurements_batch([
            {"interface_id": id_map[1], "device_id": dev_a["id"], "in_mbps": 880.0, "out_mbps": 120.0, "utilization_pct": 88.0, "crc_errors": 0, "oper_status": "UP", "timestamp": now},
            {"interface_id": id_map[2], "device_id": dev_a["id"], "in_mbps": 0.0, "out_mbps": 0.0, "utilization_pct": 0.0, "crc_errors": 0, "oper_status": "DOWN", "timestamp": now},
            {"interface_id": id_map[3], "device_id": dev_a["id"], "in_mbps": 10.0, "out_mbps": 5.0, "utilization_pct": 1.0, "crc_errors": 9, "oper_status": "UP", "timestamp": now},
        ])
        db.upsert_snmp_vlans(dev_a["id"], [
            {"vlan_id": 10, "name": "MGMT", "status": "ACTIVE", "untagged_ports": ["Gi1/0/1"], "tagged_ports": ["Gi1/0/3"], "trunk_ports": ["Gi1/0/3"]},
        ])
        db.save_syslog_events_batch([
            {"source_ip": "10.81.0.1", "hostname": "SW-POE-CORE", "timestamp": now, "facility": 23, "severity": 3, "severity_name": "Error", "app_name": "LINK", "event_category": "LINK_DOWN", "message": "Gi1/0/2 down", "raw_message": "raw"}
        ])
        db.create_network_anomaly({
            "anomaly_uid": "ANOM-UID-01",
            "device_id": dev_a["id"],
            "device_name": "SW-POE-CORE",
            "device_ip": "10.81.0.1",
            "event_type": "PHYSICAL_LINK_FAILURE",
            "title": "Link failure Gi1/0/2",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "evidence": ["Interface Gi1/0/2 observed DOWN"],
            "probable_cause": "Probable unplugged patch cord",
            "recommended_actions": ["Check port"],
            "status": "ACTIVE",
        })

        dlg_a = DeviceDetailsDialog(db, dev_a["id"])
        try:
            assert dlg_a.tabs.count() == 10
            assert dlg_a.poe_tab_supported is True
            assert dlg_a.vlan_tab_supported is True
            assert dlg_a.tabs.isTabEnabled(4) is True and dlg_a.tabs.isTabVisible(4) is True
            assert dlg_a.tabs.isTabEnabled(5) is True and dlg_a.tabs.isTabVisible(5) is True

            assert dlg_a.if_table.rowCount() == 3
            dlg_a._set_interface_filter("UP")
            assert dlg_a.if_table.rowCount() == 2
            dlg_a._set_interface_filter("DOWN")
            assert dlg_a.if_table.rowCount() == 1
            dlg_a._set_interface_filter("HIGH_UTILIZATION")
            assert dlg_a.if_table.rowCount() == 1
            dlg_a._set_interface_filter("ERRORS")
            assert dlg_a.if_table.rowCount() == 1

            assert dlg_a.vlan_table.rowCount() == 1
            assert dlg_a.dev_syslog_table.rowCount() == 1
            assert dlg_a.ev_table.rowCount() == 1

            # Verify historical hourly toggle & config save without secret disclosure
            dlg_a.hist_gran_combo.setCurrentIndex(1)
            dlg_a.cfg_poll_int.setValue(45)
            dlg_a.cfg_anomaly.setChecked(False)
            with patch.object(QMessageBox, "information"):
                dlg_a._save_device_config()
            updated_dev = db.get_snmp_device(dev_a["id"])
            assert updated_dev["poll_interval_sec"] == 45
            assert updated_dev["anomaly_detection_enabled"] is False
            assert "VerySecretCommunityA!" not in dlg_a.hdr_sub_lbl.text()
        finally:
            dlg_a.close()

        # Device B: Plain Linux Server without PoE and without VLANs -> Tabs 4 & 5 disabled & hidden
        dev_b = db.add_snmp_device({
            "name": "SRV-PLAIN",
            "ip_address": "10.81.0.2",
            "snmp_version": "v2c",
            "encrypted_credentials": encrypt_credentials(creds_a),
            "vendor": "Linux",
            "profile_name": "snmp_server",
            "status": "ONLINE",
            "capabilities": {"interfaces": True, "cpu": True, "memory": True, "temperature": False, "poe": False, "vlans": False},
        })
        dlg_b = DeviceDetailsDialog(db, dev_b["id"])
        try:
            assert dlg_b.tabs.count() == 10
            assert dlg_b.poe_tab_supported is False
            assert dlg_b.vlan_tab_supported is False
            assert dlg_b.tabs.isTabEnabled(4) is False and dlg_b.tabs.isTabVisible(4) is False
            assert dlg_b.tabs.isTabEnabled(5) is False and dlg_b.tabs.isTabVisible(5) is False
        finally:
            dlg_b.close()

    def test_syslog_view_udp_pause_filters_firewall_and_export(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "syslog_ui.db"))
        srv = SyslogServer(
            db=db,
            bind_address="127.0.0.1",
            port=0,
            max_packets_per_sec=2000,
            max_per_ip_per_sec=2000,
            batch_size=10,
            batch_flush_interval_sec=0.1,
        )
        view = SyslogView(_dummy_logger(), db=db, server=srv)
        view.bind_edit.setText("127.0.0.1")
        view.port_spin.setValue(0)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            view.start_listener()
            assert srv.wait_until_ready(3.0) is True
            port = srv.bound_port

            now_utc = datetime.utcnow()
            en_mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][now_utc.month - 1]
            bsd_ts = f"{en_mon} {now_utc.day:2d} {now_utc.strftime('%H:%M:%S')}"
            fg_d = now_utc.strftime("%Y-%m-%d")
            fg_t = now_utc.strftime("%H:%M:%S")
            packets = [
                f"<187>{bsd_ts} SW-1 %LINK-3-UPDOWN: Interface Gi1/0/1, changed state to down".encode("utf-8"),
                f'<187>date={fg_d} time={fg_t} devname="FW-1" devid="FG100F" action="interface-stat-change" status="down" msg="Interface wan1 status changed to down"'.encode("utf-8"),
                f"<190>{bsd_ts} app-1 systemd[1]: Routine tick completed".encode("utf-8"),
            ]
            for pkt in packets:
                sock.sendto(pkt, ("127.0.0.1", port))

            deadline = time.monotonic() + 4.0
            while time.monotonic() < deadline:
                _qapp.processEvents()
                if srv.get_stats()["persisted_events"] >= 3 and view.table.rowCount() >= 3:
                    break
                time.sleep(0.02)

            assert srv.get_stats()["processed_events"] == 3
            assert view.table.rowCount() >= 3

            # Inspect selected row
            view.table.selectRow(0)
            assert view.detail_view.toPlainText().strip() != ""

            # Test pause toggle & category filter
            view.toggle_pause()
            assert view._paused is True
            view.toggle_pause()
            assert view._paused is False

            idx_cat = view.cat_combo.findData("LINK_DOWN")
            view.cat_combo.setCurrentIndex(idx_cat)
            view.refresh_table()
            assert view.table.rowCount() == 1

            # Reset filter for full export
            view.cat_combo.setCurrentIndex(0)
            view.refresh_table()
            assert view.table.rowCount() == 3

            csv_path = str(tmp_path / "ui_syslog.csv")
            json_path = str(tmp_path / "ui_syslog.json")
            assert view.export_csv(csv_path) == 3
            assert view.export_json(json_path) == 3
            with open(csv_path, "r", encoding="utf-8-sig", newline="") as cf:
                assert len(list(csv.DictReader(cf))) == 3
            with open(json_path, "r", encoding="utf-8") as jf:
                assert len(json.load(jf)) == 3

            # Firewall guide copies PowerShell command & triggers modal safely
            with patch.object(QMessageBox, "information") as info_mock:
                view.show_firewall_guide()
                info_mock.assert_called_once()
        finally:
            sock.close()
            view.shutdown()
            view.close()

        assert not srv.isRunning()

    def test_intelligence_view_diagnosis_inspector_and_lifecycle(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "intel_ui.db"))
        now = datetime.utcnow()
        creds = SNMPCredentials(version="v2c", community="ro")
        dev = db.add_snmp_device({
            "name": "SW-EDGE-99",
            "ip_address": "10.82.0.1",
            "snmp_version": "v2c",
            "encrypted_credentials": encrypt_credentials(creds),
            "profile_name": "cisco_catalyst",
        })
        db.upsert_snmp_interfaces(dev["id"], [
            {"if_index": 1, "name": "Gi0/1", "admin_status": "UP", "oper_status": "DOWN", "speed_bps": 1_000_000_000}
        ])
        db.save_syslog_events_batch([
            {"source_ip": "10.82.0.1", "hostname": "SW-EDGE-99", "timestamp": now, "facility": 23, "severity": 3, "severity_name": "Error", "app_name": "LINK", "event_category": "LINK_DOWN", "message": "Gi0/1 down", "raw_message": "raw"}
        ])

        view = IntelligenceView(_dummy_logger(), db=db)
        try:
            view.run_correlation_now()
            assert view.kpi_open.text() == "1"
            assert view.kpi_crit.text() == "1"
            assert view.kpi_affected.text() == "1"
            assert view.table.rowCount() == 1

            ev_txt = view.evidence_box.toPlainText()
            cause_txt = view.cause_box.toPlainText()
            act_txt = view.actions_box.toPlainText()
            assert "Gi0/1" in ev_txt and "LINK_DOWN" in ev_txt
            assert "Probable" in cause_txt
            assert "HIGH" in view.confidence_badge.text()
            assert act_txt.strip() != ""

            view._ack_selected()
            assert db.get_network_anomalies(device_id=dev["id"])[0]["status"] == "ACKNOWLEDGED"

            view._resolve_selected()
            assert db.get_network_anomalies(device_id=dev["id"])[0]["status"] == "RESOLVED"
        finally:
            view.shutdown()
            view.close()

    def test_dashboard_view_10_kpis_8_charts_and_inventory(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        cfg = ConfigManager()
        db = DatabaseManager(db_path=str(tmp_path / "dash_v350.db"))

        # Empty-DB safety check first
        dv = DashboardView(_dummy_logger(), config_manager=cfg, db=db)
        try:
            assert len(dv.kpi_cards) == 10
            assert dv.inventory_table.rowCount() == 0

            # Seed Ping host, Speedtest, 2 SNMP devices, interfaces, Syslog, and anomaly
            db.add_host("8.8.8.8", label="Google DNS")
            db.save_log("8.8.8.8", "UP", 14)
            db.save_speedtest(250.0, 50.0, 12.0, 1.5, 0.0, "Test-Server", "Test-ISP")

            enc = encrypt_credentials(SNMPCredentials(version="v2c", community="ro"))
            d1 = db.add_snmp_device({"name": "CORE-1", "ip_address": "10.83.0.1", "snmp_version": "v2c", "encrypted_credentials": enc, "vendor": "Cisco", "status": "ONLINE"})
            d2 = db.add_snmp_device({"name": "FW-1", "ip_address": "10.83.0.2", "snmp_version": "v2c", "encrypted_credentials": enc, "vendor": "Fortinet", "status": "DEGRADED"})
            now = datetime.utcnow()
            db.save_snmp_metrics_batch([
                {"device_id": d1["id"], "metric_name": "cpu_pct", "metric_value": 30.0, "unit": "%", "timestamp": now},
                {"device_id": d1["id"], "metric_name": "memory_pct", "metric_value": 40.0, "unit": "%", "timestamp": now},
                {"device_id": d1["id"], "metric_name": "poe_utilization_pct", "metric_value": 55.0, "unit": "%", "timestamp": now},
                {"device_id": d1["id"], "metric_name": "total_in_mbps", "metric_value": 120.0, "unit": "Mbps", "timestamp": now},
                {"device_id": d2["id"], "metric_name": "cpu_pct", "metric_value": 80.0, "unit": "%", "timestamp": now},
                {"device_id": d2["id"], "metric_name": "memory_pct", "metric_value": 70.0, "unit": "%", "timestamp": now},
            ])
            imap = db.upsert_snmp_interfaces(d1["id"], [{"if_index": 1, "name": "Gi0/1", "admin_status": "UP", "oper_status": "UP", "speed_bps": 1_000_000_000}])
            db.save_interface_measurements_batch([{"interface_id": imap[1], "device_id": d1["id"], "in_mbps": 120.0, "out_mbps": 30.0, "utilization_pct": 12.0, "oper_status": "UP", "timestamp": now}])
            db.save_syslog_events_batch([{"source_ip": "10.83.0.2", "hostname": "FW-1", "timestamp": now, "facility": 23, "severity": 3, "severity_name": "Error", "app_name": "fg", "event_category": "FIREWALL_IF_DOWN", "message": "wan1 down", "raw_message": "r"}])
            db.create_network_anomaly({"anomaly_uid": "ANOM-DASH-1", "device_id": d2["id"], "device_name": "FW-1", "device_ip": "10.83.0.2", "event_type": "PHYSICAL_LINK_FAILURE", "title": "wan1 down", "severity": "CRITICAL", "status": "ACTIVE"})

            dv.update_info()
            assert dv.snmp_devices_kpi.value_label.text() == "1/2"
            assert dv.anomalies_kpi.value_label.text() == "1"
            assert dv.syslog_kpi.value_label.text() == "1"
            assert dv.avg_cpu_kpi.value_label.text() == "55.0%"
            assert dv.avg_mem_kpi.value_label.text() == "55.0%"
            assert dv.poe_kpi.value_label.text() == "55.0%"
            assert dv.inventory_table.rowCount() == 2

            for attr in ("bandwidth_chart", "cpu_plot", "mem_plot", "traffic_plot", "top_ifaces_plot", "dev_health_plot", "syslog_sev_plot", "anomalies_plot"):
                assert hasattr(dv, attr)
        finally:
            dv.shutdown()
            dv.close()

    def test_release_v350_packaging_and_mainwindow_wiring(self):
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        assert CURRENT_VERSION == "v3.6.1"

        with open(os.path.join(root_dir, "build_scripts", "setup_compiler.iss"), "r", encoding="utf-8") as f:
            iss = f.read()
        assert "AppVersion=3.6.1" in iss
        assert "OutputBaseFilename=Install_BahaaIT_v3.6.1" in iss

        with open(os.path.join(root_dir, "build_scripts", "build.py"), "r", encoding="utf-8") as f:
            build_py = f.read()
        assert "--collect-submodules=pysnmp" in build_py
        assert "--collect-submodules=pysnmpcrypto" in build_py
        assert "--collect-data=pysnmp" in build_py

        spec_path = os.path.join(root_dir, "BahaaIT.spec")
        with open(spec_path, "r", encoding="utf-8") as f:
            spec_txt = f.read()
        compile(spec_txt, spec_path, "exec")
        assert "collect_submodules('pysnmp')" in spec_txt
        assert "collect_submodules('pysnmpcrypto')" in spec_txt

        rn_path = os.path.join(root_dir, "RELEASE_NOTES_v3.5.0.md")
        assert os.path.exists(rn_path)
        with open(rn_path, "r", encoding="utf-8") as f:
            rn_txt = f.read()
        assert "v3.5.0" in rn_txt and "Network Intelligence" in rn_txt

        mw_path = os.path.join(root_dir, "src", "ui", "main_window.py")
        with open(mw_path, "r", encoding="utf-8") as f:
            mw_txt = f.read()
        assert "elif index == 11" in mw_txt and "SNMPView" in mw_txt
        assert "elif index == 12" in mw_txt and "SyslogView" in mw_txt
        assert "elif index == 13" in mw_txt and "IntelligenceView" in mw_txt
        assert "self.snmp_view.shutdown()" in mw_txt
        assert "self.syslog_view.shutdown()" in mw_txt
        assert "self.intelligence_view.shutdown()" in mw_txt
