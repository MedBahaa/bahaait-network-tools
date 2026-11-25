import base64
from datetime import datetime, timedelta
import logging
import os
import re
import sys
import zlib
from unittest.mock import MagicMock, patch

from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication, QMessageBox

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.incident_manager import IncidentManager, IncidentStatus
from core.monitoring_state import HostState, MonitoringPolicyConfig, ProbeOutcome, StateTransition
from core.monitoring_statistics import MonitoringStatisticsService
from core.network_quality import QualitySnapshot
from core.ping_engine import AsyncPingEngine
from core.wan_monitor import WANMonitor
from ui.widgets.host_details_view import HostDetailsDialog
from ui.widgets.incident_center import IncidentCenterWidget
from ui.widgets.monitor_view import MonitorView
from ui.widgets.monitoring_dashboard import MonitoringOverviewBar
from ui.widgets.monitoring_settings import MonitoringSettingsWidget
from ui.widgets.wan_monitor_view import WANMonitorView
from utils.config import ConfigManager
from utils.db import DatabaseManager, PingMeasurement
from utils.updater import CURRENT_VERSION


_qapp = QApplication.instance() or QApplication(sys.argv)


def _dummy_logger():
    return logging.getLogger("BahaaIT.TestUI")


class TestMonitoringUI:
    def test_overview_bar_updates(self):
        bar = MonitoringOverviewBar()
        bar.update_summary({
            "total_hosts": 12,
            "online_hosts": 9,
            "degraded_hosts": 2,
            "offline_hosts": 1,
            "active_incidents": 3,
            "avg_latency_ms": 24.5,
            "global_packet_loss_pct": 4.2,
            "global_uptime_pct": 98.5,
        })
        assert bar.total_card.value_label.text() == "12"
        assert bar.online_card.value_label.text() == "9"
        assert bar.degraded_card.value_label.text() == "2"
        assert bar.offline_card.value_label.text() == "1"
        assert bar.incidents_card.value_label.text() == "3"
        assert "24.5" in bar.latency_card.value_label.text()
        assert "4.2" in bar.loss_card.value_label.text()
        assert "98.50" in bar.uptime_card.value_label.text()

    def test_monitor_view_add_pause_delete_and_live_update(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "ui_mon.db"))
        view = MonitorView(_dummy_logger(), db=db)

        # Reject command-injection input
        view.label_input.setText("Evil")
        view.ip_input.setText("8.8.8.8; whoami")
        with patch.object(QMessageBox, "warning") as warn_mock:
            view.add_host()
            warn_mock.assert_called_once()
        assert "8.8.8.8; whoami" not in view.hosts

        # Add valid host
        view.label_input.setText("Core-SW")
        view.ip_input.setText("10.10.1.1")
        view.add_host()
        assert "10.10.1.1" in view.hosts
        assert view.table.rowCount() == 1

        # Simulate live updates across all 5 states (end with UP so active=True before toggle_pause)
        now = datetime.utcnow()
        for state, lat, loss, jit, inc_uid in [
            (HostState.PAUSED.value, None, 0.0, 0.0, None),
            (HostState.DEGRADED.value, 185.0, 15.0, 35.0, "INC-TEST-1"),
            (HostState.DOWN.value, None, 100.0, 0.0, "INC-TEST-1"),
            (HostState.RECOVERING.value, 18.0, 40.0, 2.5, "INC-TEST-1"),
            (HostState.UP.value, 14.0, 0.0, 1.2, None),
        ]:
            view.on_host_updated({
                "host": "10.10.1.1",
                "label": "Core-SW",
                "active": state != HostState.PAUSED.value,
                "state": state,
                "current_latency_ms": lat,
                "avg_latency_ms": lat or 0.0,
                "packet_loss_pct": loss,
                "jitter_ms": jit,
                "uptime_pct": 99.2,
                "last_success_utc": now,
                "active_incident_uid": inc_uid,
            })
            assert view.table.item(0, 1).text() == "10.10.1.1"
            assert "%" in view.table.item(0, 5).text()

        # Pause & Resume toggle
        view.toggle_pause("10.10.1.1")
        assert view.hosts["10.10.1.1"]["state"] == HostState.PAUSED.value
        view.toggle_pause("10.10.1.1")
        assert view.hosts["10.10.1.1"]["active"] is True

        # Delete host
        view.delete_host("10.10.1.1")
        assert "10.10.1.1" not in view.hosts
        assert view.table.rowCount() == 0
        view.stop_monitor()

    def test_incident_center_lifecycle_and_export(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "ui_inc.db"))
        db.add_host("10.0.0.50", "WAN-Router")
        inc_mgr = IncidentManager(db)
        now = datetime.utcnow()
        tr = StateTransition(
            host_address="10.0.0.50",
            previous_state=HostState.DEGRADED,
            new_state=HostState.DOWN,
            changed=True,
            reason="CONFIRMED_OUTAGE",
            details="5 failures",
            timestamp_mono=10.0,
            timestamp_utc=now,
        )
        qual = QualitySnapshot(
            current_latency_ms=None, min_latency_ms=10.0, max_latency_ms=20.0, avg_latency_ms=14.0,
            p95_latency_ms=19.0, jitter_ms=1.5, packet_loss_pct=100.0, consecutive_successes=0,
            consecutive_failures=5, uptime_pct=50.0, last_success_utc=now - timedelta(seconds=10),
            last_failure_utc=now, total_probes=10, valid_probes=10, timeout_count=5,
            dns_error_count=0, engine_error_count=0,
        )
        created = inc_mgr.handle_transition(1, "WAN-Router", "10.0.0.50", tr, qual)
        assert created is not None

        widget = IncidentCenterWidget(inc_mgr, db)
        assert widget.table.rowCount() == 1
        widget.table.selectRow(0)
        widget.table.setCurrentCell(0, 0)

        with patch("PySide6.QtWidgets.QInputDialog.getText", return_value=("Checking fiber", True)):
            widget.acknowledge_selected()
        assert widget.table.item(0, 5).text() == IncidentStatus.ACKNOWLEDGED.value

        widget.table.selectRow(0)
        widget.table.setCurrentCell(0, 0)
        with patch("PySide6.QtWidgets.QInputDialog.getText", return_value=("Ticket #441", True)):
            widget.comment_selected()
        assert "Ticket #441" in widget.table.item(0, 9).text()

        widget.table.selectRow(0)
        widget.table.setCurrentCell(0, 0)
        widget.close_selected()
        assert widget.table.item(0, 5).text() == IncidentStatus.CLOSED.value

        # Exports
        csv_file = str(tmp_path / "ui_inc.csv")
        pdf_file = str(tmp_path / "ui_inc.pdf")
        with patch.object(QMessageBox, "information"), \
             patch("PySide6.QtWidgets.QFileDialog.getSaveFileName", return_value=(csv_file, "")):
            widget.export_csv()
        assert os.path.exists(csv_file)

        with patch.object(QMessageBox, "information"), \
             patch("PySide6.QtWidgets.QFileDialog.getSaveFileName", return_value=(pdf_file, "")):
            widget.export_pdf()
        assert os.path.getsize(pdf_file) > 400

    def test_host_details_dialog_charts_and_settings(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "ui_det.db"))
        db.add_host("10.0.0.99", "Core-AP")
        now = datetime.utcnow()
        db.save_measurements_batch([
            {"host_address": "10.0.0.99", "timestamp": now - timedelta(seconds=20), "status": "UP", "latency_ms": 11.0, "is_valid_probe": True},
            {"host_address": "10.0.0.99", "timestamp": now - timedelta(seconds=10), "status": "UP", "latency_ms": 16.0, "is_valid_probe": True},
            {"host_address": "10.0.0.99", "timestamp": now, "status": "UP", "latency_ms": 14.0, "is_valid_probe": True},
        ])
        inc_mgr = IncidentManager(db)
        stats_svc = MonitoringStatisticsService(db)
        engine = AsyncPingEngine(db)
        engine.add_host("10.0.0.99", "Core-AP", host_id=1)

        dlg = HostDetailsDialog("10.0.0.99", "Core-AP", db, engine, inc_mgr, stats_svc)
        dlg.show()
        _qapp.processEvents()

        # Switch chart periods
        for per in ("1m", "5m", "15m", "1h", "24h"):
            dlg._set_period(per)
            _qapp.processEvents()
        assert dlg._current_period == "24h"

        # Save per-host policy override and verify persistence
        dlg.sp_interval.setValue(2500)
        dlg.sp_warn_fail.setValue(4)
        dlg.sp_crit_fail.setValue(8)
        with patch.object(QMessageBox, "information"):
            dlg._save_host_settings()

        saved_pol = db.get_policy(dlg._host_db_id)
        assert saved_pol is not None
        assert saved_pol["probe_interval_ms"] == 2500
        assert saved_pol["critical_failures"] == 8

        # Reset back to defaults
        dlg._reset_host_settings()
        assert db.get_policy(dlg._host_db_id) is None
        dlg.close()

    def test_incident_pdf_includes_comments_and_cross_view_sync(self, tmp_path):
        pdf_gen_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "src", "utils", "pdf_generator.py")
        )
        with open(pdf_gen_path, "r", encoding="utf-8") as f:
            pdf_src = f.read()
        assert pdf_src.count("def generate_incidents_report") == 1

        db = DatabaseManager(db_path=str(tmp_path / "ui_sync.db"))
        db.add_host("10.0.0.77", "ISP-Edge")
        inc_mgr = IncidentManager(db)
        now = datetime.utcnow()
        tr = StateTransition(
            host_address="10.0.0.77",
            previous_state=HostState.DEGRADED,
            new_state=HostState.DOWN,
            changed=True,
            reason="CONFIRMED_OUTAGE",
            details="5 failures",
            timestamp_mono=25.0,
            timestamp_utc=now,
        )
        qual = QualitySnapshot(
            current_latency_ms=None, min_latency_ms=8.0, max_latency_ms=15.0, avg_latency_ms=11.0,
            p95_latency_ms=14.0, jitter_ms=1.0, packet_loss_pct=100.0, consecutive_successes=0,
            consecutive_failures=5, uptime_pct=75.0, last_success_utc=now - timedelta(seconds=10),
            last_failure_utc=now, total_probes=20, valid_probes=20, timeout_count=5,
            dns_error_count=0, engine_error_count=0,
        )
        created = inc_mgr.handle_transition(1, "ISP-Edge", "10.0.0.77", tr, qual)
        assert created is not None

        # Open IncidentCenterWidget first (populates _cached_rows before comments exist)
        inc_widget = IncidentCenterWidget(inc_mgr, db)
        assert inc_widget.table.rowCount() == 1

        stats_svc = MonitoringStatisticsService(db)
        engine = AsyncPingEngine(db)
        engine.add_host("10.0.0.77", "ISP-Edge", host_id=1)
        dlg = HostDetailsDialog("10.0.0.77", "ISP-Edge", db, engine, inc_mgr, stats_svc)

        sig_count = {"n": 0}
        dlg.incidents_changed.connect(lambda: sig_count.__setitem__("n", sig_count["n"] + 1))

        dlg.inc_table.selectRow(0)
        dlg.inc_table.setCurrentCell(0, 0)
        with patch("PySide6.QtWidgets.QInputDialog.getText", return_value=("Ack on site <noc & field>", True)):
            dlg._ack_host_incident()

        long_comment = (
            "Ligne 1 diagnostic: perte SFP port 0/1 & alarme > seuil critique, "
            "verification jarretiere optique + nettoyage connecteur LC/APC en cours "
            "pour validation complete avant cloture TECH_NOTE_FULL_CHECK_9876."
        )
        assert len(long_comment) > 200
        dlg.inc_table.selectRow(0)
        dlg.inc_table.setCurrentCell(0, 0)
        with patch("PySide6.QtWidgets.QInputDialog.getText", return_value=(long_comment, True)):
            dlg._comment_host_incident()

        assert sig_count["n"] == 2

        # Do NOT manually call inc_widget.refresh_incidents() -> export must fetch fresh DB state
        csv_file = str(tmp_path / "sync_inc.csv")
        pdf_file = str(tmp_path / "sync_inc.pdf")
        with patch.object(QMessageBox, "information"), \
             patch("PySide6.QtWidgets.QFileDialog.getSaveFileName", return_value=(csv_file, "")):
            inc_widget.export_csv()
        with open(csv_file, "r", encoding="utf-8-sig") as f:
            csv_text = f.read()
        assert "TECH_NOTE_FULL_CHECK_9876" in csv_text
        assert "Ack on site <noc & field>" in csv_text

        with patch.object(QMessageBox, "information"), \
             patch("PySide6.QtWidgets.QFileDialog.getSaveFileName", return_value=(pdf_file, "")):
            inc_widget.export_pdf()
        with open(pdf_file, "rb") as f:
            pdf_bytes = f.read()

        chunks = []
        for raw_stream in re.findall(rb"stream\r?\n(.*?)endstream", pdf_bytes, re.S):
            payload = raw_stream.strip()
            try:
                if payload.endswith(b"~>"):
                    payload = base64.a85decode(payload, adobe=True)
                decompressed = zlib.decompress(payload)
            except Exception:
                decompressed = raw_stream
            chunks.append(decompressed.decode("latin1", errors="ignore"))
        pdf_stream_text = "\n".join(chunks)

        assert "JOURNAL DES COMMENTAIRES" in pdf_stream_text
        assert "TECH_NOTE_FULL_CHECK_9876" in pdf_stream_text
        assert "Ack on site" in pdf_stream_text
        dlg.close()

    def test_wan_monitor_view_verdicts_and_manual_check(self):
        async def _fake_ping(ip, _timeout):
            if ip == "192.168.1.1":
                return True, 1.5
            return True, 14.2

        async def _fake_dns(domain):
            return True, f"{domain} -> 142.250.1.1 (4 ms)"

        async def _fake_https(host):
            return True, f"HTTPS OK {host} (18 ms)"

        wan_mon = WANMonitor(
            gateway_ip="192.168.1.1",
            ping_fn=_fake_ping,
            dns_fn=_fake_dns,
            https_fn=_fake_https,
        )
        view = WANMonitorView(wan_mon)

        # Render all 9 WAN verdict scenarios
        scenarios = [
            WANMonitor.correlate(True, True, True, True, True, {"gateway": 1.0, "primary_wan": 12.0, "secondary_wan": 9.0}, "192.168.1.1"),
            WANMonitor.correlate(False, True, True, True, True, {"gateway": 0.0, "primary_wan": 14.0, "secondary_wan": 10.0}, "192.168.1.1"),
            WANMonitor.correlate(True, True, True, False, True, {"gateway": 1.0, "primary_wan": 12.0, "secondary_wan": 9.0}, "192.168.1.1"),
            WANMonitor.correlate(True, True, True, True, False, {"gateway": 1.0, "primary_wan": 12.0, "secondary_wan": 9.0}, "192.168.1.1"),
            WANMonitor.correlate(True, False, False, True, True, {"gateway": 1.0}, "192.168.1.1"),
            WANMonitor.correlate(True, False, False, None, None, {"gateway": 1.0}, "192.168.1.1"),
            WANMonitor.correlate(True, True, False, True, True, {"gateway": 1.0, "primary_wan": 15.0}, "192.168.1.1"),
            WANMonitor.correlate(True, False, False, False, False, {"gateway": 1.2}, "192.168.1.1"),
            WANMonitor.correlate(False, False, False, False, False, {}, "192.168.1.1"),
        ]
        for v in scenarios:
            view.update_verdict(v.to_dict())

        assert view.history_table.rowCount() == 9
        assert view.gw_card.status_lbl.text() == "DOWN"
        assert view.dns_card.status_lbl.text() == "FAIL"
        assert view.https_card.status_lbl.text() == "FAIL"

        # Autonomous continuous monitoring starts without AsyncPingEngine and runs an immediate check
        toggled_vals = []
        view.continuous_toggled.connect(toggled_vals.append)

        received = []
        loop = QEventLoop()

        def _on_ready(payload):
            received.append(payload)
            loop.quit()

        view.verdict_ready.connect(_on_ready)
        QTimer.singleShot(5000, loop.quit)
        view.start_continuous_monitoring()
        assert view.is_continuous_active() is True
        assert view._auto_timer.isActive() is True
        assert toggled_vals == [True]
        assert view.status_pill.text() != ""
        loop.exec()

        # Interval spinbox updates active timer dynamically
        view.interval_spin.setValue(25)
        assert view._auto_timer.interval() == 25000

        # Stop continuous monitoring cleanly
        view.stop_continuous_monitoring()
        assert view.is_continuous_active() is False
        assert view._auto_timer.isActive() is False
        assert toggled_vals == [True, False]
        view.stop_workers()

        assert len(received) == 1
        assert received[0]["verdict_code"] == "HEALTHY"
        assert view.history_table.rowCount() == 10
        assert view.gw_card.status_lbl.text() == "UP"

    def test_monitoring_settings_save_restore_retention_and_json_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        cfg_mgr = ConfigManager()
        db = DatabaseManager(db_path=str(tmp_path / "ui_cfg.db"))
        db.add_host("10.0.0.1", "GlobalHost")
        db.add_host("10.0.0.2", "CustomHost")
        hosts_map = {h["address"]: h["id"] for h in db.get_hosts()}
        h1_id = hosts_map["10.0.0.1"]
        h2_id = hosts_map["10.0.0.2"]
        custom_pol = MonitoringPolicyConfig(probe_interval_ms=3333)
        db.save_policy(custom_pol.to_dict(), host_id=h2_id)

        engine = AsyncPingEngine(db)
        engine.add_host("10.0.0.1", "GlobalHost", host_id=h1_id)
        engine.add_host("10.0.0.2", "CustomHost", policy=custom_pol, host_id=h2_id)

        widget = MonitoringSettingsWidget(db, engine, config_manager=cfg_mgr)

        # Invalid thresholds rejected (critical < warning)
        widget.sp_warn_fail.setValue(6)
        widget.sp_crit_fail.setValue(3)
        with patch.object(QMessageBox, "warning") as warn_mock:
            assert widget.save_settings() is False
            warn_mock.assert_called_once()

        # Valid thresholds saved & propagated ONLY to non-overridden hosts
        widget.sp_interval.setValue(2000)
        widget.sp_warn_fail.setValue(3)
        widget.sp_crit_fail.setValue(6)
        widget.sp_sound_dur.setValue(15)
        widget.sp_ret_raw.setValue(10)
        widget.sp_ret_agg.setValue(45)
        with patch.object(QMessageBox, "information"):
            assert widget.save_settings() is True

        assert db.get_policy(None)["probe_interval_ms"] == 2000
        assert engine.global_policy.probe_interval_ms == 2000
        assert engine._hosts["10.0.0.1"].policy.probe_interval_ms == 2000
        assert engine._hosts["10.0.0.2"].policy.probe_interval_ms == 3333
        assert cfg_mgr.get("alarm_duration_sec") == 15
        assert cfg_mgr.get("retention_raw_days") == 10

        # Retention purge test
        now = datetime.utcnow()
        with db.Session() as session:
            session.add(PingMeasurement(host_address="10.0.0.1", timestamp=now - timedelta(days=30), status="UP", latency_ms=10.0))
            session.add(PingMeasurement(host_address="10.0.0.1", timestamp=now, status="UP", latency_ms=11.0))
            session.commit()
        with patch.object(QMessageBox, "information"):
            counts = widget.run_retention_purge()
        assert counts["raw"] == 1

        # Restore defaults
        with patch.object(QMessageBox, "information"):
            widget.restore_defaults()
        assert widget.sp_interval.value() == 1000
        assert db.get_policy(None)["probe_interval_ms"] == 1000
        assert engine._hosts["10.0.0.1"].policy.probe_interval_ms == 1000
        assert engine._hosts["10.0.0.2"].policy.probe_interval_ms == 3333

        # JSON export & import roundtrip + invalid JSON rejection
        widget.sp_interval.setValue(2222)
        with patch.object(QMessageBox, "information"):
            assert widget.save_settings() is True

        json_path = str(tmp_path / "mon_cfg.json")
        with patch.object(QMessageBox, "information"), \
             patch("PySide6.QtWidgets.QFileDialog.getSaveFileName", return_value=(json_path, "")):
            widget.export_config()
        assert os.path.exists(json_path)

        widget.sp_interval.setValue(4444)
        with patch.object(QMessageBox, "information"):
            assert widget.save_settings() is True

        with patch.object(QMessageBox, "information"), \
             patch("PySide6.QtWidgets.QFileDialog.getOpenFileName", return_value=(json_path, "")):
            assert widget.import_config() is True
        assert widget.sp_interval.value() == 2222
        assert db.get_policy(None)["probe_interval_ms"] == 2222
        assert engine._hosts["10.0.0.2"].policy.probe_interval_ms == 3333

        bad_json = str(tmp_path / "bad_cfg.json")
        with open(bad_json, "w", encoding="utf-8") as f:
            f.write("{invalid json")
        with patch.object(QMessageBox, "critical") as crit_mock, \
             patch("PySide6.QtWidgets.QFileDialog.getOpenFileName", return_value=(bad_json, "")):
            assert widget.import_config() is False
            crit_mock.assert_called_once()

    def test_monitor_view_four_tabs_and_version_340(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        cfg_mgr = ConfigManager()
        db = DatabaseManager(db_path=str(tmp_path / "ui_tabs.db"))
        view = MonitorView(_dummy_logger(), config_manager=cfg_mgr, db=db)

        assert view.tabs.count() == 4
        assert hasattr(view, "wan_view")
        assert hasattr(view, "settings_tab")

        verdict = WANMonitor.correlate(True, False, False, False, False, gateway_ip="192.168.1.1").to_dict()
        view.on_wan_updated(verdict)
        assert view.wan_view.history_table.rowCount() == 1
        log_text_once = view.event_log.toPlainText()
        assert "WAN_OUTAGE_CONFIRMED" in log_text_once
        view.on_wan_updated(verdict)
        assert view.event_log.toPlainText().count("WAN_OUTAGE_CONFIRMED") == 1

        # Autonomous WAN starts independently while Host Monitor is stopped
        assert view.is_monitoring_active is False
        assert view.engine.isRunning() is False
        with patch.object(view.wan_view, "run_manual_check"):
            view.wan_view.toggle_continuous_monitoring()
        view.wan_view.interval_spin.setValue(25)
        assert view.wan_view.is_continuous_active() is True
        assert view.engine.is_wan_enabled() is False  # No duplicate WAN loop in AsyncPingEngine
        assert cfg_mgr.get("wan_monitor_enabled") is True
        assert cfg_mgr.get("wan_check_interval_sec") == 25

        # Stopping host monitor leaves autonomous WAN running; shutdown stops both cleanly
        view.stop_monitor()
        assert view.wan_view.is_continuous_active() is True
        view.shutdown()
        assert view.wan_view.is_continuous_active() is False

        assert CURRENT_VERSION == "v3.6.1"
        iss_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "build_scripts", "setup_compiler.iss")
        )
        with open(iss_path, "r", encoding="utf-8") as f:
            iss_text = f.read()
        assert "AppVersion=3.6.1" in iss_text
        assert "OutputBaseFilename=Install_BahaaIT_v3.6.1" in iss_text

    def test_spinbox_qss_and_incident_deletion(self, tmp_path):
        # 1. Verify QSS fixes QSpinBox/QDoubleSpinBox inner QLineEdit padding/clipping and WAN spinbox width
        qss_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "src", "ui", "styles.qss")
        )
        with open(qss_path, "r", encoding="utf-8") as f:
            qss = f.read()
        assert "QSpinBox QLineEdit, QDoubleSpinBox QLineEdit" in qss
        assert "padding: 0px;" in qss
        assert "min-height: 0px;" in qss

        wan_view = WANMonitorView(WANMonitor(gateway_ip="192.168.1.1"))
        assert wan_view.interval_spin.minimumWidth() >= 90

        # 2. Verify deleting an active incident with linked AlertEvent from IncidentCenterWidget
        db = DatabaseManager(db_path=str(tmp_path / "ui_del.db"))
        db.add_host("10.10.2.5", "Branch-FW")
        host_id = db.get_hosts()[0]["id"]
        inc_mgr = IncidentManager(db)
        now = datetime.utcnow()
        tr = StateTransition(
            host_address="10.10.2.5",
            previous_state=HostState.DEGRADED,
            new_state=HostState.DOWN,
            changed=True,
            reason="CONFIRMED_OUTAGE",
            details="5 failures",
            timestamp_mono=10.0,
            timestamp_utc=now,
        )
        qual = QualitySnapshot(
            current_latency_ms=None, min_latency_ms=5.0, max_latency_ms=10.0, avg_latency_ms=7.0,
            p95_latency_ms=9.0, jitter_ms=1.0, packet_loss_pct=100.0, consecutive_successes=0,
            consecutive_failures=5, uptime_pct=50.0, last_success_utc=now - timedelta(seconds=10),
            last_failure_utc=now, total_probes=10, valid_probes=10, timeout_count=5,
            dns_error_count=0, engine_error_count=0,
        )
        created = inc_mgr.handle_transition(host_id, "Branch-FW", "10.10.2.5", tr, qual)
        assert created is not None
        db.save_alert_event({
            "host_id": host_id,
            "host_address": "10.10.2.5",
            "host_name": "Branch-FW",
            "incident_id": created["id"],
            "severity": "CRITICAL",
            "event_type": "HOST_DOWN",
            "message": "Down",
        })

        inc_widget = IncidentCenterWidget(inc_mgr, db)
        assert inc_widget.table.rowCount() == 1
        active_counts = []
        changed_calls = []
        inc_widget.active_count_changed.connect(active_counts.append)
        inc_widget.incidents_changed.connect(lambda: changed_calls.append(1))

        # Canceling confirmation keeps the incident intact
        inc_widget.table.selectRow(0)
        inc_widget.table.setCurrentCell(0, 0)
        with patch.object(QMessageBox, "question", return_value=QMessageBox.No):
            assert inc_widget.delete_selected() is False
        assert db.get_incident_by_id(created["id"]) is not None
        assert inc_widget.table.rowCount() == 1

        # Confirming deletion removes incident, clears active cache, preserves AlertEvent (incident_id=None)
        inc_widget.table.selectRow(0)
        inc_widget.table.setCurrentCell(0, 0)
        with patch.object(QMessageBox, "question", return_value=QMessageBox.Yes):
            assert inc_widget.delete_selected() is True

        assert db.get_incident_by_id(created["id"]) is None
        assert inc_mgr.get_active_incident("10.10.2.5") is None
        assert inc_widget.table.rowCount() == 0
        assert active_counts[-1] == 0
        assert len(changed_calls) == 1
        alerts = db.get_alert_events(host_address="10.10.2.5")
        assert len(alerts) == 1
        assert alerts[0]["incident_id"] is None

        # 3. Verify deleting an incident via HostDetailsDialog
        created2 = inc_mgr.handle_transition(
            host_id,
            "Branch-FW",
            "10.10.2.5",
            StateTransition(
                host_address="10.10.2.5",
                previous_state=HostState.UP,
                new_state=HostState.DOWN,
                changed=True,
                reason="CONFIRMED_OUTAGE",
                details="5 failures",
                timestamp_mono=40.0,
                timestamp_utc=now + timedelta(seconds=30),
            ),
            qual,
        )
        assert created2 is not None

        stats_svc = MonitoringStatisticsService(db)
        engine = AsyncPingEngine(db)
        engine.add_host("10.10.2.5", "Branch-FW", host_id=host_id)
        dlg = HostDetailsDialog("10.10.2.5", "Branch-FW", db, engine, inc_mgr, stats_svc)
        dlg_changed = []
        dlg.incidents_changed.connect(lambda: dlg_changed.append(1))
        assert dlg.inc_table.rowCount() == 1

        dlg.inc_table.selectRow(0)
        dlg.inc_table.setCurrentCell(0, 0)
        with patch.object(QMessageBox, "question", return_value=QMessageBox.Yes):
            assert dlg._delete_host_incident() is True

        assert db.get_incident_by_id(created2["id"]) is None
        assert inc_mgr.get_active_incident("10.10.2.5") is None
        assert dlg.inc_table.rowCount() == 0
        assert len(dlg_changed) == 1
        dlg.close()
