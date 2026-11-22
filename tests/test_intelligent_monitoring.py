import asyncio
import os
import sqlite3
import sys
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import psutil
import pytest
from PySide6.QtWidgets import QApplication

# Ensure src is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.alert_manager import AlertManager, AlertSeverity
from core.incident_manager import IncidentManager, IncidentSeverity, IncidentStatus
from core.monitoring_state import (
    HostState,
    HostStateMachine,
    MonitoringPolicyConfig,
    ProbeOutcome,
    validate_target_address,
)
from core.monitoring_statistics import MonitoringStatisticsService
from core.network_quality import NetworkQualityAnalyzer, ProbeSample
from core.ping_engine import AsyncPingEngine
from core.wan_monitor import WANMonitor
from utils.db import DatabaseManager
from utils.monitoring_export import (
    export_incidents_csv,
    export_incidents_pdf,
    export_monitoring_config,
    import_monitoring_config,
)
from utils.notification_manager import NotificationDispatcher


_qapp = QApplication.instance() or QApplication(sys.argv)


def _feed_sequence(sm: HostStateMachine, analyzer: NetworkQualityAnalyzer, seq):
    transitions = []
    now_mono = 100.0
    base_utc = datetime(2026, 11, 19, 10, 0, 0)
    last_snap = None
    for i, (outcome, lat) in enumerate(seq):
        ts_mono = now_mono + i
        ts_utc = base_utc + timedelta(seconds=i)
        last_snap = analyzer.add_sample(
            ProbeSample(timestamp_mono=ts_mono, timestamp_utc=ts_utc, outcome=outcome, latency_ms=lat)
        )
        tr = sm.process_probe(
            outcome=outcome,
            quality_snapshot=last_snap,
            now_mono=ts_mono,
            now_utc=ts_utc,
            window_samples=analyzer.get_window_samples(),
        )
        transitions.append((tr, last_snap))
    return transitions


class TestIntelligentMonitoringScenarios:
    def test_01_isolated_packet_loss(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "m1.db"))
        db.add_host("10.0.0.1", "Core-GW")
        alarm_mock = MagicMock()
        tray_mock = MagicMock()
        dispatcher = NotificationDispatcher(alarm_manager=alarm_mock, tray_manager=tray_mock, sync_email=True)
        alert_mgr = AlertManager(db, dispatcher=dispatcher)
        inc_mgr = IncidentManager(db)
        policy = MonitoringPolicyConfig()
        analyzer = NetworkQualityAnalyzer(window_sec=60)
        sm = HostStateMachine("10.0.0.1", policy=policy)

        seq = [
            (ProbeOutcome.SUCCESS, 12.0),
            (ProbeOutcome.SUCCESS, 13.0),
            (ProbeOutcome.TIMEOUT, None),  # 1 isolated lost packet
            (ProbeOutcome.SUCCESS, 11.0),
        ]
        results = _feed_sequence(sm, analyzer, seq)
        for tr, snap in results:
            inc = inc_mgr.handle_transition(1, "Core-GW", "10.0.0.1", tr, snap) if tr.changed else None
            alert_mgr.evaluate_transition(1, "Core-GW", "10.0.0.1", tr, snap, policy, inc)

        assert sm.state == HostState.UP
        assert inc_mgr.get_incidents() == []
        alarm_mock.play.assert_not_called()

    def test_02_three_consecutive_failures_degraded(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "m2.db"))
        db.add_host("10.0.0.2", "Switch-1")
        alarm_mock = MagicMock()
        dispatcher = NotificationDispatcher(alarm_manager=alarm_mock, sync_email=True)
        alert_mgr = AlertManager(db, dispatcher=dispatcher)
        inc_mgr = IncidentManager(db)
        policy = MonitoringPolicyConfig(warning_failures=3, critical_failures=5)
        analyzer = NetworkQualityAnalyzer()
        sm = HostStateMachine("10.0.0.2", policy=policy, initial_state=HostState.UP)

        seq = [(ProbeOutcome.TIMEOUT, None)] * 3
        results = _feed_sequence(sm, analyzer, seq)
        for tr, snap in results:
            inc = inc_mgr.handle_transition(1, "Switch-1", "10.0.0.2", tr, snap) if tr.changed else None
            alert_mgr.evaluate_transition(1, "Switch-1", "10.0.0.2", tr, snap, policy, inc)

        assert sm.state == HostState.DEGRADED
        alarm_mock.play.assert_not_called()
        alerts = db.get_alert_events(severity="WARNING")
        assert len(alerts) == 1
        assert len(inc_mgr.get_incidents()) == 1
        assert inc_mgr.get_incidents()[0]["severity"] == IncidentSeverity.WARNING.value

    def test_03_five_consecutive_failures_down(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "m3.db"))
        db.add_host("10.0.0.3", "FW-Edge")
        alarm_mock = MagicMock()
        tray_mock = MagicMock()
        tray_mock.tray_icon = MagicMock()
        email_mock = MagicMock()
        email_mock.send_alert_email.return_value = (True, "")
        cfg_mock = MagicMock()
        cfg_mock.get.side_effect = lambda k, d=None: {"email_alerts_enabled": True, "email_alert_on_down": True, "email_alert_on_up": True}.get(k, d)

        dispatcher = NotificationDispatcher(
            alarm_manager=alarm_mock, tray_manager=tray_mock, email_notifier=email_mock, config_manager=cfg_mock, sync_email=True
        )
        alert_mgr = AlertManager(db, dispatcher=dispatcher, config_manager=cfg_mock)
        inc_mgr = IncidentManager(db)
        policy = MonitoringPolicyConfig()
        analyzer = NetworkQualityAnalyzer()
        sm = HostStateMachine("10.0.0.3", policy=policy, initial_state=HostState.UP)

        seq = [(ProbeOutcome.SUCCESS, 10.0)] * 2 + [(ProbeOutcome.TIMEOUT, None)] * 5
        results = _feed_sequence(sm, analyzer, seq)
        for tr, snap in results:
            inc = inc_mgr.handle_transition(1, "FW-Edge", "10.0.0.3", tr, snap) if tr.changed else inc_mgr.get_active_incident("10.0.0.3")
            alert_mgr.evaluate_transition(1, "FW-Edge", "10.0.0.3", tr, snap, policy, inc)

        assert sm.state == HostState.DOWN
        alarm_mock.play.assert_called()
        email_mock.send_alert_email.assert_called_once()
        tray_mock.tray_icon.showMessage.assert_called()
        incs = inc_mgr.get_incidents()
        assert len(incs) == 1
        assert incs[0]["severity"] == IncidentSeverity.CRITICAL.value
        assert incs[0]["incident_type"] == "OUTAGE"
        assert incs[0]["avg_latency_before_ms"] == 10.0

    def test_04_recovery_after_three_successes(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "m4.db"))
        db.add_host("10.0.0.4", "AP-1")
        alarm_mock = MagicMock()
        email_mock = MagicMock()
        email_mock.send_alert_email.return_value = (True, "")
        cfg_mock = MagicMock()
        cfg_mock.get.side_effect = lambda k, d=None: {"email_alerts_enabled": True, "email_alert_on_down": True, "email_alert_on_up": True}.get(k, d)

        dispatcher = NotificationDispatcher(
            alarm_manager=alarm_mock, email_notifier=email_mock, config_manager=cfg_mock, sync_email=True
        )
        alert_mgr = AlertManager(db, dispatcher=dispatcher, config_manager=cfg_mock)
        inc_mgr = IncidentManager(db)
        policy = MonitoringPolicyConfig(critical_failures=5, recovery_successes=3)
        analyzer = NetworkQualityAnalyzer()
        sm = HostStateMachine("10.0.0.4", policy=policy, initial_state=HostState.UP)

        seq = (
            [(ProbeOutcome.TIMEOUT, None)] * 5
            + [(ProbeOutcome.SUCCESS, 14.0), (ProbeOutcome.SUCCESS, 15.0), (ProbeOutcome.SUCCESS, 12.0)]
        )
        states_seen = []
        results = _feed_sequence(sm, analyzer, seq)
        for tr, snap in results:
            states_seen.append(sm.state if tr == results[-1][0] else tr.new_state)
            inc = inc_mgr.handle_transition(1, "AP-1", "10.0.0.4", tr, snap) if tr.changed else inc_mgr.get_active_incident("10.0.0.4")
            alert_mgr.evaluate_transition(1, "AP-1", "10.0.0.4", tr, snap, policy, inc)

        assert HostState.RECOVERING in states_seen
        assert sm.state == HostState.UP
        assert states_seen[-3:] == [HostState.RECOVERING, HostState.RECOVERING, HostState.UP]
        # DOWN email + Recovery UP email = 2 calls
        assert email_mock.send_alert_email.call_count == 2
        alarm_mock.stop.assert_called()
        incs = inc_mgr.get_incidents()
        assert len(incs) == 1
        assert incs[0]["status"] == IncidentStatus.RECOVERED.value
        assert incs[0]["recovery_latency_ms"] == 12.0
        assert incs[0]["duration_seconds"] >= 3.0

    def test_05_intermittent_packet_loss(self):
        policy = MonitoringPolicyConfig(packet_loss_warn_pct=15.0, min_probes_for_quality_warn=5)
        analyzer = NetworkQualityAnalyzer(window_sec=60)
        sm = HostStateMachine("10.0.0.5", policy=policy, initial_state=HostState.UP)

        # Non-consecutive failures: 2 timeouts in 10 probes = 20% packet loss >= 15%
        seq = [
            (ProbeOutcome.SUCCESS, 10.0),
            (ProbeOutcome.TIMEOUT, None),
            (ProbeOutcome.SUCCESS, 11.0),
            (ProbeOutcome.SUCCESS, 10.0),
            (ProbeOutcome.SUCCESS, 12.0),
            (ProbeOutcome.TIMEOUT, None),
            (ProbeOutcome.SUCCESS, 10.0),
        ]
        results = _feed_sequence(sm, analyzer, seq)
        assert sm.state == HostState.DEGRADED
        assert sm.degraded_reason == "PACKET_LOSS"
        assert results[-1][1].packet_loss_pct == round((2 / 7) * 100.0, 2)

    def test_06_high_latency(self):
        policy = MonitoringPolicyConfig(latency_warn_ms=150.0, min_probes_for_quality_warn=5)
        analyzer = NetworkQualityAnalyzer(window_sec=60)
        sm = HostStateMachine("10.0.0.6", policy=policy, initial_state=HostState.UP)

        seq = [(ProbeOutcome.SUCCESS, 210.0)] * 5
        results = _feed_sequence(sm, analyzer, seq)
        assert sm.state == HostState.DEGRADED
        assert sm.degraded_reason == "HIGH_LATENCY"
        assert results[-1][1].avg_latency_ms == 210.0

    def test_07_excessive_jitter(self):
        policy = MonitoringPolicyConfig(jitter_warn_ms=30.0, latency_warn_ms=300.0, min_probes_for_quality_warn=5)
        analyzer = NetworkQualityAnalyzer(window_sec=60)
        sm = HostStateMachine("10.0.0.7", policy=policy, initial_state=HostState.UP)

        # Oscillating RTTs: 10, 90, 10, 90, 10 -> successive diffs all 80ms -> jitter = 80ms
        seq = [
            (ProbeOutcome.SUCCESS, 10.0),
            (ProbeOutcome.SUCCESS, 90.0),
            (ProbeOutcome.SUCCESS, 10.0),
            (ProbeOutcome.SUCCESS, 90.0),
            (ProbeOutcome.SUCCESS, 10.0),
        ]
        results = _feed_sequence(sm, analyzer, seq)
        assert results[-1][1].jitter_ms == 80.0
        assert sm.state == HostState.DEGRADED
        assert sm.degraded_reason == "HIGH_JITTER"

    def test_08_multiple_hosts_simultaneously(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "m8.db"))

        async def mock_probe(target: str, timeout_sec: float):
            await asyncio.sleep(0.005)
            idx = int(target.rsplit(".", 1)[-1])
            if idx % 3 == 0:
                return ProbeOutcome.TIMEOUT, None, "Request timed out."
            return ProbeOutcome.SUCCESS, float(10 + idx), f"Reply {10 + idx}ms"

        policy = MonitoringPolicyConfig(probe_interval_ms=80, timeout_ms=500, warning_failures=2, critical_failures=4)
        engine = AsyncPingEngine(db=db, global_policy=policy, probe_func=mock_probe, batch_flush_interval_sec=0.2)

        for i in range(1, 11):
            addr = f"192.168.50.{i}"
            db.add_host(addr, f"Node-{i}")
            ok, err = engine.add_host(addr, f"Node-{i}")
            assert ok, err

        engine.start()
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            snaps = engine.get_all_snapshots()
            if all(s["probe_count"] >= 4 for s in snaps.values()):
                break
            _qapp.processEvents()
            time.sleep(0.05)

        engine.stop()
        snaps = engine.get_all_snapshots()
        assert len(snaps) == 10
        assert snaps["192.168.50.3"]["state"] == HostState.DOWN.value
        assert snaps["192.168.50.1"]["state"] == HostState.UP.value

    def test_09_network_interface_disconnection(self):
        analyzer = NetworkQualityAnalyzer(window_sec=60)
        base = datetime(2026, 11, 19, 10, 0, 0)
        for i in range(5):
            analyzer.add_sample(ProbeSample(10.0 + i, base + timedelta(seconds=i), ProbeOutcome.SUCCESS, 15.0))
        # Local NIC / OS permission errors and DNS errors must stay separated from ICMP packet loss
        analyzer.add_sample(ProbeSample(15.0, base + timedelta(seconds=5), ProbeOutcome.ENGINE_ERROR, None, "Socket down"))
        snap = analyzer.add_sample(ProbeSample(16.0, base + timedelta(seconds=6), ProbeOutcome.DNS_ERROR, None, "DNS failed"))

        assert snap.valid_probes == 5
        assert snap.packet_loss_pct == 0.0
        assert snap.engine_error_count == 1
        assert snap.dns_error_count == 1

    def test_10_scheduler_overload_not_packet_loss(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "m10.db"))
        # Fake clock that jumps forward +5s on second call to simulate OS freeze / scheduler overload
        calls = {"n": 0}

        def jumping_clock():
            calls["n"] += 1
            if calls["n"] >= 3:
                return 100.0 + calls["n"] * 5.0
            return 10.0

        async def ok_probe(target, timeout):
            return ProbeOutcome.SUCCESS, 5.0, "OK"

        policy = MonitoringPolicyConfig(probe_interval_ms=200, timeout_ms=500)
        engine = AsyncPingEngine(
            db=db, global_policy=policy, probe_func=ok_probe, clock_fn=jumping_clock, batch_flush_interval_sec=0.2
        )
        engine.add_host("10.0.0.10", "LagHost")
        engine.start()
        time.sleep(0.5)
        engine.stop()

        snap = engine.get_host_snapshot("10.0.0.10")
        assert snap is not None
        assert snap["state"] != HostState.DOWN.value
        assert snap["packet_loss_pct"] == 0.0
        assert snap["engine_error_count"] >= 1

    def test_11_clean_shutdown_during_monitoring(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "m11.db"))
        db.add_host("10.0.0.11", "FlushHost")

        async def fast_probe(target, timeout):
            return ProbeOutcome.SUCCESS, 7.5, "OK"

        policy = MonitoringPolicyConfig(probe_interval_ms=60, timeout_ms=500)
        engine = AsyncPingEngine(db=db, global_policy=policy, probe_func=fast_probe, batch_flush_interval_sec=60.0)
        engine.add_host("10.0.0.11", "FlushHost")
        engine.start()
        time.sleep(0.35)
        t0 = time.monotonic()
        engine.stop(timeout_ms=3000)
        elapsed = time.monotonic() - t0

        assert not engine.isRunning()
        assert elapsed < 2.0
        # Buffer must have been flushed cleanly on shutdown
        stored = db.get_measurements("10.0.0.11")
        assert len(stored) >= 1

    def test_12_duplicate_notification_prevention(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "m12.db"))
        db.add_host("10.0.0.12", "Router")
        alarm_mock = MagicMock()
        email_mock = MagicMock()
        email_mock.send_alert_email.return_value = (True, "")
        cfg_mock = MagicMock()
        cfg_mock.get.side_effect = lambda k, d=None: {"email_alerts_enabled": True, "email_alert_on_down": True, "email_alert_on_up": True}.get(k, d)

        dispatcher = NotificationDispatcher(
            alarm_manager=alarm_mock, email_notifier=email_mock, config_manager=cfg_mock, sync_email=True
        )
        alert_mgr = AlertManager(db, dispatcher=dispatcher, config_manager=cfg_mock)
        inc_mgr = IncidentManager(db)
        policy = MonitoringPolicyConfig(critical_failures=5, repeat_alert_interval_sec=0)
        analyzer = NetworkQualityAnalyzer()
        sm = HostStateMachine("10.0.0.12", policy=policy, initial_state=HostState.UP)

        # 15 consecutive failures should still create 1 incident and send only 1 DOWN email
        results = _feed_sequence(sm, analyzer, [(ProbeOutcome.TIMEOUT, None)] * 15)
        for tr, snap in results:
            inc = inc_mgr.handle_transition(1, "Router", "10.0.0.12", tr, snap) if tr.changed else inc_mgr.get_active_incident("10.0.0.12")
            alert_mgr.evaluate_transition(1, "Router", "10.0.0.12", tr, snap, policy, inc)

        assert len(inc_mgr.get_incidents()) == 1
        assert email_mock.send_alert_email.call_count == 1
        assert alarm_mock.play.call_count == 1

    def test_13_email_notification_failure(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "m13.db"))
        db.add_host("10.0.0.13", "MailTest")
        cfg_mock = MagicMock()
        secret_pw = "SuperSecretSmtpPass_999"
        cfg_mock.get.side_effect = lambda k, d=None: {
            "email_alerts_enabled": True,
            "email_alert_on_down": True,
            "email_use_custom_smtp": True,
            "email_smtp_host": "smtp.example.local",
            "email_smtp_port": 465,
            "email_smtp_user": "noc@example.local",
            "email_smtp_password": secret_pw,
            "email_sender": "noc@example.local",
            "email_recipient": "admin1@example.local; admin2@example.local",
        }.get(k, d)

        from utils.email_notifier import EmailNotifier
        notifier = EmailNotifier(config_manager=cfg_mock)
        with patch.object(notifier, "_send_raw_smtp", side_effect=RuntimeError(f"Auth failed for {secret_pw}")):
            dispatcher = NotificationDispatcher(email_notifier=notifier, config_manager=cfg_mock, sync_email=True)
            alert_mgr = AlertManager(db, dispatcher=dispatcher, config_manager=cfg_mock)
            inc_mgr = IncidentManager(db)
            policy = MonitoringPolicyConfig(critical_failures=2, warning_failures=1)
            analyzer = NetworkQualityAnalyzer()
            sm = HostStateMachine("10.0.0.13", policy=policy, initial_state=HostState.UP)

            results = _feed_sequence(sm, analyzer, [(ProbeOutcome.TIMEOUT, None)] * 2)
            for tr, snap in results:
                inc = inc_mgr.handle_transition(1, "MailTest", "10.0.0.13", tr, snap) if tr.changed else None
                alert_mgr.evaluate_transition(1, "MailTest", "10.0.0.13", tr, snap, policy, inc)

        failed_events = [e for e in db.get_alert_events() if e["channel"] == "EMAIL"]
        assert len(failed_events) == 1
        assert failed_events[0]["delivered"] is False
        assert secret_pw not in (failed_events[0]["error_detail"] or "")

    def test_14_incident_creation(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "m14.db"))
        db.add_host("10.0.0.14", "DB-Server")
        inc_mgr = IncidentManager(db)
        policy = MonitoringPolicyConfig(critical_failures=3, warning_failures=2)
        analyzer = NetworkQualityAnalyzer()
        sm = HostStateMachine("10.0.0.14", policy=policy, initial_state=HostState.UP)

        seq = [(ProbeOutcome.SUCCESS, 20.0)] * 3 + [(ProbeOutcome.TIMEOUT, None)] * 3
        results = _feed_sequence(sm, analyzer, seq)
        for tr, snap in results:
            if tr.changed:
                inc_mgr.handle_transition(1, "DB-Server", "10.0.0.14", tr, snap)

        incs = inc_mgr.get_incidents()
        assert len(incs) == 1
        inc = incs[0]
        assert inc["incident_uid"].startswith("INC-")
        assert inc["status"] == IncidentStatus.DETECTED.value
        assert inc["acknowledged"] is False
        assert inc["avg_latency_before_ms"] == 20.0

        acked = inc_mgr.acknowledge_incident(inc["id"], "Checking ISP fiber")
        assert acked["status"] == IncidentStatus.ACKNOWLEDGED.value
        assert acked["acknowledged"] is True
        assert "Checking ISP fiber" in acked["comments"]

    def test_15_incident_recovery_and_host_deletion_preservation(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "m15.db"))
        db.add_host("10.0.0.15", "TempNode")
        host_row = db.get_hosts()[0]
        inc_mgr = IncidentManager(db)
        policy = MonitoringPolicyConfig(warning_failures=2, critical_failures=3, recovery_successes=3)
        analyzer = NetworkQualityAnalyzer()
        sm = HostStateMachine("10.0.0.15", policy=policy, initial_state=HostState.UP)

        seq = [(ProbeOutcome.TIMEOUT, None)] * 3 + [(ProbeOutcome.SUCCESS, 9.0)] * 3
        results = _feed_sequence(sm, analyzer, seq)
        for tr, snap in results:
            if tr.changed:
                inc_mgr.handle_transition(host_row["id"], "TempNode", "10.0.0.15", tr, snap)

        # Delete the host — incident history MUST survive!
        db.delete_host("10.0.0.15")
        assert db.get_hosts() == []
        remaining = inc_mgr.get_incidents(host_address="10.0.0.15")
        assert len(remaining) == 1
        assert remaining[0]["status"] == IncidentStatus.RECOVERED.value
        assert remaining[0]["recovery_latency_ms"] == 9.0
        assert remaining[0]["host_id"] is None

    def test_16_database_migration_from_v330(self, tmp_path):
        db_file = str(tmp_path / "legacy_v330.db")
        # Create an exact raw v3.3.0 schema without new columns or new tables
        conn = sqlite3.connect(db_file)
        conn.execute(
            """CREATE TABLE hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address VARCHAR NOT NULL UNIQUE,
                label VARCHAR,
                is_active BOOLEAN,
                created_at DATETIME
            )"""
        )
        conn.execute(
            """CREATE TABLE monitoring_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                timestamp DATETIME,
                status VARCHAR,
                latency INTEGER,
                response VARCHAR
            )"""
        )
        conn.execute(
            "INSERT INTO hosts (id, address, label, is_active, created_at) VALUES (1, '192.168.1.1', 'LegacyGW', 1, '2026-01-01 00:00:00')"
        )
        conn.execute(
            "INSERT INTO monitoring_logs (host_id, timestamp, status, latency, response) VALUES (1, '2026-11-18 12:00:00', 'UP', 4, 'OK')"
        )
        conn.commit()
        conn.close()

        db = DatabaseManager(db_path=db_file)
        hosts = db.get_hosts()
        assert len(hosts) == 1
        assert hosts[0]["address"] == "192.168.1.1"
        assert hosts[0]["category"] == "General"
        assert hosts[0]["profile"] == "Standard"

        # Verify all 5 new tables exist and accept writes
        db.save_policy({"probe_interval_ms": 1500})
        assert db.get_policy()["probe_interval_ms"] == 1500
        assert len(db.get_host_history("192.168.1.1")) == 1

    def test_17_historical_statistics_and_retention(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "m17.db"))
        stats_svc = MonitoringStatisticsService(db)
        now = datetime.utcnow()

        batch = []
        for i in range(10):
            batch.append({
                "host_address": "10.0.0.17",
                "timestamp": now - timedelta(seconds=30 - i),
                "status": "UP" if i != 5 else "TIMEOUT",
                "latency_ms": float(10 + i * 2) if i != 5 else None,
                "is_valid_probe": True,
            })
        # Add old expired record (> 7 days)
        batch.append({
            "host_address": "10.0.0.17",
            "timestamp": now - timedelta(days=10),
            "status": "UP",
            "latency_ms": 10.0,
            "is_valid_probe": True,
        })
        db.save_measurements_batch(batch)

        series_1m = stats_svc.get_chart_series("10.0.0.17", period="1m")
        assert len(series_1m) >= 1
        assert stats_svc.persist_rollups("10.0.0.17", granularity="1m", since=now - timedelta(minutes=2)) >= 1

        deleted = db.cleanup_by_retention(raw_days=7, aggregated_days=90, incidents_days=365, alerts_days=365)
        assert deleted["raw"] == 1

        # Verify export CSV/PDF/Config round-trip
        csv_path = str(tmp_path / "inc.csv")
        pdf_path = str(tmp_path / "inc.pdf")
        cfg_path = str(tmp_path / "mon_cfg.json")
        sample_inc = [{
            "incident_uid": "INC-20261119-AAAAAA",
            "host_name": "Core",
            "host_address": "10.0.0.17",
            "incident_type": "OUTAGE",
            "severity": "CRITICAL",
            "status": "RECOVERED",
            "start_time": now - timedelta(minutes=5),
            "end_time": now,
            "duration_seconds": 300.0,
            "failed_probes": 12,
            "packet_loss_pct": 100.0,
            "avg_latency_before_ms": 15.0,
            "recovery_latency_ms": 14.0,
            "acknowledged": True,
            "comments": "ISP fiber flap",
        }]
        ok_csv, _ = export_incidents_csv(sample_inc, csv_path)
        ok_pdf, _ = export_incidents_pdf(sample_inc, pdf_path)
        assert ok_csv and os.path.exists(csv_path)
        assert ok_pdf and os.path.getsize(pdf_path) > 500

        ok_exp, _ = export_monitoring_config(MonitoringPolicyConfig().to_dict(), {}, cfg_path)
        assert ok_exp
        ok_imp, cfg_data, _ = import_monitoring_config(cfg_path)
        assert ok_imp and cfg_data["global_policy"]["probe_interval_ms"] == 1000

    def test_18_wan_outage_correlation(self):
        # 1. ICMP blocked upstream, but HTTPS works -> NOT an ISP outage
        v_icmp_filtered = WANMonitor.correlate(
            gateway_up=True, google_up=False, cloudflare_up=False, dns_ok=True, https_ok=True
        )
        assert v_icmp_filtered.verdict_code == "ICMP_FILTERED_WAN_OK"
        assert v_icmp_filtered.severity == "WARNING"

        # 2. ICMP failed alone without secondary confirmation -> SUSPECTED, never CONFIRMED
        v_suspected = WANMonitor.correlate(
            gateway_up=True, google_up=False, cloudflare_up=False, dns_ok=None, https_ok=None
        )
        assert v_suspected.verdict_code == "WAN_OUTAGE_SUSPECTED"
        assert v_suspected.severity == "WARNING"

        # 3. Gateway UP + Google/Cloudflare/DNS/HTTPS all fail -> Confirmed WAN outage
        v_confirmed = WANMonitor.correlate(
            gateway_up=True, google_up=False, cloudflare_up=False, dns_ok=False, https_ok=False
        )
        assert v_confirmed.verdict_code == "WAN_OUTAGE_CONFIRMED"
        assert v_confirmed.severity == "CRITICAL"

        # 4. Gateway DOWN + WAN DOWN -> LAN / router / Wi-Fi issue
        v_lan = WANMonitor.correlate(
            gateway_up=False, google_up=False, cloudflare_up=False, dns_ok=False, https_ok=False
        )
        assert v_lan.verdict_code == "LAN_GATEWAY_ISSUE"

        # 5. Gateway UP + Google UP + Cloudflare DOWN -> Destination routing issue
        v_dest = WANMonitor.correlate(gateway_up=True, google_up=True, cloudflare_up=False)
        assert v_dest.verdict_code == "DESTINATION_ROUTING_ISSUE"

        # 6. Gateway UP + WAN UP + DNS FAILED -> DNS failure
        v_dns = WANMonitor.correlate(gateway_up=True, google_up=True, cloudflare_up=True, dns_ok=False, https_ok=True)
        assert v_dns.verdict_code == "DNS_FAILURE"

    def test_19_false_positive_and_flapping_prevention(self, tmp_path):
        # Validate target sanitization blocks command injection payloads
        ok_bad, _ = validate_target_address("8.8.8.8 && calc.exe")
        assert ok_bad is False
        ok_good, cleaned = validate_target_address("https://router.local:8443/login")
        assert ok_good is True and cleaned == "router.local"

        # Flapping during recovery: DOWN -> 1 ok (RECOVERING) -> 1 fail (back to DOWN) must NOT duplicate incident or spam emails
        db = DatabaseManager(db_path=str(tmp_path / "m19.db"))
        db.add_host("10.0.0.19", "FlapHost")
        email_mock = MagicMock()
        email_mock.send_alert_email.return_value = (True, "")
        cfg_mock = MagicMock()
        cfg_mock.get.side_effect = lambda k, d=None: {"email_alerts_enabled": True, "email_alert_on_down": True, "email_alert_on_up": True}.get(k, d)

        dispatcher = NotificationDispatcher(email_notifier=email_mock, config_manager=cfg_mock, sync_email=True)
        alert_mgr = AlertManager(db, dispatcher=dispatcher, config_manager=cfg_mock)
        inc_mgr = IncidentManager(db)
        policy = MonitoringPolicyConfig(critical_failures=3, warning_failures=2, recovery_successes=3)
        analyzer = NetworkQualityAnalyzer()
        sm = HostStateMachine("10.0.0.19", policy=policy, initial_state=HostState.UP)

        seq = [
            (ProbeOutcome.TIMEOUT, None),
            (ProbeOutcome.TIMEOUT, None),
            (ProbeOutcome.TIMEOUT, None),  # -> DOWN
            (ProbeOutcome.SUCCESS, 15.0),  # -> RECOVERING
            (ProbeOutcome.TIMEOUT, None),  # -> back to DOWN cleanly
        ]
        results = _feed_sequence(sm, analyzer, seq)
        for tr, snap in results:
            inc = inc_mgr.handle_transition(1, "FlapHost", "10.0.0.19", tr, snap) if tr.changed else inc_mgr.get_active_incident("10.0.0.19")
            alert_mgr.evaluate_transition(1, "FlapHost", "10.0.0.19", tr, snap, policy, inc)

        assert sm.state == HostState.DOWN
        assert len(inc_mgr.get_incidents()) == 1
        assert email_mock.send_alert_email.call_count == 1  # No recovery email & no duplicate DOWN email

    def test_20_pause_and_resume_monitoring(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "m20.db"))

        async def fast_probe(target, timeout):
            return ProbeOutcome.SUCCESS, 5.0, "OK"

        policy = MonitoringPolicyConfig(probe_interval_ms=60, timeout_ms=500)
        engine = AsyncPingEngine(db=db, global_policy=policy, probe_func=fast_probe, batch_flush_interval_sec=0.2)
        engine.add_host("10.0.0.20", "PauseNode")
        engine.start()
        time.sleep(0.25)

        engine.pause_host("10.0.0.20")
        snap_paused = engine.get_host_snapshot("10.0.0.20")
        assert snap_paused["state"] == HostState.PAUSED.value
        count_at_pause = snap_paused["probe_count"]
        time.sleep(0.2)
        assert engine.get_host_snapshot("10.0.0.20")["probe_count"] == count_at_pause

        engine.resume_host("10.0.0.20")
        time.sleep(0.25)
        engine.stop()
        snap_resumed = engine.get_host_snapshot("10.0.0.20")
        assert snap_resumed["state"] == HostState.UP.value
        assert snap_resumed["probe_count"] > count_at_pause

    def test_21_benchmark_100_hosts_concurrent(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "bench_100.db"))
        active_per_host = {}
        overlap_detected = []

        async def bench_probe(target: str, timeout_sec: float):
            if active_per_host.get(target):
                overlap_detected.append(target)
            active_per_host[target] = True
            try:
                await asyncio.sleep(0.002)
                return ProbeOutcome.SUCCESS, 12.5, "OK"
            finally:
                active_per_host[target] = False

        proc = psutil.Process(os.getpid())
        mem_before_mb = proc.memory_info().rss / (1024 * 1024)
        cpu_before = proc.cpu_times().user + proc.cpu_times().system

        policy = MonitoringPolicyConfig(probe_interval_ms=200, timeout_ms=1000)
        engine = AsyncPingEngine(
            db=db,
            global_policy=policy,
            probe_func=bench_probe,
            batch_flush_interval_sec=0.5,
            max_concurrent=150,
        )

        for i in range(1, 101):
            addr = f"10.20.{i // 50}.{10 + (i % 50)}"
            ok, err = engine.add_host(addr, f"Host-{i}")
            assert ok, err

        t_start = time.monotonic()
        engine.start()
        time.sleep(1.25)
        engine.stop(timeout_ms=3000)
        elapsed = time.monotonic() - t_start

        mem_after_mb = proc.memory_info().rss / (1024 * 1024)
        cpu_after = proc.cpu_times().user + proc.cpu_times().system

        snaps = engine.get_all_snapshots()
        total_probes = sum(s["probe_count"] for s in snaps.values())
        avg_probes_per_host = total_probes / len(snaps)

        print(
            f"\n[100-Host Benchmark] hosts={len(snaps)}, total_probes={total_probes}, "
            f"avg_per_host={avg_probes_per_host:.1f}, elapsed={elapsed:.2f}s, "
            f"cpu_time={cpu_after - cpu_before:.3f}s, rss_delta={mem_after_mb - mem_before_mb:+.2f}MB"
        )

        assert len(snaps) == 100
        assert overlap_detected == []
        assert total_probes >= 300
        assert (mem_after_mb - mem_before_mb) < 80.0
