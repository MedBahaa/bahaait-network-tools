import asyncio
from datetime import datetime, timedelta
import os
import socket
import sys
import time
from typing import Any, Dict, List

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.anomaly_detector import AnomalyDetectorConfig, StatisticalAnomalyDetector
from core.intelligence_engine import IntelligenceEngine
from core.snmp_client import SNMPClient
from core.snmp_engine import AsyncSNMPEngine, attach_standard_collectors
from core.snmp_profiles import STD_OIDS
from core.syslog_server import SyslogServer
from tests.test_snmp_foundation import MockSNMPTransport
from utils.db import DatabaseManager
from utils.snmp_credentials import SNMPCredentials, encrypt_credentials


def _add_snmp_dev(
    db: DatabaseManager,
    ip: str,
    name: str,
    profile_name: str = "cisco_catalyst",
    model: str = "C9200L-48P",
    anomaly_enabled: bool = True,
    last_reboot_at: datetime = None,
    enc_creds: str = None,
) -> Dict[str, Any]:
    if enc_creds is None:
        enc_creds = encrypt_credentials(SNMPCredentials(version="v2c", community="noc_ro"))
    dev = db.add_snmp_device({
        "name": name,
        "ip_address": ip,
        "snmp_version": "v2c",
        "encrypted_credentials": enc_creds,
        "profile_name": profile_name,
        "model": model,
        "anomaly_detection_enabled": anomaly_enabled,
        "last_reboot_at": last_reboot_at,
    })
    assert dev is not None
    return dev


class TestNetworkIntelligence:
    def test_25_physical_link_failure_correlation(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "ni_link_fail.db"))
        dev = _add_snmp_dev(db, "10.50.0.1", "SW-ACCESS-01")
        db.add_host("10.50.0.1", label="SW-ACCESS-01")
        now = datetime.utcnow()

        # 1. SNMP interface observed Admin UP / Oper DOWN + CRC errors
        id_map = db.upsert_snmp_interfaces(
            dev["id"],
            [
                {
                    "if_index": 1,
                    "name": "Gi1/0/1",
                    "description": "GigabitEthernet1/0/1",
                    "admin_status": "UP",
                    "oper_status": "DOWN",
                    "speed_bps": 1_000_000_000,
                }
            ],
        )
        db.save_interface_measurements_batch([
            {
                "interface_id": id_map[1],
                "device_id": dev["id"],
                "in_mbps": 0.0,
                "out_mbps": 0.0,
                "utilization_pct": 0.0,
                "in_errors": 4,
                "out_errors": 0,
                "crc_errors": 12,
                "oper_status": "DOWN",
                "timestamp": now - timedelta(seconds=10),
            }
        ])

        # 2. Corroborating Syslog LINK_DOWN
        db.save_syslog_events_batch([
            {
                "source_ip": "10.50.0.1",
                "hostname": "SW-ACCESS-01",
                "timestamp": now - timedelta(seconds=20),
                "facility": 23,
                "facility_name": "local7",
                "severity": 3,
                "severity_name": "Error",
                "app_name": "LINK-3-UPDOWN",
                "event_category": "LINK_DOWN",
                "message": "Interface Gi1/0/1, changed state to down",
                "raw_message": "raw-link-down",
            }
        ])

        # 3. Corroborating Ping 100% loss
        db.save_measurements_batch([
            {
                "host_address": "10.50.0.1",
                "timestamp": now - timedelta(seconds=i * 2),
                "status": "TIMEOUT",
                "latency_ms": None,
                "is_valid_probe": False,
                "error_type": "TIMEOUT",
            }
            for i in range(1, 6)
        ])

        engine = IntelligenceEngine(db=db, correlation_window_minutes=15)
        res1 = engine.correlate_device(dev["id"], now_utc=now)
        # Re-run to verify deduplication (no duplicate active anomaly rows)
        res2 = engine.correlate_device(dev["id"], now_utc=now + timedelta(seconds=15))

        assert len(res1) == 1
        assert len(res2) == 1
        all_rows = db.get_network_anomalies(device_id=dev["id"])
        assert len(all_rows) == 1

        finding = all_rows[0]
        assert finding["event_type"] == "PHYSICAL_LINK_FAILURE"
        assert finding["severity"] == "CRITICAL"
        assert finding["confidence"] == "HIGH"
        assert finding["status"] == "ACTIVE"
        ev_text = " ".join(finding["evidence"])
        assert "Gi1/0/1" in ev_text
        assert "LINK_DOWN" in ev_text
        assert "crc_errors=12" in ev_text
        assert "packet_loss=100.0%" in ev_text
        assert "probable" not in ev_text.lower()
        assert "probable" in finding["probable_cause"].lower()
        assert len(finding["recommended_actions"]) >= 2

    def test_26_switch_overload_correlation_and_auto_resolve(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "ni_overload.db"))
        dev = _add_snmp_dev(db, "10.50.0.2", "SW-DIST-01")
        now = datetime.utcnow()

        # Inject multi-source overload telemetry: CPU 94%, Mem 88%, Util 93%, Syslog HIGH_CPU, Ping RTT 240 ms
        db.save_snmp_metrics_batch([
            {"device_id": dev["id"], "metric_name": "cpu_pct", "metric_value": 94.0, "unit": "%", "timestamp": now - timedelta(seconds=15)},
            {"device_id": dev["id"], "metric_name": "memory_pct", "metric_value": 88.0, "unit": "%", "timestamp": now - timedelta(seconds=15)},
            {"device_id": dev["id"], "metric_name": "max_interface_util_pct", "metric_value": 93.0, "unit": "%", "timestamp": now - timedelta(seconds=15)},
        ])
        db.save_syslog_events_batch([
            {
                "source_ip": "10.50.0.2",
                "hostname": "SW-DIST-01",
                "timestamp": now - timedelta(seconds=30),
                "facility": 23,
                "facility_name": "local7",
                "severity": 1,
                "severity_name": "Alert",
                "app_name": "SYS-1-CPURISINGTHRESHOLD",
                "event_category": "HIGH_CPU",
                "message": "CPU usage high at 94%",
                "raw_message": "raw-cpu-high",
            }
        ])
        db.save_measurements_batch([
            {"host_address": "10.50.0.2", "timestamp": now - timedelta(seconds=10), "status": "UP", "latency_ms": 240.0, "is_valid_probe": True},
            {"host_address": "10.50.0.2", "timestamp": now - timedelta(seconds=5), "status": "UP", "latency_ms": 245.0, "is_valid_probe": True},
        ])

        engine = IntelligenceEngine(db=db, correlation_window_minutes=15, auto_resolve=True)
        findings = engine.correlate_device(dev["id"], now_utc=now)
        assert len(findings) == 1
        ov = findings[0]
        assert ov["event_type"] == "SWITCH_OVERLOAD"
        assert ov["severity"] == "CRITICAL"
        assert ov["confidence"] == "HIGH"
        ev_text = " ".join(ov["evidence"])
        assert "94.0%" in ev_text
        assert "88.0%" in ev_text
        assert "93.0%" in ev_text
        assert "HIGH_CPU" in ev_text
        assert "242.5 ms" in ev_text

        # Recovery: CPU drops to 22%, Memory to 40%, Util to 15%, Ping RTT normalizes via live snapshot
        t_rec = now + timedelta(minutes=2)
        db.save_snmp_metrics_batch([
            {"device_id": dev["id"], "metric_name": "cpu_pct", "metric_value": 22.0, "unit": "%", "timestamp": t_rec},
            {"device_id": dev["id"], "metric_name": "memory_pct", "metric_value": 40.0, "unit": "%", "timestamp": t_rec},
            {"device_id": dev["id"], "metric_name": "max_interface_util_pct", "metric_value": 15.0, "unit": "%", "timestamp": t_rec},
        ])
        db.save_measurements_batch([
            {"host_address": "10.50.0.2", "timestamp": t_rec, "status": "UP", "latency_ms": 5.0, "is_valid_probe": True}
            for _ in range(10)
        ])
        # Replace historical latency weight check by correlating past ping window or resetting ping window
        # After 15+ min correlation window passes or metrics + ping normalize:
        findings_after = engine.correlate_device(dev["id"], now_utc=t_rec)
        # Wait: because earlier 240/245 ms probes are still inside 15m window (`(240+245+50)/12 = 44.6ms < 100ms`),
        # ALL stress signals are now cleared and the overload anomaly auto-resolves immediately!
        assert findings_after == []
        resolved = db.get_network_anomalies(device_id=dev["id"], status="RESOLVED")
        assert len(resolved) == 1
        assert resolved[0]["resolved_at"] is not None

    def test_27_poe_exhaustion_unexpected_reboot_and_lifecycle(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "ni_poe_reboot.db"))
        now = datetime.utcnow()
        dev_poe = _add_snmp_dev(db, "10.50.0.3", "SW-POE-01")
        dev_rb = _add_snmp_dev(
            db,
            "10.50.0.4",
            "SW-REBOOT-01",
            last_reboot_at=now - timedelta(minutes=2),
        )

        # Part A: PoE Exhaustion (SNMP 95.95% + Syslog POE_OVERLOAD)
        db.save_snmp_metrics_batch([
            {"device_id": dev_poe["id"], "metric_name": "poe_budget_watts", "metric_value": 370.0, "unit": "W", "timestamp": now},
            {"device_id": dev_poe["id"], "metric_name": "poe_consumed_watts", "metric_value": 355.0, "unit": "W", "timestamp": now},
            {"device_id": dev_poe["id"], "metric_name": "poe_utilization_pct", "metric_value": 95.95, "unit": "%", "timestamp": now},
        ])
        db.save_syslog_events_batch([
            {
                "source_ip": "10.50.0.3",
                "hostname": "SW-POE-01",
                "timestamp": now - timedelta(seconds=10),
                "facility": 23,
                "facility_name": "local7",
                "severity": 3,
                "severity_name": "Error",
                "app_name": "ILPOWER-3-CONTROLLER_PORT_ERR",
                "event_category": "POE_OVERLOAD",
                "message": "Power denied on Gi1/0/12 (PoE overload)",
                "raw_message": "raw-poe",
            }
        ])

        # Part B: Unexpected Reboot (SNMP last_reboot_at + Syslog REBOOT + Ping loss)
        db.save_snmp_metrics_batch([
            {"device_id": dev_rb["id"], "metric_name": "uptime_sec", "metric_value": 120.0, "unit": "s", "timestamp": now}
        ])
        db.save_syslog_events_batch([
            {
                "source_ip": "10.50.0.4",
                "hostname": "SW-REBOOT-01",
                "timestamp": now - timedelta(minutes=2),
                "facility": 23,
                "facility_name": "local7",
                "severity": 5,
                "severity_name": "Notice",
                "app_name": "SYS-5-RESTART",
                "event_category": "REBOOT",
                "message": "System restarted -- Cisco IOS",
                "raw_message": "raw-reboot",
            }
        ])
        db.save_measurements_batch([
            {"host_address": "10.50.0.4", "timestamp": now - timedelta(minutes=2), "status": "TIMEOUT", "latency_ms": None, "is_valid_probe": False},
            {"host_address": "10.50.0.4", "timestamp": now - timedelta(minutes=1), "status": "UP", "latency_ms": 3.0, "is_valid_probe": True},
        ])

        engine = IntelligenceEngine(db=db, correlation_window_minutes=15)
        all_found = engine.correlate_all_devices(now_utc=now)
        by_type = {f["event_type"]: f for f in all_found}

        assert "POE_BUDGET_EXHAUSTION" in by_type
        assert by_type["POE_BUDGET_EXHAUSTION"]["severity"] == "CRITICAL"
        assert by_type["POE_BUDGET_EXHAUSTION"]["confidence"] == "HIGH"

        assert "UNEXPECTED_REBOOT" in by_type
        assert by_type["UNEXPECTED_REBOOT"]["severity"] == "CRITICAL"
        assert by_type["UNEXPECTED_REBOOT"]["confidence"] == "HIGH"

        # Part C: Summary & Acknowledge / Resolve lifecycle
        summary = engine.get_infrastructure_summary()
        assert summary["total_active"] == 2
        assert summary["critical_count"] == 2
        assert summary["affected_devices"] == 2

        ack = engine.acknowledge_anomaly(by_type["POE_BUDGET_EXHAUSTION"]["id"])
        assert ack["status"] == "ACKNOWLEDGED"

        res = engine.resolve_anomaly(by_type["UNEXPECTED_REBOOT"]["id"])
        assert res["status"] == "RESOLVED"
        assert res["resolved_at"] is not None

        summary2 = engine.get_infrastructure_summary()
        assert summary2["total_active"] == 1

    def test_28_statistical_anomaly_persistence_flatline_dedup_and_per_device_toggle(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "ni_stat_anom.db"))
        dev1 = _add_snmp_dev(db, "10.50.0.5", "SW-STAT-01", anomaly_enabled=True)
        dev2 = _add_snmp_dev(db, "10.50.0.6", "SW-STAT-DISABLED", anomaly_enabled=False)

        detector = StatisticalAnomalyDetector(
            AnomalyDetectorConfig(
                baseline_window_size=30,
                min_baseline_samples=8,
                persistence_samples=2,
                dedup_cooldown_sec=300.0,
            )
        )
        engine = IntelligenceEngine(db=db, anomaly_detector=detector)
        t0 = datetime(2026, 11, 21, 12, 0, 0)

        # 1. Seed 15 normal CPU samples (20..24%) -> 0 anomalies
        normal_vals = [20.0, 21.0, 22.0, 23.0, 24.0] * 3
        for idx, val in enumerate(normal_vals):
            assert engine.ingest_metric_sample(dev1, "cpu_pct", val, timestamp=t0 + timedelta(seconds=idx * 30)) is None

        # 2. Single transient spike (92%) followed by normal (22%) -> 0 false positives (persistence=2)
        t_trans = t0 + timedelta(minutes=10)
        assert engine.ingest_metric_sample(dev1, "cpu_pct", 92.0, timestamp=t_trans) is None
        assert engine.ingest_metric_sample(dev1, "cpu_pct", 22.0, timestamp=t_trans + timedelta(seconds=30)) is None
        assert db.get_network_anomalies(device_id=dev1["id"]) == []

        # 3. Sustained spike (2 consecutive: 92%, 95%) -> 1 anomaly persisted; 3rd (96%) deduplicated!
        t_spike = t0 + timedelta(minutes=12)
        assert engine.ingest_metric_sample(dev1, "cpu_pct", 92.0, timestamp=t_spike) is None
        persisted = engine.ingest_metric_sample(dev1, "cpu_pct", 95.0, timestamp=t_spike + timedelta(seconds=30))
        assert persisted is not None
        assert persisted["event_type"] == "ANOMALY_CPU_PCT"
        assert persisted["severity"] == "CRITICAL"
        assert "z-score=" in " ".join(persisted["evidence"])

        # Cooldown dedup check within 300s
        dup = engine.ingest_metric_sample(dev1, "cpu_pct", 96.0, timestamp=t_spike + timedelta(seconds=60))
        assert dup is None
        assert len(db.get_network_anomalies(device_id=dev1["id"])) == 1

        # 4. Zero-variance flatline guard: 15 identical 20.0% readings + minor noise 21.0% -> 0 false positives
        detector.seed_baseline(dev1["id"], "memory_pct", [20.0] * 15)
        assert engine.ingest_metric_sample(dev1, "memory_pct", 21.0, timestamp=t_spike + timedelta(seconds=90)) is None
        assert engine.ingest_metric_sample(dev1, "memory_pct", 21.0, timestamp=t_spike + timedelta(seconds=120)) is None

        # 5. Per-device toggle disabled -> 0 anomalies even on sustained 98% CPU
        detector.seed_baseline(dev2["id"], "cpu_pct", [20.0] * 12)
        assert engine.ingest_metric_sample(dev2, "cpu_pct", 98.0, timestamp=t_spike) is None
        assert engine.ingest_metric_sample(dev2, "cpu_pct", 99.0, timestamp=t_spike + timedelta(seconds=30)) is None
        assert db.get_network_anomalies(device_id=dev2["id"]) == []

    def test_benchmark_100_snmp_devices_and_synthetic_syslog(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "bench_100.db"))
        creds = SNMPCredentials(version="v2c", community="bench_ro")
        enc_creds = encrypt_credentials(creds)
        profiles_cycle = ["cisco_catalyst", "ruckus", "fortinet_fortigate", "generic_switch", "snmp_server"]

        transport = MockSNMPTransport()
        devices: List[Dict[str, Any]] = []
        base_reboot = datetime.utcnow()

        for i in range(1, 101):
            ip = f"10.100.0.{i}"
            pname = profiles_cycle[(i - 1) % len(profiles_cycle)]
            dev = _add_snmp_dev(
                db,
                ip=ip,
                name=f"DEV-{i:03d}",
                profile_name=pname,
                model="C9200L-48P" if pname == "cisco_catalyst" else "",
                enc_creds=enc_creds,
            )
            devices.append(dev)

            scalars: Dict[str, Any] = {STD_OIDS["sysUpTime"]: 1_000_000 + i * 100}
            tables: Dict[str, List[Any]] = {
                STD_OIDS["ifIndex"]: [(f"{STD_OIDS['ifIndex']}.1", 1), (f"{STD_OIDS['ifIndex']}.2", 2)],
                STD_OIDS["ifName"]: [(f"{STD_OIDS['ifName']}.1", "Gi1/0/1"), (f"{STD_OIDS['ifName']}.2", "Gi1/0/2")],
                STD_OIDS["ifAdminStatus"]: [(f"{STD_OIDS['ifAdminStatus']}.1", 1), (f"{STD_OIDS['ifAdminStatus']}.2", 1)],
                STD_OIDS["ifOperStatus"]: [
                    (f"{STD_OIDS['ifOperStatus']}.1", 2 if i == 1 else 1),  # Dev #1 link failure
                    (f"{STD_OIDS['ifOperStatus']}.2", 1),
                ],
                STD_OIDS["ifSpeed"]: [(f"{STD_OIDS['ifSpeed']}.1", 1_000_000_000), (f"{STD_OIDS['ifSpeed']}.2", 1_000_000_000)],
                STD_OIDS["ifHCInOctets"]: [(f"{STD_OIDS['ifHCInOctets']}.1", 10_000_000), (f"{STD_OIDS['ifHCInOctets']}.2", 20_000_000)],
                STD_OIDS["ifHCOutOctets"]: [(f"{STD_OIDS['ifHCOutOctets']}.1", 5_000_000), (f"{STD_OIDS['ifHCOutOctets']}.2", 10_000_000)],
                STD_OIDS["dot3StatsFCSErrors"]: [(f"{STD_OIDS['dot3StatsFCSErrors']}.1", 0)],
            }

            if pname == "cisco_catalyst":
                tables["1.3.6.1.4.1.9.9.109.1.1.1.1.7"] = [("1.3.6.1.4.1.9.9.109.1.1.1.1.7.1", 95 if i == 2 else 22)]
                tables["1.3.6.1.4.1.9.9.48.1.1.1.5"] = [("1.3.6.1.4.1.9.9.48.1.1.1.5.1", 89 if i == 2 else 45)]
                tables["1.3.6.1.4.1.9.9.48.1.1.1.6"] = [("1.3.6.1.4.1.9.9.48.1.1.1.6.1", 11 if i == 2 else 55)]
                tables["1.3.6.1.4.1.9.9.13.1.3.1.3"] = [("1.3.6.1.4.1.9.9.13.1.3.1.3.1", 40)]
            elif pname == "fortinet_fortigate":
                scalars["1.3.6.1.4.1.12356.101.4.1.3.0"] = 95 if i == 2 else 25
                scalars["1.3.6.1.4.1.12356.101.4.1.4.0"] = 89 if i == 2 else 40
            elif pname == "ruckus":
                tables["1.3.6.1.4.1.1991.1.1.2.11.1.1.4"] = [("1.3.6.1.4.1.1991.1.1.2.11.1.1.4.1", 25)]
                scalars["1.3.6.1.4.1.1991.1.1.2.1.53.0"] = 35
            else:
                tables[STD_OIDS["hrProcessorLoad"]] = [(f"{STD_OIDS['hrProcessorLoad']}.1", 20)]

            # Dev #3: PoE switch overload (355W / 370W)
            if i == 3:
                tables[STD_OIDS["pethMainPsePower"]] = [(f"{STD_OIDS['pethMainPsePower']}.1", 370)]
                tables[STD_OIDS["pethMainPseConsumptionPower"]] = [(f"{STD_OIDS['pethMainPseConsumptionPower']}.1", 355)]

            transport.register_device(ip, valid_version="v2c", valid_community="bench_ro", scalars=scalars, tables=tables)

        fake_now = [2000.0]
        client = SNMPClient(transport=transport)
        eng = AsyncSNMPEngine(db=db, client=client, max_concurrent=50, clock_fn=lambda: fake_now[0])
        attach_standard_collectors(eng, clock_fn=lambda: fake_now[0])
        eng.reload_from_db()

        async def _poll_100():
            sem = asyncio.Semaphore(50)

            async def _one(did: int):
                async with sem:
                    return await eng.poll_device_by_id(did)

            return await asyncio.gather(*(_one(d["id"]) for d in devices))

        t_poll_start = time.perf_counter()
        asyncio.run(_poll_100())

        # Poll 2 (+30s): inject Dev #1 CRC increment, Dev #2 uplink saturation (92 Mbps on 1G -> let's push 92% on 100M/1G), Dev #4 reboot
        fake_now[0] = 2030.0
        transport.devices[("10.100.0.1", 161)]["tables"][STD_OIDS["dot3StatsFCSErrors"]] = [
            (f"{STD_OIDS['dot3StatsFCSErrors']}.1", 12)
        ]
        # +3.45 GB in 30s on 1 Gbps link = 920 Mbps = 92.0%
        transport.devices[("10.100.0.2", 161)]["tables"][STD_OIDS["ifHCInOctets"]] = [
            (f"{STD_OIDS['ifHCInOctets']}.1", 10_000_000 + 3_450_000_000),
            (f"{STD_OIDS['ifHCInOctets']}.2", 20_000_000 + 5_000_000),
        ]
        # Dev #4 reboots
        transport.devices[("10.100.0.4", 161)]["scalars"][STD_OIDS["sysUpTime"]] = 2_000

        asyncio.run(_poll_100())
        flushed_metrics = eng.flush_now()
        poll_elapsed = time.perf_counter() - t_poll_start

        assert flushed_metrics >= 200
        assert len(db.get_snmp_devices()) == 100

        # Real UDP Syslog benchmark: ingest 1,000 datagrams over loopback
        t_syslog_start = time.perf_counter()
        syslog_srv = SyslogServer(
            db=db,
            bind_address="127.0.0.1",
            port=0,
            max_packets_per_sec=10000,
            max_per_ip_per_sec=10000,
            max_queue_size=10000,
            batch_size=250,
            batch_flush_interval_sec=0.1,
            emit_individual_events=False,
        )
        syslog_srv.start()
        assert syslog_srv.wait_until_ready(3.0) is True
        udp_port = syslog_srv.bound_port

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sample_msgs = [
                b"<187>Nov 21 12:00:00 DEV-001 %LINK-3-UPDOWN: Interface Gi1/0/1, changed state to down",
                b"<185>Nov 21 12:00:01 DEV-002 %SYS-1-CPURISINGTHRESHOLD: CPU usage high at 95%",
                b"<187>Nov 21 12:00:02 DEV-003 %ILPOWER-3-CONTROLLER_PORT_ERR: Power denied (PoE overload)",
                b"<189>Nov 21 12:00:03 DEV-004 %SYS-5-RESTART: System restarted -- Ruckus ICX",
                b'<189>Nov 21 12:00:04 app-host systemd[1]: Periodic health tick',
            ]
            for i in range(1000):
                sock.sendto(sample_msgs[i % 5] + f" id={i}".encode("ascii"), ("127.0.0.1", udp_port))
                if (i + 1) % 100 == 0:
                    time.sleep(0.001)

            deadline = time.monotonic() + 8.0
            while time.monotonic() < deadline:
                if syslog_srv.get_stats()["processed_events"] >= 1000:
                    break
                time.sleep(0.02)
        finally:
            sock.close()
            syslog_srv.stop(timeout_ms=3000)

        syslog_elapsed = time.perf_counter() - t_syslog_start
        st_sys = syslog_srv.get_stats()
        assert st_sys["processed_events"] == 1000
        assert st_sys["persisted_events"] == 1000
        assert st_sys["dropped_rate_limit"] == 0
        assert st_sys["dropped_queue_full"] == 0

        # Seed correlated Syslog records matching the faulted device IPs
        db.save_syslog_events_batch([
            {"source_ip": "10.100.0.1", "hostname": "DEV-001", "timestamp": base_reboot, "facility": 23, "severity": 3, "severity_name": "Error", "app_name": "LINK-3-UPDOWN", "event_category": "LINK_DOWN", "message": "Interface Gi1/0/1 changed state to down", "raw_message": "r1"},
            {"source_ip": "10.100.0.2", "hostname": "DEV-002", "timestamp": base_reboot, "facility": 23, "severity": 1, "severity_name": "Alert", "app_name": "SYS-1-CPURISINGTHRESHOLD", "event_category": "HIGH_CPU", "message": "CPU usage high 95%", "raw_message": "r2"},
            {"source_ip": "10.100.0.3", "hostname": "DEV-003", "timestamp": base_reboot, "facility": 23, "severity": 3, "severity_name": "Error", "app_name": "ILPOWER", "event_category": "POE_OVERLOAD", "message": "PoE overload on port 1", "raw_message": "r3"},
            {"source_ip": "10.100.0.4", "hostname": "DEV-004", "timestamp": base_reboot, "facility": 23, "severity": 5, "severity_name": "Notice", "app_name": "SYS-5-RESTART", "event_category": "REBOOT", "message": "System restarted", "raw_message": "r4"},
            {"source_ip": "10.100.0.5", "hostname": "DEV-005", "timestamp": base_reboot, "facility": 23, "severity": 2, "severity_name": "Critical", "app_name": "system", "event_category": "FIREWALL_IF_DOWN", "message": "Interface wan1 status changed to down", "raw_message": "r5"},
        ])

        t_corr_start = time.perf_counter()
        intel = IntelligenceEngine(db=db, correlation_window_minutes=15)
        snaps = eng.get_all_snapshots()
        correlated = intel.correlate_all_devices(now_utc=datetime.utcnow(), snmp_snapshots=snaps)
        corr_elapsed = time.perf_counter() - t_corr_start

        summary = intel.get_infrastructure_summary()
        assert "PHYSICAL_LINK_FAILURE" in summary["by_event_type"]
        assert "SWITCH_OVERLOAD" in summary["by_event_type"]
        assert "POE_BUDGET_EXHAUSTION" in summary["by_event_type"]
        assert "UNEXPECTED_REBOOT" in summary["by_event_type"]
        assert len(correlated) >= 5

        print(
            f"\n[BENCHMARK 100 SNMP + 1000 Syslog] "
            f"2x100 SNMP Poll={poll_elapsed:.3f}s | "
            f"1000 UDP Syslog={syslog_elapsed:.3f}s ({1000.0 / max(syslog_elapsed, 0.001):.0f} msg/s) | "
            f"100-Dev Correlation={corr_elapsed:.3f}s | Findings={len(correlated)}"
        )

        assert poll_elapsed < 15.0
        assert syslog_elapsed < 10.0
        assert corr_elapsed < 10.0
