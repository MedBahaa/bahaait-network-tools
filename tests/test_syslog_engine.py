import csv
from datetime import datetime, timedelta
import json
import os
import socket
import sys
import time
from typing import Any, Dict, List

import pytest
from PySide6.QtCore import QCoreApplication, Qt

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.syslog_classifier import classify_syslog_event
from core.syslog_parser import SYSLOG_FACILITIES, SYSLOG_SEVERITIES, parse_syslog_message
from core.syslog_server import (
    SyslogServer,
    export_syslog_csv,
    export_syslog_json,
    get_windows_firewall_guidance,
)
from utils.db import DatabaseManager


_qapp = QCoreApplication.instance() or QCoreApplication(sys.argv)


class TestSyslogEngine:
    def test_19_rfc3164_parsing_and_all_eight_severities(self):
        ref = datetime(2026, 11, 21, 12, 0, 0)

        # Verify all 8 severities (0..7) on local0..local7 and auth/kern facilities
        expected_fac_names = {
            0: "kern",
            4: "auth",
            16: "local0",
            17: "local1",
            18: "local2",
            19: "local3",
            20: "local4",
            23: "local7",
        }
        fac_cycle = [0, 4, 16, 17, 18, 19, 20, 23]
        for sev in range(8):
            fac = fac_cycle[sev]
            pri = fac * 8 + sev
            raw = f"<{pri}>Nov 21 10:15:30 core-rtr-01 bgpd[412]: Session event severity {sev}"
            parsed = parse_syslog_message(raw, source_ip="10.0.0.1", received_at=ref)
            assert parsed.malformed is False
            assert parsed.rfc_version == "RFC3164"
            assert parsed.facility == fac
            assert parsed.facility_name == expected_fac_names[fac] == SYSLOG_FACILITIES[fac]
            assert parsed.severity == sev
            assert parsed.severity_name == SYSLOG_SEVERITIES[sev]
            assert parsed.hostname == "core-rtr-01"
            assert parsed.app_name == "bgpd"
            assert parsed.proc_id == "412"
            assert parsed.timestamp == datetime(2026, 11, 21, 10, 15, 30)

        # Dec -> Jan year rollover check when BSD timestamp lacks explicit year
        jan_ref = datetime(2027, 1, 1, 0, 5, 0)
        dec_parsed = parse_syslog_message(
            "<34>Dec 31 23:59:58 fw-01 sshd[99]: Connection closed",
            source_ip="10.0.0.2",
            received_at=jan_ref,
        )
        assert dec_parsed.timestamp == datetime(2026, 12, 31, 23, 59, 58)

        # Cisco IOS sequence number + BSD timestamp + mnemonic
        cisco_raw = "<187>145: *Nov 21 10:20:00.123 UTC: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/1, changed state to down"
        c_parsed = parse_syslog_message(cisco_raw, source_ip="10.0.1.10", received_at=ref)
        assert c_parsed.rfc_version == "RFC3164"
        assert c_parsed.severity == 3
        assert c_parsed.app_name == "LINK-3-UPDOWN"
        assert "GigabitEthernet1/0/1" in c_parsed.message
        assert c_parsed.malformed is False

        # Ruckus ICX standard syslog
        ruckus_raw = "<189>Nov 21 11:00:05 ICX7150-SW1 System: Interface ethernet 1/1/5, state down"
        r_parsed = parse_syslog_message(ruckus_raw, source_ip="10.0.1.20", received_at=ref)
        assert r_parsed.hostname == "ICX7150-SW1"
        assert r_parsed.app_name == "System"
        assert "ethernet 1/1/5" in r_parsed.message

        # Fortinet FortiGate key-value syslog
        fg_raw = (
            '<189>date=2026-11-21 time=11:30:00 tz="+0100" devname="FW-HQ-01" '
            'devid="FG100FTK220001" logid="0100022905" type="event" subtype="system" '
            'level="warning" action="interface-stat-change" status="down" msg="Interface wan1 status changed to down"'
        )
        fg_parsed = parse_syslog_message(fg_raw, source_ip="10.0.1.1", received_at=ref)
        assert fg_parsed.hostname == "FW-HQ-01"
        assert fg_parsed.app_name == "system"
        assert fg_parsed.timestamp == datetime(2026, 11, 21, 10, 30, 0)  # normalized to naive UTC
        assert fg_parsed.structured_data["devid"] == "FG100FTK220001"

    def test_20_rfc5424_parsing_structured_data_and_nil_values(self):
        # RFC 5424 with +02:00 offset, structured data, and UTF-8 BOM
        raw_tz = (
            '<165>1 2026-11-21T14:15:30.500+02:00 sw-core.corp.local iosd 712 ID47 '
            '[meta vendor="Cisco" port="Gi1/0/1" quote="a\\"b"] '
            '\ufeffInterface Gi1/0/1 changed state to down'
        )
        p1 = parse_syslog_message(raw_tz, source_ip="10.20.0.1")
        assert p1.rfc_version == "RFC5424"
        assert p1.malformed is False
        assert p1.facility == 20 and p1.facility_name == "local4"
        assert p1.severity == 5 and p1.severity_name == "Notice"
        assert p1.timestamp == datetime(2026, 11, 21, 12, 15, 30, 500000)
        assert p1.hostname == "sw-core.corp.local"
        assert p1.app_name == "iosd"
        assert p1.proc_id == "712"
        assert p1.msg_id == "ID47"
        assert p1.structured_data == {"meta": {"vendor": "Cisco", "port": "Gi1/0/1", "quote": 'a"b'}}
        assert p1.message == "Interface Gi1/0/1 changed state to down"

        # RFC 5424 with UTC Z and all '-' nil values
        ref = datetime(2026, 11, 21, 9, 0, 0)
        raw_nil = "<14>1 - - - - - - Plain notice without metadata"
        p2 = parse_syslog_message(raw_nil, source_ip="10.20.0.9", received_at=ref)
        assert p2.rfc_version == "RFC5424"
        assert p2.hostname == "10.20.0.9"
        assert p2.timestamp == ref
        assert p2.app_name == ""
        assert p2.proc_id == ""
        assert p2.msg_id == ""
        assert p2.structured_data == {}
        assert p2.message == "Plain notice without metadata"

    def test_21_malformed_binary_and_oversized_syslog_safety(self):
        # Empty / whitespace
        p_empty = parse_syslog_message(b"   \x00\r\n", source_ip="10.9.0.1")
        assert p_empty.malformed is True
        assert p_empty.message == ""

        # Invalid UTF-8 binary noise
        p_bin = parse_syslog_message(b"\xff\xfe\x00\x01\x80binary-noise", source_ip="10.9.0.2")
        assert p_bin.malformed is True
        assert p_bin.severity == 6

        # Missing PRI + unparseable raw text
        p_nopri = parse_syslog_message("Unformatted raw log message without header", source_ip="10.9.0.3")
        assert p_nopri.malformed is True
        assert p_nopri.rfc_version == "RAW"
        assert p_nopri.severity == 6 and p_nopri.facility == 1

        # Out-of-range PRI (<999>)
        p_badpri = parse_syslog_message("<999>Nov 21 10:00:00 r1 app: Bad priority", source_ip="10.9.0.4")
        assert p_badpri.malformed is True
        assert p_badpri.severity == 6 and p_badpri.facility == 1

        # 16 KB oversized datagram truncated safely
        oversized = b"<14>1 2026-11-21T10:00:00Z h1 app - - - " + (b"A" * 16_384)
        p_big = parse_syslog_message(oversized, source_ip="10.9.0.5", max_bytes=2048)
        assert p_big.truncated is True
        assert len(p_big.raw_message.encode("utf-8")) <= 2048

    def test_22_high_volume_udp_ingestion_flood_protection_and_clean_shutdown(self, tmp_path):
        # Part A: High-volume loopback UDP ingestion (400 packets -> 0 drops, all persisted)
        db_a = DatabaseManager(db_path=str(tmp_path / "syslog_highvol.db"))
        srv_a = SyslogServer(
            db=db_a,
            bind_address="127.0.0.1",
            port=0,
            max_packets_per_sec=5000,
            max_per_ip_per_sec=5000,
            max_queue_size=5000,
            batch_size=100,
            batch_flush_interval_sec=0.1,
            emit_individual_events=False,
        )
        started_ports: List[int] = []
        srv_a.server_started.connect(lambda _ip, p: started_ports.append(p), Qt.DirectConnection)
        srv_a.start()
        assert srv_a.wait_until_ready(3.0) is True
        port_a = srv_a.bound_port
        assert port_a > 0
        assert started_ports == [port_a]

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            templates = [
                b"<187>Nov 21 12:00:01 sw-1 %LINK-3-UPDOWN: Interface Gi1/0/1, changed state to down",
                b'<189>date=2026-11-21 time=12:00:02 devname="fw-1" devid="FG1" action="interface-stat-change" status="up" msg="Interface wan1 up"',
                b"<14>1 2026-11-21T12:00:03Z srv-1 sshd 123 - - Accepted publickey for ops",
            ]
            for i in range(400):
                payload = templates[i % 3] + f" seq={i}".encode("ascii")
                sock.sendto(payload, ("127.0.0.1", port_a))
                if (i + 1) % 50 == 0:
                    time.sleep(0.002)

            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                if srv_a.get_stats()["processed_events"] >= 400:
                    break
                time.sleep(0.02)
        finally:
            sock.close()
            srv_a.stop(timeout_ms=3000)

        assert not srv_a.isRunning()
        stats_a = srv_a.get_stats()
        assert stats_a["received_packets"] == 400
        assert stats_a["processed_events"] == 400
        assert stats_a["persisted_events"] == 400
        assert stats_a["dropped_rate_limit"] == 0
        assert stats_a["dropped_queue_full"] == 0
        assert len(db_a.get_syslog_events(limit=1000)) == 400

        # Part B: Flood / Rate-limit protection
        db_b = DatabaseManager(db_path=str(tmp_path / "syslog_flood.db"))
        fake_now = [100.0]
        srv_b = SyslogServer(
            db=db_b,
            bind_address="127.0.0.1",
            port=0,
            max_packets_per_sec=20,
            max_per_ip_per_sec=15,
            max_queue_size=1000,
            batch_size=50,
            batch_flush_interval_sec=0.1,
            flood_alert_cooldown_sec=0.0,
            clock_fn=lambda: fake_now[0],
        )
        flood_alerts: List[Dict[str, Any]] = []
        srv_b.flood_detected.connect(flood_alerts.append, Qt.DirectConnection)
        srv_b.start()
        assert srv_b.wait_until_ready(3.0) is True
        port_b = srv_b.bound_port

        sock_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for i in range(120):
                sock_b.sendto(f"<14>Nov 21 12:00:00 flooder app: msg {i}".encode("ascii"), ("127.0.0.1", port_b))
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                st_b = srv_b.get_stats()
                if st_b["received_packets"] >= 120 and st_b["queue_depth"] == 0:
                    break
                time.sleep(0.02)
        finally:
            sock_b.close()
            srv_b.stop(timeout_ms=3000)

        assert not srv_b.isRunning()
        stats_b = srv_b.get_stats()
        assert stats_b["received_packets"] >= 120
        assert stats_b["dropped_rate_limit"] > 0
        assert stats_b["processed_events"] <= 20
        assert len(flood_alerts) >= 1

        # Part C: Port conflict / bind error handled gracefully without crash
        holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        holder.bind(("127.0.0.1", 0))
        occupied_port = holder.getsockname()[1]
        errors: List[str] = []
        srv_c = SyslogServer(db=db_b, bind_address="127.0.0.1", port=occupied_port)
        srv_c.server_error.connect(errors.append, Qt.DirectConnection)
        try:
            srv_c.start()
            ready_ok = srv_c.wait_until_ready(3.0)
            srv_c.wait(2000)
        finally:
            holder.close()

        assert ready_ok is False
        assert srv_c.is_listening is False
        assert len(errors) >= 1
        assert "5514" in errors[0]

    def test_23_syslog_filtering_search_and_csv_json_export(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "syslog_filter.db"))
        now = datetime(2026, 11, 21, 15, 0, 0)
        db.save_syslog_events_batch([
            {
                "source_ip": "10.0.1.1",
                "hostname": "SW-CORE",
                "timestamp": now - timedelta(hours=2),
                "facility": 23,
                "facility_name": "local7",
                "severity": 3,
                "severity_name": "Error",
                "app_name": "LINK-3-UPDOWN",
                "event_category": "LINK_DOWN",
                "message": "Interface Gi1/0/1 changed state to down",
                "raw_message": "raw1",
            },
            {
                "source_ip": "10.0.1.2",
                "hostname": "FW-EDGE",
                "timestamp": now - timedelta(minutes=30),
                "facility": 4,
                "facility_name": "auth",
                "severity": 4,
                "severity_name": "Warning",
                "app_name": "sshd",
                "event_category": "AUTH_FAIL",
                "message": "Failed password for invalid user admin",
                "raw_message": "raw2",
            },
            {
                "source_ip": "10.0.1.1",
                "hostname": "SW-CORE",
                "timestamp": now,
                "facility": 23,
                "facility_name": "local7",
                "severity": 6,
                "severity_name": "Informational",
                "app_name": "SYS-5-CONFIG_I",
                "event_category": "CONFIG_CHANGE",
                "message": "Configured from console by netops",
                "raw_message": "raw3",
            },
        ])

        assert len(db.get_syslog_events(source_ip="10.0.1.1")) == 2
        assert len(db.get_syslog_events(hostname="fw-edge")) == 1
        assert len(db.get_syslog_events(max_severity=4)) == 2
        assert len(db.get_syslog_events(severities=[3, 6])) == 2
        assert len(db.get_syslog_events(event_category="AUTH_FAIL")) == 1
        assert len(db.get_syslog_events(search_text="Gi1/0/1")) == 1
        assert len(db.get_syslog_events(since=now - timedelta(hours=1), until=now)) == 2

        events = db.get_syslog_events(limit=50)
        csv_path = str(tmp_path / "syslog_export.csv")
        json_path = str(tmp_path / "syslog_export.json")

        assert export_syslog_csv(events, csv_path) == 3
        with open(csv_path, "r", encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.DictReader(fh))
        assert len(rows) == 3
        assert rows[0]["hostname"] == "SW-CORE"
        assert rows[0]["event_category"] == "CONFIG_CHANGE"

        assert export_syslog_json(events, json_path) == 3
        with open(json_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        assert len(data) == 3
        assert data[1]["event_category"] == "AUTH_FAIL"

    def test_24_multi_vendor_classification_and_windows_firewall_guidance(self):
        cases = [
            (
                "<187>Nov 21 10:00:00 sw1 %ILPOWER-3-CONTROLLER_PORT_ERR: Power denied on Gi1/0/12 (PoE overload Imax)",
                "POE_OVERLOAD",
                "Cisco",
                "Gi1/0/12",
                "",
            ),
            (
                "<188>Nov 21 10:00:01 sw1 %PM-4-ERR_DISABLE: psecure-violation error detected on Gi1/0/8",
                "PORT_SECURITY",
                "Cisco",
                "Gi1/0/8",
                "",
            ),
            (
                "<188>Nov 21 10:00:02 sw1 %SPANTREE-2-ROOTGUARD_BLOCK: Spanning-tree topology change on Gi1/0/24",
                "STP_CHANGE",
                "Cisco",
                "Gi1/0/24",
                "",
            ),
            (
                "<189>Nov 21 10:00:03 sw1 %SYS-5-RESTART: System restarted by admin -- Cisco IOS",
                "REBOOT",
                "Cisco",
                "",
                "admin",
            ),
            (
                '<187>date=2026-11-21 time=10:00:04 devname="FW-01" devid="FG200F" action="interface-stat-change" status="down" msg="Interface wan1 status changed to down"',
                "FIREWALL_IF_DOWN",
                "Fortinet",
                "wan1",
                "",
            ),
            (
                "<187>Nov 21 10:00:05 ICX7150 System: Interface ethernet 1/1/5, state down",
                "LINK_DOWN",
                "Ruckus",
                "ethernet 1/1/5",
                "",
            ),
            (
                "<189>Nov 21 10:00:06 sw1 %LINK-3-UPDOWN: Interface GigabitEthernet1/0/3, changed state to up",
                "LINK_UP",
                "Cisco",
                "GigabitEthernet1/0/3",
                "",
            ),
            (
                "<36>Nov 21 10:00:07 fw-lin sshd[222]: Failed password for invalid user operator1 from 10.0.0.55",
                "AUTH_FAIL",
                "Generic",
                "",
                "operator1",
            ),
            (
                "<189>Nov 21 10:00:08 sw1 %SYS-5-CONFIG_I: Configured from console by netadmin on vty0",
                "CONFIG_CHANGE",
                "Cisco",
                "",
                "netadmin",
            ),
            (
                "<185>Nov 21 10:00:09 sw1 %SYS-1-CPURISINGTHRESHOLD: CPU usage high at 94%",
                "HIGH_CPU",
                "Cisco",
                "",
                "",
            ),
            (
                "<186>Nov 21 10:00:10 sw1 %ENVMON-2-TEMP: Temperature threshold exceeded on chassis",
                "HARDWARE_THERMAL",
                "Cisco",
                "",
                "",
            ),
            (
                "<190>Nov 21 10:00:11 app-srv systemd[1]: Started daily cleanup timer",
                "GENERAL",
                "Generic",
                "",
                "",
            ),
        ]

        for raw, exp_cat, exp_vendor, exp_iface, exp_user in cases:
            parsed = parse_syslog_message(raw, source_ip="10.50.0.1")
            cls = classify_syslog_event(parsed)
            assert cls.event_category == exp_cat
            assert cls.vendor == exp_vendor
            if exp_iface:
                assert cls.interface_name.lower() == exp_iface.lower()
            if exp_user:
                assert cls.username == exp_user
            if exp_cat == "FIREWALL_IF_DOWN":
                assert "LINK_DOWN" in cls.tags and "FIREWALL" in cls.tags

        fw_514 = get_windows_firewall_guidance(514)
        assert fw_514["requires_admin"] is True
        assert fw_514["recommended_non_admin_port"] == 5514
        assert "New-NetFirewallRule" in fw_514["powershell_cmd"]
        assert "LocalPort 514" in fw_514["powershell_cmd"]
        assert "localport=514" in fw_514["netsh_cmd"]

        fw_5514 = get_windows_firewall_guidance(5514)
        assert fw_5514["requires_admin"] is False
        assert "LocalPort 5514" in fw_5514["powershell_cmd"]
