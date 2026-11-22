import asyncio
from datetime import datetime, timedelta
import os
import sqlite3
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import pytest
from PySide6.QtCore import QCoreApplication

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.snmp_client import (
    UNSUPPORTED_OID,
    BaseSNMPTransport,
    PySNMPTransport,
    SNMPAuthError,
    SNMPClient,
    SNMPTimeoutError,
    convert_snmp_value,
    octet_to_mac,
)
from core.snmp_engine import AsyncSNMPEngine
from core.snmp_profiles import STD_OIDS, detect_vendor_and_profile, get_profile
from utils.db import DatabaseManager, Host, MonitoringIncident
from utils.snmp_credentials import (
    SNMPCredentials,
    decrypt_credentials,
    encrypt_credentials,
    scrub_secrets,
)


_qapp = QCoreApplication.instance() or QCoreApplication(sys.argv)


class MockSNMPTransport(BaseSNMPTransport):
    """In-memory programmable SNMP simulator for unit & integration tests."""

    def __init__(self) -> None:
        # {(ip, port): {"scalars": {oid: val}, "tables": {base_oid: [(oid, val), ...]}, ...}}
        self.devices: Dict[Tuple[str, int], Dict[str, Any]] = {}
        self.in_flight_counts: Dict[Tuple[str, int], int] = {}
        self.max_in_flight_seen: Dict[Tuple[str, int], int] = {}
        self.calls: List[Tuple[str, str, int]] = []

    def register_device(
        self,
        ip: str,
        port: int = 161,
        scalars: Optional[Dict[str, Any]] = None,
        tables: Optional[Dict[str, List[Tuple[str, Any]]]] = None,
        valid_version: Optional[str] = None,
        valid_community: Optional[str] = None,
        valid_username: Optional[str] = None,
        valid_auth_pw: Optional[str] = None,
        valid_priv_pw: Optional[str] = None,
        simulate_timeout: bool = False,
        delay_sec: float = 0.0,
    ) -> None:
        self.devices[(ip, port)] = {
            "scalars": dict(scalars or {}),
            "tables": {k: list(v) for k, v in (tables or {}).items()},
            "valid_version": valid_version,
            "valid_community": valid_community,
            "valid_username": valid_username,
            "valid_auth_pw": valid_auth_pw,
            "valid_priv_pw": valid_priv_pw,
            "simulate_timeout": simulate_timeout,
            "delay_sec": delay_sec,
        }

    def _check_device_auth(self, dev: Dict[str, Any], creds: SNMPCredentials) -> None:
        if dev["valid_version"] and creds.version != dev["valid_version"]:
            raise SNMPAuthError(f"Unsupported SNMP version for {creds.community or creds.username}")
        if creds.version in ("v1", "v2c"):
            if dev["valid_community"] is not None and creds.community != dev["valid_community"]:
                raise SNMPAuthError(f"Authentication failed for community '{creds.community}'")
        else:
            if dev["valid_username"] is not None and creds.username != dev["valid_username"]:
                raise SNMPAuthError(f"Unknown USM user '{creds.username}'")
            if dev["valid_auth_pw"] is not None and creds.auth_password != dev["valid_auth_pw"]:
                raise SNMPAuthError(f"Wrong digest with auth key '{creds.auth_password}'")
            if dev["valid_priv_pw"] is not None and creds.priv_password != dev["valid_priv_pw"]:
                raise SNMPAuthError(f"Decryption error with priv key '{creds.priv_password}'")

    async def get(
        self,
        ip: str,
        port: int,
        creds: SNMPCredentials,
        oids: List[str],
        timeout_sec: float = 2.0,
        retries: int = 1,
    ) -> Dict[str, Any]:
        key = (ip, port)
        self.calls.append(("get", ip, port))
        dev = self.devices.get(key)
        if dev is None or dev["simulate_timeout"]:
            secret_hint = creds.community or creds.auth_password or ""
            raise SNMPTimeoutError(f"Request timed out to {ip}:{port} (ctx {secret_hint})")

        cur = self.in_flight_counts.get(key, 0) + 1
        self.in_flight_counts[key] = cur
        self.max_in_flight_seen[key] = max(self.max_in_flight_seen.get(key, 0), cur)
        try:
            if dev["delay_sec"] > 0:
                await asyncio.sleep(dev["delay_sec"])
            self._check_device_auth(dev, creds)
            scalars = dev["scalars"]
            return {oid: scalars[oid] for oid in oids if oid in scalars}
        finally:
            self.in_flight_counts[key] -= 1

    async def walk(
        self,
        ip: str,
        port: int,
        creds: SNMPCredentials,
        base_oid: str,
        timeout_sec: float = 2.0,
        retries: int = 1,
        max_rows: Optional[int] = None,
    ) -> List[Tuple[str, Any]]:
        key = (ip, port)
        self.calls.append(("walk", ip, port))
        dev = self.devices.get(key)
        if dev is None or dev["simulate_timeout"]:
            raise SNMPTimeoutError(f"Walk timed out to {ip}:{port}")
        if dev["delay_sec"] > 0:
            await asyncio.sleep(dev["delay_sec"])
        self._check_device_auth(dev, creds)
        rows = dev["tables"].get(base_oid, [])
        return rows[:max_rows] if max_rows is not None else list(rows)


class TestSNMPFoundation:
    def test_01_02_snmp_v1_and_v2c_connectivity_and_discovery(self):
        transport = MockSNMPTransport()
        # Cisco Catalyst over v2c
        transport.register_device(
            "10.1.0.10",
            valid_version="v2c",
            valid_community="noc_ro_secret",
            scalars={
                STD_OIDS["sysDescr"]: "Cisco IOS Software, C2960X Software, Version 15.2(7)E6",
                STD_OIDS["sysObjectID"]: "1.3.6.1.4.1.9.1.1208",
                STD_OIDS["sysUpTime"]: 123456,
                STD_OIDS["sysName"]: "SW-CORE-01",
                STD_OIDS["sysLocation"]: "Rack-A1",
                STD_OIDS["sysServices"]: 6,
                STD_OIDS["ifNumber"]: 24,
            },
            tables={
                "1.3.6.1.4.1.9.9.109.1.1.1.1.7": [("1.3.6.1.4.1.9.9.109.1.1.1.1.7.1", 18)],
                "1.3.6.1.4.1.9.9.48.1.1.1.5": [("1.3.6.1.4.1.9.9.48.1.1.1.5.1", 40000000)],
                "1.3.6.1.4.1.9.9.13.1.3.1.3": [("1.3.6.1.4.1.9.9.13.1.3.1.3.1", 39)],
                STD_OIDS["pethMainPsePower"]: [("1.3.6.1.2.1.105.1.3.1.1.2.1", 370)],
                "1.3.6.1.4.1.9.9.46.1.3.1.1.4.1": [("1.3.6.1.4.1.9.9.46.1.3.1.1.4.1.10", "USERS")],
            },
        )
        # Legacy switch over v1
        transport.register_device(
            "10.1.0.11",
            valid_version="v1",
            valid_community="public_v1",
            scalars={
                STD_OIDS["sysDescr"]: "Generic Managed Gigabit Switch v2.1",
                STD_OIDS["sysObjectID"]: "1.3.6.1.4.1.99999.1",
                STD_OIDS["sysUpTime"]: 5500,
                STD_OIDS["sysName"]: "SW-EDGE-V1",
            },
        )

        client = SNMPClient(transport=transport)

        # Test v1
        creds_v1 = SNMPCredentials(version="v1", community="public_v1")
        auth_v1 = PySNMPTransport._build_auth_data(creds_v1)
        assert auth_v1.message_processing_model == 0
        res_v1 = asyncio.run(client.test_connectivity("10.1.0.11", creds_v1))
        assert res_v1["reachable"] is True
        assert res_v1["sys_name"] == "SW-EDGE-V1"

        # Test v2c discovery
        creds_v2c = SNMPCredentials(version="v2c", community="noc_ro_secret")
        auth_v2c = PySNMPTransport._build_auth_data(creds_v2c)
        assert auth_v2c.message_processing_model == 1
        disc = asyncio.run(client.discover_device("10.1.0.10", creds_v2c))
        assert disc.reachable is True
        assert disc.vendor == "Cisco"
        assert disc.profile_name == "cisco_catalyst"
        assert "C2960X" in disc.model
        assert disc.firmware == "15.2(7)E6"
        assert disc.sys_name == "SW-CORE-01"
        assert disc.sys_location == "Rack-A1"
        assert disc.capabilities == {
            "interfaces": True,
            "cpu": True,
            "memory": True,
            "temperature": True,
            "poe": True,
            "vlans": True,
        }

    def test_03_04_snmp_v3_authentication_and_encryption(self):
        from pysnmp.hlapi.v3arch.asyncio import (
            usmAesCfb128Protocol,
            usmAesCfb256Protocol,
            usmHMAC192SHA256AuthProtocol,
            usmHMACSHAAuthProtocol,
        )

        transport = MockSNMPTransport()
        transport.register_device(
            "10.1.0.20",
            valid_version="v3",
            valid_username="noc_admin",
            valid_auth_pw="AuthPass#1234",
            valid_priv_pw=None,
            scalars={
                STD_OIDS["sysDescr"]: "FortiGate-100F v7.4.3,build2573",
                STD_OIDS["sysObjectID"]: "1.3.6.1.4.1.12356.101.1.1000",
                STD_OIDS["sysUpTime"]: 90000,
                STD_OIDS["sysName"]: "FW-HQ-01",
            },
        )
        transport.register_device(
            "10.1.0.21",
            valid_version="v3",
            valid_username="sec_admin",
            valid_auth_pw="StrongAuth#999",
            valid_priv_pw="StrongAes#8888",
            scalars={
                STD_OIDS["sysDescr"]: "Ruckus ICX7150-48P Version 08.0.95",
                STD_OIDS["sysObjectID"]: "1.3.6.1.4.1.1991.1.3.55.1",
                STD_OIDS["sysUpTime"]: 45000,
                STD_OIDS["sysName"]: "SW-WIFI-01",
            },
        )

        client = SNMPClient(transport=transport)

        # 3. authNoPriv (SHA / SHA256)
        creds_auth = SNMPCredentials(
            version="v3",
            username="noc_admin",
            security_level="authNoPriv",
            auth_protocol="SHA",
            auth_password="AuthPass#1234",
        )
        usm_auth = PySNMPTransport._build_auth_data(creds_auth)
        assert usm_auth.authentication_protocol == usmHMACSHAAuthProtocol

        creds_sha256 = SNMPCredentials(
            version="v3",
            username="noc_admin",
            security_level="authNoPriv",
            auth_protocol="SHA256",
            auth_password="AuthPass#1234",
        )
        assert PySNMPTransport._build_auth_data(creds_sha256).authentication_protocol == usmHMAC192SHA256AuthProtocol

        disc_fg = asyncio.run(client.discover_device("10.1.0.20", creds_auth))
        assert disc_fg.reachable is True
        assert disc_fg.vendor == "Fortinet"
        assert disc_fg.profile_name == "fortinet_fortigate"

        # 4. authPriv (SHA + AES128 & AES256)
        creds_priv = SNMPCredentials(
            version="v3",
            username="sec_admin",
            security_level="authPriv",
            auth_protocol="SHA256",
            auth_password="StrongAuth#999",
            priv_protocol="AES128",
            priv_password="StrongAes#8888",
        )
        usm_priv = PySNMPTransport._build_auth_data(creds_priv)
        assert usm_priv.privacy_protocol == usmAesCfb128Protocol

        creds_aes256 = SNMPCredentials(
            version="v3",
            username="sec_admin",
            security_level="authPriv",
            auth_protocol="SHA256",
            auth_password="StrongAuth#999",
            priv_protocol="AES256",
            priv_password="StrongAes#8888",
        )
        assert PySNMPTransport._build_auth_data(creds_aes256).privacy_protocol == usmAesCfb256Protocol

        disc_rk = asyncio.run(client.discover_device("10.1.0.21", creds_priv))
        assert disc_rk.reachable is True
        assert disc_rk.vendor == "Ruckus"
        assert disc_rk.profile_name == "ruckus"

    def test_05_06_timeout_invalid_credentials_dpapi_and_secret_scrubbing(self, tmp_path):
        transport = MockSNMPTransport()
        transport.register_device("10.1.0.30", simulate_timeout=True)
        transport.register_device(
            "10.1.0.31",
            valid_version="v2c",
            valid_community="ExpectedSecret!",
            scalars={STD_OIDS["sysUpTime"]: 100},
        )
        client = SNMPClient(transport=transport)

        # 5. Timeout graceful handling & secret scrubbing in timeout messages
        creds_to = SNMPCredentials(version="v2c", community="SuperSecretTimeout!")
        to_res = asyncio.run(client.test_connectivity("10.1.0.30", creds_to))
        assert to_res["reachable"] is False
        assert "SuperSecretTimeout!" not in to_res["error"]

        disc_to = asyncio.run(client.discover_device("10.1.0.30", creds_to))
        assert disc_to.reachable is False
        assert "SuperSecretTimeout!" not in disc_to.error

        # 6. Invalid credentials & masking & DPAPI roundtrip
        bad_creds = SNMPCredentials(version="v3", username="u1", security_level="authPriv", auth_password="short")
        with pytest.raises(ValueError):
            bad_creds.validate()

        wrong_creds = SNMPCredentials(version="v2c", community="WrongSecret99")
        auth_res = asyncio.run(client.test_connectivity("10.1.0.31", wrong_creds))
        assert auth_res["reachable"] is False
        assert "WrongSecret99" not in auth_res["error"]

        v3_creds = SNMPCredentials(
            version="v3",
            username="vault_user",
            security_level="authPriv",
            auth_protocol="SHA256",
            auth_password="MyAuthPassword123",
            priv_protocol="AES",
            priv_password="MyPrivPassword456",
        )
        assert "MyAuthPassword123" not in repr(v3_creds)
        assert "MyPrivPassword456" not in str(v3_creds)
        assert v3_creds.to_masked_dict()["auth_password"] == "***"
        assert "MyPrivPassword456" not in scrub_secrets("Error using key MyPrivPassword456", v3_creds)

        # SQLite storage must NEVER contain plaintext SNMP secrets
        db_file = str(tmp_path / "snmp_vault.db")
        db = DatabaseManager(db_path=db_file)
        enc_blob = encrypt_credentials(v3_creds)
        dev = db.add_snmp_device({
            "name": "Secure-SW",
            "ip_address": "10.1.0.32",
            "snmp_version": "v3",
            "encrypted_credentials": enc_blob,
        })
        assert dev is not None

        conn = sqlite3.connect(db_file)
        raw_dump = str(conn.execute("SELECT * FROM snmp_devices").fetchall())
        conn.close()
        assert "MyAuthPassword123" not in raw_dump
        assert "MyPrivPassword456" not in raw_dump

        dec = decrypt_credentials(dev["encrypted_credentials"])
        assert dec.username == "vault_user"
        assert dec.auth_password == "MyAuthPassword123"
        assert dec.priv_password == "MyPrivPassword456"

    def test_07_unsupported_oids_and_vendor_profiles(self):
        class _FakeNoSuchObject:
            pass

        _FakeNoSuchObject.__name__ = "NoSuchObject"
        assert convert_snmp_value(_FakeNoSuchObject()) is UNSUPPORTED_OID
        assert octet_to_mac("0x001122aabbcc") == "00:11:22:AA:BB:CC"

        transport = MockSNMPTransport()
        # Appliance exposes ONLY sysDescr + sysUpTime (no CPU, no temp, no PoE, no VLANs)
        transport.register_device(
            "10.1.0.40",
            valid_version="v2c",
            valid_community="ro",
            scalars={
                STD_OIDS["sysDescr"]: "Linux EdgeSensor 6.6",
                STD_OIDS["sysObjectID"]: "1.3.6.1.4.1.8072.3.2.10",
                STD_OIDS["sysUpTime"]: 4200,
                STD_OIDS["sysName"]: "EDGE-BOX",
            },
        )
        client = SNMPClient(transport=transport)
        disc = asyncio.run(client.discover_device("10.1.0.40", SNMPCredentials(version="v2c", community="ro")))
        assert disc.reachable is True
        assert disc.profile_name == "snmp_server"
        assert disc.capabilities["temperature"] is False
        assert disc.capabilities["poe"] is False
        assert disc.capabilities["vlans"] is False

        # Verify all 6 required vendor profiles exist and detect accurately
        assert detect_vendor_and_profile("1.3.6.1.4.1.9.1.516", "Cisco IOS")["profile_name"] == "cisco_catalyst"
        assert detect_vendor_and_profile("1.3.6.1.4.1.25053.3.1", "Ruckus R750")["profile_name"] == "ruckus"
        assert detect_vendor_and_profile("1.3.6.1.4.1.12356.101.1.1", "FortiGate-200F")["profile_name"] == "fortinet_fortigate"
        assert detect_vendor_and_profile("1.3.6.1.4.1.8072.3.2.10", "Linux Ubuntu")["profile_name"] == "snmp_server"
        assert detect_vendor_and_profile("", "MikroTik RouterOS", sys_services=4)["profile_name"] == "generic_router"
        assert detect_vendor_and_profile("", "Managed L2 Switch")["profile_name"] == "generic_switch"
        assert get_profile("fortinet_fortigate").default_temp_warn_c != get_profile("cisco_catalyst").default_temp_warn_c

    def test_08_device_reboot_detection_and_non_overlapping_scheduler(self, tmp_path):
        # Static wraparound vs genuine reboot checks
        assert AsyncSNMPEngine.is_uptime_reboot(1_000_000, 2_500) is True
        assert AsyncSNMPEngine.is_uptime_reboot(4_294_900_000, 5_000) is False  # 497-day rollover
        assert AsyncSNMPEngine.is_uptime_reboot(100, 200) is False

        transport = MockSNMPTransport()
        transport.register_device(
            "10.1.0.50",
            valid_version="v2c",
            valid_community="ro_key",
            delay_sec=0.15,
            scalars={
                STD_OIDS["sysDescr"]: "Cisco Catalyst 9300",
                STD_OIDS["sysObjectID"]: "1.3.6.1.4.1.9.1.2494",
                STD_OIDS["sysUpTime"]: 800_000,
                STD_OIDS["sysName"]: "SW-DIST-01",
            },
        )
        db = DatabaseManager(db_path=str(tmp_path / "snmp_eng.db"))
        creds = SNMPCredentials(version="v2c", community="ro_key")
        dev = db.add_snmp_device({
            "name": "SW-DIST-01",
            "ip_address": "10.1.0.50",
            "snmp_version": "v2c",
            "encrypted_credentials": encrypt_credentials(creds),
            "profile_name": "cisco_catalyst",
            "poll_interval_sec": 30,
        })

        client = SNMPClient(transport=transport)
        eng = AsyncSNMPEngine(db=db, client=client)
        eng.reload_from_db()

        reboots = []
        statuses = []
        eng.device_reboot_detected.connect(reboots.append)
        eng.device_status_changed.connect(statuses.append)

        # Concurrent polls against slow device -> scheduler guard prevents overlap (max_in_flight == 1)
        async def _concurrent_polls():
            return await asyncio.gather(
                eng.poll_device_by_id(dev["id"]),
                eng.poll_device_by_id(dev["id"]),
                eng.poll_device_by_id(dev["id"]),
            )

        res_list = asyncio.run(_concurrent_polls())
        assert sum(1 for r in res_list if r is not None) == 1
        assert transport.max_in_flight_seen[("10.1.0.50", 161)] == 1
        assert eng.get_snapshot(dev["id"])["status"] == "ONLINE"
        assert len(statuses) == 1 and statuses[0]["new_status"] == "ONLINE"

        # Simulate unexpected reboot (sysUpTime drops sharply)
        transport.devices[("10.1.0.50", 161)]["scalars"][STD_OIDS["sysUpTime"]] = 1_500
        snap = asyncio.run(eng.poll_device_by_id(dev["id"]))
        assert len(reboots) == 1
        assert reboots[0]["previous_uptime_ticks"] == 800_000
        assert reboots[0]["current_uptime_ticks"] == 1_500
        assert snap["last_reboot_at"] is not None

        # Simulate timeout -> switches to OFFLINE cleanly
        transport.devices[("10.1.0.50", 161)]["simulate_timeout"] = True
        snap_off = asyncio.run(eng.poll_device_by_id(dev["id"]))
        assert snap_off["status"] == "OFFLINE"
        assert eng.flush_now() >= 3

        # Thread start + clean shutdown test
        eng.start()
        time.sleep(0.15)
        eng.stop(timeout_ms=3000)
        assert not eng.isRunning()

    def test_29_30_31_v340_db_migration_aggregation_and_retention(self, tmp_path):
        db_file = str(tmp_path / "upgrade_v340.db")

        # Seed a pre-v3.5.0 SQLite database using only v3.4.0 tables and existing rows
        raw_conn = sqlite3.connect(db_file)
        raw_conn.execute(
            "CREATE TABLE hosts (id INTEGER PRIMARY KEY AUTOINCREMENT, address VARCHAR UNIQUE NOT NULL, "
            "label VARCHAR, is_active BOOLEAN, category VARCHAR, profile VARCHAR, notes VARCHAR, created_at DATETIME)"
        )
        raw_conn.execute(
            "INSERT INTO hosts (address, label, is_active, category, profile) "
            "VALUES ('192.168.1.1', 'Legacy-GW', 1, 'Router / Firewall', 'Critical Core')"
        )
        raw_conn.execute(
            "CREATE TABLE monitoring_incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_uid VARCHAR UNIQUE NOT NULL, "
            "host_id INTEGER, host_name VARCHAR NOT NULL, host_address VARCHAR NOT NULL, incident_type VARCHAR NOT NULL, "
            "severity VARCHAR NOT NULL, start_time DATETIME NOT NULL, end_time DATETIME, duration_seconds FLOAT, "
            "failed_probes INTEGER, packet_loss_pct FLOAT, avg_latency_before_ms FLOAT, recovery_latency_ms FLOAT, "
            "status VARCHAR NOT NULL, acknowledged BOOLEAN, acknowledged_at DATETIME, comments VARCHAR)"
        )
        raw_conn.execute(
            "INSERT INTO monitoring_incidents (incident_uid, host_id, host_name, host_address, incident_type, severity, start_time, status) "
            "VALUES ('INC-LEGACY-1', 1, 'Legacy-GW', '192.168.1.1', 'OUTAGE', 'CRITICAL', '2026-10-01 10:00:00', 'RECOVERED')"
        )
        raw_conn.commit()
        raw_conn.close()

        # Open with v3.5.0 DatabaseManager -> non-destructive creation of all 8 new tables + existing records intact
        db = DatabaseManager(db_path=db_file)
        hosts = db.get_hosts()
        assert len(hosts) == 1 and hosts[0]["address"] == "192.168.1.1"
        assert len(db.get_incidents()) == 1

        check_conn = sqlite3.connect(db_file)
        tbls = {r[0] for r in check_conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        check_conn.close()
        for expected_tbl in (
            "snmp_devices",
            "snmp_metrics",
            "snmp_metrics_aggregated",
            "snmp_interfaces",
            "interface_measurements",
            "snmp_vlans",
            "syslog_events",
            "network_anomalies",
        ):
            assert expected_tbl in tbls

        # Batch write, aggregation, and configurable retention purge
        creds = SNMPCredentials(version="v2c", community="ro")
        dev = db.add_snmp_device({
            "name": "Core-SW",
            "ip_address": "10.2.0.1",
            "snmp_version": "v2c",
            "encrypted_credentials": encrypt_credentials(creds),
        })
        now = datetime.utcnow().replace(minute=15, second=0, microsecond=0)
        old_raw = now - timedelta(days=12)
        db.save_snmp_metrics_batch([
            {"device_id": dev["id"], "metric_name": "cpu_pct", "metric_value": 20.0, "unit": "%", "timestamp": now - timedelta(minutes=10)},
            {"device_id": dev["id"], "metric_name": "cpu_pct", "metric_value": 40.0, "unit": "%", "timestamp": now},
            {"device_id": dev["id"], "metric_name": "cpu_pct", "metric_value": 15.0, "unit": "%", "timestamp": old_raw},
        ])
        agg_cnt = db.aggregate_snmp_metrics("hourly", since=now - timedelta(hours=2))
        assert agg_cnt >= 1
        agg_rows = db.get_aggregated_snmp_metrics(dev["id"], metric_name="cpu_pct", granularity="hourly")
        assert len(agg_rows) == 1
        assert agg_rows[0]["min_value"] == 20.0
        assert agg_rows[0]["avg_value"] == 30.0
        assert agg_rows[0]["max_value"] == 40.0

        # Syslog & anomalies retention test
        db.save_syslog_events_batch([
            {"source_ip": "10.2.0.1", "severity": 3, "severity_name": "Error", "message": "Old link down", "timestamp": now - timedelta(days=45)},
            {"source_ip": "10.2.0.1", "severity": 6, "severity_name": "Informational", "message": "Recent link up", "timestamp": now},
        ])
        db.create_network_anomaly({
            "anomaly_uid": "ANOM-OLD-RES",
            "device_id": dev["id"],
            "event_type": "CPU_SPIKE",
            "title": "Old spike",
            "severity": "WARNING",
            "status": "RESOLVED",
            "detected_at": now - timedelta(days=400),
        })
        db.create_network_anomaly({
            "anomaly_uid": "ANOM-ACTIVE",
            "device_id": dev["id"],
            "event_type": "CPU_SPIKE",
            "title": "Active spike",
            "severity": "WARNING",
            "status": "ACTIVE",
            "detected_at": now,
        })

        purged = db.cleanup_by_retention(snmp_raw_days=7, snmp_aggregated_days=90, syslog_days=30, anomalies_days=365)
        assert purged["snmp_raw"] == 1
        assert purged["syslog"] == 1
        assert purged["anomalies"] == 1
        assert len(db.get_snmp_metrics(dev["id"], metric_name="cpu_pct")) == 2
        assert len(db.get_syslog_events(source_ip="10.2.0.1")) == 1
        assert len(db.get_network_anomalies(device_id=dev["id"])) == 1
