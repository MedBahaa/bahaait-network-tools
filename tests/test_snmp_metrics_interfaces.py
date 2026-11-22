import asyncio
from datetime import datetime, timedelta
import os
import sys
from typing import Any, Dict, List

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.device_health import (
    DeviceHealthCollector,
    compute_cpu_average,
    format_uptime,
    resolve_temperature_thresholds,
)
from core.interface_monitor import (
    COUNTER32_MAX,
    COUNTER64_MAX,
    InterfaceMonitorCollector,
    compute_counter_delta,
    compute_traffic_mbps,
    compute_utilization_pct,
    filter_interfaces,
    normalize_oper_status,
)
from core.poe_monitor import PoEMonitorCollector
from core.snmp_client import SNMPClient
from core.snmp_engine import AsyncSNMPEngine, attach_standard_collectors
from core.snmp_profiles import STD_OIDS, get_profile
from core.vlan_monitor import (
    CISCO_TRUNK_DYN_STATUS_OID,
    CISCO_VM_VLAN_OID,
    CISCO_VTP_VLAN_NAME_OID,
    CISCO_VTP_VLAN_STATE_OID,
    VLANMonitorCollector,
    decode_port_list,
)
from tests.test_snmp_foundation import MockSNMPTransport
from utils.db import DatabaseManager
from utils.snmp_credentials import SNMPCredentials, encrypt_credentials


def _make_device(
    db: DatabaseManager,
    ip: str,
    name: str,
    profile_name: str = "generic_switch",
    model: str = "",
    community: str = "secret_ro",
) -> Dict[str, Any]:
    creds = SNMPCredentials(version="v2c", community=community)
    dev = db.add_snmp_device({
        "name": name,
        "ip_address": ip,
        "snmp_version": "v2c",
        "encrypted_credentials": encrypt_credentials(creds),
        "profile_name": profile_name,
        "model": model,
    })
    assert dev is not None
    return dev


class TestSNMPMetricsAndInterfaces:
    def test_09_interface_discovery_all_six_states_and_filters(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "iface_states.db"))
        dev = _make_device(db, "10.10.1.1", "SW-ACCESS-01", profile_name="cisco_catalyst", model="C2960X")
        creds = SNMPCredentials(version="v2c", community="secret_ro")

        transport = MockSNMPTransport()
        # 6 interfaces representing all 6 canonical oper states (plus lowerLayerDown=7 -> DOWN)
        transport.register_device(
            "10.10.1.1",
            valid_version="v2c",
            valid_community="secret_ro",
            scalars={STD_OIDS["sysUpTime"]: 500_000},
            tables={
                STD_OIDS["ifIndex"]: [(f"{STD_OIDS['ifIndex']}.{i}", i) for i in range(1, 7)],
                STD_OIDS["ifDescr"]: [
                    (f"{STD_OIDS['ifDescr']}.1", "GigabitEthernet1/0/1"),
                    (f"{STD_OIDS['ifDescr']}.2", "GigabitEthernet1/0/2"),
                    (f"{STD_OIDS['ifDescr']}.3", "GigabitEthernet1/0/3"),
                    (f"{STD_OIDS['ifDescr']}.4", "GigabitEthernet1/0/4"),
                    (f"{STD_OIDS['ifDescr']}.5", "GigabitEthernet1/0/5"),
                    (f"{STD_OIDS['ifDescr']}.6", "TenGigabitEthernet1/0/6"),
                ],
                STD_OIDS["ifName"]: [
                    (f"{STD_OIDS['ifName']}.1", "Gi1/0/1"),
                    (f"{STD_OIDS['ifName']}.2", "Gi1/0/2"),
                    (f"{STD_OIDS['ifName']}.3", "Gi1/0/3"),
                    (f"{STD_OIDS['ifName']}.4", "Gi1/0/4"),
                    (f"{STD_OIDS['ifName']}.5", "Gi1/0/5"),
                    (f"{STD_OIDS['ifName']}.6", "Te1/0/6"),
                ],
                STD_OIDS["ifAlias"]: [
                    (f"{STD_OIDS['ifAlias']}.1", "Uplink-Core"),
                    (f"{STD_OIDS['ifAlias']}.2", "AP-Lobby"),
                ],
                STD_OIDS["ifPhysAddress"]: [
                    (f"{STD_OIDS['ifPhysAddress']}.1", b"\x00\x11\x22\x33\x44\x55"),
                    (f"{STD_OIDS['ifPhysAddress']}.6", b"\xaa\xbb\xcc\xdd\xee\xff"),
                ],
                STD_OIDS["ifAdminStatus"]: [(f"{STD_OIDS['ifAdminStatus']}.{i}", 1) for i in range(1, 7)],
                STD_OIDS["ifOperStatus"]: [
                    (f"{STD_OIDS['ifOperStatus']}.1", 1),  # UP
                    (f"{STD_OIDS['ifOperStatus']}.2", 2),  # DOWN
                    (f"{STD_OIDS['ifOperStatus']}.3", 3),  # TESTING
                    (f"{STD_OIDS['ifOperStatus']}.4", 4),  # UNKNOWN
                    (f"{STD_OIDS['ifOperStatus']}.5", 5),  # DORMANT
                    (f"{STD_OIDS['ifOperStatus']}.6", 6),  # NOT_PRESENT
                ],
                STD_OIDS["ifSpeed"]: [(f"{STD_OIDS['ifSpeed']}.{i}", 1_000_000_000) for i in range(1, 7)],
                STD_OIDS["ifHighSpeed"]: [(f"{STD_OIDS['ifHighSpeed']}.6", 10_000)],  # 10G
                STD_OIDS["ifLastChange"]: [(f"{STD_OIDS['ifLastChange']}.1", 400_000)],
                STD_OIDS["ifHCInOctets"]: [(f"{STD_OIDS['ifHCInOctets']}.{i}", 1000) for i in range(1, 7)],
                STD_OIDS["ifHCOutOctets"]: [(f"{STD_OIDS['ifHCOutOctets']}.{i}", 2000) for i in range(1, 7)],
                STD_OIDS["ifInErrors"]: [(f"{STD_OIDS['ifInErrors']}.{i}", 0) for i in range(1, 7)],
            },
        )
        assert normalize_oper_status(7) == "DOWN"

        collector = InterfaceMonitorCollector()
        client = SNMPClient(transport=transport)
        t0 = datetime(2026, 11, 21, 10, 0, 0)
        ctx = {
            "device_id": dev["id"],
            "ip_address": dev["ip_address"],
            "port": 161,
            "credentials": creds,
            "profile": get_profile("cisco_catalyst"),
            "client": client,
            "db": db,
            "now_utc": t0,
            "uptime_ticks": 500_000,
            "reboot_detected": False,
            "degraded_reasons": [],
            "collector_events": [],
            "collector_snapshots": {},
            "interface_name_map": {},
        }
        summary = asyncio.run(collector.collect(ctx))
        assert any(m["metric_name"] == "interfaces_total" and m["metric_value"] == 6.0 for m in summary)

        snap = collector.get_last_snapshot(dev["id"])
        assert [r["oper_status"] for r in snap] == ["UP", "DOWN", "TESTING", "UNKNOWN", "DORMANT", "NOT_PRESENT"]
        assert snap[0]["mac_address"] == "00:11:22:33:44:55"
        assert snap[0]["alias"] == "Uplink-Core"
        assert snap[5]["speed_bps"] == 10_000_000_000
        assert snap[5]["negotiated_speed_mbps"] == 10_000.0
        assert len(db.get_snmp_interfaces(dev["id"])) == 6

        # Filter modes check
        assert len(filter_interfaces(snap, "ALL")) == 6
        assert [r["name"] for r in filter_interfaces(snap, "UP")] == ["Gi1/0/1"]
        assert [r["name"] for r in filter_interfaces(snap, "DOWN")] == ["Gi1/0/2"]
        assert len(filter_interfaces(snap, "OTHER")) == 4

        # Simulate unexpected UP -> DOWN transition while Admin UP on Gi1/0/1
        transport.devices[("10.10.1.1", 161)]["tables"][STD_OIDS["ifOperStatus"]][0] = (
            f"{STD_OIDS['ifOperStatus']}.1",
            2,
        )
        ctx2 = dict(ctx)
        ctx2["now_utc"] = t0 + timedelta(seconds=30)
        ctx2["degraded_reasons"] = []
        ctx2["collector_events"] = []
        ctx2["collector_snapshots"] = {}
        asyncio.run(collector.collect(ctx2))
        assert any("Gi1/0/1" in r and "DOWN" in r for r in ctx2["degraded_reasons"])
        assert any(e["event_type"] == "INTERFACE_DOWN" and e["if_index"] == 1 for e in ctx2["collector_events"])

    def test_10_11_counter_delta_and_64bit_high_speed_counters(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "counters_64bit.db"))
        dev = _make_device(db, "10.10.1.2", "SW-CORE-10G", profile_name="generic_switch")
        creds = SNMPCredentials(version="v2c", community="secret_ro")

        transport = MockSNMPTransport()
        # Port 1: 32-bit counters only; Port 2: 10G port with 64-bit counters (>4 GiB in 30s)
        transport.register_device(
            "10.10.1.2",
            valid_version="v2c",
            valid_community="secret_ro",
            tables={
                STD_OIDS["ifIndex"]: [(f"{STD_OIDS['ifIndex']}.1", 1), (f"{STD_OIDS['ifIndex']}.2", 2)],
                STD_OIDS["ifName"]: [(f"{STD_OIDS['ifName']}.1", "Fa0/1"), (f"{STD_OIDS['ifName']}.2", "Te1/1")],
                STD_OIDS["ifAdminStatus"]: [(f"{STD_OIDS['ifAdminStatus']}.1", 1), (f"{STD_OIDS['ifAdminStatus']}.2", 1)],
                STD_OIDS["ifOperStatus"]: [(f"{STD_OIDS['ifOperStatus']}.1", 1), (f"{STD_OIDS['ifOperStatus']}.2", 1)],
                STD_OIDS["ifSpeed"]: [(f"{STD_OIDS['ifSpeed']}.1", 100_000_000), (f"{STD_OIDS['ifSpeed']}.2", 4_294_967_295)],
                STD_OIDS["ifHighSpeed"]: [(f"{STD_OIDS['ifHighSpeed']}.2", 10_000)],
                STD_OIDS["ifInOctets"]: [(f"{STD_OIDS['ifInOctets']}.1", 1_000_000)],
                STD_OIDS["ifOutOctets"]: [(f"{STD_OIDS['ifOutOctets']}.1", 2_000_000)],
                STD_OIDS["ifHCInOctets"]: [(f"{STD_OIDS['ifHCInOctets']}.2", 50_000_000_000)],
                STD_OIDS["ifHCOutOctets"]: [(f"{STD_OIDS['ifHCOutOctets']}.2", 10_000_000_000)],
            },
        )
        collector = InterfaceMonitorCollector()
        client = SNMPClient(transport=transport)
        t0 = datetime(2026, 11, 21, 10, 0, 0)

        def _ctx(ts):
            return {
                "device_id": dev["id"],
                "ip_address": dev["ip_address"],
                "port": 161,
                "credentials": creds,
                "profile": get_profile("generic_switch"),
                "client": client,
                "db": db,
                "now_utc": ts,
                "uptime_ticks": 100_000,
                "reboot_detected": False,
                "degraded_reasons": [],
                "collector_events": [],
                "collector_snapshots": {},
            }

        asyncio.run(collector.collect(_ctx(t0)))

        # Advance 30s:
        # Port 1 (32-bit): +3_750_000 in (1.0 Mbps), +7_500_000 out (2.0 Mbps)
        # Port 2 (64-bit 10G): +18_750_000_000 in (18.75 GB > 4 GB in 30s = 5000.0 Mbps = 50.0%)
        tbl = transport.devices[("10.10.1.2", 161)]["tables"]
        tbl[STD_OIDS["ifInOctets"]] = [(f"{STD_OIDS['ifInOctets']}.1", 4_750_000)]
        tbl[STD_OIDS["ifOutOctets"]] = [(f"{STD_OIDS['ifOutOctets']}.1", 9_500_000)]
        tbl[STD_OIDS["ifHCInOctets"]] = [(f"{STD_OIDS['ifHCInOctets']}.2", 50_000_000_000 + 18_750_000_000)]
        tbl[STD_OIDS["ifHCOutOctets"]] = [(f"{STD_OIDS['ifHCOutOctets']}.2", 10_000_000_000 + 3_750_000_000)]

        asyncio.run(collector.collect(_ctx(t0 + timedelta(seconds=30))))
        snap = collector.get_last_snapshot(dev["id"])
        assert snap[0]["in_mbps"] == pytest.approx(1.0, rel=1e-4)
        assert snap[0]["out_mbps"] == pytest.approx(2.0, rel=1e-4)
        assert snap[1]["in_mbps"] == pytest.approx(5000.0, rel=1e-4)
        assert snap[1]["out_mbps"] == pytest.approx(1000.0, rel=1e-4)
        assert snap[1]["utilization_pct"] == pytest.approx(50.0, rel=1e-2)

    def test_12_counter_rollover_32bit_and_64bit(self):
        # 32-bit wrap: 2^32 - 1_000_000 -> 500_000 over 10s on 100 Mbps link (delta = 1_500_000 B -> 1.2 Mbps)
        prev_32 = COUNTER32_MAX - 1_000_000
        curr_32 = 500_000
        d32, reason32 = compute_counter_delta(
            prev_32, curr_32, elapsed_sec=10.0, is_64bit=False, speed_bps=100_000_000
        )
        assert reason32 == "ROLLOVER"
        assert d32 == 1_500_000
        assert compute_traffic_mbps(d32, 10.0) == pytest.approx(1.2, rel=1e-4)

        # 64-bit wrap: 2^64 - 5_000_000 -> 2_500_000 over 10s on 1 Gbps link (delta = 7_500_000 B -> 6.0 Mbps)
        prev_64 = COUNTER64_MAX - 5_000_000
        curr_64 = 2_500_000
        d64, reason64 = compute_counter_delta(
            prev_64, curr_64, elapsed_sec=10.0, is_64bit=True, speed_bps=1_000_000_000
        )
        assert reason64 == "ROLLOVER"
        assert d64 == 7_500_000
        assert compute_traffic_mbps(d64, 10.0) == pytest.approx(6.0, rel=1e-4)

    def test_13_counter_reset_and_device_reboot_no_traffic_spike(self, tmp_path):
        # Pure unit check: manual clear (low prev -> smaller curr) MUST yield None / 0 Mbps (no wraparound spike!)
        d_reset, r_reset = compute_counter_delta(
            prev_val=1_000_000_000, curr_val=1_200, elapsed_sec=30.0, is_64bit=True, speed_bps=1_000_000_000
        )
        assert r_reset == "COUNTER_RESET"
        assert d_reset is None
        assert compute_traffic_mbps(d_reset, 30.0) == 0.0

        # Full collector reboot guard: prev counter near 32-bit high OR lower after reboot must NOT spike
        db = DatabaseManager(db_path=str(tmp_path / "reboot_guard.db"))
        dev = _make_device(db, "10.10.1.3", "SW-REBOOT")
        creds = SNMPCredentials(version="v2c", community="secret_ro")
        transport = MockSNMPTransport()
        transport.register_device(
            "10.10.1.3",
            valid_version="v2c",
            valid_community="secret_ro",
            tables={
                STD_OIDS["ifIndex"]: [(f"{STD_OIDS['ifIndex']}.1", 1)],
                STD_OIDS["ifName"]: [(f"{STD_OIDS['ifName']}.1", "Gi0/1")],
                STD_OIDS["ifOperStatus"]: [(f"{STD_OIDS['ifOperStatus']}.1", 1)],
                STD_OIDS["ifSpeed"]: [(f"{STD_OIDS['ifSpeed']}.1", 1_000_000_000)],
                STD_OIDS["ifHCInOctets"]: [(f"{STD_OIDS['ifHCInOctets']}.1", 900_000_000)],
                STD_OIDS["ifHCOutOctets"]: [(f"{STD_OIDS['ifHCOutOctets']}.1", 500_000_000)],
            },
        )
        collector = InterfaceMonitorCollector()
        client = SNMPClient(transport=transport)
        t0 = datetime(2026, 11, 21, 10, 0, 0)

        def _run_poll(ts: datetime, rebooted: bool):
            return asyncio.run(
                collector.collect({
                    "device_id": dev["id"],
                    "ip_address": dev["ip_address"],
                    "port": 161,
                    "credentials": creds,
                    "profile": get_profile("generic_switch"),
                    "client": client,
                    "db": db,
                    "now_utc": ts,
                    "uptime_ticks": 5_000 if rebooted else 500_000,
                    "reboot_detected": rebooted,
                    "degraded_reasons": [],
                    "collector_events": [],
                    "collector_snapshots": {},
                })
            )

        _run_poll(t0, rebooted=False)

        # Device reboots -> counters reset to small values -> MUST produce 0.0 Mbps (zero spike!)
        tbl = transport.devices[("10.10.1.3", 161)]["tables"]
        tbl[STD_OIDS["ifHCInOctets"]] = [(f"{STD_OIDS['ifHCInOctets']}.1", 25_000)]
        tbl[STD_OIDS["ifHCOutOctets"]] = [(f"{STD_OIDS['ifHCOutOctets']}.1", 15_000)]
        _run_poll(t0 + timedelta(seconds=30), rebooted=True)
        snap_rb = collector.get_last_snapshot(dev["id"])
        assert snap_rb[0]["in_mbps"] == 0.0
        assert snap_rb[0]["out_mbps"] == 0.0
        assert snap_rb[0]["in_delta_reason"] == "REBOOT"

        # Next normal poll calculates clean delta from 25_000 -> 3_775_000 in 30s (1.0 Mbps)
        tbl[STD_OIDS["ifHCInOctets"]] = [(f"{STD_OIDS['ifHCInOctets']}.1", 3_775_000)]
        tbl[STD_OIDS["ifHCOutOctets"]] = [(f"{STD_OIDS['ifHCOutOctets']}.1", 15_000)]
        _run_poll(t0 + timedelta(seconds=60), rebooted=False)
        snap_ok = collector.get_last_snapshot(dev["id"])
        assert snap_ok[0]["in_mbps"] == pytest.approx(1.0, rel=1e-4)

    def test_14_traffic_mbps_formula_and_utilization_congestion(self, tmp_path):
        # Exact formula check: 12_500_000 bytes / 10s = 10.0 Mbps = 10.0% on 100 Mbps
        mbps = compute_traffic_mbps(12_500_000, 10.0)
        assert mbps == pytest.approx(10.0, rel=1e-6)
        assert compute_utilization_pct(mbps, 2.0, 100_000_000) == pytest.approx(10.0, rel=1e-4)

        # Congestion check via collector (>= 90% -> CRITICAL event + HIGH_UTILIZATION filter)
        db = DatabaseManager(db_path=str(tmp_path / "congestion.db"))
        dev = _make_device(db, "10.10.1.4", "SW-CONGEST")
        creds = SNMPCredentials(version="v2c", community="secret_ro")
        transport = MockSNMPTransport()
        transport.register_device(
            "10.10.1.4",
            valid_version="v2c",
            valid_community="secret_ro",
            tables={
                STD_OIDS["ifIndex"]: [(f"{STD_OIDS['ifIndex']}.1", 1)],
                STD_OIDS["ifName"]: [(f"{STD_OIDS['ifName']}.1", "Gi0/1")],
                STD_OIDS["ifOperStatus"]: [(f"{STD_OIDS['ifOperStatus']}.1", 1)],
                STD_OIDS["ifSpeed"]: [(f"{STD_OIDS['ifSpeed']}.1", 100_000_000)],
                STD_OIDS["ifHCInOctets"]: [(f"{STD_OIDS['ifHCInOctets']}.1", 1_000_000)],
                STD_OIDS["ifHCOutOctets"]: [(f"{STD_OIDS['ifHCOutOctets']}.1", 1_000_000)],
            },
        )
        collector = InterfaceMonitorCollector()
        client = SNMPClient(transport=transport)
        t0 = datetime(2026, 11, 21, 10, 0, 0)
        base_ctx = {
            "device_id": dev["id"],
            "ip_address": dev["ip_address"],
            "port": 161,
            "credentials": creds,
            "profile": get_profile("generic_switch"),
            "client": client,
            "db": db,
            "now_utc": t0,
            "degraded_reasons": [],
            "collector_events": [],
            "collector_snapshots": {},
        }
        asyncio.run(collector.collect(dict(base_ctx)))

        # +115_000_000 octets over 10s = 92.0 Mbps = 92.0% on 100 Mbps
        transport.devices[("10.10.1.4", 161)]["tables"][STD_OIDS["ifHCInOctets"]] = [
            (f"{STD_OIDS['ifHCInOctets']}.1", 1_000_000 + 115_000_000)
        ]
        ctx2 = dict(base_ctx)
        ctx2["now_utc"] = t0 + timedelta(seconds=10)
        ctx2["degraded_reasons"] = []
        ctx2["collector_events"] = []
        ctx2["collector_snapshots"] = {}
        asyncio.run(collector.collect(ctx2))

        snap = collector.get_last_snapshot(dev["id"])
        assert snap[0]["in_mbps"] == pytest.approx(92.0, rel=1e-4)
        assert snap[0]["utilization_pct"] == pytest.approx(92.0, rel=1e-2)
        assert len(filter_interfaces(snap, "HIGH_UTILIZATION", high_util_pct=80.0)) == 1
        assert any(e["event_type"] == "INTERFACE_CONGESTION" and e["severity"] == "CRITICAL" for e in ctx2["collector_events"])

    def test_15_interface_errors_discards_and_crc_detection(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "iface_errors.db"))
        dev = _make_device(db, "10.10.1.5", "SW-ERRORS")
        creds = SNMPCredentials(version="v2c", community="secret_ro")
        transport = MockSNMPTransport()
        transport.register_device(
            "10.10.1.5",
            valid_version="v2c",
            valid_community="secret_ro",
            tables={
                STD_OIDS["ifIndex"]: [(f"{STD_OIDS['ifIndex']}.1", 1)],
                STD_OIDS["ifName"]: [(f"{STD_OIDS['ifName']}.1", "Gi0/24")],
                STD_OIDS["ifOperStatus"]: [(f"{STD_OIDS['ifOperStatus']}.1", 1)],
                STD_OIDS["ifSpeed"]: [(f"{STD_OIDS['ifSpeed']}.1", 1_000_000_000)],
                STD_OIDS["ifHCInOctets"]: [(f"{STD_OIDS['ifHCInOctets']}.1", 100_000)],
                STD_OIDS["ifHCOutOctets"]: [(f"{STD_OIDS['ifHCOutOctets']}.1", 100_000)],
                STD_OIDS["ifInErrors"]: [(f"{STD_OIDS['ifInErrors']}.1", 10)],
                STD_OIDS["ifOutErrors"]: [(f"{STD_OIDS['ifOutErrors']}.1", 2)],
                STD_OIDS["ifInDiscards"]: [(f"{STD_OIDS['ifInDiscards']}.1", 5)],
                STD_OIDS["ifOutDiscards"]: [(f"{STD_OIDS['ifOutDiscards']}.1", 1)],
                STD_OIDS["dot3StatsFCSErrors"]: [(f"{STD_OIDS['dot3StatsFCSErrors']}.1", 20)],
            },
        )
        collector = InterfaceMonitorCollector()
        client = SNMPClient(transport=transport)
        t0 = datetime(2026, 11, 21, 10, 0, 0)
        base_ctx = {
            "device_id": dev["id"],
            "ip_address": dev["ip_address"],
            "port": 161,
            "credentials": creds,
            "profile": get_profile("generic_switch"),
            "client": client,
            "db": db,
            "now_utc": t0,
            "degraded_reasons": [],
            "collector_events": [],
            "collector_snapshots": {},
        }
        asyncio.run(collector.collect(dict(base_ctx)))

        tbl = transport.devices[("10.10.1.5", 161)]["tables"]
        tbl[STD_OIDS["ifInErrors"]] = [(f"{STD_OIDS['ifInErrors']}.1", 14)]
        tbl[STD_OIDS["ifOutErrors"]] = [(f"{STD_OIDS['ifOutErrors']}.1", 3)]
        tbl[STD_OIDS["ifInDiscards"]] = [(f"{STD_OIDS['ifInDiscards']}.1", 8)]
        tbl[STD_OIDS["ifOutDiscards"]] = [(f"{STD_OIDS['ifOutDiscards']}.1", 2)]
        tbl[STD_OIDS["dot3StatsFCSErrors"]] = [(f"{STD_OIDS['dot3StatsFCSErrors']}.1", 27)]

        ctx2 = dict(base_ctx)
        ctx2["now_utc"] = t0 + timedelta(seconds=30)
        ctx2["degraded_reasons"] = []
        ctx2["collector_events"] = []
        ctx2["collector_snapshots"] = {}
        asyncio.run(collector.collect(ctx2))

        snap = collector.get_last_snapshot(dev["id"])
        assert snap[0]["in_errors"] == 4
        assert snap[0]["out_errors"] == 1
        assert snap[0]["in_discards"] == 3
        assert snap[0]["out_discards"] == 1
        assert snap[0]["crc_errors"] == 7
        assert len(filter_interfaces(snap, "ERRORS")) == 1
        assert any(e["event_type"] == "INTERFACE_ERRORS" for e in ctx2["collector_events"])
        assert ctx2["degraded_reasons"]

        db_meas = db.get_interface_measurements(device_id=dev["id"])
        assert len(db_meas) == 2
        assert db_meas[-1]["crc_errors"] == 7

    def test_16_poe_budget_consumption_overload_and_unsupported_device(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "poe.db"))
        sw_poe = _make_device(db, "10.10.1.6", "SW-POE-01", profile_name="cisco_catalyst", model="C9200L-48P")
        srv_plain = _make_device(db, "10.10.1.7", "SRV-NOPOE", profile_name="snmp_server")
        creds = SNMPCredentials(version="v2c", community="secret_ro")

        transport = MockSNMPTransport()
        # PoE switch at 340W / 370W (91.89% -> overload CRITICAL)
        transport.register_device(
            "10.10.1.6",
            valid_version="v2c",
            valid_community="secret_ro",
            tables={
                STD_OIDS["pethMainPsePower"]: [(f"{STD_OIDS['pethMainPsePower']}.1", 370)],
                STD_OIDS["pethMainPseConsumptionPower"]: [(f"{STD_OIDS['pethMainPseConsumptionPower']}.1", 340)],
                STD_OIDS["pethMainPseOperStatus"]: [(f"{STD_OIDS['pethMainPseOperStatus']}.1", 1)],
                STD_OIDS["pethMainPseUsageThreshold"]: [(f"{STD_OIDS['pethMainPseUsageThreshold']}.1", 80)],
                STD_OIDS["pethPsePortAdminEnable"]: [
                    (f"{STD_OIDS['pethPsePortAdminEnable']}.1.1", 1),
                    (f"{STD_OIDS['pethPsePortAdminEnable']}.1.2", 1),
                ],
                STD_OIDS["pethPsePortDetectionStatus"]: [
                    (f"{STD_OIDS['pethPsePortDetectionStatus']}.1.1", 3),  # DELIVERING
                    (f"{STD_OIDS['pethPsePortDetectionStatus']}.1.2", 2),  # SEARCHING
                ],
                STD_OIDS["pethPsePortPowerPriority"]: [
                    (f"{STD_OIDS['pethPsePortPowerPriority']}.1.1", 1),  # CRITICAL
                ],
                "1.3.6.1.4.1.9.9.402.1.2.1.9": [
                    ("1.3.6.1.4.1.9.9.402.1.2.1.9.1.1", 15_400),  # 15.4 W
                ],
            },
        )
        # Non-PoE server exposes NO PoE OIDs at all
        transport.register_device("10.10.1.7", valid_version="v2c", valid_community="secret_ro")

        poe_collector = PoEMonitorCollector()
        client = SNMPClient(transport=transport)

        ctx_poe = {
            "device_id": sw_poe["id"],
            "ip_address": sw_poe["ip_address"],
            "port": 161,
            "credentials": creds,
            "profile": get_profile("cisco_catalyst"),
            "client": client,
            "db": db,
            "due_flags": {"poe": True},
            "degraded_reasons": [],
            "collector_events": [],
            "collector_snapshots": {},
        }
        poe_metrics = asyncio.run(poe_collector.collect(ctx_poe))
        snap = poe_collector.get_last_snapshot(sw_poe["id"])
        assert snap.supported is True
        assert snap.budget_watts == 370.0
        assert snap.consumed_watts == 340.0
        assert snap.remaining_watts == 30.0
        assert snap.utilization_pct == pytest.approx(91.89, rel=1e-2)
        assert snap.overload is True
        assert snap.active_ports == 1
        assert snap.ports[0].power_watts == pytest.approx(15.4, rel=1e-4)
        assert any(e["event_type"] == "POE_OVERLOAD" for e in ctx_poe["collector_events"])
        assert any(m["metric_name"] == "poe_consumed_watts" and m["metric_value"] == 340.0 for m in poe_metrics)

        # Non-PoE server MUST return supported=False and ZERO fabricated metrics
        ctx_plain = {
            "device_id": srv_plain["id"],
            "ip_address": srv_plain["ip_address"],
            "port": 161,
            "credentials": creds,
            "profile": get_profile("snmp_server"),
            "client": client,
            "db": db,
            "due_flags": {"poe": True},
            "degraded_reasons": [],
            "collector_events": [],
            "collector_snapshots": {},
        }
        plain_metrics = asyncio.run(poe_collector.collect(ctx_plain))
        assert plain_metrics == []
        assert poe_collector.get_last_snapshot(srv_plain["id"]).supported is False

    def test_17_vlan_parsing_qbridge_bitmasks_and_cisco_trunks(self, tmp_path):
        # Verify PortList bitmask helper: 0x80 = port 1, 0x40 = port 2, 0x8001 = port 1 + port 16
        assert decode_port_list(b"\x80") == [1]
        assert decode_port_list("0x8001") == [1, 16]

        db = DatabaseManager(db_path=str(tmp_path / "vlans.db"))
        sw_qb = _make_device(db, "10.10.1.8", "SW-QBRIDGE", profile_name="generic_switch")
        sw_cisco = _make_device(db, "10.10.1.9", "SW-CISCO-VLAN", profile_name="cisco_catalyst")
        rtr_novlan = _make_device(db, "10.10.1.10", "RTR-NOVLAN", profile_name="generic_router")
        creds = SNMPCredentials(version="v2c", community="secret_ro")

        transport = MockSNMPTransport()
        # Q-BRIDGE switch: VLAN 10 (MGMT, port 1 untagged, port 3 trunk), VLAN 20 (USERS, port 2 untagged, port 3 trunk)
        transport.register_device(
            "10.10.1.8",
            valid_version="v2c",
            valid_community="secret_ro",
            tables={
                STD_OIDS["dot1dBasePortIfIndex"]: [
                    (f"{STD_OIDS['dot1dBasePortIfIndex']}.1", 101),
                    (f"{STD_OIDS['dot1dBasePortIfIndex']}.2", 102),
                    (f"{STD_OIDS['dot1dBasePortIfIndex']}.3", 103),
                ],
                STD_OIDS["dot1qVlanStaticName"]: [
                    (f"{STD_OIDS['dot1qVlanStaticName']}.10", "MGMT"),
                    (f"{STD_OIDS['dot1qVlanStaticName']}.20", "USERS"),
                ],
                STD_OIDS["dot1qVlanStaticRowStatus"]: [
                    (f"{STD_OIDS['dot1qVlanStaticRowStatus']}.10", 1),
                    (f"{STD_OIDS['dot1qVlanStaticRowStatus']}.20", 1),
                ],
                STD_OIDS["dot1qVlanCurrentEgressPorts"]: [
                    (f"{STD_OIDS['dot1qVlanCurrentEgressPorts']}.0.10", b"\xa0"),  # bp 1 & 3 (1010 0000)
                    (f"{STD_OIDS['dot1qVlanCurrentEgressPorts']}.0.20", b"\x60"),  # bp 2 & 3 (0110 0000)
                ],
                STD_OIDS["dot1qVlanCurrentUntaggedPorts"]: [
                    (f"{STD_OIDS['dot1qVlanCurrentUntaggedPorts']}.0.10", b"\x80"),  # bp 1
                    (f"{STD_OIDS['dot1qVlanCurrentUntaggedPorts']}.0.20", b"\x40"),  # bp 2
                ],
            },
        )
        # Cisco switch using VTP + VM + Trunk MIBs (excluding reserved 1002)
        transport.register_device(
            "10.10.1.9",
            valid_version="v2c",
            valid_community="secret_ro",
            tables={
                CISCO_VTP_VLAN_NAME_OID: [
                    (f"{CISCO_VTP_VLAN_NAME_OID}.100", "CORP_LAN"),
                    (f"{CISCO_VTP_VLAN_NAME_OID}.1002", "fddi-default"),
                ],
                CISCO_VTP_VLAN_STATE_OID: [
                    (f"{CISCO_VTP_VLAN_STATE_OID}.100", 1),
                    (f"{CISCO_VTP_VLAN_STATE_OID}.1002", 1),
                ],
                CISCO_VM_VLAN_OID: [(f"{CISCO_VM_VLAN_OID}.1", 100)],
                CISCO_TRUNK_DYN_STATUS_OID: [(f"{CISCO_TRUNK_DYN_STATUS_OID}.24", 1)],
            },
        )
        transport.register_device("10.10.1.10", valid_version="v2c", valid_community="secret_ro")

        vlan_collector = VLANMonitorCollector()
        client = SNMPClient(transport=transport)

        # Q-BRIDGE test
        m_qb = asyncio.run(
            vlan_collector.collect({
                "device_id": sw_qb["id"],
                "ip_address": sw_qb["ip_address"],
                "port": 161,
                "credentials": creds,
                "profile": get_profile("generic_switch"),
                "client": client,
                "db": db,
                "due_flags": {"sysinfo": True},
                "interface_name_map": {101: "Gi1/0/1", 102: "Gi1/0/2", 103: "Gi1/0/24"},
                "collector_snapshots": {},
            })
        )
        assert m_qb[0]["metric_value"] == 2.0
        db_vlans_qb = db.get_snmp_vlans(sw_qb["id"])
        assert len(db_vlans_qb) == 2
        assert db_vlans_qb[0]["name"] == "MGMT"
        assert db_vlans_qb[0]["untagged_ports"] == ["Gi1/0/1"]
        assert db_vlans_qb[0]["tagged_ports"] == ["Gi1/0/24"]
        assert db_vlans_qb[0]["trunk_ports"] == ["Gi1/0/24"]

        # Cisco test
        asyncio.run(
            vlan_collector.collect({
                "device_id": sw_cisco["id"],
                "ip_address": sw_cisco["ip_address"],
                "port": 161,
                "credentials": creds,
                "profile": get_profile("cisco_catalyst"),
                "client": client,
                "db": db,
                "due_flags": {"sysinfo": True},
                "interface_name_map": {1: "Gi1/0/1", 24: "Te1/0/24"},
                "collector_snapshots": {},
            })
        )
        db_vlans_c = db.get_snmp_vlans(sw_cisco["id"])
        assert len(db_vlans_c) == 1
        assert db_vlans_c[0]["vlan_id"] == 100
        assert db_vlans_c[0]["untagged_ports"] == ["Gi1/0/1"]
        assert db_vlans_c[0]["trunk_ports"] == ["Te1/0/24"]

        # Unsupported router -> empty metrics & 0 DB rows
        m_none = asyncio.run(
            vlan_collector.collect({
                "device_id": rtr_novlan["id"],
                "ip_address": rtr_novlan["ip_address"],
                "port": 161,
                "credentials": creds,
                "profile": get_profile("generic_router"),
                "client": client,
                "db": db,
                "due_flags": {"sysinfo": True},
                "collector_snapshots": {},
            })
        )
        assert m_none == []
        assert db.get_snmp_vlans(rtr_novlan["id"]) == []

    def test_18_device_health_cpu_memory_model_specific_temp_and_engine_e2e(self, tmp_path):
        # 1. Prove model-specific thresholds: same 68.0C temp is CRITICAL on C2960X vs NORMAL on FortiGate-100F
        assert resolve_temperature_thresholds(get_profile("cisco_catalyst"), "C2960X-48FPS") == (58.0, 68.0)
        assert resolve_temperature_thresholds(get_profile("fortinet_fortigate"), "FortiGate-100F") == (70.0, 85.0)
        assert format_uptime(44_352_000) == "5d 03h 12m"

        db = DatabaseManager(db_path=str(tmp_path / "health_e2e.db"))
        creds = SNMPCredentials(version="v2c", community="TopSecretCommunity99")

        sw_cisco = db.add_snmp_device({
            "name": "SW-C2960X",
            "ip_address": "10.10.2.1",
            "snmp_version": "v2c",
            "encrypted_credentials": encrypt_credentials(creds),
            "profile_name": "cisco_catalyst",
            "model": "C2960X-48FPS",
            "poll_interval_sec": 30,
        })
        sw_ruckus = _make_device(
            db, "10.10.2.2", "SW-ICX7150", profile_name="ruckus", model="ICX7150-48P", community="TopSecretCommunity99"
        )
        fw_fg = _make_device(
            db,
            "10.10.2.3",
            "FW-FG100F",
            profile_name="fortinet_fortigate",
            model="FortiGate-100F",
            community="TopSecretCommunity99",
        )
        srv_lin = _make_device(
            db, "10.10.2.4", "SRV-LINUX", profile_name="snmp_server", community="TopSecretCommunity99"
        )

        transport = MockSNMPTransport()
        # Cisco C2960X: CPU 82% (WARN), Memory 60/100 MB (60%), Temp 68.0C (CRITICAL for C2960X!)
        transport.register_device(
            "10.10.2.1",
            valid_version="v2c",
            valid_community="TopSecretCommunity99",
            scalars={STD_OIDS["sysUpTime"]: 1_200_000},
            tables={
                "1.3.6.1.4.1.9.9.109.1.1.1.1.7": [("1.3.6.1.4.1.9.9.109.1.1.1.1.7.1", 82)],
                "1.3.6.1.4.1.9.9.48.1.1.1.5": [("1.3.6.1.4.1.9.9.48.1.1.1.5.1", 60_000_000)],
                "1.3.6.1.4.1.9.9.48.1.1.1.6": [("1.3.6.1.4.1.9.9.48.1.1.1.6.1", 40_000_000)],
                "1.3.6.1.4.1.9.9.13.1.3.1.2": [("1.3.6.1.4.1.9.9.13.1.3.1.2.1", "Chassis Ambient")],
                "1.3.6.1.4.1.9.9.13.1.3.1.3": [("1.3.6.1.4.1.9.9.13.1.3.1.3.1", 68)],
                STD_OIDS["ifIndex"]: [(f"{STD_OIDS['ifIndex']}.1", 1)],
                STD_OIDS["ifName"]: [(f"{STD_OIDS['ifName']}.1", "Gi1/0/1")],
                STD_OIDS["ifOperStatus"]: [(f"{STD_OIDS['ifOperStatus']}.1", 1)],
                STD_OIDS["ifSpeed"]: [(f"{STD_OIDS['ifSpeed']}.1", 1_000_000_000)],
                STD_OIDS["ifHCInOctets"]: [(f"{STD_OIDS['ifHCInOctets']}.1", 10_000_000)],
                STD_OIDS["ifHCOutOctets"]: [(f"{STD_OIDS['ifHCOutOctets']}.1", 5_000_000)],
                CISCO_VTP_VLAN_NAME_OID: [(f"{CISCO_VTP_VLAN_NAME_OID}.10", "DATA")],
            },
        )
        # FortiGate-100F: CPU 30%, RAM 50% (8 GiB), sensors: Fan1=4500 (filtered!), CPU Core=68C (NORMAL!)
        transport.register_device(
            "10.10.2.3",
            valid_version="v2c",
            valid_community="TopSecretCommunity99",
            scalars={
                STD_OIDS["sysUpTime"]: 900_000,
                "1.3.6.1.4.1.12356.101.4.1.3.0": 30,
                "1.3.6.1.4.1.12356.101.4.1.4.0": 50,
                "1.3.6.1.4.1.12356.101.4.1.5.0": 8 * 1024 * 1024,  # 8 GiB in KiB
            },
            tables={
                "1.3.6.1.4.1.12356.101.4.3.2.1.2": [
                    ("1.3.6.1.4.1.12356.101.4.3.2.1.2.1", "Fan 1 Speed RPM"),
                    ("1.3.6.1.4.1.12356.101.4.3.2.1.2.2", "SoC Temp Sensor"),
                ],
                "1.3.6.1.4.1.12356.101.4.3.2.1.3": [
                    ("1.3.6.1.4.1.12356.101.4.3.2.1.3.1", 180),  # fan speed / noise (filtered out!)
                    ("1.3.6.1.4.1.12356.101.4.3.2.1.3.2", 68),   # 68C temperature -> NORMAL on FG-100F
                ],
            },
        )
        # Ruckus ICX7150: 0.5C raw temperature (95 -> 47.5 C)
        transport.register_device(
            "10.10.2.2",
            valid_version="v2c",
            valid_community="TopSecretCommunity99",
            scalars={
                STD_OIDS["sysUpTime"]: 500_000,
                "1.3.6.1.4.1.1991.1.1.2.1.53.0": 42,
            },
            tables={
                "1.3.6.1.4.1.1991.1.1.2.11.1.1.4": [("1.3.6.1.4.1.1991.1.1.2.11.1.1.4.1", 25)],
                "1.3.6.1.4.1.1991.1.1.2.13.1.1.3": [("1.3.6.1.4.1.1991.1.1.2.13.1.1.3.1", "Board Temp")],
                "1.3.6.1.4.1.1991.1.1.2.13.1.1.4": [("1.3.6.1.4.1.1991.1.1.2.13.1.1.4.1", 95)],
            },
        )
        # Linux snmp_server: ssCpuIdle=85 -> 15% CPU, hrStorageTable RAM (4 GiB / 16 GiB = 25%), lmSensors=47500 mC
        transport.register_device(
            "10.10.2.4",
            valid_version="v2c",
            valid_community="TopSecretCommunity99",
            scalars={
                STD_OIDS["sysUpTime"]: 300_000,
                "1.3.6.1.4.1.2021.11.11.0": 85,
            },
            tables={
                STD_OIDS["hrStorageType"]: [
                    (f"{STD_OIDS['hrStorageType']}.1", "1.3.6.1.2.1.25.2.1.2"),
                    (f"{STD_OIDS['hrStorageType']}.2", "1.3.6.1.2.1.25.2.1.3"),  # Virtual memory -> excluded
                ],
                STD_OIDS["hrStorageDescr"]: [
                    (f"{STD_OIDS['hrStorageDescr']}.1", "Physical memory"),
                    (f"{STD_OIDS['hrStorageDescr']}.2", "Virtual memory"),
                ],
                STD_OIDS["hrStorageAllocationUnits"]: [
                    (f"{STD_OIDS['hrStorageAllocationUnits']}.1", 4096),
                    (f"{STD_OIDS['hrStorageAllocationUnits']}.2", 4096),
                ],
                STD_OIDS["hrStorageSize"]: [
                    (f"{STD_OIDS['hrStorageSize']}.1", 4_194_304),  # 16 GiB
                    (f"{STD_OIDS['hrStorageSize']}.2", 8_388_608),
                ],
                STD_OIDS["hrStorageUsed"]: [
                    (f"{STD_OIDS['hrStorageUsed']}.1", 1_048_576),  # 4 GiB -> 25%
                    (f"{STD_OIDS['hrStorageUsed']}.2", 4_194_304),
                ],
                "1.3.6.1.4.1.2021.13.16.2.1.2": [("1.3.6.1.4.1.2021.13.16.2.1.2.1", "Package id 0")],
                "1.3.6.1.4.1.2021.13.16.2.1.3": [("1.3.6.1.4.1.2021.13.16.2.1.3.1", 47500)],
            },
        )

        # Deterministic clock for full AsyncSNMPEngine + attach_standard_collectors E2E test
        fake_now = [1000.0]
        client = SNMPClient(transport=transport)
        eng = AsyncSNMPEngine(db=db, client=client, clock_fn=lambda: fake_now[0])
        collectors = attach_standard_collectors(eng, clock_fn=lambda: fake_now[0])
        eng.reload_from_db()

        emitted_events: List[Dict[str, Any]] = []
        eng.collector_event.connect(emitted_events.append)

        # Poll 1 across all 4 devices
        snap_c = asyncio.run(eng.poll_device_by_id(sw_cisco["id"]))
        snap_r = asyncio.run(eng.poll_device_by_id(sw_ruckus["id"]))
        snap_f = asyncio.run(eng.poll_device_by_id(fw_fg["id"]))
        snap_l = asyncio.run(eng.poll_device_by_id(srv_lin["id"]))

        assert snap_c["status"] == "DEGRADED"  # 68C == CRITICAL for C2960X
        assert snap_c["collector_snapshots"]["health"]["temp_status"] == "CRITICAL"
        assert snap_c["collector_snapshots"]["health"]["cpu_pct"] == 82.0
        assert snap_c["collector_snapshots"]["health"]["memory_pct"] == 60.0

        assert snap_f["status"] == "ONLINE"  # Same 68C == NORMAL for FortiGate-100F!
        fg_temps = snap_f["collector_snapshots"]["health"]["temperatures"]
        assert len(fg_temps) == 1 and fg_temps[0]["label"] == "SoC Temp Sensor" and fg_temps[0]["temp_c"] == 68.0
        assert snap_f["collector_snapshots"]["health"]["memory_total_bytes"] == 8 * 1024**3

        assert snap_r["status"] == "ONLINE"
        assert snap_r["collector_snapshots"]["health"]["temperatures"][0]["temp_c"] == 47.5
        assert snap_r["collector_snapshots"]["health"]["memory_pct"] == 42.0

        assert snap_l["status"] == "ONLINE"
        assert snap_l["collector_snapshots"]["health"]["cpu_pct"] == 15.0
        assert snap_l["collector_snapshots"]["health"]["memory_pct"] == 25.0
        assert snap_l["collector_snapshots"]["health"]["temperatures"][0]["temp_c"] == 47.5

        # Advance 30s, update Cisco CPU to 50% & interface +37_500_000 octets (10.0 Mbps)
        fake_now[0] = 1030.0
        c_tbl = transport.devices[("10.10.2.1", 161)]["tables"]
        c_tbl["1.3.6.1.4.1.9.9.109.1.1.1.1.7"] = [("1.3.6.1.4.1.9.9.109.1.1.1.1.7.1", 50)]
        c_tbl[STD_OIDS["ifHCInOctets"]] = [(f"{STD_OIDS['ifHCInOctets']}.1", 10_000_000 + 37_500_000)]
        c_tbl[STD_OIDS["ifHCOutOctets"]] = [(f"{STD_OIDS['ifHCOutOctets']}.1", 5_000_000 + 7_500_000)]

        snap_c2 = asyncio.run(eng.poll_device_by_id(sw_cisco["id"]))
        eng.flush_now()

        assert snap_c2["collector_snapshots"]["interfaces"][0]["in_mbps"] == pytest.approx(10.0, rel=1e-4)
        assert snap_c2["collector_snapshots"]["interfaces"][0]["out_mbps"] == pytest.approx(2.0, rel=1e-4)
        assert compute_cpu_average(db, sw_cisco["id"]) == pytest.approx(66.0, rel=1e-3)
        assert len(db.get_snmp_vlans(sw_cisco["id"])) == 1
        assert len(db.get_interface_measurements(device_id=sw_cisco["id"])) == 2
        assert collectors["health"].get_last_snapshot(sw_cisco["id"]).cpu_pct == 50.0
        assert "TopSecretCommunity99" not in str(emitted_events)
        assert "TopSecretCommunity99" not in str(snap_c2)
