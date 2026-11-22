from dataclasses import dataclass, field
import re
from typing import Dict, Tuple


# Standard IETF MIB OID constants (numeric for fast, MIB-file-independent polling)
STD_OIDS: Dict[str, str] = {
    # MIB-II System (RFC 1213 / SNMPv2-MIB)
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysServices": "1.3.6.1.2.1.1.7.0",
    # IF-MIB (RFC 2863)
    "ifNumber": "1.3.6.1.2.1.2.1.0",
    "ifIndex": "1.3.6.1.2.1.2.2.1.1",
    "ifDescr": "1.3.6.1.2.1.2.2.1.2",
    "ifType": "1.3.6.1.2.1.2.2.1.3",
    "ifSpeed": "1.3.6.1.2.1.2.2.1.5",
    "ifPhysAddress": "1.3.6.1.2.1.2.2.1.6",
    "ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    "ifLastChange": "1.3.6.1.2.1.2.2.1.9",
    "ifInOctets": "1.3.6.1.2.1.2.2.1.10",
    "ifInDiscards": "1.3.6.1.2.1.2.2.1.13",
    "ifInErrors": "1.3.6.1.2.1.2.2.1.14",
    "ifOutOctets": "1.3.6.1.2.1.2.2.1.16",
    "ifOutDiscards": "1.3.6.1.2.1.2.2.1.19",
    "ifOutErrors": "1.3.6.1.2.1.2.2.1.20",
    # ifXTable (64-bit counters & aliases)
    "ifName": "1.3.6.1.2.1.31.1.1.1.1",
    "ifHCInOctets": "1.3.6.1.2.1.31.1.1.1.6",
    "ifHCOutOctets": "1.3.6.1.2.1.31.1.1.1.10",
    "ifHighSpeed": "1.3.6.1.2.1.31.1.1.1.15",
    "ifAlias": "1.3.6.1.2.1.31.1.1.1.18",
    "ifCounterDiscontinuityTime": "1.3.6.1.2.1.31.1.1.1.19",
    # EtherLike-MIB (RFC 3635)
    "dot3StatsFCSErrors": "1.3.6.1.2.1.10.7.2.1.3",
    # HOST-RESOURCES-MIB (RFC 2790)
    "hrMemorySize": "1.3.6.1.2.1.25.2.2.0",
    "hrStorageType": "1.3.6.1.2.1.25.2.3.1.2",
    "hrStorageDescr": "1.3.6.1.2.1.25.2.3.1.3",
    "hrStorageAllocationUnits": "1.3.6.1.2.1.25.2.3.1.4",
    "hrStorageSize": "1.3.6.1.2.1.25.2.3.1.5",
    "hrStorageUsed": "1.3.6.1.2.1.25.2.3.1.6",
    "hrProcessorLoad": "1.3.6.1.2.1.25.3.3.1.2",
    # POWER-ETHERNET-MIB (RFC 3621)
    "pethPsePortAdminEnable": "1.3.6.1.2.1.105.1.1.1.3",
    "pethPsePortDetectionStatus": "1.3.6.1.2.1.105.1.1.1.6",
    "pethPsePortPowerPriority": "1.3.6.1.2.1.105.1.1.1.7",
    "pethMainPsePower": "1.3.6.1.2.1.105.1.3.1.1.2",
    "pethMainPseOperStatus": "1.3.6.1.2.1.105.1.3.1.1.3",
    "pethMainPseConsumptionPower": "1.3.6.1.2.1.105.1.3.1.1.4",
    "pethMainPseUsageThreshold": "1.3.6.1.2.1.105.1.3.1.1.5",
    # BRIDGE-MIB & Q-BRIDGE-MIB (RFC 4363)
    "dot1dBasePortIfIndex": "1.3.6.1.2.1.17.1.4.1.2",
    "dot1qVlanCurrentEgressPorts": "1.3.6.1.2.1.17.7.1.4.2.1.4",
    "dot1qVlanCurrentUntaggedPorts": "1.3.6.1.2.1.17.7.1.4.2.1.5",
    "dot1qVlanStaticName": "1.3.6.1.2.1.17.7.1.4.3.1.1",
    "dot1qVlanStaticRowStatus": "1.3.6.1.2.1.17.7.1.4.3.1.5",
    "dot1qPvid": "1.3.6.1.2.1.17.7.1.4.5.1.1",
    # ENTITY-MIB & ENTITY-SENSOR-MIB
    "entPhysicalDescr": "1.3.6.1.2.1.47.1.1.1.1.2",
    "entPhysicalName": "1.3.6.1.2.1.47.1.1.1.1.7",
    "entPhysicalModelName": "1.3.6.1.2.1.47.1.1.1.1.13",
    "entPhySensorType": "1.3.6.1.2.1.99.1.1.1.1",
    "entPhySensorScale": "1.3.6.1.2.1.99.1.1.1.2",
    "entPhySensorPrecision": "1.3.6.1.2.1.99.1.1.1.3",
    "entPhySensorValue": "1.3.6.1.2.1.99.1.1.1.4",
    "entPhySensorOperStatus": "1.3.6.1.2.1.99.1.1.1.5",
}


@dataclass(frozen=True)
class SNMPVendorProfile:
    """Declarative vendor/device-class SNMP OID & threshold profile."""

    name: str
    vendor: str
    device_type: str
    enterprise_prefixes: Tuple[str, ...] = ()
    cpu_oids: Tuple[str, ...] = ()
    memory_used_oids: Tuple[str, ...] = ()
    memory_free_oids: Tuple[str, ...] = ()
    memory_total_oids: Tuple[str, ...] = ()
    memory_pct_oids: Tuple[str, ...] = ()
    temperature_value_oids: Tuple[str, ...] = ()
    temperature_name_oids: Tuple[str, ...] = ()
    poe_budget_oids: Tuple[str, ...] = ()
    poe_consumed_oids: Tuple[str, ...] = ()
    poe_port_power_mw_oids: Tuple[str, ...] = ()
    vlan_name_oids: Tuple[str, ...] = ()
    vlan_trunk_oids: Tuple[str, ...] = ()
    vlan_access_oids: Tuple[str, ...] = ()
    model_oids: Tuple[str, ...] = ()
    firmware_oids: Tuple[str, ...] = ()
    cpu_warn_pct: float = 75.0
    cpu_crit_pct: float = 90.0
    mem_warn_pct: float = 80.0
    mem_crit_pct: float = 90.0
    default_temp_warn_c: float = 65.0
    default_temp_crit_c: float = 80.0


SNMP_PROFILES: Dict[str, SNMPVendorProfile] = {
    "cisco_catalyst": SNMPVendorProfile(
        name="cisco_catalyst",
        vendor="Cisco",
        device_type="Switch",
        enterprise_prefixes=("1.3.6.1.4.1.9.",),
        cpu_oids=(
            "1.3.6.1.4.1.9.9.109.1.1.1.1.7",   # cpmCPUTotal1minRev
            "1.3.6.1.4.1.9.9.109.1.1.1.1.4",   # cpmCPUTotal1min (legacy)
            "1.3.6.1.4.1.9.2.1.57.0",          # OLD-CISCO-CPU-MIB avgBusy1
        ),
        memory_used_oids=("1.3.6.1.4.1.9.9.48.1.1.1.5",),   # ciscoMemoryPoolUsed
        memory_free_oids=("1.3.6.1.4.1.9.9.48.1.1.1.6",),   # ciscoMemoryPoolFree
        temperature_value_oids=(
            "1.3.6.1.4.1.9.9.13.1.3.1.3",      # ciscoEnvMonTemperatureStatusValue
            STD_OIDS["entPhySensorValue"],
        ),
        temperature_name_oids=(
            "1.3.6.1.4.1.9.9.13.1.3.1.2",      # ciscoEnvMonTemperatureStatusDescr
            STD_OIDS["entPhysicalName"],
        ),
        poe_budget_oids=(STD_OIDS["pethMainPsePower"],),
        poe_consumed_oids=(STD_OIDS["pethMainPseConsumptionPower"],),
        poe_port_power_mw_oids=(
            "1.3.6.1.4.1.9.9.402.1.2.1.9",  # cpeExtPsePortPwrConsumption (mW)
            "1.3.6.1.4.1.9.9.402.1.2.1.7",  # cpeExtPsePortPwrAllocated (mW)
        ),
        vlan_name_oids=(
            "1.3.6.1.4.1.9.9.46.1.3.1.1.4.1",  # vtpVlanName
            STD_OIDS["dot1qVlanStaticName"],
        ),
        vlan_trunk_oids=("1.3.6.1.4.1.9.9.46.1.6.1.1.14",),       # vlanTrunkPortDynamicState
        vlan_access_oids=("1.3.6.1.4.1.9.9.68.1.2.2.1.2",),       # vmVlan (CISCO-VLAN-MEMBERSHIP-MIB)
        model_oids=(STD_OIDS["entPhysicalModelName"],),
        firmware_oids=("1.3.6.1.2.1.47.1.1.1.1.9",),              # entPhysicalFirmwareRev
        default_temp_warn_c=60.0,
        default_temp_crit_c=72.0,
    ),
    "ruckus": SNMPVendorProfile(
        name="ruckus",
        vendor="Ruckus",
        device_type="Switch / AP",
        enterprise_prefixes=("1.3.6.1.4.1.1991.", "1.3.6.1.4.1.25053."),
        cpu_oids=(
            "1.3.6.1.4.1.1991.1.1.2.11.1.1.4",   # snAgGblCpuUtil1MinAvg (ICX)
            "1.3.6.1.4.1.25053.1.2.1.1.1.15.1",  # ruckusCtrlSystemStatsCpuUtil
            STD_OIDS["hrProcessorLoad"],
        ),
        memory_pct_oids=(
            "1.3.6.1.4.1.1991.1.1.2.1.53.0",     # snAgGblDynMemUtil
        ),
        temperature_value_oids=(
            "1.3.6.1.4.1.1991.1.1.2.13.1.1.4",   # snAgentTempValue (0.5 C units when Foundry/ICX)
            STD_OIDS["entPhySensorValue"],
        ),
        temperature_name_oids=(
            "1.3.6.1.4.1.1991.1.1.2.13.1.1.3",   # snAgentTempSensorDescr
            STD_OIDS["entPhysicalName"],
        ),
        poe_budget_oids=(STD_OIDS["pethMainPsePower"],),
        poe_consumed_oids=(STD_OIDS["pethMainPseConsumptionPower"],),
        poe_port_power_mw_oids=("1.3.6.1.4.1.1991.1.1.2.14.2.2.1.4",),  # snAgentPoePortConsumed
        vlan_name_oids=(
            STD_OIDS["dot1qVlanStaticName"],
            "1.3.6.1.4.1.1991.1.1.3.2.7.1.21",   # snVLanByPortCfgVlanName
        ),
        model_oids=(
            STD_OIDS["entPhysicalModelName"],
            "1.3.6.1.4.1.25053.1.1.11.1.1.1.14",
        ),
        firmware_oids=("1.3.6.1.4.1.1991.1.1.2.1.11.0",),
        default_temp_warn_c=65.0,
        default_temp_crit_c=80.0,
    ),
    "fortinet_fortigate": SNMPVendorProfile(
        name="fortinet_fortigate",
        vendor="Fortinet",
        device_type="Firewall",
        enterprise_prefixes=("1.3.6.1.4.1.12356.",),
        cpu_oids=(
            "1.3.6.1.4.1.12356.101.4.1.3.0",     # fgSysCpuUsage
            STD_OIDS["hrProcessorLoad"],
        ),
        memory_pct_oids=(
            "1.3.6.1.4.1.12356.101.4.1.4.0",     # fgSysMemUsage
        ),
        memory_total_oids=(
            "1.3.6.1.4.1.12356.101.4.1.5.0",     # fgSysMemCapacity (KB)
        ),
        temperature_value_oids=(
            "1.3.6.1.4.1.12356.101.4.3.2.1.3",   # fgHwSensorEntValue
            STD_OIDS["entPhySensorValue"],
        ),
        temperature_name_oids=(
            "1.3.6.1.4.1.12356.101.4.3.2.1.2",   # fgHwSensorEntName
            STD_OIDS["entPhysicalName"],
        ),
        model_oids=("1.3.6.1.4.1.12356.100.1.1.1.0", STD_OIDS["entPhysicalModelName"]),
        firmware_oids=("1.3.6.1.4.1.12356.101.4.1.1.0",),  # fgSysVersion
        default_temp_warn_c=70.0,
        default_temp_crit_c=85.0,
    ),
    "generic_router": SNMPVendorProfile(
        name="generic_router",
        vendor="Generic",
        device_type="Router",
        enterprise_prefixes=(),
        cpu_oids=(STD_OIDS["hrProcessorLoad"], "1.3.6.1.4.1.2021.11.9.0"),
        temperature_value_oids=(STD_OIDS["entPhySensorValue"],),
        temperature_name_oids=(STD_OIDS["entPhysicalName"],),
        vlan_name_oids=(STD_OIDS["dot1qVlanStaticName"],),
        model_oids=(STD_OIDS["entPhysicalModelName"],),
        default_temp_warn_c=65.0,
        default_temp_crit_c=80.0,
    ),
    "generic_switch": SNMPVendorProfile(
        name="generic_switch",
        vendor="Generic",
        device_type="Switch",
        enterprise_prefixes=(),
        cpu_oids=(STD_OIDS["hrProcessorLoad"],),
        temperature_value_oids=(STD_OIDS["entPhySensorValue"],),
        temperature_name_oids=(STD_OIDS["entPhysicalName"],),
        poe_budget_oids=(STD_OIDS["pethMainPsePower"],),
        poe_consumed_oids=(STD_OIDS["pethMainPseConsumptionPower"],),
        vlan_name_oids=(STD_OIDS["dot1qVlanStaticName"],),
        model_oids=(STD_OIDS["entPhysicalModelName"],),
        default_temp_warn_c=62.0,
        default_temp_crit_c=75.0,
    ),
    "snmp_server": SNMPVendorProfile(
        name="snmp_server",
        vendor="Linux/Windows Server",
        device_type="Server / Appliance",
        enterprise_prefixes=("1.3.6.1.4.1.8072.", "1.3.6.1.4.1.2021.", "1.3.6.1.4.1.311."),
        cpu_oids=(STD_OIDS["hrProcessorLoad"], "1.3.6.1.4.1.2021.11.11.0"),
        memory_total_oids=("1.3.6.1.4.1.2021.4.5.0", STD_OIDS["hrMemorySize"]),
        memory_free_oids=("1.3.6.1.4.1.2021.4.6.0",),
        temperature_value_oids=(
            "1.3.6.1.4.1.2021.13.16.2.1.3",  # lmTempSensorsValue (mC)
            STD_OIDS["entPhySensorValue"],
        ),
        temperature_name_oids=(
            "1.3.6.1.4.1.2021.13.16.2.1.2",  # lmTempSensorsDevice
        ),
        model_oids=(STD_OIDS["entPhysicalModelName"],),
        default_temp_warn_c=75.0,
        default_temp_crit_c=90.0,
    ),
}


def get_profile(profile_name: str) -> SNMPVendorProfile:
    key = str(profile_name or "").strip().lower()
    return SNMP_PROFILES.get(key, SNMP_PROFILES["generic_switch"])


def detect_vendor_and_profile(
    sys_object_id: str = "",
    sys_descr: str = "",
    sys_services: int = 0,
) -> Dict[str, str]:
    """Detect vendor, device model, firmware, device_type, and best profile from MIB-II system values."""
    oid = str(sys_object_id or "").strip().lstrip(".")
    descr = str(sys_descr or "").strip()
    descr_low = descr.lower()

    profile_name = "generic_switch"
    vendor = "Generic"
    device_type = "Network Device"
    model = ""
    firmware = ""

    # 1. Match enterprise OID prefixes first
    for prof in SNMP_PROFILES.values():
        if prof.enterprise_prefixes and any(oid.startswith(pfx) for pfx in prof.enterprise_prefixes):
            profile_name = prof.name
            vendor = prof.vendor
            device_type = prof.device_type
            break

    # 2. Fallback keyword hints from sysDescr if generic
    if profile_name == "generic_switch":
        if "cisco" in descr_low or "catalyst" in descr_low or "ios" in descr_low:
            profile_name = "cisco_catalyst"
            vendor = "Cisco"
            device_type = "Switch"
        elif "ruckus" in descr_low or "brocade" in descr_low or "icx" in descr_low or "zoneflex" in descr_low:
            profile_name = "ruckus"
            vendor = "Ruckus"
            device_type = "Switch / AP"
        elif "fortigate" in descr_low or "fortios" in descr_low or "fortinet" in descr_low:
            profile_name = "fortinet_fortigate"
            vendor = "Fortinet"
            device_type = "Firewall"
        elif "linux" in descr_low or "windows" in descr_low or "ubuntu" in descr_low or "vmware" in descr_low:
            profile_name = "snmp_server"
            vendor = "Windows" if "windows" in descr_low else ("Linux" if "linux" in descr_low else "Server")
            device_type = "Server / Appliance"
        elif "router" in descr_low or "mikrotik" in descr_low or "juniper" in descr_low or (sys_services & 0x04):
            profile_name = "generic_router"
            vendor = "MikroTik" if "mikrotik" in descr_low else ("Juniper" if "juniper" in descr_low else "Generic")
            device_type = "Router"

    # 3. Parse model & firmware best-effort from sysDescr
    if profile_name == "cisco_catalyst":
        m_mod = re.search(r"\b(C\d{4}[A-Z0-9-]*|WS-C\d{4}[A-Z0-9-]*|Catalyst\s+[A-Z0-9-]+)", descr, re.I)
        if m_mod:
            model = m_mod.group(1)
        m_fw = re.search(r"Version\s+([0-9A-Za-z.()]+)", descr, re.I)
        if m_fw:
            firmware = m_fw.group(1)
    elif profile_name == "ruckus":
        m_mod = re.search(r"\b(ICX\d{4}[A-Z0-9-]*|R\d{3}|T\d{3}|H\d{3})", descr, re.I)
        if m_mod:
            model = m_mod.group(1)
        m_fw = re.search(r"(?:Version|SW:|FastIron)\s*([0-9A-Za-z._-]+)", descr, re.I)
        if m_fw:
            firmware = m_fw.group(1)
    elif profile_name == "fortinet_fortigate":
        m_mod = re.search(r"\b(FortiGate[-\s][A-Za-z0-9-]+|FG-\d+[A-Za-z0-9]*)", descr, re.I)
        if m_mod:
            model = m_mod.group(1)
        m_fw = re.search(r"v(\d+\.\d+\.\d+[A-Za-z0-9,-]*)", descr, re.I)
        if m_fw:
            firmware = "v" + m_fw.group(1)
    elif profile_name == "snmp_server":
        parts = descr.split()
        if len(parts) >= 3:
            model = parts[0]
            firmware = parts[2]

    return {
        "profile_name": profile_name,
        "vendor": vendor,
        "device_type": device_type,
        "model": model,
        "firmware": firmware,
    }
