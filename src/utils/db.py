import json
import os
import sqlite3
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
    func,
    text,
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy.pool import StaticPool

Base = declarative_base()

class Host(Base):
    __tablename__ = 'hosts'
    id = Column(Integer, primary_key=True, autoincrement=True)
    address = Column(String, unique=True, nullable=False)
    label = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    category = Column(String, default="General")
    profile = Column(String, default="Standard")
    notes = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    logs = relationship("MonitoringLog", back_populates="host", cascade="all, delete")
    policy = relationship("MonitoringPolicy", back_populates="host", uselist=False, cascade="all, delete-orphan")


class MonitoringLog(Base):
    __tablename__ = 'monitoring_logs'
    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey('hosts.id'), index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    status = Column(String)
    latency = Column(Integer)
    response = Column(String, nullable=True)
    host = relationship("Host", back_populates="logs")


class PingMeasurement(Base):
    __tablename__ = 'ping_measurements'
    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey('hosts.id', ondelete='SET NULL'), nullable=True, index=True)
    host_address = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    status = Column(String, nullable=False)  # UP, TIMEOUT, DNS_ERROR, ENGINE_ERROR
    latency_ms = Column(Float, nullable=True)
    is_valid_probe = Column(Boolean, default=True)
    error_type = Column(String, nullable=True)
    detail = Column(String, nullable=True)

    __table_args__ = (
        Index('ix_ping_meas_addr_ts', 'host_address', 'timestamp'),
    )


class MonitoringIncident(Base):
    __tablename__ = 'monitoring_incidents'
    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_uid = Column(String, unique=True, nullable=False, index=True)
    host_id = Column(Integer, ForeignKey('hosts.id', ondelete='SET NULL'), nullable=True, index=True)
    host_name = Column(String, nullable=False)
    host_address = Column(String, nullable=False, index=True)
    incident_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    start_time = Column(DateTime, nullable=False, index=True)
    end_time = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, default=0.0)
    failed_probes = Column(Integer, default=0)
    packet_loss_pct = Column(Float, default=0.0)
    avg_latency_before_ms = Column(Float, default=0.0)
    recovery_latency_ms = Column(Float, nullable=True)
    status = Column(String, nullable=False, default="DETECTED", index=True)
    acknowledged = Column(Boolean, default=False)
    acknowledged_at = Column(DateTime, nullable=True)
    comments = Column(String, default="")


class AlertEvent(Base):
    __tablename__ = 'alert_events'
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    host_id = Column(Integer, ForeignKey('hosts.id', ondelete='SET NULL'), nullable=True, index=True)
    host_address = Column(String, nullable=False, index=True)
    host_name = Column(String, nullable=True)
    incident_id = Column(Integer, ForeignKey('monitoring_incidents.id', ondelete='SET NULL'), nullable=True, index=True)
    severity = Column(String, nullable=False, index=True)
    event_type = Column(String, nullable=False)
    message = Column(String, nullable=False)
    channel = Column(String, nullable=False)
    delivered = Column(Boolean, default=True)
    error_detail = Column(String, nullable=True)


class MonitoringPolicy(Base):
    __tablename__ = 'monitoring_policies'
    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey('hosts.id', ondelete='CASCADE'), unique=True, nullable=True, index=True)
    probe_interval_ms = Column(Integer, default=1000)
    timeout_ms = Column(Integer, default=1000)
    warning_failures = Column(Integer, default=3)
    critical_failures = Column(Integer, default=5)
    recovery_successes = Column(Integer, default=3)
    rolling_window_sec = Column(Integer, default=60)
    packet_loss_warn_pct = Column(Float, default=10.0)
    latency_warn_ms = Column(Float, default=150.0)
    jitter_warn_ms = Column(Float, default=30.0)
    sound_enabled = Column(Boolean, default=True)
    email_enabled = Column(Boolean, default=True)
    windows_notify_enabled = Column(Boolean, default=True)
    repeat_alert_interval_sec = Column(Integer, default=0)
    updated_at = Column(DateTime, default=datetime.utcnow)
    host = relationship("Host", back_populates="policy")


class MonitoringStatistics(Base):
    __tablename__ = 'monitoring_statistics'
    id = Column(Integer, primary_key=True, autoincrement=True)
    host_address = Column(String, nullable=False, index=True)
    bucket_start = Column(DateTime, nullable=False, index=True)
    granularity = Column(String, nullable=False)
    total_probes = Column(Integer, default=0)
    valid_probes = Column(Integer, default=0)
    failed_probes = Column(Integer, default=0)
    packet_loss_pct = Column(Float, default=0.0)
    min_latency_ms = Column(Float, default=0.0)
    avg_latency_ms = Column(Float, default=0.0)
    max_latency_ms = Column(Float, default=0.0)
    p95_latency_ms = Column(Float, default=0.0)
    jitter_ms = Column(Float, default=0.0)
    uptime_pct = Column(Float, default=100.0)

    __table_args__ = (
        Index('ix_mon_stats_addr_gran_ts', 'host_address', 'granularity', 'bucket_start'),
    )


class SNMPDevice(Base):
    __tablename__ = 'snmp_devices'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    ip_address = Column(String, nullable=False, unique=True, index=True)
    port = Column(Integer, default=161)
    snmp_version = Column(String, nullable=False, default="v2c")
    encrypted_credentials = Column(String, nullable=False)
    vendor = Column(String, default="Generic")
    model = Column(String, default="")
    firmware = Column(String, default="")
    device_type = Column(String, default="Network Device")
    profile_name = Column(String, default="generic_switch")
    sys_descr = Column(String, default="")
    sys_object_id = Column(String, default="")
    sys_name = Column(String, default="")
    sys_location = Column(String, default="")
    location = Column(String, default="")
    status = Column(String, default="UNKNOWN", index=True)
    enabled = Column(Boolean, default=True)
    anomaly_detection_enabled = Column(Boolean, default=True)
    timeout_sec = Column(Float, default=2.0)
    retries = Column(Integer, default=1)
    poll_interval_sec = Column(Integer, default=30)
    temp_interval_sec = Column(Integer, default=60)
    poe_interval_sec = Column(Integer, default=60)
    sysinfo_interval_sec = Column(Integer, default=300)
    capabilities_json = Column(String, default="{}")
    thresholds_json = Column(String, default="{}")
    last_uptime_ticks = Column(BigInteger, nullable=True)
    last_reboot_at = Column(DateTime, nullable=True)
    last_poll = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class SNMPMetric(Base):
    __tablename__ = 'snmp_metrics'
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey('snmp_devices.id', ondelete='CASCADE'), nullable=False, index=True)
    metric_name = Column(String, nullable=False, index=True)
    metric_value = Column(Float, nullable=False)
    unit = Column(String, default="")
    sensor_label = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        Index('ix_snmp_metric_dev_name_ts', 'device_id', 'metric_name', 'timestamp'),
    )


class SNMPMetricAggregated(Base):
    __tablename__ = 'snmp_metrics_aggregated'
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey('snmp_devices.id', ondelete='CASCADE'), nullable=False, index=True)
    metric_name = Column(String, nullable=False)
    granularity = Column(String, nullable=False)
    bucket_start = Column(DateTime, nullable=False)
    min_value = Column(Float, default=0.0)
    avg_value = Column(Float, default=0.0)
    max_value = Column(Float, default=0.0)
    sample_count = Column(Integer, default=0)

    __table_args__ = (
        Index('ix_snmp_agg_dev_name_gran_ts', 'device_id', 'metric_name', 'granularity', 'bucket_start'),
    )


class SNMPInterface(Base):
    __tablename__ = 'snmp_interfaces'
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey('snmp_devices.id', ondelete='CASCADE'), nullable=False, index=True)
    if_index = Column(Integer, nullable=False)
    name = Column(String, default="")
    description = Column(String, default="")
    alias = Column(String, default="")
    mac_address = Column(String, default="")
    admin_status = Column(String, default="UNKNOWN")
    oper_status = Column(String, default="UNKNOWN")
    speed_bps = Column(BigInteger, default=0)
    negotiated_speed_mbps = Column(Float, nullable=True)
    last_change_ticks = Column(BigInteger, nullable=True)
    last_change_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint('device_id', 'if_index', name='uq_snmp_iface_dev_idx'),
    )


class InterfaceMeasurement(Base):
    __tablename__ = 'interface_measurements'
    id = Column(Integer, primary_key=True, autoincrement=True)
    interface_id = Column(Integer, ForeignKey('snmp_interfaces.id', ondelete='CASCADE'), nullable=False, index=True)
    device_id = Column(Integer, ForeignKey('snmp_devices.id', ondelete='CASCADE'), nullable=False, index=True)
    in_mbps = Column(Float, default=0.0)
    out_mbps = Column(Float, default=0.0)
    utilization_pct = Column(Float, default=0.0)
    in_errors = Column(BigInteger, default=0)
    out_errors = Column(BigInteger, default=0)
    in_discards = Column(BigInteger, default=0)
    out_discards = Column(BigInteger, default=0)
    crc_errors = Column(BigInteger, default=0)
    oper_status = Column(String, default="UNKNOWN")
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        Index('ix_iface_meas_iface_ts', 'interface_id', 'timestamp'),
        Index('ix_iface_meas_dev_ts', 'device_id', 'timestamp'),
    )


class SNMPVlan(Base):
    __tablename__ = 'snmp_vlans'
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey('snmp_devices.id', ondelete='CASCADE'), nullable=False, index=True)
    vlan_id = Column(Integer, nullable=False)
    name = Column(String, default="")
    status = Column(String, default="ACTIVE")
    tagged_ports_json = Column(String, default="[]")
    untagged_ports_json = Column(String, default="[]")
    trunk_ports_json = Column(String, default="[]")
    updated_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint('device_id', 'vlan_id', name='uq_snmp_vlan_dev_vid'),
    )


class SyslogEvent(Base):
    __tablename__ = 'syslog_events'
    id = Column(Integer, primary_key=True, autoincrement=True)
    source_ip = Column(String, nullable=False, index=True)
    hostname = Column(String, default="", index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    facility = Column(Integer, default=0)
    facility_name = Column(String, default="kern")
    severity = Column(Integer, default=6, index=True)
    severity_name = Column(String, default="Informational", index=True)
    app_name = Column(String, default="")
    event_category = Column(String, default="GENERAL", index=True)
    message = Column(String, nullable=False)
    raw_message = Column(String, nullable=False)

    __table_args__ = (
        Index('ix_syslog_ip_ts', 'source_ip', 'timestamp'),
        Index('ix_syslog_sev_ts', 'severity', 'timestamp'),
    )


class NetworkAnomaly(Base):
    __tablename__ = 'network_anomalies'
    id = Column(Integer, primary_key=True, autoincrement=True)
    anomaly_uid = Column(String, unique=True, nullable=False, index=True)
    device_id = Column(Integer, ForeignKey('snmp_devices.id', ondelete='SET NULL'), nullable=True, index=True)
    device_name = Column(String, default="")
    device_ip = Column(String, default="", index=True)
    event_type = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False, index=True)
    confidence = Column(String, default="MEDIUM")
    probable_cause = Column(String, default="")
    evidence_json = Column(String, default="[]")
    actions_json = Column(String, default="[]")
    status = Column(String, default="ACTIVE", index=True)
    detected_at = Column(DateTime, default=datetime.utcnow, index=True)
    resolved_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index('ix_anomaly_status_ts', 'status', 'detected_at'),
    )

class SpeedTestLog(Base):
    __tablename__ = 'speed_tests'
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    download = Column(Float)
    upload = Column(Float)
    ping = Column(Float)
    jitter = Column(Float)
    packet_loss = Column(Float)
    server = Column(String)
    isp = Column(String)

class GlobalService(Base):
    __tablename__ = 'global_services'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False)
    url = Column(String, nullable=False)
    is_custom = Column(Boolean, default=False)
    logs = relationship("GlobalServiceLog", back_populates="service", cascade="all, delete")

class GlobalServiceLog(Base):
    __tablename__ = 'global_service_logs'
    id = Column(Integer, primary_key=True, autoincrement=True)
    service_id = Column(Integer, ForeignKey('global_services.id'), index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    status = Column(String)
    latency = Column(Integer)
    service = relationship("GlobalService", back_populates="logs")


# ---------------------------------------------------------------------------
# Roadmap 03 (v3.6.0) — Infrastructure Management Models (+10 tables)
# ---------------------------------------------------------------------------

class NetworkSite(Base):
    __tablename__ = 'network_sites'
    id = Column(Integer, primary_key=True, autoincrement=True)
    site_code = Column(String, unique=True, nullable=False, index=True)
    organization = Column(String, default="Default Organization", index=True)
    region = Column(String, default="Default Region", index=True)
    parent_site_id = Column(Integer, ForeignKey('network_sites.id', ondelete='SET NULL'), nullable=True, index=True)
    name = Column(String, nullable=False, index=True)
    description = Column(String, default="")
    address = Column(String, default="")
    contact_name = Column(String, default="")
    contact_email = Column(String, default="")
    contact_phone = Column(String, default="")
    network_ranges_json = Column(String, default="[]")
    default_gateway = Column(String, default="")
    dns_servers_json = Column(String, default="[]")
    isp_name = Column(String, default="")
    wan_info_json = Column(String, default="{}")
    connectivity_mode = Column(String, default="LOCAL")  # LOCAL, VPN, REMOTE_AUTHORIZED
    polling_profile_json = Column(String, default="{}")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SSHProfile(Base):
    __tablename__ = 'ssh_profiles'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False, index=True)
    vendor_profile = Column(String, default="generic_ssh")
    protocol = Column(String, default="SSH")
    port = Column(Integer, default=22)
    username = Column(String, default="")
    auth_method = Column(String, default="PASSWORD")  # PASSWORD, KEY, KEY_WITH_PASSPHRASE
    encrypted_secret = Column(String, default="")
    private_key_path = Column(String, default="")
    timeout_sec = Column(Integer, default=15)
    host_key_policy = Column(String, default="STRICT")  # STRICT, TOFU_CONFIRM
    expected_fingerprint = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class InfrastructureDevice(Base):
    __tablename__ = 'infrastructure_devices'
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_uid = Column(String, unique=True, nullable=False, index=True)
    site_id = Column(Integer, ForeignKey('network_sites.id', ondelete='SET NULL'), nullable=True, index=True)
    snmp_device_id = Column(Integer, ForeignKey('snmp_devices.id', ondelete='SET NULL'), nullable=True, index=True)
    host_id = Column(Integer, ForeignKey('hosts.id', ondelete='SET NULL'), nullable=True, index=True)
    hostname = Column(String, nullable=False, index=True)
    management_ip = Column(String, nullable=False, index=True)
    mac_address = Column(String, default="", index=True)
    vendor = Column(String, default="Unknown")
    model = Column(String, default="")
    serial_number = Column(String, default="", index=True)
    firmware_version = Column(String, default="")
    category = Column(String, default="Other", index=True)
    role = Column(String, default="")
    rack_location = Column(String, default="")
    management_protocol = Column(String, default="SNMP")
    snmp_profile = Column(String, default="")
    ssh_profile_id = Column(Integer, ForeignKey('ssh_profiles.id', ondelete='SET NULL'), nullable=True)
    discovery_source = Column(String, default="MANUAL")
    status = Column(String, default="UNKNOWN", index=True)
    tags_json = Column(String, default="[]")
    device_group = Column(String, default="", index=True)
    custom_fields_json = Column(String, default="{}")
    purchase_date = Column(String, default="")
    warranty_expiration = Column(String, default="")
    manufacturer = Column(String, default="")
    support_info = Column(String, default="")
    maintenance_notes = Column(String, default="")
    equipment_owner = Column(String, default="")
    maintenance_reminder_date = Column(String, default="")
    last_discovery = Column(DateTime, nullable=True)
    last_monitoring_check = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index('ix_infra_dev_site_cat', 'site_id', 'category'),
    )


class DeviceInterface(Base):
    __tablename__ = 'device_interfaces'
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey('infrastructure_devices.id', ondelete='CASCADE'), nullable=False, index=True)
    if_index = Column(Integer, default=0)
    name = Column(String, nullable=False)
    description = Column(String, default="")
    alias = Column(String, default="")
    mac_address = Column(String, default="")
    admin_status = Column(String, default="UNKNOWN")
    oper_status = Column(String, default="UNKNOWN")
    speed_mbps = Column(Float, nullable=True)
    port_mode = Column(String, default="UNKNOWN")  # ACCESS, TRUNK, ROUTED, UNKNOWN
    access_vlan = Column(Integer, nullable=True)
    tagged_vlans_json = Column(String, default="[]")
    native_vlan = Column(Integer, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint('device_id', 'name', name='uq_dev_iface_name'),
    )


class NetworkLink(Base):
    __tablename__ = 'network_links'
    id = Column(Integer, primary_key=True, autoincrement=True)
    source_device_id = Column(Integer, ForeignKey('infrastructure_devices.id', ondelete='CASCADE'), nullable=False, index=True)
    dest_device_id = Column(Integer, ForeignKey('infrastructure_devices.id', ondelete='CASCADE'), nullable=False, index=True)
    source_interface = Column(String, default="")
    dest_interface = Column(String, default="")
    link_type = Column(String, default="PHYSICAL")  # PHYSICAL, LOGICAL, TRUNK, UPLINK
    discovery_method = Column(String, nullable=False)  # LLDP, CDP, BRIDGE_FDB, ARP_SUBNET, ROUTING, MANUAL
    confidence = Column(String, default="MEDIUM")  # HIGH, MEDIUM, LOW
    status = Column(String, default="UP")
    vlan_ids_json = Column(String, default="[]")
    evidence_json = Column(String, default="[]")
    last_observed = Column(DateTime, default=datetime.utcnow, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('ix_netlink_src_dst', 'source_device_id', 'dest_device_id'),
    )


class TopologyLayout(Base):
    __tablename__ = 'topology_layouts'
    id = Column(Integer, primary_key=True, autoincrement=True)
    layout_name = Column(String, unique=True, nullable=False, index=True)
    view_mode = Column(String, default="PHYSICAL")
    site_id = Column(Integer, ForeignKey('network_sites.id', ondelete='SET NULL'), nullable=True)
    positions_json = Column(String, default="{}")
    zoom_level = Column(Float, default=1.0)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class InfrastructureVlan(Base):
    __tablename__ = 'infrastructure_vlans'
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey('infrastructure_devices.id', ondelete='CASCADE'), nullable=False, index=True)
    site_id = Column(Integer, ForeignKey('network_sites.id', ondelete='SET NULL'), nullable=True, index=True)
    vlan_number = Column(Integer, nullable=False, index=True)
    vlan_name = Column(String, default="")
    status = Column(String, default="ACTIVE")
    tagged_ports_json = Column(String, default="[]")
    untagged_ports_json = Column(String, default="[]")
    trunk_ports_json = Column(String, default="[]")
    discovery_source = Column(String, default="SNMP_QBRIDGE")
    last_discovery = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint('device_id', 'vlan_number', name='uq_infra_vlan_dev_num'),
    )


class ConfigurationBackup(Base):
    __tablename__ = 'configuration_backups'
    id = Column(Integer, primary_key=True, autoincrement=True)
    backup_uid = Column(String, unique=True, nullable=False, index=True)
    device_id = Column(Integer, ForeignKey('infrastructure_devices.id', ondelete='SET NULL'), nullable=True, index=True)
    device_hostname = Column(String, default="")
    device_ip = Column(String, default="")
    device_model = Column(String, default="")
    firmware_version = Column(String, default="")
    vendor_adapter = Column(String, default="generic_ssh")
    backup_method = Column(String, default="SSH")
    file_path = Column(String, default="")
    is_encrypted = Column(Boolean, default=True)
    file_size_bytes = Column(Integer, default=0)
    sha256_checksum = Column(String, default="")
    status = Column(String, default="SUCCESS", index=True)  # SUCCESS, FAILED, VERIFIED, PRE_RESTORE
    error_detail = Column(String, default="")
    triggered_by = Column(String, default="manual")
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


class ConfigurationChange(Base):
    __tablename__ = 'configuration_changes'
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey('infrastructure_devices.id', ondelete='SET NULL'), nullable=True, index=True)
    previous_backup_id = Column(Integer, ForeignKey('configuration_backups.id', ondelete='SET NULL'), nullable=True)
    current_backup_id = Column(Integer, ForeignKey('configuration_backups.id', ondelete='SET NULL'), nullable=True)
    added_lines = Column(Integer, default=0)
    removed_lines = Column(Integer, default=0)
    changed_sections_json = Column(String, default="{}")
    diff_summary = Column(String, default="")
    unified_diff_redacted = Column(String, default="")
    detected_at = Column(DateTime, default=datetime.utcnow, index=True)


class InfrastructureAudit(Base):
    __tablename__ = 'infrastructure_audit'
    id = Column(Integer, primary_key=True, autoincrement=True)
    event_uid = Column(String, unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    username = Column(String, default="", index=True)
    site_id = Column(Integer, nullable=True, index=True)
    site_name = Column(String, default="")
    device_id = Column(Integer, nullable=True, index=True)
    device_name = Column(String, default="")
    device_ip = Column(String, default="")
    operation = Column(String, nullable=False, index=True)
    command_tier = Column(String, default="SYSTEM")  # READ_ONLY, MODIFYING, DESTRUCTIVE, SYSTEM
    previous_value_json = Column(String, default="{}")
    new_value_json = Column(String, default="{}")
    result = Column(String, default="SUCCESS", index=True)
    ticket_ref = Column(String, default="")
    detail = Column(String, default="")
    record_hash = Column(String, default="")

class DatabaseManager:
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            app_data = os.environ.get('LOCALAPPDATA', os.path.expanduser('~'))
            base_dir = os.path.join(app_data, 'BahaaIT')
            os.makedirs(base_dir, exist_ok=True)
            self.db_path = os.path.join(base_dir, "bahaait_network.db")
        else:
            self.db_path = db_path
            
        # Using connect_args={'check_same_thread': False} for multithreaded PySide6 compatibility
        engine_kwargs = {"connect_args": {'check_same_thread': False}}
        if self.db_path == ":memory:":
            engine_kwargs["poolclass"] = StaticPool
        self.engine = create_engine(f"sqlite:///{self.db_path}", **engine_kwargs)
        
        from sqlalchemy import event
        @event.listens_for(self.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA busy_timeout=5000")
            except Exception:
                pass
            finally:
                cursor.close()

        self._run_migrations()
        Base.metadata.create_all(self.engine)
        self._ensure_v360_triggers()
        self.Session = sessionmaker(bind=self.engine)
        
        
        # Nettoyage automatique des anciens logs (> 30 jours) au démarrage
        try:
            self.cleanup_old_logs(30)
        except Exception as e:
            print(f"DB Warning (initial log cleanup): {e}")

    def _run_migrations(self) -> None:
        """Apply safe, non-destructive schema migrations for existing SQLite databases."""
        try:
            with self.engine.begin() as conn:
                tables = {
                    row[0]
                    for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()
                }
                if "hosts" in tables:
                    cols = {
                        row[1]
                        for row in conn.execute(text("PRAGMA table_info(hosts)")).fetchall()
                    }
                    if "category" not in cols:
                        conn.execute(text("ALTER TABLE hosts ADD COLUMN category VARCHAR DEFAULT 'General'"))
                    if "profile" not in cols:
                        conn.execute(text("ALTER TABLE hosts ADD COLUMN profile VARCHAR DEFAULT 'Standard'"))
                    if "notes" not in cols:
                        conn.execute(text("ALTER TABLE hosts ADD COLUMN notes VARCHAR"))
        except Exception as e:
            print(f"DB Migration Warning: {e}")

    def _ensure_v360_triggers(self) -> None:
        """Install append-only immutability triggers on the infrastructure_audit table."""
        try:
            with self.engine.begin() as conn:
                conn.execute(text(
                    "CREATE TRIGGER IF NOT EXISTS trg_infra_audit_no_update "
                    "BEFORE UPDATE ON infrastructure_audit "
                    "BEGIN "
                    "SELECT RAISE(ABORT, 'Audit records are immutable and cannot be modified'); "
                    "END;"
                ))
                conn.execute(text(
                    "CREATE TRIGGER IF NOT EXISTS trg_infra_audit_no_delete "
                    "BEFORE DELETE ON infrastructure_audit "
                    "BEGIN "
                    "SELECT RAISE(ABORT, 'Audit records are immutable and cannot be deleted'); "
                    "END;"
                ))
        except Exception as e:
            print(f"DB Trigger Warning: {e}")

    def backup_database(self, dest_path: str) -> Tuple[bool, str]:
        """Safely create a consistent snapshot backup of the SQLite database."""
        if self.db_path == ":memory:":
            return False, "In-memory databases cannot be backed up via file path."
        try:
            dest_dir = os.path.dirname(os.path.abspath(dest_path))
            if dest_dir:
                os.makedirs(dest_dir, exist_ok=True)
            src_conn = sqlite3.connect(self.db_path)
            dst_conn = sqlite3.connect(dest_path)
            try:
                src_conn.backup(dst_conn)
            finally:
                dst_conn.close()
                src_conn.close()
            return True, dest_path
        except Exception as e:
            return False, str(e)

    def _init_default_global_services(self):
        default_services = [
            ("Apple Services", "https://www.apple.com/support/systemstatus/data/index.json"),
            ("Netflix", "https://help.netflix.com/en/is-netflix-down"),
            ("PlayStation Network", "https://status.playstation.com/fr-be/"),
            ("GitHub", "https://www.githubstatus.com/api/v2/status.json"),
            ("Discord", "https://discordstatus.com/api/v2/status.json"),
            ("Microsoft 365", "https://status.office.com"),
            ("AWS", "https://health.aws.amazon.com"),
            ("Google Cloud", "https://status.cloud.google.com"),
            ("WhatsApp", "https://www.whatsapp.com")
        ]
        
        with self.Session() as session:
            count = session.query(GlobalService).count()
            if count == 0:
                for name, url in default_services:
                    svc = GlobalService(name=name, url=url, is_custom=False)
                    session.add(svc)
                session.commit()

    def add_host(self, address: str, label: Optional[str] = None, category: str = "General", profile: str = "Standard", notes: Optional[str] = None) -> bool:
        try:
            with self.Session() as session:
                host = session.query(Host).filter_by(address=address).first()
                if host:
                    host.label = label
                    if category is not None:
                        host.category = category
                    if profile is not None:
                        host.profile = profile
                    if notes is not None:
                        host.notes = notes
                else:
                    new_host = Host(
                        address=address,
                        label=label,
                        category=category or "General",
                        profile=profile or "Standard",
                        notes=notes,
                    )
                    session.add(new_host)
                session.commit()
                return True
        except Exception as e:
            print(f"DB Error (add_host): {e}")
            return False

    def get_hosts(self) -> List[Dict[str, Any]]:
        with self.Session() as session:
            hosts = session.query(Host).all()
            return [
                {
                    "id": h.id,
                    "address": h.address,
                    "label": h.label,
                    "is_active": h.is_active,
                    "category": h.category or "General",
                    "profile": h.profile or "Standard",
                    "notes": h.notes,
                }
                for h in hosts
            ]

    def update_host_metadata(
        self,
        address: str,
        label: Optional[str] = None,
        category: Optional[str] = None,
        profile: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> bool:
        try:
            with self.Session() as session:
                host = session.query(Host).filter_by(address=address).first()
                if not host:
                    return False
                if label is not None:
                    host.label = label
                if category is not None:
                    host.category = category
                if profile is not None:
                    host.profile = profile
                if notes is not None:
                    host.notes = notes
                session.commit()
                return True
        except Exception as e:
            print(f"DB Error (update_host_metadata): {e}")
            return False

    def set_host_active(self, address: str, is_active: bool) -> bool:
        try:
            with self.Session() as session:
                host = session.query(Host).filter_by(address=address).first()
                if host:
                    host.is_active = bool(is_active)
                    session.commit()
                    return True
                return False
        except Exception as e:
            print(f"DB Error (set_host_active): {e}")
            return False

    def delete_host(self, address: str) -> None:
        with self.Session() as session:
            host = session.query(Host).filter_by(address=address).first()
            if host:
                # Preserve historical incidents, alerts, and measurements by detaching FK
                session.query(MonitoringIncident).filter_by(host_id=host.id).update({"host_id": None})
                session.query(AlertEvent).filter_by(host_id=host.id).update({"host_id": None})
                session.query(PingMeasurement).filter_by(host_id=host.id).update({"host_id": None})
                session.delete(host)
                session.commit()

    def clear_host_history(self, address: str) -> None:
        with self.Session() as session:
            host = session.query(Host).filter_by(address=address).first()
            if host:
                session.query(MonitoringLog).filter_by(host_id=host.id).delete()
                session.commit()

    def save_log(self, address: str, status: str, latency: int, response: Optional[str] = None) -> None:
        try:
            with self.Session() as session:
                host = session.query(Host).filter_by(address=address).first()
                if not host:
                    host = Host(address=address)
                    session.add(host)
                    session.flush() # To get the host.id immediately
                
                log = MonitoringLog(host_id=host.id, status=status, latency=latency, response=response)
                session.add(log)
                session.commit()
        except Exception as e:
            print(f"DB Error (save_log): {e}")

    def get_host_history(self, address: str, limit: int = 100) -> List[Dict[str, Any]]:
        with self.Session() as session:
            host = session.query(Host).filter_by(address=address).first()
            if not host:
                return []
            logs = session.query(MonitoringLog).filter_by(host_id=host.id).order_by(MonitoringLog.timestamp.desc()).limit(limit).all()
            return [{"timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "status": log.status, "latency": log.latency, "response": log.response} for log in logs]

    def get_uptime_stats(self, address: str, days: int = 30) -> Dict[str, Any]:
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        with self.Session() as session:
            host = session.query(Host).filter_by(address=address).first()
            if not host:
                return {"total": 0, "up": 0, "down": 0, "uptime_percent": 0.0, "avg_latency": 0.0}
            logs = (
                session.query(MonitoringLog)
                .filter(MonitoringLog.host_id == host.id, MonitoringLog.timestamp >= cutoff_date)
                .all()
            )
            total = len(logs)
            if total == 0:
                return {"total": 0, "up": 0, "down": 0, "uptime_percent": 0.0, "avg_latency": 0.0}
            up_logs = [log for log in logs if log.status == "UP"]
            up_count = len(up_logs)
            down_count = total - up_count
            uptime_percent = round((up_count / total) * 100.0, 2)
            avg_latency = round(sum(log.latency or 0 for log in up_logs) / up_count, 2) if up_count else 0.0
            return {
                "total": total,
                "up": up_count,
                "down": down_count,
                "uptime_percent": uptime_percent,
                "avg_latency": avg_latency
            }

    def save_speedtest(self, download: float, upload: float, ping: float, jitter: float, packet_loss: float, server: str, isp: str) -> None:
        try:
            with self.Session() as session:
                st = SpeedTestLog(
                    download=download, upload=upload, ping=ping, 
                    jitter=jitter, packet_loss=packet_loss, 
                    server=server, isp=isp
                )
                session.add(st)
                session.commit()
        except Exception as e:
            print(f"DB Error (save_speedtest): {e}")

    def get_speedtest_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self.Session() as session:
            tests = session.query(SpeedTestLog).order_by(SpeedTestLog.timestamp.desc()).limit(limit).all()
            return [
                {
                    "timestamp": t.timestamp.strftime("%Y-%m-%d %H:%M:%S"), 
                    "download": t.download, 
                    "upload": t.upload, 
                    "ping": t.ping, 
                    "jitter": t.jitter, 
                    "packet_loss": t.packet_loss, 
                    "server": t.server, 
                    "isp": t.isp
                } for t in tests
            ]

    def clear_speedtest_history(self) -> None:
        with self.Session() as session:
            session.query(SpeedTestLog).delete()
            session.commit()

    def cleanup_old_logs(self, days: int = 30) -> None:
        cutoff = datetime.utcnow() - timedelta(days=days)
        with self.Session() as session:
            session.query(MonitoringLog).filter(MonitoringLog.timestamp < cutoff).delete()
            session.query(GlobalServiceLog).filter(GlobalServiceLog.timestamp < cutoff).delete()
            session.commit()

    # --- Global Services Methods ---
    def get_global_services(self) -> List[Dict[str, Any]]:
        with self.Session() as session:
            services = session.query(GlobalService).all()
            return [{"id": s.id, "name": s.name, "url": s.url, "is_custom": s.is_custom} for s in services]

    def add_global_service(self, name: str, url: str, is_custom: bool = True) -> bool:
        try:
            with self.Session() as session:
                if session.query(GlobalService).filter_by(name=name).first():
                    return False # Already exists
                new_svc = GlobalService(name=name, url=url, is_custom=is_custom)
                session.add(new_svc)
                session.commit()
                return True
        except Exception as e:
            print(f"DB Error (add_global_service): {e}")
            return False

    def delete_global_service(self, service_id: int) -> None:
        with self.Session() as session:
            svc = session.query(GlobalService).filter_by(id=service_id, is_custom=True).first()
            if svc:
                session.delete(svc)
                session.commit()

    def log_global_service(self, service_id: int, status: str, latency: int) -> None:
        try:
            with self.Session() as session:
                log = GlobalServiceLog(service_id=service_id, status=status, latency=latency)
                session.add(log)
                session.commit()
        except Exception as e:
            print(f"DB Error (log_global_service): {e}")

    def get_global_service_history(self, service_id: int, limit: int = 20) -> List[Dict[str, Any]]:
        with self.Session() as session:
            logs = session.query(GlobalServiceLog).filter_by(service_id=service_id).order_by(GlobalServiceLog.timestamp.desc()).limit(limit).all()
            # Reverse to have chronological order for sparklines
            res = [{"status": log.status, "latency": log.latency, "timestamp": log.timestamp} for log in logs]
            res.reverse()
            return res

    def get_hosts_status_summary(self) -> Dict[str, int]:
        try:
            with self.Session() as session:
                from sqlalchemy import func
                active_hosts = session.query(Host).filter_by(is_active=True).all()
                total = len(active_hosts)
                if total == 0:
                    return {"total": 0, "up": 0, "down": 0}

                # Prefer latest PingMeasurement per active host address; fallback to MonitoringLog
                latest_pm_sub = session.query(
                    PingMeasurement.host_address,
                    func.max(PingMeasurement.timestamp).label("max_ts"),
                ).group_by(PingMeasurement.host_address).subquery()

                pm_rows = dict(
                    session.query(PingMeasurement.host_address, PingMeasurement.status)
                    .join(
                        latest_pm_sub,
                        (PingMeasurement.host_address == latest_pm_sub.c.host_address)
                        & (PingMeasurement.timestamp == latest_pm_sub.c.max_ts),
                    )
                    .all()
                )

                latest_log_sub = session.query(
                    MonitoringLog.host_id,
                    func.max(MonitoringLog.timestamp).label("max_ts"),
                ).group_by(MonitoringLog.host_id).subquery()

                log_rows = dict(
                    session.query(MonitoringLog.host_id, MonitoringLog.status)
                    .join(
                        latest_log_sub,
                        (MonitoringLog.host_id == latest_log_sub.c.host_id)
                        & (MonitoringLog.timestamp == latest_log_sub.c.max_ts),
                    )
                    .all()
                )

                up = 0
                for h in active_hosts:
                    st = pm_rows.get(h.address) or log_rows.get(h.id)
                    if st == "UP":
                        up += 1
                return {"total": total, "up": up, "down": total - up}
        except Exception as e:
            print(f"DB Error (get_hosts_status_summary): {e}")
            return {"total": 0, "up": 0, "down": 0}

    def get_services_status_summary(self) -> Dict[str, int]:
        try:
            with self.Session() as session:
                from sqlalchemy import func
                # Subquery to get the latest timestamp per service
                latest_sub = session.query(
                    GlobalServiceLog.service_id,
                    func.max(GlobalServiceLog.timestamp).label("max_ts")
                ).group_by(GlobalServiceLog.service_id).subquery()
                
                # Join to get status of global services' latest logs
                statuses = session.query(GlobalServiceLog.status).join(
                    GlobalService, GlobalService.id == GlobalServiceLog.service_id
                ).join(
                    latest_sub,
                    (GlobalServiceLog.service_id == latest_sub.c.service_id) &
                    (GlobalServiceLog.timestamp == latest_sub.c.max_ts)
                ).all()
                
                total = session.query(GlobalService).count()
                ok = sum(1 for (status,) in statuses if status == "UP")
                return {"total": total, "ok": ok}
        except Exception as e:
            print(f"DB Error (get_services_status_summary): {e}")
            return {"total": 0, "ok": 0}

    def get_average_latency(self) -> int:
        try:
            with self.Session() as session:
                from sqlalchemy import func
                active_hosts = session.query(Host).filter_by(is_active=True).all()
                if not active_hosts:
                    return 0

                latest_pm_sub = session.query(
                    PingMeasurement.host_address,
                    func.max(PingMeasurement.timestamp).label("max_ts"),
                ).group_by(PingMeasurement.host_address).subquery()

                pm_lats = dict(
                    session.query(PingMeasurement.host_address, PingMeasurement.latency_ms)
                    .join(
                        latest_pm_sub,
                        (PingMeasurement.host_address == latest_pm_sub.c.host_address)
                        & (PingMeasurement.timestamp == latest_pm_sub.c.max_ts),
                    )
                    .filter(PingMeasurement.status == "UP", PingMeasurement.latency_ms > 0)
                    .all()
                )
                if pm_lats:
                    active_addrs = {h.address for h in active_hosts}
                    vals = [v for addr, v in pm_lats.items() if addr in active_addrs and v is not None]
                    if vals:
                        return int(sum(vals) / len(vals))

                latest_sub = session.query(
                    MonitoringLog.host_id,
                    func.max(MonitoringLog.timestamp).label("max_ts")
                ).group_by(MonitoringLog.host_id).subquery()
                
                latencies = session.query(MonitoringLog.latency).join(
                    Host, Host.id == MonitoringLog.host_id
                ).join(
                    latest_sub,
                    (MonitoringLog.host_id == latest_sub.c.host_id) &
                    (MonitoringLog.timestamp == latest_sub.c.max_ts)
                ).filter(Host.is_active == True, MonitoringLog.status == "UP", MonitoringLog.latency > 0).all()
                
                if not latencies:
                    return 0
                vals = [l for (l,) in latencies]
                return int(sum(vals) / len(vals))
        except Exception as e:
            print(f"DB Error (get_average_latency): {e}")
            return 0

    def get_latest_alerts(self, limit: int = 5) -> List[Dict[str, Any]]:
        try:
            with self.Session() as session:
                from sqlalchemy.orm import joinedload
                alerts = []

                evt_rows = (
                    session.query(AlertEvent)
                    .order_by(AlertEvent.timestamp.desc())
                    .limit(limit * 3)
                    .all()
                )
                for evt in evt_rows:
                    alerts.append({
                        "timestamp": evt.timestamp.strftime("%H:%M"),
                        "host": evt.host_name or evt.host_address,
                        "status": "UP" if evt.event_type == "HOST_RECOVERED" else evt.severity,
                        "time_obj": evt.timestamp,
                    })

                if len(alerts) < limit:
                    logs = session.query(MonitoringLog).options(
                        joinedload(MonitoringLog.host)
                    ).join(Host).order_by(MonitoringLog.timestamp.desc()).limit(200).all()
                    
                    host_last_status = {}
                    ordered_logs = list(reversed(logs))
                    for log in ordered_logs:
                        host_addr = log.host.address
                        host_label = log.host.label or host_addr
                        prev_status = host_last_status.get(host_addr)
                        if prev_status is not None and prev_status != log.status:
                            alerts.append({
                                "timestamp": log.timestamp.strftime("%H:%M"),
                                "host": host_label,
                                "status": log.status,
                                "time_obj": log.timestamp
                            })
                        elif prev_status is None and log.status == "DOWN":
                            alerts.append({
                                "timestamp": log.timestamp.strftime("%H:%M"),
                                "host": host_label,
                                "status": log.status,
                                "time_obj": log.timestamp
                            })
                        host_last_status[host_addr] = log.status
                
                alerts.sort(key=lambda x: x["time_obj"], reverse=True)
                return alerts[:limit]
        except Exception as e:
            print(f"DB Error (get_latest_alerts): {e}")
            return []

    def get_latest_speedtest(self) -> Optional[Dict[str, Any]]:
        try:
            with self.Session() as session:
                t = session.query(SpeedTestLog).order_by(SpeedTestLog.timestamp.desc()).first()
                if t:
                    diff = datetime.utcnow() - t.timestamp
                    if diff.days > 0:
                        time_str = f"il y a {diff.days}j"
                    elif diff.seconds >= 3600:
                        time_str = f"il y a {diff.seconds // 3600}h"
                    elif diff.seconds >= 60:
                        time_str = f"il y a {diff.seconds // 60}m"
                    else:
                        time_str = "à l'instant"
                    return {
                        "download": t.download,
                        "upload": t.upload,
                        "time_str": time_str
                    }
                return None
        except Exception as e:
            print(f"DB Error (get_latest_speedtest): {e}")
            return None

    # --- Intelligent Ping Monitoring Methods (v3.4.0) ---

    def save_measurements_batch(self, measurements: List[Dict[str, Any]]) -> int:
        """Persist a batch of PingMeasurement records in a single transaction."""
        if not measurements:
            return 0
        try:
            with self.Session() as session:
                addr_to_id = {h.address: h.id for h in session.query(Host.id, Host.address).all()}
                rows = []
                for m in measurements:
                    addr = m["host_address"]
                    rows.append({
                        "host_id": m.get("host_id") if m.get("host_id") is not None else addr_to_id.get(addr),
                        "host_address": addr,
                        "timestamp": m.get("timestamp") or datetime.utcnow(),
                        "status": m["status"],
                        "latency_ms": m.get("latency_ms"),
                        "is_valid_probe": bool(m.get("is_valid_probe", True)),
                        "error_type": m.get("error_type"),
                        "detail": m.get("detail"),
                    })
                session.bulk_insert_mappings(PingMeasurement, rows)
                session.commit()
                return len(rows)
        except Exception as e:
            print(f"DB Error (save_measurements_batch): {e}")
            return 0

    def get_measurements(
        self,
        address: str,
        since: Optional[datetime] = None,
        limit: int = 2000,
    ) -> List[Dict[str, Any]]:
        with self.Session() as session:
            q = session.query(PingMeasurement).filter(PingMeasurement.host_address == address)
            if since is not None:
                q = q.filter(PingMeasurement.timestamp >= since)
            logs = q.order_by(PingMeasurement.timestamp.desc()).limit(limit).all()
            logs.reverse()
            return [
                {
                    "id": row.id,
                    "host_id": row.host_id,
                    "host_address": row.host_address,
                    "timestamp": row.timestamp,
                    "status": row.status,
                    "latency_ms": row.latency_ms,
                    "is_valid_probe": row.is_valid_probe,
                    "error_type": row.error_type,
                    "detail": row.detail,
                }
                for row in logs
            ]

    def save_statistics_batch(self, rows: List[Dict[str, Any]]) -> int:
        if not rows:
            return 0
        try:
            with self.Session() as session:
                session.bulk_insert_mappings(MonitoringStatistics, rows)
                session.commit()
                return len(rows)
        except Exception as e:
            print(f"DB Error (save_statistics_batch): {e}")
            return 0

    def get_statistics(
        self,
        address: str,
        granularity: str,
        since: Optional[datetime] = None,
        limit: int = 2000,
    ) -> List[Dict[str, Any]]:
        with self.Session() as session:
            q = session.query(MonitoringStatistics).filter(
                MonitoringStatistics.host_address == address,
                MonitoringStatistics.granularity == granularity,
            )
            if since is not None:
                q = q.filter(MonitoringStatistics.bucket_start >= since)
            rows = q.order_by(MonitoringStatistics.bucket_start.asc()).limit(limit).all()
            return [
                {
                    "host_address": r.host_address,
                    "bucket_start": r.bucket_start,
                    "granularity": r.granularity,
                    "total_probes": r.total_probes,
                    "valid_probes": r.valid_probes,
                    "failed_probes": r.failed_probes,
                    "packet_loss_pct": r.packet_loss_pct,
                    "min_latency_ms": r.min_latency_ms,
                    "avg_latency_ms": r.avg_latency_ms,
                    "max_latency_ms": r.max_latency_ms,
                    "p95_latency_ms": r.p95_latency_ms,
                    "jitter_ms": r.jitter_ms,
                    "uptime_pct": r.uptime_pct,
                }
                for r in rows
            ]

    @staticmethod
    def _policy_to_dict(p: MonitoringPolicy) -> Dict[str, Any]:
        return {
            "id": p.id,
            "host_id": p.host_id,
            "probe_interval_ms": p.probe_interval_ms,
            "timeout_ms": p.timeout_ms,
            "warning_failures": p.warning_failures,
            "critical_failures": p.critical_failures,
            "recovery_successes": p.recovery_successes,
            "rolling_window_sec": p.rolling_window_sec,
            "packet_loss_warn_pct": p.packet_loss_warn_pct,
            "latency_warn_ms": p.latency_warn_ms,
            "jitter_warn_ms": p.jitter_warn_ms,
            "sound_enabled": p.sound_enabled,
            "email_enabled": p.email_enabled,
            "windows_notify_enabled": p.windows_notify_enabled,
            "repeat_alert_interval_sec": p.repeat_alert_interval_sec,
            "updated_at": p.updated_at,
        }

    def get_policy(self, host_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        with self.Session() as session:
            if host_id is None:
                policy = session.query(MonitoringPolicy).filter(MonitoringPolicy.host_id.is_(None)).first()
            else:
                policy = session.query(MonitoringPolicy).filter(MonitoringPolicy.host_id == host_id).first()
            return self._policy_to_dict(policy) if policy else None

    def save_policy(self, data: Dict[str, Any], host_id: Optional[int] = None) -> bool:
        try:
            with self.Session() as session:
                if host_id is None:
                    policy = session.query(MonitoringPolicy).filter(MonitoringPolicy.host_id.is_(None)).first()
                else:
                    policy = session.query(MonitoringPolicy).filter(MonitoringPolicy.host_id == host_id).first()

                if policy is None:
                    policy = MonitoringPolicy(host_id=host_id)
                    session.add(policy)

                fields = (
                    "probe_interval_ms",
                    "timeout_ms",
                    "warning_failures",
                    "critical_failures",
                    "recovery_successes",
                    "rolling_window_sec",
                    "packet_loss_warn_pct",
                    "latency_warn_ms",
                    "jitter_warn_ms",
                    "sound_enabled",
                    "email_enabled",
                    "windows_notify_enabled",
                    "repeat_alert_interval_sec",
                )
                for f in fields:
                    if f in data:
                        setattr(policy, f, data[f])
                policy.updated_at = datetime.utcnow()
                session.commit()
                return True
        except Exception as e:
            print(f"DB Error (save_policy): {e}")
            return False

    def delete_host_policy(self, host_id: int) -> bool:
        try:
            with self.Session() as session:
                policy = session.query(MonitoringPolicy).filter(MonitoringPolicy.host_id == host_id).first()
                if policy:
                    session.delete(policy)
                    session.commit()
                return True
        except Exception as e:
            print(f"DB Error (delete_host_policy): {e}")
            return False

    @staticmethod
    def _incident_to_dict(inc: MonitoringIncident) -> Dict[str, Any]:
        return {
            "id": inc.id,
            "incident_uid": inc.incident_uid,
            "host_id": inc.host_id,
            "host_name": inc.host_name,
            "host_address": inc.host_address,
            "incident_type": inc.incident_type,
            "severity": inc.severity,
            "start_time": inc.start_time,
            "end_time": inc.end_time,
            "duration_seconds": inc.duration_seconds,
            "failed_probes": inc.failed_probes,
            "packet_loss_pct": inc.packet_loss_pct,
            "avg_latency_before_ms": inc.avg_latency_before_ms,
            "recovery_latency_ms": inc.recovery_latency_ms,
            "status": inc.status,
            "acknowledged": inc.acknowledged,
            "acknowledged_at": inc.acknowledged_at,
            "comments": inc.comments or "",
        }

    def create_incident(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.Session() as session:
            inc = MonitoringIncident(
                incident_uid=data["incident_uid"],
                host_id=data.get("host_id"),
                host_name=data["host_name"],
                host_address=data["host_address"],
                incident_type=data["incident_type"],
                severity=data["severity"],
                start_time=data.get("start_time") or datetime.utcnow(),
                end_time=data.get("end_time"),
                duration_seconds=float(data.get("duration_seconds", 0.0)),
                failed_probes=int(data.get("failed_probes", 0)),
                packet_loss_pct=float(data.get("packet_loss_pct", 0.0)),
                avg_latency_before_ms=float(data.get("avg_latency_before_ms", 0.0)),
                recovery_latency_ms=data.get("recovery_latency_ms"),
                status=data.get("status", "DETECTED"),
                acknowledged=bool(data.get("acknowledged", False)),
                acknowledged_at=data.get("acknowledged_at"),
                comments=data.get("comments", ""),
            )
            session.add(inc)
            session.commit()
            session.refresh(inc)
            return self._incident_to_dict(inc)

    def update_incident(self, incident_id: int, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self.Session() as session:
            inc = session.query(MonitoringIncident).filter_by(id=incident_id).first()
            if not inc:
                return None
            for k, v in updates.items():
                if hasattr(inc, k) and k != "id":
                    setattr(inc, k, v)
            session.commit()
            session.refresh(inc)
            return self._incident_to_dict(inc)

    def delete_incident(self, incident_id: int) -> bool:
        try:
            with self.Session() as session:
                inc = session.query(MonitoringIncident).filter_by(id=incident_id).first()
                if not inc:
                    return False
                session.query(AlertEvent).filter(
                    AlertEvent.incident_id == incident_id
                ).update({"incident_id": None}, synchronize_session=False)
                session.delete(inc)
                session.commit()
                return True
        except Exception as e:
            print(f"DB Error (delete_incident): {e}")
            return False

    def get_incident_by_id(self, incident_id: int) -> Optional[Dict[str, Any]]:
        with self.Session() as session:
            inc = session.query(MonitoringIncident).filter_by(id=incident_id).first()
            return self._incident_to_dict(inc) if inc else None

    def get_active_incident(self, host_address: str) -> Optional[Dict[str, Any]]:
        with self.Session() as session:
            inc = (
                session.query(MonitoringIncident)
                .filter(
                    MonitoringIncident.host_address == host_address,
                    MonitoringIncident.status.in_(["DETECTED", "ACKNOWLEDGED"]),
                )
                .order_by(MonitoringIncident.start_time.desc())
                .first()
            )
            return self._incident_to_dict(inc) if inc else None

    def get_incidents(
        self,
        severity: Optional[str] = None,
        host_address: Optional[str] = None,
        status: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        with self.Session() as session:
            q = session.query(MonitoringIncident)
            if severity:
                q = q.filter(MonitoringIncident.severity == severity)
            if host_address:
                q = q.filter(MonitoringIncident.host_address == host_address)
            if status:
                q = q.filter(MonitoringIncident.status == status)
            if start_date:
                q = q.filter(MonitoringIncident.start_time >= start_date)
            if end_date:
                q = q.filter(MonitoringIncident.start_time <= end_date)
            rows = q.order_by(MonitoringIncident.start_time.desc()).limit(limit).all()
            return [self._incident_to_dict(r) for r in rows]

    def save_alert_event(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.Session() as session:
            evt = AlertEvent(
                timestamp=data.get("timestamp") or datetime.utcnow(),
                host_id=data.get("host_id"),
                host_address=data["host_address"],
                host_name=data.get("host_name"),
                incident_id=data.get("incident_id"),
                severity=data["severity"],
                event_type=data["event_type"],
                message=data["message"],
                channel=data.get("channel", "SYSTEM"),
                delivered=bool(data.get("delivered", True)),
                error_detail=data.get("error_detail"),
            )
            session.add(evt)
            session.commit()
            session.refresh(evt)
            return {
                "id": evt.id,
                "timestamp": evt.timestamp,
                "host_id": evt.host_id,
                "host_address": evt.host_address,
                "host_name": evt.host_name,
                "incident_id": evt.incident_id,
                "severity": evt.severity,
                "event_type": evt.event_type,
                "message": evt.message,
                "channel": evt.channel,
                "delivered": evt.delivered,
                "error_detail": evt.error_detail,
            }

    def get_alert_events(
        self,
        severity: Optional[str] = None,
        host_address: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        with self.Session() as session:
            q = session.query(AlertEvent)
            if severity:
                q = q.filter(AlertEvent.severity == severity)
            if host_address:
                q = q.filter(AlertEvent.host_address == host_address)
            rows = q.order_by(AlertEvent.timestamp.desc()).limit(limit).all()
            return [
                {
                    "id": evt.id,
                    "timestamp": evt.timestamp,
                    "host_id": evt.host_id,
                    "host_address": evt.host_address,
                    "host_name": evt.host_name,
                    "incident_id": evt.incident_id,
                    "severity": evt.severity,
                    "event_type": evt.event_type,
                    "message": evt.message,
                    "channel": evt.channel,
                    "delivered": evt.delivered,
                    "error_detail": evt.error_detail,
                }
                for evt in rows
            ]

    def cleanup_by_retention(
        self,
        raw_days: int = 7,
        aggregated_days: int = 90,
        incidents_days: int = 365,
        alerts_days: int = 365,
        snmp_raw_days: int = 7,
        snmp_aggregated_days: int = 90,
        syslog_days: int = 30,
        anomalies_days: int = 365,
    ) -> Dict[str, int]:
        now = datetime.utcnow()
        deleted = {
            "raw": 0,
            "aggregated": 0,
            "incidents": 0,
            "alerts": 0,
            "snmp_raw": 0,
            "snmp_aggregated": 0,
            "interface_measurements": 0,
            "syslog": 0,
            "anomalies": 0,
        }
        try:
            with self.Session() as session:
                deleted["raw"] = (
                    session.query(PingMeasurement)
                    .filter(PingMeasurement.timestamp < now - timedelta(days=raw_days))
                    .delete()
                )
                deleted["aggregated"] = (
                    session.query(MonitoringStatistics)
                    .filter(MonitoringStatistics.bucket_start < now - timedelta(days=aggregated_days))
                    .delete()
                )
                deleted["incidents"] = (
                    session.query(MonitoringIncident)
                    .filter(
                        MonitoringIncident.start_time < now - timedelta(days=incidents_days),
                        MonitoringIncident.status.in_(["RECOVERED", "CLOSED"]),
                    )
                    .delete(synchronize_session=False)
                )
                deleted["alerts"] = (
                    session.query(AlertEvent)
                    .filter(AlertEvent.timestamp < now - timedelta(days=alerts_days))
                    .delete()
                )
                deleted["snmp_raw"] = (
                    session.query(SNMPMetric)
                    .filter(SNMPMetric.timestamp < now - timedelta(days=snmp_raw_days))
                    .delete()
                )
                deleted["snmp_aggregated"] = (
                    session.query(SNMPMetricAggregated)
                    .filter(SNMPMetricAggregated.bucket_start < now - timedelta(days=snmp_aggregated_days))
                    .delete()
                )
                deleted["interface_measurements"] = (
                    session.query(InterfaceMeasurement)
                    .filter(InterfaceMeasurement.timestamp < now - timedelta(days=snmp_raw_days))
                    .delete()
                )
                deleted["syslog"] = (
                    session.query(SyslogEvent)
                    .filter(SyslogEvent.timestamp < now - timedelta(days=syslog_days))
                    .delete()
                )
                deleted["anomalies"] = (
                    session.query(NetworkAnomaly)
                    .filter(
                        NetworkAnomaly.detected_at < now - timedelta(days=anomalies_days),
                        NetworkAnomaly.status == "RESOLVED",
                    )
                    .delete(synchronize_session=False)
                )
                session.commit()
        except Exception as e:
            print(f"DB Error (cleanup_by_retention): {e}")
        return deleted

    # ══════════════════════════════════════════════════════════════════════════
    # v3.5.0 NETWORK INTELLIGENCE (SNMP, Interfaces, VLANs, Syslog, Anomalies)
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def _snmp_device_to_dict(d: SNMPDevice) -> Dict[str, Any]:
        try:
            caps = json.loads(d.capabilities_json or "{}")
        except Exception:
            caps = {}
        try:
            thresh = json.loads(d.thresholds_json or "{}")
        except Exception:
            thresh = {}
        return {
            "id": d.id,
            "name": d.name,
            "ip_address": d.ip_address,
            "port": d.port,
            "snmp_version": d.snmp_version,
            "encrypted_credentials": d.encrypted_credentials,
            "vendor": d.vendor or "Generic",
            "model": d.model or "",
            "firmware": d.firmware or "",
            "device_type": d.device_type or "Network Device",
            "profile_name": d.profile_name or "generic_switch",
            "sys_descr": d.sys_descr or "",
            "sys_object_id": d.sys_object_id or "",
            "sys_name": d.sys_name or "",
            "sys_location": d.sys_location or "",
            "location": d.location or d.sys_location or "",
            "status": d.status or "UNKNOWN",
            "enabled": bool(d.enabled),
            "anomaly_detection_enabled": bool(d.anomaly_detection_enabled),
            "timeout_sec": float(d.timeout_sec or 2.0),
            "retries": int(d.retries if d.retries is not None else 1),
            "poll_interval_sec": int(d.poll_interval_sec or 30),
            "temp_interval_sec": int(d.temp_interval_sec or 60),
            "poe_interval_sec": int(d.poe_interval_sec or 60),
            "sysinfo_interval_sec": int(d.sysinfo_interval_sec or 300),
            "capabilities": caps,
            "thresholds": thresh,
            "last_uptime_ticks": d.last_uptime_ticks,
            "last_reboot_at": d.last_reboot_at,
            "last_poll": d.last_poll,
            "created_at": d.created_at,
        }

    def add_snmp_device(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            with self.Session() as session:
                existing = session.query(SNMPDevice).filter_by(ip_address=data["ip_address"]).first()
                if existing is not None:
                    return None
                dev = SNMPDevice(
                    name=data.get("name") or data["ip_address"],
                    ip_address=data["ip_address"],
                    port=int(data.get("port", 161)),
                    snmp_version=data.get("snmp_version", "v2c"),
                    encrypted_credentials=data["encrypted_credentials"],
                    vendor=data.get("vendor", "Generic"),
                    model=data.get("model", ""),
                    firmware=data.get("firmware", ""),
                    device_type=data.get("device_type", "Network Device"),
                    profile_name=data.get("profile_name", "generic_switch"),
                    sys_descr=data.get("sys_descr", ""),
                    sys_object_id=data.get("sys_object_id", ""),
                    sys_name=data.get("sys_name", ""),
                    sys_location=data.get("sys_location", ""),
                    location=data.get("location", ""),
                    status=data.get("status", "UNKNOWN"),
                    enabled=bool(data.get("enabled", True)),
                    anomaly_detection_enabled=bool(data.get("anomaly_detection_enabled", True)),
                    timeout_sec=float(data.get("timeout_sec", 2.0)),
                    retries=int(data.get("retries", 1)),
                    poll_interval_sec=int(data.get("poll_interval_sec", 30)),
                    temp_interval_sec=int(data.get("temp_interval_sec", 60)),
                    poe_interval_sec=int(data.get("poe_interval_sec", 60)),
                    sysinfo_interval_sec=int(data.get("sysinfo_interval_sec", 300)),
                    capabilities_json=json.dumps(data.get("capabilities", {})),
                    thresholds_json=json.dumps(data.get("thresholds", {})),
                    last_uptime_ticks=data.get("last_uptime_ticks"),
                    last_reboot_at=data.get("last_reboot_at"),
                    last_poll=data.get("last_poll"),
                )
                session.add(dev)
                session.commit()
                session.refresh(dev)
                return self._snmp_device_to_dict(dev)
        except Exception as e:
            print(f"DB Error (add_snmp_device): {e}")
            return None

    def update_snmp_device(self, device_id: int, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            with self.Session() as session:
                dev = session.query(SNMPDevice).filter_by(id=device_id).first()
                if not dev:
                    return None
                for k, v in updates.items():
                    if k == "capabilities":
                        dev.capabilities_json = json.dumps(v or {})
                    elif k == "thresholds":
                        dev.thresholds_json = json.dumps(v or {})
                    elif hasattr(dev, k) and k != "id":
                        setattr(dev, k, v)
                session.commit()
                session.refresh(dev)
                return self._snmp_device_to_dict(dev)
        except Exception as e:
            print(f"DB Error (update_snmp_device): {e}")
            return None

    def get_snmp_device(self, device_id: int) -> Optional[Dict[str, Any]]:
        with self.Session() as session:
            dev = session.query(SNMPDevice).filter_by(id=device_id).first()
            return self._snmp_device_to_dict(dev) if dev else None

    def get_snmp_device_by_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        with self.Session() as session:
            dev = session.query(SNMPDevice).filter_by(ip_address=ip_address).first()
            return self._snmp_device_to_dict(dev) if dev else None

    def get_snmp_devices(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        with self.Session() as session:
            q = session.query(SNMPDevice)
            if enabled_only:
                q = q.filter(SNMPDevice.enabled == True)
            rows = q.order_by(SNMPDevice.name.asc()).all()
            return [self._snmp_device_to_dict(r) for r in rows]

    def delete_snmp_device(self, device_id: int) -> bool:
        try:
            with self.Session() as session:
                dev = session.query(SNMPDevice).filter_by(id=device_id).first()
                if not dev:
                    return False
                session.query(NetworkAnomaly).filter(
                    NetworkAnomaly.device_id == device_id
                ).update({"device_id": None}, synchronize_session=False)
                session.delete(dev)
                session.commit()
                return True
        except Exception as e:
            print(f"DB Error (delete_snmp_device): {e}")
            return False

    def save_snmp_metrics_batch(self, items: List[Dict[str, Any]]) -> int:
        if not items:
            return 0
        try:
            with self.Session() as session:
                objs = [
                    SNMPMetric(
                        device_id=it["device_id"],
                        metric_name=it["metric_name"],
                        metric_value=float(it["metric_value"]),
                        unit=it.get("unit", ""),
                        sensor_label=it.get("sensor_label"),
                        timestamp=it.get("timestamp") or datetime.utcnow(),
                    )
                    for it in items
                ]
                session.add_all(objs)
                session.commit()
                return len(objs)
        except Exception as e:
            print(f"DB Error (save_snmp_metrics_batch): {e}")
            return 0

    def get_snmp_metrics(
        self,
        device_id: int,
        metric_name: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        with self.Session() as session:
            q = session.query(SNMPMetric).filter(SNMPMetric.device_id == device_id)
            if metric_name:
                q = q.filter(SNMPMetric.metric_name == metric_name)
            if since:
                q = q.filter(SNMPMetric.timestamp >= since)
            rows = q.order_by(SNMPMetric.timestamp.desc()).limit(limit).all()
            return [
                {
                    "id": r.id,
                    "device_id": r.device_id,
                    "metric_name": r.metric_name,
                    "metric_value": r.metric_value,
                    "unit": r.unit,
                    "sensor_label": r.sensor_label,
                    "timestamp": r.timestamp,
                }
                for r in reversed(rows)
            ]

    def aggregate_snmp_metrics(self, granularity: str = "hourly", since: Optional[datetime] = None) -> int:
        cutoff = since or (datetime.utcnow() - timedelta(days=7))
        inserted = 0
        try:
            with self.Session() as session:
                rows = (
                    session.query(SNMPMetric)
                    .filter(SNMPMetric.timestamp >= cutoff)
                    .all()
                )
                buckets: Dict[tuple, List[float]] = {}
                for r in rows:
                    if granularity == "daily":
                        b_start = r.timestamp.replace(hour=0, minute=0, second=0, microsecond=0)
                    else:
                        b_start = r.timestamp.replace(minute=0, second=0, microsecond=0)
                    key = (r.device_id, r.metric_name, b_start)
                    buckets.setdefault(key, []).append(float(r.metric_value))

                for (dev_id, m_name, b_start), vals in buckets.items():
                    existing = (
                        session.query(SNMPMetricAggregated)
                        .filter_by(
                            device_id=dev_id,
                            metric_name=m_name,
                            granularity=granularity,
                            bucket_start=b_start,
                        )
                        .first()
                    )
                    min_v = round(min(vals), 3)
                    avg_v = round(sum(vals) / len(vals), 3)
                    max_v = round(max(vals), 3)
                    if existing is None:
                        session.add(
                            SNMPMetricAggregated(
                                device_id=dev_id,
                                metric_name=m_name,
                                granularity=granularity,
                                bucket_start=b_start,
                                min_value=min_v,
                                avg_value=avg_v,
                                max_value=max_v,
                                sample_count=len(vals),
                            )
                        )
                    else:
                        existing.min_value = min_v
                        existing.avg_value = avg_v
                        existing.max_value = max_v
                        existing.sample_count = len(vals)
                    inserted += 1
                session.commit()
        except Exception as e:
            print(f"DB Error (aggregate_snmp_metrics): {e}")
        return inserted

    def get_aggregated_snmp_metrics(
        self,
        device_id: int,
        metric_name: Optional[str] = None,
        granularity: str = "hourly",
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        with self.Session() as session:
            q = session.query(SNMPMetricAggregated).filter(
                SNMPMetricAggregated.device_id == device_id,
                SNMPMetricAggregated.granularity == granularity,
            )
            if metric_name:
                q = q.filter(SNMPMetricAggregated.metric_name == metric_name)
            if since:
                q = q.filter(SNMPMetricAggregated.bucket_start >= since)
            rows = q.order_by(SNMPMetricAggregated.bucket_start.asc()).all()
            return [
                {
                    "id": r.id,
                    "device_id": r.device_id,
                    "metric_name": r.metric_name,
                    "granularity": r.granularity,
                    "bucket_start": r.bucket_start,
                    "min_value": r.min_value,
                    "avg_value": r.avg_value,
                    "max_value": r.max_value,
                    "sample_count": r.sample_count,
                }
                for r in rows
            ]

    def upsert_snmp_interfaces(self, device_id: int, interfaces: List[Dict[str, Any]]) -> Dict[int, int]:
        """Insert or update SNMP interfaces for a device; returns {if_index: interface_db_id}."""
        id_map: Dict[int, int] = {}
        try:
            with self.Session() as session:
                existing_rows = session.query(SNMPInterface).filter_by(device_id=device_id).all()
                by_idx = {row.if_index: row for row in existing_rows}
                now = datetime.utcnow()
                for item in interfaces:
                    idx = int(item["if_index"])
                    row = by_idx.get(idx)
                    if row is None:
                        row = SNMPInterface(device_id=device_id, if_index=idx)
                        session.add(row)
                        by_idx[idx] = row
                    row.name = item.get("name", row.name or "")
                    row.description = item.get("description", row.description or "")
                    row.alias = item.get("alias", row.alias or "")
                    row.mac_address = item.get("mac_address", row.mac_address or "")
                    row.admin_status = item.get("admin_status", row.admin_status or "UNKNOWN")
                    row.oper_status = item.get("oper_status", row.oper_status or "UNKNOWN")
                    row.speed_bps = int(item.get("speed_bps", row.speed_bps or 0))
                    if "negotiated_speed_mbps" in item:
                        row.negotiated_speed_mbps = item["negotiated_speed_mbps"]
                    if "last_change_ticks" in item:
                        row.last_change_ticks = item["last_change_ticks"]
                    if "last_change_at" in item:
                        row.last_change_at = item["last_change_at"]
                    row.updated_at = now
                session.flush()
                for idx, row in by_idx.items():
                    id_map[idx] = row.id
                session.commit()
        except Exception as e:
            print(f"DB Error (upsert_snmp_interfaces): {e}")
        return id_map

    def get_snmp_interfaces(self, device_id: int) -> List[Dict[str, Any]]:
        with self.Session() as session:
            rows = (
                session.query(SNMPInterface)
                .filter(SNMPInterface.device_id == device_id)
                .order_by(SNMPInterface.if_index.asc())
                .all()
            )
            return [
                {
                    "id": r.id,
                    "device_id": r.device_id,
                    "if_index": r.if_index,
                    "name": r.name or "",
                    "description": r.description or "",
                    "alias": r.alias or "",
                    "mac_address": r.mac_address or "",
                    "admin_status": r.admin_status or "UNKNOWN",
                    "oper_status": r.oper_status or "UNKNOWN",
                    "speed_bps": r.speed_bps or 0,
                    "negotiated_speed_mbps": r.negotiated_speed_mbps,
                    "last_change_ticks": r.last_change_ticks,
                    "last_change_at": r.last_change_at,
                    "updated_at": r.updated_at,
                }
                for r in rows
            ]

    def save_interface_measurements_batch(self, items: List[Dict[str, Any]]) -> int:
        if not items:
            return 0
        try:
            with self.Session() as session:
                objs = [
                    InterfaceMeasurement(
                        interface_id=it["interface_id"],
                        device_id=it["device_id"],
                        in_mbps=float(it.get("in_mbps", 0.0)),
                        out_mbps=float(it.get("out_mbps", 0.0)),
                        utilization_pct=float(it.get("utilization_pct", 0.0)),
                        in_errors=int(it.get("in_errors", 0)),
                        out_errors=int(it.get("out_errors", 0)),
                        in_discards=int(it.get("in_discards", 0)),
                        out_discards=int(it.get("out_discards", 0)),
                        crc_errors=int(it.get("crc_errors", 0)),
                        oper_status=it.get("oper_status", "UNKNOWN"),
                        timestamp=it.get("timestamp") or datetime.utcnow(),
                    )
                    for it in items
                ]
                session.add_all(objs)
                session.commit()
                return len(objs)
        except Exception as e:
            print(f"DB Error (save_interface_measurements_batch): {e}")
            return 0

    def get_interface_measurements(
        self,
        interface_id: Optional[int] = None,
        device_id: Optional[int] = None,
        since: Optional[datetime] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        with self.Session() as session:
            q = session.query(InterfaceMeasurement)
            if interface_id is not None:
                q = q.filter(InterfaceMeasurement.interface_id == interface_id)
            if device_id is not None:
                q = q.filter(InterfaceMeasurement.device_id == device_id)
            if since is not None:
                q = q.filter(InterfaceMeasurement.timestamp >= since)
            rows = q.order_by(InterfaceMeasurement.timestamp.desc()).limit(limit).all()
            return [
                {
                    "id": r.id,
                    "interface_id": r.interface_id,
                    "device_id": r.device_id,
                    "in_mbps": r.in_mbps,
                    "out_mbps": r.out_mbps,
                    "utilization_pct": r.utilization_pct,
                    "in_errors": r.in_errors,
                    "out_errors": r.out_errors,
                    "in_discards": r.in_discards,
                    "out_discards": r.out_discards,
                    "crc_errors": r.crc_errors,
                    "oper_status": r.oper_status,
                    "timestamp": r.timestamp,
                }
                for r in reversed(rows)
            ]

    def upsert_snmp_vlans(self, device_id: int, vlans: List[Dict[str, Any]]) -> None:
        try:
            with self.Session() as session:
                session.query(SNMPVlan).filter(SNMPVlan.device_id == device_id).delete()
                now = datetime.utcnow()
                for v in vlans:
                    session.add(
                        SNMPVlan(
                            device_id=device_id,
                            vlan_id=int(v["vlan_id"]),
                            name=v.get("name", ""),
                            status=v.get("status", "ACTIVE"),
                            tagged_ports_json=json.dumps(v.get("tagged_ports", [])),
                            untagged_ports_json=json.dumps(v.get("untagged_ports", [])),
                            trunk_ports_json=json.dumps(v.get("trunk_ports", [])),
                            updated_at=now,
                        )
                    )
                session.commit()
        except Exception as e:
            print(f"DB Error (upsert_snmp_vlans): {e}")

    def get_snmp_vlans(self, device_id: int) -> List[Dict[str, Any]]:
        with self.Session() as session:
            rows = (
                session.query(SNMPVlan)
                .filter(SNMPVlan.device_id == device_id)
                .order_by(SNMPVlan.vlan_id.asc())
                .all()
            )
            return [
                {
                    "id": r.id,
                    "device_id": r.device_id,
                    "vlan_id": r.vlan_id,
                    "name": r.name or "",
                    "status": r.status or "ACTIVE",
                    "tagged_ports": json.loads(r.tagged_ports_json or "[]"),
                    "untagged_ports": json.loads(r.untagged_ports_json or "[]"),
                    "trunk_ports": json.loads(r.trunk_ports_json or "[]"),
                    "updated_at": r.updated_at,
                }
                for r in rows
            ]

    def save_syslog_events_batch(self, items: List[Dict[str, Any]]) -> int:
        if not items:
            return 0
        try:
            with self.Session() as session:
                objs = [
                    SyslogEvent(
                        source_ip=it["source_ip"],
                        hostname=it.get("hostname", ""),
                        timestamp=it.get("timestamp") or datetime.utcnow(),
                        facility=int(it.get("facility", 0)),
                        facility_name=it.get("facility_name", "kern"),
                        severity=int(it.get("severity", 6)),
                        severity_name=it.get("severity_name", "Informational"),
                        app_name=it.get("app_name", ""),
                        event_category=it.get("event_category", "GENERAL"),
                        message=it["message"],
                        raw_message=it.get("raw_message", it["message"]),
                    )
                    for it in items
                ]
                session.add_all(objs)
                session.commit()
                return len(objs)
        except Exception as e:
            print(f"DB Error (save_syslog_events_batch): {e}")
            return 0

    def get_syslog_events(
        self,
        source_ip: Optional[str] = None,
        hostname: Optional[str] = None,
        max_severity: Optional[int] = None,
        severities: Optional[List[int]] = None,
        event_category: Optional[str] = None,
        search_text: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        with self.Session() as session:
            q = session.query(SyslogEvent)
            if source_ip:
                q = q.filter(SyslogEvent.source_ip == source_ip)
            if hostname:
                q = q.filter(SyslogEvent.hostname.ilike(f"%{hostname}%"))
            if max_severity is not None:
                q = q.filter(SyslogEvent.severity <= int(max_severity))
            if severities:
                q = q.filter(SyslogEvent.severity.in_([int(s) for s in severities]))
            if event_category:
                q = q.filter(SyslogEvent.event_category == event_category)
            if search_text:
                q = q.filter(SyslogEvent.message.ilike(f"%{search_text}%"))
            if since:
                q = q.filter(SyslogEvent.timestamp >= since)
            if until:
                q = q.filter(SyslogEvent.timestamp <= until)
            rows = q.order_by(SyslogEvent.timestamp.desc()).limit(limit).all()
            return [
                {
                    "id": r.id,
                    "source_ip": r.source_ip,
                    "hostname": r.hostname,
                    "timestamp": r.timestamp,
                    "facility": r.facility,
                    "facility_name": r.facility_name,
                    "severity": r.severity,
                    "severity_name": r.severity_name,
                    "app_name": r.app_name,
                    "event_category": r.event_category,
                    "message": r.message,
                    "raw_message": r.raw_message,
                }
                for r in rows
            ]

    @staticmethod
    def _anomaly_to_dict(a: NetworkAnomaly) -> Dict[str, Any]:
        return {
            "id": a.id,
            "anomaly_uid": a.anomaly_uid,
            "device_id": a.device_id,
            "device_name": a.device_name or "",
            "device_ip": a.device_ip or "",
            "event_type": a.event_type,
            "title": a.title,
            "severity": a.severity,
            "confidence": a.confidence or "MEDIUM",
            "probable_cause": a.probable_cause or "",
            "evidence": json.loads(a.evidence_json or "[]"),
            "recommended_actions": json.loads(a.actions_json or "[]"),
            "status": a.status or "ACTIVE",
            "detected_at": a.detected_at,
            "resolved_at": a.resolved_at,
        }

    def create_network_anomaly(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.Session() as session:
            a = NetworkAnomaly(
                anomaly_uid=data["anomaly_uid"],
                device_id=data.get("device_id"),
                device_name=data.get("device_name", ""),
                device_ip=data.get("device_ip", ""),
                event_type=data["event_type"],
                title=data["title"],
                severity=data["severity"],
                confidence=data.get("confidence", "MEDIUM"),
                probable_cause=data.get("probable_cause", ""),
                evidence_json=json.dumps(data.get("evidence", [])),
                actions_json=json.dumps(data.get("recommended_actions", [])),
                status=data.get("status", "ACTIVE"),
                detected_at=data.get("detected_at") or datetime.utcnow(),
                resolved_at=data.get("resolved_at"),
            )
            session.add(a)
            session.commit()
            session.refresh(a)
            return self._anomaly_to_dict(a)

    def update_network_anomaly(self, anomaly_id: int, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self.Session() as session:
            a = session.query(NetworkAnomaly).filter_by(id=anomaly_id).first()
            if not a:
                return None
            for k, v in updates.items():
                if k == "evidence":
                    a.evidence_json = json.dumps(v or [])
                elif k == "recommended_actions":
                    a.actions_json = json.dumps(v or [])
                elif hasattr(a, k) and k != "id":
                    setattr(a, k, v)
            session.commit()
            session.refresh(a)
            return self._anomaly_to_dict(a)

    def get_network_anomalies(
        self,
        device_id: Optional[int] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 300,
    ) -> List[Dict[str, Any]]:
        with self.Session() as session:
            q = session.query(NetworkAnomaly)
            if device_id is not None:
                q = q.filter(NetworkAnomaly.device_id == device_id)
            if status:
                q = q.filter(NetworkAnomaly.status == status)
            if severity:
                q = q.filter(NetworkAnomaly.severity == severity)
            rows = q.order_by(NetworkAnomaly.detected_at.desc()).limit(limit).all()
            return [self._anomaly_to_dict(r) for r in rows]
