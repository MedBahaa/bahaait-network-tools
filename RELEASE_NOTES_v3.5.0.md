# BahaaIT Network Tools v3.5.0 — Release Notes

## Roadmap 02 — Network Intelligence Platform

### 1. SNMP Infrastructure Monitoring Engine (`SNMPClient` & `AsyncSNMPEngine`)
- **Full Protocol Support**: SNMP **v1**, **v2c**, and **v3** (`noAuthNoPriv`, `authNoPriv`, `authPriv` with SHA/SHA224/SHA256/SHA384/SHA512 authentication and AES128/AES192/AES256/DES/3DES privacy encryption).
- **DPAPI Credential Security**: SNMP community strings and SNMPv3 keys are encrypted at rest via Windows DPAPI and scrubbed automatically from all exceptions, logs, snapshots, and UI banners.
- **Vendor-Independent Architecture & Profiles**: Dedicated OID and threshold profiles for **Cisco Catalyst**, **Ruckus ICX/AP**, **Fortinet FortiGate**, **Generic Routers**, **Generic Managed Switches**, and **SNMP Servers/Appliances** without hardcoding uniform OIDs across vendors.
- **Automated Device Discovery & Non-Overlapping Scheduler**: Automatic detection of vendor, model, firmware, system metadata (`MIB-II`), hardware capabilities, reboot detection (`sysUpTime` drop with 32-bit 497-day wraparound immunity), and concurrent non-overlapping asynchronous polling.

### 2. Device Health, Interfaces (64-bit), PoE & VLAN Discovery
- **Device Health (`DeviceHealthCollector`)**: CPU utilization (historical average & configurable warning/critical thresholds), Memory accounting across vendor pools and `HOST-RESOURCES-MIB`, and multi-sensor Temperature monitoring using **model- and profile-specific thresholds**.
- **Network Interface Monitoring (`InterfaceMonitorCollector`)**: `IF-MIB` + 64-bit `ifXTable` (`ifHCInOctets` / `ifHCOutOctets`) with 32-bit fallback, all 6 canonical operational states (`UP`, `DOWN`, `TESTING`, `UNKNOWN`, `DORMANT`, `NOT_PRESENT`), Mbps throughput & utilization %, `EtherLike-MIB` CRC/FCS errors, discards, and strict protection against false traffic spikes on 32/64-bit counter rollovers, counter resets, discontinuities, and device reboots.
- **PoE & VLAN Discovery**: `POWER-ETHERNET-MIB` + vendor per-port consumption (`W`), remaining budget & overload alerts, plus `Q-BRIDGE-MIB` PortList bitmask decoding and Cisco/Ruckus trunk/tagged/untagged port mapping — never fabricating values on unsupported hardware.

### 3. Centralized Syslog Monitor (`SyslogServer`, `syslog_parser`, `syslog_classifier`)
- **Non-Blocking UDP Receiver**: Isolated `QThread` asyncio datagram listener on configurable port (`514` Admin / `5514` Non-Admin) with dual token-bucket flood protection (global + per-IP) and bounded queue backpressure reporting explicit drop counters.
- **RFC 3164 & RFC 5424 Support**: Full 8-severity decoding (`Emergency` → `Debug`), structured data parsing, Cisco IOS / FortiGate KV / Ruckus variants, and crash-safe handling of malformed or oversized packets.
- **Multi-Vendor Structured Classification & Exports**: 12 normalized event categories (`FIREWALL_IF_DOWN`, `LINK_DOWN`, `LINK_UP`, `REBOOT`, `POE_OVERLOAD`, `AUTH_FAIL`, `CONFIG_CHANGE`, `STP_CHANGE`, `PORT_SECURITY`, `HIGH_CPU`, `HARDWARE_THERMAL`, `GENERAL`), interactive filters, CSV/JSON export, and integrated Windows Firewall command guide.

### 4. Network Intelligence & Lightweight Statistical Anomaly Detection
- **Lightweight Statistical Detector**: Dependency-free rolling baseline & z-score anomaly detection with flatline noise-floor guards, consecutive persistence window against transient spikes, deduplication cooldown, and per-device enable/disable control.
- **Multi-Source Root-Cause Correlation (`IntelligenceEngine`)**: Fuses Ping Monitoring (v3.4.0), SNMP Availability/Health, Interfaces, PoE, Syslog, and History across key infrastructure scenarios (`PHYSICAL_LINK_FAILURE`, `SWITCH_OVERLOAD`, `POE_BUDGET_EXHAUSTION`, `UNEXPECTED_REBOOT`, `INTERFACE_ERROR_DEGRADATION`, `SYSLOG_SECURITY_BURST`), strictly separating **Observed Evidence** from **Inferred Probable Cause**, with confidence levels, recommended actions, and automatic resolution.

### 5. Quantum Midnight UI & Internationalization
- **Upgraded Infrastructure Dashboard**: Expanded to **10 NOC KPI cards**, **8 real-time/historical charts**, and live **SNMP Infrastructure Inventory** while preserving all v3.4.0 general metrics.
- **Dedicated v3.5.0 Views & 10-Tab Device Details**: SNMP Infrastructure (Index 11), Syslog Monitor (Index 12), Network Intelligence (Index 13), and a 10-tab capability-gated Device Details dialog (dynamically hiding/disabling PoE & VLAN tabs when unsupported).
- Full 1:1 **French / English** internationalization (`862` verified translation keys in both languages).

### 6. Measured Compatibility & Scale Benchmarks
- **Seamless SQLite Non-Destructive Migration**: Automatically upgrades existing v3.4.0 databases in place with 8 new Network Intelligence tables while preserving all hosts, incidents, logs, and settings.
- **Measured Simulation Benchmark (100 SNMP Devices + 1,000 UDP Syslog Datagrams)**:
  - **2×100 Concurrent SNMP Poll Cycles**: `1.022 s` (50 concurrent semaphore slots, health + 64-bit interfaces + VLAN/PoE + batched SQLite flush).
  - **1,000 Loopback UDP Syslog Events**: `0.261 s` (`3,825 msg/s`, 0 dropped packets, persisted in SQLite).
  - **100-Device Multi-Source Correlation**: `0.471 s` (identifies 5 injected cross-source faults).
