# BahaaIT Network Tools v3.4.0 — Release Notes

## Roadmap 01 — Intelligent Ping Monitoring

### 1. Asynchronous Multi-Host Monitoring Engine (`AsyncPingEngine`)
- **Non-blocking asyncio architecture** running inside an isolated `QThread` capable of monitoring **100+ concurrent hosts** without stalling the PySide6 UI.
- **Per-probe outcome classification**: cleanly distinguishes `SUCCESS`, `TIMEOUT`, `DNS_ERROR`, and `ENGINE_ERROR` (scheduler overload / local socket errors are excluded from packet loss & false outage alerts).
- **Batched SQLite persistence** with WAL mode, `PRAGMA foreign_keys=ON`, `busy_timeout=5000`, and seamless non-destructive schema migration from v3.3.0.

### 2. Intelligent 4-State Hysteresis State Machine
- **UP**: Healthy host within latency, jitter, and packet loss budgets.
- **DEGRADED**: Early warning triggered by configurable consecutive failures (default 3), rolling packet loss %, elevated average latency, or excessive jitter.
- **DOWN**: Confirmed critical outage after consecutive failures reach the critical threshold (default 5) — single lost packets never trigger false outages.
- **RECOVERING**: Intermediate stabilization state requiring configurable consecutive successes (default 3) before returning to `UP`.
- **PAUSED**: Per-host pause/resume without losing configuration or history.

### 3. Real-Time Quality Metrics & Multi-Period Statistics
- Rolling window calculation of **Packet Loss (%)**, **IPDV Jitter (ms)**, **Min / Avg / Max / P95 Latency (ms)**, and **Availability (%)**.
- Historical queries across **1m, 5m, 15m, 1h, and 24h** windows with real-time `pyqtgraph` charts in `HostDetailsDialog`.

### 4. Incident Lifecycle & Corporate PDF/CSV Reporting
- Automatic incident creation on degradation/outage and closure on recovery (`DETECTED` -> `ACKNOWLEDGED` -> `RECOVERED` -> `CLOSED`), preserved even if a host is deleted.
- **Incident Center** with multi-criteria filtering (Severity, Status, Host, Time Period), technician **Acknowledgement**, timestamped **Comments**, manual **Close**, CSV export, and **Corporate PDF Report** including an unabridged *Journal des Commentaires & Interventions* section.
- Instant bidirectional synchronization between `HostDetailsDialog` and `IncidentCenterWidget`.

### 5. Deduplicated Multi-Channel Alerting
- Independent dispatch for **Critical Sound Alarm** (with configurable auto-stop duration), **Windows Tray Toast Notifications**, and **Async SMTP Emails** with retry & credential masking.
- Anti-spam deduplication per `(host, incident_uid, severity)` with optional repeat notification interval.

### 6. WAN Connectivity Intelligence & Global Configuration
- **WAN Intelligence Tab**: Multi-target correlation across **Local Gateway**, **8.8.8.8**, **1.1.1.1**, **DNS Resolution**, and **HTTPS/TLS (443)** producing 9 diagnostic verdicts (`HEALTHY`, `WAN_OUTAGE_CONFIRMED`, `WAN_OUTAGE_SUSPECTED`, `LAN_GATEWAY_ISSUE`, `DNS_FAILURE`, `ICMP_FILTERED_WAN_OK`, `HTTPS_BLOCKED_OR_PROXY`, `DESTINATION_ROUTING_ISSUE`, `GATEWAY_ICMP_BLOCKED`) with evidence and recommended actions.
- **Global Monitoring Settings Tab**: Configurable global defaults with automatic propagation to non-overridden hosts, data retention policies (`raw`, `aggregated`, `incidents`, `alerts`) with on-demand purge, **Restore Defaults**, and validated **JSON Export / Import**.
- Full **French / English** internationalization (`i18n`).
