from datetime import datetime
import os
import re
import sys
from typing import Any, Dict, Optional

from PySide6.QtCore import Qt, QDateTime, QTimer
from PySide6.QtGui import QColor, QFont, QIcon
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.monitor import create_monitoring_stack
from core.monitoring_state import HostState, MonitoringPolicyConfig, validate_target_address
from core.monitoring_statistics import MonitoringStatisticsService
from ui.widgets.host_details_view import HostDetailsDialog
from ui.widgets.incident_center import IncidentCenterWidget
from ui.widgets.monitoring_dashboard import MonitoringOverviewBar
from ui.widgets.monitoring_settings import MonitoringSettingsWidget
from ui.widgets.wan_monitor_view import WANMonitorView
from utils.db import DatabaseManager
from utils.i18n import _
from utils.pdf_generator import PDFReportGenerator


_STATE_STYLE = {
    HostState.UP.value: ("#10B981", "mon_status_up_badge", "UP"),
    HostState.DEGRADED.value: ("#F59E0B", "mon_status_degraded_badge", "DEGRADED"),
    HostState.DOWN.value: ("#F43F5E", "mon_status_down_badge", "DOWN"),
    HostState.RECOVERING.value: ("#38BDF8", "mon_status_recovering_badge", "RECOVERING"),
    HostState.PAUSED.value: ("#94A3B8", "mon_status_paused_badge", "PAUSED"),
    HostState.UNKNOWN.value: ("#94A3B8", "mon_status_unknown_badge", "PENDING"),
}


class MonitorView(QWidget):
    """Upgraded Intelligent Ping Monitoring UI consuming the Lot 1 AsyncPingEngine stack."""

    def __init__(self, logger, alarm_manager=None, config_manager=None, tray_manager=None, db=None):
        super().__init__()
        self.logger = logger
        self.alarm_manager = alarm_manager
        self.config = config_manager
        self.tray_manager = tray_manager
        self.db = db if db is not None else DatabaseManager()

        # Load alarm preferences
        if self.config and self.alarm_manager:
            saved_sound = self.config.get("alarm_sound")
            if saved_sound and os.path.exists(saved_sound):
                self.alarm_manager.set_source(saved_sound)
            saved_enabled = self.config.get("alarm_enabled", True)
            self.alarm_manager.set_enabled(saved_enabled)

        # Assemble Lot 1 monitoring stack
        stack = create_monitoring_stack(
            db=self.db,
            config_manager=self.config,
            alarm_manager=self.alarm_manager,
            tray_manager=self.tray_manager,
            logger=self.logger,
        )
        self.engine = stack["engine"]
        self.incident_manager = stack["incident_manager"]
        self.alert_manager = stack["alert_manager"]
        self.stats_service: MonitoringStatisticsService = stack["statistics_service"]
        self.wan_monitor = stack["wan_monitor"]
        self._last_wan_verdict_code: Optional[str] = None

        wan_interval = int(self.config.get("wan_check_interval_sec", 15) or 15) if self.config else 15
        self.engine.set_wan_interval(wan_interval)
        self.engine.enable_wan_monitor(False)

        self.is_monitoring_active = False
        self.details_dialogs: Dict[str, HostDetailsDialog] = {}
        self.hosts: Dict[str, Dict[str, Any]] = {}
        self._row_by_host: Dict[str, int] = {}
        self._overview_dirty = False

        if getattr(sys, "frozen", False):
            self.icons_dir = os.path.join(sys._MEIPASS, "assets", "icons")
        else:
            self.icons_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..", "assets", "icons")

        # Seed hosts from DB or config defaults on first run
        self._load_initial_hosts()

        # Connect engine signals to Qt GUI slots
        self.engine.host_updated.connect(self.on_host_updated)
        self.engine.state_changed.connect(self.on_state_changed)
        self.engine.incident_updated.connect(self.on_incident_updated)
        self.engine.alert_triggered.connect(self.on_alert_triggered)
        self.engine.wan_updated.connect(self.on_wan_updated)
        self.engine.engine_error.connect(self.on_engine_error)
        self.engine.finished.connect(self.on_monitor_finished)

        # Build UI
        self._build_ui()

        # Coalesced KPI refresh timer (500ms) keeps 100-host updates ultra smooth
        self._overview_timer = QTimer(self)
        self._overview_timer.setInterval(500)
        self._overview_timer.timeout.connect(self._flush_overview_summary)
        self._overview_timer.start()

        self.refresh_table()
        self._update_overview_summary()

    def _load_initial_hosts(self) -> None:
        saved_hosts = self.db.get_hosts()
        if not saved_hosts and self.config:
            default_hosts = self.config.get("monitored_hosts", [])
            for item in default_hosts:
                if isinstance(item, str) and item.strip():
                    self.db.add_host(item.strip(), item.strip())
                elif isinstance(item, dict) and item.get("address"):
                    self.db.add_host(item["address"], item.get("label") or item["address"])
            saved_hosts = self.db.get_hosts()

        for h in saved_hosts:
            addr = h["address"]
            is_active = bool(h.get("is_active", True))
            label = h.get("label") or addr
            policy_dict = self.db.get_policy(h["id"])
            policy_cfg = MonitoringPolicyConfig.from_dict(policy_dict) if policy_dict else None

            self.engine.add_host(
                address=addr,
                label=label,
                active=is_active,
                policy=policy_cfg,
                host_id=h["id"],
                category=h.get("category", "General"),
                profile=h.get("profile", "Standard"),
            )
            snap = self.engine.get_host_snapshot(addr) or {}
            self.hosts[addr] = snap

    def _build_ui(self) -> None:
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(25, 22, 25, 22)
        self.layout.setSpacing(12)

        # Main Header + Global Start/Stop
        header_layout = QHBoxLayout()
        header = QLabel(_("mon_header_ping", "Ping Monitor"))
        header.setObjectName("Title")
        header_layout.addWidget(header)

        self.status_label = QLabel(_("mon_status_stopped", "Stopped"))
        self.status_label.setStyleSheet("color: #F43F5E; font-weight: bold; margin-left: 10px;")
        header_layout.addWidget(self.status_label)
        header_layout.addStretch()

        self.start_btn = QPushButton(_("mon_btn_start", "Start Monitor"))
        self.start_btn.setObjectName("PrimaryButton")
        self.start_btn.setMinimumWidth(160)
        self.start_btn.setFixedHeight(38)
        self.start_btn.setCursor(Qt.PointingHandCursor)
        self.start_btn.clicked.connect(self.toggle_monitor)
        header_layout.addWidget(self.start_btn)
        self.layout.addLayout(header_layout)

        # Sub-tabs: Live Supervision | Incident Center
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs, 1)

        # ── Tab 0: Live Supervision ──
        sup_tab = QWidget()
        sup_layout = QVBoxLayout(sup_tab)
        sup_layout.setContentsMargins(0, 12, 0, 0)
        sup_layout.setSpacing(12)

        self.overview_bar = MonitoringOverviewBar(self)
        sup_layout.addWidget(self.overview_bar)

        # Add Host Controls
        controls = QHBoxLayout()
        controls.setSpacing(10)

        self.label_input = QLineEdit()
        self.label_input.setPlaceholderText(_("mon_name_optional_placeholder", "Device Name (optional)..."))
        self.label_input.setFixedWidth(210)
        self.label_input.setFixedHeight(35)

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText(_("mon_ip_placeholder", "IP Address or Hostname..."))
        self.ip_input.setFixedHeight(35)
        self.ip_input.returnPressed.connect(self.add_host)

        self.add_btn = QPushButton(_("mon_btn_add", "Add Host"))
        self.add_btn.setObjectName("SecondaryButton")
        self.add_btn.setMinimumWidth(130)
        self.add_btn.setFixedHeight(35)
        self.add_btn.setCursor(Qt.PointingHandCursor)
        self.add_btn.clicked.connect(self.add_host)

        controls.addWidget(self.label_input)
        controls.addWidget(self.ip_input, 1)
        controls.addWidget(self.add_btn)
        sup_layout.addLayout(controls)

        # Enriched Monitoring Table (11 columns)
        self.table = QTableWidget(0, 11)
        self.table.setHorizontalHeaderLabels([
            _("mon_col_name", "Host Name").upper(),
            _("mon_col_ip", "IP Address").upper(),
            _("mon_col_status", "Status").upper(),
            _("mon_col_current", "Current").upper(),
            _("mon_col_avg", "Average").upper(),
            _("mon_col_loss", "Packet Loss").upper(),
            _("mon_col_jitter", "Jitter").upper(),
            _("mon_col_uptime", "Uptime").upper(),
            _("mon_col_last_resp", "Last Response").upper(),
            _("mon_col_incident", "Active Incident").upper(),
            _("mon_col_actions", "Actions").upper(),
        ])

        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.Fixed)
        hdr.setSectionResizeMode(3, QHeaderView.Fixed)
        hdr.setSectionResizeMode(4, QHeaderView.Fixed)
        hdr.setSectionResizeMode(5, QHeaderView.Fixed)
        hdr.setSectionResizeMode(6, QHeaderView.Fixed)
        hdr.setSectionResizeMode(7, QHeaderView.Fixed)
        hdr.setSectionResizeMode(8, QHeaderView.Fixed)
        hdr.setSectionResizeMode(10, QHeaderView.Fixed)
        self.table.setColumnWidth(2, 96)
        self.table.setColumnWidth(3, 68)
        self.table.setColumnWidth(4, 68)
        self.table.setColumnWidth(5, 64)
        self.table.setColumnWidth(6, 60)
        self.table.setColumnWidth(7, 68)
        self.table.setColumnWidth(8, 82)
        self.table.setColumnWidth(10, 122)

        self.table.verticalHeader().setDefaultSectionSize(44)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.cellDoubleClicked.connect(self._on_row_double_clicked)

        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #1E293B;
                alternate-background-color: #161E2D;
                border: 1px solid rgba(255, 255, 255, 0.05);
                border-radius: 12px;
                gridline-color: transparent;
            }
            QTableWidget::item {
                padding-left: 6px;
                padding-right: 6px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.02);
            }
            QHeaderView::section {
                background-color: #0F172A;
                padding: 8px 6px;
                font-weight: bold;
                font-size: 10px;
                letter-spacing: 0.7px;
            }
        """)
        sup_layout.addWidget(self.table, 1)

        # Compact Live Event Log + Log Export Buttons
        log_header_row = QHBoxLayout()
        log_lbl = QLabel(_("mon_event_log", "Event Log") + ":")
        log_lbl.setStyleSheet("font-weight: 600; color: #94A3B8; margin-bottom: 0px;")
        log_header_row.addWidget(log_lbl)
        log_header_row.addStretch()

        self.export_log_btn = QPushButton(_("mon_btn_export", "Export Log"))
        self.export_log_btn.setObjectName("SecondaryButton")
        self.export_log_btn.setFixedHeight(30)
        self.export_log_btn.clicked.connect(self.export_log)

        self.export_pdf_btn = QPushButton(_("mon_btn_export_pdf", "Export PDF"))
        self.export_pdf_btn.setObjectName("SecondaryButton")
        self.export_pdf_btn.setFixedHeight(30)
        self.export_pdf_btn.clicked.connect(self.export_pdf)

        clear_log_btn = QPushButton(_("mon_btn_clear", "Clear Log"))
        clear_log_btn.setObjectName("SecondaryButton")
        clear_log_btn.setFixedHeight(30)
        clear_log_btn.clicked.connect(lambda: self.event_log.clear())

        log_header_row.addWidget(self.export_log_btn)
        log_header_row.addWidget(self.export_pdf_btn)
        log_header_row.addWidget(clear_log_btn)
        sup_layout.addLayout(log_header_row)

        self.event_log = QTextEdit()
        self.event_log.setReadOnly(True)
        self.event_log.setMaximumHeight(110)
        self.event_log.setStyleSheet("""
            QTextEdit {
                background-color: #090D16;
                color: #10B981;
                font-family: 'Consolas', monospace;
                font-size: 11px;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 8px;
            }
        """)
        sup_layout.addWidget(self.event_log)

        self.tabs.addTab(sup_tab, _("mon_tab_supervision", "Live Supervision"))

        # ── Tab 1: Incident Center ──
        self.incident_center = IncidentCenterWidget(self.incident_manager, self.db, self)
        self.incident_center.active_count_changed.connect(self._update_incident_tab_title)
        self.incident_center.incidents_changed.connect(self._on_incident_center_changed)
        self.tabs.addTab(self.incident_center, _("mon_tab_incidents", "Incident Center"))
        self._update_incident_tab_title(len(self.incident_manager.get_active_incidents()))

        # ── Tab 2: WAN Intelligence (Autonomous) ──
        wan_interval = int(self.config.get("wan_check_interval_sec", 15) or 15) if self.config else 15
        self.wan_view = WANMonitorView(
            self.wan_monitor,
            continuous_enabled=False,
            interval_sec=wan_interval,
            parent=self,
        )
        self.wan_view.continuous_toggled.connect(self._on_wan_continuous_toggled)
        self.wan_view.interval_changed.connect(self._on_wan_interval_changed)
        self.wan_view.verdict_ready.connect(self._log_wan_verdict)
        self.tabs.addTab(self.wan_view, _("mon_tab_wan", "WAN Intelligence"))

        # ── Tab 3: Global Monitoring Settings ──
        self.settings_tab = MonitoringSettingsWidget(
            self.db,
            self.engine,
            config_manager=self.config,
            parent=self,
        )
        self.settings_tab.global_policy_saved.connect(self._on_global_policy_saved)
        self.tabs.addTab(self.settings_tab, _("mon_tab_settings", "Monitoring Settings"))

    def _update_incident_tab_title(self, active_count: int) -> None:
        base = _("mon_tab_incidents", "Incident Center")
        title = f"{base} ({active_count})" if active_count > 0 else base
        self.tabs.setTabText(1, title)

    def add_log_entry(self, message: str, level: str = "INFO") -> None:
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd HH:mm:ss")
        color = "#10B981"
        if level == "WARNING":
            color = "#F59E0B"
        elif level in ("ERROR", "CRITICAL"):
            color = "#F43F5E"
        self.event_log.append(f'<span style="color: #64748B;">[{timestamp}]</span> <span style="color: {color};">[{level}]</span> {message}')

    def add_host(self) -> None:
        raw_host = self.ip_input.text().strip()
        label = self.label_input.text().strip() or raw_host
        if not raw_host:
            return

        ok, cleaned_or_err = validate_target_address(raw_host)
        if not ok:
            QMessageBox.warning(self, _("mon_invalid_host_title", "Invalid Host Address"), cleaned_or_err)
            return

        host = cleaned_or_err
        self.db.add_host(host, label)
        host_row = next((h for h in self.db.get_hosts() if h["address"] == host), None)
        host_id = host_row["id"] if host_row else None

        self.engine.add_host(host, label=label, active=True, host_id=host_id)
        self.hosts[host] = self.engine.get_host_snapshot(host) or {}

        if self.config:
            self.config.set("monitored_hosts", list(self.hosts.keys()))

        self.ip_input.clear()
        self.label_input.clear()
        self.add_log_entry(f"Host updated/added: {host} ({label})")
        self.refresh_table()
        self._update_overview_summary()

    def toggle_pause(self, host: str) -> None:
        if host not in self.hosts:
            return
        currently_active = bool(self.hosts[host].get("active", True))
        if currently_active:
            self.db.set_host_active(host, False)
            self.engine.pause_host(host)
            self.add_log_entry(f"Host {host} paused", "WARNING")
        else:
            self.db.set_host_active(host, True)
            self.engine.resume_host(host)
            self.add_log_entry(f"Host {host} resumed", "INFO")

        self.hosts[host] = self.engine.get_host_snapshot(host) or self.hosts[host]
        self.refresh_table()
        self._update_overview_summary()

    def delete_host(self, host: str) -> None:
        if host not in self.hosts:
            return
        self.engine.remove_host(host)
        self.db.delete_host(host)
        self.hosts.pop(host, None)
        if host in self.details_dialogs:
            dlg = self.details_dialogs.pop(host)
            dlg.close()

        if self.config:
            self.config.set("monitored_hosts", list(self.hosts.keys()))

        self.add_log_entry(f"Host deleted: {host}", "WARNING")
        self.refresh_table()
        self._update_overview_summary()

    def _on_row_double_clicked(self, row: int, _col: int) -> None:
        ip_item = self.table.item(row, 1)
        if ip_item:
            self.show_details(ip_item.text())

    def show_details(self, host: str, initial_tab: int = 0) -> None:
        if host not in self.hosts:
            return
        existing = self.details_dialogs.get(host)
        if existing is not None and existing.isVisible():
            existing.tabs.setCurrentIndex(initial_tab)
            existing.raise_()
            existing.activateWindow()
            return

        snap = self.engine.get_host_snapshot(host) or self.hosts[host]
        dlg = HostDetailsDialog(
            host_address=host,
            host_label=snap.get("label", host),
            db=self.db,
            engine=self.engine,
            incident_manager=self.incident_manager,
            stats_service=self.stats_service,
            initial_snapshot=snap,
            parent=self,
        )
        dlg.incidents_changed.connect(self._on_host_dialog_incidents_changed)
        dlg.tabs.setCurrentIndex(initial_tab)
        self.details_dialogs[host] = dlg
        dlg.show()

    def show_graph(self, host: str) -> None:
        self.show_details(host, initial_tab=0)

    def show_history(self, host: str) -> None:
        self.show_details(host, initial_tab=1)

    def refresh_table(self) -> None:
        self.table.setRowCount(0)
        self._row_by_host.clear()

        for host, snap in self.hosts.items():
            row = self.table.rowCount()
            self.table.insertRow(row)
            self._row_by_host[host] = row

            for col in range(10):
                item = QTableWidgetItem("")
                item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row, col, item)

            # Build action widget (Pause/Resume, Details, Delete)
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(4, 0, 4, 0)
            action_layout.setSpacing(6)
            action_layout.setAlignment(Qt.AlignCenter)

            is_active = bool(snap.get("active", True))
            pause_icon = "pause.svg" if is_active else "play.svg"

            pause_btn = QPushButton()
            pause_btn.setFixedSize(28, 28)
            pause_btn.setCursor(Qt.PointingHandCursor)
            pause_btn.setIcon(QIcon(os.path.join(self.icons_dir, pause_icon)))
            pause_btn.setToolTip(_("mon_tooltip_pause"))
            pause_btn.setStyleSheet("background: rgba(99, 102, 241, 0.12); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: 6px;")
            pause_btn.clicked.connect(lambda checked=False, h=host: self.toggle_pause(h))

            details_btn = QPushButton()
            details_btn.setFixedSize(28, 28)
            details_btn.setCursor(Qt.PointingHandCursor)
            details_btn.setIcon(QIcon(os.path.join(self.icons_dir, "activity.svg")))
            details_btn.setToolTip(_("mon_tooltip_details", "Host Details & Real-Time Charts"))
            details_btn.setStyleSheet("background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 6px;")
            details_btn.clicked.connect(lambda checked=False, h=host: self.show_details(h))

            delete_btn = QPushButton()
            delete_btn.setFixedSize(28, 28)
            delete_btn.setCursor(Qt.PointingHandCursor)
            delete_btn.setIcon(QIcon(os.path.join(self.icons_dir, "trash.svg")))
            delete_btn.setToolTip(_("mon_tooltip_delete"))
            delete_btn.setStyleSheet("background: rgba(244, 63, 94, 0.12); border: 1px solid rgba(244, 63, 94, 0.25); border-radius: 6px;")
            delete_btn.clicked.connect(lambda checked=False, h=host: self.delete_host(h))

            action_layout.addWidget(pause_btn)
            action_layout.addWidget(details_btn)
            action_layout.addWidget(delete_btn)
            self.table.setCellWidget(row, 10, action_widget)

            self._apply_snapshot_to_row(row, snap)

    def _apply_snapshot_to_row(self, row: int, snap: Dict[str, Any]) -> None:
        host = snap.get("host", "")
        label = snap.get("label") or host
        state = str(snap.get("state", "UNKNOWN")).upper()
        cur_lat = snap.get("current_latency_ms")
        avg_lat = float(snap.get("avg_latency_ms", 0.0))
        loss_pct = float(snap.get("packet_loss_pct", 0.0))
        jitter_ms = float(snap.get("jitter_ms", 0.0))
        uptime_pct = float(snap.get("uptime_pct", 100.0))
        last_ok = snap.get("last_success_utc")
        inc_uid = snap.get("active_incident_uid")

        color_hex, badge_key, badge_fb = _STATE_STYLE.get(state, _STATE_STYLE[HostState.UNKNOWN.value])
        bold_font = QFont()
        bold_font.setBold(True)

        self.table.item(row, 0).setText(label)
        self.table.item(row, 0).setForeground(QColor("#E2E8F0"))

        self.table.item(row, 1).setText(host)
        self.table.item(row, 1).setForeground(QColor("#818CF8"))

        st_item = self.table.item(row, 2)
        st_item.setText(_(badge_key, badge_fb))
        st_item.setFont(bold_font)
        st_item.setForeground(QColor(color_hex))

        self.table.item(row, 3).setText(f"{cur_lat:.0f} ms" if cur_lat is not None else "—")
        self.table.item(row, 4).setText(f"{avg_lat:.1f} ms" if avg_lat > 0 else "—")

        loss_item = self.table.item(row, 5)
        loss_item.setText(f"{loss_pct:.1f}%")
        loss_item.setForeground(QColor("#F43F5E" if loss_pct >= 10.0 else ("#F59E0B" if loss_pct > 0 else "#10B981")))

        self.table.item(row, 6).setText(f"{jitter_ms:.1f} ms" if jitter_ms > 0 else "0.0 ms")

        up_item = self.table.item(row, 7)
        up_item.setText(f"{uptime_pct:.1f}%")
        up_item.setForeground(QColor("#10B981" if uptime_pct >= 99.0 else ("#F59E0B" if uptime_pct >= 95.0 else "#F43F5E")))

        last_str = last_ok.strftime("%H:%M:%S") if isinstance(last_ok, datetime) else "—"
        self.table.item(row, 8).setText(last_str)

        inc_item = self.table.item(row, 9)
        inc_item.setText(inc_uid if inc_uid else "—")
        inc_item.setForeground(QColor("#F43F5E" if inc_uid else "#64748B"))

    def toggle_monitor(self) -> None:
        if not self.start_btn.isEnabled():
            return
        if self.is_monitoring_active:
            self.stop_monitor()
        else:
            self.start_monitor()

    def start_monitor(self) -> None:
        if self.is_monitoring_active:
            return
        self.is_monitoring_active = True
        self.start_btn.setEnabled(False)

        if not self.engine.isRunning():
            self.engine.start()

        self.add_log_entry(_("mon_log_started", "Monitoring started"))
        self.start_btn.setText(_("mon_btn_stop", "Stop Monitor"))
        self.start_btn.setStyleSheet("background-color: #F43F5E;")
        self.status_label.setText(_("mon_status_running", "Running"))
        self.status_label.setStyleSheet("color: #10B981; font-weight: bold; margin-left: 10px;")

        QTimer.singleShot(250, lambda: self.start_btn.setEnabled(True) if self.is_monitoring_active else None)

    def stop_monitor(self) -> None:
        if not self.is_monitoring_active:
            return
        self.is_monitoring_active = False

        if self.alarm_manager:
            self.alarm_manager.stop()

        if self.engine and self.engine.isRunning():
            self.start_btn.setEnabled(False)
            self.start_btn.setText(_("mon_btn_stopping", "Stopping..."))
            self.start_btn.setStyleSheet("background-color: #64748B; color: #E2E8F0;")
            self.engine.stop(timeout_ms=3000)
        else:
            self.on_monitor_finished()

    def shutdown(self) -> None:
        """Stop both autonomous WAN workers and Host monitoring engine on app exit."""
        if hasattr(self, "wan_view"):
            self.wan_view.stop_workers(stop_continuous=True)
        self.stop_monitor()

    def on_monitor_finished(self) -> None:
        self.is_monitoring_active = False
        self.start_btn.setEnabled(True)
        self.start_btn.setText(_("mon_btn_start", "Start Monitor"))
        self.start_btn.setStyleSheet("")
        self.status_label.setText(_("mon_status_stopped", "Stopped"))
        self.status_label.setStyleSheet("color: #F43F5E; font-weight: bold; margin-left: 10px;")
        self.add_log_entry(_("mon_log_stopped", "Monitoring stopped"), "WARNING")

    def on_host_updated(self, snap: Dict[str, Any]) -> None:
        host = snap.get("host")
        if not host or host not in self.hosts:
            return
        self.hosts[host] = snap
        row = self._row_by_host.get(host)
        if row is not None and 0 <= row < self.table.rowCount():
            self._apply_snapshot_to_row(row, snap)

        if host in self.details_dialogs and self.details_dialogs[host].isVisible():
            self.details_dialogs[host].update_live_snapshot(snap)

        self._overview_dirty = True

    def on_state_changed(self, evt: Dict[str, Any]) -> None:
        host = evt.get("host", "")
        prev_st = evt.get("previous_state", "")
        new_st = evt.get("new_state", "")
        reason = evt.get("reason", "")
        level = "INFO" if new_st == "UP" else ("WARNING" if new_st in ("DEGRADED", "RECOVERING") else "CRITICAL")
        self.add_log_entry(f"{host}: {prev_st} -> {new_st} ({reason})", level)
        self._update_overview_summary()

    def on_incident_updated(self, inc: Dict[str, Any]) -> None:
        self.incident_center.refresh_incidents()
        host = inc.get("host_address")
        if host and host in self.details_dialogs and self.details_dialogs[host].isVisible():
            self.details_dialogs[host].refresh_host_incidents()
        self._update_overview_summary()

    def _on_incident_center_changed(self) -> None:
        for dlg in self.details_dialogs.values():
            if dlg is not None and dlg.isVisible():
                dlg.refresh_host_incidents()
        self._update_overview_summary()

    def _on_host_dialog_incidents_changed(self) -> None:
        self.incident_center.refresh_incidents()
        self._update_overview_summary()

    def on_alert_triggered(self, evt: Dict[str, Any]) -> None:
        channel = evt.get("channel", "SYSTEM")
        msg = evt.get("message", "")
        sev = evt.get("severity", "INFO")
        if channel in ("EMAIL", "SOUND") and not evt.get("delivered", True):
            self.add_log_entry(f"[{channel}] Delivery error: {evt.get('error_detail', '')}", "ERROR")
        elif channel in ("EMAIL", "WINDOWS", "SOUND"):
            self.add_log_entry(f"[{channel}] {msg}", sev)

    def on_engine_error(self, msg: str) -> None:
        self.logger.error(f"Monitoring Engine Error: {msg}")
        self.add_log_entry(f"Engine Error: {msg}", "ERROR")

    def _on_wan_continuous_toggled(self, enabled: bool) -> None:
        if self.config is not None:
            self.config.set("wan_monitor_enabled", bool(enabled))
        self.add_log_entry(
            f"[WAN] Continuous WAN monitoring {'started' if enabled else 'stopped'}.",
            "INFO",
        )

    def _on_wan_interval_changed(self, seconds: int) -> None:
        self.engine.set_wan_interval(float(seconds))
        if self.config is not None:
            self.config.set("wan_check_interval_sec", int(seconds))

    def _log_wan_verdict(self, verdict: Dict[str, Any]) -> None:
        code = str(verdict.get("verdict_code", ""))
        if not code or code == self._last_wan_verdict_code:
            return
        self._last_wan_verdict_code = code
        sev = str(verdict.get("severity", "INFO")).upper()
        level = "CRITICAL" if sev == "CRITICAL" else ("WARNING" if sev == "WARNING" else "INFO")
        self.add_log_entry(f"[WAN] {code}: {verdict.get('probable_cause', '')}", level)

    def on_wan_updated(self, verdict: Dict[str, Any]) -> None:
        if hasattr(self, "wan_view"):
            self.wan_view.update_verdict(verdict)
        self._log_wan_verdict(verdict)

    def _on_global_policy_saved(self, policy_dict: Dict[str, Any]) -> None:
        self.add_log_entry(
            f"Global monitoring policy updated (interval={policy_dict.get('probe_interval_ms')}ms, "
            f"crit={policy_dict.get('critical_failures')}).",
            "INFO",
        )

    def _flush_overview_summary(self) -> None:
        if self._overview_dirty:
            self._overview_dirty = False
            self._update_overview_summary()

    def _update_overview_summary(self) -> None:
        active_cnt = len(self.incident_manager.get_active_incidents())
        summary = MonitoringStatisticsService.get_global_summary(self.hosts, active_incidents_count=active_cnt)
        self.overview_bar.update_summary(summary)

    def export_log(self) -> None:
        if self.event_log.toPlainText().strip() == "":
            QMessageBox.warning(self, _("msg_warning"), _("mon_log_empty"))
            return

        file_path, _selected_filter = QFileDialog.getSaveFileName(
            self, _("mon_export_log_title"), "BahaaIT_Monitor_Log.txt", "Text Files (*.txt);;CSV Files (*.csv)"
        )
        if file_path:
            try:
                content = re.sub(r"<[^>]+>", "", self.event_log.toPlainText())
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                self.add_log_entry(_("mon_log_exported").format(file_path))
                QMessageBox.information(self, _("msg_success"), _("mon_export_success"))
            except Exception as e:
                self.add_log_entry(_("mon_export_fail_log").format(str(e)), "ERROR")
                QMessageBox.critical(self, _("msg_error"), _("mon_export_fail_msg").format(str(e)))

    def export_pdf(self) -> None:
        if not self.hosts:
            QMessageBox.warning(self, _("msg_warning"), _("mon_no_hosts"))
            return

        file_path, _filter = QFileDialog.getSaveFileName(
            self, _("mon_export_pdf_title"), "BahaaIT_Network_Report.pdf", "PDF Files (*.pdf)"
        )
        if file_path:
            data = []
            for ip, snap in self.hosts.items():
                data.append({
                    "label": snap.get("label", ip),
                    "ip": ip,
                    "status": snap.get("state", "UNKNOWN"),
                    "latency": snap.get("current_latency_ms") or snap.get("avg_latency_ms") or 0,
                    "availability": float(snap.get("uptime_pct", 100.0)),
                })

            event_log_text = self.event_log.toPlainText()
            generator = PDFReportGenerator()
            success, msg = generator.generate_monitor_report(data, file_path, event_log_text)
            if success:
                self.add_log_entry(_("mon_pdf_generated").format(file_path))
                QMessageBox.information(self, _("msg_success"), _("mon_pdf_export_success"))
            else:
                self.add_log_entry(_("mon_pdf_fail_log").format(msg), "ERROR")
                QMessageBox.critical(self, _("msg_error"), _("mon_pdf_fail_msg").format(msg))
