from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.syslog_parser import SYSLOG_SEVERITIES
from core.syslog_server import (
    SyslogServer,
    export_syslog_csv,
    export_syslog_json,
    get_windows_firewall_guidance,
)
from utils.db import DatabaseManager
from utils.i18n import _


_SEVERITY_COLORS = {
    0: "#F43F5E",  # Emergency
    1: "#F43F5E",  # Alert
    2: "#F43F5E",  # Critical
    3: "#FB7185",  # Error
    4: "#F59E0B",  # Warning
    5: "#38BDF8",  # Notice
    6: "#CBD5E1",  # Informational
    7: "#94A3B8",  # Debug
}

_SYSLOG_CATEGORIES = [
    "ALL",
    "FIREWALL_IF_DOWN",
    "LINK_DOWN",
    "LINK_UP",
    "REBOOT",
    "POE_OVERLOAD",
    "AUTH_FAIL",
    "CONFIG_CHANGE",
    "STP_CHANGE",
    "PORT_SECURITY",
    "HIGH_CPU",
    "HARDWARE_THERMAL",
    "GENERAL",
]


class SyslogView(QWidget):
    """Centralized Syslog Monitor UI (Navigation Index 12)."""

    def __init__(
        self,
        logger,
        config_manager=None,
        db: Optional[DatabaseManager] = None,
        server: Optional[SyslogServer] = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.logger = logger
        self.config_manager = config_manager
        self.db = db or DatabaseManager()
        self._injected_server = server is not None
        self.server = server
        self._paused = False
        self._displayed_events: List[Dict[str, Any]] = []

        self._init_bind = self.config_manager.get("syslog_bind_address", "0.0.0.0") if self.config_manager else "0.0.0.0"
        self._init_port = int(self.config_manager.get("syslog_port", 514)) if self.config_manager else 514
        self._max_pps = int(self.config_manager.get("syslog_max_pps", 2000)) if self.config_manager else 2000
        self._max_per_ip = int(self.config_manager.get("syslog_max_per_ip_pps", 500)) if self.config_manager else 500

        if self.server is None:
            self.server = self._create_server(self._init_bind, self._init_port)
        self._connect_server_signals(self.server)

        self._build_ui()
        self.refresh_table()

    def _create_server(self, bind_addr: str, port: int) -> SyslogServer:
        return SyslogServer(
            db=self.db,
            bind_address=bind_addr,
            port=port,
            max_packets_per_sec=self._max_pps,
            max_per_ip_per_sec=self._max_per_ip,
        )

    def _connect_server_signals(self, srv: SyslogServer) -> None:
        srv.events_batch_received.connect(self._on_events_batch)
        srv.stats_updated.connect(self._on_stats_updated)
        srv.flood_detected.connect(self._on_flood_detected)
        srv.server_started.connect(self._on_server_started)
        srv.server_stopped.connect(self._on_server_stopped)
        srv.server_error.connect(self._on_server_error)

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 22, 24, 22)
        root.setSpacing(12)

        # Header Row (Full Title + Badge + Primary Listener Actions)
        hdr = QHBoxLayout()
        hdr.setSpacing(10)
        title = QLabel(_("syslog_title", "Centralized Syslog Monitor"))
        title.setObjectName("Title")
        title.setWordWrap(True)
        title.setStyleSheet("font-size: 24px; font-weight: 800; color: #FFFFFF; margin-bottom: 0px;")
        hdr.addWidget(title, 1)

        self.status_badge = QLabel(_("syslog_status_stopped", "STOPPED"))
        self.status_badge.setStyleSheet(
            "background-color: #334155; color: #CBD5E1; border-radius: 8px; padding: 5px 12px; "
            "font-weight: 700; font-size: 11px; margin-bottom: 0px;"
        )
        hdr.addWidget(self.status_badge)

        self.btn_toggle_srv = QPushButton(_("syslog_btn_start", "Start Listener"))
        self.btn_toggle_srv.setObjectName("PrimaryButton")
        self.btn_toggle_srv.setCursor(Qt.PointingHandCursor)
        self.btn_toggle_srv.clicked.connect(self.toggle_listener)
        hdr.addWidget(self.btn_toggle_srv)

        self.btn_pause = QPushButton(_("syslog_btn_pause", "Pause Stream"))
        self.btn_pause.setObjectName("SecondaryButton")
        self.btn_pause.setCursor(Qt.PointingHandCursor)
        self.btn_pause.clicked.connect(self.toggle_pause)
        hdr.addWidget(self.btn_pause)

        self.btn_firewall = QPushButton(_("syslog_btn_firewall", "Windows Firewall Guide"))
        self.btn_firewall.setObjectName("SecondaryButton")
        self.btn_firewall.setCursor(Qt.PointingHandCursor)
        self.btn_firewall.clicked.connect(self.show_firewall_guide)
        hdr.addWidget(self.btn_firewall)
        root.addLayout(hdr)

        # Flood Warning Banner
        self.flood_banner = QLabel("")
        self.flood_banner.setWordWrap(True)
        self.flood_banner.setStyleSheet(
            "background-color: rgba(244,63,94,0.15); color: #FB7185; border: 1px solid #F43F5E; "
            "border-radius: 8px; padding: 8px 12px; font-weight: bold; margin-bottom: 0px;"
        )
        self.flood_banner.hide()
        root.addWidget(self.flood_banner)

        # Stats Strip (5 cards)
        stats_row = QHBoxLayout()
        stats_row.setSpacing(10)
        self.st_recv = self._make_stat_badge(stats_row, _("syslog_stat_received", "Received"), "0", "#FFFFFF")
        self.st_proc = self._make_stat_badge(stats_row, _("syslog_stat_processed", "Processed"), "0", "#10B981")
        self.st_pers = self._make_stat_badge(stats_row, _("syslog_stat_persisted", "Persisted"), "0", "#06B6D4")
        self.st_drop = self._make_stat_badge(stats_row, _("syslog_stat_dropped", "Dropped"), "0", "#F59E0B")
        self.st_mal = self._make_stat_badge(stats_row, _("syslog_stat_malformed", "Malformed"), "0", "#FB7185")
        root.addLayout(stats_row)

        # 2-Row Listener + Filter + Export Bar inside FilterBar (no squished 2-letter inputs!)
        ctrl_frame = QFrame()
        ctrl_frame.setObjectName("FilterBar")
        ctrl_lay = QVBoxLayout(ctrl_frame)
        ctrl_lay.setContentsMargins(12, 8, 12, 8)
        ctrl_lay.setSpacing(8)

        row1 = QHBoxLayout()
        row1.setSpacing(8)
        bind_lbl = QLabel(_("syslog_bind_label", "Bind:"))
        bind_lbl.setStyleSheet("margin-bottom: 0px; color: #94A3B8; font-weight: 600;")
        row1.addWidget(bind_lbl)
        self.bind_edit = QLineEdit(self._init_bind)
        self.bind_edit.setFixedWidth(120)
        row1.addWidget(self.bind_edit)

        port_lbl = QLabel(_("syslog_port_label", "UDP Port:"))
        port_lbl.setStyleSheet("margin-bottom: 0px; color: #94A3B8; font-weight: 600;")
        row1.addWidget(port_lbl)
        self.port_spin = QSpinBox()
        self.port_spin.setRange(0, 65535)
        self.port_spin.setValue(self._init_port)
        self.port_spin.setFixedWidth(92)
        self.port_spin.setToolTip("Standard UDP 514 (Admin) or 5514 (Non-Admin alternative)")
        row1.addWidget(self.port_spin)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText(_("syslog_filter_search", "Search message..."))
        self.search_edit.setMinimumWidth(180)
        self.search_edit.returnPressed.connect(self.refresh_table)
        row1.addWidget(self.search_edit, 2)

        self.ip_edit = QLineEdit()
        self.ip_edit.setPlaceholderText(_("syslog_filter_ip", "Source IP..."))
        self.ip_edit.setMinimumWidth(120)
        self.ip_edit.returnPressed.connect(self.refresh_table)
        row1.addWidget(self.ip_edit, 1)

        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText(_("syslog_filter_host", "Hostname..."))
        self.host_edit.setMinimumWidth(120)
        self.host_edit.returnPressed.connect(self.refresh_table)
        row1.addWidget(self.host_edit, 1)
        ctrl_lay.addLayout(row1)

        row2 = QHBoxLayout()
        row2.setSpacing(8)

        sev_lbl = QLabel(_("syslog_filter_sev", "Severity:"))
        sev_lbl.setStyleSheet("margin-bottom: 0px; color: #94A3B8; font-weight: 600;")
        row2.addWidget(sev_lbl)
        self.sev_combo = QComboBox()
        self.sev_combo.addItem(_("snmp_filter_all", "All"), None)
        self.sev_combo.addItem("<= Critical (2)", ("MAX", 2))
        self.sev_combo.addItem("<= Error (3)", ("MAX", 3))
        self.sev_combo.addItem("<= Warning (4)", ("MAX", 4))
        for sid, sname in SYSLOG_SEVERITIES.items():
            self.sev_combo.addItem(f"{sid} — {sname}", ("EXACT", sid))
        self.sev_combo.currentIndexChanged.connect(self.refresh_table)
        row2.addWidget(self.sev_combo)

        cat_lbl = QLabel(_("syslog_filter_cat", "Category:"))
        cat_lbl.setStyleSheet("margin-bottom: 0px; color: #94A3B8; font-weight: 600;")
        row2.addWidget(cat_lbl)
        self.cat_combo = QComboBox()
        for cat in _SYSLOG_CATEGORIES:
            lbl_cat = _("snmp_filter_all", "All") if cat == "ALL" else cat
            self.cat_combo.addItem(lbl_cat, cat)
        self.cat_combo.currentIndexChanged.connect(self.refresh_table)
        row2.addWidget(self.cat_combo)

        per_lbl = QLabel(_("syslog_filter_period", "Period:"))
        per_lbl.setStyleSheet("margin-bottom: 0px; color: #94A3B8; font-weight: 600;")
        row2.addWidget(per_lbl)
        self.period_combo = QComboBox()
        self.period_combo.addItem("1h", 1)
        self.period_combo.addItem("24h", 24)
        self.period_combo.addItem("7d", 24 * 7)
        self.period_combo.addItem(_("snmp_filter_all", "All"), 0)
        self.period_combo.setCurrentIndex(1)
        self.period_combo.currentIndexChanged.connect(self.refresh_table)
        row2.addWidget(self.period_combo)

        row2.addStretch()

        btn_apply = QPushButton(_("syslog_btn_apply", "Apply Filter"))
        btn_apply.setObjectName("SecondaryButton")
        btn_apply.setCursor(Qt.PointingHandCursor)
        btn_apply.clicked.connect(self.refresh_table)
        row2.addWidget(btn_apply)

        btn_csv = QPushButton(_("syslog_btn_export_csv", "Export CSV"))
        btn_csv.setObjectName("SecondaryButton")
        btn_csv.setCursor(Qt.PointingHandCursor)
        btn_csv.clicked.connect(lambda: self.export_csv(show_dialog=True))
        row2.addWidget(btn_csv)

        btn_json = QPushButton(_("syslog_btn_export_json", "Export JSON"))
        btn_json.setObjectName("SecondaryButton")
        btn_json.setCursor(Qt.PointingHandCursor)
        btn_json.clicked.connect(lambda: self.export_json(show_dialog=True))
        row2.addWidget(btn_json)
        ctrl_lay.addLayout(row2)
        root.addWidget(ctrl_frame)

        # Events Table (7 columns) + Detail Inspector inside QSplitter
        headers = [
            _("syslog_col_ts", "Timestamp"),
            _("syslog_col_ip", "Source IP"),
            _("syslog_col_host", "Hostname"),
            _("syslog_col_sev", "Severity"),
            _("syslog_col_cat", "Category"),
            _("syslog_col_app", "App / Tag"),
            _("syslog_col_msg", "Message"),
        ]
        self.table = QTableWidget(0, len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(34)
        th = self.table.horizontalHeader()
        th.setSectionResizeMode(QHeaderView.ResizeToContents)
        th.setSectionResizeMode(6, QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self._on_row_selected)

        det_container = QWidget()
        det_lay = QVBoxLayout(det_container)
        det_lay.setContentsMargins(0, 4, 0, 0)
        det_lay.setSpacing(6)
        det_hdr = QLabel(_("syslog_detail_hdr", "SELECTED SYSLOG EVENT DETAILS"))
        det_hdr.setStyleSheet("color: #06B6D4; font-weight: 700; font-size: 11px; margin-bottom: 0px;")
        det_lay.addWidget(det_hdr)

        self.detail_view = QTextEdit()
        self.detail_view.setReadOnly(True)
        self.detail_view.setMinimumHeight(76)
        self.detail_view.setStyleSheet(
            "QTextEdit { background-color: #0B1220; color: #F1F5F9; border: 1px solid #334155; border-radius: 8px; padding: 8px; font-family: Consolas, monospace; font-size: 12px; }"
        )
        det_lay.addWidget(self.detail_view, 1)

        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)
        splitter.addWidget(self.table)
        splitter.addWidget(det_container)
        splitter.setSizes([310, 115])
        root.addWidget(splitter, 1)

    @staticmethod
    def _make_stat_badge(layout: QHBoxLayout, title: str, init_val: str, color: str) -> QLabel:
        frame = QFrame()
        frame.setObjectName("KpiCard")
        fl = QVBoxLayout(frame)
        fl.setContentsMargins(10, 8, 10, 8)
        fl.setSpacing(2)
        val_lbl = QLabel(init_val)
        val_lbl.setAlignment(Qt.AlignCenter)
        val_lbl.setStyleSheet(f"font-size: 17px; font-weight: 800; color: {color}; margin-bottom: 0px;")
        t_lbl = QLabel(title.upper())
        t_lbl.setAlignment(Qt.AlignCenter)
        t_lbl.setWordWrap(True)
        t_lbl.setStyleSheet("font-size: 11px; color: #94A3B8; font-weight: 700; margin-bottom: 0px;")
        fl.addWidget(val_lbl)
        fl.addWidget(t_lbl)
        layout.addWidget(frame, 1)
        return val_lbl

    def start_listener(self) -> None:
        if self.server is not None and self.server.isRunning():
            return
        bind_addr = self.bind_edit.text().strip() or "0.0.0.0"
        port = int(self.port_spin.value())
        if self.config_manager is not None:
            self.config_manager.set("syslog_bind_address", bind_addr)
            self.config_manager.set("syslog_port", port)

        if not self._injected_server or (self.server is not None and self.server.isFinished()):
            self.server = self._create_server(bind_addr, port)
            self._connect_server_signals(self.server)
        else:
            self.server.reconfigure(bind_address=bind_addr, port=port)

        self.flood_banner.hide()
        self.server.start()

    def stop_listener(self) -> None:
        if self.server is not None and self.server.isRunning():
            self.server.stop(timeout_ms=3000)

    def toggle_listener(self) -> None:
        if self.server is not None and self.server.isRunning():
            self.stop_listener()
        else:
            self.start_listener()

    def toggle_pause(self) -> None:
        self._paused = not self._paused
        self.btn_pause.setText(
            _("syslog_btn_resume", "Resume Stream") if self._paused else _("syslog_btn_pause", "Pause Stream")
        )
        if not self._paused:
            self.refresh_table()

    def _on_server_started(self, _addr: str, actual_port: int) -> None:
        self.bind_edit.setEnabled(False)
        self.port_spin.setEnabled(False)
        self.btn_toggle_srv.setText(_("syslog_btn_stop", "Stop Listener"))
        self.status_badge.setText(_("syslog_status_listening", "LISTENING :{}").format(actual_port))
        self.status_badge.setStyleSheet(
            "background-color: rgba(16,185,129,0.2); color: #10B981; border: 1px solid #10B981; "
            "border-radius: 8px; padding: 5px 12px; font-weight: 700; font-size: 11px; margin-bottom: 0px;"
        )

    def _on_server_stopped(self) -> None:
        self.bind_edit.setEnabled(True)
        self.port_spin.setEnabled(True)
        self.btn_toggle_srv.setText(_("syslog_btn_start", "Start Listener"))
        self.status_badge.setText(_("syslog_status_stopped", "STOPPED"))
        self.status_badge.setStyleSheet(
            "background-color: #334155; color: #CBD5E1; border-radius: 8px; padding: 5px 12px; "
            "font-weight: 700; font-size: 11px; margin-bottom: 0px;"
        )

    def _on_server_error(self, msg: str) -> None:
        self._on_server_stopped()
        QMessageBox.warning(self, _("msg_error", "Error"), msg)

    def _on_flood_detected(self, info: Dict[str, Any]) -> None:
        dropped = int(info.get("dropped_rate_limit", 0)) + int(info.get("dropped_queue_full", 0))
        self.flood_banner.setText(
            _("syslog_flood_banner", "Flood protection triggered ({}): {} packet(s) dropped from {}").format(
                info.get("reason", "RATE_LIMIT"), dropped, info.get("source_ip", "unknown")
            )
        )
        self.flood_banner.show()

    def _on_stats_updated(self, st: Dict[str, Any]) -> None:
        self.st_recv.setText(str(st.get("received_packets", 0)))
        self.st_proc.setText(str(st.get("processed_events", 0)))
        self.st_pers.setText(str(st.get("persisted_events", 0)))
        dropped = int(st.get("dropped_rate_limit", 0)) + int(st.get("dropped_queue_full", 0))
        self.st_drop.setText(str(dropped))
        self.st_mal.setText(str(st.get("malformed_packets", 0)))

    def _matches_active_filters(self, ev: Dict[str, Any]) -> bool:
        ip_q = self.ip_edit.text().strip()
        if ip_q and ev.get("source_ip") != ip_q:
            return False
        host_q = self.host_edit.text().strip().lower()
        if host_q and host_q not in str(ev.get("hostname", "")).lower():
            return False
        cat_q = self.cat_combo.currentData() or "ALL"
        if cat_q != "ALL" and ev.get("event_category") != cat_q:
            return False
        sev_data = self.sev_combo.currentData()
        if sev_data is not None:
            mode, s_val = sev_data
            ev_sev = int(ev.get("severity", 6))
            if mode == "MAX" and ev_sev > s_val:
                return False
            if mode == "EXACT" and ev_sev != s_val:
                return False
        msg_q = self.search_edit.text().strip().lower()
        if msg_q and msg_q not in str(ev.get("message", "")).lower():
            return False
        return True

    def _on_events_batch(self, events: List[Dict[str, Any]]) -> None:
        if self._paused:
            return
        matched = [e for e in events if self._matches_active_filters(e)]
        if not matched:
            return
        self._displayed_events = (list(reversed(matched)) + self._displayed_events)[:500]
        self._render_table(self._displayed_events)

    def _query_filtered_events(self) -> List[Dict[str, Any]]:
        sev_data = self.sev_combo.currentData()
        max_sev = sev_data[1] if (sev_data and sev_data[0] == "MAX") else None
        exact_sevs = [sev_data[1]] if (sev_data and sev_data[0] == "EXACT") else None
        cat = self.cat_combo.currentData()
        hours = int(self.period_combo.currentData() or 0)
        since = datetime.utcnow() - timedelta(hours=hours) if hours > 0 else None
        return self.db.get_syslog_events(
            source_ip=self.ip_edit.text().strip() or None,
            hostname=self.host_edit.text().strip() or None,
            max_severity=max_sev,
            severities=exact_sevs,
            event_category=None if cat == "ALL" else cat,
            search_text=self.search_edit.text().strip() or None,
            since=since,
            limit=500,
        )

    def refresh_table(self) -> None:
        self._displayed_events = self._query_filtered_events()
        self._render_table(self._displayed_events)

    def _render_table(self, rows: List[Dict[str, Any]]) -> None:
        self.table.setRowCount(0)
        self.detail_view.clear()
        for ev in rows[:500]:
            r = self.table.rowCount()
            self.table.insertRow(r)
            ts = ev.get("timestamp")
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime) else str(ts or "")
            sev_num = int(ev.get("severity", 6))
            sev_str = f"{ev.get('severity_name', 'Informational')} ({sev_num})"

            self.table.setItem(r, 0, QTableWidgetItem(ts_str))
            self.table.setItem(r, 1, QTableWidgetItem(str(ev.get("source_ip", ""))))
            self.table.setItem(r, 2, QTableWidgetItem(str(ev.get("hostname", ""))))
            sev_it = QTableWidgetItem(sev_str)
            sev_it.setForeground(QColor(_SEVERITY_COLORS.get(sev_num, "#CBD5E1")))
            self.table.setItem(r, 3, sev_it)
            self.table.setItem(r, 4, QTableWidgetItem(str(ev.get("event_category", "GENERAL"))))
            self.table.setItem(r, 5, QTableWidgetItem(str(ev.get("app_name", ""))))
            self.table.setItem(r, 6, QTableWidgetItem(str(ev.get("message", ""))))

    def _on_row_selected(self) -> None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self._displayed_events):
            return
        ev = self._displayed_events[row]
        ts = ev.get("timestamp")
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC") if isinstance(ts, datetime) else str(ts or "")
        txt = (
            f"Timestamp: {ts_str} | Source: {ev.get('source_ip')} ({ev.get('hostname')}) | "
            f"Facility: {ev.get('facility_name')} ({ev.get('facility')}) | "
            f"Severity: {ev.get('severity_name')} ({ev.get('severity')}) | "
            f"Category: {ev.get('event_category')}\n"
            f"Raw Message: {ev.get('raw_message', ev.get('message', ''))}"
        )
        self.detail_view.setPlainText(txt)

    def show_firewall_guide(self) -> None:
        g = get_windows_firewall_guidance(int(self.port_spin.value()) or 514)
        body = _(
            "syslog_fw_body",
            "UDP Port {port}:\n\nPowerShell:\n{ps}\n\nnetsh:\n{netsh}",
        ).format(
            port=g["port"],
            alt_port=g["recommended_non_admin_port"],
            ps=g["powershell_cmd"],
            netsh=g["netsh_cmd"],
        )
        QGuiApplication.clipboard().setText(g["powershell_cmd"])
        QMessageBox.information(self, _("syslog_fw_title", "Windows Firewall & Privilege Guide"), body)

    def export_csv(self, file_path: Optional[str] = None, show_dialog: bool = False) -> int:
        if not file_path:
            file_path, _f = QFileDialog.getSaveFileName(self, "Export Syslog CSV", "syslog_events.csv", "CSV (*.csv)")
        if not file_path:
            return 0
        count = export_syslog_csv(self._displayed_events, file_path)
        if show_dialog:
            QMessageBox.information(self, _("msg_success", "Success"), _("syslog_export_ok", "Exported {} Syslog event(s).").format(count))
        return count

    def export_json(self, file_path: Optional[str] = None, show_dialog: bool = False) -> int:
        if not file_path:
            file_path, _f = QFileDialog.getSaveFileName(self, "Export Syslog JSON", "syslog_events.json", "JSON (*.json)")
        if not file_path:
            return 0
        count = export_syslog_json(self._displayed_events, file_path)
        if show_dialog:
            QMessageBox.information(self, _("msg_success", "Success"), _("syslog_export_ok", "Exported {} Syslog event(s).").format(count))
        return count

    def shutdown(self) -> None:
        if self.server is not None and self.server.isRunning():
            self.server.stop(timeout_ms=3000)
