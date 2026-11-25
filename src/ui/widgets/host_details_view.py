from datetime import datetime
import platform
import re
import subprocess
from typing import Any, Dict, List, Optional

import pyqtgraph as pg
from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.incident_manager import IncidentManager, IncidentStatus
from core.monitoring_state import MonitoringPolicyConfig, validate_target_address
from core.monitoring_statistics import MonitoringStatisticsService
from core.ping_engine import AsyncPingEngine
from core.scanner import Scanner
from core.tools import NetworkTools
from utils.db import DatabaseManager
from utils.i18n import _, escape_qt_mnemonic
from utils.monitoring_export import export_incidents_csv, export_incidents_pdf


_STATE_COLORS = {
    "UP": "#10B981",
    "DEGRADED": "#F59E0B",
    "DOWN": "#F43F5E",
    "RECOVERING": "#38BDF8",
    "PAUSED": "#94A3B8",
    "UNKNOWN": "#94A3B8",
}


class _DiagWorker(QThread):
    """Background worker for running explicit diagnostic actions from Host Details."""

    output_ready = Signal(str)

    def __init__(self, action: str, target: str, parent=None):
        super().__init__(parent)
        self.action = action
        self.target = target
        self._cancelled = False
        self._proc = None

    def cancel(self) -> None:
        self._cancelled = True
        if self._proc is not None:
            try:
                self._proc.terminate()
            except Exception:
                pass

    def run(self) -> None:
        ok, clean_target = validate_target_address(self.target)
        if not ok:
            self.output_ready.emit(f"Invalid target: {clean_target}")
            return

        is_win = platform.system().lower() == "windows"
        cflags = subprocess.CREATE_NO_WINDOW if is_win else 0
        enc = "cp850" if is_win else "utf-8"

        try:
            if self.action == "ping":
                cmd = ["ping", "-n" if is_win else "-c", "4", clean_target]
                self._proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding=enc, errors="replace", creationflags=cflags,
                )
                try:
                    out, _ = self._proc.communicate(timeout=12)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                    out, _ = self._proc.communicate()
                if not self._cancelled:
                    self.output_ready.emit(out or "No output.")
            elif self.action == "tracert":
                cmd = ["tracert", "-d", "-w", "1500", clean_target] if is_win else ["traceroute", "-n", clean_target]
                self._proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding=enc, errors="replace", creationflags=cflags,
                )
                try:
                    out, _ = self._proc.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                    out, _ = self._proc.communicate()
                if not self._cancelled:
                    self.output_ready.emit(out or "No output.")
            elif self.action == "dns":
                out = NetworkTools.nslookup(clean_target)
                if not self._cancelled:
                    self.output_ready.emit(out or "No DNS output.")
            elif self.action == "ports":
                scanner = Scanner()
                opened = scanner.scan_ports(clean_target, fast_mode=True)
                if not self._cancelled:
                    if opened:
                        self.output_ready.emit(f"Open common TCP ports on {clean_target}: {', '.join(map(str, opened))}")
                    else:
                        self.output_ready.emit(f"No common TCP ports open on {clean_target}.")
        except Exception as e:
            if not self._cancelled:
                self.output_ready.emit(f"Diagnostic error: {e}")


class HostDetailsDialog(QDialog):
    """Comprehensive Host Details dialog with live KPIs, 4 multi-period charts, incidents, settings & diagnostics."""

    policy_saved = Signal(str)
    incidents_changed = Signal()

    def __init__(
        self,
        host_address: str,
        host_label: str,
        db: DatabaseManager,
        engine: AsyncPingEngine,
        incident_manager: IncidentManager,
        stats_service: MonitoringStatisticsService,
        initial_snapshot: Optional[Dict[str, Any]] = None,
        parent=None,
    ):
        super().__init__(parent)
        self.host_address = host_address
        self.host_label = host_label or host_address
        self.db = db
        self.engine = engine
        self.incident_manager = incident_manager
        self.stats_service = stats_service
        self._current_period = "5m"
        self._diag_worker: Optional[_DiagWorker] = None
        self._latest_snapshot: Dict[str, Any] = initial_snapshot or engine.get_host_snapshot(host_address) or {}

        self.setWindowTitle(_("mon_details_title", "Host Monitoring Details — {}").format(f"{self.host_label} ({self.host_address})"))
        screen = QGuiApplication.primaryScreen()
        if screen is not None:
            avail = screen.availableGeometry()
            w = min(960, max(760, avail.width() - 60))
            h = min(640, max(500, avail.height() - 80))
            self.resize(w, h)
            self.move(avail.x() + (avail.width() - w) // 2, avail.y() + (avail.height() - h) // 2)
        else:
            self.resize(960, 640)
        self.setStyleSheet("QDialog { background-color: #0F172A; color: #F1F5F9; }")

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 14, 18, 14)
        root.setSpacing(10)

        # Header banner
        banner = QFrame()
        banner.setObjectName("PanelCard")
        banner_layout = QHBoxLayout(banner)
        banner_layout.setContentsMargins(16, 10, 16, 10)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        name_lbl = QLabel(f"{self.host_label}  •  {self.host_address}")
        name_lbl.setStyleSheet("font-size: 17px; font-weight: 800; color: #FFFFFF; margin-bottom: 0px;")
        self.sub_stats_lbl = QLabel("")
        self.sub_stats_lbl.setWordWrap(True)
        self.sub_stats_lbl.setStyleSheet("font-size: 12px; color: #94A3B8; margin-bottom: 0px;")
        title_col.addWidget(name_lbl)
        title_col.addWidget(self.sub_stats_lbl)

        self.state_badge = QLabel("UNKNOWN")
        self.state_badge.setAlignment(Qt.AlignCenter)
        self.state_badge.setFixedWidth(120)
        self.state_badge.setFixedHeight(30)

        banner_layout.addLayout(title_col, 1)
        banner_layout.addWidget(self.state_badge)
        root.addWidget(banner)

        # Sub-tabs
        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)

        self._build_charts_tab()
        self._build_incidents_tab()
        self._build_settings_tab()
        self._build_diag_tab()

        self.update_live_snapshot(self._latest_snapshot)
        self.refresh_charts()
        self.refresh_host_incidents()

        # Refresh charts smoothly every 2 seconds while open
        self._chart_timer = QTimer(self)
        self._chart_timer.timeout.connect(self.refresh_charts)
        self._chart_timer.start(2000)

    def _build_charts_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Time window selector row
        top_row = QHBoxLayout()
        top_row.addWidget(QLabel(_("mon_details_period", "Time Window:")))
        self.period_group = QButtonGroup(self)
        self.period_buttons: Dict[str, QPushButton] = {}
        for p in ("1m", "5m", "15m", "1h", "24h"):
            btn = QPushButton(p)
            btn.setCheckable(True)
            btn.setFixedWidth(56)
            btn.setFixedHeight(30)
            btn.setCursor(Qt.PointingHandCursor)
            if p == self._current_period:
                btn.setChecked(True)
            btn.clicked.connect(lambda checked, per=p: self._set_period(per))
            self.period_group.addButton(btn)
            self.period_buttons[p] = btn
            top_row.addWidget(btn)
        top_row.addStretch()
        self._style_period_buttons()
        layout.addLayout(top_row)

        pg.setConfigOption("background", "#0F172A")
        pg.setConfigOption("foreground", "#94A3B8")
        pg.setConfigOptions(antialias=True)

        grid = QGridLayout()
        grid.setSpacing(10)

        self.lat_plot, self.lat_curve = self._make_chart(_("mon_chart_latency", "Latency (ms)"), "#38BDF8", (56, 189, 248, 45))
        self.loss_plot, self.loss_curve = self._make_chart(_("mon_chart_loss", "Packet Loss (%)"), "#F43F5E", (244, 63, 94, 45), y_range=(0, 100))
        self.jit_plot, self.jit_curve = self._make_chart(_("mon_chart_jitter", "Jitter (ms)"), "#F59E0B", (245, 158, 11, 45))
        self.up_plot, self.up_curve = self._make_chart(_("mon_chart_uptime", "Availability (%)"), "#10B981", (16, 185, 129, 45), y_range=(0, 100))

        grid.addWidget(self.lat_plot, 0, 0)
        grid.addWidget(self.loss_plot, 0, 1)
        grid.addWidget(self.jit_plot, 1, 0)
        grid.addWidget(self.up_plot, 1, 1)
        layout.addLayout(grid, 1)

        self.tabs.addTab(tab, escape_qt_mnemonic(_("mon_details_tab_charts", "Live Stats & Charts")))

    @staticmethod
    def _make_chart(title: str, line_hex: str, brush_rgba, y_range=None):
        plot = pg.PlotWidget()
        plot.setBackground("#0F172A")
        plot.setMenuEnabled(False)
        plot.setTitle(title, color="#F1F5F9", size="10pt")
        plot.getAxis("bottom").setTextPen("#94A3B8")
        plot.getAxis("left").setTextPen("#94A3B8")
        plot.showGrid(x=True, y=True, alpha=0.25)
        if y_range is not None:
            plot.setYRange(y_range[0], y_range[1], padding=0.05)
        pen = pg.mkPen(color=line_hex, width=2)
        curve = plot.plot([], pen=pen, fillLevel=0, brush=brush_rgba)
        return plot, curve

    def _style_period_buttons(self) -> None:
        for p, btn in self.period_buttons.items():
            if p == self._current_period:
                btn.setStyleSheet(
                    "QPushButton { background-color: #4F46E5; color: #FFFFFF; border: none; border-radius: 6px; font-weight: 700; padding: 4px 8px; }"
                )
            else:
                btn.setStyleSheet(
                    "QPushButton { background-color: #1E293B; color: #CBD5E1; border: 1px solid #334155; border-radius: 6px; padding: 4px 8px; }"
                    "QPushButton:hover { border-color: #6366F1; color: #FFFFFF; background-color: #242F42; }"
                )

    def _set_period(self, period: str) -> None:
        self._current_period = period
        self._style_period_buttons()
        self.refresh_charts()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self.refresh_charts()

    def refresh_charts(self) -> None:
        if not self.isVisible():
            return
        series = self.stats_service.get_chart_series(self.host_address, period=self._current_period)
        if not series:
            self.lat_curve.setData([], [])
            self.loss_curve.setData([], [])
            self.jit_curve.setData([], [])
            self.up_curve.setData([], [])
            return
        xs = list(range(len(series)))
        self.lat_curve.setData(xs, [pt["latency_ms"] for pt in series])
        self.loss_curve.setData(xs, [pt["packet_loss_pct"] for pt in series])
        self.jit_curve.setData(xs, [pt["jitter_ms"] for pt in series])
        self.up_curve.setData(xs, [pt["uptime_pct"] for pt in series])

    def _build_incidents_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        self.inc_table = QTableWidget(0, 7)
        self.inc_table.setHorizontalHeaderLabels([
            _("inc_col_uid", "Incident ID"),
            _("inc_col_severity", "Severity"),
            _("inc_col_type", "Type"),
            _("inc_col_status", "Status"),
            _("inc_col_start", "Start Time"),
            _("inc_col_duration", "Duration"),
            _("inc_col_comments", "Comments"),
        ])
        ih = self.inc_table.horizontalHeader()
        ih.setSectionResizeMode(QHeaderView.Stretch)
        ih.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        ih.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        ih.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        ih.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.inc_table.verticalHeader().setVisible(False)
        self.inc_table.verticalHeader().setDefaultSectionSize(34)
        self.inc_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.inc_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.inc_table.setAlternatingRowColors(True)
        self.inc_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.inc_table, 1)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        ack_btn = QPushButton(_("inc_btn_ack", "Acknowledge"))
        ack_btn.setObjectName("PrimaryButton")
        ack_btn.setCursor(Qt.PointingHandCursor)
        ack_btn.clicked.connect(self._ack_host_incident)

        comment_btn = QPushButton(_("inc_btn_comment", "Add Comment"))
        comment_btn.setObjectName("SecondaryButton")
        comment_btn.setCursor(Qt.PointingHandCursor)
        comment_btn.clicked.connect(self._comment_host_incident)

        close_btn = QPushButton(_("inc_btn_close", "Close Incident"))
        close_btn.setObjectName("SecondaryButton")
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.clicked.connect(self._close_host_incident)

        self.del_inc_btn = QPushButton(_("inc_btn_delete", "Delete Incident"))
        self.del_inc_btn.setObjectName("DangerButton")
        self.del_inc_btn.setCursor(Qt.PointingHandCursor)
        self.del_inc_btn.clicked.connect(self._delete_host_incident)

        export_csv_btn = QPushButton(_("inc_btn_export_csv", "Export CSV"))
        export_csv_btn.setObjectName("SecondaryButton")
        export_csv_btn.setCursor(Qt.PointingHandCursor)
        export_csv_btn.clicked.connect(self._export_host_incidents_csv)

        export_pdf_btn = QPushButton(_("inc_btn_export_pdf", "Export PDF"))
        export_pdf_btn.setObjectName("SecondaryButton")
        export_pdf_btn.setCursor(Qt.PointingHandCursor)
        export_pdf_btn.clicked.connect(self._export_host_incidents_pdf)

        btn_row.addWidget(ack_btn)
        btn_row.addWidget(comment_btn)
        btn_row.addWidget(close_btn)
        btn_row.addWidget(self.del_inc_btn)
        btn_row.addStretch()
        btn_row.addWidget(export_csv_btn)
        btn_row.addWidget(export_pdf_btn)
        layout.addLayout(btn_row)

        self._host_incident_rows: List[Dict[str, Any]] = []
        self.tabs.addTab(tab, _("mon_details_tab_incidents", "Incident History"))

    def _selected_incident_id(self) -> Optional[int]:
        row = self.inc_table.currentRow()
        if row < 0 and self.inc_table.selectionModel() is not None:
            selected = self.inc_table.selectionModel().selectedRows()
            if selected:
                row = selected[0].row()
        if row < 0:
            return None
        item = self.inc_table.item(row, 0)
        return item.data(Qt.UserRole) if item else None

    def refresh_host_incidents(self) -> None:
        selected_id = self._selected_incident_id()
        rows = self.incident_manager.get_incidents(host_address=self.host_address, limit=200)
        self._host_incident_rows = rows
        self.inc_table.setRowCount(0)
        restore_row = -1
        for inc in rows:
            row = self.inc_table.rowCount()
            self.inc_table.insertRow(row)
            if selected_id is not None and inc["id"] == selected_id:
                restore_row = row
            dur = float(inc.get("duration_seconds", 0.0))
            dur_s = f"{int(dur)}s" if dur < 60 else f"{int(dur // 60)}m {int(dur % 60)}s"
            start_ts = inc.get("start_time")
            start_s = start_ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(start_ts, datetime) else str(start_ts or "")

            uid_item = QTableWidgetItem(inc["incident_uid"])
            uid_item.setData(Qt.UserRole, inc["id"])
            vals = [
                uid_item,
                QTableWidgetItem(inc["severity"]),
                QTableWidgetItem(inc["incident_type"]),
                QTableWidgetItem(inc["status"]),
                QTableWidgetItem(start_s),
                QTableWidgetItem(dur_s),
                QTableWidgetItem((inc.get("comments") or "").replace("\n", " | ")),
            ]
            for c, it in enumerate(vals):
                it.setTextAlignment(Qt.AlignCenter)
                self.inc_table.setItem(row, c, it)

        if restore_row >= 0:
            self.inc_table.selectRow(restore_row)
            self.inc_table.setCurrentCell(restore_row, 0)

    def _ack_host_incident(self) -> None:
        inc_id = self._selected_incident_id()
        if inc_id is None:
            QMessageBox.information(self, _("msg_info"), _("inc_none_selected", "Please select an incident first."))
            return
        note, ok = QInputDialog.getText(self, _("inc_btn_ack", "Acknowledge"), _("inc_ack_prompt", "Optional technician acknowledgement note:"))
        if ok:
            self.incident_manager.acknowledge_incident(inc_id, note)
            self.refresh_host_incidents()
            self.incidents_changed.emit()

    def _comment_host_incident(self) -> None:
        inc_id = self._selected_incident_id()
        if inc_id is None:
            QMessageBox.information(self, _("msg_info"), _("inc_none_selected", "Please select an incident first."))
            return
        note, ok = QInputDialog.getText(self, _("inc_btn_comment", "Add Comment"), _("inc_comment_prompt", "Add technician comment:"))
        if ok and note.strip():
            self.incident_manager.add_comment(inc_id, note)
            self.refresh_host_incidents()
            self.incidents_changed.emit()

    def _close_host_incident(self) -> None:
        inc_id = self._selected_incident_id()
        if inc_id is None:
            QMessageBox.information(self, _("msg_info"), _("inc_none_selected", "Please select an incident first."))
            return
        self.incident_manager.close_incident(inc_id)
        self.refresh_host_incidents()
        self.incidents_changed.emit()

    def _delete_host_incident(self) -> bool:
        inc_id = self._selected_incident_id()
        if inc_id is None:
            QMessageBox.information(self, _("msg_info"), _("inc_none_selected", "Please select an incident first."))
            return False
        reply = QMessageBox.question(
            self,
            _("inc_delete_confirm_title", "Delete Incident"),
            _("inc_delete_confirm_msg", "Are you sure you want to permanently delete this incident?"),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return False
        if self.incident_manager.delete_incident(inc_id):
            self.refresh_host_incidents()
            self.incidents_changed.emit()
            return True
        return False

    def _export_host_incidents_csv(self) -> None:
        rows = self.incident_manager.get_incidents(host_address=self.host_address, limit=200)
        self._host_incident_rows = rows
        safe_addr = re.sub(r'[<>:"/\\|?*]', "_", str(self.host_address))
        path, _f = QFileDialog.getSaveFileName(
            self, _("inc_btn_export_csv", "Export CSV"), f"BahaaIT_Incidents_{safe_addr}.csv", "CSV Files (*.csv)"
        )
        if not path:
            return
        ok, err = export_incidents_csv(rows, path)
        if ok:
            QMessageBox.information(self, _("msg_success"), _("inc_export_ok", "Incidents exported successfully."))
        else:
            QMessageBox.critical(self, _("msg_error"), err)

    def _export_host_incidents_pdf(self) -> None:
        rows = self.incident_manager.get_incidents(host_address=self.host_address, limit=200)
        self._host_incident_rows = rows
        safe_addr = re.sub(r'[<>:"/\\|?*]', "_", str(self.host_address))
        path, _f = QFileDialog.getSaveFileName(
            self, _("inc_btn_export_pdf", "Export PDF"), f"BahaaIT_Incidents_{safe_addr}.pdf", "PDF Files (*.pdf)"
        )
        if not path:
            return
        ok, err = export_incidents_pdf(rows, path)
        if ok:
            QMessageBox.information(self, _("msg_success"), _("inc_export_ok", "Incidents exported successfully."))
        else:
            QMessageBox.critical(self, _("msg_error"), err)

    def _build_settings_tab(self) -> None:
        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(10)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("background: transparent;")

        scroll_body = QWidget()
        scroll_body.setStyleSheet("background: transparent;")
        cols_layout = QHBoxLayout(scroll_body)
        cols_layout.setContentsMargins(4, 4, 8, 4)
        cols_layout.setSpacing(24)

        left_form = QFormLayout()
        left_form.setSpacing(10)
        right_form = QFormLayout()
        right_form.setSpacing(10)

        host_row = next((h for h in self.db.get_hosts() if h["address"] == self.host_address), None)
        self._host_db_id = host_row["id"] if host_row else None
        existing_policy = self.db.get_policy(self._host_db_id) if self._host_db_id else None
        cfg = MonitoringPolicyConfig.from_dict(existing_policy) if existing_policy else MonitoringPolicyConfig(**self.engine.global_policy.to_dict())

        self.cat_combo = QComboBox()
        self.cat_combo.addItems(["General", "Router / Firewall", "Switch", "Wi-Fi AP", "Server", "WAN / ISP", "Printer / IoT"])
        if host_row:
            self.cat_combo.setCurrentText(host_row.get("category", "General"))

        self.prof_combo = QComboBox()
        self.prof_combo.addItems(["Standard", "Critical Core", "WAN / High Latency", "Strict LAN"])
        if host_row:
            self.prof_combo.setCurrentText(host_row.get("profile", "Standard"))

        self.sp_interval = QSpinBox()
        self.sp_interval.setRange(100, 60000)
        self.sp_interval.setValue(cfg.probe_interval_ms)

        self.sp_timeout = QSpinBox()
        self.sp_timeout.setRange(100, 10000)
        self.sp_timeout.setValue(cfg.timeout_ms)

        self.sp_warn_fail = QSpinBox()
        self.sp_warn_fail.setRange(1, 50)
        self.sp_warn_fail.setValue(cfg.warning_failures)

        self.sp_crit_fail = QSpinBox()
        self.sp_crit_fail.setRange(1, 100)
        self.sp_crit_fail.setValue(cfg.critical_failures)

        self.sp_rec_ok = QSpinBox()
        self.sp_rec_ok.setRange(1, 50)
        self.sp_rec_ok.setValue(cfg.recovery_successes)

        self.sp_window = QSpinBox()
        self.sp_window.setRange(10, 3600)
        self.sp_window.setValue(cfg.rolling_window_sec)

        self.sp_loss = QDoubleSpinBox()
        self.sp_loss.setRange(0.5, 100.0)
        self.sp_loss.setValue(cfg.packet_loss_warn_pct)

        self.sp_lat = QDoubleSpinBox()
        self.sp_lat.setRange(5.0, 5000.0)
        self.sp_lat.setValue(cfg.latency_warn_ms)

        self.sp_jit = QDoubleSpinBox()
        self.sp_jit.setRange(1.0, 2000.0)
        self.sp_jit.setValue(cfg.jitter_warn_ms)

        for sp in (
            self.sp_interval, self.sp_timeout, self.sp_warn_fail, self.sp_crit_fail,
            self.sp_rec_ok, self.sp_window, self.sp_loss, self.sp_lat, self.sp_jit,
        ):
            sp.setMinimumWidth(110)

        self.chk_sound = QCheckBox(_("mon_host_cfg_sound", "Enable Critical Sound Alarm"))
        self.chk_sound.setChecked(cfg.sound_enabled)
        self.chk_email = QCheckBox(_("mon_host_cfg_email", "Enable Email Alerts"))
        self.chk_email.setChecked(cfg.email_enabled)
        self.chk_win = QCheckBox(_("mon_host_cfg_win_notify", "Enable Windows Desktop Notifications"))
        self.chk_win.setChecked(cfg.windows_notify_enabled)

        left_form.addRow(_("mon_host_cfg_category", "Category:"), self.cat_combo)
        left_form.addRow(_("mon_host_cfg_profile", "Monitoring Profile:"), self.prof_combo)
        left_form.addRow(_("mon_host_cfg_interval", "Probe Interval (ms):"), self.sp_interval)
        left_form.addRow(_("mon_host_cfg_timeout", "Timeout (ms):"), self.sp_timeout)
        left_form.addRow(_("mon_host_cfg_warn_fail", "Warning Failures:"), self.sp_warn_fail)
        left_form.addRow(_("mon_host_cfg_crit_fail", "Critical Failures (DOWN):"), self.sp_crit_fail)
        left_form.addRow(_("mon_host_cfg_rec_ok", "Recovery Successes:"), self.sp_rec_ok)

        right_form.addRow(_("mon_host_cfg_window", "Rolling Window (s):"), self.sp_window)
        right_form.addRow(_("mon_host_cfg_loss_warn", "Packet Loss Warning (%):"), self.sp_loss)
        right_form.addRow(_("mon_host_cfg_lat_warn", "Latency Warning (ms):"), self.sp_lat)
        right_form.addRow(_("mon_host_cfg_jit_warn", "Jitter Warning (ms):"), self.sp_jit)
        right_form.addRow("", self.chk_sound)
        right_form.addRow("", self.chk_email)
        right_form.addRow("", self.chk_win)

        cols_layout.addLayout(left_form, 1)
        cols_layout.addLayout(right_form, 1)
        scroll.setWidget(scroll_body)
        outer.addWidget(scroll, 1)

        btn_row = QHBoxLayout()
        save_btn = QPushButton(_("mon_host_cfg_save", "Save Host Settings"))
        save_btn.setObjectName("PrimaryButton")
        save_btn.setCursor(Qt.PointingHandCursor)
        save_btn.clicked.connect(self._save_host_settings)
        reset_btn = QPushButton(_("mon_host_cfg_reset", "Reset to Global Defaults"))
        reset_btn.setObjectName("SecondaryButton")
        reset_btn.setCursor(Qt.PointingHandCursor)
        reset_btn.clicked.connect(self._reset_host_settings)
        btn_row.addWidget(save_btn)
        btn_row.addWidget(reset_btn)
        btn_row.addStretch()
        outer.addLayout(btn_row)

        self.tabs.addTab(tab, _("mon_details_tab_settings", "Host Settings"))

    def _save_host_settings(self) -> None:
        cfg = MonitoringPolicyConfig(
            probe_interval_ms=self.sp_interval.value(),
            timeout_ms=self.sp_timeout.value(),
            warning_failures=self.sp_warn_fail.value(),
            critical_failures=self.sp_crit_fail.value(),
            recovery_successes=self.sp_rec_ok.value(),
            rolling_window_sec=self.sp_window.value(),
            packet_loss_warn_pct=float(self.sp_loss.value()),
            latency_warn_ms=float(self.sp_lat.value()),
            jitter_warn_ms=float(self.sp_jit.value()),
            sound_enabled=self.chk_sound.isChecked(),
            email_enabled=self.chk_email.isChecked(),
            windows_notify_enabled=self.chk_win.isChecked(),
        )
        try:
            cfg.validate()
        except ValueError as e:
            QMessageBox.warning(self, _("msg_error"), str(e))
            return

        self.db.update_host_metadata(
            self.host_address,
            category=self.cat_combo.currentText(),
            profile=self.prof_combo.currentText(),
        )
        if self._host_db_id is not None:
            self.db.save_policy(cfg.to_dict(), host_id=self._host_db_id)
        self.engine.update_host_policy(self.host_address, cfg)
        self.policy_saved.emit(self.host_address)
        QMessageBox.information(self, _("msg_success"), _("mon_host_cfg_saved", "Host monitoring settings saved."))

    def _reset_host_settings(self) -> None:
        if self._host_db_id is not None:
            self.db.delete_host_policy(self._host_db_id)
        cfg = MonitoringPolicyConfig(**self.engine.global_policy.to_dict())
        self.sp_interval.setValue(cfg.probe_interval_ms)
        self.sp_timeout.setValue(cfg.timeout_ms)
        self.sp_warn_fail.setValue(cfg.warning_failures)
        self.sp_crit_fail.setValue(cfg.critical_failures)
        self.sp_rec_ok.setValue(cfg.recovery_successes)
        self.sp_window.setValue(cfg.rolling_window_sec)
        self.sp_loss.setValue(cfg.packet_loss_warn_pct)
        self.sp_lat.setValue(cfg.latency_warn_ms)
        self.sp_jit.setValue(cfg.jitter_warn_ms)
        self.chk_sound.setChecked(cfg.sound_enabled)
        self.chk_email.setChecked(cfg.email_enabled)
        self.chk_win.setChecked(cfg.windows_notify_enabled)
        self.engine.update_host_policy(self.host_address, cfg)

    def _build_diag_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        self._diag_buttons = []
        for action, key, fallback in (
            ("ping", "mon_diag_ping", "Ping (4x)"),
            ("tracert", "mon_diag_tracert", "Traceroute"),
            ("dns", "mon_diag_dns", "DNS Lookup"),
            ("ports", "mon_diag_ports", "Check Common Ports"),
        ):
            btn = QPushButton(_(key, fallback))
            btn.setObjectName("SecondaryButton")
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda checked=False, act=action: self._run_diag(act))
            btn_row.addWidget(btn)
            self._diag_buttons.append(btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self.diag_output = QTextEdit()
        self.diag_output.setReadOnly(True)
        self.diag_output.setStyleSheet(
            "QTextEdit { background-color: #090D16; color: #E2E8F0; font-family: 'Consolas', monospace; font-size: 12px; border: 1px solid #334155; border-radius: 10px; padding: 10px; }"
        )
        layout.addWidget(self.diag_output, 1)
        self.tabs.addTab(tab, _("mon_details_tab_diag", "Diagnostics"))

    def _run_diag(self, action: str) -> None:
        if self._diag_worker and self._diag_worker.isRunning():
            return
        for b in self._diag_buttons:
            b.setEnabled(False)
        self.diag_output.setPlainText(_("mon_diag_running", "Running {} on {}...").format(action.upper(), self.host_address))
        worker = _DiagWorker(action, self.host_address, self)
        self._diag_worker = worker
        worker.output_ready.connect(self.diag_output.setPlainText)
        worker.finished.connect(lambda w=worker: self._on_diag_finished(w))
        worker.start()

    def _on_diag_finished(self, worker: _DiagWorker) -> None:
        if self._diag_worker is worker:
            self._diag_worker = None
        for b in getattr(self, "_diag_buttons", []):
            b.setEnabled(True)
        worker.deleteLater()

    def update_live_snapshot(self, snap: Dict[str, Any]) -> None:
        if not snap:
            return
        self._latest_snapshot = snap
        state = str(snap.get("state", "UNKNOWN")).upper()
        color = _STATE_COLORS.get(state, "#94A3B8")
        self.state_badge.setText(state)
        self.state_badge.setStyleSheet(
            f"background-color: rgba(15, 23, 42, 0.8); color: {color}; border: 1.5px solid {color}; border-radius: 8px; font-weight: 800; font-size: 12px; margin-bottom: 0px;"
        )

        cur = snap.get("current_latency_ms")
        cur_s = f"{cur:.1f} ms" if cur is not None else "--"
        last_ok = snap.get("last_success_utc")
        last_fail = snap.get("last_failure_utc")
        ok_s = last_ok.strftime("%H:%M:%S") if isinstance(last_ok, datetime) else "--"
        fail_s = last_fail.strftime("%H:%M:%S") if isinstance(last_fail, datetime) else "--"

        summary = (
            f"Current: {cur_s}  |  "
            f"{_('mon_details_min', 'Min')}/{_('mon_col_avg', 'Average')}/{_('mon_details_max', 'Max')}/{_('mon_details_p95', 'P95')}: "
            f"{snap.get('min_latency_ms', 0.0):.1f} / {snap.get('avg_latency_ms', 0.0):.1f} / {snap.get('max_latency_ms', 0.0):.1f} / {snap.get('p95_latency_ms', 0.0):.1f} ms  |  "
            f"Jitter: {snap.get('jitter_ms', 0.0):.1f} ms  |  "
            f"Loss: {snap.get('packet_loss_pct', 0.0):.1f}%  |  "
            f"Uptime: {snap.get('uptime_pct', 100.0):.2f}%  |  "
            f"{_('mon_col_last_resp', 'Last Response')}: {ok_s}  |  "
            f"{_('mon_details_last_fail', 'Last Failure')}: {fail_s}"
        )
        self.sub_stats_lbl.setText(summary)

    def closeEvent(self, event) -> None:
        if hasattr(self, "_chart_timer") and self._chart_timer:
            self._chart_timer.stop()
        if self._diag_worker and self._diag_worker.isRunning():
            self._diag_worker.cancel()
            self._diag_worker.wait(1500)
        super().closeEvent(event)
