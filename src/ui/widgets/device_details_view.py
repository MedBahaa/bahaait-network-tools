import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional

import pyqtgraph as pg
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
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

from core.device_health import compute_cpu_average, format_uptime, resolve_temperature_thresholds
from core.intelligence_engine import IntelligenceEngine
from core.interface_monitor import filter_interfaces
from core.snmp_engine import AsyncSNMPEngine
from core.snmp_profiles import SNMP_PROFILES, get_profile
from utils.db import DatabaseManager
from utils.i18n import _, escape_qt_mnemonic


_STATUS_COLORS = {
    "ONLINE": "#10B981",
    "UP": "#10B981",
    "NORMAL": "#10B981",
    "ACTIVE": "#10B981",
    "DELIVERING": "#10B981",
    "RESOLVED": "#10B981",
    "DEGRADED": "#F59E0B",
    "WARNING": "#F59E0B",
    "DORMANT": "#F59E0B",
    "ACKNOWLEDGED": "#F59E0B",
    "TESTING": "#38BDF8",
    "INFO": "#38BDF8",
    "OFFLINE": "#F43F5E",
    "DOWN": "#F43F5E",
    "CRITICAL": "#F43F5E",
    "FAULT": "#F43F5E",
    "UNKNOWN": "#94A3B8",
    "NOT_PRESENT": "#64748B",
}


class _PollDeviceWorker(QThread):
    """Runs an on-demand asynchronous SNMP poll without blocking the Qt GUI thread."""

    finished_poll = Signal(object)
    failed_poll = Signal(str)

    def __init__(self, snmp_engine: AsyncSNMPEngine, device_id: int, parent=None) -> None:
        super().__init__(parent)
        self.snmp_engine = snmp_engine
        self.device_id = int(device_id)

    def run(self) -> None:
        try:
            snap = asyncio.run(self.snmp_engine.poll_device_by_id(self.device_id))
            self.snmp_engine.flush_now()
            self.finished_poll.emit(snap)
        except Exception as e:
            self.failed_poll.emit(str(e))


def _make_plot(title: str = "") -> pg.PlotWidget:
    pw = pg.PlotWidget()
    pw.setBackground("#0F172A")
    pw.showGrid(x=True, y=True, alpha=0.15)
    pw.setMenuEnabled(False)
    pw.setMouseEnabled(x=True, y=False)
    if title:
        pw.setTitle(title, color="#CBD5E1", size="10pt")
    pw.getAxis("bottom").setTextPen("#94A3B8")
    pw.getAxis("left").setTextPen("#94A3B8")
    return pw


def _format_bytes(num_bytes: Optional[float]) -> str:
    if num_bytes is None:
        return "N/A"
    b = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024.0:
            return f"{b:.1f} {unit}"
        b /= 1024.0
    return f"{b:.1f} PB"


def _make_readonly_table(headers: List[str]) -> QTableWidget:
    tbl = QTableWidget(0, len(headers))
    tbl.setHorizontalHeaderLabels(headers)
    tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)
    tbl.setSelectionBehavior(QAbstractItemView.SelectRows)
    tbl.setSelectionMode(QAbstractItemView.SingleSelection)
    tbl.verticalHeader().setVisible(False)
    tbl.verticalHeader().setDefaultSectionSize(34)
    tbl.setAlternatingRowColors(True)
    tbl.horizontalHeader().setStretchLastSection(True)
    tbl.setStyleSheet(
        "QTableWidget { background-color: #0F172A; alternate-background-color: #162032; "
        "border: 1px solid #334155; border-radius: 8px; color: #F1F5F9; gridline-color: rgba(255,255,255,0.05); }"
        "QTableWidget::item { padding: 4px 6px; }"
        "QTableWidget::item:selected { background-color: rgba(79, 70, 229, 0.38); color: #FFFFFF; }"
        "QHeaderView::section { background-color: #1E293B; color: #CBD5E1; font-weight: 700; border: none; "
        "border-bottom: 1px solid #334155; padding: 6px; font-size: 11px; }"
    )
    return tbl


class DeviceDetailsDialog(QDialog):
    """10-tab capability-gated SNMP Device Intelligence details dialog."""

    def __init__(
        self,
        db: DatabaseManager,
        device_id: int,
        snmp_engine: Optional[AsyncSNMPEngine] = None,
        intelligence_engine: Optional[IntelligenceEngine] = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.db = db
        self.device_id = int(device_id)
        self.snmp_engine = snmp_engine
        self.intelligence_engine = intelligence_engine or IntelligenceEngine(db=self.db)
        self._poll_worker: Optional[_PollDeviceWorker] = None
        self._iface_filter_mode = "ALL"

        dev = self.db.get_snmp_device(self.device_id)
        dev_name = dev.get("name", f"Device #{self.device_id}") if dev else f"Device #{self.device_id}"
        self.setWindowTitle(_("devdet_title", "Device Intelligence Details — {}").format(dev_name))
        screen = QGuiApplication.primaryScreen()
        if screen is not None:
            avail = screen.availableGeometry()
            w = min(1100, int(avail.width() * 0.92))
            h = min(740, int(avail.height() * 0.88))
            self.setMinimumSize(min(900, w), min(580, h))
            self.resize(w, h)
            self.move(avail.x() + (avail.width() - w) // 2, avail.y() + (avail.height() - h) // 2)
        else:
            self.setMinimumSize(900, 580)
            self.resize(1060, 720)
        self.setStyleSheet("QDialog { background-color: #0F172A; color: #F1F5F9; }")

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(10)

        # Header Card
        header_card = QFrame()
        header_card.setObjectName("PanelCard")
        h_lay = QHBoxLayout(header_card)
        h_lay.setContentsMargins(16, 12, 16, 12)
        h_lay.setSpacing(12)

        left_info = QVBoxLayout()
        left_info.setSpacing(2)
        self.hdr_name_lbl = QLabel(dev_name)
        self.hdr_name_lbl.setStyleSheet("font-size: 18px; font-weight: 800; color: #FFFFFF; margin-bottom: 0px;")
        self.hdr_sub_lbl = QLabel("")
        self.hdr_sub_lbl.setWordWrap(True)
        self.hdr_sub_lbl.setStyleSheet("font-size: 12px; color: #94A3B8; margin-bottom: 0px;")
        left_info.addWidget(self.hdr_name_lbl)
        left_info.addWidget(self.hdr_sub_lbl)
        h_lay.addLayout(left_info, 1)

        self.hdr_uptime_lbl = QLabel(f"{_('devdet_uptime', 'Uptime:')} N/A")
        self.hdr_uptime_lbl.setStyleSheet("font-size: 12px; color: #CBD5E1; font-weight: 600; margin-bottom: 0px;")
        h_lay.addWidget(self.hdr_uptime_lbl)

        self.hdr_status_badge = QLabel("UNKNOWN")
        self.hdr_status_badge.setAlignment(Qt.AlignCenter)
        self.hdr_status_badge.setMinimumWidth(96)
        self.hdr_status_badge.setStyleSheet(
            "background-color: #334155; color: #F1F5F9; border-radius: 8px; padding: 6px 10px; font-weight: 700; margin-bottom: 0px;"
        )
        h_lay.addWidget(self.hdr_status_badge)

        self.btn_poll_now = QPushButton(_("devdet_poll_now", "Poll Now"))
        self.btn_poll_now.setObjectName("PrimaryButton")
        self.btn_poll_now.setCursor(Qt.PointingHandCursor)
        self.btn_poll_now.setEnabled(self.snmp_engine is not None and dev is not None)
        if self.snmp_engine is None:
            self.btn_poll_now.setToolTip(_("snmp_status_stopped", "SNMP Polling Engine not attached in this context"))
        self.btn_poll_now.clicked.connect(self._on_poll_now)
        h_lay.addWidget(self.btn_poll_now)

        self.btn_refresh = QPushButton(_("devdet_refresh", "Refresh"))
        self.btn_refresh.setObjectName("SecondaryButton")
        self.btn_refresh.setCursor(Qt.PointingHandCursor)
        self.btn_refresh.clicked.connect(self.refresh_all)
        h_lay.addWidget(self.btn_refresh)

        root.addWidget(header_card)

        # 10-Tab Widget (indices 0..9, compact tab padding so all tabs fit cleanly)
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(
            "QTabBar::tab { padding: 7px 12px; font-size: 12px; margin-right: 3px; min-height: 20px; }"
        )
        root.addWidget(self.tabs, 1)

        self._build_tab0_overview()
        self._build_tab1_health()
        self._build_tab2_interfaces()
        self._build_tab3_traffic()
        self._build_tab4_poe()
        self._build_tab5_vlans()
        self._build_tab6_syslog()
        self._build_tab7_events()
        self._build_tab8_history()
        self._build_tab9_config()

        self.poe_tab_supported = False
        self.vlan_tab_supported = False

        # Footer close button
        foot = QHBoxLayout()
        foot.addStretch()
        btn_close = QPushButton(_("devdet_close", "Close"))
        btn_close.setObjectName("SecondaryButton")
        btn_close.clicked.connect(self.accept)
        foot.addWidget(btn_close)
        root.addLayout(foot)

        self.refresh_all()

    # ── Tab Builders (0..9) ────────────────────────────────────────────────────

    def _build_tab0_overview(self) -> None:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(12)

        # Quick metric summary row
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(12)
        self.ov_cpu_val = self._mini_kpi_card(kpi_row, _("devdet_cpu_cur", "CPU"), "--")
        self.ov_mem_val = self._mini_kpi_card(kpi_row, _("snmp_col_mem", "RAM"), "--")
        self.ov_temp_val = self._mini_kpi_card(kpi_row, _("snmp_col_temp", "Temp"), "--")
        self.ov_ifaces_val = self._mini_kpi_card(kpi_row, _("devdet_tab_interfaces", "Interfaces"), "--")
        lay.addLayout(kpi_row)

        # System Info Card
        sys_card = QFrame()
        sys_card.setStyleSheet("QFrame { background-color: #1E293B; border-radius: 10px; border: 1px solid #334155; }")
        s_lay = QVBoxLayout(sys_card)
        s_lay.setContentsMargins(14, 12, 14, 12)
        hdr = QLabel(_("devdet_sysinfo_hdr", "SYSTEM IDENTIFICATION & STATUS"))
        hdr.setStyleSheet("color: #6366F1; font-weight: bold; font-size: 11px; margin-bottom: 4px; border: none;")
        s_lay.addWidget(hdr)

        self.ov_sys_grid = QGridLayout()
        self.ov_sys_grid.setSpacing(8)
        self._ov_fields: Dict[str, QLabel] = {}
        fields = [
            ("sys_name", "sysName"),
            ("vendor", "Vendor"),
            ("model", "Model"),
            ("firmware", "Firmware"),
            ("location", "Location"),
            ("snmp_version", "SNMP Version"),
            ("sys_object_id", "sysObjectID"),
            ("last_poll", "Last Poll (UTC)"),
            ("last_reboot_at", "Last Reboot (UTC)"),
            ("sys_descr", "sysDescr"),
        ]
        for idx, (k, label_txt) in enumerate(fields):
            r, c = divmod(idx, 2)
            k_lbl = QLabel(f"{label_txt}:")
            k_lbl.setStyleSheet("color: #94A3B8; font-weight: 600; font-size: 12px; margin-bottom: 0px; border: none;")
            v_lbl = QLabel("—")
            v_lbl.setWordWrap(True)
            v_lbl.setStyleSheet("color: #F1F5F9; font-size: 12px; margin-bottom: 0px; border: none;")
            self.ov_sys_grid.addWidget(k_lbl, r, c * 2)
            self.ov_sys_grid.addWidget(v_lbl, r, c * 2 + 1)
            self._ov_fields[k] = v_lbl
        s_lay.addLayout(self.ov_sys_grid)
        lay.addWidget(sys_card)

        # Capabilities Card
        cap_card = QFrame()
        cap_card.setStyleSheet("QFrame { background-color: #1E293B; border-radius: 10px; border: 1px solid #334155; }")
        c_lay = QVBoxLayout(cap_card)
        c_lay.setContentsMargins(14, 12, 14, 12)
        cap_hdr = QLabel(_("devdet_caps_hdr", "DETECTED HARDWARE / MIB CAPABILITIES"))
        cap_hdr.setStyleSheet("color: #06B6D4; font-weight: bold; font-size: 11px; margin-bottom: 4px; border: none;")
        c_lay.addWidget(cap_hdr)
        self.ov_caps_row = QHBoxLayout()
        self.ov_caps_row.setSpacing(10)
        self._cap_badges: Dict[str, QLabel] = {}
        for cap_key, cap_label in [
            ("interfaces", "Interfaces"),
            ("cpu", "CPU"),
            ("memory", "Memory"),
            ("temperature", "Temperature"),
            ("poe", "PoE"),
            ("vlans", "VLANs"),
        ]:
            b = QLabel(cap_label)
            b.setAlignment(Qt.AlignCenter)
            b.setStyleSheet(
                "background-color: #0F172A; color: #94A3B8; border: 1px solid #334155; "
                "border-radius: 8px; padding: 6px 12px; font-weight: bold; font-size: 12px; margin-bottom: 0px;"
            )
            self.ov_caps_row.addWidget(b)
            self._cap_badges[cap_key] = b
        self.ov_caps_row.addStretch()
        c_lay.addLayout(self.ov_caps_row)
        lay.addWidget(cap_card)
        lay.addStretch()
        self.tabs.addTab(w, _("devdet_tab_overview", "Overview"))

    def _mini_kpi_card(self, parent_layout: QHBoxLayout, title: str, init_val: str) -> QLabel:
        frame = QFrame()
        frame.setStyleSheet("QFrame { background-color: #1E293B; border-radius: 10px; border: 1px solid #334155; }")
        l = QVBoxLayout(frame)
        l.setContentsMargins(12, 10, 12, 10)
        l.setSpacing(2)
        val_lbl = QLabel(init_val)
        val_lbl.setAlignment(Qt.AlignCenter)
        val_lbl.setStyleSheet("font-size: 18px; font-weight: 800; color: #FFFFFF; margin-bottom: 0px; border: none;")
        t_lbl = QLabel(title)
        t_lbl.setAlignment(Qt.AlignCenter)
        t_lbl.setStyleSheet("font-size: 11px; color: #94A3B8; font-weight: 600; margin-bottom: 0px; border: none;")
        l.addWidget(val_lbl)
        l.addWidget(t_lbl)
        parent_layout.addWidget(frame)
        return val_lbl

    def _build_tab1_health(self) -> None:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        self.health_banner_lbl = QLabel("")
        self.health_banner_lbl.setStyleSheet("color: #F59E0B; font-style: italic; font-size: 12px; margin-bottom: 0px;")
        self.health_banner_lbl.hide()
        lay.addWidget(self.health_banner_lbl)

        kpi = QHBoxLayout()
        kpi.setSpacing(10)
        self.h_cpu_cur = self._mini_kpi_card(kpi, _("devdet_cpu_cur", "Current CPU"), "--")
        self.h_cpu_avg = self._mini_kpi_card(kpi, _("devdet_cpu_avg", "Historical Avg CPU"), "--")
        self.h_mem_used = self._mini_kpi_card(kpi, _("devdet_mem_used", "Memory Used"), "--")
        self.h_mem_avail = self._mini_kpi_card(kpi, _("devdet_mem_avail", "Available Memory"), "--")
        lay.addLayout(kpi)

        charts_row = QHBoxLayout()
        charts_row.setSpacing(10)
        self.h_cpu_plot = _make_plot("CPU (%)")
        self.h_mem_plot = _make_plot("Memory (%)")
        charts_row.addWidget(self.h_cpu_plot)
        charts_row.addWidget(self.h_mem_plot)
        lay.addLayout(charts_row, 2)

        temp_hdr = QLabel(_("devdet_temp_hdr", "TEMPERATURE SENSORS"))
        temp_hdr.setStyleSheet("color: #06B6D4; font-weight: bold; font-size: 11px; margin-bottom: 0px;")
        lay.addWidget(temp_hdr)
        self.h_temp_table = _make_readonly_table(["Sensor", "Temperature (°C)", "Warn / Crit (°C)", "Status"])
        self.h_temp_table.setMaximumHeight(150)
        lay.addWidget(self.h_temp_table, 1)
        self.tabs.addTab(w, escape_qt_mnemonic(_("devdet_tab_health", "CPU & Memory")))

    def _build_tab2_interfaces(self) -> None:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        bar = QHBoxLayout()
        bar.setSpacing(6)
        self._if_filter_group = QButtonGroup(self)
        self._if_filter_group.setExclusive(True)
        for mode, key, fallback in [
            ("ALL", "devdet_if_filter_all", "All"),
            ("UP", "devdet_if_filter_up", "UP"),
            ("DOWN", "devdet_if_filter_down", "DOWN"),
            ("HIGH_UTILIZATION", "devdet_if_filter_high", "High Util (>=80%)"),
            ("ERRORS", "devdet_if_filter_err", "Errors / CRC"),
            ("OTHER", "devdet_if_filter_other", "Other States"),
        ]:
            btn = QPushButton(_(key, fallback))
            btn.setCheckable(True)
            btn.setChecked(mode == "ALL")
            btn.setCursor(Qt.PointingHandCursor)
            btn.setProperty("filter_mode", mode)
            btn.clicked.connect(lambda _c, m=mode: self._set_interface_filter(m))
            btn.setStyleSheet(
                "QPushButton { background-color: #1E293B; color: #CBD5E1; border: 1px solid #334155; border-radius: 6px; padding: 5px 10px; font-size: 11px; }"
                "QPushButton:hover { border-color: #6366F1; color: #FFFFFF; background-color: #242F42; }"
                "QPushButton:checked { background-color: #4F46E5; color: #FFFFFF; border-color: #6366F1; font-weight: bold; }"
            )
            self._if_filter_group.addButton(btn)
            bar.addWidget(btn)

        bar.addStretch()
        self.if_search_edit = QLineEdit()
        self.if_search_edit.setPlaceholderText(_("devdet_if_search", "Filter interface name or alias..."))
        self.if_search_edit.setMaximumWidth(240)
        self.if_search_edit.textChanged.connect(self._refresh_interfaces_tab)
        bar.addWidget(self.if_search_edit)
        lay.addLayout(bar)

        self.if_table = _make_readonly_table([
            "ifIndex", "Name", "Alias", "MAC", "Admin", "Oper", "Speed",
            "In Mbps", "Out Mbps", "Util %", "Errors", "Discards", "CRC", "Last Change",
        ])
        lay.addWidget(self.if_table, 1)
        self.tabs.addTab(w, _("devdet_tab_interfaces", "Interfaces"))

    def _build_tab3_traffic(self) -> None:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        top = QHBoxLayout()
        lbl = QLabel(_("devdet_traffic_iface", "Interface:"))
        lbl.setStyleSheet("margin-bottom: 0px; font-weight: 600;")
        self.tr_iface_combo = QComboBox()
        self.tr_iface_combo.setMinimumWidth(260)
        self.tr_iface_combo.currentIndexChanged.connect(self._refresh_traffic_charts)
        top.addWidget(lbl)
        top.addWidget(self.tr_iface_combo)
        top.addStretch()
        lay.addLayout(top)

        self.tr_io_plot = _make_plot(_("devdet_traffic_in_out", "INBOUND vs OUTBOUND THROUGHPUT (Mbps)"))
        self.tr_util_plot = _make_plot(_("devdet_traffic_util", "LINK UTILIZATION (%)"))
        lay.addWidget(self.tr_io_plot, 1)
        lay.addWidget(self.tr_util_plot, 1)
        self.tabs.addTab(w, _("devdet_tab_traffic", "Traffic"))

    def _build_tab4_poe(self) -> None:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        self.poe_unsupported_lbl = QLabel(_("devdet_unsupported", "Not exposed / unsupported by this device."))
        self.poe_unsupported_lbl.setStyleSheet("color: #94A3B8; font-style: italic; margin-bottom: 0px;")
        lay.addWidget(self.poe_unsupported_lbl)

        kpi = QHBoxLayout()
        kpi.setSpacing(10)
        self.poe_budget_lbl = self._mini_kpi_card(kpi, _("devdet_poe_budget", "PoE Budget"), "--")
        self.poe_consumed_lbl = self._mini_kpi_card(kpi, _("devdet_poe_consumed", "Power Consumed"), "--")
        self.poe_rem_lbl = self._mini_kpi_card(kpi, _("devdet_poe_remaining", "Power Remaining"), "--")
        self.poe_util_lbl = self._mini_kpi_card(kpi, _("devdet_poe_util", "Utilization"), "--")
        lay.addLayout(kpi)

        self.poe_bar = QProgressBar()
        self.poe_bar.setRange(0, 100)
        self.poe_bar.setTextVisible(True)
        lay.addWidget(self.poe_bar)

        self.poe_ports_table = _make_readonly_table(["Port Key", "Admin Enabled", "Status", "Priority", "Power (W)"])
        self.poe_plot = _make_plot("PoE Consumed (W)")
        lay.addWidget(self.poe_ports_table, 1)
        lay.addWidget(self.poe_plot, 1)
        self.tabs.addTab(w, _("devdet_tab_poe", "PoE"))

    def _build_tab5_vlans(self) -> None:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        self.vlan_unsupported_lbl = QLabel(_("devdet_unsupported", "Not exposed / unsupported by this device."))
        self.vlan_unsupported_lbl.setStyleSheet("color: #94A3B8; font-style: italic; margin-bottom: 0px;")
        lay.addWidget(self.vlan_unsupported_lbl)

        self.vlan_table = _make_readonly_table([
            _("devdet_vlan_id", "VLAN ID"),
            _("devdet_vlan_name", "VLAN Name"),
            _("devdet_vlan_status", "Status"),
            _("devdet_vlan_untagged", "Untagged Ports"),
            _("devdet_vlan_tagged", "Tagged Ports"),
            _("devdet_vlan_trunks", "Trunk Ports"),
        ])
        lay.addWidget(self.vlan_table, 1)
        self.tabs.addTab(w, _("devdet_tab_vlans", "VLANs"))

    def _build_tab6_syslog(self) -> None:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        bar = QHBoxLayout()
        sev_lbl = QLabel(_("syslog_filter_sev", "Severity:"))
        sev_lbl.setStyleSheet("margin-bottom: 0px;")
        self.sl_sev_combo = QComboBox()
        self.sl_sev_combo.addItem(_("snmp_filter_all", "All"), None)
        for s_id, s_name in [(2, "<= Critical (2)"), (3, "<= Error (3)"), (4, "<= Warning (4)"), (6, "<= Informational (6)")]:
            self.sl_sev_combo.addItem(s_name, s_id)
        self.sl_sev_combo.currentIndexChanged.connect(self._refresh_syslog_tab)
        bar.addWidget(sev_lbl)
        bar.addWidget(self.sl_sev_combo)
        bar.addStretch()
        lay.addLayout(bar)

        self.dev_syslog_table = _make_readonly_table([
            _("syslog_col_ts", "Timestamp"),
            _("syslog_col_sev", "Severity"),
            _("syslog_col_cat", "Category"),
            _("syslog_col_app", "App / Tag"),
            _("syslog_col_msg", "Message"),
        ])
        lay.addWidget(self.dev_syslog_table, 1)
        self.tabs.addTab(w, _("devdet_tab_syslog", "Syslog"))

    def _build_tab7_events(self) -> None:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        self.ev_table = _make_readonly_table([
            _("intel_col_time", "Detected At"),
            _("intel_col_sev", "Severity"),
            _("intel_col_conf", "Confidence"),
            _("intel_col_type", "Category / Type"),
            _("intel_col_title", "Title"),
            _("intel_col_status", "Status"),
        ])
        self.ev_table.itemSelectionChanged.connect(self._on_anomaly_selected)
        lay.addWidget(self.ev_table, 2)

        self.ev_detail_box = QTextEdit()
        self.ev_detail_box.setReadOnly(True)
        self.ev_detail_box.setMaximumHeight(160)
        self.ev_detail_box.setStyleSheet(
            "QTextEdit { background-color: #1E293B; color: #F1F5F9; border: 1px solid #334155; border-radius: 8px; padding: 8px; }"
        )
        lay.addWidget(self.ev_detail_box, 1)

        acts = QHBoxLayout()
        self.btn_ack = QPushButton(_("intel_btn_ack", "Acknowledge"))
        self.btn_ack.setObjectName("SecondaryButton")
        self.btn_ack.setCursor(Qt.PointingHandCursor)
        self.btn_ack.setEnabled(False)
        self.btn_ack.clicked.connect(self._ack_selected_anomaly)
        self.btn_res = QPushButton(_("intel_btn_resolve", "Mark Resolved"))
        self.btn_res.setObjectName("PrimaryButton")
        self.btn_res.setCursor(Qt.PointingHandCursor)
        self.btn_res.setEnabled(False)
        self.btn_res.clicked.connect(self._resolve_selected_anomaly)
        acts.addStretch()
        acts.addWidget(self.btn_ack)
        acts.addWidget(self.btn_res)
        lay.addLayout(acts)

        self.tabs.addTab(w, escape_qt_mnemonic(_("devdet_tab_events", "Events & Anomalies")))

    def _build_tab8_history(self) -> None:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        bar = QHBoxLayout()
        bar.setSpacing(10)
        m_lbl = QLabel(_("devdet_hist_metric", "Metric:"))
        m_lbl.setStyleSheet("margin-bottom: 0px;")
        self.hist_metric_combo = QComboBox()
        for m in [
            "cpu_pct",
            "memory_pct",
            "temperature_max_c",
            "total_in_mbps",
            "total_out_mbps",
            "poe_utilization_pct",
            "uptime_sec",
        ]:
            self.hist_metric_combo.addItem(m, m)
        self.hist_metric_combo.currentIndexChanged.connect(self._refresh_history_tab)

        g_lbl = QLabel(_("devdet_hist_granularity", "Granularity:"))
        g_lbl.setStyleSheet("margin-bottom: 0px;")
        self.hist_gran_combo = QComboBox()
        self.hist_gran_combo.addItem(_("devdet_hist_raw", "Raw"), "raw")
        self.hist_gran_combo.addItem(_("devdet_hist_hourly", "Hourly"), "hourly")
        self.hist_gran_combo.addItem(_("devdet_hist_daily", "Daily"), "daily")
        self.hist_gran_combo.currentIndexChanged.connect(self._refresh_history_tab)

        self.hist_stats_lbl = QLabel("Min: -- | Avg: -- | Max: --")
        self.hist_stats_lbl.setStyleSheet("color: #06B6D4; font-weight: bold; margin-bottom: 0px;")

        bar.addWidget(m_lbl)
        bar.addWidget(self.hist_metric_combo)
        bar.addWidget(g_lbl)
        bar.addWidget(self.hist_gran_combo)
        bar.addStretch()
        bar.addWidget(self.hist_stats_lbl)
        lay.addLayout(bar)

        self.hist_plot = _make_plot("Historical SNMP Telemetry")
        lay.addWidget(self.hist_plot, 1)
        self.tabs.addTab(w, _("devdet_tab_history", "Historical Metrics"))

    def _build_tab9_config(self) -> None:
        w = QWidget()
        outer = QVBoxLayout(w)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background: transparent;")
        inner = QWidget()
        inner.setStyleSheet("background: transparent;")
        form = QFormLayout(inner)
        form.setSpacing(10)

        self.cfg_name = QLineEdit()
        self.cfg_location = QLineEdit()
        self.cfg_profile = QComboBox()
        for pname in SNMP_PROFILES:
            self.cfg_profile.addItem(pname, pname)

        self.cfg_poll_int = QSpinBox()
        self.cfg_poll_int.setRange(5, 3600)
        self.cfg_temp_int = QSpinBox()
        self.cfg_temp_int.setRange(10, 3600)
        self.cfg_poe_int = QSpinBox()
        self.cfg_poe_int.setRange(10, 3600)
        self.cfg_sys_int = QSpinBox()
        self.cfg_sys_int.setRange(30, 86400)
        self.cfg_timeout = QDoubleSpinBox()
        self.cfg_timeout.setRange(0.5, 30.0)
        self.cfg_timeout.setSingleStep(0.5)
        self.cfg_retries = QSpinBox()
        self.cfg_retries.setRange(0, 5)

        self.cfg_cpu_warn = QDoubleSpinBox()
        self.cfg_cpu_warn.setRange(1.0, 100.0)
        self.cfg_cpu_crit = QDoubleSpinBox()
        self.cfg_cpu_crit.setRange(1.0, 100.0)
        self.cfg_mem_warn = QDoubleSpinBox()
        self.cfg_mem_warn.setRange(1.0, 100.0)
        self.cfg_mem_crit = QDoubleSpinBox()
        self.cfg_mem_crit.setRange(1.0, 100.0)
        self.cfg_temp_warn = QDoubleSpinBox()
        self.cfg_temp_warn.setRange(10.0, 150.0)
        self.cfg_temp_crit = QDoubleSpinBox()
        self.cfg_temp_crit.setRange(10.0, 150.0)
        self.cfg_poe_warn = QDoubleSpinBox()
        self.cfg_poe_warn.setRange(10.0, 100.0)
        self.cfg_poe_crit = QDoubleSpinBox()
        self.cfg_poe_crit.setRange(10.0, 100.0)

        self.cfg_enabled = QCheckBox("Enable SNMP Polling")
        self.cfg_anomaly = QCheckBox(_("snmp_dlg_anomaly", "Enable Statistical Anomaly Detection"))

        form.addRow(_("snmp_dlg_name", "Device Name:"), self.cfg_name)
        form.addRow(_("snmp_dlg_location", "Location:"), self.cfg_location)
        form.addRow(_("snmp_dlg_profile", "Vendor Profile:"), self.cfg_profile)
        form.addRow(_("snmp_dlg_interval", "Poll Interval (s):"), self.cfg_poll_int)
        form.addRow("Temp Interval (s):", self.cfg_temp_int)
        form.addRow("PoE Interval (s):", self.cfg_poe_int)
        form.addRow("SysInfo Interval (s):", self.cfg_sys_int)
        form.addRow(_("snmp_dlg_timeout", "Timeout (s):"), self.cfg_timeout)
        form.addRow(_("snmp_dlg_retries", "Retries:"), self.cfg_retries)
        form.addRow("CPU Warn (%):", self.cfg_cpu_warn)
        form.addRow("CPU Crit (%):", self.cfg_cpu_crit)
        form.addRow("Memory Warn (%):", self.cfg_mem_warn)
        form.addRow("Memory Crit (%):", self.cfg_mem_crit)
        form.addRow("Temperature Warn (°C):", self.cfg_temp_warn)
        form.addRow("Temperature Crit (°C):", self.cfg_temp_crit)
        form.addRow("PoE Warn (%):", self.cfg_poe_warn)
        form.addRow("PoE Crit (%):", self.cfg_poe_crit)
        form.addRow("", self.cfg_enabled)
        form.addRow("", self.cfg_anomaly)

        btn_save = QPushButton(_("devdet_cfg_save", "Save Device Configuration"))
        btn_save.setObjectName("PrimaryButton")
        btn_save.clicked.connect(self._save_device_config)
        form.addRow("", btn_save)

        scroll.setWidget(inner)
        outer.addWidget(scroll)
        self.tabs.addTab(w, _("devdet_tab_config", "Configuration"))

    # ── Data Refresh Methods ───────────────────────────────────────────────────

    def _set_interface_filter(self, mode: str) -> None:
        self._iface_filter_mode = mode
        self._refresh_interfaces_tab()

    def _live_snapshot(self) -> Dict[str, Any]:
        if self.snmp_engine is not None:
            return self.snmp_engine.get_snapshot(self.device_id) or {}
        return {}

    def _latest_metrics_map(self) -> Dict[str, float]:
        rows = self.db.get_snmp_metrics(self.device_id, limit=300)
        out: Dict[str, float] = {}
        for r in rows:
            if r.get("metric_value") is not None:
                out[r["metric_name"]] = float(r["metric_value"])
        snap = self._live_snapshot()
        for k, v in (snap.get("metrics") or {}).items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                out[k] = float(v)
        return out

    def refresh_all(self) -> None:
        dev = self.db.get_snmp_device(self.device_id)
        if dev is None:
            self.hdr_name_lbl.setText(f"Unknown Device #{self.device_id}")
            self.hdr_status_badge.setText("UNKNOWN")
            return

        snap = self._live_snapshot()
        metrics = self._latest_metrics_map()
        caps = dict(dev.get("capabilities") or {})
        col_snaps = dict(snap.get("collector_snapshots") or {})

        status = str(snap.get("status") or dev.get("status") or "UNKNOWN").upper()
        scolor = _STATUS_COLORS.get(status, "#94A3B8")
        self.hdr_name_lbl.setText(dev["name"])
        self.hdr_sub_lbl.setText(
            f"{dev['ip_address']}:{dev['port']}  •  {dev.get('vendor', 'Generic')} {dev.get('model', '')}  •  "
            f"FW: {dev.get('firmware') or 'N/A'}  •  SNMP {dev.get('snmp_version', 'v2c')}"
        )
        fg_col = "#0F172A" if status in ("DEGRADED", "WARNING", "TESTING", "UNKNOWN") else "#FFFFFF"
        self.hdr_status_badge.setText(status)
        self.hdr_status_badge.setStyleSheet(
            f"background-color: {scolor}; color: {fg_col}; border-radius: 8px; padding: 6px 12px; font-weight: 700; margin-bottom: 0px;"
        )
        ticks = snap.get("last_uptime_ticks") or dev.get("last_uptime_ticks")
        self.hdr_uptime_lbl.setText(f"{_('devdet_uptime', 'Uptime:')} {format_uptime(ticks)}")

        # Overview Tab (0)
        self.ov_cpu_val.setText(f"{metrics['cpu_pct']:.1f}%" if "cpu_pct" in metrics else "N/A")
        self.ov_mem_val.setText(f"{metrics['memory_pct']:.1f}%" if "memory_pct" in metrics else "N/A")
        self.ov_temp_val.setText(f"{metrics['temperature_max_c']:.1f}°C" if "temperature_max_c" in metrics else "N/A")
        ifaces_db = self.db.get_snmp_interfaces(self.device_id)
        up_cnt = sum(1 for i in ifaces_db if str(i.get("oper_status")).upper() == "UP")
        self.ov_ifaces_val.setText(f"{up_cnt} / {len(ifaces_db)}" if ifaces_db else "0")

        self._ov_fields["sys_name"].setText(dev.get("sys_name") or "—")
        self._ov_fields["vendor"].setText(dev.get("vendor") or "—")
        self._ov_fields["model"].setText(dev.get("model") or "—")
        self._ov_fields["firmware"].setText(dev.get("firmware") or "—")
        self._ov_fields["location"].setText(dev.get("location") or dev.get("sys_location") or "—")
        self._ov_fields["snmp_version"].setText(dev.get("snmp_version") or "v2c")
        self._ov_fields["sys_object_id"].setText(dev.get("sys_object_id") or "—")
        lp = snap.get("last_poll") or dev.get("last_poll")
        lr = snap.get("last_reboot_at") or dev.get("last_reboot_at")
        self._ov_fields["last_poll"].setText(lp.strftime("%Y-%m-%d %H:%M:%S") if isinstance(lp, datetime) else "Never")
        self._ov_fields["last_reboot_at"].setText(lr.strftime("%Y-%m-%d %H:%M:%S") if isinstance(lr, datetime) else "None")
        self._ov_fields["sys_descr"].setText(dev.get("sys_descr") or "—")

        for ck, badge in self._cap_badges.items():
            ok = bool(caps.get(ck))
            if ck == "interfaces" and ifaces_db:
                ok = True
            if ck == "poe" and "poe_budget_watts" in metrics:
                ok = True
            if ck == "vlans" and len(self.db.get_snmp_vlans(self.device_id)) > 0:
                ok = True
            if ck == "cpu" and "cpu_pct" in metrics:
                ok = True
            if ck == "memory" and "memory_pct" in metrics:
                ok = True
            if ck == "temperature" and "temperature_max_c" in metrics:
                ok = True
            if ok:
                badge.setStyleSheet(
                    "background-color: rgba(16,185,129,0.2); color: #10B981; border: 1px solid #10B981; "
                    "border-radius: 8px; padding: 6px 12px; font-weight: bold; font-size: 12px; margin-bottom: 0px;"
                )
            else:
                badge.setStyleSheet(
                    "background-color: #0F172A; color: #64748B; border: 1px solid #334155; "
                    "border-radius: 8px; padding: 6px 12px; font-weight: normal; font-size: 12px; margin-bottom: 0px;"
                )

        # Health Tab (1)
        self._refresh_health_tab(dev, metrics, col_snaps.get("health") or {})

        # Interfaces (2) & Traffic (3)
        self._refresh_interfaces_tab()
        self._populate_traffic_iface_combo(ifaces_db)
        self._refresh_traffic_charts()

        # PoE Tab (4) — capability gated
        poe_snap = col_snaps.get("poe") or {}
        poe_supported = bool(caps.get("poe")) or ("poe_budget_watts" in metrics) or bool(poe_snap.get("supported"))
        self.poe_tab_supported = poe_supported
        self.tabs.setTabEnabled(4, poe_supported)
        self.tabs.setTabVisible(4, poe_supported)
        self._refresh_poe_tab(poe_supported, metrics, poe_snap)

        # VLANs Tab (5) — capability gated
        vlans = self.db.get_snmp_vlans(self.device_id)
        vlan_supported = bool(caps.get("vlans")) or len(vlans) > 0
        self.vlan_tab_supported = vlan_supported
        self.tabs.setTabEnabled(5, vlan_supported)
        self.tabs.setTabVisible(5, vlan_supported)
        self._refresh_vlans_tab(vlan_supported, vlans)

        # Syslog (6), Events (7), History (8), Config (9)
        self._refresh_syslog_tab()
        self._refresh_events_tab()
        self._refresh_history_tab()
        self._load_config_tab(dev)

    def _refresh_health_tab(self, dev: Dict[str, Any], metrics: Dict[str, float], health_snap: Dict[str, Any]) -> None:
        cpu_cur = metrics.get("cpu_pct")
        cpu_avg = compute_cpu_average(self.db, self.device_id)
        self.h_cpu_cur.setText(f"{cpu_cur:.1f}%" if cpu_cur is not None else "N/A")
        self.h_cpu_avg.setText(f"{cpu_avg:.1f}%" if cpu_avg is not None else "N/A")

        mem_pct = metrics.get("memory_pct")
        mem_used = metrics.get("memory_used_bytes")
        mem_avail = metrics.get("memory_available_bytes")
        self.h_mem_used.setText(
            f"{_format_bytes(mem_used)} ({mem_pct:.1f}%)" if mem_pct is not None else "N/A"
        )
        self.h_mem_avail.setText(_format_bytes(mem_avail) if mem_avail is not None else "N/A")

        if cpu_cur is None and mem_pct is None:
            self.health_banner_lbl.setText(_("devdet_unsupported", "Not exposed / unsupported by this device."))
            self.health_banner_lbl.show()
        else:
            self.health_banner_lbl.hide()

        # CPU / Memory trend plots
        cpu_rows = self.db.get_snmp_metrics(self.device_id, metric_name="cpu_pct", limit=200)
        self.h_cpu_plot.clear()
        if cpu_rows:
            ys = [float(r["metric_value"]) for r in cpu_rows]
            self.h_cpu_plot.plot(list(range(len(ys))), ys, pen=pg.mkPen("#06B6D4", width=2))
            self.h_cpu_plot.setYRange(0, 100)

        mem_rows = self.db.get_snmp_metrics(self.device_id, metric_name="memory_pct", limit=200)
        self.h_mem_plot.clear()
        if mem_rows:
            ys = [float(r["metric_value"]) for r in mem_rows]
            self.h_mem_plot.plot(list(range(len(ys))), ys, pen=pg.mkPen("#6366F1", width=2))
            self.h_mem_plot.setYRange(0, 100)

        # Temperature table (prefer live collector sensors, fallback latest temperature_c rows)
        self.h_temp_table.setRowCount(0)
        sensors = health_snap.get("temperatures") or []
        profile = get_profile(dev.get("profile_name", "generic_switch"))
        warn_c, crit_c = resolve_temperature_thresholds(profile, dev.get("model", ""), dev.get("thresholds"))
        if not sensors:
            t_rows = self.db.get_snmp_metrics(self.device_id, metric_name="temperature_c", limit=60)
            by_lbl: Dict[str, float] = {}
            for r in t_rows:
                lbl = r.get("sensor_label") or "Chassis"
                by_lbl[lbl] = float(r["metric_value"])
            for lbl, val in by_lbl.items():
                st = "CRITICAL" if val >= crit_c else ("WARNING" if val >= warn_c else "NORMAL")
                sensors.append({"label": lbl, "temp_c": val, "warn_c": warn_c, "crit_c": crit_c, "status": st})

        for s in sensors:
            row = self.h_temp_table.rowCount()
            self.h_temp_table.insertRow(row)
            self.h_temp_table.setItem(row, 0, QTableWidgetItem(str(s.get("label", "Sensor"))))
            self.h_temp_table.setItem(row, 1, QTableWidgetItem(f"{float(s.get('temp_c', 0.0)):.1f} °C"))
            self.h_temp_table.setItem(
                row, 2, QTableWidgetItem(f"{float(s.get('warn_c', warn_c)):.0f} / {float(s.get('crit_c', crit_c)):.0f}")
            )
            st = str(s.get("status", "NORMAL")).upper()
            st_item = QTableWidgetItem(st)
            st_item.setForeground(QColor(_STATUS_COLORS.get(st, "#94A3B8")))
            self.h_temp_table.setItem(row, 3, st_item)

    def _refresh_interfaces_tab(self) -> None:
        metas = self.db.get_snmp_interfaces(self.device_id)
        meas_rows = self.db.get_interface_measurements(device_id=self.device_id, limit=500)
        latest_m: Dict[int, Dict[str, Any]] = {}
        for mr in meas_rows:
            latest_m[int(mr["interface_id"])] = mr

        live_ifaces = (self._live_snapshot().get("collector_snapshots") or {}).get("interfaces") or []
        live_by_idx = {int(i["if_index"]): i for i in live_ifaces if "if_index" in i}

        merged: List[Dict[str, Any]] = []
        for meta in metas:
            iid = int(meta["id"])
            idx = int(meta["if_index"])
            m = live_by_idx.get(idx) or latest_m.get(iid, {})
            spd = int(meta.get("speed_bps") or 0)
            merged.append({
                "if_index": idx,
                "name": meta.get("name") or meta.get("description") or f"if{idx}",
                "alias": meta.get("alias") or "",
                "mac_address": meta.get("mac_address") or "",
                "admin_status": meta.get("admin_status") or "UNKNOWN",
                "oper_status": m.get("oper_status") or meta.get("oper_status") or "UNKNOWN",
                "speed_str": f"{spd // 1_000_000}M" if spd >= 1_000_000 else (f"{spd} bps" if spd > 0 else "--"),
                "in_mbps": float(m.get("in_mbps", 0.0) or 0.0),
                "out_mbps": float(m.get("out_mbps", 0.0) or 0.0),
                "utilization_pct": float(m.get("utilization_pct", 0.0) or 0.0),
                "in_errors": int(m.get("in_errors", 0) or 0),
                "out_errors": int(m.get("out_errors", 0) or 0),
                "in_discards": int(m.get("in_discards", 0) or 0),
                "out_discards": int(m.get("out_discards", 0) or 0),
                "crc_errors": int(m.get("crc_errors", 0) or 0),
                "last_change_at": meta.get("last_change_at"),
            })

        filtered = filter_interfaces(merged, mode=self._iface_filter_mode, high_util_pct=80.0)
        q = self.if_search_edit.text().strip().lower()
        if q:
            filtered = [
                r for r in filtered if q in r["name"].lower() or q in r["alias"].lower() or q in r["mac_address"].lower()
            ]

        self.if_table.setRowCount(0)
        for item in filtered:
            row = self.if_table.rowCount()
            self.if_table.insertRow(row)
            lc = item["last_change_at"]
            lc_str = lc.strftime("%m-%d %H:%M") if isinstance(lc, datetime) else "--"
            errs = item["in_errors"] + item["out_errors"]
            discs = item["in_discards"] + item["out_discards"]
            vals = [
                str(item["if_index"]),
                item["name"],
                item["alias"],
                item["mac_address"],
                item["admin_status"],
                item["oper_status"],
                item["speed_str"],
                f"{item['in_mbps']:.2f}",
                f"{item['out_mbps']:.2f}",
                f"{item['utilization_pct']:.1f}%",
                str(errs),
                str(discs),
                str(item["crc_errors"]),
                lc_str,
            ]
            for c, txt in enumerate(vals):
                cell = QTableWidgetItem(txt)
                if c == 5:
                    cell.setForeground(QColor(_STATUS_COLORS.get(item["oper_status"], "#94A3B8")))
                self.if_table.setItem(row, c, cell)

    def _populate_traffic_iface_combo(self, ifaces_db: List[Dict[str, Any]]) -> None:
        prev_id = self.tr_iface_combo.currentData()
        self.tr_iface_combo.blockSignals(True)
        self.tr_iface_combo.clear()
        for iface in ifaces_db:
            lbl = f"[{iface['if_index']}] {iface.get('name') or iface.get('description') or ''}"
            self.tr_iface_combo.addItem(lbl, int(iface["id"]))
        if prev_id is not None:
            idx = self.tr_iface_combo.findData(prev_id)
            if idx >= 0:
                self.tr_iface_combo.setCurrentIndex(idx)
        self.tr_iface_combo.blockSignals(False)

    def _refresh_traffic_charts(self) -> None:
        self.tr_io_plot.clear()
        self.tr_util_plot.clear()
        iid = self.tr_iface_combo.currentData()
        if iid is None:
            return
        rows = self.db.get_interface_measurements(interface_id=int(iid), limit=200)
        if not rows:
            return
        xs = list(range(len(rows)))
        ins = [float(r["in_mbps"]) for r in rows]
        outs = [float(r["out_mbps"]) for r in rows]
        utils = [float(r["utilization_pct"]) for r in rows]
        if not getattr(self.tr_io_plot, "_legend_added", False):
            self.tr_io_plot.addLegend()
            self.tr_io_plot._legend_added = True
        self.tr_io_plot.plot(xs, ins, pen=pg.mkPen("#10B981", width=2), name="Inbound (Mbps)")
        self.tr_io_plot.plot(xs, outs, pen=pg.mkPen("#6366F1", width=2), name="Outbound (Mbps)")
        self.tr_util_plot.plot(xs, utils, pen=pg.mkPen("#F59E0B", width=2))
        self.tr_util_plot.setYRange(0, 100)

    def _refresh_poe_tab(self, supported: bool, metrics: Dict[str, float], poe_snap: Dict[str, Any]) -> None:
        self.poe_unsupported_lbl.setVisible(not supported)
        self.poe_ports_table.setRowCount(0)
        self.poe_plot.clear()
        if not supported:
            self.poe_budget_lbl.setText("N/A")
            self.poe_consumed_lbl.setText("N/A")
            self.poe_rem_lbl.setText("N/A")
            self.poe_util_lbl.setText("N/A")
            self.poe_bar.setValue(0)
            return

        budget = float(poe_snap.get("budget_watts", metrics.get("poe_budget_watts", 0.0)))
        consumed = float(poe_snap.get("consumed_watts", metrics.get("poe_consumed_watts", 0.0)))
        remaining = max(0.0, budget - consumed) if budget > 0 else 0.0
        util = float(poe_snap.get("utilization_pct", metrics.get("poe_utilization_pct", (consumed / budget * 100.0) if budget > 0 else 0.0)))

        self.poe_budget_lbl.setText(f"{budget:.1f} W")
        self.poe_consumed_lbl.setText(f"{consumed:.1f} W")
        self.poe_rem_lbl.setText(f"{remaining:.1f} W")
        self.poe_util_lbl.setText(f"{util:.1f}%")
        self.poe_bar.setValue(min(100, int(round(util))))

        for p in poe_snap.get("ports") or []:
            row = self.poe_ports_table.rowCount()
            self.poe_ports_table.insertRow(row)
            self.poe_ports_table.setItem(row, 0, QTableWidgetItem(str(p.get("port_key", ""))))
            self.poe_ports_table.setItem(row, 1, QTableWidgetItem("YES" if p.get("admin_enabled", True) else "NO"))
            st = str(p.get("detection_status", "DISABLED"))
            st_it = QTableWidgetItem(st)
            st_it.setForeground(QColor(_STATUS_COLORS.get(st, "#94A3B8")))
            self.poe_ports_table.setItem(row, 2, st_it)
            self.poe_ports_table.setItem(row, 3, QTableWidgetItem(str(p.get("priority", "LOW"))))
            pw = p.get("power_watts")
            self.poe_ports_table.setItem(row, 4, QTableWidgetItem(f"{float(pw):.2f}" if pw is not None else "--"))

        poe_hist = self.db.get_snmp_metrics(self.device_id, metric_name="poe_consumed_watts", limit=150)
        if poe_hist:
            ys = [float(r["metric_value"]) for r in poe_hist]
            self.poe_plot.plot(list(range(len(ys))), ys, pen=pg.mkPen("#F59E0B", width=2))

    def _refresh_vlans_tab(self, supported: bool, vlans: List[Dict[str, Any]]) -> None:
        self.vlan_unsupported_lbl.setVisible(not supported)
        self.vlan_table.setRowCount(0)
        if not supported:
            return
        for v in vlans:
            row = self.vlan_table.rowCount()
            self.vlan_table.insertRow(row)
            self.vlan_table.setItem(row, 0, QTableWidgetItem(str(v.get("vlan_id", ""))))
            self.vlan_table.setItem(row, 1, QTableWidgetItem(str(v.get("name", ""))))
            st = str(v.get("status", "ACTIVE"))
            st_it = QTableWidgetItem(st)
            st_it.setForeground(QColor(_STATUS_COLORS.get(st, "#94A3B8")))
            self.vlan_table.setItem(row, 2, st_it)
            self.vlan_table.setItem(row, 3, QTableWidgetItem(", ".join(v.get("untagged_ports", []))))
            self.vlan_table.setItem(row, 4, QTableWidgetItem(", ".join(v.get("tagged_ports", []))))
            self.vlan_table.setItem(row, 5, QTableWidgetItem(", ".join(v.get("trunk_ports", []))))

    def _refresh_syslog_tab(self) -> None:
        dev = self.db.get_snmp_device(self.device_id)
        self.dev_syslog_table.setRowCount(0)
        if not dev:
            return
        max_sev = self.sl_sev_combo.currentData()
        rows = self.db.get_syslog_events(source_ip=dev["ip_address"], max_severity=max_sev, limit=200)
        for ev in rows:
            row = self.dev_syslog_table.rowCount()
            self.dev_syslog_table.insertRow(row)
            ts = ev.get("timestamp")
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime) else str(ts or "")
            self.dev_syslog_table.setItem(row, 0, QTableWidgetItem(ts_str))
            sev_name = str(ev.get("severity_name", "Informational"))
            sev_item = QTableWidgetItem(f"{sev_name} ({ev.get('severity')})")
            if int(ev.get("severity", 6)) <= 3:
                sev_item.setForeground(QColor("#F43F5E"))
            elif int(ev.get("severity", 6)) == 4:
                sev_item.setForeground(QColor("#F59E0B"))
            self.dev_syslog_table.setItem(row, 1, sev_item)
            self.dev_syslog_table.setItem(row, 2, QTableWidgetItem(str(ev.get("event_category", "GENERAL"))))
            self.dev_syslog_table.setItem(row, 3, QTableWidgetItem(str(ev.get("app_name", ""))))
            self.dev_syslog_table.setItem(row, 4, QTableWidgetItem(str(ev.get("message", ""))))

    def _refresh_events_tab(self) -> None:
        self._device_anomalies = self.db.get_network_anomalies(device_id=self.device_id, limit=200)
        self.ev_table.setRowCount(0)
        for a in self._device_anomalies:
            row = self.ev_table.rowCount()
            self.ev_table.insertRow(row)
            ts = a.get("detected_at")
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime) else str(ts or "")
            self.ev_table.setItem(row, 0, QTableWidgetItem(ts_str))
            sev = str(a.get("severity", "INFO"))
            s_it = QTableWidgetItem(sev)
            s_it.setForeground(QColor(_STATUS_COLORS.get(sev, "#94A3B8")))
            self.ev_table.setItem(row, 1, s_it)
            self.ev_table.setItem(row, 2, QTableWidgetItem(str(a.get("confidence", ""))))
            self.ev_table.setItem(row, 3, QTableWidgetItem(str(a.get("event_type", ""))))
            self.ev_table.setItem(row, 4, QTableWidgetItem(str(a.get("title", ""))))
            anom_st = str(a.get("status", ""))
            st_item = QTableWidgetItem(anom_st)
            st_item.setForeground(QColor(_STATUS_COLORS.get(anom_st.upper(), "#94A3B8")))
            self.ev_table.setItem(row, 5, st_item)
        self.ev_detail_box.clear()
        if hasattr(self, "btn_ack"):
            self.btn_ack.setEnabled(False)
            self.btn_res.setEnabled(False)

    def _on_anomaly_selected(self) -> None:
        row = self.ev_table.currentRow()
        if row < 0 or row >= len(getattr(self, "_device_anomalies", [])):
            if hasattr(self, "btn_ack"):
                self.btn_ack.setEnabled(False)
                self.btn_res.setEnabled(False)
            return
        a = self._device_anomalies[row]
        if hasattr(self, "btn_ack"):
            st = str(a.get("status", "")).upper()
            self.btn_ack.setEnabled(st == "ACTIVE")
            self.btn_res.setEnabled(st in ("ACTIVE", "ACKNOWLEDGED"))
        lines = [f"TITLE: {a.get('title', '')}", "", "OBSERVED EVIDENCE (FACTS):"]
        for ev in a.get("evidence", []):
            lines.append(f"  • {ev}")
        lines.extend(["", f"INFERRED PROBABLE CAUSE (Confidence: {a.get('confidence', 'MEDIUM')}):", f"  {a.get('probable_cause', '')}", "", "RECOMMENDED ACTIONS:"])
        for act in a.get("recommended_actions", []):
            lines.append(f"  - {act}")
        self.ev_detail_box.setPlainText("\n".join(lines))

    def _ack_selected_anomaly(self) -> None:
        row = self.ev_table.currentRow()
        if row < 0 or row >= len(getattr(self, "_device_anomalies", [])):
            return
        self.intelligence_engine.acknowledge_anomaly(self._device_anomalies[row]["id"])
        self._refresh_events_tab()

    def _resolve_selected_anomaly(self) -> None:
        row = self.ev_table.currentRow()
        if row < 0 or row >= len(getattr(self, "_device_anomalies", [])):
            return
        self.intelligence_engine.resolve_anomaly(self._device_anomalies[row]["id"])
        self._refresh_events_tab()

    def _refresh_history_tab(self) -> None:
        metric = self.hist_metric_combo.currentData() or "cpu_pct"
        gran = self.hist_gran_combo.currentData() or "raw"
        self.hist_plot.clear()
        if gran == "raw":
            rows = self.db.get_snmp_metrics(self.device_id, metric_name=metric, limit=500)
            vals = [float(r["metric_value"]) for r in rows]
            if vals:
                self.hist_plot.plot(list(range(len(vals))), vals, pen=pg.mkPen("#06B6D4", width=2))
                self.hist_stats_lbl.setText(f"Min: {min(vals):.2f} | Avg: {sum(vals)/len(vals):.2f} | Max: {max(vals):.2f}")
            else:
                self.hist_stats_lbl.setText("Min: -- | Avg: -- | Max: --")
        else:
            agg_rows = self.db.get_aggregated_snmp_metrics(self.device_id, metric_name=metric, granularity=gran)
            if not agg_rows:
                self.db.aggregate_snmp_metrics(gran)
                agg_rows = self.db.get_aggregated_snmp_metrics(self.device_id, metric_name=metric, granularity=gran)
            if agg_rows:
                xs = list(range(len(agg_rows)))
                avgs = [float(r["avg_value"]) for r in agg_rows]
                maxs = [float(r["max_value"]) for r in agg_rows]
                if not getattr(self.hist_plot, "_legend_added", False):
                    self.hist_plot.addLegend()
                    self.hist_plot._legend_added = True
                self.hist_plot.plot(xs, avgs, pen=pg.mkPen("#6366F1", width=2), name="Avg")
                self.hist_plot.plot(xs, maxs, pen=pg.mkPen("#F59E0B", width=1.5), name="Max")
                self.hist_stats_lbl.setText(
                    f"Min: {min(r['min_value'] for r in agg_rows):.2f} | Avg: {sum(avgs)/len(avgs):.2f} | Max: {max(maxs):.2f}"
                )
            else:
                self.hist_stats_lbl.setText("Min: -- | Avg: -- | Max: --")

    def _load_config_tab(self, dev: Dict[str, Any]) -> None:
        self.cfg_name.setText(str(dev.get("name") or ""))
        self.cfg_location.setText(str(dev.get("location") or dev.get("sys_location") or ""))
        idx = self.cfg_profile.findData(dev.get("profile_name", "generic_switch"))
        if idx >= 0:
            self.cfg_profile.setCurrentIndex(idx)
        self.cfg_poll_int.setValue(int(dev.get("poll_interval_sec") or 30))
        self.cfg_temp_int.setValue(int(dev.get("temp_interval_sec") or 60))
        self.cfg_poe_int.setValue(int(dev.get("poe_interval_sec") or 60))
        self.cfg_sys_int.setValue(int(dev.get("sysinfo_interval_sec") or 300))
        self.cfg_timeout.setValue(float(dev.get("timeout_sec") or 2.0))
        self.cfg_retries.setValue(int(dev.get("retries") if dev.get("retries") is not None else 1))

        prof = get_profile(dev.get("profile_name", "generic_switch"))
        t = dict(dev.get("thresholds") or {})
        def_tw, def_tc = resolve_temperature_thresholds(prof, str(dev.get("model") or ""), None)
        self.cfg_cpu_warn.setValue(float(t.get("cpu_warn_pct", prof.cpu_warn_pct)))
        self.cfg_cpu_crit.setValue(float(t.get("cpu_crit_pct", prof.cpu_crit_pct)))
        self.cfg_mem_warn.setValue(float(t.get("mem_warn_pct", prof.mem_warn_pct)))
        self.cfg_mem_crit.setValue(float(t.get("mem_crit_pct", prof.mem_crit_pct)))
        self.cfg_temp_warn.setValue(float(t.get("temp_warn_c", def_tw)))
        self.cfg_temp_crit.setValue(float(t.get("temp_crit_c", def_tc)))
        self.cfg_poe_warn.setValue(float(t.get("poe_warn_pct", 80.0)))
        self.cfg_poe_crit.setValue(float(t.get("poe_crit_pct", 90.0)))
        self.cfg_enabled.setChecked(bool(dev.get("enabled", True)))
        self.cfg_anomaly.setChecked(bool(dev.get("anomaly_detection_enabled", True)))

    def _save_device_config(self) -> None:
        pairs = [
            ("CPU", self.cfg_cpu_warn.value(), self.cfg_cpu_crit.value()),
            ("Memory", self.cfg_mem_warn.value(), self.cfg_mem_crit.value()),
            ("Temperature", self.cfg_temp_warn.value(), self.cfg_temp_crit.value()),
            ("PoE", self.cfg_poe_warn.value(), self.cfg_poe_crit.value()),
        ]
        for label, wv, cv in pairs:
            if wv >= cv:
                QMessageBox.warning(self, _("msg_warning", "Warning"), f"{label}: Warning ({wv}) must be less than Critical ({cv}).")
                return
        updates = {
            "name": self.cfg_name.text().strip() or f"Device #{self.device_id}",
            "location": self.cfg_location.text().strip(),
            "profile_name": self.cfg_profile.currentData() or "generic_switch",
            "poll_interval_sec": int(self.cfg_poll_int.value()),
            "temp_interval_sec": int(self.cfg_temp_int.value()),
            "poe_interval_sec": int(self.cfg_poe_int.value()),
            "sysinfo_interval_sec": int(self.cfg_sys_int.value()),
            "timeout_sec": float(self.cfg_timeout.value()),
            "retries": int(self.cfg_retries.value()),
            "enabled": bool(self.cfg_enabled.isChecked()),
            "anomaly_detection_enabled": bool(self.cfg_anomaly.isChecked()),
            "thresholds": {
                "cpu_warn_pct": float(self.cfg_cpu_warn.value()),
                "cpu_crit_pct": float(self.cfg_cpu_crit.value()),
                "mem_warn_pct": float(self.cfg_mem_warn.value()),
                "mem_crit_pct": float(self.cfg_mem_crit.value()),
                "temp_warn_c": float(self.cfg_temp_warn.value()),
                "temp_crit_c": float(self.cfg_temp_crit.value()),
                "poe_warn_pct": float(self.cfg_poe_warn.value()),
                "poe_crit_pct": float(self.cfg_poe_crit.value()),
            },
        }
        self.db.update_snmp_device(self.device_id, updates)
        if self.snmp_engine is not None:
            self.snmp_engine.reload_from_db()
        self.refresh_all()
        QMessageBox.information(self, _("msg_info", "Information"), _("devdet_cfg_saved", "Device configuration saved and applied."))

    def _on_poll_now(self) -> None:
        if self.snmp_engine is None or (self._poll_worker is not None and self._poll_worker.isRunning()):
            return
        self.btn_poll_now.setEnabled(False)
        self.btn_poll_now.setText(_("devdet_polling", "Polling..."))
        self._poll_worker = _PollDeviceWorker(self.snmp_engine, self.device_id, self)
        self._poll_worker.finished_poll.connect(self._on_poll_done)
        self._poll_worker.failed_poll.connect(self._on_poll_failed)
        self._poll_worker.start()

    def _on_poll_done(self, _snap: Any) -> None:
        self.btn_poll_now.setEnabled(True)
        self.btn_poll_now.setText(_("devdet_poll_now", "Poll Now"))
        self.refresh_all()

    def _on_poll_failed(self, err: str) -> None:
        self.btn_poll_now.setEnabled(True)
        self.btn_poll_now.setText(_("devdet_poll_now", "Poll Now"))
        QMessageBox.warning(self, _("msg_error", "Error"), err)

    def _stop_poll_worker(self) -> None:
        if self._poll_worker is not None and self._poll_worker.isRunning():
            self._poll_worker.wait(2500)

    def done(self, r: int) -> None:
        self._stop_poll_worker()
        super().done(r)

    def closeEvent(self, event) -> None:
        self._stop_poll_worker()
        super().closeEvent(event)
