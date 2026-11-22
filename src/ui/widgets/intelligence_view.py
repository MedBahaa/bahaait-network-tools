from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.intelligence_engine import IntelligenceEngine
from ui.widgets.device_details_view import DeviceDetailsDialog
from utils.db import DatabaseManager
from utils.i18n import _


_SEV_COLORS = {
    "CRITICAL": "#F43F5E",
    "WARNING": "#F59E0B",
    "INFO": "#38BDF8",
}

_STATUS_COLORS = {
    "ACTIVE": "#F43F5E",
    "ACKNOWLEDGED": "#F59E0B",
    "RESOLVED": "#10B981",
}


class IntelligenceView(QWidget):
    """Network Intelligence & Root-Cause Correlation Console (Navigation Index 13)."""

    def __init__(
        self,
        logger,
        config_manager=None,
        db: Optional[DatabaseManager] = None,
        intelligence_engine: Optional[IntelligenceEngine] = None,
        snmp_snapshots_provider: Optional[Callable[[], Dict[int, Dict[str, Any]]]] = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.logger = logger
        self.config_manager = config_manager
        self.db = db or DatabaseManager()
        self.intelligence_engine = intelligence_engine or IntelligenceEngine(db=self.db)
        self._snmp_snapshots_provider = snmp_snapshots_provider
        self._visible_rows: List[Dict[str, Any]] = []

        self._build_ui()
        self.refresh_findings()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_findings)
        self.timer.start(15000)

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 22, 24, 22)
        root.setSpacing(12)

        # Header
        hdr = QHBoxLayout()
        title = QLabel(_("intel_title", "Network Intelligence & Root-Cause Correlation"))
        title.setObjectName("Title")
        title.setStyleSheet("font-size: 24px; font-weight: 800; color: #FFFFFF; margin-bottom: 0px;")
        hdr.addWidget(title)
        hdr.addStretch()

        self.btn_correlate = QPushButton(_("intel_btn_correlate", "Run Correlation Now"))
        self.btn_correlate.setObjectName("PrimaryButton")
        self.btn_correlate.clicked.connect(self.run_correlation_now)
        hdr.addWidget(self.btn_correlate)

        self.btn_refresh = QPushButton(_("intel_btn_refresh", "Refresh"))
        self.btn_refresh.setObjectName("SecondaryButton")
        self.btn_refresh.clicked.connect(self.refresh_findings)
        hdr.addWidget(self.btn_refresh)
        root.addLayout(hdr)

        # KPI Strip (4 cards)
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(12)
        self.kpi_open = self._make_kpi_card(kpi_row, _("intel_kpi_active", "Open Findings"), "0", "#FFFFFF")
        self.kpi_crit = self._make_kpi_card(kpi_row, _("intel_kpi_critical", "Critical"), "0", "#F43F5E")
        self.kpi_warn = self._make_kpi_card(kpi_row, _("intel_kpi_warning", "Warning"), "0", "#F59E0B")
        self.kpi_affected = self._make_kpi_card(kpi_row, _("intel_kpi_affected", "Affected Devices"), "0", "#06B6D4")
        root.addLayout(kpi_row)

        # Filter Bar
        filt = QHBoxLayout()
        filt.setSpacing(10)
        s_lbl = QLabel(_("intel_filter_status", "Status:"))
        s_lbl.setStyleSheet("margin-bottom: 0px;")
        filt.addWidget(s_lbl)
        self.status_combo = QComboBox()
        self.status_combo.addItem("OPEN (Active + Ack)", "OPEN")
        self.status_combo.addItem("ACTIVE", "ACTIVE")
        self.status_combo.addItem("ACKNOWLEDGED", "ACKNOWLEDGED")
        self.status_combo.addItem("RESOLVED", "RESOLVED")
        self.status_combo.addItem(_("snmp_filter_all", "All"), "ALL")
        self.status_combo.currentIndexChanged.connect(self.refresh_findings)
        filt.addWidget(self.status_combo)

        sev_lbl = QLabel(_("intel_filter_sev", "Severity:"))
        sev_lbl.setStyleSheet("margin-bottom: 0px;")
        filt.addWidget(sev_lbl)
        self.sev_combo = QComboBox()
        self.sev_combo.addItem(_("snmp_filter_all", "All"), "ALL")
        for sv in ("CRITICAL", "WARNING", "INFO"):
            self.sev_combo.addItem(sv, sv)
        self.sev_combo.currentIndexChanged.connect(self.refresh_findings)
        filt.addWidget(self.sev_combo)

        t_lbl = QLabel(_("intel_filter_type", "Event Type:"))
        t_lbl.setStyleSheet("margin-bottom: 0px;")
        filt.addWidget(t_lbl)
        self.type_combo = QComboBox()
        self.type_combo.addItem(_("snmp_filter_all", "All"), "ALL")
        for et in (
            "PHYSICAL_LINK_FAILURE",
            "SWITCH_OVERLOAD",
            "POE_BUDGET_EXHAUSTION",
            "UNEXPECTED_REBOOT",
            "INTERFACE_ERROR_DEGRADATION",
            "SYSLOG_SECURITY_BURST",
            "ANOMALY_CPU_PCT",
            "ANOMALY_MEMORY_PCT",
            "ANOMALY_TEMPERATURE_MAX_C",
        ):
            self.type_combo.addItem(et, et)
        self.type_combo.currentIndexChanged.connect(self.refresh_findings)
        filt.addWidget(self.type_combo)
        filt.addStretch()
        root.addLayout(filt)

        # Findings Table (8 columns)
        headers = [
            _("intel_col_time", "Detected At"),
            _("intel_col_sev", "Severity"),
            _("intel_col_conf", "Confidence"),
            _("intel_col_dev", "Device"),
            _("intel_col_ip", "IP"),
            _("intel_col_type", "Category / Type"),
            _("intel_col_title", "Title"),
            _("intel_col_status", "Status"),
        ]
        self.table = QTableWidget(0, len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self._on_finding_selected)
        root.addWidget(self.table, 2)

        # Three-Panel Diagnosis Inspector (strictly separating Observed Evidence vs Inferred Probable Cause vs Actions)
        panels = QHBoxLayout()
        panels.setSpacing(12)
        self.evidence_box = self._make_inspector_panel(
            panels, _("intel_panel_evidence", "OBSERVED EVIDENCE (FACTS)"), "#06B6D4"
        )
        self.cause_card, self.cause_box, self.confidence_badge = self._make_cause_panel(
            panels, _("intel_panel_cause", "INFERRED PROBABLE CAUSE"), "#F59E0B"
        )
        self.actions_box = self._make_inspector_panel(
            panels, _("intel_panel_actions", "RECOMMENDED ACTIONS"), "#10B981"
        )
        root.addLayout(panels, 1)

        # Bottom Action Buttons
        acts = QHBoxLayout()
        acts.setSpacing(10)
        self.btn_ack = QPushButton(_("intel_btn_ack", "Acknowledge"))
        self.btn_ack.setObjectName("SecondaryButton")
        self.btn_ack.clicked.connect(self._ack_selected)
        acts.addWidget(self.btn_ack)

        self.btn_resolve = QPushButton(_("intel_btn_resolve", "Mark Resolved"))
        self.btn_resolve.setObjectName("PrimaryButton")
        self.btn_resolve.clicked.connect(self._resolve_selected)
        acts.addWidget(self.btn_resolve)

        self.btn_open_device = QPushButton(_("intel_btn_open_dev", "Open Device Details"))
        self.btn_open_device.setObjectName("SecondaryButton")
        self.btn_open_device.clicked.connect(self._open_selected_device)
        acts.addWidget(self.btn_open_device)
        acts.addStretch()
        root.addLayout(acts)

        self._clear_inspector()

    @staticmethod
    def _make_kpi_card(layout: QHBoxLayout, title: str, init_val: str, color: str) -> QLabel:
        frame = QFrame()
        frame.setObjectName("Card")
        fl = QVBoxLayout(frame)
        fl.setContentsMargins(12, 10, 12, 10)
        fl.setSpacing(2)
        val_lbl = QLabel(init_val)
        val_lbl.setAlignment(Qt.AlignCenter)
        val_lbl.setStyleSheet(f"font-size: 20px; font-weight: 800; color: {color}; margin-bottom: 0px;")
        t_lbl = QLabel(title)
        t_lbl.setAlignment(Qt.AlignCenter)
        t_lbl.setStyleSheet("font-size: 11px; color: #94A3B8; font-weight: 700; text-transform: uppercase; margin-bottom: 0px;")
        fl.addWidget(val_lbl)
        fl.addWidget(t_lbl)
        layout.addWidget(frame)
        return val_lbl

    @staticmethod
    def _make_inspector_panel(layout: QHBoxLayout, title: str, accent: str) -> QTextEdit:
        card = QFrame()
        card.setObjectName("Card")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(12, 10, 12, 10)
        cl.setSpacing(6)
        hdr = QLabel(title)
        hdr.setStyleSheet(f"color: {accent}; font-weight: 800; font-size: 11px; letter-spacing: 0.8px; margin-bottom: 0px;")
        cl.addWidget(hdr)
        box = QTextEdit()
        box.setReadOnly(True)
        box.setMinimumHeight(130)
        box.setStyleSheet(
            "QTextEdit { background-color: #0F172A; color: #E2E8F0; border: 1px solid #334155; border-radius: 8px; padding: 8px; font-size: 12px; }"
        )
        cl.addWidget(box)
        layout.addWidget(card, 1)
        return box

    @staticmethod
    def _make_cause_panel(layout: QHBoxLayout, title: str, accent: str):
        card = QFrame()
        card.setObjectName("Card")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(12, 10, 12, 10)
        cl.setSpacing(6)
        top = QHBoxLayout()
        hdr = QLabel(title)
        hdr.setStyleSheet(f"color: {accent}; font-weight: 800; font-size: 11px; letter-spacing: 0.8px; margin-bottom: 0px;")
        conf_badge = QLabel("--")
        conf_badge.setStyleSheet(
            "background-color: #334155; color: #FFFFFF; border-radius: 6px; padding: 2px 8px; font-size: 10px; font-weight: bold; margin-bottom: 0px;"
        )
        top.addWidget(hdr)
        top.addStretch()
        top.addWidget(conf_badge)
        cl.addLayout(top)
        box = QTextEdit()
        box.setReadOnly(True)
        box.setMinimumHeight(130)
        box.setStyleSheet(
            "QTextEdit { background-color: #0F172A; color: #FDE68A; border: 1px solid #334155; border-radius: 8px; padding: 8px; font-size: 12px; }"
        )
        cl.addWidget(box)
        layout.addWidget(card, 1)
        return card, box, conf_badge

    def run_correlation_now(self) -> None:
        snaps = self._snmp_snapshots_provider() if callable(self._snmp_snapshots_provider) else {}
        self.intelligence_engine.correlate_all_devices(snmp_snapshots=snaps)
        self.refresh_findings()

    def refresh_findings(self) -> None:
        summary = self.intelligence_engine.get_infrastructure_summary()
        self.kpi_open.setText(str(summary["total_active"]))
        self.kpi_crit.setText(str(summary["critical_count"]))
        self.kpi_warn.setText(str(summary["warning_count"]))
        self.kpi_affected.setText(str(summary["affected_devices"]))

        st_filter = self.status_combo.currentData() or "OPEN"
        sev_filter = self.sev_combo.currentData() or "ALL"
        type_filter = self.type_combo.currentData() or "ALL"

        db_status = None if st_filter in ("OPEN", "ALL") else st_filter
        db_sev = None if sev_filter == "ALL" else sev_filter
        rows = self.db.get_network_anomalies(status=db_status, severity=db_sev, limit=300)

        filtered: List[Dict[str, Any]] = []
        for r in rows:
            if st_filter == "OPEN" and r["status"] not in ("ACTIVE", "ACKNOWLEDGED"):
                continue
            if type_filter != "ALL" and r["event_type"] != type_filter:
                continue
            filtered.append(r)

        self._visible_rows = filtered
        self.table.setRowCount(0)
        for r in filtered:
            row_idx = self.table.rowCount()
            self.table.insertRow(row_idx)
            ts = r.get("detected_at")
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime) else str(ts or "")
            sev = str(r.get("severity", "INFO"))
            st = str(r.get("status", "ACTIVE"))

            self.table.setItem(row_idx, 0, QTableWidgetItem(ts_str))
            sev_it = QTableWidgetItem(sev)
            sev_it.setForeground(QColor(_SEV_COLORS.get(sev, "#CBD5E1")))
            self.table.setItem(row_idx, 1, sev_it)
            self.table.setItem(row_idx, 2, QTableWidgetItem(str(r.get("confidence", "MEDIUM"))))
            self.table.setItem(row_idx, 3, QTableWidgetItem(str(r.get("device_name", ""))))
            self.table.setItem(row_idx, 4, QTableWidgetItem(str(r.get("device_ip", ""))))
            self.table.setItem(row_idx, 5, QTableWidgetItem(str(r.get("event_type", ""))))
            self.table.setItem(row_idx, 6, QTableWidgetItem(str(r.get("title", ""))))
            st_it = QTableWidgetItem(st)
            st_it.setForeground(QColor(_STATUS_COLORS.get(st, "#94A3B8")))
            self.table.setItem(row_idx, 7, st_it)

        if not filtered:
            self._clear_inspector()
        elif self.table.currentRow() < 0:
            self.table.selectRow(0)

    def _clear_inspector(self) -> None:
        hint = _("intel_none_selected", "Select a finding above to inspect observed evidence and root-cause analysis.")
        self.evidence_box.setPlainText(hint)
        self.cause_box.setPlainText("")
        self.confidence_badge.setText("--")
        self.actions_box.setPlainText("")

    def _selected_finding(self) -> Optional[Dict[str, Any]]:
        idx = self.table.currentRow()
        if 0 <= idx < len(self._visible_rows):
            return self._visible_rows[idx]
        return None

    def _on_finding_selected(self) -> None:
        f = self._selected_finding()
        if f is None:
            self._clear_inspector()
            return
        ev_lines = [f"• {e}" for e in f.get("evidence", [])]
        self.evidence_box.setPlainText("\n".join(ev_lines) if ev_lines else "No raw evidence attached.")
        self.cause_box.setPlainText(str(f.get("probable_cause") or ""))
        self.confidence_badge.setText(f"CONFIDENCE: {f.get('confidence', 'MEDIUM')}")
        act_lines = [f"{i + 1}. {a}" for i, a in enumerate(f.get("recommended_actions", []))]
        self.actions_box.setPlainText("\n".join(act_lines) if act_lines else "No actions listed.")

    def _ack_selected(self) -> None:
        f = self._selected_finding()
        if f is None:
            return
        self.intelligence_engine.acknowledge_anomaly(f["id"])
        self.refresh_findings()

    def _resolve_selected(self) -> None:
        f = self._selected_finding()
        if f is None:
            return
        self.intelligence_engine.resolve_anomaly(f["id"])
        self.refresh_findings()

    def _open_selected_device(self) -> None:
        f = self._selected_finding()
        if f is None or f.get("device_id") is None:
            return
        dlg = DeviceDetailsDialog(
            self.db,
            int(f["device_id"]),
            intelligence_engine=self.intelligence_engine,
            parent=self,
        )
        dlg.exec()
        self.refresh_findings()

    def shutdown(self) -> None:
        if hasattr(self, "timer") and self.timer is not None:
            self.timer.stop()
