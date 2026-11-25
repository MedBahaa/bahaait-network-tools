import json
from typing import Any, Dict, List, Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
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
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.audit_logger import AuditLogger
from utils.db import DatabaseManager
from utils.i18n import _


class AuditView(QWidget):
    """Immutable Infrastructure Change & Command Audit Trail viewer with SHA-256 verification."""

    def __init__(self, db: Optional[DatabaseManager] = None, auth_manager: Any = None, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.db = db or DatabaseManager()
        self.audit = AuditLogger(self.db, auth_manager=auth_manager)
        self._events_cache: List[Dict[str, Any]] = []

        self._setup_ui()
        self.refresh()

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(12)

        # Header Row 1: Title + Wrapped Subtitle
        t_lbl = QLabel(_("aud_title", "Infrastructure Audit & Change Trail"))
        t_lbl.setObjectName("Title")
        t_lbl.setStyleSheet("font-size: 20px; font-weight: bold; color: #F8FAFC;")
        s_lbl = QLabel(_("aud_subtitle", "Append-only SQLite audit log with automatic secret redaction and SHA-256 hash verification"))
        s_lbl.setWordWrap(True)
        s_lbl.setStyleSheet("color: #94A3B8; font-size: 12px;")
        root.addWidget(t_lbl)
        root.addWidget(s_lbl)

        # Header Row 2: Action Buttons
        hdr_btns = QHBoxLayout()
        hdr_btns.setSpacing(8)
        self.btn_verify_all = QPushButton(_("aud_btn_verify", "Verify SHA-256 Hashes"))
        self.btn_verify_all.setObjectName("PrimaryButton")
        self.btn_verify_all.clicked.connect(self._verify_all)
        self.btn_exp_csv = QPushButton(_("inv_btn_export_csv", "Export CSV"))
        self.btn_exp_csv.setObjectName("SecondaryButton")
        self.btn_exp_csv.clicked.connect(self._export_csv)
        self.btn_exp_json = QPushButton(_("aud_btn_json", "Export JSON"))
        self.btn_exp_json.setObjectName("SecondaryButton")
        self.btn_exp_json.clicked.connect(self._export_json)
        self.btn_refresh = QPushButton(_("common_refresh", "Refresh"))
        self.btn_refresh.setObjectName("SecondaryButton")
        self.btn_refresh.clicked.connect(self.refresh)
        for b in (self.btn_verify_all, self.btn_exp_csv, self.btn_exp_json, self.btn_refresh):
            b.setCursor(Qt.PointingHandCursor)
            b.setToolTip(b.text())
            hdr_btns.addWidget(b)
        hdr_btns.addStretch()
        root.addLayout(hdr_btns)

        # Filter bar (scoped #FilterBar prevents cascaded label borders)
        bar = QFrame()
        bar.setObjectName("FilterBar")
        b_l = QHBoxLayout(bar)
        b_l.setContentsMargins(12, 8, 12, 8)
        b_l.setSpacing(10)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(_("aud_search_ph", "Filter device, IP, operation, ticket, detail..."))
        self.search_input.textChanged.connect(self.refresh)
        b_l.addWidget(self.search_input, 1)

        b_l.addWidget(QLabel(_("aud_lbl_tier", "Tier:")))
        self.tier_combo = QComboBox()
        self.tier_combo.setMinimumWidth(115)
        self.tier_combo.addItem(_("common_all", "All"), "")
        for t in ("SYSTEM", "READ_ONLY", "MODIFYING", "DESTRUCTIVE"):
            self.tier_combo.addItem(t, t)
        self.tier_combo.currentIndexChanged.connect(self.refresh)
        b_l.addWidget(self.tier_combo)

        b_l.addWidget(QLabel(_("aud_lbl_result", "Result:")))
        self.result_combo = QComboBox()
        self.result_combo.setMinimumWidth(110)
        self.result_combo.addItem(_("common_all", "All"), "")
        for r in ("SUCCESS", "BLOCKED", "FAILURE"):
            self.result_combo.addItem(r, r)
        self.result_combo.currentIndexChanged.connect(self.refresh)
        b_l.addWidget(self.result_combo)
        root.addWidget(bar)

        split = QSplitter(Qt.Vertical)
        split.setChildrenCollapsible(False)
        self.table = QTableWidget(0, 10)
        self.table.setHorizontalHeaderLabels([
            _("bkp_col_ts", "Timestamp"),
            "UID",
            _("aud_col_user", "Operator"),
            _("inv_col_hostname", "Device"),
            _("site_hdr_ip", "IP"),
            _("aud_col_op", "Operation"),
            _("aud_col_tier", "Tier"),
            _("aud_col_res", "Result"),
            _("aud_col_ticket", "Ticket"),
            _("aud_col_integrity", "Hash Check"),
        ])
        ahdr = self.table.horizontalHeader()
        ahdr.setSectionResizeMode(QHeaderView.Interactive)
        ahdr.setSectionResizeMode(5, QHeaderView.Stretch)
        self.table.setColumnWidth(0, 128)
        self.table.setColumnWidth(1, 86)
        self.table.setColumnWidth(2, 82)
        self.table.setColumnWidth(3, 102)
        self.table.setColumnWidth(4, 100)
        self.table.setColumnWidth(6, 80)
        self.table.setColumnWidth(7, 74)
        self.table.setColumnWidth(8, 68)
        self.table.setColumnWidth(9, 122)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.itemSelectionChanged.connect(self._on_row_selected)
        split.addWidget(self.table)

        self.detail_box = QTextEdit()
        self.detail_box.setReadOnly(True)
        self.detail_box.setPlaceholderText(_("aud_detail_ph", "Select an audit record to inspect redacted values and SHA-256 hash."))
        self.detail_box.setStyleSheet(
            "QTextEdit { background-color: #020617; color: #E2E8F0; font-family: Consolas; font-size: 11px; border: 1px solid #334155; padding: 8px; }"
        )
        split.addWidget(self.detail_box)
        split.setSizes([280, 180])
        root.addWidget(split, 1)

        self.summary_lbl = QLabel("")
        self.summary_lbl.setStyleSheet("color: #94A3B8; font-size: 12px;")
        root.addWidget(self.summary_lbl)

    def refresh(self) -> None:
        events = self.audit.query_events(
            search=self.search_input.text().strip(),
            command_tier=self.tier_combo.currentData() or "",
            result=self.result_combo.currentData() or "",
            limit=500,
        )
        self._events_cache = events
        self.table.setRowCount(0)
        tampered = 0
        for ev in events:
            r = self.table.rowCount()
            self.table.insertRow(r)
            ts_s = ev["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if ev.get("timestamp") else "-"
            valid = self.audit.verify_record_integrity(ev)
            if not valid:
                tampered += 1

            self.table.setItem(r, 0, QTableWidgetItem(ts_s))
            self.table.setItem(r, 1, QTableWidgetItem(ev["event_uid"]))
            self.table.setItem(r, 2, QTableWidgetItem(ev["username"]))
            self.table.setItem(r, 3, QTableWidgetItem(ev["device_name"] or "-"))
            self.table.setItem(r, 4, QTableWidgetItem(ev["device_ip"] or "-"))
            self.table.setItem(r, 5, QTableWidgetItem(ev["operation"]))

            t_it = QTableWidgetItem(ev["command_tier"])
            if ev["command_tier"] == "DESTRUCTIVE":
                t_it.setForeground(QColor("#F43F5E"))
            elif ev["command_tier"] == "MODIFYING":
                t_it.setForeground(QColor("#F59E0B"))
            self.table.setItem(r, 6, t_it)

            r_it = QTableWidgetItem(ev["result"])
            r_it.setForeground(QColor("#10B981" if ev["result"] == "SUCCESS" else ("#F59E0B" if ev["result"] == "BLOCKED" else "#F43F5E")))
            self.table.setItem(r, 7, r_it)
            self.table.setItem(r, 8, QTableWidgetItem(ev["ticket_ref"] or "-"))

            v_it = QTableWidgetItem("VALID" if valid else "TAMPERED")
            v_it.setForeground(QColor("#10B981" if valid else "#F43F5E"))
            self.table.setItem(r, 9, v_it)

        self.summary_lbl.setText(f"Records: {len(events)} | Hash Check Failures: {tampered}")
        if not events:
            self.detail_box.clear()

    def _on_row_selected(self) -> None:
        r = self.table.currentRow()
        if r < 0 or r >= len(self._events_cache):
            self.detail_box.clear()
            return
        ev = self._events_cache[r]
        d_name = ev.get("device_name") or ""
        d_ip = ev.get("device_ip") or ""
        dev_str = f"{d_name} ({d_ip})".strip() if (d_name and d_ip) else (d_name or d_ip or "—")
        payload = {
            "event_uid": ev["event_uid"],
            "timestamp": str(ev["timestamp"]),
            "username": ev["username"],
            "operation": ev["operation"],
            "command_tier": ev["command_tier"],
            "result": ev["result"],
            "device": dev_str,
            "ticket_ref": ev["ticket_ref"],
            "previous_value": ev["previous_value"],
            "new_value": ev["new_value"],
            "detail": ev["detail"],
            "record_hash": ev["record_hash"],
            "integrity_ok": self.audit.verify_record_integrity(ev),
        }
        self.detail_box.setPlainText(json.dumps(payload, indent=2, default=str))

    def _verify_all(self) -> None:
        self.refresh()
        failed = [e["event_uid"] for e in self._events_cache if not self.audit.verify_record_integrity(e)]
        if failed:
            QMessageBox.critical(self, "Audit Integrity", f"Tampered records detected: {', '.join(failed)}")
        else:
            QMessageBox.information(self, "Audit Integrity", f"All {len(self._events_cache)} displayed audit record SHA-256 hashes verified.")

    def _export_csv(self) -> None:
        path, _flt = QFileDialog.getSaveFileName(self, "Export Audit CSV", "audit_trail.csv", "CSV Files (*.csv)")
        if not path:
            return
        try:
            self.audit.export_csv(path, self._events_cache)
            QMessageBox.information(self, _("msg_success", "Success"), f"Audit CSV exported to:\n{path}")
        except Exception as exc:
            QMessageBox.critical(self, _("common_error", "Error"), str(exc))

    def _export_json(self) -> None:
        path, _flt = QFileDialog.getSaveFileName(self, "Export Audit JSON", "audit_trail.json", "JSON Files (*.json)")
        if not path:
            return
        try:
            self.audit.export_json(path, self._events_cache)
            QMessageBox.information(self, _("msg_success", "Success"), f"Audit JSON exported to:\n{path}")
        except Exception as exc:
            QMessageBox.critical(self, _("common_error", "Error"), str(exc))

    def shutdown(self) -> None:
        return None
