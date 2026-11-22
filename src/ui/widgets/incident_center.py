from datetime import datetime, timedelta
import html
from typing import Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from core.incident_manager import IncidentManager, IncidentStatus
from utils.db import DatabaseManager
from utils.i18n import _
from utils.monitoring_export import export_incidents_csv, export_incidents_pdf


class IncidentCenterWidget(QWidget):
    """Incident Center view: filters, acknowledgement, technician comments, and CSV/PDF export."""

    active_count_changed = Signal(int)
    incidents_changed = Signal()

    def __init__(self, incident_manager: IncidentManager, db: DatabaseManager, parent=None):
        super().__init__(parent)
        self.incident_manager = incident_manager
        self.db = db

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 12, 0, 0)
        layout.setSpacing(12)

        # Filter Toolbar
        filters_row = QHBoxLayout()
        filters_row.setSpacing(10)

        filters_row.addWidget(QLabel(_("inc_filter_severity", "Severity:")))
        self.severity_combo = QComboBox()
        self.severity_combo.addItem(_("inc_filter_all", "All"), None)
        for sev in ("CRITICAL", "WARNING", "INFO"):
            self.severity_combo.addItem(sev, sev)
        self.severity_combo.currentIndexChanged.connect(self.refresh_incidents)
        filters_row.addWidget(self.severity_combo)

        filters_row.addWidget(QLabel(_("inc_filter_status", "Status:")))
        self.status_combo = QComboBox()
        self.status_combo.addItem(_("inc_filter_all", "All"), None)
        for st in (
            IncidentStatus.DETECTED.value,
            IncidentStatus.ACKNOWLEDGED.value,
            IncidentStatus.RECOVERED.value,
            IncidentStatus.CLOSED.value,
        ):
            self.status_combo.addItem(st, st)
        self.status_combo.currentIndexChanged.connect(self.refresh_incidents)
        filters_row.addWidget(self.status_combo)

        filters_row.addWidget(QLabel(_("inc_filter_host", "Host:")))
        self.host_combo = QComboBox()
        self.host_combo.setMinimumWidth(140)
        self.host_combo.currentIndexChanged.connect(self.refresh_incidents)
        filters_row.addWidget(self.host_combo)

        filters_row.addWidget(QLabel(_("inc_filter_date", "Period:")))
        self.date_combo = QComboBox()
        self.date_combo.addItem(_("inc_filter_all", "All"), None)
        self.date_combo.addItem(_("inc_date_24h", "Last 24 Hours"), 1)
        self.date_combo.addItem(_("inc_date_7d", "Last 7 Days"), 7)
        self.date_combo.addItem(_("inc_date_30d", "Last 30 Days"), 30)
        self.date_combo.currentIndexChanged.connect(self.refresh_incidents)
        filters_row.addWidget(self.date_combo)

        filters_row.addStretch()

        self.refresh_btn = QPushButton(_("inc_btn_refresh", "Refresh"))
        self.refresh_btn.setObjectName("SecondaryButton")
        self.refresh_btn.setFixedHeight(34)
        self.refresh_btn.setCursor(Qt.PointingHandCursor)
        self.refresh_btn.clicked.connect(self.refresh_incidents)
        filters_row.addWidget(self.refresh_btn)

        self.export_csv_btn = QPushButton(_("inc_btn_export_csv", "Export CSV"))
        self.export_csv_btn.setObjectName("SecondaryButton")
        self.export_csv_btn.setFixedHeight(34)
        self.export_csv_btn.setCursor(Qt.PointingHandCursor)
        self.export_csv_btn.clicked.connect(self.export_csv)
        filters_row.addWidget(self.export_csv_btn)

        self.export_pdf_btn = QPushButton(_("inc_btn_export_pdf", "Export PDF"))
        self.export_pdf_btn.setObjectName("SecondaryButton")
        self.export_pdf_btn.setFixedHeight(34)
        self.export_pdf_btn.setCursor(Qt.PointingHandCursor)
        self.export_pdf_btn.clicked.connect(self.export_pdf)
        filters_row.addWidget(self.export_pdf_btn)

        layout.addLayout(filters_row)

        # Incident Table (10 columns)
        self.table = QTableWidget(0, 10)
        self.table.setHorizontalHeaderLabels([
            _("inc_col_uid", "Incident ID").upper(),
            _("inc_col_severity", "Severity").upper(),
            _("inc_col_host", "Host").upper(),
            _("inc_col_ip", "IP").upper(),
            _("inc_col_type", "Type").upper(),
            _("inc_col_status", "Status").upper(),
            _("inc_col_start", "Start Time").upper(),
            _("inc_col_duration", "Duration").upper(),
            _("inc_col_loss", "Loss %").upper(),
            _("inc_col_comments", "Comments").upper(),
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(8, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setDefaultSectionSize(42)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #1E293B;
                alternate-background-color: #161E2D;
                border: 1px solid rgba(255, 255, 255, 0.05);
                border-radius: 12px;
                gridline-color: transparent;
            }
            QTableWidget::item {
                padding-left: 8px;
                padding-right: 8px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.02);
            }
            QHeaderView::section {
                background-color: #0F172A;
                padding: 8px;
                font-weight: bold;
                font-size: 11px;
                letter-spacing: 0.8px;
            }
        """)
        self.table.doubleClicked.connect(self.view_selected_details)
        layout.addWidget(self.table, 1)

        # Action Bar
        actions_row = QHBoxLayout()
        actions_row.setSpacing(10)

        self.ack_btn = QPushButton(_("inc_btn_ack", "Acknowledge"))
        self.ack_btn.setObjectName("PrimaryButton")
        self.ack_btn.setFixedHeight(36)
        self.ack_btn.setCursor(Qt.PointingHandCursor)
        self.ack_btn.clicked.connect(self.acknowledge_selected)

        self.comment_btn = QPushButton(_("inc_btn_comment", "Add Comment"))
        self.comment_btn.setObjectName("SecondaryButton")
        self.comment_btn.setFixedHeight(36)
        self.comment_btn.setCursor(Qt.PointingHandCursor)
        self.comment_btn.clicked.connect(self.comment_selected)

        self.close_btn = QPushButton(_("inc_btn_close", "Close Incident"))
        self.close_btn.setObjectName("SecondaryButton")
        self.close_btn.setFixedHeight(36)
        self.close_btn.setCursor(Qt.PointingHandCursor)
        self.close_btn.clicked.connect(self.close_selected)

        self.details_btn = QPushButton(_("inc_btn_details", "Details"))
        self.details_btn.setObjectName("SecondaryButton")
        self.details_btn.setFixedHeight(36)
        self.details_btn.setCursor(Qt.PointingHandCursor)
        self.details_btn.clicked.connect(self.view_selected_details)

        self.delete_btn = QPushButton(_("inc_btn_delete", "Delete Incident"))
        self.delete_btn.setObjectName("DangerButton")
        self.delete_btn.setFixedHeight(36)
        self.delete_btn.setStyleSheet("padding: 0px 14px;")
        self.delete_btn.setCursor(Qt.PointingHandCursor)
        self.delete_btn.clicked.connect(self.delete_selected)

        actions_row.addWidget(self.ack_btn)
        actions_row.addWidget(self.comment_btn)
        actions_row.addWidget(self.close_btn)
        actions_row.addWidget(self.details_btn)
        actions_row.addStretch()
        actions_row.addWidget(self.delete_btn)

        layout.addLayout(actions_row)

        self._cached_rows = []
        self._reload_host_filter()
        self.refresh_incidents()

    def _reload_host_filter(self) -> None:
        current = self.host_combo.currentData()
        self.host_combo.blockSignals(True)
        self.host_combo.clear()
        self.host_combo.addItem(_("inc_filter_all", "All"), None)
        addrs = set()
        for h in self.db.get_hosts():
            addrs.add(h["address"])
        for inc in self.incident_manager.get_incidents(limit=500):
            addrs.add(inc["host_address"])
        for a in sorted(addrs):
            self.host_combo.addItem(a, a)
        idx = self.host_combo.findData(current)
        self.host_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self.host_combo.blockSignals(False)

    def _get_filtered_incidents(self):
        sev = self.severity_combo.currentData()
        status = self.status_combo.currentData()
        host_addr = self.host_combo.currentData()
        days = self.date_combo.currentData()
        start_date: Optional[datetime] = datetime.utcnow() - timedelta(days=days) if days else None
        return self.incident_manager.get_incidents(
            severity=sev,
            host_address=host_addr,
            status=status,
            start_date=start_date,
            limit=500,
        )

    @staticmethod
    def _format_duration(seconds: float) -> str:
        s = int(max(0, round(seconds or 0.0)))
        if s < 60:
            return f"{s}s"
        if s < 3600:
            return f"{s // 60}m {s % 60}s"
        return f"{s // 3600}h {(s % 3600) // 60}m"

    def refresh_incidents(self) -> None:
        selected_id = self._selected_incident_id()
        self._reload_host_filter()
        rows = self._get_filtered_incidents()
        self._cached_rows = rows
        self.table.setRowCount(0)

        restore_row = -1
        for inc in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            if selected_id is not None and inc["id"] == selected_id:
                restore_row = row

            uid_item = QTableWidgetItem(inc.get("incident_uid", ""))
            uid_item.setData(Qt.UserRole, inc["id"])
            uid_item.setTextAlignment(Qt.AlignCenter)

            sev = inc.get("severity", "INFO")
            sev_item = QTableWidgetItem(sev)
            sev_item.setTextAlignment(Qt.AlignCenter)
            bold_font = QFont()
            bold_font.setBold(True)
            sev_item.setFont(bold_font)
            if sev == "CRITICAL":
                sev_item.setForeground(QColor("#F43F5E"))
            elif sev == "WARNING":
                sev_item.setForeground(QColor("#F59E0B"))
            else:
                sev_item.setForeground(QColor("#38BDF8"))

            host_item = QTableWidgetItem(inc.get("host_name", ""))
            host_item.setTextAlignment(Qt.AlignCenter)

            ip_item = QTableWidgetItem(inc.get("host_address", ""))
            ip_item.setTextAlignment(Qt.AlignCenter)
            ip_item.setForeground(QColor("#818CF8"))

            type_item = QTableWidgetItem(inc.get("incident_type", ""))
            type_item.setTextAlignment(Qt.AlignCenter)

            st = inc.get("status", "")
            st_item = QTableWidgetItem(st)
            st_item.setTextAlignment(Qt.AlignCenter)
            st_item.setFont(bold_font)
            if st == IncidentStatus.DETECTED.value:
                st_item.setForeground(QColor("#F43F5E"))
            elif st == IncidentStatus.ACKNOWLEDGED.value:
                st_item.setForeground(QColor("#F59E0B"))
            elif st == IncidentStatus.RECOVERED.value:
                st_item.setForeground(QColor("#10B981"))
            else:
                st_item.setForeground(QColor("#94A3B8"))

            start_ts = inc.get("start_time")
            start_str = start_ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(start_ts, datetime) else str(start_ts or "")
            start_item = QTableWidgetItem(start_str)
            start_item.setTextAlignment(Qt.AlignCenter)

            dur_item = QTableWidgetItem(self._format_duration(inc.get("duration_seconds", 0.0)))
            dur_item.setTextAlignment(Qt.AlignCenter)

            loss_item = QTableWidgetItem(f"{float(inc.get('packet_loss_pct', 0.0)):.1f}%")
            loss_item.setTextAlignment(Qt.AlignCenter)

            comment_txt = (inc.get("comments") or "").replace("\n", " | ")
            comment_item = QTableWidgetItem(comment_txt)

            for col_idx, item in enumerate((
                uid_item, sev_item, host_item, ip_item, type_item,
                st_item, start_item, dur_item, loss_item, comment_item
            )):
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.table.setItem(row, col_idx, item)

        if restore_row >= 0:
            self.table.selectRow(restore_row)
            self.table.setCurrentCell(restore_row, 0)

        active_count = len(self.incident_manager.get_active_incidents())
        self.active_count_changed.emit(active_count)

    def _selected_incident_id(self) -> Optional[int]:
        row = self.table.currentRow()
        if row < 0 and self.table.selectionModel() is not None:
            selected = self.table.selectionModel().selectedRows()
            if selected:
                row = selected[0].row()
        if row < 0:
            return None
        item = self.table.item(row, 0)
        if not item:
            return None
        return item.data(Qt.UserRole)

    def acknowledge_selected(self) -> None:
        inc_id = self._selected_incident_id()
        if inc_id is None:
            QMessageBox.information(self, _("msg_info"), _("inc_none_selected", "Please select an incident first."))
            return
        note, ok = QInputDialog.getText(
            self,
            _("inc_btn_ack", "Acknowledge"),
            _("inc_ack_prompt", "Optional technician acknowledgement note:"),
        )
        if ok:
            self.incident_manager.acknowledge_incident(inc_id, note)
            self.refresh_incidents()
            self.incidents_changed.emit()

    def comment_selected(self) -> None:
        inc_id = self._selected_incident_id()
        if inc_id is None:
            QMessageBox.information(self, _("msg_info"), _("inc_none_selected", "Please select an incident first."))
            return
        note, ok = QInputDialog.getText(
            self,
            _("inc_btn_comment", "Add Comment"),
            _("inc_comment_prompt", "Add technician comment:"),
        )
        if ok and note.strip():
            self.incident_manager.add_comment(inc_id, note)
            self.refresh_incidents()
            self.incidents_changed.emit()

    def close_selected(self) -> None:
        inc_id = self._selected_incident_id()
        if inc_id is None:
            QMessageBox.information(self, _("msg_info"), _("inc_none_selected", "Please select an incident first."))
            return
        self.incident_manager.close_incident(inc_id)
        self.refresh_incidents()
        self.incidents_changed.emit()

    def delete_selected(self) -> bool:
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
            self._reload_host_filter()
            self.refresh_incidents()
            self.incidents_changed.emit()
            return True
        return False

    def view_selected_details(self) -> None:
        inc_id = self._selected_incident_id()
        if inc_id is None:
            return
        inc = self.db.get_incident_by_id(inc_id)
        if not inc:
            return
        start_s = inc["start_time"].strftime("%Y-%m-%d %H:%M:%S") if isinstance(inc.get("start_time"), datetime) else str(inc.get("start_time"))
        end_s = inc["end_time"].strftime("%Y-%m-%d %H:%M:%S") if isinstance(inc.get("end_time"), datetime) else (inc.get("end_time") or "Ongoing")
        rec_lat = f"{inc['recovery_latency_ms']:.1f} ms" if inc.get("recovery_latency_ms") is not None else "N/A"
        comments_html = html.escape(inc.get("comments") or "—").replace("\n", "<br>")
        body = (
            f"<b>UID:</b> {html.escape(str(inc['incident_uid']))}<br>"
            f"<b>Host:</b> {html.escape(str(inc['host_name']))} ({html.escape(str(inc['host_address']))})<br>"
            f"<b>Type / Severity:</b> {html.escape(str(inc['incident_type']))} / {html.escape(str(inc['severity']))}<br>"
            f"<b>Status:</b> {html.escape(str(inc['status']))} | <b>Acknowledged:</b> {'Yes' if inc['acknowledged'] else 'No'}<br>"
            f"<b>Start:</b> {html.escape(start_s)}<br>"
            f"<b>End:</b> {html.escape(str(end_s))}<br>"
            f"<b>Duration:</b> {self._format_duration(inc.get('duration_seconds', 0.0))}<br>"
            f"<b>Failed Probes:</b> {inc['failed_probes']} | <b>Packet Loss:</b> {inc['packet_loss_pct']:.1f}%<br>"
            f"<b>Avg Latency Before Outage:</b> {inc['avg_latency_before_ms']:.1f} ms<br>"
            f"<b>Recovery Latency:</b> {rec_lat}<br><br>"
            f"<b>Comments:</b><br>{comments_html}"
        )
        QMessageBox.information(self, f"{inc['incident_uid']}", body)

    def export_csv(self) -> None:
        path, _f = QFileDialog.getSaveFileName(
            self, _("inc_btn_export_csv", "Export CSV"), "BahaaIT_Incidents.csv", "CSV Files (*.csv)"
        )
        if not path:
            return
        rows = self._get_filtered_incidents()
        self._cached_rows = rows
        ok, err = export_incidents_csv(rows, path)
        if ok:
            QMessageBox.information(self, _("msg_success"), _("inc_export_ok", "Incidents exported successfully."))
        else:
            QMessageBox.critical(self, _("msg_error"), err)

    def export_pdf(self) -> None:
        path, _f = QFileDialog.getSaveFileName(
            self, _("inc_btn_export_pdf", "Export PDF"), "BahaaIT_Incidents_Report.pdf", "PDF Files (*.pdf)"
        )
        if not path:
            return
        rows = self._get_filtered_incidents()
        self._cached_rows = rows
        ok, err = export_incidents_pdf(rows, path)
        if ok:
            QMessageBox.information(self, _("msg_success"), _("inc_export_ok", "Incidents exported successfully."))
        else:
            QMessageBox.critical(self, _("msg_error"), err)
