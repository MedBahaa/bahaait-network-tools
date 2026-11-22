import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.device_health import format_uptime
from core.monitoring_state import validate_target_address
from core.snmp_client import SNMPClient, SNMPDiscoveryResult
from core.snmp_engine import AsyncSNMPEngine, attach_standard_collectors
from core.snmp_profiles import SNMP_PROFILES, get_profile
from ui.widgets.device_details_view import DeviceDetailsDialog
from utils.db import DatabaseManager
from utils.i18n import _
from utils.snmp_credentials import SNMPCredentials, encrypt_credentials, scrub_secrets


_STATUS_COLORS = {
    "ONLINE": "#10B981",
    "DEGRADED": "#F59E0B",
    "OFFLINE": "#F43F5E",
    "UNKNOWN": "#94A3B8",
}


class _DiscoveryWorker(QThread):
    """Runs SNMP test & discovery in the background without blocking the UI thread."""

    finished_discovery = Signal(object)

    def __init__(
        self,
        client: SNMPClient,
        ip: str,
        creds: SNMPCredentials,
        port: int,
        timeout_sec: float,
        retries: int,
        profile_override: str,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.client = client
        self.ip = ip
        self.creds = creds
        self.port = port
        self.timeout_sec = timeout_sec
        self.retries = retries
        self.profile_override = profile_override

    def run(self) -> None:
        try:
            res = asyncio.run(
                self.client.discover_device(
                    self.ip,
                    self.creds,
                    port=self.port,
                    timeout_sec=self.timeout_sec,
                    retries=self.retries,
                    profile_override=self.profile_override,
                )
            )
            self.finished_discovery.emit(res)
        except Exception as e:
            self.finished_discovery.emit(
                SNMPDiscoveryResult(
                    ip_address=self.ip,
                    port=self.port,
                    snmp_version=self.creds.version,
                    reachable=False,
                    error=scrub_secrets(str(e), self.creds),
                )
            )


class _PollAllWorker(QThread):
    """Polls all enabled SNMP devices once asynchronously off the Qt GUI thread."""

    finished_batch = Signal()

    def __init__(self, engine: AsyncSNMPEngine, device_ids: List[int], parent=None) -> None:
        super().__init__(parent)
        self.engine = engine
        self.device_ids = [int(d) for d in device_ids]

    def run(self) -> None:
        async def _poll_all() -> None:
            sem = asyncio.Semaphore(25)

            async def _one(did: int) -> None:
                async with sem:
                    await self.engine.poll_device_by_id(did)

            await asyncio.gather(*(_one(d) for d in self.device_ids), return_exceptions=True)

        try:
            if self.device_ids:
                asyncio.run(_poll_all())
                self.engine.flush_now()
        finally:
            self.finished_batch.emit()


class AddSNMPDeviceDialog(QDialog):
    """Dialog for configuring, testing, discovering, and encrypting credentials for an SNMP device."""

    def __init__(self, parent=None, client: Optional[SNMPClient] = None) -> None:
        super().__init__(parent)
        self.client = client or SNMPClient()
        self._discovery_res: Optional[SNMPDiscoveryResult] = None
        self._device_data: Optional[Dict[str, Any]] = None
        self._disc_worker: Optional[_DiscoveryWorker] = None

        self.setWindowTitle(_("snmp_dlg_add_title", "Add SNMP Device"))
        self.setMinimumWidth(560)
        self.setStyleSheet("QDialog { background-color: #0F172A; color: #F1F5F9; }")

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(12)

        form = QFormLayout()
        form.setSpacing(10)

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("SW-CORE-01")
        self.ip_edit = QLineEdit()
        self.ip_edit.setPlaceholderText("192.168.1.10")
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(161)

        self.version_combo = QComboBox()
        self.version_combo.addItems(["v2c", "v3", "v1"])
        self.version_combo.currentTextChanged.connect(self._on_version_changed)

        self.profile_combo = QComboBox()
        self.profile_combo.addItem("auto (Auto-detect)", "")
        for pname, prof in SNMP_PROFILES.items():
            self.profile_combo.addItem(f"{pname} ({prof.vendor} — {prof.device_type})", pname)

        form.addRow(_("snmp_dlg_name", "Device Name:"), self.name_edit)
        form.addRow(_("snmp_dlg_ip", "IP Address / Hostname:"), self.ip_edit)
        form.addRow(_("snmp_dlg_port", "UDP Port:"), self.port_spin)
        form.addRow(_("snmp_dlg_version", "SNMP Version:"), self.version_combo)
        form.addRow(_("snmp_dlg_profile", "Vendor Profile:"), self.profile_combo)

        # v1 / v2c Credentials Frame
        self.v2_frame = QFrame()
        v2_form = QFormLayout(self.v2_frame)
        v2_form.setContentsMargins(0, 0, 0, 0)
        v2_form.setSpacing(8)
        self.community_edit = QLineEdit()
        self.community_edit.setEchoMode(QLineEdit.Password)
        self.community_edit.setPlaceholderText("public / custom community")
        v2_form.addRow(_("snmp_dlg_community", "Community String:"), self.community_edit)
        form.addRow(self.v2_frame)

        # v3 Credentials Frame
        self.v3_frame = QFrame()
        v3_form = QFormLayout(self.v3_frame)
        v3_form.setContentsMargins(0, 0, 0, 0)
        v3_form.setSpacing(8)
        self.v3_user_edit = QLineEdit()
        self.v3_sec_combo = QComboBox()
        self.v3_sec_combo.addItems(["authPriv", "authNoPriv", "noAuthNoPriv"])
        self.v3_sec_combo.currentTextChanged.connect(self._on_sec_level_changed)
        self.v3_auth_proto = QComboBox()
        self.v3_auth_proto.addItems(["SHA256", "SHA", "SHA512", "SHA384", "SHA224", "MD5"])
        self.v3_auth_pass = QLineEdit()
        self.v3_auth_pass.setEchoMode(QLineEdit.Password)
        self.v3_priv_proto = QComboBox()
        self.v3_priv_proto.addItems(["AES128", "AES256", "AES192", "AES", "3DES", "DES"])
        self.v3_priv_pass = QLineEdit()
        self.v3_priv_pass.setEchoMode(QLineEdit.Password)

        v3_form.addRow(_("snmp_dlg_username", "SNMPv3 Username:"), self.v3_user_edit)
        v3_form.addRow(_("snmp_dlg_sec_level", "Security Level:"), self.v3_sec_combo)
        v3_form.addRow(_("snmp_dlg_auth_proto", "Auth Protocol:"), self.v3_auth_proto)
        v3_form.addRow(_("snmp_dlg_auth_pass", "Auth Password:"), self.v3_auth_pass)
        v3_form.addRow(_("snmp_dlg_priv_proto", "Privacy Protocol:"), self.v3_priv_proto)
        v3_form.addRow(_("snmp_dlg_priv_pass", "Privacy Password:"), self.v3_priv_pass)
        form.addRow(self.v3_frame)

        # Polling / Location / Anomaly
        self.poll_int_spin = QSpinBox()
        self.poll_int_spin.setRange(5, 3600)
        self.poll_int_spin.setValue(30)
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(0.5, 30.0)
        self.timeout_spin.setSingleStep(0.5)
        self.timeout_spin.setValue(2.0)
        self.retries_spin = QSpinBox()
        self.retries_spin.setRange(0, 5)
        self.retries_spin.setValue(1)
        self.location_edit = QLineEdit()
        self.anomaly_chk = QCheckBox(_("snmp_dlg_anomaly", "Enable Statistical Anomaly Detection"))
        self.anomaly_chk.setChecked(True)

        form.addRow(_("snmp_dlg_interval", "Poll Interval (s):"), self.poll_int_spin)
        form.addRow(_("snmp_dlg_timeout", "Timeout (s):"), self.timeout_spin)
        form.addRow(_("snmp_dlg_retries", "Retries:"), self.retries_spin)
        form.addRow(_("snmp_dlg_location", "Location:"), self.location_edit)
        form.addRow("", self.anomaly_chk)
        root.addLayout(form)

        # Discovery Result Banner (never shows secrets)
        self.disc_banner = QLabel("")
        self.disc_banner.setWordWrap(True)
        self.disc_banner.setStyleSheet(
            "background-color: #1E293B; color: #CBD5E1; border: 1px solid #334155; "
            "border-radius: 8px; padding: 8px 10px; font-size: 12px; margin-bottom: 0px;"
        )
        self.disc_banner.hide()
        root.addWidget(self.disc_banner)

        # Action Buttons
        btns = QHBoxLayout()
        self.btn_test = QPushButton(_("snmp_dlg_test", "Test & Discover"))
        self.btn_test.setObjectName("SecondaryButton")
        self.btn_test.clicked.connect(self._on_test_discover)
        btns.addWidget(self.btn_test)
        btns.addStretch()

        self.btn_cancel = QPushButton(_("snmp_dlg_cancel", "Cancel"))
        self.btn_cancel.setObjectName("SecondaryButton")
        self.btn_cancel.clicked.connect(self.reject)
        btns.addWidget(self.btn_cancel)

        self.btn_save = QPushButton(_("snmp_dlg_save", "Save Device"))
        self.btn_save.setObjectName("PrimaryButton")
        self.btn_save.clicked.connect(self._on_save)
        btns.addWidget(self.btn_save)
        root.addLayout(btns)

        self._on_version_changed(self.version_combo.currentText())
        self._on_sec_level_changed(self.v3_sec_combo.currentText())

    def _on_version_changed(self, ver: str) -> None:
        is_v3 = ver == "v3"
        self.v2_frame.setVisible(not is_v3)
        self.v3_frame.setVisible(is_v3)

    def _on_sec_level_changed(self, lvl: str) -> None:
        has_auth = lvl in ("authNoPriv", "authPriv")
        has_priv = lvl == "authPriv"
        self.v3_auth_proto.setEnabled(has_auth)
        self.v3_auth_pass.setEnabled(has_auth)
        self.v3_priv_proto.setEnabled(has_priv)
        self.v3_priv_pass.setEnabled(has_priv)

    def _build_credentials(self) -> SNMPCredentials:
        ver = self.version_combo.currentText()
        if ver in ("v1", "v2c"):
            creds = SNMPCredentials(version=ver, community=self.community_edit.text().strip())
        else:
            lvl = self.v3_sec_combo.currentText()
            creds = SNMPCredentials(
                version="v3",
                username=self.v3_user_edit.text().strip(),
                security_level=lvl,
                auth_protocol=self.v3_auth_proto.currentText() if lvl in ("authNoPriv", "authPriv") else "NONE",
                auth_password=self.v3_auth_pass.text() if lvl in ("authNoPriv", "authPriv") else "",
                priv_protocol=self.v3_priv_proto.currentText() if lvl == "authPriv" else "NONE",
                priv_password=self.v3_priv_pass.text() if lvl == "authPriv" else "",
            )
        creds.validate()
        return creds

    def _on_test_discover(self) -> None:
        ok, clean_ip = validate_target_address(self.ip_edit.text())
        if not ok:
            QMessageBox.warning(self, _("msg_warning", "Warning"), _("snmp_dlg_err_ip", "Please enter a valid IP address or hostname."))
            return
        try:
            creds = self._build_credentials()
        except ValueError as ve:
            QMessageBox.warning(self, _("msg_warning", "Warning"), _("snmp_dlg_err_cred", "Credential validation error: {}").format(ve))
            return

        self.btn_test.setEnabled(False)
        self.btn_test.setText(_("snmp_dlg_testing", "Discovering..."))
        self.disc_banner.setText(_("snmp_dlg_testing", "Discovering..."))
        self.disc_banner.show()

        self._disc_worker = _DiscoveryWorker(
            self.client,
            clean_ip,
            creds,
            int(self.port_spin.value()),
            float(self.timeout_spin.value()),
            int(self.retries_spin.value()),
            self.profile_combo.currentData() or "",
            self,
        )
        self._disc_worker.finished_discovery.connect(self._on_discovery_finished)
        self._disc_worker.start()

    def _on_discovery_finished(self, res: SNMPDiscoveryResult) -> None:
        self.btn_test.setEnabled(True)
        self.btn_test.setText(_("snmp_dlg_test", "Test & Discover"))
        self._discovery_res = res
        if res.reachable:
            self.disc_banner.setStyleSheet(
                "background-color: rgba(16,185,129,0.12); color: #10B981; border: 1px solid #10B981; "
                "border-radius: 8px; padding: 8px 10px; font-size: 12px; margin-bottom: 0px;"
            )
            caps_on = [k for k, v in (res.capabilities or {}).items() if v]
            caps_str = ", ".join(caps_on) if caps_on else "MIB-II System"
            self.disc_banner.setText(
                _("snmp_dlg_disc_ok", "Reachable ({} ms) | Vendor: {} | Model: {} | Profile: {}").format(
                    res.rtt_ms, res.vendor, res.model or "N/A", res.profile_name
                )
                + f"\nCapabilities: {caps_str}"
            )
            if not self.name_edit.text().strip() and res.sys_name:
                self.name_edit.setText(res.sys_name)
            if not self.location_edit.text().strip() and res.sys_location:
                self.location_edit.setText(res.sys_location)
            if (self.profile_combo.currentData() or "") == "":
                p_idx = self.profile_combo.findData(res.profile_name)
                if p_idx >= 0:
                    self.profile_combo.setCurrentIndex(p_idx)
        else:
            self.disc_banner.setStyleSheet(
                "background-color: rgba(244,63,94,0.12); color: #F43F5E; border: 1px solid #F43F5E; "
                "border-radius: 8px; padding: 8px 10px; font-size: 12px; margin-bottom: 0px;"
            )
            self.disc_banner.setText(
                _("snmp_dlg_disc_fail", "Discovery failed: {}").format(res.error or "No response")
            )

    def _on_save(self) -> None:
        ok, clean_ip = validate_target_address(self.ip_edit.text())
        if not ok:
            QMessageBox.warning(self, _("msg_warning", "Warning"), _("snmp_dlg_err_ip", "Please enter a valid IP address or hostname."))
            return
        try:
            creds = self._build_credentials()
        except ValueError as ve:
            QMessageBox.warning(self, _("msg_warning", "Warning"), _("snmp_dlg_err_cred", "Credential validation error: {}").format(ve))
            return

        sel_profile = self.profile_combo.currentData() or (
            self._discovery_res.profile_name if self._discovery_res and self._discovery_res.reachable else "generic_switch"
        )
        prof = get_profile(sel_profile)
        disc = self._discovery_res if (self._discovery_res and self._discovery_res.ip_address == clean_ip) else None

        self._device_data = {
            "name": self.name_edit.text().strip() or (disc.sys_name if disc and disc.sys_name else clean_ip),
            "ip_address": clean_ip,
            "port": int(self.port_spin.value()),
            "snmp_version": creds.version,
            "encrypted_credentials": encrypt_credentials(creds),
            "vendor": disc.vendor if disc and disc.reachable else prof.vendor,
            "model": disc.model if disc and disc.reachable else "",
            "firmware": disc.firmware if disc and disc.reachable else "",
            "device_type": disc.device_type if disc and disc.reachable else prof.device_type,
            "profile_name": sel_profile,
            "sys_descr": disc.sys_descr if disc and disc.reachable else "",
            "sys_object_id": disc.sys_object_id if disc and disc.reachable else "",
            "sys_name": disc.sys_name if disc and disc.reachable else "",
            "sys_location": disc.sys_location if disc and disc.reachable else "",
            "location": self.location_edit.text().strip() or (disc.sys_location if disc else ""),
            "status": "ONLINE" if disc and disc.reachable else "UNKNOWN",
            "enabled": True,
            "anomaly_detection_enabled": bool(self.anomaly_chk.isChecked()),
            "timeout_sec": float(self.timeout_spin.value()),
            "retries": int(self.retries_spin.value()),
            "poll_interval_sec": int(self.poll_int_spin.value()),
            "capabilities": dict(disc.capabilities) if disc and disc.reachable else {},
        }
        self.accept()

    def get_device_data(self) -> Optional[Dict[str, Any]]:
        return dict(self._device_data) if self._device_data is not None else None

    def closeEvent(self, event) -> None:
        if self._disc_worker is not None and self._disc_worker.isRunning():
            self._disc_worker.wait(2000)
        super().closeEvent(event)


class SNMPView(QWidget):
    """Main Infrastructure SNMP Monitoring screen (Navigation Index 11)."""

    def __init__(
        self,
        logger,
        config_manager=None,
        db: Optional[DatabaseManager] = None,
        engine: Optional[AsyncSNMPEngine] = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.logger = logger
        self.config_manager = config_manager
        self.db = db or DatabaseManager()
        self.engine = engine or AsyncSNMPEngine(self.db)
        if not getattr(self.engine, "_collectors", None):
            attach_standard_collectors(self.engine)
        self.engine.reload_from_db()

        self._poll_all_worker: Optional[_PollAllWorker] = None
        self._row_device_ids: List[int] = []

        self.engine.device_updated.connect(self._on_engine_device_updated)
        self.engine.device_status_changed.connect(self._on_engine_device_updated)

        self._build_ui()
        self.refresh_devices()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 22, 24, 22)
        root.setSpacing(14)

        # Header + Controls
        hdr = QHBoxLayout()
        hdr.setSpacing(10)
        title = QLabel(_("snmp_title", "SNMP Infrastructure Monitoring"))
        title.setObjectName("Title")
        title.setStyleSheet("font-size: 24px; font-weight: 800; color: #FFFFFF; margin-bottom: 0px;")
        hdr.addWidget(title)
        hdr.addStretch()

        self.engine_badge = QLabel(_("snmp_status_stopped", "POLLING STOPPED"))
        self.engine_badge.setStyleSheet(
            "background-color: #334155; color: #CBD5E1; border-radius: 8px; padding: 6px 12px; font-weight: bold; font-size: 11px; margin-bottom: 0px;"
        )
        hdr.addWidget(self.engine_badge)

        self.btn_toggle_engine = QPushButton(_("snmp_btn_start", "Start Polling"))
        self.btn_toggle_engine.setObjectName("PrimaryButton")
        self.btn_toggle_engine.clicked.connect(self.toggle_engine)
        hdr.addWidget(self.btn_toggle_engine)

        self.btn_poll_all = QPushButton(_("snmp_btn_poll_all", "Poll All Now"))
        self.btn_poll_all.setObjectName("SecondaryButton")
        self.btn_poll_all.clicked.connect(self.poll_all_now)
        hdr.addWidget(self.btn_poll_all)

        self.btn_add = QPushButton(_("snmp_btn_add", "Add SNMP Device"))
        self.btn_add.setObjectName("PrimaryButton")
        self.btn_add.clicked.connect(self.open_add_dialog)
        hdr.addWidget(self.btn_add)

        self.btn_refresh = QPushButton(_("snmp_btn_refresh", "Refresh"))
        self.btn_refresh.setObjectName("SecondaryButton")
        self.btn_refresh.clicked.connect(self.refresh_devices)
        hdr.addWidget(self.btn_refresh)
        root.addLayout(hdr)

        # KPI Row (6 Cards)
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(12)
        self.kpi_total = self._make_kpi_card(kpi_row, _("snmp_kpi_total", "Total Devices"), "0", "#FFFFFF")
        self.kpi_online = self._make_kpi_card(kpi_row, _("snmp_kpi_online", "Online"), "0", "#10B981")
        self.kpi_degraded = self._make_kpi_card(kpi_row, _("snmp_kpi_degraded", "Degraded"), "0", "#F59E0B")
        self.kpi_offline = self._make_kpi_card(kpi_row, _("snmp_kpi_offline", "Offline"), "0", "#F43F5E")
        self.kpi_cpu = self._make_kpi_card(kpi_row, _("snmp_kpi_avg_cpu", "Average CPU"), "--", "#06B6D4")
        self.kpi_mem = self._make_kpi_card(kpi_row, _("snmp_kpi_avg_mem", "Average Memory"), "--", "#6366F1")
        root.addLayout(kpi_row)

        # Filter Row
        filt = QHBoxLayout()
        filt.setSpacing(10)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText(_("snmp_filter_search", "Search name, IP, vendor, model..."))
        self.search_edit.textChanged.connect(self.refresh_devices)
        filt.addWidget(self.search_edit, 2)

        st_lbl = QLabel(_("snmp_filter_status", "Status:"))
        st_lbl.setStyleSheet("margin-bottom: 0px;")
        filt.addWidget(st_lbl)
        self.status_filter = QComboBox()
        self.status_filter.addItem(_("snmp_filter_all", "All"), "ALL")
        for st in ("ONLINE", "DEGRADED", "OFFLINE", "UNKNOWN"):
            self.status_filter.addItem(st, st)
        self.status_filter.currentIndexChanged.connect(self.refresh_devices)
        filt.addWidget(self.status_filter)
        root.addLayout(filt)

        # Devices Table (12 columns)
        headers = [
            _("snmp_col_name", "Device Name"),
            _("snmp_col_ip", "IP : Port"),
            _("snmp_col_vendor_model", "Vendor / Model"),
            _("snmp_col_version", "SNMP"),
            _("snmp_col_status", "Status"),
            _("snmp_col_cpu", "CPU %"),
            _("snmp_col_mem", "RAM %"),
            _("snmp_col_temp", "Temp"),
            _("snmp_col_ifaces", "Interfaces"),
            _("snmp_col_uptime", "Uptime"),
            _("snmp_col_last_poll", "Last Poll"),
            _("snmp_col_actions", "Actions"),
        ]
        self.table = QTableWidget(0, len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.cellDoubleClicked.connect(self._on_row_double_clicked)
        root.addWidget(self.table, 1)

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

    def toggle_engine(self) -> None:
        if self.engine.isRunning():
            self.engine.stop(timeout_ms=3000)
            self.btn_toggle_engine.setText(_("snmp_btn_start", "Start Polling"))
            self.engine_badge.setText(_("snmp_status_stopped", "POLLING STOPPED"))
            self.engine_badge.setStyleSheet(
                "background-color: #334155; color: #CBD5E1; border-radius: 8px; padding: 6px 12px; font-weight: bold; font-size: 11px; margin-bottom: 0px;"
            )
        else:
            self.engine.reload_from_db()
            self.engine.start()
            self.btn_toggle_engine.setText(_("snmp_btn_stop", "Stop Polling"))
            self.engine_badge.setText(_("snmp_status_running", "POLLING ACTIVE"))
            self.engine_badge.setStyleSheet(
                "background-color: rgba(16,185,129,0.2); color: #10B981; border: 1px solid #10B981; "
                "border-radius: 8px; padding: 6px 12px; font-weight: bold; font-size: 11px; margin-bottom: 0px;"
            )

    def poll_all_now(self) -> None:
        if self._poll_all_worker is not None and self._poll_all_worker.isRunning():
            return
        dev_ids = [int(d["id"]) for d in self.db.get_snmp_devices(enabled_only=True)]
        if not dev_ids:
            return
        self.engine.reload_from_db()
        self.btn_poll_all.setEnabled(False)
        self._poll_all_worker = _PollAllWorker(self.engine, dev_ids, self)
        self._poll_all_worker.finished_batch.connect(self._on_poll_all_done)
        self._poll_all_worker.start()

    def _on_poll_all_done(self) -> None:
        self.btn_poll_all.setEnabled(True)
        self.refresh_devices()

    def open_add_dialog(self) -> None:
        dlg = AddSNMPDeviceDialog(self)
        if dlg.exec() == QDialog.Accepted:
            payload = dlg.get_device_data()
            if payload is not None:
                added = self.db.add_snmp_device(payload)
                if added is None:
                    QMessageBox.warning(self, _("msg_warning", "Warning"), _("snmp_dlg_err_dup", "A device with this IP address already exists."))
                    return
                self.engine.reload_from_db()
                self.refresh_devices()

    def _on_engine_device_updated(self, _payload: Dict[str, Any]) -> None:
        self.refresh_devices()

    def get_live_snapshots(self) -> Dict[int, Dict[str, Any]]:
        return self.engine.get_all_snapshots()

    def refresh_devices(self) -> None:
        devices = self.db.get_snmp_devices(enabled_only=False)
        snaps = self.engine.get_all_snapshots()

        online = degraded = offline = 0
        cpu_vals: List[float] = []
        mem_vals: List[float] = []

        enriched: List[Dict[str, Any]] = []
        for d in devices:
            did = int(d["id"])
            snap = snaps.get(did) or {}
            metrics = dict(snap.get("metrics") or {})
            if not metrics:
                for mr in self.db.get_snmp_metrics(did, limit=50):
                    metrics[mr["metric_name"]] = float(mr["metric_value"])

            st = str(snap.get("status") or d.get("status") or "UNKNOWN").upper()
            if st == "ONLINE":
                online += 1
            elif st == "DEGRADED":
                degraded += 1
            elif st == "OFFLINE":
                offline += 1

            if "cpu_pct" in metrics:
                cpu_vals.append(float(metrics["cpu_pct"]))
            if "memory_pct" in metrics:
                mem_vals.append(float(metrics["memory_pct"]))

            ifaces = self.db.get_snmp_interfaces(did)
            up_if = sum(1 for i in ifaces if str(i.get("oper_status")).upper() == "UP")

            enriched.append({
                "device": d,
                "snap": snap,
                "metrics": metrics,
                "status": st,
                "ifaces_up": up_if,
                "ifaces_total": len(ifaces),
            })

        self.kpi_total.setText(str(len(devices)))
        self.kpi_online.setText(str(online))
        self.kpi_degraded.setText(str(degraded))
        self.kpi_offline.setText(str(offline))
        self.kpi_cpu.setText(f"{sum(cpu_vals)/len(cpu_vals):.1f}%" if cpu_vals else "--")
        self.kpi_mem.setText(f"{sum(mem_vals)/len(mem_vals):.1f}%" if mem_vals else "--")

        q = self.search_edit.text().strip().lower()
        st_filt = self.status_filter.currentData() or "ALL"

        self.table.setRowCount(0)
        self._row_device_ids = []
        for entry in enriched:
            d = entry["device"]
            st = entry["status"]
            if st_filt != "ALL" and st != st_filt:
                continue
            vm_txt = f"{d.get('vendor', 'Generic')} {d.get('model', '')}".strip()
            if q and not (
                q in d["name"].lower()
                or q in d["ip_address"].lower()
                or q in vm_txt.lower()
            ):
                continue

            did = int(d["id"])
            metrics = entry["metrics"]
            snap = entry["snap"]
            ticks = snap.get("last_uptime_ticks") or d.get("last_uptime_ticks")
            lp = snap.get("last_poll") or d.get("last_poll")
            lp_str = lp.strftime("%H:%M:%S") if isinstance(lp, datetime) else "--"

            row = self.table.rowCount()
            self.table.insertRow(row)
            self._row_device_ids.append(did)
            self.table.setRowHeight(row, 40)

            self.table.setItem(row, 0, QTableWidgetItem(d["name"]))
            self.table.setItem(row, 1, QTableWidgetItem(f"{d['ip_address']}:{d['port']}"))
            self.table.setItem(row, 2, QTableWidgetItem(vm_txt))
            self.table.setItem(row, 3, QTableWidgetItem(str(d.get("snmp_version", "v2c"))))

            st_it = QTableWidgetItem(st)
            st_it.setForeground(QColor(_STATUS_COLORS.get(st, "#94A3B8")))
            self.table.setItem(row, 4, st_it)

            self.table.setItem(row, 5, QTableWidgetItem(f"{metrics['cpu_pct']:.1f}%" if "cpu_pct" in metrics else "--"))
            self.table.setItem(row, 6, QTableWidgetItem(f"{metrics['memory_pct']:.1f}%" if "memory_pct" in metrics else "--"))
            self.table.setItem(row, 7, QTableWidgetItem(f"{metrics['temperature_max_c']:.1f}°C" if "temperature_max_c" in metrics else "--"))
            self.table.setItem(row, 8, QTableWidgetItem(f"{entry['ifaces_up']}/{entry['ifaces_total']}" if entry["ifaces_total"] else "--"))
            self.table.setItem(row, 9, QTableWidgetItem(format_uptime(ticks)))
            self.table.setItem(row, 10, QTableWidgetItem(lp_str))

            act_w = QWidget()
            act_l = QHBoxLayout(act_w)
            act_l.setContentsMargins(4, 2, 4, 2)
            act_l.setSpacing(6)
            btn_det = QPushButton(_("snmp_btn_details", "Details"))
            btn_det.setStyleSheet("background-color: #334155; color: #FFFFFF; border-radius: 6px; padding: 4px 8px; font-size: 11px;")
            btn_det.clicked.connect(lambda _c, target_id=did: self.open_device_details(target_id))
            btn_del = QPushButton(_("snmp_btn_delete", "Delete"))
            btn_del.setStyleSheet("background-color: rgba(244,63,94,0.2); color: #F43F5E; border: 1px solid #F43F5E; border-radius: 6px; padding: 4px 8px; font-size: 11px;")
            btn_del.clicked.connect(lambda _c, target_id=did, nm=d["name"], ip=d["ip_address"]: self.delete_device(target_id, nm, ip))
            act_l.addWidget(btn_det)
            act_l.addWidget(btn_del)
            self.table.setCellWidget(row, 11, act_w)

    def _on_row_double_clicked(self, row: int, _col: int) -> None:
        if 0 <= row < len(self._row_device_ids):
            self.open_device_details(self._row_device_ids[row])

    def open_device_details(self, device_id: int) -> None:
        dlg = DeviceDetailsDialog(self.db, device_id, snmp_engine=self.engine, parent=self)
        dlg.exec()
        self.refresh_devices()

    def delete_device(self, device_id: int, name: str, ip: str) -> None:
        ans = QMessageBox.question(
            self,
            _("snmp_delete_confirm_title", "Delete SNMP Device"),
            _("snmp_delete_confirm_msg", "Delete SNMP device '{}' ({})?").format(name, ip),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if ans == QMessageBox.Yes:
            self.engine.remove_device(device_id)
            self.db.delete_snmp_device(device_id)
            self.refresh_devices()

    def shutdown(self) -> None:
        if self._poll_all_worker is not None and self._poll_all_worker.isRunning():
            self._poll_all_worker.wait(2000)
        if self.engine is not None and self.engine.isRunning():
            self.engine.stop(timeout_ms=3000)
