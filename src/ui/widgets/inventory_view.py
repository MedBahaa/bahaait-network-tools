import json
from typing import Any, Dict, List, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
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

from core.inventory_manager import DEVICE_CATEGORIES, InventoryManager
from core.site_manager import SiteManager
from utils.db import DatabaseManager, SSHProfile
from utils.i18n import _

_STATUS_COLORS = {
    "UP": "#10B981",
    "ONLINE": "#10B981",
    "OK": "#10B981",
    "DEGRADED": "#F59E0B",
    "WARNING": "#F59E0B",
    "DOWN": "#F43F5E",
    "OFFLINE": "#F43F5E",
    "CRITICAL": "#F43F5E",
    "UNKNOWN": "#94A3B8",
}


class DeviceEditorDialog(QDialog):
    """Add/Edit Infrastructure Device dialog with General, Asset Lifecycle, and Tags tabs."""

    def __init__(
        self,
        sites: List[Dict[str, Any]],
        ssh_profiles: List[Dict[str, Any]],
        device: Optional[Dict[str, Any]] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.device = device
        is_edit = device is not None
        self.setWindowTitle(
            _("inv_dlg_edit_title", "Edit Infrastructure Device")
            if is_edit
            else _("inv_dlg_add_title", "Add Infrastructure Device")
        )
        self.setMinimumSize(620, 520)
        self.setStyleSheet("QDialog { background-color: #0F172A; color: #F1F5F9; }")

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(12)

        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        # Tab 1: General & Network
        tab_gen = QWidget()
        f_gen = QFormLayout(tab_gen)
        f_gen.setSpacing(8)

        self.hostname_edit = QLineEdit(device.get("hostname", "") if device else "")
        self.ip_edit = QLineEdit(device.get("management_ip", "") if device else "")
        self.mac_edit = QLineEdit(device.get("mac_address", "") if device else "")
        self.mac_edit.setPlaceholderText("AA:BB:CC:DD:EE:FF")
        self.vendor_edit = QLineEdit(device.get("vendor", "") if device else "")
        self.model_edit = QLineEdit(device.get("model", "") if device else "")
        self.fw_edit = QLineEdit(device.get("firmware_version", "") if device else "")

        self.category_combo = QComboBox()
        for cat in DEVICE_CATEGORIES:
            self.category_combo.addItem(cat, cat)
        if device and device.get("category"):
            idx = self.category_combo.findData(device["category"])
            if idx >= 0:
                self.category_combo.setCurrentIndex(idx)

        self.role_edit = QLineEdit(device.get("role", "") if device else "")
        self.site_combo = QComboBox()
        self.site_combo.addItem(_("inv_unassigned_site", "(Unassigned)"), None)
        for s in sites:
            self.site_combo.addItem(f"{s['name']} ({s['region']})", s["id"])
        if device and device.get("site_id") is not None:
            idx = self.site_combo.findData(device["site_id"])
            if idx >= 0:
                self.site_combo.setCurrentIndex(idx)

        self.rack_edit = QLineEdit(device.get("rack_location", "") if device else "")
        self.proto_combo = QComboBox()
        for p in ("SNMP", "SSH", "SNMP+SSH", "HTTPS", "ICMP", "API"):
            self.proto_combo.addItem(p, p)
        if device and device.get("management_protocol"):
            idx = self.proto_combo.findData(device["management_protocol"])
            if idx >= 0:
                self.proto_combo.setCurrentIndex(idx)
            else:
                self.proto_combo.addItem(device["management_protocol"], device["management_protocol"])
                self.proto_combo.setCurrentIndex(self.proto_combo.count() - 1)

        self.snmp_profile_edit = QLineEdit(device.get("snmp_profile", "") if device else "")
        self.ssh_profile_combo = QComboBox()
        self.ssh_profile_combo.addItem(_("inv_none", "(None)"), None)
        for sp in ssh_profiles:
            self.ssh_profile_combo.addItem(sp["name"], sp["id"])
        if device and device.get("ssh_profile_id") is not None:
            idx = self.ssh_profile_combo.findData(device["ssh_profile_id"])
            if idx >= 0:
                self.ssh_profile_combo.setCurrentIndex(idx)

        f_gen.addRow(_("inv_col_hostname", "Hostname") + " *:", self.hostname_edit)
        f_gen.addRow(_("inv_col_ip", "Management IP") + " *:", self.ip_edit)
        f_gen.addRow(_("inv_col_mac", "MAC Address") + ":", self.mac_edit)
        f_gen.addRow(_("inv_col_vendor", "Vendor") + ":", self.vendor_edit)
        f_gen.addRow(_("inv_col_model", "Model") + ":", self.model_edit)
        f_gen.addRow(_("inv_col_firmware", "Firmware") + ":", self.fw_edit)
        f_gen.addRow(_("inv_col_category", "Category") + ":", self.category_combo)
        f_gen.addRow(_("inv_col_role", "Role") + ":", self.role_edit)
        f_gen.addRow(_("inv_col_site", "Site") + ":", self.site_combo)
        f_gen.addRow(_("inv_col_rack", "Rack / Location") + ":", self.rack_edit)
        f_gen.addRow(_("inv_col_protocol", "Protocol") + ":", self.proto_combo)
        f_gen.addRow(_("inv_lbl_snmp_profile", "SNMP Profile") + ":", self.snmp_profile_edit)
        f_gen.addRow(_("inv_lbl_ssh_profile", "SSH Profile") + ":", self.ssh_profile_combo)
        tabs.addTab(tab_gen, _("inv_tab_general", "General & Network"))

        # Tab 2: Asset Lifecycle
        tab_asset = QWidget()
        f_asset = QFormLayout(tab_asset)
        f_asset.setSpacing(8)
        self.serial_edit = QLineEdit(device.get("serial_number", "") if device else "")
        self.mfg_edit = QLineEdit(device.get("manufacturer", "") if device else "")
        self.purchase_edit = QLineEdit(device.get("purchase_date", "") if device else "")
        self.purchase_edit.setPlaceholderText("YYYY-MM-DD")
        self.warranty_edit = QLineEdit(device.get("warranty_expiration", "") if device else "")
        self.warranty_edit.setPlaceholderText("YYYY-MM-DD")
        self.reminder_edit = QLineEdit(device.get("maintenance_reminder_date", "") if device else "")
        self.reminder_edit.setPlaceholderText("YYYY-MM-DD")
        self.owner_edit = QLineEdit(device.get("equipment_owner", "") if device else "")
        self.support_edit = QLineEdit(device.get("support_info", "") if device else "")
        self.notes_edit = QTextEdit(device.get("maintenance_notes", "") if device else "")
        self.notes_edit.setMaximumHeight(110)

        f_asset.addRow(_("inv_lbl_serial", "Serial Number") + ":", self.serial_edit)
        f_asset.addRow(_("inv_lbl_manufacturer", "Manufacturer") + ":", self.mfg_edit)
        f_asset.addRow(_("inv_lbl_purchase_date", "Purchase Date") + ":", self.purchase_edit)
        f_asset.addRow(_("inv_lbl_warranty", "Warranty Expiration") + ":", self.warranty_edit)
        f_asset.addRow(_("inv_lbl_reminder", "Maintenance Reminder") + ":", self.reminder_edit)
        f_asset.addRow(_("inv_lbl_owner", "Equipment Owner") + ":", self.owner_edit)
        f_asset.addRow(_("inv_lbl_support", "Support Info") + ":", self.support_edit)
        f_asset.addRow(_("inv_lbl_notes", "Maintenance Notes") + ":", self.notes_edit)
        tabs.addTab(tab_asset, _("inv_tab_asset", "Asset & Lifecycle"))

        # Tab 3: Grouping, Tags & Custom Fields
        tab_extra = QWidget()
        f_extra = QFormLayout(tab_extra)
        f_extra.setSpacing(8)
        self.group_edit = QLineEdit(device.get("device_group", "") if device else "")
        self.tags_edit = QLineEdit(", ".join(device.get("tags") or []) if device else "")
        self.tags_edit.setPlaceholderText("core, critical, building-a")
        self.custom_edit = QTextEdit(
            json.dumps(device.get("custom_fields") or {}, indent=2) if device and device.get("custom_fields") else "{}"
        )
        self.custom_edit.setMaximumHeight(160)

        f_extra.addRow(_("inv_lbl_group", "Device Group") + ":", self.group_edit)
        f_extra.addRow(_("inv_lbl_tags", "Tags (comma-sep)") + ":", self.tags_edit)
        f_extra.addRow(_("inv_lbl_custom_fields", "Custom Fields (JSON)") + ":", self.custom_edit)
        tabs.addTab(tab_extra, _("inv_tab_custom", "Tags & Custom Fields"))

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _on_accept(self) -> None:
        if not self.hostname_edit.text().strip() or not self.ip_edit.text().strip():
            QMessageBox.warning(
                self,
                _("msg_error", "Error"),
                _("inv_err_required", "Hostname and Management IP are required."),
            )
            return
        try:
            raw_json = self.custom_edit.toPlainText().strip() or "{}"
            parsed = json.loads(raw_json)
            if not isinstance(parsed, dict):
                raise ValueError("Custom fields must be a JSON object.")
        except Exception as exc:
            QMessageBox.warning(self, _("msg_error", "Error"), f"Invalid Custom Fields JSON: {exc}")
            return
        self.accept()

    def get_payload(self) -> Dict[str, Any]:
        tags = [t.strip() for t in self.tags_edit.text().split(",") if t.strip()]
        return {
            "hostname": self.hostname_edit.text().strip(),
            "management_ip": self.ip_edit.text().strip(),
            "mac_address": self.mac_edit.text().strip(),
            "vendor": self.vendor_edit.text().strip(),
            "model": self.model_edit.text().strip(),
            "firmware_version": self.fw_edit.text().strip(),
            "category": self.category_combo.currentData(),
            "role": self.role_edit.text().strip(),
            "site_id": self.site_combo.currentData(),
            "rack_location": self.rack_edit.text().strip(),
            "management_protocol": self.proto_combo.currentData(),
            "snmp_profile": self.snmp_profile_edit.text().strip(),
            "ssh_profile_id": self.ssh_profile_combo.currentData(),
            "serial_number": self.serial_edit.text().strip(),
            "manufacturer": self.mfg_edit.text().strip(),
            "purchase_date": self.purchase_edit.text().strip(),
            "warranty_expiration": self.warranty_edit.text().strip(),
            "maintenance_reminder_date": self.reminder_edit.text().strip(),
            "equipment_owner": self.owner_edit.text().strip(),
            "support_info": self.support_edit.text().strip(),
            "maintenance_notes": self.notes_edit.toPlainText().strip(),
            "device_group": self.group_edit.text().strip(),
            "tags": tags,
            "custom_fields": json.loads(self.custom_edit.toPlainText().strip() or "{}"),
        }


class InventoryView(QWidget):
    """Advanced Centralized Infrastructure Device Inventory view (v3.6.0)."""

    open_in_access_center = Signal(str, str)  # ip, protocol
    open_in_topology = Signal(int)  # device_id

    def __init__(
        self,
        logger: Any,
        config_manager: Any = None,
        db: Optional[DatabaseManager] = None,
        auth_manager: Any = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.logger = logger
        self.config = config_manager
        self.db = db or DatabaseManager()
        from core.audit_logger import AuditLogger
        self.audit_logger = AuditLogger(self.db, auth_manager=auth_manager)
        self.site_manager = SiteManager(self.db, audit_logger=self.audit_logger, config_manager=self.config)
        self.inventory = InventoryManager(self.db, audit_logger=self.audit_logger, site_manager=self.site_manager)

        self._devices_cache: List[Dict[str, Any]] = []
        self._build_ui()
        self.refresh_data()

    def _make_kpi_card(self, label_text: str, accent: str) -> QLabel:
        frame = QFrame()
        frame.setObjectName("Card")
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.setSpacing(2)
        val_lbl = QLabel("0")
        val_lbl.setAlignment(Qt.AlignCenter)
        val_lbl.setStyleSheet(f"font-size: 20px; font-weight: 800; color: {accent}; margin-bottom: 0px;")
        title_lbl = QLabel(label_text)
        title_lbl.setAlignment(Qt.AlignCenter)
        title_lbl.setStyleSheet("font-size: 10px; font-weight: bold; color: #94A3B8; text-transform: uppercase; margin-bottom: 0px;")
        lay.addWidget(val_lbl)
        lay.addWidget(title_lbl)
        self.kpi_layout.addWidget(frame)
        return val_lbl

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 22, 24, 22)
        root.setSpacing(14)

        # Header + Primary Actions
        hdr_row = QHBoxLayout()
        title = QLabel(_("inv_title", "Advanced Device Inventory"))
        title.setObjectName("Title")
        title.setStyleSheet("font-size: 24px; font-weight: 800; color: #FFFFFF; margin-bottom: 0px;")
        hdr_row.addWidget(title)
        hdr_row.addStretch()

        self.btn_sync = QPushButton(_("inv_btn_sync", "Sync SNMP / Hosts"))
        self.btn_sync.setObjectName("SecondaryButton")
        self.btn_sync.setCursor(Qt.PointingHandCursor)
        self.btn_sync.clicked.connect(self.on_sync_sources)

        self.btn_dups = QPushButton(_("inv_btn_check_dups", "Check Duplicates"))
        self.btn_dups.setObjectName("SecondaryButton")
        self.btn_dups.setCursor(Qt.PointingHandCursor)
        self.btn_dups.clicked.connect(self.on_check_duplicates)

        self.btn_import = QPushButton(_("inv_btn_import_csv", "Import CSV"))
        self.btn_import.setObjectName("SecondaryButton")
        self.btn_import.setCursor(Qt.PointingHandCursor)
        self.btn_import.clicked.connect(self.on_import_csv)

        self.btn_export_csv = QPushButton(_("inv_btn_export_csv", "Export CSV"))
        self.btn_export_csv.setObjectName("SecondaryButton")
        self.btn_export_csv.setCursor(Qt.PointingHandCursor)
        self.btn_export_csv.clicked.connect(self.on_export_csv)

        self.btn_export_pdf = QPushButton(_("inv_btn_export_pdf", "Export PDF"))
        self.btn_export_pdf.setObjectName("SecondaryButton")
        self.btn_export_pdf.setCursor(Qt.PointingHandCursor)
        self.btn_export_pdf.clicked.connect(self.on_export_pdf)

        self.btn_add = QPushButton("+ " + _("inv_btn_add", "Add Device"))
        self.btn_add.setObjectName("PrimaryButton")
        self.btn_add.setCursor(Qt.PointingHandCursor)
        self.btn_add.clicked.connect(self.on_add_device)

        for b in (self.btn_sync, self.btn_dups, self.btn_import, self.btn_export_csv, self.btn_export_pdf, self.btn_add):
            hdr_row.addWidget(b)
        root.addLayout(hdr_row)

        # KPI Strip
        self.kpi_layout = QHBoxLayout()
        self.kpi_layout.setSpacing(12)
        self.kpi_total = self._make_kpi_card(_("inv_kpi_total", "Total Devices"), "#FFFFFF")
        self.kpi_online = self._make_kpi_card(_("inv_kpi_online", "Online"), "#10B981")
        self.kpi_issues = self._make_kpi_card(_("inv_kpi_issues", "Degraded / Offline"), "#F43F5E")
        self.kpi_dups = self._make_kpi_card(_("inv_kpi_dups", "Duplicate IP / MAC"), "#F59E0B")
        self.kpi_maint = self._make_kpi_card(_("inv_kpi_maint", "Maintenance / Warranty Due"), "#06B6D4")
        root.addLayout(self.kpi_layout)

        # Filter Toolbar
        filter_card = QFrame()
        filter_card.setObjectName("Card")
        flay = QHBoxLayout(filter_card)
        flay.setContentsMargins(14, 10, 14, 10)
        flay.setSpacing(10)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText(_("inv_search_placeholder", "Search hostname, IP, MAC, serial, vendor, tag..."))
        self.search_edit.textChanged.connect(self.apply_filters)

        self.site_filter = QComboBox()
        self.site_filter.currentIndexChanged.connect(self.apply_filters)

        self.cat_filter = QComboBox()
        self.cat_filter.addItem(_("inv_all_categories", "All Categories"), None)
        for cat in DEVICE_CATEGORIES:
            self.cat_filter.addItem(cat, cat)
        self.cat_filter.currentIndexChanged.connect(self.apply_filters)

        self.status_filter = QComboBox()
        self.status_filter.addItem(_("inv_all_statuses", "All Statuses"), None)
        for st in ("ONLINE", "UP", "DEGRADED", "OFFLINE", "DOWN", "UNKNOWN"):
            self.status_filter.addItem(st, st)
        self.status_filter.currentIndexChanged.connect(self.apply_filters)

        self.group_filter = QComboBox()
        self.group_filter.currentIndexChanged.connect(self.apply_filters)

        flay.addWidget(self.search_edit, 3)
        flay.addWidget(self.site_filter, 1)
        flay.addWidget(self.cat_filter, 1)
        flay.addWidget(self.status_filter, 1)
        flay.addWidget(self.group_filter, 1)
        root.addWidget(filter_card)

        # Inventory Table
        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels([
            _("inv_col_hostname", "Hostname"),
            _("inv_col_ip", "Management IP"),
            _("inv_col_mac", "MAC Address"),
            _("inv_col_vendor_model", "Vendor / Model"),
            _("inv_col_category", "Category"),
            _("inv_col_site", "Site / Rack"),
            _("inv_col_status", "Status"),
            _("inv_col_serial_warranty", "Serial / Warranty"),
            _("inv_col_actions", "Actions"),
        ])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.Interactive)
        hdr.setSectionResizeMode(0, QHeaderView.Stretch)
        hdr.setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.setColumnWidth(8, 175)
        self.table.setStyleSheet(
            "QTableWidget { background-color: #0F172A; border: 1px solid #334155; border-radius: 10px; color: #F1F5F9; }"
            "QHeaderView::section { background-color: #1E293B; color: #94A3B8; font-weight: bold; border: none; padding: 8px; }"
        )
        root.addWidget(self.table, 1)

        self.footer_lbl = QLabel("")
        self.footer_lbl.setStyleSheet("color: #64748B; font-size: 11px; margin-bottom: 0px;")
        root.addWidget(self.footer_lbl)

    def _load_ssh_profiles(self) -> List[Dict[str, Any]]:
        with self.db.Session() as session:
            return [{"id": p.id, "name": p.name} for p in session.query(SSHProfile).order_by(SSHProfile.name.asc()).all()]

    def refresh_data(self) -> None:
        sites = self.site_manager.list_sites()
        cur_site = self.site_filter.currentData()
        self.site_filter.blockSignals(True)
        self.site_filter.clear()
        self.site_filter.addItem(_("inv_all_sites", "All Sites"), None)
        for s in sites:
            self.site_filter.addItem(s["name"], s["id"])
        idx = self.site_filter.findData(cur_site)
        self.site_filter.setCurrentIndex(idx if idx >= 0 else 0)
        self.site_filter.blockSignals(False)

        all_devs = self.inventory.list_devices(limit=5000)
        self._devices_cache = all_devs

        cur_grp = self.group_filter.currentData()
        groups = sorted({d["device_group"] for d in all_devs if d.get("device_group")})
        self.group_filter.blockSignals(True)
        self.group_filter.clear()
        self.group_filter.addItem(_("inv_all_groups", "All Groups"), None)
        for g in groups:
            self.group_filter.addItem(g, g)
        g_idx = self.group_filter.findData(cur_grp)
        self.group_filter.setCurrentIndex(g_idx if g_idx >= 0 else 0)
        self.group_filter.blockSignals(False)

        # Update KPIs
        total = len(all_devs)
        online = sum(1 for d in all_devs if str(d.get("status", "")).upper() in ("UP", "ONLINE", "OK"))
        issues = sum(
            1
            for d in all_devs
            if str(d.get("status", "")).upper() in ("DEGRADED", "WARNING", "DOWN", "OFFLINE", "CRITICAL")
        )
        dup_ips = len(self.inventory.find_duplicate_ips())
        dup_macs = len(self.inventory.find_duplicate_macs())
        reminders = len(self.inventory.get_maintenance_reminders(within_days=30))

        self.kpi_total.setText(str(total))
        self.kpi_online.setText(str(online))
        self.kpi_issues.setText(str(issues))
        self.kpi_dups.setText(f"{dup_ips} IP / {dup_macs} MAC")
        self.kpi_maint.setText(str(reminders))

        self.apply_filters()

    def apply_filters(self) -> None:
        filtered = self.inventory.list_devices(
            site_id=self.site_filter.currentData(),
            category=self.cat_filter.currentData(),
            status=self.status_filter.currentData(),
            group=self.group_filter.currentData(),
            search=self.search_edit.text().strip(),
            limit=2000,
        )
        self._populate_table(filtered)

    def _populate_table(self, devices: List[Dict[str, Any]]) -> None:
        self.table.setRowCount(0)
        for dev in devices:
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setRowHeight(r, 42)

            self.table.setItem(r, 0, QTableWidgetItem(dev["hostname"]))
            ip_item = QTableWidgetItem(dev["management_ip"])
            ip_item.setForeground(QColor("#818CF8"))
            self.table.setItem(r, 1, ip_item)
            self.table.setItem(r, 2, QTableWidgetItem(dev.get("mac_address") or "—"))

            vm = f"{dev.get('vendor') or 'Unknown'} / {dev.get('model') or '—'}"
            self.table.setItem(r, 3, QTableWidgetItem(vm))
            self.table.setItem(r, 4, QTableWidgetItem(dev.get("category") or "Other"))

            sr = dev.get("site_name") or "—"
            if dev.get("rack_location"):
                sr = f"{sr} ({dev['rack_location']})"
            self.table.setItem(r, 5, QTableWidgetItem(sr))

            st = str(dev.get("status") or "UNKNOWN").upper()
            st_item = QTableWidgetItem(st)
            st_item.setTextAlignment(Qt.AlignCenter)
            f = QFont()
            f.setBold(True)
            st_item.setFont(f)
            st_item.setForeground(QColor(_STATUS_COLORS.get(st, "#94A3B8")))
            self.table.setItem(r, 6, st_item)

            sw = dev.get("serial_number") or "—"
            if dev.get("warranty_expiration"):
                sw = f"{sw} | {dev['warranty_expiration']}"
            self.table.setItem(r, 7, QTableWidgetItem(sw))

            act_w = QWidget()
            act_l = QHBoxLayout(act_w)
            act_l.setContentsMargins(4, 2, 4, 2)
            act_l.setSpacing(4)

            btn_edit = QPushButton(_("inv_btn_edit", "Edit"))
            btn_edit.setObjectName("SecondaryButton")
            btn_edit.setFixedHeight(26)
            btn_edit.clicked.connect(lambda _c, did=dev["id"]: self.on_edit_device(did))

            btn_del = QPushButton(_("inv_btn_delete", "Delete"))
            btn_del.setObjectName("DangerButton")
            btn_del.setFixedHeight(26)
            btn_del.clicked.connect(lambda _c, did=dev["id"]: self.on_delete_device(did))

            act_l.addWidget(btn_edit)
            act_l.addWidget(btn_del)
            self.table.setCellWidget(r, 8, act_w)

        self.footer_lbl.setText(
            _("inv_footer_count", "Showing {} of {} infrastructure devices").format(
                len(devices), len(self._devices_cache)
            )
        )

    def on_add_device(self) -> None:
        dlg = DeviceEditorDialog(
            sites=self.site_manager.list_sites(),
            ssh_profiles=self._load_ssh_profiles(),
            parent=self,
        )
        if dlg.exec() == QDialog.Accepted:
            try:
                self.inventory.add_device(dlg.get_payload())
                self.refresh_data()
            except Exception as exc:
                QMessageBox.warning(self, _("msg_error", "Error"), str(exc))

    def on_edit_device(self, device_id: int) -> None:
        dev = self.inventory.get_device(device_id)
        if not dev:
            return
        dlg = DeviceEditorDialog(
            sites=self.site_manager.list_sites(),
            ssh_profiles=self._load_ssh_profiles(),
            device=dev,
            parent=self,
        )
        if dlg.exec() == QDialog.Accepted:
            try:
                self.inventory.update_device(device_id, dlg.get_payload())
                self.refresh_data()
            except Exception as exc:
                QMessageBox.warning(self, _("msg_error", "Error"), str(exc))

    def on_delete_device(self, device_id: int) -> None:
        dev = self.inventory.get_device(device_id)
        if not dev:
            return
        reply = QMessageBox.question(
            self,
            _("inv_confirm_delete_title", "Confirm Deletion"),
            _("inv_confirm_delete_msg", "Delete device '{}' ({}) from infrastructure inventory?").format(
                dev["hostname"], dev["management_ip"]
            ),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.inventory.delete_device(device_id)
            self.refresh_data()

    def on_sync_sources(self) -> None:
        res = self.inventory.sync_from_snmp_and_hosts()
        self.site_manager.migrate_legacy_config_sites(self.config)
        self.refresh_data()
        QMessageBox.information(
            self,
            _("msg_info", "Information"),
            _("inv_sync_done", "Synchronized infrastructure inventory: {} created, {} updated.").format(
                res["created"], res["updated"]
            ),
        )

    def on_check_duplicates(self) -> None:
        dup_ips = self.inventory.find_duplicate_ips()
        dup_macs = self.inventory.find_duplicate_macs()
        if not dup_ips and not dup_macs:
            QMessageBox.information(
                self,
                _("msg_info", "Information"),
                _("inv_no_dups", "No duplicate IPs or MAC addresses detected."),
            )
            return
        lines = []
        for ip, devs in dup_ips.items():
            lines.append(f"Duplicate IP {ip}: " + ", ".join(d["hostname"] for d in devs))
        for mac, devs in dup_macs.items():
            lines.append(f"Duplicate MAC {mac}: " + ", ".join(d["hostname"] for d in devs))
        QMessageBox.warning(self, _("inv_dups_found", "Duplicates Detected"), "\n".join(lines[:20]))

    def on_import_csv(self) -> None:
        path, _f = QFileDialog.getOpenFileName(self, _("inv_btn_import_csv", "Import CSV"), "", "CSV Files (*.csv)")
        if not path:
            return
        res = self.inventory.import_csv(path, default_site_id=self.site_filter.currentData())
        self.refresh_data()
        QMessageBox.information(
            self,
            _("msg_info", "Information"),
            _("inv_import_done", "CSV Import: {} imported, {} duplicates skipped, {} errors.").format(
                res["imported"], res["skipped_duplicates"], len(res["errors"])
            ),
        )

    def on_export_csv(self) -> None:
        path, _f = QFileDialog.getSaveFileName(self, _("inv_btn_export_csv", "Export CSV"), "BahaaIT_Inventory.csv", "CSV Files (*.csv)")
        if not path:
            return
        self.inventory.export_csv(path)
        QMessageBox.information(self, _("msg_success", "Success"), _("inv_export_ok", "Inventory exported successfully."))

    def on_export_pdf(self) -> None:
        path, _f = QFileDialog.getSaveFileName(self, _("inv_btn_export_pdf", "Export PDF"), "BahaaIT_Inventory_Report.pdf", "PDF Files (*.pdf)")
        if not path:
            return
        ok, err = self.inventory.export_pdf(path)
        if ok:
            QMessageBox.information(self, _("msg_success", "Success"), _("inv_export_ok", "Inventory exported successfully."))
        else:
            QMessageBox.critical(self, _("msg_error", "Error"), str(err))
