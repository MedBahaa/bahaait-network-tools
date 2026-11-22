from typing import Any, Callable, Dict, List, Optional, Tuple

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
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
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.audit_logger import AuditLogger
from core.inventory_manager import InventoryManager
from core.site_manager import SiteManager
from core.vlan_manager import SUPPORTED_VLAN_OPERATIONS, VLANManager
from utils.db import DatabaseManager
from utils.i18n import _


class VLANConfirmDialog(QDialog):
    """Explicit confirmation dialog displaying exact vendor CLI commands before applying VLAN changes."""

    def __init__(self, plan: Dict[str, Any], parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.plan = plan
        self.setWindowTitle(_("vlan_confirm_title", "Confirm VLAN Configuration Change"))
        self.setMinimumSize(560, 440)
        self.setStyleSheet("QDialog { background-color: #0F172A; color: #F1F5F9; }")

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(10)

        risk = str(plan.get("risk_tier") or "MODIFYING")
        banner_color = "#F43F5E" if risk == "DESTRUCTIVE" else "#F59E0B"
        hdr = QLabel(
            f"[{risk}] {plan.get('operation')} on {plan.get('device_hostname')} ({plan.get('device_ip')}) "
            f"— Profile: {plan.get('vendor_profile')}"
        )
        hdr.setWordWrap(True)
        hdr.setStyleSheet(f"color: {banner_color}; font-weight: bold; font-size: 13px;")
        root.addWidget(hdr)

        if plan.get("warnings"):
            warn_lbl = QLabel("\n".join(f"! {w}" for w in plan["warnings"]))
            warn_lbl.setWordWrap(True)
            warn_lbl.setStyleSheet("color: #FBBF24; background-color: #1E293B; padding: 8px; border-radius: 6px;")
            root.addWidget(warn_lbl)

        root.addWidget(QLabel(_("vlan_confirm_cmds", "Exact CLI commands that will be executed:")))
        self.cmd_preview = QTextEdit("\n".join(plan.get("commands") or []))
        self.cmd_preview.setReadOnly(True)
        self.cmd_preview.setStyleSheet(
            "QTextEdit { background-color: #020617; color: #38BDF8; font-family: Consolas; font-size: 12px; border: 1px solid #334155; border-radius: 6px; padding: 8px; }"
        )
        root.addWidget(self.cmd_preview, 1)

        form = QFormLayout()
        self.ticket_edit = QLineEdit()
        self.ticket_edit.setPlaceholderText("CHG-1042 (optional change ticket)")
        form.addRow(_("vlan_confirm_ticket", "Change Ticket:"), self.ticket_edit)
        root.addLayout(form)

        self.confirm_chk = QCheckBox(
            _("vlan_confirm_check", "I have reviewed these vendor CLI commands and confirm execution.")
        )
        root.addWidget(self.confirm_chk)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.ok_btn = btns.button(QDialogButtonBox.Ok)
        self.ok_btn.setText(_("vlan_btn_execute", "Execute Plan"))
        self.ok_btn.setEnabled(False)
        self.confirm_chk.toggled.connect(self.ok_btn.setEnabled)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        root.addWidget(btns)

    def ticket_ref(self) -> str:
        return self.ticket_edit.text().strip()


class VLANView(QWidget):
    """Enterprise multi-vendor VLAN Visualization, Consistency Audit & Controlled Planner."""

    def __init__(
        self,
        db: Optional[DatabaseManager] = None,
        ssh_executor: Optional[Callable[[Dict[str, Any], List[str]], Tuple[bool, str]]] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.db = db or DatabaseManager()
        self.audit = AuditLogger(self.db)
        self.site_manager = SiteManager(self.db, audit_logger=self.audit)
        self.inventory = InventoryManager(self.db, audit_logger=self.audit, site_manager=self.site_manager)
        self.manager = VLANManager(self.db, audit_logger=self.audit)
        self.ssh_executor = ssh_executor
        self._last_plan: Optional[Dict[str, Any]] = None

        self._setup_ui()
        self.refresh()

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(12)

        # Header
        hdr = QHBoxLayout()
        t_col = QVBoxLayout()
        lbl_t = QLabel(_("vlan_title", "VLAN Management"))
        lbl_t.setStyleSheet("font-size: 20px; font-weight: bold; color: #F8FAFC;")
        lbl_s = QLabel(_("vlan_subtitle", "Multi-switch IEEE 802.1Q visibility, consistency diagnostics & confirmed CLI planning"))
        lbl_s.setStyleSheet("color: #94A3B8; font-size: 12px;")
        t_col.addWidget(lbl_t)
        t_col.addWidget(lbl_s)
        hdr.addLayout(t_col)
        hdr.addStretch()

        self.sync_btn = QPushButton(_("vlan_btn_sync", "Sync SNMP VLANs"))
        self.sync_btn.setProperty("class", "PrimaryButton")
        self.sync_btn.clicked.connect(self._sync_snmp)
        hdr.addWidget(self.sync_btn)

        self.refresh_btn = QPushButton(_("common_refresh", "Refresh"))
        self.refresh_btn.clicked.connect(self.refresh)
        hdr.addWidget(self.refresh_btn)
        root.addLayout(hdr)

        # KPI Cards Strip
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(10)
        self.kpi_total = self._make_kpi_card(_("vlan_kpi_total", "Unique VLANs"), "0", "#38BDF8")
        self.kpi_devs = self._make_kpi_card(_("vlan_kpi_devices", "Switches / Nodes"), "0", "#10B981")
        self.kpi_warns = self._make_kpi_card(_("vlan_kpi_warnings", "Inconsistencies"), "0", "#F59E0B")
        self.kpi_ports = self._make_kpi_card(_("vlan_kpi_ports", "Mapped Ports"), "0", "#818CF8")
        for c in (self.kpi_total, self.kpi_devs, self.kpi_warns, self.kpi_ports):
            kpi_row.addWidget(c)
        root.addLayout(kpi_row)

        # Filter Toolbar
        bar = QFrame()
        bar.setStyleSheet("QFrame { background-color: #1E293B; border: 1px solid #334155; border-radius: 10px; }")
        bar_l = QHBoxLayout(bar)
        bar_l.setContentsMargins(12, 8, 12, 8)
        bar_l.setSpacing(10)

        bar_l.addWidget(QLabel(_("topo_lbl_site", "Site:")))
        self.site_combo = QComboBox()
        self.site_combo.currentIndexChanged.connect(self.refresh)
        bar_l.addWidget(self.site_combo)

        bar_l.addWidget(QLabel(_("vlan_lbl_device", "Device:")))
        self.dev_filter_combo = QComboBox()
        self.dev_filter_combo.currentIndexChanged.connect(self.refresh)
        bar_l.addWidget(self.dev_filter_combo)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(_("vlan_search_ph", "Filter VLAN ID, name, switch..."))
        self.search_input.textChanged.connect(self.refresh)
        bar_l.addWidget(self.search_input, 1)
        root.addWidget(bar)

        # Tabs
        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)

        # Tab 1: VLAN Inventory & Multi-Switch Matrix
        t1 = QWidget()
        t1_l = QVBoxLayout(t1)
        split = QSplitter(Qt.Vertical)

        self.vlan_table = QTableWidget(0, 9)
        self.vlan_table.setHorizontalHeaderLabels([
            _("inv_col_host", "Device"),
            _("inv_col_vendor", "Vendor"),
            _("inv_col_site", "Site"),
            "VLAN ID",
            _("vlan_col_name", "VLAN Name"),
            _("inv_col_status", "Status"),
            _("vlan_col_untagged", "Untagged / Access"),
            _("vlan_col_tagged", "Tagged Ports"),
            _("vlan_col_trunks", "Trunks"),
        ])
        self.vlan_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.vlan_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.vlan_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.vlan_table.verticalHeader().setVisible(False)
        split.addWidget(self.vlan_table)

        matrix_wrap = QWidget()
        mw_l = QVBoxLayout(matrix_wrap)
        mw_l.setContentsMargins(0, 6, 0, 0)
        mw_l.addWidget(QLabel(_("vlan_matrix_hdr", "Multi-Switch Spanning Matrix")))
        self.matrix_table = QTableWidget(0, 6)
        self.matrix_table.setHorizontalHeaderLabels([
            "VLAN ID",
            _("vlan_col_names", "Observed Name(s)"),
            _("vlan_col_switches", "Switches"),
            _("vlan_col_acc_cnt", "Access Ports"),
            _("vlan_col_tr_cnt", "Tagged / Trunk Ports"),
            _("vlan_col_consistency", "Consistency"),
        ])
        self.matrix_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.matrix_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.matrix_table.verticalHeader().setVisible(False)
        mw_l.addWidget(self.matrix_table)
        split.addWidget(matrix_wrap)
        t1_l.addWidget(split)
        self.tabs.addTab(t1, _("vlan_tab_overview", "VLAN Visualization"))

        # Tab 2: Inconsistencies
        t2 = QWidget()
        t2_l = QVBoxLayout(t2)
        self.warn_table = QTableWidget(0, 6)
        self.warn_table.setHorizontalHeaderLabels([
            _("common_severity", "Severity"),
            _("vlan_warn_kind", "Type"),
            "VLAN ID",
            _("vlan_col_switches", "Affected Devices"),
            _("common_detail", "Detail"),
            _("vlan_warn_fix", "Recommended Action"),
        ])
        self.warn_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.warn_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.warn_table.verticalHeader().setVisible(False)
        t2_l.addWidget(self.warn_table)
        self.tabs.addTab(t2, _("vlan_tab_warnings", "Inconsistencies"))

        # Tab 3: Controlled VLAN Change Planner
        t3 = QWidget()
        t3_l = QHBoxLayout(t3)

        form_card = QFrame()
        form_card.setStyleSheet("QFrame { background-color: #1E293B; border: 1px solid #334155; border-radius: 10px; }")
        fc_l = QVBoxLayout(form_card)
        fc_l.setContentsMargins(14, 14, 14, 14)
        form = QFormLayout()
        form.setSpacing(8)

        self.plan_dev_combo = QComboBox()
        self.plan_op_combo = QComboBox()
        for op in SUPPORTED_VLAN_OPERATIONS:
            self.plan_op_combo.addItem(op, op)
        self.plan_vid_edit = QLineEdit()
        self.plan_vid_edit.setPlaceholderText("e.g. 20")
        self.plan_vname_edit = QLineEdit()
        self.plan_vname_edit.setPlaceholderText("e.g. STAFF_DATA")
        self.plan_port_edit = QLineEdit()
        self.plan_port_edit.setPlaceholderText("e.g. Gi1/0/12 or 1/1/12")
        self.plan_extra_edit = QLineEdit()
        self.plan_extra_edit.setPlaceholderText("tag_action (add/remove) or parent_interface")

        form.addRow(_("vlan_plan_dev", "Target Switch/Firewall:"), self.plan_dev_combo)
        form.addRow(_("vlan_plan_op", "Operation:"), self.plan_op_combo)
        form.addRow("VLAN ID (1-4094):", self.plan_vid_edit)
        form.addRow(_("vlan_col_name", "VLAN Name:"), self.plan_vname_edit)
        form.addRow(_("vlan_plan_port", "Port / Interface:"), self.plan_port_edit)
        form.addRow(_("vlan_plan_extra", "Option / Parent IF:"), self.plan_extra_edit)
        fc_l.addLayout(form)

        btn_row = QHBoxLayout()
        self.preview_plan_btn = QPushButton(_("vlan_btn_preview", "Preview CLI Plan"))
        self.preview_plan_btn.setProperty("class", "PrimaryButton")
        self.preview_plan_btn.clicked.connect(self._generate_preview)
        btn_row.addWidget(self.preview_plan_btn)

        self.apply_plan_btn = QPushButton(_("vlan_btn_confirm_apply", "Review & Confirm Apply..."))
        self.apply_plan_btn.setEnabled(False)
        self.apply_plan_btn.clicked.connect(self._open_confirm_dialog)
        btn_row.addWidget(self.apply_plan_btn)
        fc_l.addLayout(btn_row)
        fc_l.addStretch()

        prev_card = QFrame()
        prev_card.setStyleSheet("QFrame { background-color: #1E293B; border: 1px solid #334155; border-radius: 10px; }")
        pc_l = QVBoxLayout(prev_card)
        pc_l.setContentsMargins(14, 14, 14, 14)
        self.plan_meta_lbl = QLabel(_("vlan_preview_hint", "Select a target device and generate a vendor-specific CLI plan preview."))
        self.plan_meta_lbl.setWordWrap(True)
        self.plan_meta_lbl.setStyleSheet("color: #CBD5E1; font-weight: bold;")
        pc_l.addWidget(self.plan_meta_lbl)

        self.plan_cli_box = QTextEdit()
        self.plan_cli_box.setReadOnly(True)
        self.plan_cli_box.setStyleSheet(
            "QTextEdit { background-color: #020617; color: #38BDF8; font-family: Consolas; font-size: 12px; border: 1px solid #334155; border-radius: 6px; padding: 8px; }"
        )
        pc_l.addWidget(self.plan_cli_box, 1)

        t3_l.addWidget(form_card, 1)
        t3_l.addWidget(prev_card, 1)
        self.tabs.addTab(t3, _("vlan_tab_planner", "Controlled Change Planner"))

    @staticmethod
    def _make_kpi_card(title: str, value: str, accent: str) -> QFrame:
        card = QFrame()
        card.setStyleSheet("QFrame { background-color: #1E293B; border: 1px solid #334155; border-radius: 10px; }")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(14, 10, 14, 10)
        lbl_v = QLabel(value)
        lbl_v.setObjectName("kpi_val")
        lbl_v.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {accent};")
        lbl_t = QLabel(title)
        lbl_t.setStyleSheet("color: #94A3B8; font-size: 11px;")
        lay.addWidget(lbl_v)
        lay.addWidget(lbl_t)
        return card

    @staticmethod
    def _set_kpi_value(card: QFrame, val: str) -> None:
        lbl = card.findChild(QLabel, "kpi_val")
        if lbl:
            lbl.setText(val)

    def _reload_combos(self) -> None:
        cur_site = self.site_combo.currentData()
        cur_dev = self.dev_filter_combo.currentData()
        cur_plan_dev = self.plan_dev_combo.currentData()

        self.site_combo.blockSignals(True)
        self.site_combo.clear()
        self.site_combo.addItem(_("common_all_sites", "All Sites"), None)
        for s in self.site_manager.list_sites():
            self.site_combo.addItem(s["name"], s["id"])
        idx = self.site_combo.findData(cur_site)
        if idx >= 0:
            self.site_combo.setCurrentIndex(idx)
        self.site_combo.blockSignals(False)

        devs = self.inventory.list_devices(site_id=self.site_combo.currentData())
        self.dev_filter_combo.blockSignals(True)
        self.dev_filter_combo.clear()
        self.dev_filter_combo.addItem(_("common_all_devices", "All Devices"), None)
        self.plan_dev_combo.clear()
        for d in devs:
            label = f"{d['hostname']} ({d['management_ip']} | {d['vendor']})"
            self.dev_filter_combo.addItem(d["hostname"], d["id"])
            self.plan_dev_combo.addItem(label, d["id"])
        if cur_dev is not None:
            didx = self.dev_filter_combo.findData(cur_dev)
            if didx >= 0:
                self.dev_filter_combo.setCurrentIndex(didx)
        if cur_plan_dev is not None:
            pidx = self.plan_dev_combo.findData(cur_plan_dev)
            if pidx >= 0:
                self.plan_dev_combo.setCurrentIndex(pidx)
        self.dev_filter_combo.blockSignals(False)

    def refresh(self) -> None:
        self._reload_combos()
        site_id = self.site_combo.currentData()
        dev_id = self.dev_filter_combo.currentData()
        search = self.search_input.text().strip()

        rows = self.manager.list_vlans(site_id=site_id, device_id=dev_id, search=search)
        matrix = self.manager.get_vlan_summary_matrix(site_id=site_id)
        warnings = self.manager.detect_inconsistencies(site_id=site_id)

        self._set_kpi_value(self.kpi_total, str(len(matrix)))
        self._set_kpi_value(self.kpi_devs, str(len({r["device_id"] for r in rows})))
        self._set_kpi_value(self.kpi_warns, str(len(warnings)))
        total_ports = sum(len(r["untagged_ports"]) + len(r["tagged_ports"]) for r in rows)
        self._set_kpi_value(self.kpi_ports, str(total_ports))

        self.vlan_table.setRowCount(0)
        for v in rows:
            r = self.vlan_table.rowCount()
            self.vlan_table.insertRow(r)
            self.vlan_table.setItem(r, 0, QTableWidgetItem(v["device_hostname"]))
            self.vlan_table.setItem(r, 1, QTableWidgetItem(v["vendor"]))
            self.vlan_table.setItem(r, 2, QTableWidgetItem(v["site_name"]))
            self.vlan_table.setItem(r, 3, QTableWidgetItem(str(v["vlan_number"])))
            self.vlan_table.setItem(r, 4, QTableWidgetItem(v["vlan_name"]))
            st_item = QTableWidgetItem(v["status"])
            st_item.setForeground(QColor("#10B981" if v["status"] == "ACTIVE" else "#F59E0B"))
            self.vlan_table.setItem(r, 5, st_item)
            self.vlan_table.setItem(r, 6, QTableWidgetItem(", ".join(v["untagged_ports"]) or "-"))
            self.vlan_table.setItem(r, 7, QTableWidgetItem(", ".join(v["tagged_ports"]) or "-"))
            self.vlan_table.setItem(r, 8, QTableWidgetItem(", ".join(v["trunk_ports"]) or "-"))

        self.matrix_table.setRowCount(0)
        for m in matrix:
            r = self.matrix_table.rowCount()
            self.matrix_table.insertRow(r)
            self.matrix_table.setItem(r, 0, QTableWidgetItem(str(m["vlan_number"])))
            self.matrix_table.setItem(r, 1, QTableWidgetItem(", ".join(m["names"])))
            self.matrix_table.setItem(r, 2, QTableWidgetItem(f"{m['device_count']} ({', '.join(m['devices'][:4])})"))
            self.matrix_table.setItem(r, 3, QTableWidgetItem(str(m["untagged_count"])))
            self.matrix_table.setItem(r, 4, QTableWidgetItem(f"{m['tagged_count']} / {m['trunk_count']}"))
            c_txt = f"WARNING ({len(m['warnings'])})" if m["has_inconsistency"] else "CONSISTENT"
            c_item = QTableWidgetItem(c_txt)
            c_item.setForeground(QColor("#F59E0B" if m["has_inconsistency"] else "#10B981"))
            self.matrix_table.setItem(r, 5, c_item)

        self.warn_table.setRowCount(0)
        for w in warnings:
            r = self.warn_table.rowCount()
            self.warn_table.insertRow(r)
            sev = QTableWidgetItem(w["severity"])
            sev.setForeground(QColor("#F43F5E" if w["severity"] == "CRITICAL" else "#F59E0B"))
            self.warn_table.setItem(r, 0, sev)
            self.warn_table.setItem(r, 1, QTableWidgetItem(w["kind"]))
            self.warn_table.setItem(r, 2, QTableWidgetItem(str(w["vlan_number"])))
            self.warn_table.setItem(r, 3, QTableWidgetItem(", ".join(w["devices"])))
            self.warn_table.setItem(r, 4, QTableWidgetItem(w["detail"]))
            self.warn_table.setItem(r, 5, QTableWidgetItem(w["remediation"]))

    def _sync_snmp(self) -> None:
        res = self.manager.sync_from_snmp()
        self.refresh()
        self.plan_meta_lbl.setText(
            f"SNMP VLAN sync checked {res['devices_checked']} device(s), updated {res['vlans_synced']} VLAN entries."
        )

    def _generate_preview(self) -> Optional[Dict[str, Any]]:
        dev_id = self.plan_dev_combo.currentData()
        if dev_id is None:
            return None
        op = self.plan_op_combo.currentData()
        extra = self.plan_extra_edit.text().strip()
        params: Dict[str, Any] = {
            "vlan_id": self.plan_vid_edit.text().strip(),
            "vlan_name": self.plan_vname_edit.text().strip(),
            "port": self.plan_port_edit.text().strip(),
        }
        if op == "SET_PORT_TAGGING" and extra:
            params["tag_action"] = extra
        elif op == "CREATE_VLAN" and extra:
            params["parent_interface"] = extra
        elif op in ("RENAME_VLAN", "DELETE_VLAN") and extra:
            params["interface_name"] = extra

        try:
            plan = self.manager.build_change_plan(dev_id, op, params)
            self._last_plan = plan
            self.plan_meta_lbl.setText(
                f"Plan {plan['plan_uid']} | Vendor: {plan['vendor_profile']} | Tier: {plan['risk_tier']}"
                + (f"\nWarnings: {'; '.join(plan['warnings'])}" if plan["warnings"] else "")
            )
            self.plan_cli_box.setPlainText("\n".join(plan["commands"]))
            self.apply_plan_btn.setEnabled(True)
            return plan
        except Exception as exc:
            self._last_plan = None
            self.apply_plan_btn.setEnabled(False)
            self.plan_meta_lbl.setText(f"Plan error: {exc}")
            self.plan_cli_box.clear()
            return None

    def _open_confirm_dialog(self) -> None:
        if not self._last_plan:
            return
        if self._last_plan["risk_tier"] == "READ_ONLY":
            if self.ssh_executor:
                res = self.manager.apply_change_plan(self._last_plan, confirmed=True, executor=self.ssh_executor)
                self.plan_cli_box.setPlainText(res.get("output", ""))
            return
        dlg = VLANConfirmDialog(self._last_plan, self)
        if dlg.exec() == QDialog.Accepted:
            try:
                if self.ssh_executor:
                    res = self.manager.apply_change_plan(
                        self._last_plan,
                        confirmed=True,
                        executor=self.ssh_executor,
                        ticket_ref=dlg.ticket_ref(),
                    )
                    self.plan_meta_lbl.setText(f"Execution {res['status']} ({self._last_plan['plan_uid']})")
                else:
                    res = self.manager.apply_change_plan(
                        self._last_plan,
                        confirmed=True,
                        dry_run=True,
                        ticket_ref=dlg.ticket_ref(),
                    )
                    self.plan_meta_lbl.setText("Confirmed (No active SSH executor -> audit-logged dry-run preview).")
                self.refresh()
            except Exception as exc:
                QMessageBox.critical(self, _("common_error", "Error"), str(exc))

    def shutdown(self) -> None:
        return None
