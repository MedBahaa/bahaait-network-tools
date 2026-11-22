import csv
import platform
import re
import subprocess
from typing import Any, Dict, List, Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor
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
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.audit_logger import AuditLogger
from core.inventory_manager import InventoryManager
from core.site_manager import CONNECTIVITY_MODES, SiteManager
from utils.db import DatabaseManager
from utils.i18n import _


class PingWorker(QThread):
    """Non-blocking ICMP ping worker supporting single-row legacy (row, ip) and site batch targets."""

    progress = Signal(int, bool, str)  # device_id, ok, latency_text
    finished_all = Signal()
    result = Signal(int, str, float)  # legacy: row_index, "up"|"down", latency_ms

    _UNREACHABLE_MARKERS = (
        "unreachable",
        "impossible de joindre",
        "timed out",
        "attente dépassé",
        "attente depasse",
        "general failure",
        "défaillance générale",
        "transmit failed",
        "could not find host",
        "hôte inconnu",
    )

    def __init__(self, row_or_targets: Any, ip: Optional[str] = None) -> None:
        super().__init__()
        self._cancel = False
        if isinstance(row_or_targets, int) and ip is not None:
            self._legacy_mode = True
            self.row = int(row_or_targets)
            self.ip = str(ip).strip()
            self.targets: List[Dict[str, Any]] = []
        else:
            self._legacy_mode = False
            self.row = 0
            self.ip = ""
            self.targets = list(row_or_targets or [])

    def request_stop(self) -> None:
        self._cancel = True

    def _ping_single(self, target_ip: str) -> tuple[bool, float]:
        # Try icmplib first (matches legacy SitesView behavior & test_bug6 mock point)
        try:
            import icmplib
            res = icmplib.ping(target_ip, count=1, timeout=1.5, privileged=False)
            if getattr(res, "is_alive", False):
                return True, float(round(float(getattr(res, "avg_rtt", 0.0)), 1))
            return False, 0.0
        except Exception:
            pass

        is_win = platform.system().lower() == "windows"
        kwargs: Dict[str, Any] = {"capture_output": True, "text": True, "timeout": 3}
        if is_win:
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        cmd = ["ping", "-n", "1", "-w", "1000", target_ip] if is_win else ["ping", "-c", "1", "-W", "1", target_ip]
        try:
            proc = subprocess.run(cmd, **kwargs)
            stdout_txt = str(proc.stdout or "")
            low = stdout_txt.lower()
            if proc.returncode != 0 or any(m in low for m in self._UNREACHABLE_MARKERS):
                return False, 0.0
            m = re.search(r"(?:time|temps)[=<]\s*([\d.]+)\s*ms", stdout_txt, re.IGNORECASE)
            if m:
                return True, float(m.group(1))
            if "ttl=" in low:
                return True, 1.0
            return False, 0.0
        except Exception:
            return False, 0.0

    def run(self) -> None:
        if self._legacy_mode:
            ok, lat = self._ping_single(self.ip)
            self.result.emit(self.row, "up" if ok else "down", float(lat if ok else 0.0))
            return

        for tgt in self.targets:
            if self._cancel:
                break
            ip = str(tgt.get("management_ip") or "").strip()
            did = int(tgt["id"])
            if not ip or ip.startswith("UNKNOWN-IP-"):
                self.progress.emit(did, False, "N/A")
                continue
            ok, lat = self._ping_single(ip)
            lat_txt = f"{lat} ms" if ok else "Timeout"
            self.progress.emit(did, ok, lat_txt)
        self.finished_all.emit()


class NetworkSiteDialog(QDialog):
    """Create/Edit enterprise NetworkSite dialog."""

    def __init__(self, site: Optional[Dict[str, Any]] = None, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.site = site
        self.setWindowTitle(_("site_dlg_edit", "Edit Network Site") if site else _("site_dlg_add", "Add Network Site"))
        self.setMinimumWidth(520)
        self.setStyleSheet("QDialog { background-color: #0F172A; color: #F1F5F9; }")

        root = QVBoxLayout(self)
        form = QFormLayout()
        form.setSpacing(8)

        self.name_edit = QLineEdit(site.get("name", "") if site else "")
        self.code_edit = QLineEdit(site.get("site_code", "") if site else "")
        self.org_edit = QLineEdit(site.get("organization", "Default Organization") if site else "Default Organization")
        self.reg_edit = QLineEdit(site.get("region", "Default Region") if site else "Default Region")
        self.addr_edit = QLineEdit(site.get("address", "") if site else "")
        self.contact_edit = QLineEdit(site.get("contact_name", "") if site else "")
        self.email_edit = QLineEdit(site.get("contact_email", "") if site else "")
        self.ranges_edit = QLineEdit(", ".join(site.get("network_ranges", [])) if site else "")
        self.ranges_edit.setPlaceholderText("10.10.0.0/16, 192.168.10.0/24")
        self.gw_edit = QLineEdit(site.get("default_gateway", "") if site else "")
        self.dns_edit = QLineEdit(", ".join(site.get("dns_servers", [])) if site else "")
        self.isp_edit = QLineEdit(site.get("isp_name", "") if site else "")

        self.mode_combo = QComboBox()
        for m in CONNECTIVITY_MODES:
            self.mode_combo.addItem(m, m)
        if site and site.get("connectivity_mode"):
            idx = self.mode_combo.findData(site["connectivity_mode"])
            if idx >= 0:
                self.mode_combo.setCurrentIndex(idx)

        self.desc_edit = QLineEdit(site.get("description", "") if site else "")

        form.addRow(_("site_col_name", "Site Name*:"), self.name_edit)
        form.addRow(_("site_col_code", "Site Code:"), self.code_edit)
        form.addRow(_("site_col_org", "Organization:"), self.org_edit)
        form.addRow(_("site_col_region", "Region:"), self.reg_edit)
        form.addRow(_("site_col_mode", "Connectivity Mode:"), self.mode_combo)
        form.addRow(_("site_col_ranges", "Subnets (CIDR):"), self.ranges_edit)
        form.addRow(_("site_col_gw", "Default Gateway:"), self.gw_edit)
        form.addRow(_("site_col_dns", "DNS Servers:"), self.dns_edit)
        form.addRow(_("site_col_isp", "ISP / WAN:"), self.isp_edit)
        form.addRow(_("site_col_addr", "Address:"), self.addr_edit)
        form.addRow(_("site_col_contact", "Technical Contact:"), self.contact_edit)
        form.addRow("Email:", self.email_edit)
        form.addRow(_("common_desc", "Description:"), self.desc_edit)
        root.addLayout(form)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        root.addWidget(btns)

    def get_payload(self) -> Dict[str, Any]:
        return {
            "name": self.name_edit.text().strip(),
            "site_code": self.code_edit.text().strip(),
            "organization": self.org_edit.text().strip() or "Default Organization",
            "region": self.reg_edit.text().strip() or "Default Region",
            "connectivity_mode": self.mode_combo.currentData(),
            "network_ranges": [x.strip() for x in self.ranges_edit.text().split(",") if x.strip()],
            "default_gateway": self.gw_edit.text().strip(),
            "dns_servers": [x.strip() for x in self.dns_edit.text().split(",") if x.strip()],
            "isp_name": self.isp_edit.text().strip(),
            "address": self.addr_edit.text().strip(),
            "contact_name": self.contact_edit.text().strip(),
            "contact_email": self.email_edit.text().strip(),
            "description": self.desc_edit.text().strip(),
        }


class SitesView(QWidget):
    """Multi-Site Infrastructure Management view with Hierarchy, Site KPI Dashboard & Comparison."""

    open_in_browser = Signal(str)
    open_in_access_center = Signal(dict)
    open_in_topology = Signal(int)

    def __init__(
        self,
        logger: Any = None,
        config_manager: Any = None,
        db: Optional[DatabaseManager] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        if isinstance(logger, DatabaseManager) and db is None:
            db = logger
            logger = None
        elif hasattr(logger, "get") and not hasattr(logger, "info") and config_manager is None:
            config_manager = logger
            logger = None

        self.logger = logger
        self.config = config_manager
        self.db = db or DatabaseManager()
        self.audit = AuditLogger(self.db)
        self.site_manager = SiteManager(self.db, audit_logger=self.audit, config_manager=self.config)
        self.inventory = InventoryManager(self.db, audit_logger=self.audit, site_manager=self.site_manager)
        self._selected_site_id: Optional[int] = None
        self._ping_worker: Optional[PingWorker] = None
        self._sites_cache: List[Dict[str, Any]] = []
        self._devices_cache: List[Dict[str, Any]] = []

        if self.config is not None:
            try:
                self.site_manager.migrate_legacy_config_sites()
            except Exception:
                pass

        self._setup_ui()
        self.refresh()

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(12)

        # Header
        hdr = QHBoxLayout()
        col = QVBoxLayout()
        t_lbl = QLabel(_("site_title", "Multi-Site Infrastructure Management"))
        t_lbl.setStyleSheet("font-size: 20px; font-weight: bold; color: #F8FAFC;")
        s_lbl = QLabel(_("site_subtitle", "Hierarchical sites (Organization -> Region -> Site), availability dashboards & comparisons"))
        s_lbl.setStyleSheet("color: #94A3B8; font-size: 12px;")
        col.addWidget(t_lbl)
        col.addWidget(s_lbl)
        hdr.addLayout(col)
        hdr.addStretch()

        self.btn_add = QPushButton("+ " + _("site_btn_add", "Add Site"))
        self.btn_add.setProperty("class", "PrimaryButton")
        self.btn_add.clicked.connect(self.add_site)
        self.btn_edit = QPushButton(_("site_btn_edit", "Edit Site"))
        self.btn_edit.clicked.connect(self.edit_site)
        self.btn_del = QPushButton(_("site_btn_del", "Delete Site"))
        self.btn_del.clicked.connect(self.delete_site)
        self.btn_import = QPushButton(_("inv_btn_import_csv", "Import CSV"))
        self.btn_import.clicked.connect(self.import_csv)
        self.btn_exp_csv = QPushButton(_("inv_btn_export_csv", "Export CSV"))
        self.btn_exp_csv.clicked.connect(self.export_csv)
        self.btn_exp_pdf = QPushButton(_("inv_btn_export_pdf", "Export PDF"))
        self.btn_exp_pdf.clicked.connect(self.export_pdf)
        for b in (self.btn_add, self.btn_edit, self.btn_del, self.btn_import, self.btn_exp_csv, self.btn_exp_pdf):
            hdr.addWidget(b)
        root.addLayout(hdr)

        splitter = QSplitter(Qt.Horizontal)

        # Left Panel: Organization -> Region -> Site Hierarchy Tree
        left = QFrame()
        left.setMinimumWidth(260)
        left.setMaximumWidth(340)
        left.setStyleSheet("QFrame { background-color: #1E293B; border: 1px solid #334155; border-radius: 10px; }")
        l_lay = QVBoxLayout(left)
        l_lay.setContentsMargins(10, 10, 10, 10)
        l_lay.addWidget(QLabel(_("site_tree_hdr", "Organization / Region / Site")))

        self.site_tree = QTreeWidget()
        self.site_tree.setHeaderLabels([_("site_col_name", "Site"), _("site_col_mode", "Mode")])
        self.site_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.site_tree.currentItemChanged.connect(self._on_tree_selection)
        l_lay.addWidget(self.site_tree, 1)
        splitter.addWidget(left)

        # Right Panel: Tabs
        self.tabs = QTabWidget()

        # Tab 1: Selected Site Dashboard & Devices
        t1 = QWidget()
        t1_l = QVBoxLayout(t1)

        # KPI Cards
        krow = QHBoxLayout()
        self.kpi_devs = self._make_kpi(_("site_kpi_devs", "Devices"), "0", "#38BDF8")
        self.kpi_online = self._make_kpi(_("inv_kpi_online", "Online"), "0", "#10B981")
        self.kpi_offline = self._make_kpi(_("site_kpi_off", "Offline / Deg"), "0", "#F43F5E")
        self.kpi_avail = self._make_kpi(_("site_kpi_avail", "Availability"), "0%", "#10B981")
        self.kpi_lat = self._make_kpi(_("site_kpi_lat", "Avg Latency"), "-", "#818CF8")
        self.kpi_inc = self._make_kpi(_("site_kpi_inc", "Open Incidents"), "0", "#F59E0B")
        for c in (self.kpi_devs, self.kpi_online, self.kpi_offline, self.kpi_avail, self.kpi_lat, self.kpi_inc):
            krow.addWidget(c)
        t1_l.addLayout(krow)

        self.site_meta_lbl = QLabel(_("site_select_hint", "Select a site on the left to inspect KPIs and equipment."))
        self.site_meta_lbl.setWordWrap(True)
        self.site_meta_lbl.setStyleSheet("color: #CBD5E1; background-color: #1E293B; padding: 10px; border-radius: 8px;")
        t1_l.addWidget(self.site_meta_lbl)

        # Device Action Toolbar
        dev_bar = QHBoxLayout()
        self.btn_ping_all = QPushButton(_("site_btn_ping_all", "Ping Site Devices"))
        self.btn_ping_all.setProperty("class", "PrimaryButton")
        self.btn_ping_all.clicked.connect(self.ping_all_devices)
        self.btn_open_topo = QPushButton(_("site_btn_topo", "Open Site in Topology"))
        self.btn_open_topo.clicked.connect(self._emit_open_topology)
        self.btn_open_access = QPushButton(_("topo_btn_access", "Open in Access Center"))
        self.btn_open_access.clicked.connect(self._emit_open_access)
        self.btn_open_web = QPushButton(_("topo_btn_web", "Open Web UI"))
        self.btn_open_web.clicked.connect(self._emit_open_web)
        for b in (self.btn_ping_all, self.btn_open_topo, self.btn_open_access, self.btn_open_web):
            dev_bar.addWidget(b)
        dev_bar.addStretch()
        t1_l.addLayout(dev_bar)

        self.dev_table = QTableWidget(0, 7)
        self.dev_table.setHorizontalHeaderLabels([
            _("inv_col_host", "Hostname"),
            _("inv_col_ip", "IP Address"),
            _("inv_col_cat", "Category"),
            _("inv_col_vendor", "Vendor"),
            _("inv_col_status", "Status"),
            _("site_col_ping", "Ping"),
            _("inv_col_rack", "Rack"),
        ])
        self.dev_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.dev_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.dev_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.dev_table.verticalHeader().setVisible(False)
        t1_l.addWidget(self.dev_table, 1)
        self.tabs.addTab(t1, _("site_tab_dash", "Site Dashboard & Devices"))

        # Tab 2: Multi-Site Comparison
        t2 = QWidget()
        t2_l = QVBoxLayout(t2)
        self.comp_table = QTableWidget(0, 9)
        self.comp_table.setHorizontalHeaderLabels([
            _("site_col_name", "Site"),
            _("site_col_org", "Organization"),
            _("site_col_region", "Region"),
            _("site_col_mode", "Mode"),
            _("site_kpi_devs", "Devices"),
            _("inv_kpi_online", "Online"),
            _("site_kpi_avail", "Availability %"),
            _("site_kpi_lat", "Avg Latency (ms)"),
            _("site_kpi_inc", "Incidents"),
        ])
        self.comp_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.comp_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.comp_table.verticalHeader().setVisible(False)
        t2_l.addWidget(self.comp_table, 1)
        self.tabs.addTab(t2, _("site_tab_compare", "Multi-Site Comparison"))

        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)
        root.addWidget(splitter, 1)

    @staticmethod
    def _make_kpi(title: str, value: str, accent: str) -> QFrame:
        f = QFrame()
        f.setStyleSheet("QFrame { background-color: #1E293B; border: 1px solid #334155; border-radius: 8px; }")
        lay = QVBoxLayout(f)
        lay.setContentsMargins(10, 8, 10, 8)
        v = QLabel(value)
        v.setObjectName("kpi_v")
        v.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {accent};")
        t = QLabel(title)
        t.setStyleSheet("font-size: 11px; color: #94A3B8;")
        lay.addWidget(v)
        lay.addWidget(t)
        return f

    @staticmethod
    def _set_kpi(card: QFrame, val: str) -> None:
        lbl = card.findChild(QLabel, "kpi_v")
        if lbl:
            lbl.setText(val)

    def refresh(self) -> None:
        self._sites_cache = self.site_manager.list_sites()
        hierarchy = self.site_manager.get_site_hierarchy()

        self.site_tree.blockSignals(True)
        self.site_tree.clear()
        first_site_item: Optional[QTreeWidgetItem] = None
        selected_item: Optional[QTreeWidgetItem] = None

        for org_name, regions in sorted(hierarchy.items()):
            org_item = QTreeWidgetItem([org_name, ""])
            org_item.setExpanded(True)
            for reg_name, site_list in sorted(regions.items()):
                reg_item = QTreeWidgetItem([reg_name, ""])
                reg_item.setExpanded(True)
                for s in site_list:
                    s_item = QTreeWidgetItem([f"{s['name']} ({s['site_code']})", s["connectivity_mode"]])
                    s_item.setData(0, Qt.UserRole, s["id"])
                    reg_item.addChild(s_item)
                    if first_site_item is None:
                        first_site_item = s_item
                    if self._selected_site_id is not None and int(s["id"]) == int(self._selected_site_id):
                        selected_item = s_item
                org_item.addChild(reg_item)
            self.site_tree.addTopLevelItem(org_item)

        if selected_item is not None:
            self.site_tree.setCurrentItem(selected_item)
        elif first_site_item is not None:
            self.site_tree.setCurrentItem(first_site_item)
            self._selected_site_id = int(first_site_item.data(0, Qt.UserRole))
        else:
            self._selected_site_id = None
        self.site_tree.blockSignals(False)

        self._refresh_selected_site_dashboard()
        self._refresh_comparison_table()

    def _on_tree_selection(self, current: Optional[QTreeWidgetItem], _prev: Optional[QTreeWidgetItem]) -> None:
        if current is None:
            return
        sid = current.data(0, Qt.UserRole)
        if sid is not None:
            self._selected_site_id = int(sid)
            self._refresh_selected_site_dashboard()

    def _refresh_selected_site_dashboard(self) -> None:
        self.dev_table.setRowCount(0)
        self._devices_cache = []
        if self._selected_site_id is None:
            for card in (self.kpi_devs, self.kpi_online, self.kpi_offline, self.kpi_avail, self.kpi_inc):
                self._set_kpi(card, "0")
            self._set_kpi(self.kpi_lat, "-")
            self.site_meta_lbl.setText(_("site_select_hint", "Select a site on the left to inspect KPIs and equipment."))
            return

        dash = self.site_manager.get_site_dashboard(self._selected_site_id)
        site = dash["site"]
        self._set_kpi(self.kpi_devs, str(dash["total_devices"]))
        self._set_kpi(self.kpi_online, str(dash["online_devices"]))
        self._set_kpi(self.kpi_offline, f"{dash['offline_devices']} / {dash['degraded_devices']}")
        self._set_kpi(self.kpi_avail, f"{dash['availability_pct']}%")
        self._set_kpi(self.kpi_lat, f"{dash['avg_latency_ms']} ms" if dash["avg_latency_ms"] is not None else "-")
        self._set_kpi(self.kpi_inc, str(dash["active_incidents"]))

        ranges = ", ".join(site.get("network_ranges") or []) or "-"
        dns = ", ".join(site.get("dns_servers") or []) or "-"
        self.site_meta_lbl.setText(
            f"{site['name']} [{site['site_code']}] | {site['organization']} / {site['region']} | Mode: {site['connectivity_mode']}\n"
            f"Subnets: {ranges} | Gateway: {site.get('default_gateway') or '-'} | DNS: {dns} | ISP: {site.get('isp_name') or '-'}"
        )

        self._devices_cache = self.inventory.list_devices(site_id=self._selected_site_id)
        for d in self._devices_cache:
            r = self.dev_table.rowCount()
            self.dev_table.insertRow(r)
            h_item = QTableWidgetItem(d["hostname"])
            h_item.setData(Qt.UserRole, d["id"])
            self.dev_table.setItem(r, 0, h_item)
            self.dev_table.setItem(r, 1, QTableWidgetItem(d["management_ip"]))
            self.dev_table.setItem(r, 2, QTableWidgetItem(d["category"]))
            self.dev_table.setItem(r, 3, QTableWidgetItem(d["vendor"]))
            st_it = QTableWidgetItem(d["status"])
            st_it.setForeground(QColor("#10B981" if d["status"] in ("UP", "ONLINE", "OK") else ("#F43F5E" if d["status"] in ("DOWN", "OFFLINE") else "#F59E0B")))
            self.dev_table.setItem(r, 4, st_it)
            self.dev_table.setItem(r, 5, QTableWidgetItem("-"))
            self.dev_table.setItem(r, 6, QTableWidgetItem(d.get("rack_location") or "-"))

    def _refresh_comparison_table(self) -> None:
        rows = self.site_manager.compare_sites()
        self.comp_table.setRowCount(0)
        for c in rows:
            r = self.comp_table.rowCount()
            self.comp_table.insertRow(r)
            self.comp_table.setItem(r, 0, QTableWidgetItem(c["site_name"]))
            self.comp_table.setItem(r, 1, QTableWidgetItem(c["organization"]))
            self.comp_table.setItem(r, 2, QTableWidgetItem(c["region"]))
            self.comp_table.setItem(r, 3, QTableWidgetItem(c["connectivity_mode"]))
            self.comp_table.setItem(r, 4, QTableWidgetItem(str(c["total_devices"])))
            self.comp_table.setItem(r, 5, QTableWidgetItem(str(c["online_devices"])))
            av = QTableWidgetItem(f"{c['availability_pct']}%")
            av.setForeground(QColor("#10B981" if c["availability_pct"] >= 95 else ("#F59E0B" if c["availability_pct"] >= 75 else "#F43F5E")))
            self.comp_table.setItem(r, 6, av)
            self.comp_table.setItem(r, 7, QTableWidgetItem(str(c["avg_latency_ms"]) if c["avg_latency_ms"] is not None else "-"))
            self.comp_table.setItem(r, 8, QTableWidgetItem(str(c["active_incidents"])))

    def add_site(self) -> None:
        dlg = NetworkSiteDialog(parent=self)
        if dlg.exec() == QDialog.Accepted:
            try:
                created = self.site_manager.create_site(dlg.get_payload())
                self._selected_site_id = int(created["id"])
                self.refresh()
            except Exception as exc:
                QMessageBox.critical(self, _("common_error", "Error"), str(exc))

    def edit_site(self) -> None:
        if self._selected_site_id is None:
            return
        site = self.site_manager.get_site(self._selected_site_id)
        if not site:
            return
        dlg = NetworkSiteDialog(site=site, parent=self)
        if dlg.exec() == QDialog.Accepted:
            try:
                self.site_manager.update_site(self._selected_site_id, dlg.get_payload())
                self.refresh()
            except Exception as exc:
                QMessageBox.critical(self, _("common_error", "Error"), str(exc))

    def delete_site(self) -> None:
        if self._selected_site_id is None:
            return
        site = self.site_manager.get_site(self._selected_site_id)
        if not site:
            return
        ans = QMessageBox.question(
            self,
            _("site_btn_del", "Delete Site"),
            f"Delete site '{site['name']}'? Devices remain preserved in inventory as unassigned.",
        )
        if ans == QMessageBox.Yes:
            self.site_manager.delete_site(self._selected_site_id)
            self._selected_site_id = None
            self.refresh()

    def import_csv(self) -> None:
        path, _flt = QFileDialog.getOpenFileName(self, "Import Sites / Devices CSV", "", "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8-sig") as fh:
                reader = csv.DictReader(fh)
                created = 0
                for row in reader:
                    sname = (row.get("Site") or row.get("name") or row.get("site") or "").strip()
                    if not sname:
                        continue
                    site = self.site_manager.get_or_create_site(sname, organization=row.get("Organization", "Default Organization"), region=row.get("Region", "Default Region"))
                    ip = (row.get("IP") or row.get("management_ip") or "").strip()
                    if ip:
                        host = (row.get("Hostname") or row.get("Device") or ip).strip()
                        self.inventory.add_device({"hostname": host, "management_ip": ip, "site_id": site["id"]})
                    created += 1
            self.refresh()
            QMessageBox.information(self, "Import CSV", f"Processed {created} row(s).")
        except Exception as exc:
            QMessageBox.critical(self, "Import Error", str(exc))

    def export_csv(self) -> None:
        if self._selected_site_id is None:
            return
        path, _flt = QFileDialog.getSaveFileName(self, "Export Site CSV", "site_report.csv", "CSV Files (*.csv)")
        if path:
            self.site_manager.export_site_csv(self._selected_site_id, path)

    def export_pdf(self) -> None:
        if self._selected_site_id is None:
            return
        path, _flt = QFileDialog.getSaveFileName(self, "Export Site PDF", "site_report.pdf", "PDF Files (*.pdf)")
        if not path:
            return
        ok, msg = self.site_manager.export_site_pdf(self._selected_site_id, path)
        if not ok:
            QMessageBox.critical(self, "PDF Export Error", msg)

    def ping_all_devices(self) -> None:
        if not self._devices_cache:
            return
        if self._ping_worker and self._ping_worker.isRunning():
            return
        self.btn_ping_all.setEnabled(False)
        self._ping_worker = PingWorker(list(self._devices_cache))
        self._ping_worker.progress.connect(self._on_ping_progress)
        self._ping_worker.finished_all.connect(lambda: self.btn_ping_all.setEnabled(True))
        self._ping_worker.start()

    def _on_ping_progress(self, dev_id: int, ok: bool, lat: str) -> None:
        for r in range(self.dev_table.rowCount()):
            it = self.dev_table.item(r, 0)
            if it and int(it.data(Qt.UserRole)) == dev_id:
                pit = QTableWidgetItem(lat)
                pit.setForeground(QColor("#10B981" if ok else "#F43F5E"))
                self.dev_table.setItem(r, 5, pit)
                break

    def _selected_device_dict(self) -> Optional[Dict[str, Any]]:
        r = self.dev_table.currentRow()
        if r < 0 or r >= len(self._devices_cache):
            return self._devices_cache[0] if self._devices_cache else None
        it = self.dev_table.item(r, 0)
        did = int(it.data(Qt.UserRole)) if it else -1
        for d in self._devices_cache:
            if int(d["id"]) == did:
                return d
        return None

    def _emit_open_topology(self) -> None:
        if self._selected_site_id is not None:
            self.open_in_topology.emit(int(self._selected_site_id))

    def _emit_open_access(self) -> None:
        d = self._selected_device_dict()
        if d:
            self.open_in_access_center.emit(d)

    def _emit_open_web(self) -> None:
        d = self._selected_device_dict()
        if d and d.get("management_ip"):
            self.open_in_browser.emit(f"https://{d['management_ip']}")

    def shutdown(self) -> None:
        if self._ping_worker and self._ping_worker.isRunning():
            self._ping_worker.request_stop()
            self._ping_worker.quit()
            self._ping_worker.wait(3000)
