from typing import Any, Callable, Dict, List, Optional, Tuple

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
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
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.audit_logger import AuditLogger
from core.backup_manager import BackupManager
from core.config_diff import export_diff_html, export_diff_text
from core.config_templates import apply_template, list_templates, render_template_preview
from core.inventory_manager import InventoryManager
from core.site_manager import SiteManager
from utils.db import DatabaseManager
from utils.i18n import _, escape_qt_mnemonic


class BackupWorker(QThread):
    """Runs device or site configuration backups in the background."""

    finished_batch = Signal(dict)
    failed = Signal(str)

    def __init__(
        self,
        db_path: Optional[str],
        base_dir: str,
        device_id: Optional[int] = None,
        site_id: Optional[int] = None,
        ssh_transport: Optional[Callable[..., Tuple[int, str, str]]] = None,
    ) -> None:
        super().__init__()
        self.db_path = db_path
        self.base_dir = base_dir
        self.device_id = device_id
        self.site_id = site_id
        self.ssh_transport = ssh_transport

    def run(self) -> None:
        try:
            db = DatabaseManager(self.db_path) if self.db_path else DatabaseManager()
            mgr = BackupManager(db, base_dir=self.base_dir)
            if self.device_id is not None:
                res = mgr.backup_device(
                    self.device_id,
                    triggered_by="manual_ui",
                    ssh_transport=self.ssh_transport,
                )
                self.finished_batch.emit({"mode": "single", "result": res})
            else:
                res = mgr.backup_site(
                    self.site_id,
                    triggered_by="site_ui",
                    ssh_transport=self.ssh_transport,
                )
                self.finished_batch.emit({"mode": "site", "result": res})
        except Exception as exc:
            self.failed.emit(str(exc))


class RestoreConfirmDialog(QDialog):
    """Strict confirmation dialog showing integrity check, warnings, and redacted preview prior to restore."""

    def __init__(self, plan: Dict[str, Any], parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.plan = plan
        self.setWindowTitle(_("bkp_restore_dlg_title", "Confirm Controlled Configuration Restore"))
        screen = QApplication.primaryScreen().availableGeometry() if QApplication.primaryScreen() else None
        max_h = int(screen.height() * 0.85) if screen else 640
        self.setMinimumSize(600, min(500, max_h))
        self.setMaximumHeight(max_h)
        self.setStyleSheet("QDialog { background-color: #0F172A; color: #F1F5F9; }")

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(10)

        hdr = QLabel(
            f"[DESTRUCTIVE] Restore {plan['backup_uid']} onto {plan['target_hostname']} ({plan['target_ip']})\n"
            f"Adapter: {plan['vendor_adapter']} | SHA-256: {plan['sha256_checksum'][:24]}...\n"
            "Safety guard: A mandatory PRE_RESTORE backup will be taken immediately before restoring."
        )
        hdr.setWordWrap(True)
        hdr.setStyleSheet("color: #F43F5E; font-weight: bold;")
        root.addWidget(hdr)

        if plan.get("warnings"):
            wl = QLabel("\n".join(f"! {w}" for w in plan["warnings"]))
            wl.setWordWrap(True)
            wl.setStyleSheet("color: #FBBF24; background-color: #1E293B; padding: 8px; border-radius: 6px;")
            root.addWidget(wl)

        root.addWidget(QLabel(_("bkp_restore_preview", "Redacted Configuration Content:")))
        prev = QTextEdit(plan.get("redacted_preview", ""))
        prev.setReadOnly(True)
        prev.setStyleSheet(
            "QTextEdit { background-color: #020617; color: #E2E8F0; font-family: Consolas; font-size: 11px; border: 1px solid #334155; padding: 8px; }"
        )
        root.addWidget(prev, 1)

        form = QFormLayout()
        self.ticket_edit = QLineEdit()
        self.ticket_edit.setPlaceholderText("CHG-RESTORE-001 (recommended)")
        form.addRow(_("vlan_confirm_ticket", "Change Ticket:"), self.ticket_edit)
        root.addLayout(form)

        self.confirm_chk = QCheckBox(
            _("bkp_restore_chk", "I verify device identity/compatibility and confirm executing this configuration restore.")
        )
        self.confirm_chk.setCursor(Qt.PointingHandCursor)
        root.addWidget(self.confirm_chk)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        ok_b = btns.button(QDialogButtonBox.Ok)
        cancel_b = btns.button(QDialogButtonBox.Cancel)
        ok_b.setText(_("bkp_btn_exec_restore", "Execute Controlled Restore"))
        ok_b.setObjectName("DangerButton")
        ok_b.setCursor(Qt.PointingHandCursor)
        ok_b.setEnabled(False)
        if cancel_b:
            cancel_b.setObjectName("SecondaryButton")
            cancel_b.setCursor(Qt.PointingHandCursor)
        self.confirm_chk.toggled.connect(ok_b.setEnabled)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        root.addWidget(btns)

    def ticket_ref(self) -> str:
        return self.ticket_edit.text().strip()


class TemplateConfirmDialog(QDialog):
    """Explicit confirmation dialog for applying vendor configuration templates."""

    def __init__(self, preview: Dict[str, Any], parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.preview = preview
        self.setWindowTitle(_("tpl_confirm_title", "Confirm Template Application"))
        screen = QApplication.primaryScreen().availableGeometry() if QApplication.primaryScreen() else None
        max_h = int(screen.height() * 0.85) if screen else 640
        self.setMinimumSize(560, min(440, max_h))
        self.setMaximumHeight(max_h)
        self.setStyleSheet("QDialog { background-color: #0F172A; color: #F1F5F9; }")

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(10)

        hdr = QLabel(
            f"[{preview['risk_tier']}] Apply '{preview['template_name']}' to "
            f"{preview['device_hostname']} ({preview['device_ip']})"
        )
        hdr.setWordWrap(True)
        hdr.setStyleSheet("color: #F59E0B; font-weight: bold;")
        root.addWidget(hdr)

        txt = QTextEdit(preview.get("rendered_text", ""))
        txt.setReadOnly(True)
        txt.setStyleSheet(
            "QTextEdit { background-color: #020617; color: #38BDF8; font-family: Consolas; font-size: 12px; border: 1px solid #334155; padding: 8px; }"
        )
        root.addWidget(txt, 1)

        form = QFormLayout()
        self.ticket_edit = QLineEdit()
        self.ticket_edit.setPlaceholderText("CHG-TPL-100")
        form.addRow(_("vlan_confirm_ticket", "Change Ticket:"), self.ticket_edit)
        root.addLayout(form)

        self.confirm_chk = QCheckBox(
            _("tpl_confirm_chk", "I have previewed these commands and confirm applying this template.")
        )
        self.confirm_chk.setCursor(Qt.PointingHandCursor)
        root.addWidget(self.confirm_chk)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        ok_b = btns.button(QDialogButtonBox.Ok)
        cancel_b = btns.button(QDialogButtonBox.Cancel)
        ok_b.setObjectName("DangerButton" if str(preview.get("risk_tier")) == "DESTRUCTIVE" else "PrimaryButton")
        ok_b.setCursor(Qt.PointingHandCursor)
        ok_b.setEnabled(False)
        if cancel_b:
            cancel_b.setObjectName("SecondaryButton")
            cancel_b.setCursor(Qt.PointingHandCursor)
        self.confirm_chk.toggled.connect(ok_b.setEnabled)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        root.addWidget(btns)

    def ticket_ref(self) -> str:
        return self.ticket_edit.text().strip()


class BackupView(QWidget):
    """Configuration Backup, Visual Diff, Scheduler & Templates module."""

    def __init__(
        self,
        db: Optional[DatabaseManager] = None,
        base_dir: Optional[str] = None,
        ssh_transport: Optional[Callable[..., Tuple[int, str, str]]] = None,
        config_manager: Any = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.db = db or DatabaseManager()
        self.config = config_manager
        self.audit = AuditLogger(self.db)
        self.site_manager = SiteManager(self.db, audit_logger=self.audit)
        self.inventory = InventoryManager(self.db, audit_logger=self.audit, site_manager=self.site_manager)
        self.manager = BackupManager(self.db, audit_logger=self.audit, base_dir=base_dir)
        self.ssh_transport = ssh_transport
        self._worker: Optional[BackupWorker] = None
        self._last_diff: Optional[Dict[str, Any]] = None
        self._last_template_preview: Optional[Dict[str, Any]] = None
        self._param_inputs: Dict[str, QLineEdit] = {}

        self._setup_ui()
        self.refresh()

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(10)

        # Header Row 1: Title + Wrapped Subtitle
        lbl_t = QLabel(_("bkp_title", "Configuration Backup, Diff & Templates"))
        lbl_t.setObjectName("Title")
        lbl_t.setStyleSheet("font-size: 20px; font-weight: bold; color: #F8FAFC;")
        lbl_s = QLabel(_("bkp_subtitle", "DPAPI-encrypted backups, SHA-256 tamper protection, visual diff & controlled restore"))
        lbl_s.setWordWrap(True)
        lbl_s.setStyleSheet("color: #94A3B8; font-size: 12px;")
        root.addWidget(lbl_t)
        root.addWidget(lbl_s)

        # Header Row 2: Action Buttons
        hdr_btns = QHBoxLayout()
        hdr_btns.setSpacing(8)
        self.btn_bkp_dev = QPushButton(_("bkp_btn_device", "Backup Selected Device"))
        self.btn_bkp_dev.setObjectName("PrimaryButton")
        self.btn_bkp_dev.clicked.connect(self._run_device_backup)
        hdr_btns.addWidget(self.btn_bkp_dev)

        self.btn_bkp_site = QPushButton(_("bkp_btn_site", "Backup Site Batch"))
        self.btn_bkp_site.setObjectName("SecondaryButton")
        self.btn_bkp_site.clicked.connect(self._run_site_backup)
        hdr_btns.addWidget(self.btn_bkp_site)

        self.refresh_btn = QPushButton(_("common_refresh", "Refresh"))
        self.refresh_btn.setObjectName("SecondaryButton")
        self.refresh_btn.clicked.connect(self.refresh)
        hdr_btns.addWidget(self.refresh_btn)

        for b in (self.btn_bkp_dev, self.btn_bkp_site, self.refresh_btn):
            b.setCursor(Qt.PointingHandCursor)
            b.setToolTip(b.text())
        hdr_btns.addStretch()
        root.addLayout(hdr_btns)

        # Filter Toolbar (scoped #FilterBar avoids cascading label borders)
        bar = QFrame()
        bar.setObjectName("FilterBar")
        bar_l = QHBoxLayout(bar)
        bar_l.setContentsMargins(12, 8, 12, 8)
        bar_l.setSpacing(10)

        bar_l.addWidget(QLabel(_("topo_lbl_site", "Site:")))
        self.site_combo = QComboBox()
        self.site_combo.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.site_combo.setMinimumWidth(135)
        self.site_combo.currentIndexChanged.connect(self.refresh)
        bar_l.addWidget(self.site_combo)

        bar_l.addWidget(QLabel(_("vlan_lbl_device", "Device:")))
        self.dev_combo = QComboBox()
        self.dev_combo.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.dev_combo.setMinimumWidth(185)
        self.dev_combo.currentIndexChanged.connect(self.refresh)
        bar_l.addWidget(self.dev_combo)

        bar_l.addStretch()
        self.status_lbl = QLabel(_("topo_ready", "Ready"))
        self.status_lbl.setStyleSheet("color: #94A3B8; font-size: 12px;")
        bar_l.addWidget(self.status_lbl)
        root.addWidget(bar)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)

        # Tab 1: Backups & Controlled Restore
        t1 = QWidget()
        t1_l = QVBoxLayout(t1)
        t1_l.setContentsMargins(10, 10, 10, 10)
        split = QSplitter(Qt.Vertical)
        split.setChildrenCollapsible(False)

        self.bkp_table = QTableWidget(0, 9)
        self.bkp_table.setHorizontalHeaderLabels([
            "UID",
            _("bkp_col_ts", "Timestamp"),
            _("inv_col_hostname", "Device"),
            _("site_hdr_ip", "Management IP"),
            _("bkp_col_adapter", "Adapter"),
            _("bkp_col_method", "Method"),
            _("inv_col_status", "Status"),
            _("bkp_col_size", "Bytes"),
            "SHA-256",
        ])
        bhdr = self.bkp_table.horizontalHeader()
        bhdr.setSectionResizeMode(QHeaderView.Interactive)
        bhdr.setSectionResizeMode(2, QHeaderView.Stretch)
        self.bkp_table.setColumnWidth(0, 128)
        self.bkp_table.setColumnWidth(1, 136)
        self.bkp_table.setColumnWidth(3, 114)
        self.bkp_table.setColumnWidth(4, 98)
        self.bkp_table.setColumnWidth(5, 76)
        self.bkp_table.setColumnWidth(6, 78)
        self.bkp_table.setColumnWidth(7, 66)
        self.bkp_table.setColumnWidth(8, 118)
        self.bkp_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.bkp_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.bkp_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.bkp_table.verticalHeader().setVisible(False)
        self.bkp_table.itemSelectionChanged.connect(self._on_backup_row_selected)
        split.addWidget(self.bkp_table)

        bot = QWidget()
        bot_l = QVBoxLayout(bot)
        bot_l.setContentsMargins(0, 6, 0, 0)
        act_row = QHBoxLayout()
        act_row.setSpacing(8)
        self.btn_verify = QPushButton(_("bkp_btn_verify", "Verify SHA-256 Integrity"))
        self.btn_verify.setObjectName("SecondaryButton")
        self.btn_verify.setEnabled(False)
        self.btn_verify.clicked.connect(self._verify_selected)
        self.btn_export = QPushButton(_("bkp_btn_export", "Export Redacted Config"))
        self.btn_export.setObjectName("SecondaryButton")
        self.btn_export.setEnabled(False)
        self.btn_export.clicked.connect(self._export_selected)
        self.btn_restore = QPushButton(_("bkp_btn_restore", "Prepare Controlled Restore..."))
        self.btn_restore.setObjectName("DangerButton")
        self.btn_restore.setEnabled(False)
        self.btn_restore.clicked.connect(self._prepare_restore_dialog)
        for b in (self.btn_verify, self.btn_export, self.btn_restore):
            b.setCursor(Qt.PointingHandCursor)
            act_row.addWidget(b)
        act_row.addStretch()
        bot_l.addLayout(act_row)

        self.bkp_viewer = QTextEdit()
        self.bkp_viewer.setReadOnly(True)
        self.bkp_viewer.setPlaceholderText(_("bkp_viewer_ph", "Select a successful backup to inspect its redacted decrypted configuration."))
        self.bkp_viewer.setStyleSheet(
            "QTextEdit { background-color: #020617; color: #E2E8F0; font-family: Consolas; font-size: 11px; border: 1px solid #334155; padding: 8px; }"
        )
        bot_l.addWidget(self.bkp_viewer, 1)
        split.addWidget(bot)
        split.setSizes([240, 180])
        t1_l.addWidget(split)
        self.tabs.addTab(t1, escape_qt_mnemonic(_("bkp_tab_history", "Backups & History")))

        # Tab 2: Visual Diff
        t2 = QWidget()
        t2_l = QVBoxLayout(t2)
        t2_l.setContentsMargins(10, 10, 10, 10)
        d_bar = QHBoxLayout()
        d_bar.setSpacing(8)
        d_bar.addWidget(QLabel(_("bkp_diff_a", "Baseline (A):")))
        self.diff_a_combo = QComboBox()
        self.diff_a_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.diff_a_combo.setMinimumWidth(140)
        d_bar.addWidget(self.diff_a_combo, 1)
        d_bar.addWidget(QLabel(_("bkp_diff_b", "Candidate (B):")))
        self.diff_b_combo = QComboBox()
        self.diff_b_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.diff_b_combo.setMinimumWidth(140)
        d_bar.addWidget(self.diff_b_combo, 1)

        self.btn_compare = QPushButton(_("bkp_btn_compare", "Compare Diff"))
        self.btn_compare.setObjectName("PrimaryButton")
        self.btn_compare.setCursor(Qt.PointingHandCursor)
        self.btn_compare.clicked.connect(self._run_compare)
        d_bar.addWidget(self.btn_compare)

        self.btn_exp_diff = QPushButton(_("bkp_btn_export_diff", "Export HTML/TXT"))
        self.btn_exp_diff.setObjectName("SecondaryButton")
        self.btn_exp_diff.setCursor(Qt.PointingHandCursor)
        self.btn_exp_diff.clicked.connect(self._export_diff)
        d_bar.addWidget(self.btn_exp_diff)
        t2_l.addLayout(d_bar)

        self.diff_summary_lbl = QLabel("-")
        self.diff_summary_lbl.setWordWrap(True)
        self.diff_summary_lbl.setStyleSheet("color: #38BDF8; font-weight: bold;")
        t2_l.addWidget(self.diff_summary_lbl)

        self.diff_table = QTableWidget(0, 5)
        self.diff_table.setHorizontalHeaderLabels(["#", "Baseline (A)", "#", "Candidate (B)", "Section"])
        self.diff_table.setFont(QFont("Consolas", 10))
        dhdr = self.diff_table.horizontalHeader()
        dhdr.setSectionResizeMode(QHeaderView.Stretch)
        dhdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        dhdr.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        dhdr.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.diff_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.diff_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.diff_table.verticalHeader().setVisible(False)
        t2_l.addWidget(self.diff_table, 1)
        self.tabs.addTab(t2, _("bkp_tab_diff", "Visual Diff"))

        # Tab 3: Scheduler & Policy (scoped #PanelCard capped width)
        t3 = QWidget()
        t3_l = QVBoxLayout(t3)
        t3_l.setContentsMargins(10, 10, 10, 10)
        pol_card = QFrame()
        pol_card.setObjectName("PanelCard")
        pol_card.setMaximumWidth(560)
        pc_l = QFormLayout(pol_card)
        pc_l.setContentsMargins(18, 18, 18, 18)
        pc_l.setSpacing(12)

        self.sched_freq = QComboBox()
        self.sched_freq.addItems(["Manual Only", "Every 6 Hours", "Daily (02:00 UTC)", "Weekly (Sunday)"])
        self.ret_days = QSpinBox()
        self.ret_days.setRange(7, 3650)
        self.ret_days.setValue(90)
        self.keep_min = QSpinBox()
        self.keep_min.setRange(1, 50)
        self.keep_min.setValue(3)

        if self.config is not None:
            saved_freq = self.config.get("backup_sched_freq", "Manual Only")
            fidx = self.sched_freq.findText(str(saved_freq))
            if fidx >= 0:
                self.sched_freq.setCurrentIndex(fidx)
            try:
                self.ret_days.setValue(int(self.config.get("backup_ret_days", 90) or 90))
                self.keep_min.setValue(int(self.config.get("backup_keep_min", 3) or 3))
            except Exception:
                pass
        self.sched_freq.currentIndexChanged.connect(self._persist_scheduler_settings)
        self.ret_days.valueChanged.connect(self._persist_scheduler_settings)
        self.keep_min.valueChanged.connect(self._persist_scheduler_settings)

        sec_badge = QLabel("Encrypted at rest via Windows DPAPI + zlib + SHA-256 checksum")
        sec_badge.setWordWrap(True)
        sec_badge.setStyleSheet("color: #10B981; font-weight: bold;")

        pc_l.addRow(_("bkp_sched_freq", "Automatic Schedule:"), self.sched_freq)
        pc_l.addRow(_("bkp_sched_ret", "Retention Days:"), self.ret_days)
        pc_l.addRow(_("bkp_sched_min", "Min Copies / Device:"), self.keep_min)
        pc_l.addRow(_("bkp_sched_sec", "At-Rest Security:"), sec_badge)

        self.btn_prune = QPushButton(_("bkp_btn_prune", "Apply Retention Policy Now"))
        self.btn_prune.setObjectName("DangerButton")
        self.btn_prune.setCursor(Qt.PointingHandCursor)
        self.btn_prune.clicked.connect(lambda: self._apply_retention(confirm=True))
        pc_l.addRow("", self.btn_prune)
        t3_l.addWidget(pol_card)
        t3_l.addStretch()
        self.tabs.addTab(t3, escape_qt_mnemonic(_("bkp_tab_sched", "Scheduler & Retention")))

        # Tab 4: Configuration Templates
        t4 = QWidget()
        t4_l = QHBoxLayout(t4)
        t4_l.setContentsMargins(10, 10, 10, 10)
        t4_l.setSpacing(12)
        left_tpl = QFrame()
        left_tpl.setObjectName("PanelCard")
        lt_l = QVBoxLayout(left_tpl)
        lt_l.setContentsMargins(14, 14, 14, 14)
        lt_l.setSpacing(10)

        tpl_scroll = QScrollArea()
        tpl_scroll.setWidgetResizable(True)
        tpl_scroll.setFrameShape(QFrame.NoFrame)
        tpl_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        tpl_body = QWidget()
        tpl_form_wrap = QVBoxLayout(tpl_body)
        tpl_form_wrap.setContentsMargins(0, 0, 4, 0)
        tpl_form_wrap.setSpacing(10)

        top_f = QFormLayout()
        top_f.setVerticalSpacing(8)
        self.tpl_dev_combo = QComboBox()
        self.tpl_dev_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.tpl_dev_combo.setMinimumContentsLength(18)
        self.tpl_dev_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.tpl_dev_combo.currentIndexChanged.connect(self._invalidate_template_preview)
        self.tpl_combo = QComboBox()
        self.tpl_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.tpl_combo.setMinimumContentsLength(18)
        self.tpl_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        for tpl in list_templates():
            self.tpl_combo.addItem(f"[{tpl['vendor_profile']}] {tpl['name']}", tpl["id"])
        self.tpl_combo.currentIndexChanged.connect(self._rebuild_template_params)
        self.tpl_combo.currentIndexChanged.connect(self._invalidate_template_preview)
        top_f.addRow(_("bkp_tpl_target", "Target Device:"), self.tpl_dev_combo)
        top_f.addRow(_("tpl_select", "Template:"), self.tpl_combo)
        tpl_form_wrap.addLayout(top_f)

        self.tpl_param_box = QFormLayout()
        self.tpl_param_box.setVerticalSpacing(8)
        tpl_form_wrap.addLayout(self.tpl_param_box)
        tpl_form_wrap.addStretch()
        tpl_scroll.setWidget(tpl_body)
        lt_l.addWidget(tpl_scroll, 1)

        t_btns = QHBoxLayout()
        t_btns.setSpacing(8)
        self.btn_tpl_preview = QPushButton(_("tpl_btn_preview", "Render Preview"))
        self.btn_tpl_preview.setObjectName("PrimaryButton")
        self.btn_tpl_preview.setCursor(Qt.PointingHandCursor)
        self.btn_tpl_preview.clicked.connect(self._render_template_preview)
        self.btn_tpl_apply = QPushButton(escape_qt_mnemonic(_("tpl_btn_apply", "Confirm & Apply...")))
        self.btn_tpl_apply.setObjectName("SecondaryButton")
        self.btn_tpl_apply.setCursor(Qt.PointingHandCursor)
        self.btn_tpl_apply.setEnabled(False)
        self.btn_tpl_apply.clicked.connect(self._open_template_confirm)
        t_btns.addWidget(self.btn_tpl_preview)
        t_btns.addWidget(self.btn_tpl_apply)
        lt_l.addLayout(t_btns)

        right_tpl = QFrame()
        right_tpl.setObjectName("PanelCard")
        rt_l = QVBoxLayout(right_tpl)
        rt_l.setContentsMargins(14, 14, 14, 14)
        self.tpl_info_lbl = QLabel("-")
        self.tpl_info_lbl.setWordWrap(True)
        self.tpl_info_lbl.setStyleSheet("color: #CBD5E1; font-weight: bold;")
        rt_l.addWidget(self.tpl_info_lbl)
        self.tpl_preview_box = QTextEdit()
        self.tpl_preview_box.setReadOnly(True)
        self.tpl_preview_box.setStyleSheet(
            "QTextEdit { background-color: #020617; color: #38BDF8; font-family: Consolas; font-size: 12px; border: 1px solid #334155; padding: 8px; }"
        )
        rt_l.addWidget(self.tpl_preview_box, 1)

        t4_l.addWidget(left_tpl, 1)
        t4_l.addWidget(right_tpl, 1)
        self.tabs.addTab(t4, _("bkp_tab_templates", "Config Templates"))

        self._rebuild_template_params()

    def _invalidate_template_preview(self) -> None:
        self._last_template_preview = None
        self.btn_tpl_apply.setEnabled(False)

    def _persist_scheduler_settings(self) -> None:
        if self.config is None:
            return
        self.config.set("backup_sched_freq", self.sched_freq.currentText())
        self.config.set("backup_ret_days", self.ret_days.value())
        self.config.set("backup_keep_min", self.keep_min.value())

    def _rebuild_template_params(self) -> None:
        while self.tpl_param_box.rowCount() > 0:
            self.tpl_param_box.removeRow(0)
        self._param_inputs.clear()
        self._invalidate_template_preview()
        tpl_id = self.tpl_combo.currentData()
        if not tpl_id:
            return
        from core.config_templates import get_template
        tpl = get_template(tpl_id)
        for p in tpl["parameters"]:
            le = QLineEdit(str(p.get("default", "")))
            if p.get("secret"):
                le.setEchoMode(QLineEdit.Password)
            le.textChanged.connect(self._invalidate_template_preview)
            self._param_inputs[p["key"]] = le
            self.tpl_param_box.addRow(f"{p['label']}:", le)

    def _reload_combos(self) -> None:
        cur_site = self.site_combo.currentData()
        cur_dev = self.dev_combo.currentData()
        cur_tdev = self.tpl_dev_combo.currentData()

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
        self.dev_combo.blockSignals(True)
        self.dev_combo.clear()
        self.dev_combo.addItem(_("common_all_devices", "All Devices"), None)
        self.tpl_dev_combo.clear()
        for d in devs:
            lbl = f"{d['hostname']} ({d['management_ip']} | {d['vendor']})"
            self.dev_combo.addItem(d["hostname"], d["id"])
            self.tpl_dev_combo.addItem(lbl, d["id"])
        if cur_dev is not None:
            didx = self.dev_combo.findData(cur_dev)
            if didx >= 0:
                self.dev_combo.setCurrentIndex(didx)
        if cur_tdev is not None:
            tidx = self.tpl_dev_combo.findData(cur_tdev)
            if tidx >= 0:
                self.tpl_dev_combo.setCurrentIndex(tidx)
        self.dev_combo.blockSignals(False)

    def refresh(self) -> None:
        self._reload_combos()
        site_id = self.site_combo.currentData()
        dev_id = self.dev_combo.currentData()
        backups = self.manager.list_backups(device_id=dev_id, site_id=site_id)

        self.bkp_table.setRowCount(0)
        self.bkp_viewer.clear()
        self.btn_verify.setEnabled(False)
        self.btn_export.setEnabled(False)
        self.btn_restore.setEnabled(False)
        cur_a = self.diff_a_combo.currentData()
        cur_b = self.diff_b_combo.currentData()
        self.diff_a_combo.clear()
        self.diff_b_combo.clear()

        for b in backups:
            r = self.bkp_table.rowCount()
            self.bkp_table.insertRow(r)
            uid_item = QTableWidgetItem(b["backup_uid"])
            uid_item.setData(Qt.UserRole, b["id"])
            self.bkp_table.setItem(r, 0, uid_item)
            ts_str = b["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if b["timestamp"] else "-"
            self.bkp_table.setItem(r, 1, QTableWidgetItem(ts_str))
            self.bkp_table.setItem(r, 2, QTableWidgetItem(b["device_hostname"]))
            self.bkp_table.setItem(r, 3, QTableWidgetItem(b["device_ip"]))
            self.bkp_table.setItem(r, 4, QTableWidgetItem(b["vendor_adapter"]))
            self.bkp_table.setItem(r, 5, QTableWidgetItem(b["backup_method"]))
            st_item = QTableWidgetItem(b["status"])
            st_item.setForeground(QColor("#F43F5E" if b["status"] == "FAILED" else "#10B981"))
            self.bkp_table.setItem(r, 6, st_item)
            self.bkp_table.setItem(r, 7, QTableWidgetItem(str(b["file_size_bytes"])))
            self.bkp_table.setItem(r, 8, QTableWidgetItem((b["sha256_checksum"] or "-")[:16]))

            if b["status"] != "FAILED":
                lbl = f"{b['device_hostname']} | {b['backup_uid']} ({ts_str})"
                self.diff_a_combo.addItem(lbl, b["id"])
                self.diff_b_combo.addItem(lbl, b["id"])

        if cur_a is not None and self.diff_a_combo.findData(cur_a) >= 0:
            self.diff_a_combo.setCurrentIndex(self.diff_a_combo.findData(cur_a))
        elif self.diff_a_combo.count() >= 2:
            self.diff_a_combo.setCurrentIndex(1)
        if cur_b is not None and self.diff_b_combo.findData(cur_b) >= 0:
            self.diff_b_combo.setCurrentIndex(self.diff_b_combo.findData(cur_b))

    def _selected_backup_id(self) -> Optional[int]:
        row = self.bkp_table.currentRow()
        if row < 0:
            return None
        it = self.bkp_table.item(row, 0)
        return int(it.data(Qt.UserRole)) if it else None

    def _on_backup_row_selected(self) -> None:
        bid = self._selected_backup_id()
        has_sel = bid is not None
        self.btn_verify.setEnabled(has_sel)
        self.btn_export.setEnabled(has_sel)
        self.btn_restore.setEnabled(has_sel)
        if not has_sel:
            self.bkp_viewer.clear()
            return
        try:
            self.bkp_viewer.setPlainText(self.manager.get_backup_content(bid, redact=True))
        except Exception as exc:
            self.bkp_viewer.setPlainText(f"[Unavailable: {exc}]")

    def _run_device_backup(self) -> None:
        dev_id = self.dev_combo.currentData()
        if dev_id is None:
            QMessageBox.information(self, "Backup", _("bkp_pick_dev", "Select a specific device from the Device dropdown."))
            return
        self._start_worker(device_id=int(dev_id))

    def _run_site_backup(self) -> None:
        site_id = self.site_combo.currentData()
        self._start_worker(site_id=site_id)

    def _start_worker(self, device_id: Optional[int] = None, site_id: Optional[int] = None) -> None:
        if self._worker and self._worker.isRunning():
            return
        self.btn_bkp_dev.setEnabled(False)
        self.btn_bkp_site.setEnabled(False)
        self.status_lbl.setText(_("bkp_running", "Backing up configuration(s)..."))
        self._worker = BackupWorker(
            db_path=getattr(self.db, "db_path", None),
            base_dir=self.manager.base_dir,
            device_id=device_id,
            site_id=site_id,
            ssh_transport=self.ssh_transport,
        )
        self._worker.finished_batch.connect(self._on_worker_done)
        self._worker.failed.connect(self._on_worker_failed)
        self._worker.start()

    def _on_worker_done(self, payload: Dict[str, Any]) -> None:
        self.btn_bkp_dev.setEnabled(True)
        self.btn_bkp_site.setEnabled(True)
        if payload.get("mode") == "single":
            r = payload["result"]
            self.status_lbl.setText(f"Backup {r['backup_uid']}: {r['status']}")
        else:
            r = payload["result"]
            self.status_lbl.setText(f"Batch complete: {r['succeeded']}/{r['total']} succeeded, {r['failed']} failed")
        self.refresh()

    def _on_worker_failed(self, err: str) -> None:
        self.btn_bkp_dev.setEnabled(True)
        self.btn_bkp_site.setEnabled(True)
        self.status_lbl.setText(f"Backup error: {err}")

    def _verify_selected(self) -> None:
        bid = self._selected_backup_id()
        if bid is None:
            return
        ok, msg = self.manager.verify_backup_integrity(bid)
        if ok:
            QMessageBox.information(self, "Integrity", msg)
        else:
            QMessageBox.critical(self, "Integrity Failed", msg)

    def _export_selected(self) -> None:
        bid = self._selected_backup_id()
        if bid is None:
            return
        path, _flt = QFileDialog.getSaveFileName(self, "Export Redacted Config", f"backup_{bid}.txt", "Text Files (*.txt *.cfg)")
        if not path:
            return
        self.manager.export_backup(bid, path, redacted=True)

    def _prepare_restore_dialog(self) -> None:
        bid = self._selected_backup_id()
        if bid is None:
            return
        backups = {b["id"]: b for b in self.manager.list_backups()}
        bkp = backups.get(bid)
        if not bkp or not bkp.get("device_id"):
            return
        try:
            plan = self.manager.prepare_restore_plan(bid, int(bkp["device_id"]))
        except Exception as exc:
            QMessageBox.critical(self, "Restore Blocked", str(exc))
            return

        dlg = RestoreConfirmDialog(plan, self)
        if dlg.exec() == QDialog.Accepted:
            try:
                res = self.manager.restore_backup(
                    plan,
                    confirmed=True,
                    ssh_transport=self.ssh_transport,
                    ticket_ref=dlg.ticket_ref(),
                )
                QMessageBox.information(
                    self,
                    "Restore Complete",
                    f"Status: {res['status']}\nPre-restore snapshot: {res['pre_restore_backup']['backup_uid']}",
                )
                self.refresh()
            except Exception as exc:
                QMessageBox.critical(self, "Restore Error", str(exc))

    def _run_compare(self) -> None:
        id_a = self.diff_a_combo.currentData()
        id_b = self.diff_b_combo.currentData()
        if id_a is None or id_b is None:
            return
        diff = self.manager.compare_backups(int(id_a), int(id_b))
        self._last_diff = diff
        self.diff_summary_lbl.setText(diff["diff_summary"])

        self.diff_table.setRowCount(0)
        bg_map = {
            "ADD": QColor("#064E3B"),
            "DEL": QColor("#4C0519"),
            "CHANGE": QColor("#451A03"),
            "EQUAL": QColor("#0F172A"),
        }
        for row in diff["side_by_side"]:
            r = self.diff_table.rowCount()
            self.diff_table.insertRow(r)
            bg = bg_map.get(row["tag"], QColor("#0F172A"))
            items = [
                QTableWidgetItem(str(row["line_a"] or "")),
                QTableWidgetItem(row["text_a"] or ""),
                QTableWidgetItem(str(row["line_b"] or "")),
                QTableWidgetItem(row["text_b"] or ""),
                QTableWidgetItem(row.get("section", "")),
            ]
            for c, it in enumerate(items):
                it.setBackground(bg)
                it.setForeground(QColor("#E2E8F0"))
                self.diff_table.setItem(r, c, it)

    def _export_diff(self) -> None:
        if not self._last_diff:
            return
        path, flt = QFileDialog.getSaveFileName(self, "Export Diff", "config_diff.html", "HTML Files (*.html);;Text Diff (*.diff *.txt)")
        if not path:
            return
        try:
            if path.lower().endswith(".html") or "HTML" in (flt or ""):
                export_diff_html(self._last_diff, path)
            else:
                export_diff_text(self._last_diff, path)
            QMessageBox.information(self, _("msg_success", "Success"), f"Diff exported to:\n{path}")
        except Exception as exc:
            QMessageBox.critical(self, _("common_error", "Error"), str(exc))

    def _apply_retention(self, confirm: bool = False) -> None:
        if confirm:
            ans = QMessageBox.question(
                self,
                _("bkp_btn_prune", "Apply Retention Policy"),
                f"Prune backups older than {self.ret_days.value()} days (keeping at least {self.keep_min.value()} per device)?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if ans != QMessageBox.Yes:
                return
        removed = self.manager.apply_retention_policy(
            max_age_days=self.ret_days.value(),
            keep_min_per_device=self.keep_min.value(),
        )
        self.status_lbl.setText(f"Retention applied: removed {removed} expired backup(s).")
        self.refresh()

    def _render_template_preview(self) -> None:
        dev_id = self.tpl_dev_combo.currentData()
        tpl_id = self.tpl_combo.currentData()
        if dev_id is None or not tpl_id:
            return
        dev = self.inventory.get_device(int(dev_id))
        if not dev:
            return
        params = {k: w.text().strip() for k, w in self._param_inputs.items()}
        try:
            prev = render_template_preview(tpl_id, dev, params)
            self._last_template_preview = prev
            self.tpl_info_lbl.setText(
                f"{prev['template_name']} | Profile: {prev['vendor_profile']} | Risk: {prev['risk_tier']}"
            )
            self.tpl_preview_box.setPlainText(prev["rendered_text"])
            self.btn_tpl_apply.setEnabled(True)
        except Exception as exc:
            self._last_template_preview = None
            self.btn_tpl_apply.setEnabled(False)
            self.tpl_info_lbl.setText(f"Template error: {exc}")
            self.tpl_preview_box.clear()

    def _open_template_confirm(self) -> None:
        if not self._last_template_preview:
            return
        if not self.ssh_transport:
            QMessageBox.warning(
                self,
                _("tpl_confirm_title", "Live SSH Execution Unavailable"),
                "No active SSH transport is wired for live template push. You can still review/copy the rendered CLI preview.",
            )
            return
        dlg = TemplateConfirmDialog(self._last_template_preview, self)
        if dlg.exec() == QDialog.Accepted:
            try:
                def _exec(prev: Dict[str, Any], cmds: List[str]) -> Tuple[bool, str]:
                    if self.ssh_transport:
                        rc, out, err = self.ssh_transport(prev["device_ip"], 22, "", "", None, cmds, None)
                        return (rc == 0), (out or err)
                    raise ValueError("No active SSH transport wired for live execution.")

                res = apply_template(
                    self._last_template_preview,
                    confirmed=True,
                    backup_manager=self.manager if self.ssh_transport else None,
                    executor=_exec,
                    audit_logger=self.audit,
                    ticket_ref=dlg.ticket_ref(),
                )
                QMessageBox.information(self, "Template Applied", f"Status: {res['status']}")
                self.refresh()
            except Exception as exc:
                QMessageBox.critical(self, "Template Error", str(exc))

    def shutdown(self) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.quit()
            self._worker.wait(3000)
