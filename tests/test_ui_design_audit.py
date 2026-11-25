import os
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFrame,
    QLabel,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QTabBar,
    QTabWidget,
)

ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.inventory_manager import InventoryManager
from core.site_manager import SiteManager
from utils.db import DatabaseManager
from utils.i18n import TranslationManager, _


_SINGLE_AMP_RE = re.compile(r"(?<!&)&(?!&)")


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication(sys.argv)


@pytest.fixture(scope="module")
def audit_window(tmp_path_factory, qapp):
    tmp_dir = tmp_path_factory.mktemp("ui_audit_win")
    old_local = os.environ.get("LOCALAPPDATA")
    os.environ["LOCALAPPDATA"] = str(tmp_dir)
    import logging
    from ui.main_window import MainWindow

    logger = logging.getLogger("test_ui_audit")
    handler = logging.NullHandler()

    with (
        patch.object(MainWindow, "update_header_stats", lambda self: None),
        patch(
            "core.net_config.NetworkConfig.get_interface_config",
            return_value={"ip": "192.168.1.10", "mask": "255.255.255.0", "gateway": "192.168.1.1", "dns1": "8.8.8.8", "dns2": "1.1.1.1"},
        ),
    ):
        win = MainWindow(logger, handler)
        win.tabs_to_preload = []
        if getattr(win, "monitor", None) and hasattr(win.monitor, "stop_monitor"):
            win.monitor.stop_monitor()
        win.resize(1280, 800)
        win.show()
        qapp.processEvents()

    yield win

    win._cleanup_before_exit()
    win.close()
    if old_local is not None:
        os.environ["LOCALAPPDATA"] = old_local
    else:
        os.environ.pop("LOCALAPPDATA", None)


def _audit_tab_widget(win, idx: int, qapp) -> None:
    with patch(
        "core.net_config.NetworkConfig.get_interface_config",
        return_value={"ip": "192.168.1.10", "mask": "255.255.255.0", "gateway": "192.168.1.1", "dns1": "8.8.8.8", "dns2": "1.1.1.1"},
    ):
        win.load_tab_by_index(idx)
        win.switch_page(idx)
        qapp.processEvents()

    page = win.content_area.widget(idx)
    assert page is not None and type(page).__name__ != "QWidget", f"Tab {idx} failed to instantiate"
    page_w = page.width()
    assert page_w >= 800, f"Tab {idx} unexpectedly narrow: {page_w}"

    # 1. Zero unescaped '&' Qt mnemonics on visible controls & tab bars; zero clipped buttons
    for btn in page.findChildren(QPushButton):
        if btn.isVisibleTo(page) and btn.text():
            assert not _SINGLE_AMP_RE.search(btn.text()), f"Unescaped '&' in button {btn.text()!r} (tab {idx})"
            clean = btn.text().replace("&&", "&").strip()
            if len(clean) >= 2:
                fm = QFontMetrics(btn.font())
                needed = fm.horizontalAdvance(clean)
                assert btn.width() >= needed - 2, (
                    f"Clipped button {clean!r} on tab {idx}: width={btn.width()} < text={needed}"
                )

    for chk in page.findChildren(QCheckBox) + page.findChildren(QRadioButton):
        if chk.isVisibleTo(page) and chk.text():
            assert not _SINGLE_AMP_RE.search(chk.text()), f"Unescaped '&' in check/radio {chk.text()!r} (tab {idx})"

    for tb in page.findChildren(QTabBar):
        for t_i in range(tb.count()):
            tt = tb.tabText(t_i)
            if tt:
                assert not _SINGLE_AMP_RE.search(tt), f"Unescaped '&' in tab {tt!r} (tab {idx})"

    # 2. Page Titles must fit horizontally without truncation
    for lbl in page.findChildren(QLabel):
        if lbl.isVisibleTo(page) and lbl.objectName() == "Title" and lbl.text() and not lbl.wordWrap():
            fm = QFontMetrics(lbl.font())
            needed = fm.horizontalAdvance(lbl.text())
            assert lbl.width() >= needed - 2, (
                f"Clipped Title {lbl.text()!r} on tab {idx}: width={lbl.width()} < text={needed}"
            )

    # 3. Scoped FilterBars & PanelCards must stay within page horizontal bounds
    for frm in page.findChildren(QFrame):
        if frm.isVisibleTo(page) and frm.objectName() in ("FilterBar", "PanelCard"):
            assert frm.width() <= page_w + 6, (
                f"Horizontal overflow in {frm.objectName()} on tab {idx}: {frm.width()} > {page_w}"
            )

    # 4. Inspect nested sub-tabs cleanly
    for tw in page.findChildren(QTabWidget):
        for s_i in range(tw.count()):
            tw.setCurrentIndex(s_i)
            qapp.processEvents()
            sub_w = tw.currentWidget()
            if sub_w is not None:
                for btn in sub_w.findChildren(QPushButton):
                    if btn.isVisibleTo(sub_w) and btn.text():
                        assert not _SINGLE_AMP_RE.search(btn.text()), f"Unescaped '&' in subtab button {btn.text()!r} (tab {idx})"
        tw.setCurrentIndex(0)


def test_static_qss_svg_security_and_i18n():
    qss_path = SRC_DIR / "ui" / "styles.qss"
    qss_txt = qss_path.read_text(encoding="utf-8")

    # No invalid CSS properties or inline data URIs in Quantum Midnight v2 QSS
    for forbidden in ("!important", "text-transform:", "line-height:", "data:image/svg+xml"):
        assert forbidden not in qss_txt, f"Forbidden token {forbidden!r} in styles.qss"

    # All 6 SVG icons referenced in styles.qss must exist
    icons_dir = ROOT_DIR / "assets" / "icons"
    for icon_name in (
        "chevron-down.svg",
        "chevron-down-active.svg",
        "chevron-up-sm.svg",
        "chevron-down-sm.svg",
        "check.svg",
        "close-sm.svg",
    ):
        assert (icons_dir / icon_name).exists(), f"Missing SVG icon: {icon_name}"

    # Zero forbidden QSS tokens or inline QFrame cascades in v3.6 widgets
    ui_files = list((SRC_DIR / "ui").rglob("*.py"))
    for py_file in ui_files:
        txt = py_file.read_text(encoding="utf-8")
        for forbidden in ("!important", "text-transform:", "line-height:", "data:image/svg+xml"):
            assert forbidden not in txt, f"Forbidden token {forbidden!r} in {py_file.name}"

    for v36_name in ("remote_view.py", "sites_view.py", "topology_view.py", "vlan_view.py", "backup_view.py", "audit_view.py"):
        vtxt = (SRC_DIR / "ui" / "widgets" / v36_name).read_text(encoding="utf-8")
        assert "QFrame {" not in vtxt, f"Unscoped 'QFrame {{' cascade found in {v36_name}"

    # No plaintext SMTP password literal in SettingsView
    settings_txt = (SRC_DIR / "ui" / "widgets" / "settings_view.py").read_text(encoding="utf-8")
    assert "rgsrodggtfbpshaj" not in settings_txt, "Hardcoded plaintext SMTP secret found in settings_view.py"

    # Strict 1:1 EN/FR translation parity
    tm = TranslationManager()
    assert set(tm.translations["en"].keys()) == set(tm.translations["fr"].keys())


def test_live_main_window_shell_and_core_tabs(audit_window, qapp):
    assert hasattr(audit_window, "max_btn")
    assert audit_window.minimumWidth() <= 1280
    assert audit_window.minimumHeight() <= 800

    # Check indices 0..9 excluding WebEngine tab 7
    for idx in (0, 1, 2, 3, 4, 5, 6, 8, 9):
        _audit_tab_widget(audit_window, idx, qapp)


def test_live_main_window_intel_and_infra_tabs(audit_window, qapp):
    # Check indices 10..18
    for idx in range(10, 19):
        _audit_tab_widget(audit_window, idx, qapp)


def test_functional_ui_regressions(tmp_path, monkeypatch, qapp):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    # 1. LoginDialog register success restores LOGIN mode & button text
    from ui.widgets.login_view import LoginDialog

    auth_mock = MagicMock()
    dlg = LoginDialog(auth_manager=auth_mock)
    try:
        dlg.toggle_mode()
        assert dlg.is_register_mode is True
        assert dlg.action_btn.text() == _("login_btn_register")
        with patch.object(QMessageBox, "information", return_value=QMessageBox.Ok):
            dlg._on_auth_completed(True, "Account created!", True)
        assert dlg.is_register_mode is False
        assert dlg.action_btn.text() == _("login_btn")
    finally:
        dlg.close()

    # 1b. HostDetailsDialog sequential _run_diag calls never raise RuntimeError
    from core.incident_manager import IncidentManager
    from core.monitoring_statistics import MonitoringStatisticsService
    from core.ping_engine import AsyncPingEngine
    from ui.widgets.host_details_view import HostDetailsDialog, _DiagWorker

    diag_db = DatabaseManager(str(tmp_path / "diag.db"))
    diag_engine = AsyncPingEngine(diag_db)
    diag_inc = IncidentManager(diag_db)
    diag_stats = MonitoringStatisticsService(diag_db)
    hd = HostDetailsDialog("127.0.0.1", "Loopback", diag_db, diag_engine, diag_inc, diag_stats)
    try:
        with patch.object(_DiagWorker, "run", lambda self: self.output_ready.emit("ok")):
            hd._run_diag("dns")
            for _i in range(40):
                qapp.processEvents()
                if hd._diag_worker is None:
                    break
            hd._run_diag("ports")
            for _i in range(40):
                qapp.processEvents()
                if hd._diag_worker is None:
                    break
        assert hd.diag_output.toPlainText() == "ok"
    finally:
        hd.close()

    # 2. LatencyGraphDialog None guard + high latency auto-range
    from ui.widgets.latency_graph import LatencyGraphDialog

    lg = LatencyGraphDialog("10.0.0.1")
    try:
        lg.add_data(None)
        lg.add_data(245.5)
        assert len(lg.history) == 1
        assert lg.history[0] == 245.5
    finally:
        lg.close()

    # 3. SettingsView handles missing keys & syncs form state on load_settings_to_ui
    from ui.widgets.settings_view import SettingsView

    class _SparseConfig:
        def __init__(self):
            self.config = {}

        def get(self, key, default=None):
            return self.config.get(key, default)

        def set(self, key, val):
            self.config[key] = val

    sparse_cfg = _SparseConfig()
    sv = SettingsView(MagicMock(), config_manager=sparse_cfg)
    try:
        assert sv.mute_checkbox.isChecked() is True
        assert sv.email_checkbox.isChecked() is False
        sparse_cfg.config["email_alerts_enabled"] = True
        sv.load_settings_to_ui()
        assert sv.email_checkbox.isChecked() is True
        assert sv.form_master.isEnabled() is True
    finally:
        sv.shutdown()
        sv.close()

    # 4. VLANView invalidates stale CLI plan when inputs change
    from ui.widgets.vlan_view import VLANView

    db = DatabaseManager(str(tmp_path / "func.db"))
    inv = InventoryManager(db)
    sm = SiteManager(db)
    site = sm.create_site({"name": "HQ-Test", "organization": "BahaaIT", "region": "EU"})
    dev = inv.add_device({
        "hostname": "SW-CORE-01",
        "management_ip": "10.10.0.1",
        "vendor": "Cisco",
        "category": "Core Switch",
        "site_id": site["id"],
        "status": "ONLINE",
    })

    vv = VLANView(db=db)
    try:
        vv.plan_vid_edit.setText("30")
        vv.plan_vname_edit.setText("VOICE")
        plan = vv._generate_preview()
        assert plan is not None
        assert vv.apply_plan_btn.isEnabled() is True
        vv.plan_vid_edit.setText("31")
        assert vv._last_plan is None
        assert vv.apply_plan_btn.isEnabled() is False
    finally:
        vv.shutdown()
        vv.close()

    # 5. BackupView invalidates stale template preview when parameters change
    from ui.widgets.backup_view import BackupView

    bv = BackupView(db=db, base_dir=str(tmp_path / "vault"))
    try:
        bv._render_template_preview()
        assert bv._last_template_preview is not None
        assert bv.btn_tpl_apply.isEnabled() is True
        first_param = next(iter(bv._param_inputs.values()), None)
        if first_param is not None:
            first_param.setText("changed_value")
            assert bv._last_template_preview is None
            assert bv.btn_tpl_apply.isEnabled() is False
    finally:
        bv.shutdown()
        bv.close()

    # 6. TopologyView handles empty-scene export_png & syncs inspector on select_device
    from ui.widgets.topology_view import TopologyView

    empty_db = DatabaseManager(str(tmp_path / "empty_topo.db"))
    tv_empty = TopologyView(db=empty_db)
    try:
        out_png = str(tmp_path / "empty.png")
        with patch("ui.widgets.topology_view.QFileDialog.getSaveFileName", return_value=(out_png, "PNG Files (*.png)")):
            tv_empty.export_png()
        assert Path(out_png).exists() and Path(out_png).stat().st_size > 0
    finally:
        tv_empty.shutdown()
        tv_empty.close()

    tv = TopologyView(db=db)
    try:
        tv.canvas.select_device(dev["id"])
        assert tv.lbl_host.text() == "SW-CORE-01"
    finally:
        tv.shutdown()
        tv.close()

    # 7. SitesView does not fall back to row 0 when no device row is selected
    from ui.widgets.sites_view import SitesView

    stv = SitesView(db=db)
    try:
        stv.dev_table.clearSelection()
        stv.dev_table.setCurrentCell(-1, -1)
        assert stv._selected_device_dict() is None
    finally:
        stv.shutdown()
        stv.close()
