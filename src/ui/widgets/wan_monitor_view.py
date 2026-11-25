import asyncio
from datetime import datetime
import html
from typing import Any, Dict, Optional

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.wan_monitor import WANMonitor
from utils.i18n import _, escape_qt_mnemonic


_SEVERITY_COLORS = {
    "INFO": "#10B981",
    "WARNING": "#F59E0B",
    "CRITICAL": "#F43F5E",
}


class _WanCheckWorker(QThread):
    """Runs an on-demand WANMonitor check outside the Qt GUI thread."""

    verdict_ready = Signal(dict)
    error_occurred = Signal(str)

    def __init__(self, wan_monitor: WANMonitor, include_secondary: bool = True, parent=None):
        super().__init__(parent)
        self.wan_monitor = wan_monitor
        self.include_secondary = include_secondary

    def run(self) -> None:
        try:
            verdict = asyncio.run(
                self.wan_monitor.run_check(include_secondary_checks=self.include_secondary)
            )
            self.verdict_ready.emit(verdict.to_dict())
        except Exception as e:
            self.error_occurred.emit(str(e))


class _TargetStatusCard(QFrame):
    """Compact target card for Gateway, 8.8.8.8, 1.1.1.1, DNS, and HTTPS."""

    def __init__(self, title: str, initial_target: str = "—", parent=None):
        super().__init__(parent)
        self.setObjectName("KpiCard")
        self.setMinimumHeight(106)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(3)

        self.title_lbl = QLabel(title.upper())
        self.title_lbl.setAlignment(Qt.AlignCenter)
        self.title_lbl.setWordWrap(True)
        self.title_lbl.setStyleSheet(
            "font-size: 11px; font-weight: 700; color: #94A3B8; margin-bottom: 0px;"
        )

        self.target_lbl = QLabel(initial_target)
        self.target_lbl.setAlignment(Qt.AlignCenter)
        self.target_lbl.setWordWrap(True)
        self.target_lbl.setStyleSheet(
            "font-size: 12px; font-weight: 600; color: #E2E8F0; margin-bottom: 0px;"
        )

        self.status_lbl = QLabel("--")
        self.status_lbl.setAlignment(Qt.AlignCenter)
        self.status_lbl.setStyleSheet(
            "font-size: 16px; font-weight: 800; color: #94A3B8; margin-bottom: 0px;"
        )

        self.detail_lbl = QLabel("—")
        self.detail_lbl.setAlignment(Qt.AlignCenter)
        self.detail_lbl.setWordWrap(True)
        self.detail_lbl.setStyleSheet(
            "font-size: 11px; color: #94A3B8; margin-bottom: 0px;"
        )

        layout.addWidget(self.title_lbl)
        layout.addWidget(self.target_lbl)
        layout.addWidget(self.status_lbl)
        layout.addWidget(self.detail_lbl)

    def set_state(self, target_text: str, status_text: str, color: str, detail_text: str = "") -> None:
        self.target_lbl.setText(target_text or "—")
        self.status_lbl.setText(status_text)
        self.status_lbl.setStyleSheet(
            f"font-size: 16px; font-weight: 800; color: {color}; margin-bottom: 0px;"
        )
        self.detail_lbl.setText(detail_text or "—")


class WANMonitorView(QWidget):
    """Autonomous WAN Connectivity Intelligence view correlating LAN gateway, 8.8.8.8, 1.1.1.1, DNS, and HTTPS."""

    continuous_toggled = Signal(bool)
    interval_changed = Signal(int)
    verdict_ready = Signal(dict)
    manual_verdict_ready = Signal(dict)

    def __init__(
        self,
        wan_monitor: WANMonitor,
        continuous_enabled: bool = False,
        interval_sec: int = 15,
        parent=None,
    ):
        super().__init__(parent)
        self.wan_monitor = wan_monitor
        self._engine_running = False
        self._continuous_active = False
        self._worker: Optional[_WanCheckWorker] = None
        self._auto_timer = QTimer(self)
        self._auto_timer.timeout.connect(self._on_auto_timer_tick)
        self._build_ui(interval_sec=interval_sec)
        self._refresh_status_pill()
        if continuous_enabled:
            self.start_continuous_monitoring()

    def _build_ui(self, interval_sec: int) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 12, 0, 0)
        root.setSpacing(10)

        # ── Top Control Bar (2 compact rows inside FilterBar so FR never overflows) ──
        ctrl_bar = QFrame()
        ctrl_bar.setObjectName("FilterBar")
        ctrl_outer = QVBoxLayout(ctrl_bar)
        ctrl_outer.setContentsMargins(14, 10, 14, 10)
        ctrl_outer.setSpacing(8)

        row_top = QHBoxLayout()
        row_top.setSpacing(10)

        self.toggle_wan_btn = QPushButton(_("wan_btn_start_continuous", "Start Continuous WAN"))
        self.toggle_wan_btn.setObjectName("PrimaryButton")
        self.toggle_wan_btn.setCursor(Qt.PointingHandCursor)
        self.toggle_wan_btn.clicked.connect(self.toggle_continuous_monitoring)
        row_top.addWidget(self.toggle_wan_btn)

        self.run_btn = QPushButton(_("wan_btn_run", "Run WAN Check Now"))
        self.run_btn.setObjectName("SecondaryButton")
        self.run_btn.setCursor(Qt.PointingHandCursor)
        self.run_btn.clicked.connect(self.run_manual_check)
        row_top.addWidget(self.run_btn)

        row_top.addStretch()

        self.status_pill = QLabel(_("wan_status_idle", "IDLE"))
        self.status_pill.setAlignment(Qt.AlignCenter)
        row_top.addWidget(self.status_pill)
        ctrl_outer.addLayout(row_top)

        row_opts = QHBoxLayout()
        row_opts.setSpacing(12)

        int_lbl = QLabel(_("wan_interval_label", "Interval (s):"))
        int_lbl.setStyleSheet("color: #94A3B8; font-size: 12px; margin-bottom: 0px;")
        row_opts.addWidget(int_lbl)

        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(5, 300)
        self.interval_spin.setValue(max(5, min(300, int(interval_sec))))
        self.interval_spin.setMinimumWidth(90)
        self.interval_spin.valueChanged.connect(self._on_interval_changed)
        row_opts.addWidget(self.interval_spin)

        self.secondary_chk = QCheckBox(escape_qt_mnemonic(_("wan_chk_secondary", "Include DNS & HTTPS Verification")))
        self.secondary_chk.setCursor(Qt.PointingHandCursor)
        self.secondary_chk.setChecked(True)
        row_opts.addWidget(self.secondary_chk)
        row_opts.addStretch()
        ctrl_outer.addLayout(row_opts)

        root.addWidget(ctrl_bar)

        # ── Scrollable Body ──
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("background: transparent;")

        body = QWidget()
        body.setStyleSheet("background: transparent;")
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(0, 2, 4, 4)
        body_layout.setSpacing(12)

        # 1. Verdict Banner
        self.verdict_banner = QFrame()
        self.verdict_banner.setObjectName("Card")
        self._apply_banner_border("#6366F1")
        banner_layout = QVBoxLayout(self.verdict_banner)
        banner_layout.setContentsMargins(16, 12, 16, 12)
        banner_layout.setSpacing(6)

        banner_top = QHBoxLayout()
        banner_top.setSpacing(10)

        self.verdict_title_lbl = QLabel(_("wan_banner_initial_title", "WAN Intelligence Ready"))
        self.verdict_title_lbl.setWordWrap(True)
        self.verdict_title_lbl.setStyleSheet(
            "font-size: 18px; font-weight: 800; color: #FFFFFF; margin-bottom: 0px;"
        )
        banner_top.addWidget(self.verdict_title_lbl, 1)

        self.severity_badge = QLabel(f"{_('wan_severity_label', 'Severity:')} —")
        self.severity_badge.setStyleSheet(
            "background: rgba(99, 102, 241, 0.16); color: #818CF8; border: 1px solid rgba(99, 102, 241, 0.35);"
            "border-radius: 6px; padding: 3px 10px; font-size: 11px; font-weight: 700; margin-bottom: 0px;"
        )
        banner_top.addWidget(self.severity_badge)

        self.confidence_badge = QLabel(f"{_('wan_confidence_label', 'Confidence:')} —")
        self.confidence_badge.setStyleSheet(
            "background: rgba(148, 163, 184, 0.14); color: #CBD5E1; border: 1px solid rgba(148, 163, 184, 0.25);"
            "border-radius: 6px; padding: 3px 10px; font-size: 11px; font-weight: 700; margin-bottom: 0px;"
        )
        banner_top.addWidget(self.confidence_badge)

        self.timestamp_lbl = QLabel(f"{_('wan_last_check', 'Last Check:')} —")
        self.timestamp_lbl.setStyleSheet("color: #94A3B8; font-size: 11px; margin-bottom: 0px;")
        banner_top.addWidget(self.timestamp_lbl)

        banner_layout.addLayout(banner_top)

        self.cause_lbl = QLabel(
            _(
                "wan_banner_initial_cause",
                "Click 'Run WAN Check Now' or enable continuous WAN monitoring while the monitor is active to correlate gateway, Internet, DNS, and HTTPS health.",
            )
        )
        self.cause_lbl.setWordWrap(True)
        self.cause_lbl.setStyleSheet("color: #CBD5E1; font-size: 13px; margin-bottom: 0px;")
        banner_layout.addWidget(self.cause_lbl)

        body_layout.addWidget(self.verdict_banner)

        # 2. Five Target Cards Row
        cards_row = QHBoxLayout()
        cards_row.setSpacing(10)

        gw_initial = self.wan_monitor.gateway_ip or "Auto"
        self.gw_card = _TargetStatusCard(_("wan_card_gateway", "LOCAL GATEWAY"), gw_initial, self)
        self.primary_card = _TargetStatusCard(_("wan_card_primary", "PRIMARY WAN (GOOGLE)"), self.wan_monitor.primary_wan_ip, self)
        self.secondary_card = _TargetStatusCard(_("wan_card_secondary", "SECONDARY WAN (CLOUDFLARE)"), self.wan_monitor.secondary_wan_ip, self)
        self.dns_card = _TargetStatusCard(_("wan_card_dns", "DNS RESOLUTION"), self.wan_monitor.dns_test_domain, self)
        self.https_card = _TargetStatusCard(_("wan_card_https", "HTTPS / TLS (443)"), ", ".join(self.wan_monitor.https_test_hosts[:1]), self)

        for card in (self.gw_card, self.primary_card, self.secondary_card, self.dns_card, self.https_card):
            cards_row.addWidget(card, 1)
        body_layout.addLayout(cards_row)

        # 3. Side-by-Side Evidence & Recommended Actions Cards
        diag_row = QHBoxLayout()
        diag_row.setSpacing(10)

        ev_card = QFrame()
        ev_card.setObjectName("PanelCard")
        ev_layout = QVBoxLayout(ev_card)
        ev_layout.setContentsMargins(14, 12, 14, 12)
        ev_layout.setSpacing(6)
        ev_hdr = QLabel(_("wan_section_evidence", "DIAGNOSTIC EVIDENCE"))
        ev_hdr.setObjectName("SectionHeader")
        ev_hdr.setStyleSheet("margin-bottom: 2px;")
        self.evidence_lbl = QLabel("—")
        self.evidence_lbl.setWordWrap(True)
        self.evidence_lbl.setTextFormat(Qt.RichText)
        self.evidence_lbl.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.evidence_lbl.setStyleSheet("color: #CBD5E1; font-size: 12px; margin-bottom: 0px;")
        ev_layout.addWidget(ev_hdr)
        ev_layout.addWidget(self.evidence_lbl, 1)

        act_card = QFrame()
        act_card.setObjectName("PanelCard")
        act_layout = QVBoxLayout(act_card)
        act_layout.setContentsMargins(14, 12, 14, 12)
        act_layout.setSpacing(6)
        act_hdr = QLabel(_("wan_section_actions", "RECOMMENDED ACTIONS"))
        act_hdr.setObjectName("SectionHeader")
        act_hdr.setStyleSheet("margin-bottom: 2px;")
        self.actions_lbl = QLabel("—")
        self.actions_lbl.setWordWrap(True)
        self.actions_lbl.setTextFormat(Qt.RichText)
        self.actions_lbl.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.actions_lbl.setStyleSheet("color: #CBD5E1; font-size: 12px; margin-bottom: 0px;")
        act_layout.addWidget(act_hdr)
        act_layout.addWidget(self.actions_lbl, 1)

        diag_row.addWidget(ev_card, 1)
        diag_row.addWidget(act_card, 1)
        body_layout.addLayout(diag_row)

        # 4. Recent Checks History Table
        hist_hdr = QLabel(_("wan_section_history", "RECENT WAN CHECKS HISTORY"))
        hist_hdr.setObjectName("SectionHeader")
        hist_hdr.setStyleSheet("margin-bottom: 2px;")
        body_layout.addWidget(hist_hdr)

        self.history_table = QTableWidget(0, 8)
        self.history_table.setHorizontalHeaderLabels([
            _("wan_col_time", "Time").upper(),
            _("wan_col_verdict", "Verdict").upper(),
            _("wan_col_severity", "Severity").upper(),
            _("wan_col_confidence", "Confidence").upper(),
            _("wan_col_gateway", "Gateway").upper(),
            _("wan_col_primary", "8.8.8.8").upper(),
            _("wan_col_secondary", "1.1.1.1").upper(),
            _("wan_col_sec_checks", "DNS / HTTPS").upper(),
        ])
        hdr = self.history_table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.Stretch)
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.history_table.verticalHeader().setDefaultSectionSize(34)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.history_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.history_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setMinimumHeight(180)
        self.history_table.setStyleSheet("""
            QTableWidget {
                background-color: #1E293B;
                alternate-background-color: #161E2D;
                border: 1px solid #334155;
                border-radius: 12px;
                gridline-color: rgba(255, 255, 255, 0.04);
            }
            QTableWidget::item { padding: 4px 6px; }
            QTableWidget::item:selected {
                background-color: rgba(79, 70, 229, 0.35);
                color: #FFFFFF;
            }
            QHeaderView::section {
                background-color: #0F172A;
                padding: 7px 6px;
                font-weight: 700;
                font-size: 11px;
                border-bottom: 1px solid #334155;
            }
        """)
        body_layout.addWidget(self.history_table, 1)

        scroll.setWidget(body)
        root.addWidget(scroll, 1)

    def _apply_banner_border(self, color_hex: str) -> None:
        self.verdict_banner.setStyleSheet(
            f"QFrame#Card {{ background-color: #1E293B; border-radius: 16px; "
            f"border: 1px solid rgba(255, 255, 255, 0.08); border-left: 5px solid {color_hex}; }}"
        )

    def is_continuous_active(self) -> bool:
        return bool(self._continuous_active)

    def toggle_continuous_monitoring(self) -> None:
        if self._continuous_active:
            self.stop_continuous_monitoring()
        else:
            self.start_continuous_monitoring()

    def start_continuous_monitoring(self) -> None:
        if self._continuous_active:
            return
        self._continuous_active = True
        self.toggle_wan_btn.setText(_("wan_btn_stop_continuous", "Stop Continuous WAN"))
        self.toggle_wan_btn.setStyleSheet(
            "QPushButton { background-color: #E11D48; color: #FFFFFF; padding: 7px 16px; border-radius: 10px; font-weight: 700; border: none; }"
            "QPushButton:hover { background-color: #F43F5E; }"
        )
        self._auto_timer.start(max(5, int(self.interval_spin.value())) * 1000)
        self._refresh_status_pill()
        self.continuous_toggled.emit(True)
        self.run_manual_check()

    def stop_continuous_monitoring(self) -> None:
        self._auto_timer.stop()
        was_active = self._continuous_active
        self._continuous_active = False
        self.toggle_wan_btn.setText(_("wan_btn_start_continuous", "Start Continuous WAN"))
        self.toggle_wan_btn.setStyleSheet("")
        self._refresh_status_pill()
        if was_active:
            self.continuous_toggled.emit(False)

    def _on_interval_changed(self, value: int) -> None:
        if self._auto_timer.isActive():
            self._auto_timer.setInterval(max(5, int(value)) * 1000)
        self.interval_changed.emit(int(value))

    def _on_auto_timer_tick(self) -> None:
        if self._continuous_active and (self._worker is None or not self._worker.isRunning()):
            self.run_manual_check()

    def set_engine_running(self, running: bool) -> None:
        self._engine_running = bool(running)
        self._refresh_status_pill()

    def _refresh_status_pill(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            txt = _("wan_status_checking", "CHECKING...")
            col, bg = "#38BDF8", "rgba(56, 189, 248, 0.16)"
        elif self._continuous_active:
            txt = _("wan_status_continuous_active", "WAN ACTIVE")
            col, bg = "#10B981", "rgba(16, 185, 129, 0.16)"
        else:
            txt = _("wan_status_idle", "IDLE")
            col, bg = "#94A3B8", "rgba(148, 163, 184, 0.14)"

        self.status_pill.setText(txt)
        self.status_pill.setStyleSheet(
            f"background: {bg}; color: {col}; border: 1px solid {col}; border-radius: 6px; "
            f"padding: 4px 10px; font-size: 11px; font-weight: 700; margin-bottom: 0px;"
        )

    def run_manual_check(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        self.run_btn.setEnabled(False)
        self.run_btn.setText(_("wan_btn_running", "Checking..."))
        worker = _WanCheckWorker(
            self.wan_monitor,
            include_secondary=self.secondary_chk.isChecked(),
            parent=self,
        )
        self._worker = worker
        worker.verdict_ready.connect(self._on_manual_verdict)
        worker.error_occurred.connect(self._on_manual_error)
        worker.finished.connect(self._on_worker_finished)
        self._refresh_status_pill()
        worker.start()

    def _on_manual_verdict(self, verdict: Dict[str, Any]) -> None:
        self.update_verdict(verdict)
        self.verdict_ready.emit(verdict)
        self.manual_verdict_ready.emit(verdict)

    def _on_manual_error(self, err: str) -> None:
        self.cause_lbl.setText(str(err))
        self._apply_banner_border("#F43F5E")

    def _on_worker_finished(self) -> None:
        w = self._worker
        self._worker = None
        if w is not None:
            w.deleteLater()
        self.run_btn.setEnabled(True)
        self.run_btn.setText(_("wan_btn_run", "Run WAN Check Now"))
        self._refresh_status_pill()

    def stop_workers(self, stop_continuous: bool = True) -> None:
        if stop_continuous:
            self.stop_continuous_monitoring()
        if self._worker is not None and self._worker.isRunning():
            self._worker.wait(3000)

    def update_verdict(self, verdict: Dict[str, Any]) -> None:
        verdict_code = str(verdict.get("verdict_code", "HEALTHY"))
        severity = str(verdict.get("severity", "INFO")).upper()
        confidence = str(verdict.get("confidence", "MEDIUM")).upper()
        cause = str(verdict.get("probable_cause", ""))
        evidence = verdict.get("evidence") or []
        actions = verdict.get("recommended_actions") or []
        targets = verdict.get("targets") or {}

        ts_raw = verdict.get("timestamp_utc")
        ts_str = ts_raw.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts_raw, datetime) else str(ts_raw or "—")
        time_short = ts_raw.strftime("%H:%M:%S") if isinstance(ts_raw, datetime) else ts_str[-8:]

        sev_col = _SEVERITY_COLORS.get(severity, "#6366F1")
        self._apply_banner_border(sev_col)

        title_text = _(f"wan_verdict_{verdict_code}", verdict_code.replace("_", " ").title())
        self.verdict_title_lbl.setText(title_text)
        self.cause_lbl.setText(cause)
        self.timestamp_lbl.setText(f"{_('wan_last_check', 'Last Check:')} {ts_str}")

        self.severity_badge.setText(f"{_('wan_severity_label', 'Severity:')} {severity}")
        self.severity_badge.setStyleSheet(
            f"background: rgba(15, 23, 42, 0.6); color: {sev_col}; border: 1px solid {sev_col}; "
            f"border-radius: 6px; padding: 3px 10px; font-size: 11px; font-weight: 700; margin-bottom: 0px;"
        )

        conf_col = "#10B981" if confidence == "HIGH" else ("#F59E0B" if confidence == "MEDIUM" else "#94A3B8")
        self.confidence_badge.setText(f"{_('wan_confidence_label', 'Confidence:')} {confidence}")
        self.confidence_badge.setStyleSheet(
            f"background: rgba(15, 23, 42, 0.6); color: {conf_col}; border: 1px solid {conf_col}; "
            f"border-radius: 6px; padding: 3px 10px; font-size: 11px; font-weight: 700; margin-bottom: 0px;"
        )

        # Update 5 Target Cards
        def _fmt_ping_card(card: _TargetStatusCard, key: str, default_tgt: str) -> str:
            info = targets.get(key, {})
            tgt = str(info.get("target") or default_tgt)
            up = info.get("up")
            lat = float(info.get("latency_ms") or 0.0)
            if up is True:
                det = f"{lat:.1f} ms" if lat > 0 else "OK"
                card.set_state(tgt, "UP", "#10B981", det)
                return f"UP ({lat:.0f}ms)" if lat > 0 else "UP"
            if up is False:
                card.set_state(tgt, "DOWN", "#F43F5E", "Timeout / Unreachable")
                return "DOWN"
            card.set_state(tgt, "N/A", "#94A3B8", "—")
            return "N/A"

        gw_summary = _fmt_ping_card(self.gw_card, "gateway", self.wan_monitor.gateway_ip or "Gateway")
        p_summary = _fmt_ping_card(self.primary_card, "primary_wan", self.wan_monitor.primary_wan_ip)
        s_summary = _fmt_ping_card(self.secondary_card, "secondary_wan", self.wan_monitor.secondary_wan_ip)

        dns_info = targets.get("dns", {})
        dns_ok = dns_info.get("ok")
        dns_det = str(dns_info.get("detail") or "")
        if dns_ok is True:
            self.dns_card.set_state(self.wan_monitor.dns_test_domain, "OK", "#10B981", dns_det or "Resolved")
            dns_tag = "DNS:OK"
        elif dns_ok is False:
            self.dns_card.set_state(self.wan_monitor.dns_test_domain, "FAIL", "#F43F5E", dns_det or "Lookup failed")
            dns_tag = "DNS:FAIL"
        else:
            self.dns_card.set_state(self.wan_monitor.dns_test_domain, "N/A", "#94A3B8", "—")
            dns_tag = "DNS:N/A"

        https_info = targets.get("https", {})
        https_ok = https_info.get("ok")
        https_det = str(https_info.get("detail") or "")
        https_tgt = ", ".join(self.wan_monitor.https_test_hosts[:1]) or "443"
        if https_ok is True:
            self.https_card.set_state(https_tgt, "OK", "#10B981", https_det or "TLS Handshake OK")
            https_tag = "HTTPS:OK"
        elif https_ok is False:
            self.https_card.set_state(https_tgt, "FAIL", "#F43F5E", https_det or "Connection failed")
            https_tag = "HTTPS:FAIL"
        else:
            self.https_card.set_state(https_tgt, "N/A", "#94A3B8", "—")
            https_tag = "HTTPS:N/A"

        # Update Evidence & Actions
        ev_html = "<br/>".join(f"• {html.escape(str(item))}" for item in evidence) if evidence else "—"
        act_html = "<br/>".join(f"-> {html.escape(str(item))}" for item in actions) if actions else "—"
        self.evidence_lbl.setText(ev_html)
        self.actions_lbl.setText(act_html)

        # Insert latest check at top of History Table (keep max 20 rows)
        self.history_table.insertRow(0)
        bold_font = QFont()
        bold_font.setBold(True)

        row_vals = [
            time_short,
            title_text,
            severity,
            confidence,
            gw_summary,
            p_summary,
            s_summary,
            f"{dns_tag} | {https_tag}",
        ]
        for col, text_val in enumerate(row_vals):
            it = QTableWidgetItem(text_val)
            it.setTextAlignment(Qt.AlignCenter)
            if col == 1:
                it.setFont(bold_font)
                it.setForeground(QColor("#E2E8F0"))
            elif col == 2:
                it.setFont(bold_font)
                it.setForeground(QColor(sev_col))
            elif col == 3:
                it.setForeground(QColor(conf_col))
            elif col in (4, 5, 6):
                it.setForeground(QColor("#10B981" if text_val.startswith("UP") else ("#F43F5E" if text_val == "DOWN" else "#94A3B8")))
            elif col == 7:
                has_fail = "FAIL" in text_val
                has_ok = "OK" in text_val
                it.setForeground(QColor("#F43F5E" if has_fail else ("#10B981" if has_ok else "#94A3B8")))
            self.history_table.setItem(0, col, it)

        while self.history_table.rowCount() > 20:
            self.history_table.removeRow(20)
