from typing import Any, Dict, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from core.monitoring_state import MonitoringPolicyConfig
from core.ping_engine import AsyncPingEngine
from utils.db import DatabaseManager
from utils.i18n import _
from utils.monitoring_export import export_monitoring_config, import_monitoring_config


_DEFAULT_RAW_DAYS = 7
_DEFAULT_AGG_DAYS = 90
_DEFAULT_INC_DAYS = 365
_DEFAULT_ALERT_DAYS = 365
_DEFAULT_SOUND_DUR_SEC = 0


class MonitoringSettingsWidget(QWidget):
    """Global Intelligent Ping Monitoring Settings: thresholds, alerts, retention, and JSON import/export."""

    global_policy_saved = Signal(dict)

    def __init__(
        self,
        db: DatabaseManager,
        engine: AsyncPingEngine,
        config_manager=None,
        parent=None,
    ):
        super().__init__(parent)
        self.db = db
        self.engine = engine
        self.config = config_manager
        self._build_ui()
        self.load_from_storage()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 12, 0, 0)
        root.setSpacing(10)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("background: transparent;")

        body = QWidget()
        body.setStyleSheet("background: transparent;")
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(0, 2, 6, 6)
        body_layout.setSpacing(12)

        # ── Section 1: Global Probe & State Machine Thresholds ──
        thresh_card = QFrame()
        thresh_card.setObjectName("Card")
        thresh_outer = QVBoxLayout(thresh_card)
        thresh_outer.setContentsMargins(16, 14, 16, 14)
        thresh_outer.setSpacing(10)

        lbl_thresh = QLabel(_("mon_cfg_sec_thresholds", "GLOBAL PROBE & STATE MACHINE THRESHOLDS"))
        lbl_thresh.setObjectName("SectionHeader")
        lbl_thresh.setStyleSheet("margin-bottom: 2px;")
        thresh_outer.addWidget(lbl_thresh)

        thresh_cols = QHBoxLayout()
        thresh_cols.setSpacing(24)
        left_form = QFormLayout()
        left_form.setSpacing(10)
        right_form = QFormLayout()
        right_form.setSpacing(10)

        self.sp_interval = QSpinBox()
        self.sp_interval.setRange(100, 60000)

        self.sp_timeout = QSpinBox()
        self.sp_timeout.setRange(100, 10000)

        self.sp_warn_fail = QSpinBox()
        self.sp_warn_fail.setRange(1, 50)

        self.sp_crit_fail = QSpinBox()
        self.sp_crit_fail.setRange(1, 100)

        self.sp_rec_ok = QSpinBox()
        self.sp_rec_ok.setRange(1, 50)

        self.sp_window = QSpinBox()
        self.sp_window.setRange(10, 3600)

        self.sp_loss = QDoubleSpinBox()
        self.sp_loss.setRange(0.5, 100.0)
        self.sp_loss.setDecimals(1)

        self.sp_lat = QDoubleSpinBox()
        self.sp_lat.setRange(5.0, 5000.0)
        self.sp_lat.setDecimals(1)

        self.sp_jit = QDoubleSpinBox()
        self.sp_jit.setRange(1.0, 2000.0)
        self.sp_jit.setDecimals(1)

        left_form.addRow(_("mon_host_cfg_interval", "Probe Interval (ms):"), self.sp_interval)
        left_form.addRow(_("mon_host_cfg_timeout", "Timeout (ms):"), self.sp_timeout)
        left_form.addRow(_("mon_host_cfg_warn_fail", "Warning Failures:"), self.sp_warn_fail)
        left_form.addRow(_("mon_host_cfg_crit_fail", "Critical Failures (DOWN):"), self.sp_crit_fail)
        left_form.addRow(_("mon_host_cfg_rec_ok", "Recovery Successes:"), self.sp_rec_ok)

        right_form.addRow(_("mon_host_cfg_window", "Rolling Window (s):"), self.sp_window)
        right_form.addRow(_("mon_host_cfg_loss_warn", "Packet Loss Warning (%):"), self.sp_loss)
        right_form.addRow(_("mon_host_cfg_lat_warn", "Latency Warning (ms):"), self.sp_lat)
        right_form.addRow(_("mon_host_cfg_jit_warn", "Jitter Warning (ms):"), self.sp_jit)

        thresh_cols.addLayout(left_form, 1)
        thresh_cols.addLayout(right_form, 1)
        thresh_outer.addLayout(thresh_cols)
        body_layout.addWidget(thresh_card)

        # ── Section 2: Alert & Notification Preferences ──
        notif_card = QFrame()
        notif_card.setObjectName("Card")
        notif_outer = QVBoxLayout(notif_card)
        notif_outer.setContentsMargins(16, 14, 16, 14)
        notif_outer.setSpacing(10)

        lbl_notif = QLabel(_("mon_cfg_sec_notifications", "ALERT & NOTIFICATION PREFERENCES"))
        lbl_notif.setObjectName("SectionHeader")
        lbl_notif.setStyleSheet("margin-bottom: 2px;")
        notif_outer.addWidget(lbl_notif)

        chk_row = QHBoxLayout()
        chk_row.setSpacing(20)
        self.chk_sound = QCheckBox(_("mon_host_cfg_sound", "Enable Critical Sound Alarm"))
        self.chk_sound.setCursor(Qt.PointingHandCursor)
        self.chk_email = QCheckBox(_("mon_host_cfg_email", "Enable Email Alerts"))
        self.chk_email.setCursor(Qt.PointingHandCursor)
        self.chk_win = QCheckBox(_("mon_host_cfg_win_notify", "Enable Windows Desktop Notifications"))
        self.chk_win.setCursor(Qt.PointingHandCursor)
        chk_row.addWidget(self.chk_sound)
        chk_row.addWidget(self.chk_email)
        chk_row.addWidget(self.chk_win)
        chk_row.addStretch()
        notif_outer.addLayout(chk_row)

        notif_cols = QHBoxLayout()
        notif_cols.setSpacing(24)
        n_left = QFormLayout()
        n_left.setSpacing(10)
        n_right = QFormLayout()
        n_right.setSpacing(10)

        self.sp_repeat_sec = QSpinBox()
        self.sp_repeat_sec.setRange(0, 86400)

        self.sp_sound_dur = QSpinBox()
        self.sp_sound_dur.setRange(0, 600)
        self.sp_sound_dur.setToolTip(_("mon_cfg_sound_duration_hint", "0 = continuous until recovery"))

        n_left.addRow(_("mon_cfg_repeat_alert", "Repeat Critical Alert (s):"), self.sp_repeat_sec)
        n_right.addRow(_("mon_cfg_sound_duration", "Alarm Sound Duration (s):"), self.sp_sound_dur)

        notif_cols.addLayout(n_left, 1)
        notif_cols.addLayout(n_right, 1)
        notif_outer.addLayout(notif_cols)

        hint_lbl = QLabel(_("mon_cfg_email_hint", "SMTP server & recipient settings are managed in App Settings -> Alerts (Sound & Email)."))
        hint_lbl.setStyleSheet("color: #94A3B8; font-size: 11px; margin-bottom: 0px;")
        notif_outer.addWidget(hint_lbl)
        body_layout.addWidget(notif_card)

        # ── Section 3: Data Retention & Database Maintenance ──
        ret_card = QFrame()
        ret_card.setObjectName("Card")
        ret_outer = QVBoxLayout(ret_card)
        ret_outer.setContentsMargins(16, 14, 16, 14)
        ret_outer.setSpacing(10)

        lbl_ret = QLabel(_("mon_cfg_sec_retention", "DATA RETENTION & DATABASE MAINTENANCE"))
        lbl_ret.setObjectName("SectionHeader")
        lbl_ret.setStyleSheet("margin-bottom: 2px;")
        ret_outer.addWidget(lbl_ret)

        ret_cols = QHBoxLayout()
        ret_cols.setSpacing(24)
        r_left = QFormLayout()
        r_left.setSpacing(10)
        r_right = QFormLayout()
        r_right.setSpacing(10)

        self.sp_ret_raw = QSpinBox()
        self.sp_ret_raw.setRange(1, 365)

        self.sp_ret_agg = QSpinBox()
        self.sp_ret_agg.setRange(7, 3650)

        self.sp_ret_inc = QSpinBox()
        self.sp_ret_inc.setRange(7, 3650)

        self.sp_ret_alerts = QSpinBox()
        self.sp_ret_alerts.setRange(7, 3650)

        r_left.addRow(_("mon_cfg_ret_raw", "Raw Measurements Retention (days):"), self.sp_ret_raw)
        r_left.addRow(_("mon_cfg_ret_agg", "Aggregated Stats Retention (days):"), self.sp_ret_agg)
        r_right.addRow(_("mon_cfg_ret_inc", "Closed Incidents Retention (days):"), self.sp_ret_inc)
        r_right.addRow(_("mon_cfg_ret_alerts", "Alert Events Retention (days):"), self.sp_ret_alerts)

        ret_cols.addLayout(r_left, 1)
        ret_cols.addLayout(r_right, 1)
        ret_outer.addLayout(ret_cols)

        purge_row = QHBoxLayout()
        purge_row.setSpacing(12)
        self.purge_btn = QPushButton(_("mon_cfg_btn_purge", "Run Retention Purge Now"))
        self.purge_btn.setObjectName("SecondaryButton")
        self.purge_btn.setFixedHeight(32)
        self.purge_btn.setCursor(Qt.PointingHandCursor)
        self.purge_btn.clicked.connect(self.run_retention_purge)
        self.purge_result_lbl = QLabel("")
        self.purge_result_lbl.setStyleSheet("color: #10B981; font-size: 12px; margin-bottom: 0px;")
        purge_row.addWidget(self.purge_btn)
        purge_row.addWidget(self.purge_result_lbl, 1)
        ret_outer.addLayout(purge_row)

        for sp in (
            self.sp_interval, self.sp_timeout, self.sp_warn_fail, self.sp_crit_fail,
            self.sp_rec_ok, self.sp_window, self.sp_loss, self.sp_lat, self.sp_jit,
            self.sp_repeat_sec, self.sp_sound_dur,
            self.sp_ret_raw, self.sp_ret_agg, self.sp_ret_inc, self.sp_ret_alerts,
        ):
            sp.setMinimumWidth(110)

        body_layout.addWidget(ret_card)
        body_layout.addStretch()

        scroll.setWidget(body)
        root.addWidget(scroll, 1)

        # ── Sticky Action Bar ──
        actions_row = QHBoxLayout()
        actions_row.setSpacing(10)

        self.save_btn = QPushButton(_("mon_cfg_btn_save", "Save Global Settings"))
        self.save_btn.setObjectName("PrimaryButton")
        self.save_btn.setFixedHeight(36)
        self.save_btn.setCursor(Qt.PointingHandCursor)
        self.save_btn.clicked.connect(self.save_settings)

        self.restore_btn = QPushButton(_("mon_cfg_btn_restore", "Restore Defaults"))
        self.restore_btn.setObjectName("SecondaryButton")
        self.restore_btn.setFixedHeight(36)
        self.restore_btn.setCursor(Qt.PointingHandCursor)
        self.restore_btn.clicked.connect(self.restore_defaults)

        self.export_btn = QPushButton(_("mon_cfg_btn_export", "Export Config (JSON)"))
        self.export_btn.setObjectName("SecondaryButton")
        self.export_btn.setFixedHeight(36)
        self.export_btn.setCursor(Qt.PointingHandCursor)
        self.export_btn.clicked.connect(self.export_config)

        self.import_btn = QPushButton(_("mon_cfg_btn_import", "Import Config (JSON)"))
        self.import_btn.setObjectName("SecondaryButton")
        self.import_btn.setFixedHeight(36)
        self.import_btn.setCursor(Qt.PointingHandCursor)
        self.import_btn.clicked.connect(self.import_config)

        actions_row.addWidget(self.save_btn)
        actions_row.addWidget(self.restore_btn)
        actions_row.addStretch()
        actions_row.addWidget(self.export_btn)
        actions_row.addWidget(self.import_btn)
        root.addLayout(actions_row)

    def _apply_policy_to_form(self, cfg: MonitoringPolicyConfig) -> None:
        self.sp_interval.setValue(int(cfg.probe_interval_ms))
        self.sp_timeout.setValue(int(cfg.timeout_ms))
        self.sp_warn_fail.setValue(int(cfg.warning_failures))
        self.sp_crit_fail.setValue(int(cfg.critical_failures))
        self.sp_rec_ok.setValue(int(cfg.recovery_successes))
        self.sp_window.setValue(int(cfg.rolling_window_sec))
        self.sp_loss.setValue(float(cfg.packet_loss_warn_pct))
        self.sp_lat.setValue(float(cfg.latency_warn_ms))
        self.sp_jit.setValue(float(cfg.jitter_warn_ms))
        self.chk_sound.setChecked(bool(cfg.sound_enabled))
        self.chk_email.setChecked(bool(cfg.email_enabled))
        self.chk_win.setChecked(bool(cfg.windows_notify_enabled))
        self.sp_repeat_sec.setValue(int(cfg.repeat_alert_interval_sec))

    def _build_policy_from_form(self) -> MonitoringPolicyConfig:
        cfg = MonitoringPolicyConfig(
            probe_interval_ms=self.sp_interval.value(),
            timeout_ms=self.sp_timeout.value(),
            warning_failures=self.sp_warn_fail.value(),
            critical_failures=self.sp_crit_fail.value(),
            recovery_successes=self.sp_rec_ok.value(),
            rolling_window_sec=self.sp_window.value(),
            packet_loss_warn_pct=float(self.sp_loss.value()),
            latency_warn_ms=float(self.sp_lat.value()),
            jitter_warn_ms=float(self.sp_jit.value()),
            sound_enabled=self.chk_sound.isChecked(),
            email_enabled=self.chk_email.isChecked(),
            windows_notify_enabled=self.chk_win.isChecked(),
            repeat_alert_interval_sec=self.sp_repeat_sec.value(),
        )
        cfg.validate()
        return cfg

    def load_from_storage(self) -> None:
        saved = self.db.get_policy(host_id=None)
        cfg = MonitoringPolicyConfig.from_dict(saved) if saved else MonitoringPolicyConfig(**self.engine.global_policy.to_dict())
        self._apply_policy_to_form(cfg)

        sound_dur = _DEFAULT_SOUND_DUR_SEC
        ret_raw = _DEFAULT_RAW_DAYS
        ret_agg = _DEFAULT_AGG_DAYS
        ret_inc = _DEFAULT_INC_DAYS
        ret_alerts = _DEFAULT_ALERT_DAYS
        if self.config is not None:
            sound_dur = int(self.config.get("alarm_duration_sec", _DEFAULT_SOUND_DUR_SEC) or 0)
            ret_raw = int(self.config.get("retention_raw_days", _DEFAULT_RAW_DAYS) or _DEFAULT_RAW_DAYS)
            ret_agg = int(self.config.get("retention_aggregated_days", _DEFAULT_AGG_DAYS) or _DEFAULT_AGG_DAYS)
            ret_inc = int(self.config.get("retention_incidents_days", _DEFAULT_INC_DAYS) or _DEFAULT_INC_DAYS)
            ret_alerts = int(self.config.get("retention_alerts_days", _DEFAULT_ALERT_DAYS) or _DEFAULT_ALERT_DAYS)

        self.sp_sound_dur.setValue(sound_dur)
        self.sp_ret_raw.setValue(ret_raw)
        self.sp_ret_agg.setValue(ret_agg)
        self.sp_ret_inc.setValue(ret_inc)
        self.sp_ret_alerts.setValue(ret_alerts)

    def _persist_aux_config(self) -> None:
        if self.config is not None:
            self.config.set("alarm_duration_sec", self.sp_sound_dur.value())
            self.config.set("retention_raw_days", self.sp_ret_raw.value())
            self.config.set("retention_aggregated_days", self.sp_ret_agg.value())
            self.config.set("retention_incidents_days", self.sp_ret_inc.value())
            self.config.set("retention_alerts_days", self.sp_ret_alerts.value())

    def save_settings(self) -> bool:
        try:
            cfg = self._build_policy_from_form()
        except ValueError as e:
            QMessageBox.warning(self, _("msg_error"), str(e))
            return False

        self.db.save_policy(cfg.to_dict(), host_id=None)
        self.engine.update_global_policy(cfg, propagate_non_overridden=True)
        self._persist_aux_config()
        self.global_policy_saved.emit(cfg.to_dict())
        QMessageBox.information(self, _("msg_success"), _("mon_cfg_saved_ok", "Global monitoring settings saved and applied."))
        return True

    def restore_defaults(self) -> None:
        default_cfg = MonitoringPolicyConfig()
        self._apply_policy_to_form(default_cfg)
        self.sp_sound_dur.setValue(_DEFAULT_SOUND_DUR_SEC)
        self.sp_ret_raw.setValue(_DEFAULT_RAW_DAYS)
        self.sp_ret_agg.setValue(_DEFAULT_AGG_DAYS)
        self.sp_ret_inc.setValue(_DEFAULT_INC_DAYS)
        self.sp_ret_alerts.setValue(_DEFAULT_ALERT_DAYS)

        self.db.save_policy(default_cfg.to_dict(), host_id=None)
        self.engine.update_global_policy(default_cfg, propagate_non_overridden=True)
        self._persist_aux_config()
        self.global_policy_saved.emit(default_cfg.to_dict())
        QMessageBox.information(self, _("msg_success"), _("mon_cfg_restored_ok", "Default monitoring settings restored."))

    def run_retention_purge(self) -> Dict[str, int]:
        self._persist_aux_config()
        counts = self.db.cleanup_by_retention(
            raw_days=self.sp_ret_raw.value(),
            aggregated_days=self.sp_ret_agg.value(),
            incidents_days=self.sp_ret_inc.value(),
            alerts_days=self.sp_ret_alerts.value(),
        )
        summary_msg = _(
            "mon_cfg_purge_done",
            "Purge completed: {} raw, {} stats, {} incidents, {} alerts removed.",
        ).format(counts["raw"], counts["aggregated"], counts["incidents"], counts["alerts"])
        self.purge_result_lbl.setText(summary_msg)
        QMessageBox.information(self, _("msg_success"), summary_msg)
        return counts

    def export_config(self) -> None:
        try:
            global_dict = self._build_policy_from_form().to_dict()
        except ValueError:
            global_dict = self.engine.global_policy.to_dict()

        host_policies: Dict[str, Dict[str, Any]] = {}
        for h in self.db.get_hosts():
            pol = self.db.get_policy(h["id"])
            if pol is not None:
                host_policies[h["address"]] = MonitoringPolicyConfig.from_dict(pol).to_dict()

        path, _f = QFileDialog.getSaveFileName(
            self,
            _("mon_cfg_btn_export", "Export Config (JSON)"),
            "BahaaIT_Monitoring_Config.json",
            "JSON Files (*.json)",
        )
        if not path:
            return

        ok, err = export_monitoring_config(global_dict, host_policies, path)
        if ok:
            QMessageBox.information(self, _("msg_success"), _("mon_cfg_export_ok", "Monitoring configuration exported successfully."))
        else:
            QMessageBox.critical(self, _("msg_error"), err)

    def import_config(self) -> bool:
        path, _f = QFileDialog.getOpenFileName(
            self,
            _("mon_cfg_btn_import", "Import Config (JSON)"),
            "",
            "JSON Files (*.json)",
        )
        if not path:
            return False

        ok, payload, err = import_monitoring_config(path)
        if not ok:
            QMessageBox.critical(
                self,
                _("msg_error"),
                _("mon_cfg_import_err", "Failed to import configuration: {}").format(err),
            )
            return False

        gp_cfg = MonitoringPolicyConfig.from_dict(payload["global_policy"])
        self.db.save_policy(gp_cfg.to_dict(), host_id=None)

        host_by_addr = {h["address"]: h for h in self.db.get_hosts()}
        for addr, h_dict in payload.get("host_policies", {}).items():
            h_row = host_by_addr.get(addr)
            if h_row is not None:
                h_cfg = MonitoringPolicyConfig.from_dict(h_dict)
                self.db.save_policy(h_cfg.to_dict(), host_id=h_row["id"])
                self.engine.update_host_policy(addr, h_cfg)

        self.engine.update_global_policy(gp_cfg, propagate_non_overridden=True)
        self._apply_policy_to_form(gp_cfg)
        self.global_policy_saved.emit(gp_cfg.to_dict())
        QMessageBox.information(self, _("msg_success"), _("mon_cfg_import_ok", "Monitoring configuration imported successfully."))
        return True
