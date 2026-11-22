import time
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from core.monitoring_state import HostState, MonitoringPolicyConfig, StateTransition
from core.network_quality import QualitySnapshot
from utils.db import DatabaseManager
from utils.notification_manager import NotificationDispatcher


class AlertSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class AlertManager:
    """Independent Alert Manager with anti-spam deduplication and channel isolation."""

    def __init__(
        self,
        db: DatabaseManager,
        dispatcher: Optional[NotificationDispatcher] = None,
        config_manager=None,
        logger=None,
    ):
        self.db = db
        self.dispatcher = dispatcher or NotificationDispatcher(config_manager=config_manager, logger=logger)
        self.config_manager = config_manager
        self.logger = logger
        # Per-host deduplication tracking:
        # {host_address: {"incident_uid": str, "severity": str, "last_sent_mono": float, "email_sent_down": bool}}
        self._active_alerts: Dict[str, Dict[str, Any]] = {}
        self._down_hosts: set[str] = set()

    def _is_global_email_enabled(self) -> bool:
        if self.config_manager is None:
            return False
        return bool(self.config_manager.get("email_alerts_enabled", False))

    def _should_email_for_status(self, is_recovery: bool) -> bool:
        if self.config_manager is None:
            return True
        if is_recovery:
            return bool(self.config_manager.get("email_alert_on_up", True))
        return bool(self.config_manager.get("email_alert_on_down", True))

    def _record_event(
        self,
        host_id: Optional[int],
        host_name: str,
        host_address: str,
        incident_id: Optional[int],
        severity: AlertSeverity,
        event_type: str,
        message: str,
        channel: str,
        delivered: bool = True,
        error_detail: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self.db.save_alert_event({
            "timestamp": datetime.utcnow(),
            "host_id": host_id,
            "host_address": host_address,
            "host_name": host_name,
            "incident_id": incident_id,
            "severity": severity.value,
            "event_type": event_type,
            "message": message,
            "channel": channel,
            "delivered": delivered,
            "error_detail": error_detail,
        })

    def evaluate_transition(
        self,
        host_id: Optional[int],
        host_name: str,
        host_address: str,
        transition: StateTransition,
        quality: QualitySnapshot,
        policy: MonitoringPolicyConfig,
        incident: Optional[Dict[str, Any]] = None,
        now_mono: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Evaluate a state transition or repeated failure and dispatch deduplicated alerts."""
        ts_mono = now_mono if now_mono is not None else time.monotonic()
        emitted: List[Dict[str, Any]] = []
        inc_id = incident.get("id") if incident else None
        inc_uid = incident.get("incident_uid") if incident else f"NOINC-{host_address}"
        inc_start = (
            incident["start_time"].strftime("%Y-%m-%d %H:%M:%S")
            if incident and incident.get("start_time")
            else transition.timestamp_utc.strftime("%Y-%m-%d %H:%M:%S")
        )
        display_name = host_name or host_address

        # Isolated packet loss / unchanged steady-state UP / RECOVERING progress: log-only unless DOWN repeat interval reached
        if not transition.changed and transition.new_state != HostState.DOWN:
            return emitted

        new_state = transition.new_state

        if new_state == HostState.PAUSED:
            self._down_hosts.discard(host_address)
            if not self._down_hosts:
                self.dispatcher.stop_sound()
            evt = self._record_event(
                host_id, display_name, host_address, inc_id,
                AlertSeverity.INFO, "MONITORING_PAUSED",
                f"Monitoring paused for {display_name} ({host_address}).",
                "SYSTEM",
            )
            emitted.append(evt)
            return emitted

        if transition.reason == "RESUMED":
            evt = self._record_event(
                host_id, display_name, host_address, inc_id,
                AlertSeverity.INFO, "MONITORING_RESUMED",
                f"Monitoring resumed for {display_name} ({host_address}).",
                "SYSTEM",
            )
            emitted.append(evt)
            return emitted

        if new_state == HostState.DEGRADED:
            dedup = self._active_alerts.get(host_address)
            if dedup and dedup.get("incident_uid") == inc_uid and dedup.get("severity") == AlertSeverity.WARNING.value:
                return emitted

            self._active_alerts[host_address] = {
                "incident_uid": inc_uid,
                "severity": AlertSeverity.WARNING.value,
                "last_sent_mono": ts_mono,
                "email_sent_down": dedup.get("email_sent_down", False) if dedup else False,
            }
            msg = f"Host degraded ({transition.reason}): {transition.details}"
            emitted.append(self._record_event(
                host_id, display_name, host_address, inc_id,
                AlertSeverity.WARNING, transition.reason or "DEGRADED", msg, "UI",
            ))
            if policy.windows_notify_enabled:
                self.dispatcher.dispatch_windows_notification(
                    f"[WARNING] {display_name}", msg, severity="WARNING"
                )
            return emitted

        if new_state == HostState.DOWN:
            self._down_hosts.add(host_address)
            dedup = self._active_alerts.get(host_address)
            already_critical_same_inc = (
                dedup is not None
                and dedup.get("incident_uid") == inc_uid
                and dedup.get("severity") == AlertSeverity.CRITICAL.value
            )

            repeat_due = False
            if already_critical_same_inc and policy.repeat_alert_interval_sec > 0:
                if (ts_mono - dedup["last_sent_mono"]) >= policy.repeat_alert_interval_sec:
                    repeat_due = True

            if already_critical_same_inc and not repeat_due:
                # Duplicate outage alert suppressed (anti-spam)
                return emitted

            email_already_sent = bool(dedup and dedup.get("email_sent_down"))
            email_sent_now = False

            msg = f"Host DOWN confirmed: {transition.details}"
            sound_dur = 0.0
            if self.config_manager is not None:
                sound_dur = float(self.config_manager.get("alarm_duration_sec", 0.0) or 0.0)

            if policy.sound_enabled:
                played = self.dispatcher.dispatch_sound("CRITICAL", duration_sec=sound_dur)
                if played and not already_critical_same_inc:
                    emitted.append(self._record_event(
                        host_id, display_name, host_address, inc_id,
                        AlertSeverity.CRITICAL, "OUTAGE_ALARM", msg, "SOUND",
                    ))

            if policy.windows_notify_enabled:
                sent_win = self.dispatcher.dispatch_windows_notification(
                    f"[CRITICAL] {display_name} DOWN", msg, severity="CRITICAL"
                )
                if sent_win:
                    emitted.append(self._record_event(
                        host_id, display_name, host_address, inc_id,
                        AlertSeverity.CRITICAL, "OUTAGE_TOAST", msg, "WINDOWS",
                    ))

            if policy.email_enabled and self._is_global_email_enabled() and self._should_email_for_status(is_recovery=False):
                if not email_already_sent or repeat_due:
                    def _on_email_done(ok: bool, err: str):
                        self._record_event(
                            host_id, display_name, host_address, inc_id,
                            AlertSeverity.CRITICAL, "OUTAGE_EMAIL", msg, "EMAIL",
                            delivered=ok, error_detail=err or None,
                        )

                    self.dispatcher.dispatch_email(
                        host=host_address,
                        label=display_name,
                        severity="CRITICAL",
                        status="DOWN",
                        latency=0.0,
                        incident_start=inc_start,
                        diagnosis=transition.details,
                        on_done=_on_email_done,
                    )
                    email_sent_now = True

            # Record primary UI/log event if no channel event was logged yet
            if not emitted or not already_critical_same_inc:
                emitted.append(self._record_event(
                    host_id, display_name, host_address, inc_id,
                    AlertSeverity.CRITICAL, "OUTAGE_CONFIRMED", msg, "SYSTEM",
                ))

            self._active_alerts[host_address] = {
                "incident_uid": inc_uid,
                "severity": AlertSeverity.CRITICAL.value,
                "last_sent_mono": ts_mono,
                "email_sent_down": email_already_sent or email_sent_now,
            }
            return emitted

        if new_state == HostState.RECOVERING:
            self._down_hosts.discard(host_address)
            if not self._down_hosts:
                self.dispatcher.stop_sound()
            emitted.append(self._record_event(
                host_id, display_name, host_address, inc_id,
                AlertSeverity.INFO, "RECOVERY_IN_PROGRESS", transition.details, "SYSTEM",
            ))
            return emitted

        if new_state == HostState.UP:
            self._down_hosts.discard(host_address)
            if not self._down_hosts:
                self.dispatcher.stop_sound()

            dedup = self._active_alerts.pop(host_address, None)
            if transition.previous_state in (HostState.DOWN, HostState.RECOVERING, HostState.DEGRADED):
                msg = f"Host recovered ({transition.details})"
                emitted.append(self._record_event(
                    host_id, display_name, host_address, inc_id,
                    AlertSeverity.INFO, "HOST_RECOVERED", msg, "SYSTEM",
                ))
                if policy.windows_notify_enabled:
                    self.dispatcher.dispatch_windows_notification(
                        f"[INFO] {display_name} RECOVERED", msg, severity="INFO"
                    )
                if (
                    dedup
                    and dedup.get("email_sent_down")
                    and policy.email_enabled
                    and self._is_global_email_enabled()
                    and self._should_email_for_status(is_recovery=True)
                ):
                    def _on_rec_email_done(ok: bool, err: str):
                        self._record_event(
                            host_id, display_name, host_address, inc_id,
                            AlertSeverity.INFO, "RECOVERY_EMAIL", msg, "EMAIL",
                            delivered=ok, error_detail=err or None,
                        )

                    self.dispatcher.dispatch_email(
                        host=host_address,
                        label=display_name,
                        severity="INFO",
                        status="UP",
                        latency=float(quality.current_latency_ms or 0.0),
                        incident_start=inc_start,
                        diagnosis=transition.details,
                        on_done=_on_rec_email_done,
                    )

        return emitted
