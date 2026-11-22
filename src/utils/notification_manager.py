import threading
from typing import Callable, Optional

from utils.email_notifier import EmailNotifier


class NotificationDispatcher:
    """Independent notification channel dispatcher (Sound, Windows Tray Toast, SMTP Email)."""

    def __init__(
        self,
        alarm_manager=None,
        tray_manager=None,
        email_notifier: Optional[EmailNotifier] = None,
        config_manager=None,
        logger=None,
        sync_email: bool = False,
    ):
        self.alarm_manager = alarm_manager
        self.tray_manager = tray_manager
        self.config_manager = config_manager
        self.logger = logger
        self.sync_email = sync_email
        self.email_notifier = email_notifier or EmailNotifier(logger=logger, config_manager=config_manager)
        self._sound_timer: Optional[threading.Timer] = None
        self._sound_lock = threading.Lock()

    def dispatch_sound(
        self,
        severity: str,
        duration_sec: float = 0.0,
        sound_path: Optional[str] = None,
    ) -> bool:
        """Play severity alarm sound if AlarmManager is present. Only CRITICAL plays continuous/timed alarm."""
        if str(severity).upper() != "CRITICAL":
            return False
        if not self.alarm_manager:
            return False

        with self._sound_lock:
            if self._sound_timer is not None:
                self._sound_timer.cancel()
                self._sound_timer = None
            if sound_path:
                self.alarm_manager.set_source(sound_path)
            self.alarm_manager.play()
            if duration_sec and duration_sec > 0:
                self._sound_timer = threading.Timer(float(duration_sec), self.stop_sound)
                self._sound_timer.daemon = True
                self._sound_timer.start()
        return True

    def stop_sound(self) -> None:
        with self._sound_lock:
            if self._sound_timer is not None:
                self._sound_timer.cancel()
                self._sound_timer = None
            if self.alarm_manager:
                self.alarm_manager.stop()

    def dispatch_windows_notification(self, title: str, message: str, severity: str = "INFO") -> bool:
        if not self.tray_manager:
            return False
        try:
            if hasattr(self.tray_manager, "tray_icon") and self.tray_manager.tray_icon is not None:
                from PySide6.QtWidgets import QSystemTrayIcon
                sev = str(severity).upper()
                icon = QSystemTrayIcon.Information
                if sev == "WARNING":
                    icon = QSystemTrayIcon.Warning
                elif sev == "CRITICAL":
                    icon = QSystemTrayIcon.Critical
                self.tray_manager.tray_icon.showMessage(title, message, icon, 4000)
                return True
            if hasattr(self.tray_manager, "notify"):
                self.tray_manager.notify(title, message)
                return True
        except Exception as e:
            if self.logger:
                self.logger.error(f"Desktop notification failed: {e}")
        return False

    def dispatch_email(
        self,
        host: str,
        label: str,
        severity: str,
        status: str,
        latency: float,
        incident_start: str,
        diagnosis: str,
        on_done: Optional[Callable[[bool, str], None]] = None,
    ) -> None:
        def _worker():
            ok, err = self.email_notifier.send_alert_email(
                host=host,
                label=label,
                severity=severity,
                status=status,
                latency=latency,
                incident_start=incident_start,
                diagnosis=diagnosis,
            )
            if on_done:
                on_done(ok, err)

        if self.sync_email:
            _worker()
        else:
            t = threading.Thread(target=_worker, daemon=True)
            t.start()
