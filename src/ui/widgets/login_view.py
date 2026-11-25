from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
)
from PySide6.QtCore import Qt, Signal, QThread
from utils.auth import AuthManager
from utils.i18n import _


class _AuthWorker(QThread):
    completed = Signal(bool, str, bool)  # success, msg, is_register

    def __init__(self, auth_manager, email, password, is_register=False):
        super().__init__()
        self.auth_manager = auth_manager
        self.email = email
        self.password = password
        self.is_register = is_register

    def run(self):
        try:
            if self.is_register:
                ok, msg = self.auth_manager.register(self.email, self.password)
            else:
                ok, msg = self.auth_manager.login(self.email, self.password)
            self.completed.emit(bool(ok), str(msg or ""), self.is_register)
        except Exception as exc:
            self.completed.emit(False, str(exc), self.is_register)


class LoginDialog(QDialog):
    login_successful = Signal()

    def __init__(self, auth_manager: AuthManager, parent=None):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.is_register_mode = False
        self._worker = None

        self.setWindowTitle(_("login_title"))
        self.setMinimumSize(410, 400)
        self.setStyleSheet("""
            QDialog { background-color: #0F172A; }
            QLabel { color: #F1F5F9; font-size: 13px; background: transparent; margin: 0px; }
            QLineEdit { background-color: #1E293B; color: #F1F5F9; border: 1px solid #334155; border-radius: 8px; padding: 10px 12px; font-size: 13px; selection-background-color: #6366F1; }
            QLineEdit:focus { border: 1px solid #6366F1; background-color: #243045; }
            QLineEdit:disabled { background-color: #0B1220; color: #64748B; }
            QPushButton#PrimaryButton { background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #4F46E5, stop:1 #6366F1); color: #FFFFFF; border-radius: 10px; padding: 11px; font-weight: 700; font-size: 14px; border: none; margin-top: 8px; }
            QPushButton#PrimaryButton:hover { background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #6366F1, stop:1 #4F46E5); }
            QPushButton#PrimaryButton:disabled { background-color: #1E293B; color: #64748B; }
            QPushButton#SecondaryButton { background-color: transparent; color: #94A3B8; border: none; font-size: 13px; text-decoration: underline; margin-top: 6px; padding: 4px 8px; }
            QPushButton#SecondaryButton:hover { color: #F1F5F9; }
            QPushButton#PwdToggle { background-color: #1E293B; color: #94A3B8; border: 1px solid #334155; border-radius: 8px; padding: 6px 10px; font-size: 12px; font-weight: 600; }
            QPushButton#PwdToggle:hover { border-color: #6366F1; color: #FFFFFF; }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 32, 36, 32)
        layout.setSpacing(12)

        # Logo/Title (aligned with MainWindow brand casing)
        title = QLabel("Bahaa<span style='color: #6366F1;'>IT</span>")
        title.setStyleSheet("font-size: 30px; font-weight: 900; color: #FFFFFF;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel(_("login_subtitle"))
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #94A3B8; font-size: 13px; margin-bottom: 12px;")
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)

        # Inputs
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText(_("login_email_placeholder"))
        self.email_input.returnPressed.connect(lambda: self.password_input.setFocus())
        layout.addWidget(self.email_input)

        pwd_row = QHBoxLayout()
        pwd_row.setSpacing(6)
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText(_("login_password_placeholder"))
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.returnPressed.connect(self.perform_action)
        pwd_row.addWidget(self.password_input, 1)

        self.toggle_pwd_btn = QPushButton("Show")
        self.toggle_pwd_btn.setObjectName("PwdToggle")
        self.toggle_pwd_btn.setCheckable(True)
        self.toggle_pwd_btn.setCursor(Qt.PointingHandCursor)
        self.toggle_pwd_btn.toggled.connect(self._on_toggle_pwd)
        pwd_row.addWidget(self.toggle_pwd_btn)
        layout.addLayout(pwd_row)

        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setPlaceholderText(_("login_confirm_placeholder"))
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.returnPressed.connect(self.perform_action)
        self.confirm_password_input.setVisible(False)
        layout.addWidget(self.confirm_password_input)

        # Buttons
        self.action_btn = QPushButton(_("login_btn"))
        self.action_btn.setObjectName("PrimaryButton")
        self.action_btn.setCursor(Qt.PointingHandCursor)
        self.action_btn.clicked.connect(self.perform_action)
        layout.addWidget(self.action_btn)

        self.toggle_mode_btn = QPushButton(_("login_create_account"))
        self.toggle_mode_btn.setObjectName("SecondaryButton")
        self.toggle_mode_btn.setCursor(Qt.PointingHandCursor)
        self.toggle_mode_btn.clicked.connect(self.toggle_mode)
        layout.addWidget(self.toggle_mode_btn, alignment=Qt.AlignCenter)

        layout.addStretch()
        self.adjustSize()

    def _on_toggle_pwd(self, checked):
        mode = QLineEdit.Normal if checked else QLineEdit.Password
        self.password_input.setEchoMode(mode)
        self.confirm_password_input.setEchoMode(mode)
        self.toggle_pwd_btn.setText("Hide" if checked else "Show")

    def toggle_mode(self):
        self.is_register_mode = not self.is_register_mode
        if self.is_register_mode:
            self.confirm_password_input.setVisible(True)
            self.action_btn.setText(_("login_btn_register"))
            self.toggle_mode_btn.setText(_("login_already_have_account"))
            self.setWindowTitle(_("login_title_register"))
        else:
            self.confirm_password_input.clear()
            self.confirm_password_input.setVisible(False)
            self.action_btn.setText(_("login_btn"))
            self.toggle_mode_btn.setText(_("login_create_account"))
            self.setWindowTitle(_("login_title"))
        self.adjustSize()

    def perform_action(self):
        if self._worker and self._worker.isRunning():
            return
        if self.is_register_mode:
            self.attempt_register()
        else:
            self.attempt_login()

    def _set_busy(self, busy: bool, label: str = None):
        self.email_input.setEnabled(not busy)
        self.password_input.setEnabled(not busy)
        self.confirm_password_input.setEnabled(not busy)
        self.toggle_mode_btn.setEnabled(not busy)
        self.action_btn.setEnabled(not busy)
        if label is not None:
            self.action_btn.setText(label)

    def attempt_login(self):
        if not self.auth_manager:
            QMessageBox.critical(self, _("login_failed"), _("settings_sync_unavailable", "Cloud Sync not available."))
            return
        email = self.email_input.text().strip()
        pwd = self.password_input.text()
        if not email or not pwd:
            QMessageBox.warning(self, _("msg_error"), _("login_error_empty"))
            return

        self._set_busy(True, _("login_logging_in"))
        self._worker = _AuthWorker(self.auth_manager, email, pwd, is_register=False)
        self._worker.completed.connect(self._on_auth_completed)
        self._worker.start()

    def attempt_register(self):
        if not self.auth_manager:
            QMessageBox.critical(self, _("login_registration_failed"), _("settings_sync_unavailable", "Cloud Sync not available."))
            return
        email = self.email_input.text().strip()
        pwd = self.password_input.text()
        pwd_confirm = self.confirm_password_input.text()

        if not email or not pwd or not pwd_confirm:
            QMessageBox.warning(self, _("msg_error"), _("login_error_fill_all"))
            return

        if pwd != pwd_confirm:
            QMessageBox.warning(self, _("msg_error"), _("login_passwords_mismatch"))
            return

        self._set_busy(True, _("login_registering"))
        self._worker = _AuthWorker(self.auth_manager, email, pwd, is_register=True)
        self._worker.completed.connect(self._on_auth_completed)
        self._worker.start()

    def _on_auth_completed(self, success: bool, msg: str, is_register: bool):
        w = self._worker
        self._worker = None
        if w is not None:
            w.deleteLater()

        if is_register:
            self._set_busy(False)
            if success:
                QMessageBox.information(self, _("login_registration"), msg)
                if self.is_register_mode:
                    self.toggle_mode()
            else:
                QMessageBox.critical(self, _("login_registration_failed"), msg)
                self.action_btn.setText(_("login_btn_register"))
        else:
            if success:
                self._set_busy(False)
                self.login_successful.emit()
                self.accept()
            else:
                self._set_busy(False, _("login_btn"))
                QMessageBox.critical(self, _("login_failed"), msg)

    def closeEvent(self, event):
        if self._worker and self._worker.isRunning():
            self._worker.wait(1500)
        super().closeEvent(event)
