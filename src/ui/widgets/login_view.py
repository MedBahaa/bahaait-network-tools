from PySide6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PySide6.QtCore import Qt, Signal
from utils.auth import AuthManager
from utils.i18n import _

class LoginDialog(QDialog):
    login_successful = Signal()

    def __init__(self, auth_manager: AuthManager, parent=None):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.is_register_mode = False
        
        self.setWindowTitle(_("login_title"))
        self.setFixedSize(400, 480) # Increased a bit more to fit the 3rd field comfortably
        self.setStyleSheet("""
            QDialog { background-color: #0F172A; border-radius: 12px; }
            QLabel { color: #F1F5F9; font-size: 14px; }
            QLineEdit { background-color: #1E293B; color: white; border: 1px solid #334155; border-radius: 8px; padding: 12px; font-size: 14px; }
            QLineEdit:focus { border: 1px solid #6366F1; background-color: #243045; }
            QPushButton#PrimaryButton { background-color: #6366F1; color: white; border-radius: 8px; padding: 12px; font-weight: bold; font-size: 14px; margin-top: 10px; }
            QPushButton#PrimaryButton:hover { background-color: #4F46E5; }
            QPushButton#SecondaryButton { background-color: transparent; color: #94A3B8; border: none; font-size: 13px; text-decoration: underline; margin-top: 10px; }
            QPushButton#SecondaryButton:hover { color: #F1F5F9; }
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(12)
        
        # Logo/Title
        title = QLabel("BAHAA<span style='color: #6366F1;'>IT</span>")
        title.setStyleSheet("font-size: 32px; font-weight: 900; color: #FFFFFF;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        subtitle = QLabel(_("login_subtitle"))
        subtitle.setStyleSheet("color: #94A3B8; font-size: 13px; margin-bottom: 25px;")
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)
        
        # Inputs
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText(_("login_email_placeholder"))
        layout.addWidget(self.email_input)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText(_("login_password_placeholder"))
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.returnPressed.connect(self.perform_action)
        layout.addWidget(self.password_input)
        
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

    def toggle_mode(self):
        self.is_register_mode = not self.is_register_mode
        if self.is_register_mode:
            self.confirm_password_input.setVisible(True)
            self.action_btn.setText(_("login_btn_register"))
            self.toggle_mode_btn.setText(_("login_already_have_account"))
            self.setWindowTitle(_("login_title_register"))
        else:
            self.confirm_password_input.setVisible(False)
            self.action_btn.setText(_("login_btn"))
            self.toggle_mode_btn.setText(_("login_create_account"))
            self.setWindowTitle(_("login_title"))

    def perform_action(self):
        if self.is_register_mode:
            self.attempt_register()
        else:
            self.attempt_login()

    def attempt_login(self):
        email = self.email_input.text().strip()
        pwd = self.password_input.text()
        if not email or not pwd:
            QMessageBox.warning(self, _("msg_error"), _("login_error_empty"))
            return
            
        self.action_btn.setText(_("login_logging_in"))
        self.action_btn.setEnabled(False)
        
        success, msg = self.auth_manager.login(email, pwd)
        if success:
            self.login_successful.emit()
            self.accept()
        else:
            QMessageBox.critical(self, _("login_failed"), msg)
            self.action_btn.setText(_("login_btn"))
            self.action_btn.setEnabled(True)

    def attempt_register(self):
        email = self.email_input.text().strip()
        pwd = self.password_input.text()
        pwd_confirm = self.confirm_password_input.text()
        
        if not email or not pwd or not pwd_confirm:
            QMessageBox.warning(self, _("msg_error"), _("login_error_fill_all"))
            return
            
        if pwd != pwd_confirm:
            QMessageBox.warning(self, _("msg_error"), _("login_passwords_mismatch"))
            return
            
        self.action_btn.setText(_("login_registering"))
        self.action_btn.setEnabled(False)
            
        success, msg = self.auth_manager.register(email, pwd)
        if success:
            QMessageBox.information(self, _("login_registration"), msg)
            self.toggle_mode() # Switch back to login mode after successful registration
        else:
            QMessageBox.critical(self, _("login_registration_failed"), msg)
            
        self.action_btn.setText(_("login_btn_register"))
        self.action_btn.setEnabled(True)
