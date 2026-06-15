from PySide6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PySide6.QtCore import Qt, Signal
from utils.auth import AuthManager

class LoginDialog(QDialog):
    login_successful = Signal()

    def __init__(self, auth_manager: AuthManager, parent=None):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.is_register_mode = False
        
        self.setWindowTitle("BahaaIT Network Tools - Login")
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
        
        subtitle = QLabel("Premium Network Toolkit")
        subtitle.setStyleSheet("color: #94A3B8; font-size: 13px; margin-bottom: 25px;")
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)
        
        # Inputs
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Email Address")
        layout.addWidget(self.email_input)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.returnPressed.connect(self.perform_action)
        layout.addWidget(self.password_input)
        
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setPlaceholderText("Confirm Password")
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.returnPressed.connect(self.perform_action)
        self.confirm_password_input.setVisible(False)
        layout.addWidget(self.confirm_password_input)
        
        # Buttons
        self.action_btn = QPushButton("LOGIN")
        self.action_btn.setObjectName("PrimaryButton")
        self.action_btn.setCursor(Qt.PointingHandCursor)
        self.action_btn.clicked.connect(self.perform_action)
        layout.addWidget(self.action_btn)
        
        self.toggle_mode_btn = QPushButton("Create an account")
        self.toggle_mode_btn.setObjectName("SecondaryButton")
        self.toggle_mode_btn.setCursor(Qt.PointingHandCursor)
        self.toggle_mode_btn.clicked.connect(self.toggle_mode)
        layout.addWidget(self.toggle_mode_btn, alignment=Qt.AlignCenter)
        
        layout.addStretch()

    def toggle_mode(self):
        self.is_register_mode = not self.is_register_mode
        if self.is_register_mode:
            self.confirm_password_input.setVisible(True)
            self.action_btn.setText("CREATE ACCOUNT")
            self.toggle_mode_btn.setText("Already have an account? Login")
            self.setWindowTitle("BahaaIT Network Tools - Register")
        else:
            self.confirm_password_input.setVisible(False)
            self.action_btn.setText("LOGIN")
            self.toggle_mode_btn.setText("Create an account")
            self.setWindowTitle("BahaaIT Network Tools - Login")

    def perform_action(self):
        if self.is_register_mode:
            self.attempt_register()
        else:
            self.attempt_login()

    def attempt_login(self):
        email = self.email_input.text().strip()
        pwd = self.password_input.text()
        if not email or not pwd:
            QMessageBox.warning(self, "Error", "Please enter email and password.")
            return
            
        self.action_btn.setText("Logging in...")
        self.action_btn.setEnabled(False)
        
        success, msg = self.auth_manager.login(email, pwd)
        if success:
            self.login_successful.emit()
            self.accept()
        else:
            QMessageBox.critical(self, "Login Failed", msg)
            self.action_btn.setText("LOGIN")
            self.action_btn.setEnabled(True)

    def attempt_register(self):
        email = self.email_input.text().strip()
        pwd = self.password_input.text()
        pwd_confirm = self.confirm_password_input.text()
        
        if not email or not pwd or not pwd_confirm:
            QMessageBox.warning(self, "Error", "Please fill in all fields.")
            return
            
        if pwd != pwd_confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match!")
            return
            
        self.action_btn.setText("Registering...")
        self.action_btn.setEnabled(False)
            
        success, msg = self.auth_manager.register(email, pwd)
        if success:
            QMessageBox.information(self, "Registration", msg)
            self.toggle_mode() # Switch back to login mode after successful registration
        else:
            QMessageBox.critical(self, "Registration Failed", msg)
            
        self.action_btn.setText("CREATE ACCOUNT")
        self.action_btn.setEnabled(True)
