from PySide6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PySide6.QtCore import Qt, Signal
from utils.auth import AuthManager

class LoginDialog(QDialog):
    login_successful = Signal()

    def __init__(self, auth_manager: AuthManager, parent=None):
        super().__init__(parent)
        self.auth_manager = auth_manager
        
        self.setWindowTitle("BahaaIT Network Tools - Login")
        self.setFixedSize(400, 350)
        self.setStyleSheet("""
            QDialog { background-color: #0F172A; border-radius: 12px; }
            QLabel { color: #F1F5F9; font-size: 14px; }
            QLineEdit { background-color: #1E293B; color: white; border: 1px solid #334155; border-radius: 8px; padding: 10px; font-size: 14px; }
            QLineEdit:focus { border: 1px solid #6366F1; }
            QPushButton#PrimaryButton { background-color: #6366F1; color: white; border-radius: 8px; padding: 10px; font-weight: bold; font-size: 14px; }
            QPushButton#PrimaryButton:hover { background-color: #4F46E5; }
            QPushButton#SecondaryButton { background-color: transparent; color: #94A3B8; border: none; text-decoration: underline; }
            QPushButton#SecondaryButton:hover { color: #F1F5F9; }
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 40, 30, 40)
        layout.setSpacing(20)
        
        # Logo/Title
        title = QLabel("BAHAA<span style='color: #6366F1;'>IT</span>")
        title.setStyleSheet("font-size: 28px; font-weight: 900; color: #FFFFFF;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        subtitle = QLabel("Premium Network Toolkit")
        subtitle.setStyleSheet("color: #94A3B8; font-size: 12px;")
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)
        
        # Inputs
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Email Address")
        layout.addWidget(self.email_input)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.returnPressed.connect(self.attempt_login)
        layout.addWidget(self.password_input)
        
        # Buttons
        self.login_btn = QPushButton("LOGIN")
        self.login_btn.setObjectName("PrimaryButton")
        self.login_btn.clicked.connect(self.attempt_login)
        layout.addWidget(self.login_btn)
        
        self.register_btn = QPushButton("Create an account")
        self.register_btn.setObjectName("SecondaryButton")
        self.register_btn.clicked.connect(self.attempt_register)
        layout.addWidget(self.register_btn, alignment=Qt.AlignCenter)

    def attempt_login(self):
        email = self.email_input.text().strip()
        pwd = self.password_input.text()
        if not email or not pwd:
            QMessageBox.warning(self, "Error", "Please enter email and password.")
            return
            
        self.login_btn.setText("Logging in...")
        self.login_btn.setEnabled(False)
        
        success, msg = self.auth_manager.login(email, pwd)
        if success:
            self.login_successful.emit()
            self.accept()
        else:
            QMessageBox.critical(self, "Login Failed", msg)
            self.login_btn.setText("LOGIN")
            self.login_btn.setEnabled(True)

    def attempt_register(self):
        email = self.email_input.text().strip()
        pwd = self.password_input.text()
        if not email or not pwd:
            QMessageBox.warning(self, "Error", "Please enter email and password.")
            return
            
        success, msg = self.auth_manager.register(email, pwd)
        if success:
            QMessageBox.information(self, "Registration", msg)
        else:
            QMessageBox.critical(self, "Registration Failed", msg)
