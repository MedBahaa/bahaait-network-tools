from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QFrame, QCheckBox, QFileDialog, QMessageBox)
from PySide6.QtCore import Qt
import os
import webbrowser
from scapy.all import conf
from utils.cloud_sync import CloudSyncManager

class SettingsView(QWidget):
    def __init__(self, logger, alarm_manager=None, config_manager=None, auth_manager=None):
        super().__init__()
        self.logger = logger
        self.alarm_manager = alarm_manager
        self.config = config_manager
        self.auth_manager = auth_manager
        self.cloud_sync = CloudSyncManager(auth_manager) if auth_manager else None
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(30, 30, 30, 30)
        
        # Header
        header = QLabel("Global Settings")
        header.setObjectName("Title")
        self.layout.addWidget(header)
        
        # Application Settings Card
        app_card = QFrame()
        app_card.setObjectName("Card")
        app_layout = QVBoxLayout(app_card)
        sec_header1 = QLabel("Behavior & Security")
        sec_header1.setObjectName("SectionHeader")
        app_layout.addWidget(sec_header1)
        
        self.tray_checkbox = QCheckBox("Minimize to System Tray on close (Ghost Mode)")
        self.tray_checkbox.setChecked(self.config.get("minimize_to_tray", True) if self.config else True)
        self.tray_checkbox.stateChanged.connect(self.save_app_settings)
        app_layout.addWidget(self.tray_checkbox)
        
        self.ssl_checkbox = QCheckBox("Disable SSL/TLS Certificate Security (Not recommended)")
        self.ssl_checkbox.setChecked(self.config.get("disable_ssl", False) if self.config else False)
        self.ssl_checkbox.stateChanged.connect(self.save_app_settings)
        app_layout.addWidget(self.ssl_checkbox)
        
        self.autostart_checkbox = QCheckBox("Launch BahaaIT silently on Windows Startup")
        is_autostart = False
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                winreg.QueryValueEx(key, "BahaaIT_Network_Tools")
                is_autostart = True
        except FileNotFoundError:
            pass
        self.autostart_checkbox.setChecked(is_autostart)
        self.autostart_checkbox.stateChanged.connect(self.toggle_autostart)
        app_layout.addWidget(self.autostart_checkbox)
        
        # Check for updates button
        self.update_btn = QPushButton("Check for Updates")
        self.update_btn.setObjectName("SecondaryButton")
        self.update_btn.clicked.connect(self.check_updates_manually)
        app_layout.addWidget(self.update_btn)
        
        self.layout.addWidget(app_card)
        
        # Alarm Settings Card
        alarm_card = QFrame()
        alarm_card.setObjectName("Card")
        alarm_layout = QVBoxLayout(alarm_card)
        sec_header2 = QLabel("Alert Notifications")
        sec_header2.setObjectName("SectionHeader")
        alarm_layout.addWidget(sec_header2)
        
        sound_h_layout = QHBoxLayout()
        self.sound_label = QLabel("Current Sound: Default")
        saved_sound = self.config.get("alarm_sound") if self.config else None
        if saved_sound:
            self.sound_label.setText(f"Current Sound: {os.path.basename(saved_sound)}")
            
        self.set_sound_btn = QPushButton("Change Sound (.wav)")
        self.set_sound_btn.setObjectName("SecondaryButton")
        self.set_sound_btn.clicked.connect(self.select_alarm_sound)
        
        sound_h_layout.addWidget(self.sound_label)
        sound_h_layout.addStretch()
        sound_h_layout.addWidget(self.set_sound_btn)
        alarm_layout.addLayout(sound_h_layout)
        
        self.mute_checkbox = QCheckBox("Enable Audible Alarms")
        alarm_enabled = self.config.get("alarm_enabled") if self.config else True
        self.mute_checkbox.setChecked(alarm_enabled)
        self.mute_checkbox.stateChanged.connect(self.save_alarm_enabled)
        alarm_layout.addWidget(self.mute_checkbox)
        
        self.layout.addWidget(alarm_card)
        
        # Driver Status Card
        driver_frame = QFrame()
        driver_frame.setObjectName("Card")
        driver_layout = QVBoxLayout(driver_frame)
        sec_header3 = QLabel("Network Engine Status")
        sec_header3.setObjectName("SectionHeader")
        driver_layout.addWidget(sec_header3)
        
        self.status_h_layout = QHBoxLayout()
        driver_layout.addLayout(self.status_h_layout)
        
        self.check_npcap_status()
        
        self.layout.addWidget(driver_frame)
        
        # Cloud Sync Card
        sync_card = QFrame()
        sync_card.setObjectName("Card")
        sync_layout = QVBoxLayout(sync_card)
        sec_header4 = QLabel("Cloud Configuration Sync (Premium)")
        sec_header4.setObjectName("SectionHeader")
        sync_layout.addWidget(sec_header4)

        self.sync_status_label = QLabel()
        sync_layout.addWidget(self.sync_status_label)

        sync_btn_layout = QHBoxLayout()
        
        self.login_btn = QPushButton("Login to Cloud")
        self.login_btn.setObjectName("PrimaryButton")
        self.login_btn.clicked.connect(self.open_login)
        
        self.backup_btn = QPushButton("Backup to Cloud")
        self.backup_btn.setObjectName("PrimaryButton")
        self.backup_btn.clicked.connect(self.backup_to_cloud)

        self.restore_btn = QPushButton("Restore from Cloud")
        self.restore_btn.setObjectName("SecondaryButton")
        self.restore_btn.clicked.connect(self.restore_from_cloud)

        sync_btn_layout.addWidget(self.login_btn)
        sync_btn_layout.addWidget(self.backup_btn)
        sync_btn_layout.addWidget(self.restore_btn)
        sync_btn_layout.addStretch()

        sync_layout.addLayout(sync_btn_layout)
        self.layout.addWidget(sync_card)
        
        self.update_cloud_ui()
        
        self.layout.addStretch()

    def showEvent(self, event):
        super().showEvent(event)
        self.update_cloud_ui()

    def toggle_autostart(self, state):
        import winreg
        import sys
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        app_name = "BahaaIT_Network_Tools"
        executable_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(sys.argv[0])
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                if state == Qt.Checked:
                    winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, f'"{executable_path}"')
                    self.logger.info("Auto-start enabled")
                else:
                    winreg.DeleteValue(key, app_name)
                    self.logger.info("Auto-start disabled")
        except Exception as e:
            self.logger.error(f"Failed to toggle auto-start: {e}")

    def check_npcap_status(self):
        import os
        has_npcap = os.path.exists(r"C:\Windows\System32\wpcap.dll") or os.path.exists(r"C:\Windows\SysWOW64\wpcap.dll")
        
        while self.status_h_layout.count():
            child = self.status_h_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
                
        self.npcap_status_label = QLabel()
        self.npcap_status_label.setWordWrap(True)
        self.status_h_layout.addWidget(self.npcap_status_label)
        
        if has_npcap:
            self.npcap_status_label.setText("✅ <b>Npcap Driver: Installed</b><br><small style='color: #94A3B8;'>High-performance packet capture is active.</small>")
            self.npcap_status_label.setStyleSheet("color: #10B981;")
        else:
            self.npcap_status_label.setText("⚠️ <b>Npcap Driver: Missing</b><br><small style='color: #94A3B8;'>MAC detection and advanced scans may be limited.</small>")
            self.npcap_status_label.setStyleSheet("color: #F43F5E;")
            
            download_btn = QPushButton("Download Npcap")
            download_btn.setObjectName("SecondaryButton")
            download_btn.clicked.connect(lambda: webbrowser.open("https://nmap.org/npcap/"))
            self.status_h_layout.addWidget(download_btn)
            
        recheck_btn = QPushButton("Re-check Status")
        recheck_btn.setObjectName("SecondaryButton")
        recheck_btn.clicked.connect(self.check_npcap_status)
        self.status_h_layout.addWidget(recheck_btn)

    def update_cloud_ui(self):
        if self.auth_manager and self.auth_manager.is_authenticated():
            email = self.auth_manager.user.email if hasattr(self.auth_manager.user, 'email') else "User"
            self.sync_status_label.setText(f"Status: Connected as {email}")
            self.sync_status_label.setStyleSheet("color: #10B981; font-weight: bold;")
            self.login_btn.setVisible(False)
            self.backup_btn.setVisible(True)
            self.restore_btn.setVisible(True)
        else:
            self.sync_status_label.setText("Status: Offline (Not logged in)")
            self.sync_status_label.setStyleSheet("color: #F43F5E; font-weight: bold;")
            self.login_btn.setVisible(True)
            self.backup_btn.setVisible(False)
            self.restore_btn.setVisible(False)

    def open_login(self):
        from ui.widgets.login_view import LoginDialog
        dialog = LoginDialog(self.auth_manager, self)
        dialog.exec()
        self.update_cloud_ui()

    def save_app_settings(self):
        if self.config:
            self.config.set("minimize_to_tray", self.tray_checkbox.isChecked())
            self.config.set("disable_ssl", self.ssl_checkbox.isChecked())
            self.logger.info("Application settings updated")

    def save_alarm_enabled(self):
        enabled = self.mute_checkbox.isChecked()
        if self.alarm_manager:
            self.alarm_manager.set_enabled(enabled)
            if not enabled:
                self.alarm_manager.stop()
        if self.config:
            self.config.set("alarm_enabled", enabled)
        self.logger.info(f"Alarm enabled: {enabled}")

    def select_alarm_sound(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Alarm Sound", "", "Audio Files (*.wav)")
        if file_path:
            if self.alarm_manager and self.alarm_manager.set_source(file_path):
                self.sound_label.setText(f"Current Sound: {os.path.basename(file_path)}")
                if self.config:
                    self.config.set("alarm_sound", file_path)
                QMessageBox.information(self, "Success", "Alarm sound updated.")
            else:
                QMessageBox.critical(self, "Error", "Failed to load audio file.")

    def backup_to_cloud(self):
        if not self.cloud_sync:
            QMessageBox.warning(self, "Error", "Cloud Sync not available.")
            return
            
        config_data = {}
        if self.config:
            # config is a dict-like manager
            config_data = self.config.config
            
        success, msg = self.cloud_sync.backup_config(config_data)
        if success:
            QMessageBox.information(self, "Cloud Sync", msg)
        else:
            QMessageBox.critical(self, "Cloud Sync Failed", msg)

    def restore_from_cloud(self):
        if not self.cloud_sync:
            QMessageBox.warning(self, "Error", "Cloud Sync not available.")
            return
            
        success, data = self.cloud_sync.restore_config()
        if success and self.config:
            for key, val in data.items():
                self.config.set(key, val)
            QMessageBox.information(self, "Cloud Sync", "Configuration restored successfully. A restart is recommended.")
            self.logger.info("Configuration restored from cloud.")
        else:
            QMessageBox.critical(self, "Cloud Sync Failed", str(data))

    def check_updates_manually(self):
        from utils.updater import AutoUpdater
        from PySide6.QtWidgets import QApplication
        
        self.update_btn.setText("Checking...")
        self.update_btn.setEnabled(False)
        QApplication.processEvents() # Force UI update before blocking
        
        try:
            updater = AutoUpdater(self)
            updater.check_for_updates(silent=False)
        finally:
            self.update_btn.setText("Check for Updates")
            self.update_btn.setEnabled(True)
