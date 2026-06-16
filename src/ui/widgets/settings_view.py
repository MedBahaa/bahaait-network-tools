from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QFrame, QCheckBox, QFileDialog, QMessageBox)
from PySide6.QtCore import Qt
import os
import webbrowser
from utils.cloud_sync import CloudSyncManager

class SettingsView(QWidget):
    def __init__(self, logger, alarm_manager=None, config_manager=None, auth_manager=None):
        super().__init__()
        self.logger = logger
        self.alarm_manager = alarm_manager
        self.config = config_manager
        self.auth_manager = auth_manager
        self.cloud_sync = CloudSyncManager(auth_manager) if auth_manager else None
        
        # Main layout
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(30, 30, 30, 30)
        self.main_layout.setSpacing(20)
        
        # Header
        header = QLabel("Global Settings")
        header.setObjectName("Title")
        self.main_layout.addWidget(header)
        
        # Columns Layout
        columns_layout = QHBoxLayout()
        columns_layout.setSpacing(25)
        self.main_layout.addLayout(columns_layout)
        
        # Left Column Layout
        left_col = QVBoxLayout()
        left_col.setSpacing(20)
        columns_layout.addLayout(left_col, 1)
        
        # Right Column Layout
        right_col = QVBoxLayout()
        right_col.setSpacing(20)
        columns_layout.addLayout(right_col, 1)

        # ----------------------------------------------------
        # LEFT COLUMN CARDS
        # ----------------------------------------------------
        
        # 1. Behavior & Security Card
        app_card = QFrame()
        app_card.setObjectName("Card")
        app_layout = QVBoxLayout(app_card)
        app_layout.setContentsMargins(22, 22, 22, 22)
        app_layout.setSpacing(15)
        
        sec_header1 = QLabel("Behavior & Security")
        sec_header1.setObjectName("SectionHeader")
        app_layout.addWidget(sec_header1)
        
        self.tray_checkbox = QCheckBox("Minimize to System Tray on close (Ghost Mode)")
        self.tray_checkbox.setChecked(self.config.get("minimize_to_tray", False) if self.config else False)
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
        
        # Separator line
        sep1 = QFrame()
        sep1.setFrameShape(QFrame.HLine)
        sep1.setStyleSheet("background-color: rgba(255, 255, 255, 0.05); min-height: 1px; max-height: 1px; border: none; margin-top: 5px;")
        app_layout.addWidget(sep1)
        
        # Check for updates button
        self.update_btn = QPushButton("Check for Updates")
        self.update_btn.setObjectName("SecondaryButton")
        self.update_btn.clicked.connect(self.check_updates_manually)
        app_layout.addWidget(self.update_btn)
        
        left_col.addWidget(app_card)
        
        # 2. Alert Notifications Card
        alarm_card = QFrame()
        alarm_card.setObjectName("Card")
        alarm_layout = QVBoxLayout(alarm_card)
        alarm_layout.setContentsMargins(22, 22, 22, 22)
        alarm_layout.setSpacing(15)
        
        sec_header2 = QLabel("Alert Notifications")
        sec_header2.setObjectName("SectionHeader")
        alarm_layout.addWidget(sec_header2)
        
        self.mute_checkbox = QCheckBox("Enable Audible Alarms")
        alarm_enabled = self.config.get("alarm_enabled") if self.config else True
        self.mute_checkbox.setChecked(alarm_enabled)
        self.mute_checkbox.stateChanged.connect(self.save_alarm_enabled)
        alarm_layout.addWidget(self.mute_checkbox)
        
        # Horizontal sound info layout
        sound_h_layout = QHBoxLayout()
        sound_h_layout.setSpacing(15)
        
        self.sound_label = QLabel("Current Sound: Default")
        saved_sound = self.config.get("alarm_sound") if self.config else None
        if saved_sound:
            self.sound_label.setText(f"Current Sound: {os.path.basename(saved_sound)}")
        self.sound_label.setWordWrap(True)
        self.sound_label.setStyleSheet("color: #94A3B8; font-size: 12px;")
            
        self.set_sound_btn = QPushButton("Change Sound (.wav)")
        self.set_sound_btn.setObjectName("SecondaryButton")
        self.set_sound_btn.clicked.connect(self.select_alarm_sound)
        
        sound_h_layout.addWidget(self.sound_label, 1)
        sound_h_layout.addWidget(self.set_sound_btn)
        alarm_layout.addLayout(sound_h_layout)
        
        left_col.addWidget(alarm_card)
        left_col.addStretch()

        # ----------------------------------------------------
        # RIGHT COLUMN CARDS
        # ----------------------------------------------------
        
        # 3. Network Engine Status Card
        driver_frame = QFrame()
        driver_frame.setObjectName("Card")
        driver_layout = QVBoxLayout(driver_frame)
        driver_layout.setContentsMargins(22, 22, 22, 22)
        driver_layout.setSpacing(15)
        
        sec_header3 = QLabel("Network Engine Status")
        sec_header3.setObjectName("SectionHeader")
        driver_layout.addWidget(sec_header3)
        
        self.status_h_layout = QHBoxLayout()
        self.status_h_layout.setSpacing(15)
        driver_layout.addLayout(self.status_h_layout)
        
        self.check_npcap_status()
        right_col.addWidget(driver_frame)
        
        # 4. Storage & Maintenance Card
        maint_card = QFrame()
        maint_card.setObjectName("Card")
        maint_layout = QVBoxLayout(maint_card)
        maint_layout.setContentsMargins(22, 22, 22, 22)
        maint_layout.setSpacing(15)
        
        sec_header5 = QLabel("Storage & Maintenance")
        sec_header5.setObjectName("SectionHeader")
        maint_layout.addWidget(sec_header5)

        maint_desc = QLabel("Manage your local application data files (logs and database).")
        maint_desc.setStyleSheet("color: #94A3B8; font-size: 12px;")
        maint_layout.addWidget(maint_desc)

        maint_btn_layout = QHBoxLayout()
        maint_btn_layout.setSpacing(10)
        
        self.open_db_btn = QPushButton("Open DB Folder")
        self.open_db_btn.setObjectName("SecondaryButton")
        self.open_db_btn.clicked.connect(self.open_db_folder)
        
        self.open_logs_btn = QPushButton("Open Logs Folder")
        self.open_logs_btn.setObjectName("SecondaryButton")
        self.open_logs_btn.clicked.connect(self.open_logs_folder)
        
        maint_btn_layout.addWidget(self.open_db_btn)
        maint_btn_layout.addWidget(self.open_logs_btn)
        maint_btn_layout.addStretch()
        maint_layout.addLayout(maint_btn_layout)
        right_col.addWidget(maint_card)
        
        # 5. Cloud Sync Card
        sync_card = QFrame()
        sync_card.setObjectName("Card")
        sync_layout = QVBoxLayout(sync_card)
        sync_layout.setContentsMargins(22, 22, 22, 22)
        sync_layout.setSpacing(15)
        
        sec_header4 = QLabel("Cloud Configuration Sync (Premium)")
        sec_header4.setObjectName("SectionHeader")
        sync_layout.addWidget(sec_header4)

        self.sync_status_label = QLabel()
        self.sync_status_label.setStyleSheet("font-size: 13px;")
        sync_layout.addWidget(self.sync_status_label)

        sync_btn_layout = QHBoxLayout()
        sync_btn_layout.setSpacing(10)
        
        self.login_btn = QPushButton("Login / Create Account")
        self.login_btn.setObjectName("PrimaryButton")
        self.login_btn.clicked.connect(self.open_login)
        
        self.backup_btn = QPushButton("Backup to Cloud")
        self.backup_btn.setObjectName("PrimaryButton")
        self.backup_btn.clicked.connect(self.backup_to_cloud)

        self.restore_btn = QPushButton("Restore from Cloud")
        self.restore_btn.setObjectName("SecondaryButton")
        self.restore_btn.clicked.connect(self.restore_from_cloud)

        self.logout_btn = QPushButton("Logout")
        self.logout_btn.setObjectName("DangerButton")
        self.logout_btn.clicked.connect(self.logout)

        sync_btn_layout.addWidget(self.login_btn)
        sync_btn_layout.addWidget(self.backup_btn)
        sync_btn_layout.addWidget(self.restore_btn)
        sync_btn_layout.addWidget(self.logout_btn)
        sync_btn_layout.addStretch()

        sync_layout.addLayout(sync_btn_layout)
        right_col.addWidget(sync_card)
        
        self.update_cloud_ui()
        right_col.addStretch()

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
        
        if has_npcap:
            self.npcap_status_label.setText("✅ <b>Npcap Driver: Installed</b><br><small style='color: #94A3B8;'>High-performance packet capture is active.</small>")
            self.npcap_status_label.setStyleSheet("color: #10B981; font-size: 13px;")
        else:
            self.npcap_status_label.setText("⚠️ <b>Npcap Driver: Missing</b><br><small style='color: #94A3B8;'>MAC detection and advanced scans may be limited.</small>")
            self.npcap_status_label.setStyleSheet("color: #F43F5E; font-size: 13px;")
            
        self.status_h_layout.addWidget(self.npcap_status_label, 1)
        
        btn_v_layout = QVBoxLayout()
        btn_v_layout.setSpacing(5)
        
        if not has_npcap:
            download_btn = QPushButton("Download Npcap")
            download_btn.setObjectName("SecondaryButton")
            download_btn.clicked.connect(lambda: webbrowser.open("https://nmap.org/npcap/"))
            btn_v_layout.addWidget(download_btn)
            
        recheck_btn = QPushButton("Re-check Status")
        recheck_btn.setObjectName("SecondaryButton")
        recheck_btn.clicked.connect(self.check_npcap_status)
        btn_v_layout.addWidget(recheck_btn)
        
        self.status_h_layout.addLayout(btn_v_layout)

    def update_cloud_ui(self):
        if self.auth_manager and self.auth_manager.is_authenticated():
            email = self.auth_manager.user.email if hasattr(self.auth_manager.user, 'email') else "User"
            self.sync_status_label.setText(f"Status: Connected as {email}")
            self.sync_status_label.setStyleSheet("color: #10B981; font-weight: bold;")
            self.login_btn.setVisible(False)
            self.backup_btn.setVisible(True)
            self.restore_btn.setVisible(True)
            self.logout_btn.setVisible(True)
        else:
            self.sync_status_label.setText("Status: Offline (Not logged in)")
            self.sync_status_label.setStyleSheet("color: #F43F5E; font-weight: bold;")
            self.login_btn.setVisible(True)
            self.backup_btn.setVisible(False)
            self.restore_btn.setVisible(False)
            self.logout_btn.setVisible(False)

    def open_login(self):
        from ui.widgets.login_view import LoginDialog
        dialog = LoginDialog(self.auth_manager, self)
        dialog.exec()
        self.update_cloud_ui()

    def logout(self):
        if self.auth_manager:
            self.auth_manager.logout()
            self.update_cloud_ui()
            QMessageBox.information(self, "Logout", "You have been logged out successfully.")

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
        
        self.update_btn.setText("Checking...")
        self.update_btn.setEnabled(False)
        
        self.updater = AutoUpdater(self)
        self.updater.finished.connect(self.on_update_check_finished)
        self.updater.check_for_updates(silent=False)

    def on_update_check_finished(self):
        self.update_btn.setText("Check for Updates")
        self.update_btn.setEnabled(True)

    def open_db_folder(self):
        import subprocess
        app_data = os.environ.get('LOCALAPPDATA', os.path.expanduser('~'))
        base_dir = os.path.join(app_data, 'BahaaIT')
        if os.path.exists(base_dir):
            if os.name == 'nt':
                os.startfile(base_dir)
            else:
                subprocess.Popen(['xdg-open', base_dir])

    def open_logs_folder(self):
        import subprocess
        app_data = os.environ.get('LOCALAPPDATA', os.path.expanduser('~'))
        log_dir = os.path.join(app_data, 'BahaaIT', 'logs')
        if os.path.exists(log_dir):
            if os.name == 'nt':
                os.startfile(log_dir)
            else:
                subprocess.Popen(['xdg-open', log_dir])
