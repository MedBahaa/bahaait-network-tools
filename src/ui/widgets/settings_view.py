from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QFrame, QCheckBox, QFileDialog, QMessageBox, QComboBox, QScrollArea, QLineEdit, QGridLayout, QTabWidget, QSpinBox)
from PySide6.QtCore import Qt, QTimer
import os
import webbrowser
import json
from utils.cloud_sync import CloudSyncManager
from utils.i18n import _
from utils.db import DatabaseManager, Host

class SettingsView(QWidget):
    def __init__(self, logger, alarm_manager=None, config_manager=None, auth_manager=None):
        super().__init__()
        self.logger = logger
        self.alarm_manager = alarm_manager
        self.config = config_manager
        self.auth_manager = auth_manager
        self.cloud_sync = CloudSyncManager(auth_manager) if auth_manager else None
        self.db = DatabaseManager()
        
        # Audio test states
        self.is_testing_sound = False
        self.test_sound_timer = QTimer(self)
        self.test_sound_timer.setSingleShot(True)
        self.test_sound_timer.timeout.connect(self.stop_sound_test)
        
        # Main layout
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(30, 30, 30, 30)
        self.main_layout.setSpacing(20)
        
        # Header
        header = QLabel(_("settings_title", "Global Settings"))
        header.setObjectName("Title")
        self.main_layout.addWidget(header)
        
        # Create Tab Widget
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)
        
        # Helper function to create scrollable tab content
        def create_tab(title_key, default_title):
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QFrame.NoFrame)
            scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            scroll.setStyleSheet("background: transparent;")
            
            content_widget = QWidget()
            content_widget.setStyleSheet("background: transparent;")
            layout = QVBoxLayout(content_widget)
            layout.setContentsMargins(0, 10, 10, 10)
            layout.setSpacing(20)
            
            scroll.setWidget(content_widget)
            self.tabs.addTab(scroll, _(title_key, default_title))
            return layout
            
        tab1_layout = create_tab("settings_tab_general", "General")
        tab2_layout = create_tab("settings_tab_alerts", "Alerts (Sound & Email)")
        tab3_layout = create_tab("settings_tab_network", "Network Engine")
        tab4_layout = create_tab("settings_tab_cloud", "Backup, Sync & Storage")

        # ----------------------------------------------------
        # LEFT COLUMN CARDS
        # ----------------------------------------------------
        
        # 1. Behavior & Security Card
        app_card = QFrame()
        app_card.setObjectName("Card")
        app_layout = QVBoxLayout(app_card)
        app_layout.setContentsMargins(22, 22, 22, 22)
        app_layout.setSpacing(15)
        
        sec_header1 = QLabel(_("settings_behavior", "Behavior & Security"))
        sec_header1.setObjectName("SectionHeader")
        app_layout.addWidget(sec_header1)
        
        self.tray_checkbox = QCheckBox(_("settings_minimize", "Minimize to System Tray on close (Ghost Mode)"))
        self.tray_checkbox.setCursor(Qt.PointingHandCursor)
        self.tray_checkbox.setChecked(self.config.get("minimize_to_tray", False) if self.config else False)
        self.tray_checkbox.stateChanged.connect(self.save_app_settings)
        app_layout.addWidget(self.tray_checkbox)
        
        self.ssl_checkbox = QCheckBox(_("settings_ssl", "Disable SSL/TLS Certificate Security (Not recommended)"))
        self.ssl_checkbox.setCursor(Qt.PointingHandCursor)
        self.ssl_checkbox.setChecked(self.config.get("disable_ssl", False) if self.config else False)
        self.ssl_checkbox.stateChanged.connect(self.save_app_settings)
        app_layout.addWidget(self.ssl_checkbox)
        
        self.autostart_checkbox = QCheckBox(_("settings_autostart", "Launch BahaaIT silently on Windows Startup"))
        self.autostart_checkbox.setCursor(Qt.PointingHandCursor)
        is_autostart = False
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                winreg.QueryValueEx(key, "BahaaIT_Network_Tools")
                is_autostart = True
        except FileNotFoundError:
            pass
        except Exception:
            pass
        self.autostart_checkbox.setChecked(is_autostart)
        self.autostart_checkbox.stateChanged.connect(self.toggle_autostart)
        app_layout.addWidget(self.autostart_checkbox)
        
        # Separator line
        sep1 = QFrame()
        sep1.setFrameShape(QFrame.HLine)
        sep1.setStyleSheet("background-color: rgba(255, 255, 255, 0.05); min-height: 1px; max-height: 1px; border: none; margin-top: 5px;")
        app_layout.addWidget(sep1)
        
        # Language Selector
        lang_h_layout = QHBoxLayout()
        lang_h_layout.setSpacing(15)
        self.lang_label = QLabel(_("settings_language_label", "Select UI Language:"))
        self.lang_label.setStyleSheet("color: #E2E8F0; font-size: 13px;")
        self.lang_combo = QComboBox()
        self.lang_combo.setCursor(Qt.PointingHandCursor)
        self.lang_combo.addItem("Français", "fr")
        self.lang_combo.addItem("English", "en")
        
        current_lang = self.config.get("language", "fr") if self.config else "fr"
        idx = self.lang_combo.findData(current_lang)
        if idx >= 0:
            self.lang_combo.setCurrentIndex(idx)
        self.lang_combo.currentIndexChanged.connect(self.change_language)
        
        lang_h_layout.addWidget(self.lang_label)
        lang_h_layout.addWidget(self.lang_combo, 1)
        app_layout.addLayout(lang_h_layout)
        
        # Separator line 2
        sep_lang = QFrame()
        sep_lang.setFrameShape(QFrame.HLine)
        sep_lang.setStyleSheet("background-color: rgba(255, 255, 255, 0.05); min-height: 1px; max-height: 1px; border: none; margin-top: 5px;")
        app_layout.addWidget(sep_lang)
        
        # Check for updates button
        self.update_btn = QPushButton(_("settings_check_update", "Check for Updates"))
        self.update_btn.setObjectName("SecondaryButton")
        self.update_btn.setCursor(Qt.PointingHandCursor)
        self.update_btn.clicked.connect(self.check_updates_manually)
        app_layout.addWidget(self.update_btn)
        
        tab1_layout.addWidget(app_card)
        tab1_layout.addStretch()
        
        # 1b. Backup & Restore Card
        backup_card = QFrame()
        backup_card.setObjectName("Card")
        backup_layout = QVBoxLayout(backup_card)
        backup_layout.setContentsMargins(22, 22, 22, 22)
        backup_layout.setSpacing(15)
        
        backup_header = QLabel(_("settings_backup_title", "Backup & Restore"))
        backup_header.setObjectName("SectionHeader")
        backup_layout.addWidget(backup_header)
        
        backup_desc = QLabel(_("settings_backup_desc", "Export or import your monitored hosts, custom sites, and general preferences."))
        backup_desc.setWordWrap(True)
        backup_desc.setStyleSheet("color: #94A3B8; font-size: 12px;")
        backup_layout.addWidget(backup_desc)
        
        backup_btn_layout = QHBoxLayout()
        backup_btn_layout.setSpacing(10)
        
        self.export_btn = QPushButton(_("settings_backup_export_btn", "Export Backup"))
        self.export_btn.setObjectName("SecondaryButton")
        self.export_btn.setCursor(Qt.PointingHandCursor)
        self.export_btn.clicked.connect(self.export_backup_data)
        backup_btn_layout.addWidget(self.export_btn)
        
        self.import_btn = QPushButton(_("settings_backup_import_btn", "Import Backup"))
        self.import_btn.setObjectName("SecondaryButton")
        self.import_btn.setCursor(Qt.PointingHandCursor)
        self.import_btn.clicked.connect(self.import_backup_data)
        backup_btn_layout.addWidget(self.import_btn)
        backup_btn_layout.addStretch()
        
        backup_layout.addLayout(backup_btn_layout)
        
        tab4_layout.addWidget(backup_card)
        
        # 2. Alert Notifications Card
        alarm_card = QFrame()
        alarm_card.setObjectName("Card")
        alarm_layout = QVBoxLayout(alarm_card)
        alarm_layout.setContentsMargins(22, 22, 22, 22)
        alarm_layout.setSpacing(15)
        
        sec_header2 = QLabel(_("settings_alarm", "Alert Notifications"))
        sec_header2.setObjectName("SectionHeader")
        alarm_layout.addWidget(sec_header2)
        
        self.mute_checkbox = QCheckBox(_("settings_alarm_enable", "Enable audio alarm for Down hosts"))
        self.mute_checkbox.setCursor(Qt.PointingHandCursor)
        alarm_enabled = self.config.get("alarm_enabled") if self.config else True
        self.mute_checkbox.setChecked(alarm_enabled)
        self.mute_checkbox.stateChanged.connect(self.save_alarm_enabled)
        alarm_layout.addWidget(self.mute_checkbox)
        
        # Sound file indicator
        self.sound_label = QLabel(_("settings_alarm_sound", "Custom Alarm Sound (.wav)") + ": Default")
        saved_sound = self.config.get("alarm_sound") if self.config else None
        if saved_sound:
            self.sound_label.setText(f"{_('settings_alarm_sound', 'Custom Alarm Sound (.wav)')}: {os.path.basename(saved_sound)}")
        self.sound_label.setWordWrap(True)
        self.sound_label.setStyleSheet("color: #94A3B8; font-size: 12px; margin-top: 5px;")
        alarm_layout.addWidget(self.sound_label)
        
        # Audio action buttons layout
        audio_btn_layout = QHBoxLayout()
        audio_btn_layout.setSpacing(10)
            
        self.set_sound_btn = QPushButton(_("settings_alarm_choose", "Choose sound"))
        self.set_sound_btn.setObjectName("SecondaryButton")
        self.set_sound_btn.setCursor(Qt.PointingHandCursor)
        self.set_sound_btn.clicked.connect(self.select_alarm_sound)
        audio_btn_layout.addWidget(self.set_sound_btn)
        
        self.test_sound_btn = QPushButton(_("settings_alarm_play", "Test sound"))
        self.test_sound_btn.setObjectName("SecondaryButton")
        self.test_sound_btn.setCursor(Qt.PointingHandCursor)
        self.test_sound_btn.clicked.connect(self.toggle_test_sound)
        audio_btn_layout.addWidget(self.test_sound_btn)
        audio_btn_layout.addStretch()
        
        alarm_layout.addLayout(audio_btn_layout)
        
        tab2_layout.addWidget(alarm_card)
        
        # 2b. Email Alert Settings Card
        email_card = QFrame()
        email_card.setObjectName("Card")
        email_layout = QVBoxLayout(email_card)
        email_layout.setContentsMargins(22, 22, 22, 22)
        email_layout.setSpacing(15)
        
        email_header = QLabel(_("settings_email_alerts", "Email Alert Settings"))
        email_header.setObjectName("SectionHeader")
        email_layout.addWidget(email_header)
        
        self.email_checkbox = QCheckBox(_("settings_email_enable", "Enable Email Alerts"))
        self.email_checkbox.setCursor(Qt.PointingHandCursor)
        email_enabled = self.config.get("email_alerts_enabled") if self.config else False
        self.email_checkbox.setChecked(email_enabled)
        email_layout.addWidget(self.email_checkbox)
        
        # Filters layout (indented/spaced under the main checkbox)
        filters_layout = QVBoxLayout()
        filters_layout.setContentsMargins(25, 0, 0, 0)
        filters_layout.setSpacing(10)

        self.email_on_down_checkbox = QCheckBox(_("settings_email_on_down", "Alert when a device goes DOWN"))
        self.email_on_down_checkbox.setCursor(Qt.PointingHandCursor)
        email_on_down_enabled = self.config.get("email_alert_on_down", True) if self.config else True
        self.email_on_down_checkbox.setChecked(email_on_down_enabled)
        filters_layout.addWidget(self.email_on_down_checkbox)

        self.email_on_up_checkbox = QCheckBox(_("settings_email_on_up", "Alert when a device goes UP (Recovery)"))
        self.email_on_up_checkbox.setCursor(Qt.PointingHandCursor)
        email_on_up_enabled = self.config.get("email_alert_on_up", True) if self.config else True
        self.email_on_up_checkbox.setChecked(email_on_up_enabled)
        filters_layout.addWidget(self.email_on_up_checkbox)

        # Consecutive Failures setting (indented under DOWN checkbox)
        consecutive_layout = QHBoxLayout()
        consecutive_layout.setContentsMargins(20, 0, 0, 0)
        consecutive_layout.setSpacing(10)
        self.consecutive_label = QLabel(_("settings_email_consecutive", "Notify DOWN after:"))
        self.consecutive_label.setStyleSheet("color: #E2E8F0; font-size: 13px;")
        
        self.consecutive_input = QLineEdit()
        self.consecutive_input.setFixedWidth(60)
        from PySide6.QtGui import QIntValidator
        self.consecutive_input.setValidator(QIntValidator(1, 999))
        threshold_val = self.config.get("email_consecutive_down_threshold", 1) if self.config else 1
        self.consecutive_input.setText(str(threshold_val))
        
        self.consecutive_suffix = QLabel(_("settings_email_checks_suffix", "timeout"))
        self.consecutive_suffix.setStyleSheet("color: #E2E8F0; font-size: 13px;")
        
        consecutive_layout.addWidget(self.consecutive_label)
        consecutive_layout.addWidget(self.consecutive_input)
        consecutive_layout.addWidget(self.consecutive_suffix)
        consecutive_layout.addStretch()
        filters_layout.addLayout(consecutive_layout)

        email_layout.addLayout(filters_layout)
        
        # SMTP Type Selector
        type_layout = QHBoxLayout()
        type_layout.setSpacing(15)
        smtp_type_label = QLabel(_("settings_email_smtp_type", "SMTP Server Configuration:"))
        smtp_type_label.setStyleSheet("color: #E2E8F0; font-size: 13px;")
        
        self.smtp_type_combo = QComboBox()
        self.smtp_type_combo.setCursor(Qt.PointingHandCursor)
        self.smtp_type_combo.addItem(_("settings_email_smtp_type_default", "Default (BahaaIT Server)"), "default")
        self.smtp_type_combo.addItem(_("settings_email_smtp_type_custom", "Custom SMTP Server"), "custom")
        
        use_custom_saved = self.config.get("email_use_custom_smtp", False) if self.config else False
        self.smtp_type_combo.setCurrentIndex(1 if use_custom_saved else 0)
        
        type_layout.addWidget(smtp_type_label)
        type_layout.addWidget(self.smtp_type_combo, 1)
        email_layout.addLayout(type_layout)
        
        # Main form master container (recipient + custom SMTP)
        form_master = QWidget()
        form_master_layout = QVBoxLayout(form_master)
        form_master_layout.setContentsMargins(0, 0, 0, 0)
        form_master_layout.setSpacing(15)
        
        # 1. Recipient Email Field
        recipient_container = QWidget()
        recipient_layout = QVBoxLayout(recipient_container)
        recipient_layout.setContentsMargins(0, 0, 0, 0)
        recipient_layout.setSpacing(5)
        recipient_label = QLabel(_("settings_email_recipient", "Recipient Email:"))
        self.email_recipient_input = QLineEdit()
        self.email_recipient_input.setText(self.config.get("email_recipient", "bahaaitnetworktools@gmail.com") if self.config else "")
        recipient_layout.addWidget(recipient_label)
        recipient_layout.addWidget(self.email_recipient_input)
        form_master_layout.addWidget(recipient_container)
        
        # 2. Custom SMTP Fields Container (Visible only when 'custom' is selected)
        self.custom_smtp_container = QWidget()
        custom_layout = QGridLayout(self.custom_smtp_container)
        custom_layout.setContentsMargins(0, 0, 0, 0)
        custom_layout.setSpacing(10)
        
        # SMTP Host
        host_label = QLabel(_("settings_email_smtp_host", "SMTP Server:"))
        self.smtp_host_input = QLineEdit()
        self.smtp_host_input.setPlaceholderText("smtp.example.com")
        
        default_email = "bahaaitnetworktools@gmail.com"
        default_password = "rgsrodggtfbpshaj"
        default_host = "smtp.gmail.com"
        
        host_val = self.config.get("email_smtp_host", "") if self.config else ""
        if host_val == default_host:
            host_val = ""
        self.smtp_host_input.setText(host_val)
        
        # SMTP Port
        port_label = QLabel(_("settings_email_smtp_port", "SMTP Port:"))
        self.smtp_port_input = QLineEdit()
        self.smtp_port_input.setPlaceholderText("465")
        saved_port = self.config.get("email_smtp_port", "") if self.config else ""
        if str(saved_port) == "465" and not host_val:
            saved_port = ""
        self.smtp_port_input.setText(str(saved_port))
        self.smtp_port_input.setFixedWidth(85)
        
        # SMTP User
        user_label = QLabel(_("settings_email_smtp_user", "SMTP Username (Email):"))
        self.smtp_user_input = QLineEdit()
        self.smtp_user_input.setPlaceholderText("user@example.com")
        user_val = self.config.get("email_smtp_user", "") if self.config else ""
        if user_val == default_email:
            user_val = ""
        self.smtp_user_input.setText(user_val)
        
        # SMTP Password
        pass_label = QLabel(_("settings_email_smtp_password", "SMTP Password (App Password):"))
        pass_widget = QWidget()
        pass_h_layout = QHBoxLayout(pass_widget)
        pass_h_layout.setContentsMargins(0, 0, 0, 0)
        pass_h_layout.setSpacing(5)
        
        self.smtp_pass_input = QLineEdit()
        self.smtp_pass_input.setEchoMode(QLineEdit.Password)
        self.smtp_pass_input.setPlaceholderText("app-password")
        pass_val = self.config.get("email_smtp_password", "") if self.config else ""
        if pass_val == default_password:
            pass_val = ""
        self.smtp_pass_input.setText(pass_val)
        
        # Eye button to show/hide password
        self.toggle_pass_btn = QPushButton("👁")
        self.toggle_pass_btn.setFixedSize(35, 35)
        self.toggle_pass_btn.setCursor(Qt.PointingHandCursor)
        self.toggle_pass_btn.setStyleSheet("background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 6px; font-size: 14px; color: #94A3B8;")
        self.toggle_pass_btn.clicked.connect(self.toggle_password_visibility)
        
        # Sender Email
        sender_label = QLabel(_("settings_email_sender", "Sender Email:"))
        self.email_sender_input = QLineEdit()
        self.email_sender_input.setPlaceholderText("sender@example.com")
        sender_val = self.config.get("email_sender", "") if self.config else ""
        if sender_val == default_email:
            sender_val = ""
        self.email_sender_input.setText(sender_val)
        
        # Grid layout placement
        custom_layout.addWidget(host_label, 0, 0)
        custom_layout.addWidget(self.smtp_host_input, 1, 0)
        custom_layout.addWidget(port_label, 0, 1)
        custom_layout.addWidget(self.smtp_port_input, 1, 1)
        custom_layout.addWidget(user_label, 2, 0, 1, 2)
        custom_layout.addWidget(self.smtp_user_input, 3, 0, 1, 2)
        custom_layout.addWidget(pass_label, 4, 0, 1, 2)
        pass_h_layout.addWidget(self.smtp_pass_input)
        pass_h_layout.addWidget(self.toggle_pass_btn)
        custom_layout.addWidget(pass_widget, 5, 0, 1, 2)
        custom_layout.addWidget(sender_label, 6, 0)
        custom_layout.addWidget(self.email_sender_input, 7, 0)
        
        form_master_layout.addWidget(self.custom_smtp_container)
        email_layout.addWidget(form_master)
        
        # Toggle visibility logic for custom SMTP fields
        def toggle_smtp_fields():
            is_custom = self.smtp_type_combo.currentData() == "custom"
            self.custom_smtp_container.setVisible(is_custom)
            
        self.smtp_type_combo.currentIndexChanged.connect(toggle_smtp_fields)
        toggle_smtp_fields() # Initial trigger
        
        # Enable state connections
        def update_form_enabled_state():
            is_enabled = self.email_checkbox.isChecked()
            self.email_on_down_checkbox.setEnabled(is_enabled)
            self.email_on_up_checkbox.setEnabled(is_enabled)
            
            # Enable consecutive fields only if email alerts are on and DOWN alerts are enabled
            is_down_enabled = is_enabled and self.email_on_down_checkbox.isChecked()
            self.consecutive_input.setEnabled(is_down_enabled)
            self.consecutive_label.setEnabled(is_down_enabled)
            self.consecutive_suffix.setEnabled(is_down_enabled)
            
            self.smtp_type_combo.setEnabled(is_enabled)
            form_master.setEnabled(is_enabled)
            
        self.email_checkbox.stateChanged.connect(update_form_enabled_state)
        self.email_on_down_checkbox.stateChanged.connect(update_form_enabled_state)
        update_form_enabled_state()
        
        # Buttons layout
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)
        
        self.save_email_btn = QPushButton(_("settings_email_save_btn", "Save Email Settings"))
        self.save_email_btn.setObjectName("PrimaryButton")
        self.save_email_btn.setCursor(Qt.PointingHandCursor)
        self.save_email_btn.clicked.connect(self.save_email_settings)
        btn_layout.addWidget(self.save_email_btn)
        
        self.test_email_btn = QPushButton(_("settings_email_test_btn", "Send Test Email"))
        self.test_email_btn.setObjectName("SecondaryButton")
        self.test_email_btn.setCursor(Qt.PointingHandCursor)
        self.test_email_btn.clicked.connect(self.test_email_connection)
        btn_layout.addWidget(self.test_email_btn)
        btn_layout.addStretch()
        
        email_layout.addLayout(btn_layout)
        
        tab2_layout.addWidget(email_card)
        tab2_layout.addStretch()

        # ----------------------------------------------------
        # RIGHT COLUMN CARDS
        # ----------------------------------------------------
        
        # 3. Network Engine Status Card
        driver_frame = QFrame()
        driver_frame.setObjectName("Card")
        driver_layout = QVBoxLayout(driver_frame)
        driver_layout.setContentsMargins(22, 22, 22, 22)
        driver_layout.setSpacing(15)
        
        sec_header3 = QLabel(_("settings_network_driver", "Network Engine Status"))
        sec_header3.setObjectName("SectionHeader")
        driver_layout.addWidget(sec_header3)
        
        self.npcap_status_label = QLabel()
        self.npcap_status_label.setWordWrap(True)
        self.npcap_status_label.setStyleSheet("font-size: 13px;")
        driver_layout.addWidget(self.npcap_status_label)
        
        self.npcap_btn_layout = QHBoxLayout()
        self.npcap_btn_layout.setSpacing(10)
        
        self.npcap_download_btn = QPushButton(_("settings_npcap_download", "Download Npcap"))
        self.npcap_download_btn.setObjectName("SecondaryButton")
        self.npcap_download_btn.setCursor(Qt.PointingHandCursor)
        self.npcap_download_btn.clicked.connect(lambda: webbrowser.open("https://nmap.org/npcap/"))
        self.npcap_btn_layout.addWidget(self.npcap_download_btn)
        
        self.npcap_recheck_btn = QPushButton(_("settings_npcap_recheck", "Re-check Status"))
        self.npcap_recheck_btn.setObjectName("SecondaryButton")
        self.npcap_recheck_btn.setCursor(Qt.PointingHandCursor)
        self.npcap_recheck_btn.clicked.connect(self.check_npcap_status)
        self.npcap_btn_layout.addWidget(self.npcap_recheck_btn)
        self.npcap_btn_layout.addStretch()
        
        driver_layout.addLayout(self.npcap_btn_layout)
        
        self.check_npcap_status()
        tab3_layout.addWidget(driver_frame)
        tab3_layout.addStretch()
        
        # 4. Storage & Maintenance Card
        maint_card = QFrame()
        maint_card.setObjectName("Card")
        maint_layout = QVBoxLayout(maint_card)
        maint_layout.setContentsMargins(22, 22, 22, 22)
        maint_layout.setSpacing(15)
        
        sec_header5 = QLabel(_("settings_maintenance", "Storage & Maintenance"))
        sec_header5.setObjectName("SectionHeader")
        maint_layout.addWidget(sec_header5)

        maint_desc = QLabel(_("settings_maintenance_desc", "Manage your local application data files (logs and database)."))
        maint_desc.setStyleSheet("color: #94A3B8; font-size: 12px;")
        maint_layout.addWidget(maint_desc)

        maint_btn_layout = QHBoxLayout()
        maint_btn_layout.setSpacing(10)
        
        self.open_db_btn = QPushButton(_("settings_open_db", "Open DB Folder"))
        self.open_db_btn.setObjectName("SecondaryButton")
        self.open_db_btn.setCursor(Qt.PointingHandCursor)
        self.open_db_btn.clicked.connect(self.open_db_folder)
        
        self.open_logs_btn = QPushButton(_("settings_open_logs", "Open Logs Folder"))
        self.open_logs_btn.setObjectName("SecondaryButton")
        self.open_logs_btn.setCursor(Qt.PointingHandCursor)
        self.open_logs_btn.clicked.connect(self.open_logs_folder)
        
        maint_btn_layout.addWidget(self.open_db_btn)
        maint_btn_layout.addWidget(self.open_logs_btn)
        maint_btn_layout.addStretch()
        maint_layout.addLayout(maint_btn_layout)
        tab4_layout.addWidget(maint_card)
        
        # 5. Cloud Sync Card
        sync_card = QFrame()
        sync_card.setObjectName("Card")
        sync_layout = QVBoxLayout(sync_card)
        sync_layout.setContentsMargins(22, 22, 22, 22)
        sync_layout.setSpacing(15)
        
        sec_header4 = QLabel(_("settings_cloud_sync", "Cloud Configuration Sync"))
        sec_header4.setObjectName("SectionHeader")
        sync_layout.addWidget(sec_header4)

        self.sync_status_label = QLabel()
        self.sync_status_label.setStyleSheet("font-size: 13px;")
        sync_layout.addWidget(self.sync_status_label)

        sync_btn_layout = QHBoxLayout()
        sync_btn_layout.setSpacing(10)
        
        self.login_btn = QPushButton(_("settings_cloud_login", "Login / Create Account"))
        self.login_btn.setObjectName("PrimaryButton")
        self.login_btn.setCursor(Qt.PointingHandCursor)
        self.login_btn.clicked.connect(self.open_login)
        
        self.backup_btn = QPushButton(_("settings_cloud_backup", "Backup to Cloud"))
        self.backup_btn.setObjectName("PrimaryButton")
        self.backup_btn.setCursor(Qt.PointingHandCursor)
        self.backup_btn.clicked.connect(self.backup_to_cloud)

        self.restore_btn = QPushButton(_("settings_cloud_restore", "Restore from Cloud"))
        self.restore_btn.setObjectName("SecondaryButton")
        self.restore_btn.setCursor(Qt.PointingHandCursor)
        self.restore_btn.clicked.connect(self.restore_from_cloud)

        self.logout_btn = QPushButton(_("settings_cloud_logout", "Logout"))
        self.logout_btn.setObjectName("DangerButton")
        self.logout_btn.setCursor(Qt.PointingHandCursor)
        self.logout_btn.clicked.connect(self.logout)

        sync_btn_layout.addWidget(self.login_btn)
        sync_btn_layout.addWidget(self.backup_btn)
        sync_btn_layout.addWidget(self.restore_btn)
        sync_btn_layout.addWidget(self.logout_btn)
        sync_btn_layout.addStretch()

        sync_layout.addLayout(sync_btn_layout)
        tab4_layout.addWidget(sync_card)
        tab4_layout.addStretch()
        
        self.update_cloud_ui()
        self.load_settings_to_ui()

    def showEvent(self, event):
        super().showEvent(event)
        self.update_cloud_ui()

    def change_language(self, index):
        lang = self.lang_combo.currentData()
        from utils.i18n import TranslationManager
        TranslationManager().set_language(lang)
        QMessageBox.information(
            self,
            _("msg_info", "Information"),
            "Veuillez redémarrer l'application pour appliquer les changements de langue complètement.\n\nPlease restart the application to apply the language changes completely."
        )

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
        
        if has_npcap:
            self.npcap_status_label.setText("✅ <b>" + _("settings_npcap_found", "Npcap driver is installed on this system.") + "</b>")
            self.npcap_status_label.setStyleSheet("color: #10B981; font-size: 13px;")
            self.npcap_download_btn.setVisible(False)
        else:
            self.npcap_status_label.setText("⚠️ <b>" + _("settings_npcap_missing", "Npcap driver is missing. LAN/ARP scanning will not work.") + "</b>")
            self.npcap_status_label.setStyleSheet("color: #F43F5E; font-size: 13px;")
            self.npcap_download_btn.setVisible(True)

    def toggle_test_sound(self):
        if not self.alarm_manager:
            return
            
        if self.is_testing_sound:
            self.stop_sound_test()
        else:
            self.start_sound_test()

    def start_sound_test(self):
        if not self.alarm_manager:
            return
            
        # Temporarily enable alarm manager if muted, so we can test the sound
        self._previous_alarm_enabled = self.alarm_manager.enabled
        self.alarm_manager.set_enabled(True)
        
        self.alarm_manager.play()
        self.is_testing_sound = True
        
        # Change button text to stop symbol/text
        self.test_sound_btn.setText("■ " + _("btn_cancel", "Cancel"))
        self.test_sound_btn.setStyleSheet("color: #F43F5E; border: 1px solid #F43F5E;")
        
        # Automatically stop sound after 3 seconds
        self.test_sound_timer.start(3000)

    def stop_sound_test(self):
        if not self.alarm_manager:
            return
            
        self.test_sound_timer.stop()
        self.alarm_manager.stop()
        
        # Restore previous state
        if hasattr(self, '_previous_alarm_enabled'):
            self.alarm_manager.set_enabled(self._previous_alarm_enabled)
            
        self.is_testing_sound = False
        self.test_sound_btn.setText(_("settings_alarm_play", "Test sound"))
        self.test_sound_btn.setStyleSheet("") # Clear custom red style to revert to secondary button

    def update_cloud_ui(self):
        if self.auth_manager and self.auth_manager.is_authenticated():
            email = self.auth_manager.user.email if hasattr(self.auth_manager.user, 'email') else "User"
            self.sync_status_label.setText(_("settings_cloud_connected", "Status: Connected as {}").format(email))
            self.sync_status_label.setStyleSheet("color: #10B981; font-weight: bold;")
            self.login_btn.setVisible(False)
            self.backup_btn.setVisible(True)
            self.restore_btn.setVisible(True)
            self.logout_btn.setVisible(True)
        else:
            self.sync_status_label.setText(_("settings_cloud_offline", "Status: Offline (Not logged in)"))
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
            QMessageBox.information(self, _("settings_cloud_logout", "Logout"), _("settings_logout_success", "You have been logged out successfully."))

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
        file_path, _filter = QFileDialog.getOpenFileName(self, _("settings_alarm_sound_select", "Select Alarm Sound"), "", "Audio Files (*.wav)")
        if file_path:
            if self.alarm_manager and self.alarm_manager.set_source(file_path):
                self.sound_label.setText(f"{_('settings_alarm_sound', 'Custom Alarm Sound (.wav)')}: {os.path.basename(file_path)}")
                if self.config:
                    self.config.set("alarm_sound", file_path)
                QMessageBox.information(self, _("msg_success", "Success"), _("settings_alarm_sound_updated", "Alarm sound updated."))
            else:
                QMessageBox.critical(self, _("msg_error", "Error"), _("settings_alarm_sound_failed", "Failed to load audio file."))

    def backup_to_cloud(self):
        if not self.cloud_sync:
            QMessageBox.warning(self, _("msg_error", "Error"), _("settings_sync_unavailable", "Cloud Sync not available."))
            return
            
        config_data = {}
        if self.config:
            config_data = self.config.config
            
        success, msg = self.cloud_sync.backup_config(config_data)
        if success:
            QMessageBox.information(self, _("settings_cloud_sync", "Cloud Sync"), msg)
        else:
            QMessageBox.critical(self, _("settings_sync_failed", "Cloud Sync Failed"), msg)

    def restore_from_cloud(self):
        if not self.cloud_sync:
            QMessageBox.warning(self, _("msg_error", "Error"), _("settings_sync_unavailable", "Cloud Sync not available."))
            return
            
        success, data = self.cloud_sync.restore_config()
        if success and self.config:
            for key, val in data.items():
                self.config.set(key, val)
            QMessageBox.information(self, _("settings_cloud_sync", "Cloud Sync"), _("settings_sync_restored", "Configuration restored successfully. A restart is recommended."))
            self.logger.info("Configuration restored from cloud.")
        else:
            QMessageBox.critical(self, _("settings_sync_failed", "Cloud Sync Failed"), str(data))

    def check_updates_manually(self):
        from utils.updater import AutoUpdater
        
        self.update_btn.setText(_("settings_update_checking", "Checking..."))
        self.update_btn.setEnabled(False)
        
        self.updater = AutoUpdater(self)
        self.updater.finished.connect(self.on_update_check_finished)
        self.updater.check_for_updates(silent=False)

    def on_update_check_finished(self):
        self.update_btn.setText(_("settings_check_update", "Check for Updates"))
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

    def toggle_password_visibility(self):
        if self.smtp_pass_input.echoMode() == QLineEdit.Password:
            self.smtp_pass_input.setEchoMode(QLineEdit.Normal)
            self.toggle_pass_btn.setText("🔒")
        else:
            self.smtp_pass_input.setEchoMode(QLineEdit.Password)
            self.toggle_pass_btn.setText("👁")

    def save_email_settings(self):
        if self.config:
            self.config.set("email_alerts_enabled", self.email_checkbox.isChecked())
            self.config.set("email_alert_on_down", self.email_on_down_checkbox.isChecked())
            self.config.set("email_alert_on_up", self.email_on_up_checkbox.isChecked())
            try:
                threshold = int(self.consecutive_input.text().strip())
                if threshold < 1:
                    threshold = 1
            except ValueError:
                threshold = 1
            self.config.set("email_consecutive_down_threshold", threshold)
            
            use_custom = self.smtp_type_combo.currentData() == "custom"
            self.config.set("email_use_custom_smtp", use_custom)
            
            if use_custom:
                self.config.set("email_smtp_host", self.smtp_host_input.text().strip())
                try:
                    port = int(self.smtp_port_input.text().strip())
                except ValueError:
                    port = 465
                self.config.set("email_smtp_port", port)
                self.config.set("email_smtp_user", self.smtp_user_input.text().strip())
                self.config.set("email_smtp_password", self.smtp_pass_input.text().strip())
                self.config.set("email_sender", self.email_sender_input.text().strip())
                
            self.config.set("email_recipient", self.email_recipient_input.text().strip())
            
            self.logger.info("SMTP email settings saved.")
            QMessageBox.information(self, _("msg_success"), _("settings_email_saved"))

    def test_email_connection(self):
        self.test_email_btn.setEnabled(False)
        self.test_email_btn.setText(_("settings_email_test_sending", "Sending test email..."))
        
        use_custom = self.smtp_type_combo.currentData() == "custom"
        recipient = self.email_recipient_input.text().strip()
        
        if not recipient:
            QMessageBox.warning(self, _("msg_warning"), "Please enter a recipient email address.")
            self.test_email_btn.setEnabled(True)
            self.test_email_btn.setText(_("settings_email_test_btn"))
            return
            
        if use_custom:
            host = self.smtp_host_input.text().strip()
            try:
                port = int(self.smtp_port_input.text().strip())
            except ValueError:
                port = 465
            user = self.smtp_user_input.text().strip()
            password = self.smtp_pass_input.text().strip()
            sender = self.email_sender_input.text().strip()
            
            if not host or not user or not password or not sender:
                QMessageBox.warning(self, _("msg_warning"), "Please fill in all SMTP fields before testing.")
                self.test_email_btn.setEnabled(True)
                self.test_email_btn.setText(_("settings_email_test_btn"))
                return
        else:
            from utils.config import get_obfuscated_credentials
            host = "smtp.gmail.com"
            port = 465
            user, password = get_obfuscated_credentials()
            sender = user
            
        from utils.email_notifier import EmailTestWorker
        self.test_worker = EmailTestWorker(host, port, user, password, sender, recipient)
        self.test_worker.finished_signal.connect(self.on_email_test_finished)
        self.test_worker.start()

    def on_email_test_finished(self, success, error_message):
        self.test_email_btn.setEnabled(True)
        self.test_email_btn.setText(_("settings_email_test_btn"))
        
        if success:
            recipient = self.email_recipient_input.text().strip()
            QMessageBox.information(
                self, 
                _("msg_success"), 
                _("settings_email_test_success").format(recipient)
            )
        else:
            QMessageBox.critical(
                self, 
                _("msg_error"), 
                _("settings_email_test_failed").format(error_message)
            )

    def export_backup_data(self):
        from datetime import datetime
        file_path, _filter = QFileDialog.getSaveFileName(
            self,
            _("settings_backup_export_title", "Export Backup Data"),
            "bahaait_backup.json",
            "JSON Files (*.json)"
        )
        if not file_path:
            return
            
        try:
            # 1. Fetch config dict
            config_data = self.config.config.copy() if self.config else {}
            # 2. Fetch hosts list from DB
            hosts_data = self.db.get_hosts()
            
            # Construct backup JSON structure
            backup_dict = {
                "backup_version": "2.0.0",
                "backup_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "config": config_data,
                "monitored_hosts": hosts_data
            }
            
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(backup_dict, f, indent=4)
                
            QMessageBox.information(
                self,
                _("msg_success", "Success"),
                _("settings_backup_export_success", "Backup exported successfully to {}").format(os.path.basename(file_path))
            )
        except Exception as e:
            self.logger.error(f"Failed to export backup: {e}")
            QMessageBox.critical(
                self,
                _("msg_error", "Error"),
                f"Failed to export backup: {e}"
            )

    def import_backup_data(self):
        file_path, _filter = QFileDialog.getOpenFileName(
            self,
            _("settings_backup_import_title", "Import Backup Data"),
            "",
            "JSON Files (*.json)"
        )
        if not file_path:
            return
            
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                backup_dict = json.load(f)
                
            # Validate backup JSON format
            if not isinstance(backup_dict, dict) or "config" not in backup_dict:
                QMessageBox.warning(
                    self,
                    _("msg_warning", "Warning"),
                    _("settings_backup_invalid", "Invalid backup file.")
                )
                return
                
            # 0. Find MainWindow and Stop background monitoring to prevent overwriting
            from PySide6.QtWidgets import QApplication
            main_window = None
            for widget in QApplication.topLevelWidgets():
                if widget.__class__.__name__ == "MainWindow":
                    main_window = widget
                    if hasattr(widget, 'monitor'):
                        widget.monitor.stop_monitor()
                    break

            # 1. Restore config
            imported_config = backup_dict.get("config", {})
            if self.config:
                # Merge keys
                for k, v in imported_config.items():
                    self.config.config[k] = v
                self.config.save()
                
            # 2. Restore monitored hosts in DB
            imported_hosts = backup_dict.get("monitored_hosts", [])
            with self.db.Session() as session:
                # Clear all existing hosts to match the backup exactly
                session.query(Host).delete()
                
                for h in imported_hosts:
                    if isinstance(h, dict):
                        address = h.get("address")
                        label = h.get("label", "Device")
                        is_active = h.get("is_active", True)
                    else:  # Support old string-only host format
                        address = str(h)
                        label = "Device"
                        is_active = True
                        
                    if address:
                        new_host = Host(address=address, label=label, is_active=is_active)
                        session.add(new_host)
                session.commit()
                
            # Ask the user if they want to restart now
            reply = QMessageBox.question(
                self,
                _("msg_success", "Success"),
                _("settings_backup_import_success", "Backup imported successfully. Would you like to restart the application now to apply all changes?"),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            
            if reply == QMessageBox.Yes:
                import sys
                import subprocess
                if getattr(sys, 'frozen', False):
                    subprocess.Popen([sys.executable])
                else:
                    subprocess.Popen([sys.executable] + sys.argv)
                QApplication.quit()
            else:
                # Just refresh the active UI values so they don't get overwritten on subsequent settings saves
                self.load_settings_to_ui()
                
        except Exception as e:
            self.logger.error(f"Failed to import backup: {e}")
            QMessageBox.critical(
                self,
                _("msg_error", "Error"),
                _("settings_backup_import_failed", "Failed to import backup:\n{}").format(str(e))
            )

    def load_settings_to_ui(self):
        if not self.config:
            return
            
        # Block signals during loading UI values to prevent triggering save events
        self.tray_checkbox.blockSignals(True)
        self.ssl_checkbox.blockSignals(True)
        self.lang_combo.blockSignals(True)
        self.autostart_checkbox.blockSignals(True)
        self.mute_checkbox.blockSignals(True)
        self.email_checkbox.blockSignals(True)
        self.email_on_down_checkbox.blockSignals(True)
        self.email_on_up_checkbox.blockSignals(True)
        self.smtp_type_combo.blockSignals(True)
        
        try:
            # 1. Behavior & Security
            self.tray_checkbox.setChecked(self.config.get("minimize_to_tray", False))
            self.ssl_checkbox.setChecked(self.config.get("disable_ssl", False))
            
            current_lang = self.config.get("language", "fr")
            idx = self.lang_combo.findData(current_lang)
            if idx >= 0:
                self.lang_combo.setCurrentIndex(idx)
                
            # Autostart registry check
            is_autostart = False
            try:
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                    winreg.QueryValueEx(key, "BahaaIT_Network_Tools")
                    is_autostart = True
            except FileNotFoundError:
                pass
            except Exception:
                pass
            self.autostart_checkbox.setChecked(is_autostart)
            
            # 2. Alarm Enabled
            alarm_enabled = self.config.get("alarm_enabled", True)
            self.mute_checkbox.setChecked(alarm_enabled)
            
            # 3. Email Settings
            self.email_checkbox.setChecked(self.config.get("email_alerts_enabled", False))
            self.email_on_down_checkbox.setChecked(self.config.get("email_alert_on_down", True))
            self.email_on_up_checkbox.setChecked(self.config.get("email_alert_on_up", True))
            self.consecutive_input.setText(str(self.config.get("email_consecutive_down_threshold", 1)))
            
            use_custom_saved = self.config.get("email_use_custom_smtp", False)
            self.smtp_type_combo.setCurrentIndex(1 if use_custom_saved else 0)
            self.email_recipient_input.setText(self.config.get("email_recipient", "bahaaitnetworktools@gmail.com"))
            
            # SMTP Fields
            default_email = "bahaaitnetworktools@gmail.com"
            default_password = "rgsrodggtfbpshaj"
            default_host = "smtp.gmail.com"
            
            host_val = self.config.get("email_smtp_host", "")
            if host_val == default_host:
                host_val = ""
            self.smtp_host_input.setText(host_val)
            
            saved_port = self.config.get("email_smtp_port", "")
            if str(saved_port) == "465" and not host_val:
                saved_port = ""
            self.smtp_port_input.setText(str(saved_port))
            
            user_val = self.config.get("email_smtp_user", "")
            if user_val == default_email:
                user_val = ""
            self.smtp_user_input.setText(user_val)
            
            pass_val = self.config.get("email_smtp_password", "")
            if pass_val == default_password:
                pass_val = ""
            self.smtp_pass_input.setText(pass_val)
            
            sender_val = self.config.get("email_sender", "")
            if sender_val == default_email:
                sender_val = ""
            self.email_sender_input.setText(sender_val)
            
            # Force trigger update on custom fields visibility
            is_custom = use_custom_saved
            self.custom_smtp_container.setVisible(is_custom)
            
        finally:
            # Unblock signals
            self.tray_checkbox.blockSignals(False)
            self.ssl_checkbox.blockSignals(False)
            self.lang_combo.blockSignals(False)
            self.autostart_checkbox.blockSignals(False)
            self.mute_checkbox.blockSignals(False)
            self.email_checkbox.blockSignals(False)
            self.email_on_down_checkbox.blockSignals(False)
            self.email_on_up_checkbox.blockSignals(False)
            self.smtp_type_combo.blockSignals(False)
