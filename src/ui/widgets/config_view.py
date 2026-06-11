from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QLineEdit, QComboBox, QFrame, QMessageBox, QGridLayout, QSizePolicy)
from PySide6.QtCore import Qt
from core.net_config import NetworkConfig
from utils.admin import is_admin, run_as_admin
import psutil
import socket

class ConfigView(QWidget):
    def __init__(self, logger, config_manager=None):
        super().__init__()
        self.logger = logger
        self.config = config_manager
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(30, 30, 30, 30)
        
        # Header
        header = QLabel("Network Interface Configuration")
        header.setObjectName("Title")
        self.layout.addWidget(header)
        
        # Admin Banner
        self.admin_banner = QFrame()
        self.admin_banner.setFixedHeight(50)
        self.admin_banner.setVisible(not is_admin())
        self.admin_banner.setStyleSheet("background-color: #7C2D12; border-radius: 8px; margin-bottom: 10px;")
        banner_layout = QHBoxLayout(self.admin_banner)
        banner_layout.setContentsMargins(15, 0, 15, 0)
        
        warn_icon = QLabel("⚠️")
        warn_text = QLabel("Administrator privileges required to modify network settings.")
        warn_text.setStyleSheet("color: #FDBA74; font-weight: bold; border: none;")
        
        self.elevate_btn = QPushButton("ELEVATE")
        self.elevate_btn.setFixedWidth(80)
        self.elevate_btn.setStyleSheet("background-color: #FDBA74; color: #7C2D12; font-weight: bold; border-radius: 4px; font-size: 10px;")
        self.elevate_btn.clicked.connect(run_as_admin)
        
        banner_layout.addWidget(warn_icon)
        banner_layout.addWidget(warn_text)
        banner_layout.addStretch()
        banner_layout.addWidget(self.elevate_btn)
        
        self.layout.addWidget(self.admin_banner)
        
        # Form Card
        self.form_card = QFrame()
        self.form_card.setObjectName("Card")
        form_layout = QVBoxLayout(self.form_card)
        form_layout.setContentsMargins(25, 25, 25, 25)
        form_layout.setSpacing(20)
        
        # Interface Selector row
        selector_layout = QHBoxLayout()
        selector_layout.setSpacing(20)
        selector_layout.setAlignment(Qt.AlignVCenter)
        
        l1 = QLabel("ACTIVE INTERFACE:")
        l1.setObjectName("SectionHeader")
        l1.setStyleSheet("margin-bottom: 0px;")
        
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(300)
        self.interface_combo.setFixedHeight(35)
        self.interface_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.interface_combo.currentIndexChanged.connect(self.load_current_settings)
        
        refresh_btn = QPushButton("REFRESH")
        refresh_btn.setFixedWidth(100)
        refresh_btn.setObjectName("SecondaryButton")
        refresh_btn.setFixedHeight(35)
        refresh_btn.setCursor(Qt.PointingHandCursor)
        refresh_btn.clicked.connect(self.refresh_interfaces)
        
        selector_layout.addStretch() # Left stretch
        selector_layout.addWidget(l1, 0, Qt.AlignCenter)
        selector_layout.addWidget(self.interface_combo, 0, Qt.AlignCenter)
        selector_layout.addWidget(refresh_btn, 0, Qt.AlignCenter)
        selector_layout.addStretch() # Right stretch
        form_layout.addLayout(selector_layout)
        
        # Separator
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        line.setStyleSheet("background-color: rgba(255, 255, 255, 0.05); min-height: 1px; max-height: 1px; border: none;")
        form_layout.addSpacing(10)
        form_layout.addWidget(line)
        form_layout.addSpacing(30)
        
        # Grid for IP and DNS
        grid = QGridLayout()
        grid.setSpacing(25)
        
        # IP Column (Left)
        def create_field_group(label_text, input_widget):
            group = QVBoxLayout()
            group.setSpacing(2)
            l = QLabel(label_text)
            l.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
            group.addWidget(l)
            group.addWidget(input_widget)
            return group

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("0.0.0.0")
        self.ip_input.setFixedHeight(35)
        self.ip_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        grid.addLayout(create_field_group("IP ADDRESS:", self.ip_input), 0, 0)
        
        self.mask_input = QLineEdit()
        self.mask_input.setPlaceholderText("255.255.255.0")
        self.mask_input.setFixedHeight(35)
        self.mask_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        grid.addLayout(create_field_group("SUBNET MASK:", self.mask_input), 1, 0)
        
        self.gateway_input = QLineEdit()
        self.gateway_input.setPlaceholderText("0.0.0.0")
        self.gateway_input.setFixedHeight(35)
        self.gateway_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        grid.addLayout(create_field_group("GATEWAY:", self.gateway_input), 2, 0)
        
        # DNS Column (Right)
        self.dns1_input = QLineEdit()
        self.dns1_input.setPlaceholderText("8.8.8.8")
        self.dns1_input.setFixedHeight(35)
        self.dns1_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        grid.addLayout(create_field_group("PRIMARY DNS:", self.dns1_input), 0, 1)
        
        self.dns2_input = QLineEdit()
        self.dns2_input.setPlaceholderText("8.8.4.4")
        self.dns2_input.setFixedHeight(35)
        self.dns2_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        grid.addLayout(create_field_group("SECONDARY DNS:", self.dns2_input), 1, 1)
        
        # Help text / Info in empty grid spot
        info_box = QLabel("Note: Static IP requires accurate Mask and Gateway values to maintain internet connectivity.")
        info_box.setWordWrap(True)
        info_box.setStyleSheet("color: #64748B; font-style: italic; font-size: 11px;")
        grid.addWidget(info_box, 2, 1)
        
        # Add a dummy row to take up remaining space in the grid
        grid.setRowStretch(6, 1)
        
        form_layout.addLayout(grid)
        form_layout.addStretch() # Push everything up inside the card
        self.layout.addWidget(self.form_card)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.apply_static_btn = QPushButton("Apply Static IP")
        self.apply_static_btn.setObjectName("PrimaryButton")
        self.apply_static_btn.clicked.connect(self.apply_static)
        
        self.apply_dhcp_btn = QPushButton("Set to DHCP")
        self.apply_dhcp_btn.setObjectName("SecondaryButton")
        self.apply_dhcp_btn.clicked.connect(self.apply_dhcp)
        
        btn_layout.addWidget(self.apply_static_btn)
        btn_layout.addWidget(self.apply_dhcp_btn)
        self.layout.addLayout(btn_layout)
        
        self.refresh_interfaces() # Call this last after UI is ready
        self.layout.addStretch()

    def refresh_interfaces(self):
        from core.tools import NetworkTools
        info = NetworkTools.get_local_info()
        active = info.get("active_interface")
        
        self.interface_combo.blockSignals(True)
        self.interface_combo.clear()
        
        # Get all interfaces and move the active one to the top
        interfaces = list(psutil.net_if_addrs().keys())
        if active in interfaces:
            interfaces.remove(active)
            interfaces.insert(0, active)
            
        for interface in interfaces:
            self.interface_combo.addItem(interface)
            
        self.interface_combo.blockSignals(False)
        self.load_current_settings()

    def load_current_settings(self):
        interface = self.interface_combo.currentText()
        if not interface: return
        
        config = NetworkConfig.get_interface_config(interface)
        self.ip_input.setText(config["ip"])
        self.mask_input.setText(config["mask"])
        self.gateway_input.setText(config["gateway"])
        self.dns1_input.setText(config["dns1"])
        self.dns2_input.setText(config["dns2"])

    def apply_static(self):
        if not is_admin():
            QMessageBox.warning(self, "Admin Required", "This action requires administrator privileges.")
            return
            
        interface = self.interface_combo.currentText()
        ip = self.ip_input.text()
        mask = self.mask_input.text()
        gw = self.gateway_input.text()
        dns1 = self.dns1_input.text()
        dns2 = self.dns2_input.text()
        
        success = NetworkConfig.set_static_ip(interface, ip, mask, gw)
        if success:
            NetworkConfig.set_dns(interface, dns1, dns2)
            QMessageBox.information(self, "Success", "Static IP settings applied successfully.")
        else:
            QMessageBox.critical(self, "Error", "Failed to apply static IP settings.")

    def apply_dhcp(self):
        if not is_admin():
            QMessageBox.warning(self, "Admin Required", "This action requires administrator privileges.")
            return
            
        interface = self.interface_combo.currentText()
        if NetworkConfig.set_dhcp(interface):
            QMessageBox.information(self, "Success", f"{interface} set to DHCP.")
        else:
            QMessageBox.critical(self, "Error", "Failed to set DHCP.")
