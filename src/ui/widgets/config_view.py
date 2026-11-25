import ipaddress
import psutil
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)
from core.net_config import NetworkConfig
from utils.admin import is_admin, run_as_admin
from utils.i18n import _


class ConfigView(QWidget):
    def __init__(self, logger, config_manager=None):
        super().__init__()
        self.logger = logger
        self.config = config_manager

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        outer_layout.addWidget(scroll)

        container = QWidget()
        self.layout = QVBoxLayout(container)
        self.layout.setContentsMargins(28, 24, 28, 24)
        self.layout.setSpacing(16)
        scroll.setWidget(container)

        # Header
        header = QLabel(_("cfg_title"))
        header.setObjectName("Title")
        self.layout.addWidget(header)

        # Admin Banner (scoped ID avoids QLabel cascading)
        self.admin_banner = QFrame()
        self.admin_banner.setObjectName("AdminBanner")
        self.admin_banner.setMinimumHeight(48)
        self.admin_banner.setVisible(not is_admin())
        self.admin_banner.setStyleSheet(
            "#AdminBanner { background-color: #7C2D12; border: 1px solid #EA580C; border-radius: 10px; }"
        )
        banner_layout = QHBoxLayout(self.admin_banner)
        banner_layout.setContentsMargins(14, 10, 14, 10)
        banner_layout.setSpacing(10)

        warn_badge = QLabel("!")
        warn_badge.setAlignment(Qt.AlignCenter)
        warn_badge.setFixedSize(22, 22)
        warn_badge.setStyleSheet(
            "background-color: #EA580C; color: #FFFFFF; font-weight: 800; font-size: 12px; border-radius: 11px;"
        )

        warn_text = QLabel(_("cfg_admin_warn"))
        warn_text.setWordWrap(True)
        warn_text.setStyleSheet("color: #FED7AA; font-weight: 600;")

        self.elevate_btn = QPushButton(_("cfg_elevate"))
        self.elevate_btn.setCursor(Qt.PointingHandCursor)
        self.elevate_btn.setMinimumHeight(28)
        self.elevate_btn.setStyleSheet(
            "QPushButton { background-color: #FDBA74; color: #7C2D12; border: none; border-radius: 6px; "
            "padding: 5px 14px; font-weight: 700; font-size: 11px; }"
            "QPushButton:hover { background-color: #FED7AA; }"
        )
        self.elevate_btn.clicked.connect(run_as_admin)

        banner_layout.addWidget(warn_badge)
        banner_layout.addWidget(warn_text, 1)
        banner_layout.addWidget(self.elevate_btn)

        self.layout.addWidget(self.admin_banner)

        # Form Card
        self.form_card = QFrame()
        self.form_card.setObjectName("PanelCard")
        form_layout = QVBoxLayout(self.form_card)
        form_layout.setContentsMargins(24, 22, 24, 22)
        form_layout.setSpacing(18)

        # Interface Selector row
        selector_layout = QHBoxLayout()
        selector_layout.setSpacing(14)
        selector_layout.setAlignment(Qt.AlignVCenter)

        l1 = QLabel(_("cfg_active_interface"))
        l1.setObjectName("SectionHeader")
        l1.setStyleSheet("margin-bottom: 0px;")

        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(260)
        self.interface_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.interface_combo.currentIndexChanged.connect(self.load_current_settings)

        refresh_btn = QPushButton(_("cfg_refresh"))
        refresh_btn.setObjectName("SecondaryButton")
        refresh_btn.setCursor(Qt.PointingHandCursor)
        refresh_btn.clicked.connect(self.refresh_interfaces)

        selector_layout.addWidget(l1)
        selector_layout.addWidget(self.interface_combo, 1)
        selector_layout.addWidget(refresh_btn)
        form_layout.addLayout(selector_layout)

        # Separator
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        line.setStyleSheet("background-color: rgba(255, 255, 255, 0.06); min-height: 1px; max-height: 1px; border: none;")
        form_layout.addWidget(line)

        # Grid for IP and DNS
        grid = QGridLayout()
        grid.setHorizontalSpacing(24)
        grid.setVerticalSpacing(16)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

        def create_field_group(label_text, input_widget):
            group = QVBoxLayout()
            group.setSpacing(4)
            lbl = QLabel(label_text)
            lbl.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
            lbl.setStyleSheet("color: #CBD5E1; font-weight: 600;")
            group.addWidget(lbl)
            group.addWidget(input_widget)
            return group

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("192.168.1.50")
        self.ip_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        grid.addLayout(create_field_group(_("cfg_ip_label"), self.ip_input), 0, 0)

        self.mask_input = QLineEdit()
        self.mask_input.setPlaceholderText("255.255.255.0")
        self.mask_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        grid.addLayout(create_field_group(_("cfg_mask_label"), self.mask_input), 1, 0)

        self.gateway_input = QLineEdit()
        self.gateway_input.setPlaceholderText("192.168.1.1")
        self.gateway_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        grid.addLayout(create_field_group(_("cfg_gateway_label"), self.gateway_input), 2, 0)

        # DNS Column (Right)
        self.dns1_input = QLineEdit()
        self.dns1_input.setPlaceholderText("8.8.8.8")
        self.dns1_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        grid.addLayout(create_field_group(_("cfg_dns1_label"), self.dns1_input), 0, 1)

        self.dns2_input = QLineEdit()
        self.dns2_input.setPlaceholderText("8.8.4.4")
        self.dns2_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        grid.addLayout(create_field_group(_("cfg_dns2_label"), self.dns2_input), 1, 1)

        # Help text / Info
        info_box = QLabel(_("cfg_static_note"))
        info_box.setWordWrap(True)
        info_box.setStyleSheet("color: #94A3B8; font-style: italic; font-size: 12px;")
        grid.addWidget(info_box, 2, 1, Qt.AlignBottom)

        form_layout.addLayout(grid)
        self.layout.addWidget(self.form_card)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)
        self.apply_static_btn = QPushButton(_("cfg_apply_static"))
        self.apply_static_btn.setObjectName("PrimaryButton")
        self.apply_static_btn.setCursor(Qt.PointingHandCursor)
        self.apply_static_btn.clicked.connect(self.apply_static)

        self.apply_dhcp_btn = QPushButton(_("cfg_set_dhcp"))
        self.apply_dhcp_btn.setObjectName("SecondaryButton")
        self.apply_dhcp_btn.setCursor(Qt.PointingHandCursor)
        self.apply_dhcp_btn.clicked.connect(self.apply_dhcp)

        btn_layout.addWidget(self.apply_static_btn)
        btn_layout.addWidget(self.apply_dhcp_btn)
        btn_layout.addStretch()
        self.layout.addLayout(btn_layout)

        self.layout.addStretch()
        self.refresh_interfaces()

    def refresh_interfaces(self):
        from core.tools import NetworkTools
        info = NetworkTools.get_local_info()
        active = info.get("active_interface")

        self.interface_combo.blockSignals(True)
        self.interface_combo.clear()

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
        if not interface:
            return

        config = NetworkConfig.get_interface_config(interface)
        self.ip_input.setText(config["ip"])
        self.mask_input.setText(config["mask"])
        self.gateway_input.setText(config["gateway"])
        self.dns1_input.setText(config["dns1"])
        self.dns2_input.setText(config["dns2"])

    @staticmethod
    def _validate_ipv4(value: str, required: bool = False) -> bool:
        val = (value or "").strip()
        if not val:
            return not required
        try:
            ipaddress.IPv4Address(val)
            return True
        except ValueError:
            return False

    def apply_static(self):
        if not is_admin():
            QMessageBox.warning(self, _("cfg_admin_required"), _("cfg_admin_required_msg"))
            return

        interface = self.interface_combo.currentText().strip()
        if not interface:
            QMessageBox.warning(self, _("msg_warning", "Warning"), _("cfg_active_interface", "Select a network interface."))
            return

        ip = self.ip_input.text().strip()
        mask = self.mask_input.text().strip()
        gw = self.gateway_input.text().strip()
        dns1 = self.dns1_input.text().strip()
        dns2 = self.dns2_input.text().strip()

        if not self._validate_ipv4(ip, required=True) or not self._validate_ipv4(mask, required=True):
            QMessageBox.warning(self, _("msg_warning", "Warning"), "Invalid IPv4 address or subnet mask.")
            return
        if not self._validate_ipv4(gw) or not self._validate_ipv4(dns1) or not self._validate_ipv4(dns2):
            QMessageBox.warning(self, _("msg_warning", "Warning"), "Invalid IPv4 address in Gateway or DNS fields.")
            return

        success = NetworkConfig.set_static_ip(interface, ip, mask, gw)
        if success:
            NetworkConfig.set_dns(interface, dns1, dns2)
            self.load_current_settings()
            QMessageBox.information(self, _("msg_success"), _("cfg_static_success"))
        else:
            QMessageBox.critical(self, _("msg_error"), _("cfg_static_error"))

    def apply_dhcp(self):
        if not is_admin():
            QMessageBox.warning(self, _("cfg_admin_required"), _("cfg_admin_required_msg"))
            return

        interface = self.interface_combo.currentText().strip()
        if not interface:
            return
        if NetworkConfig.set_dhcp(interface):
            self.load_current_settings()
            QMessageBox.information(self, _("msg_success"), _("cfg_dhcp_success").format(interface))
        else:
            QMessageBox.critical(self, _("msg_error"), _("cfg_dhcp_error"))
