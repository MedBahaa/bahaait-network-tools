from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QLineEdit, QProgressBar, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QRadioButton, QButtonGroup)
from PySide6.QtCore import Qt, QThread, Signal
from core.scanner import Scanner
from utils.i18n import _

class ScannerWorker(QThread):
    progress_signal = Signal(int)
    result_signal = Signal(dict)
    finished_signal = Signal()

    def __init__(self, scan_type, target, *args):
        super().__init__()
        self.scan_type = scan_type
        self.target = target
        self.args = args
        self.scanner = None

    def run(self):
        self.scanner = Scanner()
        self.scanner.progress_signal.connect(self.progress_signal.emit)
        self.scanner.result_signal.connect(self.result_signal.emit)
        self.scanner.finished_signal.connect(self.finished_signal.emit)
        
        if self.scan_type == "lan":
            self.scanner.scan_lan_arp(self.target)
        elif self.scan_type == "port":
            port_range, fast_mode = self.args
            self.scanner.scan_ports(self.target, port_range, fast_mode)
        elif self.scan_type == "traceroute":
            self.scanner.traceroute(self.target)

    def stop(self):
        if self.scanner:
            self.scanner.running = False
        self.wait()

class LocalInfoWorker(QThread):
    prefix_ready = Signal(str)

    def run(self):
        from core.tools import NetworkTools
        info = NetworkTools.get_local_info()
        prefix = info.get("network_cidr", "")
        if prefix:
            self.prefix_ready.emit(prefix)

class ScannerView(QWidget):
    network_prefix_ready = Signal(str)

    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        self.worker = None
        self.info_worker = None
        self.network_prefix_ready.connect(self.on_network_prefix_ready)
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(30, 30, 30, 30)
        
        # Header
        header = QLabel(_("scan_title"))
        header.setObjectName("Title")
        self.layout.addWidget(header)
        
        # Mode Selection
        mode_layout = QHBoxLayout()
        mode_layout.setSpacing(40) # Increased spacing for better visibility
        self.mode_group = QButtonGroup(self)
        
        self.lan_radio = QRadioButton(_("scan_mode_lan_label"))
        self.lan_radio.setChecked(True)
        self.lan_radio.setMinimumWidth(160)
        
        self.port_radio = QRadioButton(_("scan_mode_port_label"))
        self.port_radio.setMinimumWidth(160)
        
        self.trace_radio = QRadioButton(_("scan_mode_tracert_label"))
        self.trace_radio.setMinimumWidth(160)
        
        self.mode_group.addButton(self.lan_radio)
        self.mode_group.addButton(self.port_radio)
        self.mode_group.addButton(self.trace_radio)
        
        mode_layout.addWidget(self.lan_radio)
        mode_layout.addWidget(self.port_radio)
        mode_layout.addWidget(self.trace_radio)
        mode_layout.addStretch()
        self.layout.addLayout(mode_layout)
        
        # Connect mode change
        self.lan_radio.toggled.connect(self.on_mode_changed)
        self.port_radio.toggled.connect(self.on_mode_changed)
        self.trace_radio.toggled.connect(self.on_mode_changed)
        
        # Controls
        controls = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText(_("scan_placeholder_lan"))
        self.target_input.returnPressed.connect(self.start_scan)
        
        self.scan_btn = QPushButton(_("scan_btn_start"))
        self.scan_btn.setObjectName("PrimaryButton")
        self.scan_btn.clicked.connect(self.start_scan)
        
        controls.addWidget(self.target_input)
        controls.addWidget(self.scan_btn)
        # Port Scan Settings (Hidden by default)
        self.port_settings = QWidget()
        port_settings_layout = QHBoxLayout(self.port_settings)
        port_settings_layout.setContentsMargins(0, 10, 0, 10)
        
        self.port_settings.setVisible(False)
        
        self.port_mode_common = QRadioButton(_("scan_port_common"))
        self.port_mode_common.setChecked(True)
        self.port_mode_custom = QRadioButton(_("scan_port_custom"))
        
        self.start_port = QLineEdit("1")
        self.start_port.setPlaceholderText(_("scan_port_start"))
        self.start_port.setFixedWidth(80)
        self.start_port.setEnabled(False)
        
        self.end_port = QLineEdit("1024")
        self.end_port.setPlaceholderText(_("scan_port_end"))
        self.end_port.setFixedWidth(80)
        self.end_port.setEnabled(False)
        
        self.port_mode_custom.toggled.connect(self.start_port.setEnabled)
        self.port_mode_custom.toggled.connect(self.end_port.setEnabled)
        
        port_settings_layout.addWidget(QLabel(_("scan_port_mode_label")))
        port_settings_layout.addWidget(self.port_mode_common)
        port_settings_layout.addWidget(self.port_mode_custom)
        port_settings_layout.addWidget(QLabel(_("scan_port_range")))
        port_settings_layout.addWidget(self.start_port)
        port_settings_layout.addWidget(QLabel("-"))
        port_settings_layout.addWidget(self.end_port)
        port_settings_layout.addStretch()
        
        self.layout.addWidget(self.port_settings)

        # Connect mode change to show/hide port settings
        self.port_radio.toggled.connect(self.port_settings.setVisible)
        
        self.layout.addLayout(controls)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.layout.addWidget(self.progress_bar)
        
        # Table
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels([_("scan_table_target"), _("scan_table_info"), _("scan_table_status"), _("scan_table_mac")])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.verticalHeader().setDefaultSectionSize(45)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.layout.addWidget(self.table)
        
        # Auto-fill local network prefix (only for LAN mode)
        self._network_cidr = ""
        self.auto_fill_prefix()

    def on_mode_changed(self, checked):
        """Update input field placeholder and content when mode changes."""
        if not checked:
            return
        if self.lan_radio.isChecked():
            self.target_input.setPlaceholderText(_("scan_placeholder_lan_short"))
            if self._network_cidr:
                self.target_input.setText(self._network_cidr)
        elif self.port_radio.isChecked():
            self.target_input.clear()
            self.target_input.setPlaceholderText(_("scan_placeholder_port"))
        elif self.trace_radio.isChecked():
            self.target_input.clear()
            self.target_input.setPlaceholderText(_("scan_placeholder_tracert"))

    def auto_fill_prefix(self):
        self.info_worker = LocalInfoWorker()
        self.info_worker.prefix_ready.connect(self.network_prefix_ready.emit)
        self.info_worker.finished.connect(self.info_worker.deleteLater)
        self.info_worker.start()

    def on_network_prefix_ready(self, prefix):
        self._network_cidr = prefix
        if self.lan_radio.isChecked():
            self.target_input.setText(prefix)

    def start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            return
            
        # Basic validation: ensure it's not just a prefix for single-target scans
        if not self.lan_radio.isChecked():
            # Block incomplete IP prefixes like "192.168.1" but allow domains like "google.com"
            is_ip_like = all(c.isdigit() or c == '.' for c in target)
            if is_ip_like and target.count(".") < 3:
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.warning(self, _("scan_error_invalid_title"), 
                                  _("scan_error_invalid_msg"))
                return

        self.table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText(_("scan_scanning"))
        
        if self.lan_radio.isChecked():
            self.table.setHorizontalHeaderLabels([_("scan_table_ip"), _("scan_table_hostname"), _("scan_table_status"), _("scan_table_mac")])
            # If target is a prefix (e.g. 192.168.1), convert to CIDR for scapy
            if target.count(".") == 2:
                scan_target = f"{target}.0/24"
            elif "/" not in target and target.count(".") == 3:
                scan_target = f"{target.rsplit('.', 1)[0]}.0/24"
            else:
                scan_target = target
            self.worker = ScannerWorker("lan", scan_target)
        elif self.port_radio.isChecked():
            self.table.setHorizontalHeaderLabels([_("scan_table_target"), _("scan_table_port"), _("scan_table_status"), _("scan_table_extra")])
            fast_mode = self.port_mode_common.isChecked()
            try:
                start = int(self.start_port.text())
                end = int(self.end_port.text())
            except:
                start, end = 1, 1024
            
            self.worker = ScannerWorker("port", target, (start, end), fast_mode)
        else:
            self.table.setColumnCount(6)
            self.table.setHorizontalHeaderLabels([_("scan_table_hop"), _("scan_table_ip"), _("scan_table_rtt1"), _("scan_table_rtt2"), _("scan_table_rtt3"), _("scan_table_status")])
            self.worker = ScannerWorker("traceroute", target)

        self.worker.progress_signal.connect(self.update_progress)
        self.worker.result_signal.connect(self.on_result)
        self.worker.finished_signal.connect(self.on_finished)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.start()

    def update_progress(self, val):
        self.progress_bar.setValue(val)

    def on_result(self, data):
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        from PySide6.QtGui import QColor
        
        if self.lan_radio.isChecked():
            self.table.setColumnCount(4)
            items = [data.get("ip", ""), data.get("hostname", ""), data.get("status", ""), data.get("mac", "N/A")]
        elif self.port_radio.isChecked():
            self.table.setColumnCount(4)
            items = [data.get("target", ""), str(data.get("port", "")), data.get("status", ""), ""]
        else:
            # Traceroute case with 6 columns
            items = [str(data.get("hop", "")), data.get("ip", ""), data.get("p1", ""), data.get("p2", ""), data.get("p3", ""), data.get("status", "")]

        for col, text in enumerate(items):
            item = QTableWidgetItem(text)
            item.setTextAlignment(Qt.AlignCenter)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            
            # Semantic Coloring for Status Column
            # Status is at index 2 for LAN/Port, and index 5 for Traceroute
            status_idx = 2 if not self.trace_radio.isChecked() else 5
            if col == status_idx:
                status_text = text.upper()
                if any(kw in status_text for kw in ["UP", "OPEN", "SUCCESS"]):
                    item.setForeground(QColor("#10B981")) # Green
                    item.setToolTip(_("scan_tooltip_active"))
                elif "UNREACHABLE" in status_text or "ERROR" in status_text:
                    item.setForeground(QColor("#F59E0B")) # Orange
                    item.setToolTip(_("scan_tooltip_unreachable"))
                elif any(kw in status_text for kw in ["DOWN", "CLOSED", "TIMEOUT", "FAILED"]):
                    item.setForeground(QColor("#F43F5E")) # Red
                    item.setToolTip(_("scan_tooltip_inactive"))
            
            self.table.setItem(row, col, item)

    def on_finished(self):
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText(_("scan_btn_start"))
        self.progress_bar.setValue(100)
