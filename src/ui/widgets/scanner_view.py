from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QLineEdit, QProgressBar, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QRadioButton, QButtonGroup)
from PySide6.QtCore import Qt
from core.scanner import Scanner

class ScannerView(QWidget):
    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        self.scanner = Scanner()
        self.scanner.progress_signal.connect(self.update_progress)
        self.scanner.result_signal.connect(self.on_result)
        self.scanner.finished_signal.connect(self.on_finished)
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(30, 30, 30, 30)
        
        # Header
        header = QLabel("Network Scanner")
        header.setObjectName("Title")
        self.layout.addWidget(header)
        
        # Mode Selection
        mode_layout = QHBoxLayout()
        mode_layout.setSpacing(40) # Increased spacing for better visibility
        self.mode_group = QButtonGroup(self)
        
        self.lan_radio = QRadioButton("LAN Scan")
        self.lan_radio.setChecked(True)
        self.lan_radio.setMinimumWidth(160)
        
        self.port_radio = QRadioButton("Port Scan")
        self.port_radio.setMinimumWidth(160)
        
        self.trace_radio = QRadioButton("Traceroute")
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
        self.target_input.setPlaceholderText("Network Range (e.g. 192.168.1.0/24) or Target IP...")
        self.target_input.returnPressed.connect(self.start_scan)
        
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.setObjectName("PrimaryButton")
        self.scan_btn.clicked.connect(self.start_scan)
        
        controls.addWidget(self.target_input)
        controls.addWidget(self.scan_btn)
        # Port Scan Settings (Hidden by default)
        self.port_settings = QWidget()
        port_settings_layout = QHBoxLayout(self.port_settings)
        port_settings_layout.setContentsMargins(0, 10, 0, 10)
        
        self.port_settings.setVisible(False)
        
        self.port_mode_common = QRadioButton("Common Ports")
        self.port_mode_common.setChecked(True)
        self.port_mode_custom = QRadioButton("Custom Range")
        
        self.start_port = QLineEdit("1")
        self.start_port.setPlaceholderText("Start")
        self.start_port.setFixedWidth(80)
        self.start_port.setEnabled(False)
        
        self.end_port = QLineEdit("1024")
        self.end_port.setPlaceholderText("End")
        self.end_port.setFixedWidth(80)
        self.end_port.setEnabled(False)
        
        self.port_mode_custom.toggled.connect(self.start_port.setEnabled)
        self.port_mode_custom.toggled.connect(self.end_port.setEnabled)
        
        port_settings_layout.addWidget(QLabel("Port Mode:"))
        port_settings_layout.addWidget(self.port_mode_common)
        port_settings_layout.addWidget(self.port_mode_custom)
        port_settings_layout.addWidget(QLabel("Range:"))
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
        self.table.setHorizontalHeaderLabels(["Target", "Info", "Status", "MAC"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.verticalHeader().setDefaultSectionSize(45)
        self.table.verticalHeader().setVisible(False)
        self.layout.addWidget(self.table)
        
        # Auto-fill local network prefix (only for LAN mode)
        self._network_cidr = ""
        self.auto_fill_prefix()

    def on_mode_changed(self, checked):
        """Update input field placeholder and content when mode changes."""
        if not checked:
            return
        if self.lan_radio.isChecked():
            self.target_input.setPlaceholderText("Network Range (e.g. 192.168.1.0/24)...")
            if self._network_cidr:
                self.target_input.setText(self._network_cidr)
        elif self.port_radio.isChecked():
            self.target_input.clear()
            self.target_input.setPlaceholderText("Target IP or Domain (e.g. 192.168.1.1, google.com)...")
        elif self.trace_radio.isChecked():
            self.target_input.clear()
            self.target_input.setPlaceholderText("Target IP or Domain (e.g. google.com, 8.8.8.8)...")

    def auto_fill_prefix(self):
        from core.tools import NetworkTools
        import threading
        
        def _fetch():
            info = NetworkTools.get_local_info()
            net_cidr = info.get("network_cidr", "")
            if net_cidr:
                self._network_cidr = net_cidr
                # Only auto-fill if still in LAN mode
                if self.lan_radio.isChecked():
                    self.target_input.setText(net_cidr)
        
        threading.Thread(target=_fetch, daemon=True).start()

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
                QMessageBox.warning(self, "Invalid Address", 
                                  "Please enter a full IP address or domain for Port Scan and Traceroute.")
                return

        self.table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("Scanning...")
        if self.lan_radio.isChecked():
            self.table.setHorizontalHeaderLabels(["IP Address", "Hostname", "Status", "MAC"])
            import threading
            # If target is a prefix (e.g. 192.168.1), convert to CIDR for scapy
            if target.count(".") == 2:
                scan_target = f"{target}.0/24"
            elif "/" not in target and target.count(".") == 3:
                scan_target = f"{target.rsplit('.', 1)[0]}.0/24"
            else:
                scan_target = target
            threading.Thread(target=self.scanner.scan_lan_arp, args=(scan_target,), daemon=True).start()
        elif self.port_radio.isChecked():
            self.table.setHorizontalHeaderLabels(["Target", "Port", "Status", "Extra"])
            fast_mode = self.port_mode_common.isChecked()
            try:
                start = int(self.start_port.text())
                end = int(self.end_port.text())
            except:
                start, end = 1, 1024
            
            import threading
            threading.Thread(target=self.scanner.scan_ports, 
                             args=(target, (start, end), fast_mode), 
                             daemon=True).start()
        else:
            self.table.setColumnCount(6)
            self.table.setHorizontalHeaderLabels(["Hop #", "IP Address", "RTT1", "RTT2", "RTT3", "Status"])
            import threading
            threading.Thread(target=self.scanner.traceroute, args=(target,), daemon=True).start()

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
                    item.setToolTip("Active/Responsive")
                elif "UNREACHABLE" in status_text or "ERROR" in status_text:
                    item.setForeground(QColor("#F59E0B")) # Orange
                    item.setToolTip("Destination Unreachable")
                elif any(kw in status_text for kw in ["DOWN", "CLOSED", "TIMEOUT", "FAILED"]):
                    item.setForeground(QColor("#F43F5E")) # Red
                    item.setToolTip("Inactive/Blocked")
            
            self.table.setItem(row, col, item)

    def on_finished(self):
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Start Scan")
        self.progress_bar.setValue(100)
