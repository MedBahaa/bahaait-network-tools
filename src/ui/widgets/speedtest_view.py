from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QFrame, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QComboBox,
                             QDialog, QLineEdit, QListWidget, QListWidgetItem)
from PySide6.QtGui import QPainter, QPen, QColor, QFont, QPainterPath
from PySide6.QtCore import Qt, QRect, Signal
from core.speedtest import SpeedTestWorker, ServerListWorker
from utils.db import DatabaseManager
import psutil
import time

class ServerSelectionDialog(QDialog):
    def __init__(self, servers, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Server")
        self.setFixedSize(400, 500)
        self.setObjectName("ServerDialog")
        self.setStyleSheet("""
            QDialog { background-color: #0F172A; }
            QLineEdit { 
                background-color: #1E293B; border: 1px solid #334155; 
                border-radius: 8px; padding: 10px; color: white; margin-bottom: 10px;
            }
            QListWidget { 
                background-color: #1E293B; border: none; border-radius: 8px; 
                color: #CBD5E1; font-size: 13px; outline: none;
            }
            QListWidget::item { padding: 12px; border-bottom: 1px solid #334155; }
            QListWidget::item:selected { background-color: #3D5AFE; color: white; border-radius: 4px; }
            QPushButton { 
                background-color: #3D5AFE; color: white; border-radius: 6px; 
                padding: 10px; font-weight: bold; min-width: 80px;
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search server, sponsor or city...")
        layout.addWidget(self.search_bar)
        
        self.list_widget = QListWidget()
        
        # Add "Automatic" option first
        auto_item = QListWidgetItem("Auto Select Best (Recommended)")
        auto_item.setData(Qt.UserRole, None)
        self.list_widget.addItem(auto_item)
        
        for s in servers:
            item = QListWidgetItem(f"{s.get('ui_name', s.get('name', 'Server'))} ({s['distance']:.0f} km)")
            item.setData(Qt.UserRole, s)
            self.list_widget.addItem(item)
            
        layout.addWidget(self.list_widget)
        
        self.search_bar.textChanged.connect(self.filter_servers)
        self.list_widget.itemDoubleClicked.connect(self.accept)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self.select_btn = QPushButton("SELECT")
        self.select_btn.clicked.connect(self.accept)
        btn_layout.addWidget(self.select_btn)
        layout.addLayout(btn_layout)

    def filter_servers(self, text):
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            item.setHidden(text.lower() not in item.text().lower())

    def get_selected_server(self):
        item = self.list_widget.currentItem()
        if item:
            return item.data(Qt.UserRole)
        return None

class CircularGauge(QWidget):
    def __init__(self, title, unit, color, max_val=100, parent=None):
        super().__init__(parent)
        self.title = title
        self.unit = unit
        self.color = QColor(color)
        self.value = 0.0
        self.max_val = max_val
        self.setMinimumSize(100, 100)

    def setValue(self, val):
        self.value = float(val)
        if self.value > self.max_val:
            self.max_val = self.value * 1.2 # Auto-scale
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        width = self.width()
        height = self.height()
        side = min(width, height) - 20
        rect = QRect((width - side) // 2, (height - side) // 2, side, side)
        
        # 1. Draw Background Track
        pen = QPen(QColor("#1E293B")) # Dark slate
        pen.setWidth(12)
        pen.setCapStyle(Qt.RoundCap)
        painter.setPen(pen)
        # Start at 225 degrees (bottom-left), span -270 degrees (clockwise to bottom-right)
        painter.drawArc(rect, 225 * 16, -270 * 16)
        
        # 2. Draw Value Arc
        pen.setColor(self.color)
        painter.setPen(pen)
        span = (self.value / self.max_val) * 270 if self.max_val > 0 else 0
        painter.drawArc(rect, 225 * 16, -int(span) * 16)
        
        # 3. Draw Text
        # Value
        painter.setPen(QColor("#FFFFFF"))
        font = QFont("Outfit")
        font.setBold(True)
        font.setPixelSize(int(side * 0.22))
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignCenter, f"{self.value:.1f}" if self.value < 100 else f"{int(self.value)}")
        
        # Unit
        font.setPixelSize(int(side * 0.1))
        font.setBold(False)
        painter.setFont(font)
        painter.setPen(QColor("#94A3B8"))
        painter.drawText(rect.adjusted(0, int(side * 0.3), 0, 0), Qt.AlignCenter, self.unit)
        
        # Title
        font.setPixelSize(int(side * 0.11))
        font.setBold(True)
        painter.setFont(font)
        painter.setPen(self.color)
        painter.drawText(rect.adjusted(0, -int(side * 0.35), 0, 0), Qt.AlignCenter, self.title)

class LiveGraph(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("Card")
        self.setMinimumHeight(120)
        self.points_down = []
        self.points_up = []
        self.max_val = 1.0
        
    def add_point(self, val, type):
        if type == "down":
            self.points_down.append(val)
        else:
            self.points_up.append(val)
        
        self.max_val = max(self.max_val, val)
        if len(self.points_down) > 100: self.points_down.pop(0)
        if len(self.points_up) > 100: self.points_up.pop(0)
        self.update()

    def clear(self):
        self.points_down = []
        self.points_up = []
        self.max_val = 1.0
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        w = self.width()
        h = self.height()
        
        # Grid
        painter.setPen(QPen(QColor("#334155"), 1, Qt.DashLine))
        for i in range(1, 4):
            y = int(h * i / 4)
            painter.drawLine(0, y, w, y)
            
        # Draw Down Path
        if len(self.points_down) > 1:
            self._draw_path(painter, self.points_down, "#10B981")
            
        # Draw Up Path
        if len(self.points_up) > 1:
            self._draw_path(painter, self.points_up, "#6366F1")

    def _draw_path(self, painter, points, color_hex):
        painter.setPen(QPen(QColor(color_hex), 2))
        path = QPainterPath()
        
        if len(points) < 2: return
        step = self.width() / max(10, len(points) - 1)
        for i, p in enumerate(points):
            x = i * step
            y = self.height() - (p / self.max_val * (self.height() - 20)) - 10
            if i == 0: path.moveTo(x, y)
            else: path.lineTo(x, y)
            
        painter.drawPath(path)
        # Fill area
        fill_color = QColor(color_hex)
        fill_color.setAlpha(30)
        path.lineTo((len(points)-1)*step, self.height())
        path.lineTo(0, self.height())
        path.closeSubpath()
        painter.fillPath(path, fill_color)

class SpeedtestView(QWidget):
    info_ready = Signal(dict)
    
    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        self.worker = None
        self.server_list_worker = None
        self.all_servers = []
        self.selected_server_data = None
        self.db = DatabaseManager()
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(30, 10, 30, 30)
        self.layout.setSpacing(15)
        
        # Header
        header_layout = QHBoxLayout()
        header = QLabel("Network Performance Test")
        header.setObjectName("Title")
        header_layout.addWidget(header)
        header_layout.addStretch()
        
        self.start_btn = QPushButton("START TEST")
        self.start_btn.setObjectName("PrimaryButton")
        self.start_btn.setFixedSize(160, 40)
        self.start_btn.clicked.connect(self.start_test)
        header_layout.addWidget(self.start_btn)
        self.layout.addLayout(header_layout)
        
        # 1. Stats Display (Gauges)
        self.stats_container = QFrame()
        self.stats_container.setObjectName("Card")
        stats_layout = QHBoxLayout(self.stats_container)
        stats_layout.setContentsMargins(15, 15, 15, 15)
        
        self.download_gauge = CircularGauge("DOWNLOAD", "Mbps", "#10B981", 100)
        self.upload_gauge = CircularGauge("UPLOAD", "Mbps", "#6366F1", 100)
        self.latency_gauge = CircularGauge("PING", "ms", "#F59E0B", 200)
        self.jitter_gauge = CircularGauge("JITTER", "ms", "#EC4899", 50)
        self.loss_gauge = CircularGauge("LOSS", "%", "#EF4444", 10) # Added Packet Loss
        
        stats_layout.addWidget(self.download_gauge)
        stats_layout.addWidget(self.upload_gauge)
        stats_layout.addWidget(self.latency_gauge)
        stats_layout.addWidget(self.jitter_gauge)
        stats_layout.addWidget(self.loss_gauge)
        self.layout.addWidget(self.stats_container)
        
        # 2. Live Chart
        self.graph = LiveGraph()
        self.layout.addWidget(self.graph)
        
        # 3. Info Bar (ISP, IP, Server)
        self.info_bar = QFrame()
        self.info_bar.setObjectName("Card")
        self.info_bar.setFixedHeight(70)
        info_layout = QHBoxLayout(self.info_bar)
        
        self.isp_label_layout = self._create_info_label("ISP", "Scanning...")
        self.ip_label_layout = self._create_info_label("PUBLIC IP", "Scanning...")
        
        # Server selector button
        self.server_btn = QPushButton("Auto Select Best")
        self.server_btn.setStyleSheet("""
            QPushButton { 
                background-color: #1E293B; color: #FFFFFF; font-weight: bold; 
                border: 1px solid #334155; border-radius: 6px; padding: 5px 15px;
                text-align: left; font-size: 12px;
            }
            QPushButton:hover { background-color: #334155; border-color: #3D5AFE; }
        """)
        self.server_btn.setMinimumWidth(250)
        self.server_btn.clicked.connect(self.open_server_selection)
        
        server_layout = QVBoxLayout()
        server_layout.setSpacing(2)
        s_title = QLabel("SERVER")
        s_title.setStyleSheet("color: #64748B; font-size: 9px; font-weight: bold;")
        server_layout.addWidget(s_title)
        server_layout.addWidget(self.server_btn)
        
        info_layout.addLayout(self.isp_label_layout)
        info_layout.addLayout(self.ip_label_layout)
        info_layout.addLayout(server_layout)
        self.layout.addWidget(self.info_bar)
        
        # Real-time tracking data
        self.last_recv = psutil.net_io_counters().bytes_recv
        self.last_sent = psutil.net_io_counters().bytes_sent
        self.last_time = time.time()
        
        # 4. History Table
        history_header_layout = QHBoxLayout()
        h_title = QLabel("Test History")
        h_title.setStyleSheet("font-weight: bold;")
        history_header_layout.addWidget(h_title)
        
        history_header_layout.addStretch()
        
        self.clear_history_btn = QPushButton("Clear History")
        self.clear_history_btn.setObjectName("SecondaryButton")
        self.clear_history_btn.clicked.connect(self.clear_history)
        
        self.export_pdf_btn = QPushButton("Export PDF")
        self.export_pdf_btn.setObjectName("SecondaryButton")
        self.export_pdf_btn.clicked.connect(self.export_pdf)
        
        history_header_layout.addWidget(self.clear_history_btn)
        history_header_layout.addWidget(self.export_pdf_btn)
        self.layout.addLayout(history_header_layout)
        
        self.history_table = QTableWidget(0, 6)
        self.history_table.setHorizontalHeaderLabels(["Date/Time", "Down (Mbps)", "Up (Mbps)", "Ping (ms)", "Jitter", "Loss %"])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.history_table.setMinimumHeight(100)
        self.history_table.setMaximumHeight(150)
        self.history_table.verticalHeader().setVisible(False)
        self.layout.addWidget(self.history_table)
        
        self.status_label = QLabel("Professional Network Engine Ready")
        self.status_label.setStyleSheet("color: #64748B; font-size: 11px;")
        self.layout.addWidget(self.status_label, alignment=Qt.AlignCenter)
        
        self.info_ready.connect(self.update_info_labels)
        
        self.load_history()
        self.quick_fetch_info()
        self.load_servers()

    def load_servers(self):
        self.server_list_worker = ServerListWorker()
        self.server_list_worker.status_update.connect(self.update_status)
        self.server_list_worker.servers_ready.connect(self.populate_servers)
        self.server_list_worker.start()

    def populate_servers(self, servers):
        self.all_servers = servers
        if servers:
            self.status_label.setText(f"System Ready: {len(servers)} servers loaded")
            self.logger.info(f"Loaded {len(servers)} speedtest servers")
        else:
            self.status_label.setText("Notice: Auto-select mode only (Discovery limited)")
            self.logger.warning("Server list fetch returned empty results")

    def open_server_selection(self):
        dialog = ServerSelectionDialog(self.all_servers, self)
        if dialog.exec_():
            server = dialog.get_selected_server()
            if server:
                self.selected_server_data = server
                self.server_btn.setText(f"{server.get('ui_name', server.get('name'))}")
            else:
                self.selected_server_data = None
                self.server_btn.setText("Auto Select Best")

    def _create_info_label(self, title, val):
        layout = QVBoxLayout()
        layout.setSpacing(2)
        t = QLabel(title)
        t.setStyleSheet("color: #64748B; font-size: 9px; font-weight: bold;")
        v = QLabel(val)
        v.setStyleSheet("color: #FFFFFF; font-size: 13px; font-weight: bold;")
        layout.addWidget(t)
        layout.addWidget(v)
        
        if not hasattr(self, "_info_labels"): self._info_labels = {}
        self._info_labels[title] = v
        return layout

    def update_info_labels(self, info):
        self._info_labels["ISP"].setText(info["isp"])
        self._info_labels["PUBLIC IP"].setText(info["ip"])

    def quick_fetch_info(self):
        from core.tools import NetworkTools
        import threading
        def _fetch():
            info = NetworkTools.get_fast_ip_info()
            if info:
                self.info_ready.emit(info)
        threading.Thread(target=_fetch, daemon=True).start()

    def load_history(self):
        history = self.db.get_speedtest_history(10)
        self.history_table.setRowCount(0)
        for entry in history:
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            
            def create_item(text):
                item = QTableWidgetItem(text)
                item.setTextAlignment(Qt.AlignCenter)
                return item
                
            self.history_table.setItem(row, 0, create_item(entry["timestamp"]))
            self.history_table.setItem(row, 1, create_item(f"{entry['download']:.2f}"))
            self.history_table.setItem(row, 2, create_item(f"{entry['upload']:.2f}"))
            self.history_table.setItem(row, 3, create_item(f"{entry['ping']:.1f}"))
            self.history_table.setItem(row, 4, create_item(f"{entry['jitter'] or 0:.1f}"))
            self.history_table.setItem(row, 5, create_item(f"{entry['packet_loss'] or 0:.1f}"))

    def clear_history(self):
        from PySide6.QtWidgets import QMessageBox
        reply = QMessageBox.question(self, 'Clear History', 'Are you sure you want to clear the speedtest history?', 
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.db.clear_speedtest_history()
            self.load_history()

    def export_pdf(self):
        from PySide6.QtWidgets import QMessageBox, QFileDialog
        history = self.db.get_speedtest_history(100)
        if not history:
            QMessageBox.warning(self, "Export", "No history data to export.")
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export PDF Report", "BahaaIT_Speedtest_Report.pdf", "PDF Files (*.pdf)"
        )
        
        if file_path:
            from utils.pdf_generator import PDFReportGenerator
            generator = PDFReportGenerator()
            success, msg = generator.generate_speedtest_report(history, file_path)
            
            if success:
                QMessageBox.information(self, "Success", "PDF Report exported successfully.")
            else:
                QMessageBox.critical(self, "Error", f"Failed to export PDF: {msg}")

    def start_test(self):
        self.start_btn.setEnabled(False)
        self.start_btn.setText("TESTING...")
        self.status_label.setText("Preparing Professional Test...")
        self.download_gauge.setValue(0)
        self.upload_gauge.setValue(0)
        self.latency_gauge.setValue(0)
        self.jitter_gauge.setValue(0)
        self.loss_gauge.setValue(0)
        self.graph.clear()
        
        self.worker = SpeedTestWorker(server_data=self.selected_server_data)
        self.worker.status_update.connect(self.update_status)
        self.worker.progress_update.connect(self.on_progress)
        self.worker.result_ready.connect(self.on_result)
        self.worker.finished.connect(self.on_finished)
        self.worker.start()
        
        self.last_recv = psutil.net_io_counters().bytes_recv
        self.last_sent = psutil.net_io_counters().bytes_sent
        self.last_time = time.time()
        
        if not hasattr(self, "realtime_timer"):
            from PySide6.QtCore import QTimer
            self.realtime_timer = QTimer(self)
            self.realtime_timer.timeout.connect(self.update_realtime_gauges)
        self.realtime_timer.start(200)

    def on_progress(self, val, type):
        if type == "down_done":
            self.download_gauge.setValue(val)
        elif type == "up_done":
            self.upload_gauge.setValue(val)

    def update_status(self, status):
        self.status_label.setText(status)

    def on_result(self, data):
        self.download_gauge.setValue(data['download'])
        self.upload_gauge.setValue(data['upload'])
        self.latency_gauge.setValue(data['ping'])
        self.jitter_gauge.setValue(data['jitter'])
        self.loss_gauge.setValue(data['packet_loss'])
        
        self._info_labels["ISP"].setText(data["isp"])
        self._info_labels["PUBLIC IP"].setText(data["ip"])
        
        if self.selected_server_data is None:
            self.server_btn.setText(f"Auto: {data['server']}")
        
        self.db.save_speedtest(
            data["download"], data["upload"], data["ping"], 
            data["jitter"], data["packet_loss"],
            data["server"], data["isp"]
        )
        self.load_history()

    def on_finished(self):
        if hasattr(self, "realtime_timer"):
            self.realtime_timer.stop()
        self.start_btn.setEnabled(True)
        self.start_btn.setText("START TEST")
        
        # Don't overwrite error messages with success message
        current_status = self.status_label.text()
        if "Error" not in current_status and "Speedtest Error" not in current_status:
            self.status_label.setText("Test Completed Successfully")
        else:
            # If there was an error, make sure gauges are reset to 0
            self.download_gauge.setValue(0)
            self.upload_gauge.setValue(0)
            self.latency_gauge.setValue(0)
            self.jitter_gauge.setValue(0)
            self.loss_gauge.setValue(0)

    def update_realtime_gauges(self):
        if not self.worker or not self.worker.isRunning():
            return
            
        now = time.time()
        dt = now - self.last_time
        if dt <= 0: return
        
        counters = psutil.net_io_counters()
        
        # Calculate Mbps (bits per second / 1M)
        dl_mbps = (counters.bytes_recv - self.last_recv) * 8 / (1_000_000 * dt)
        ul_mbps = (counters.bytes_sent - self.last_sent) * 8 / (1_000_000 * dt)
        
        status = self.status_label.text().lower()
        if "download" in status:
            if dl_mbps > 0.1:
                self.download_gauge.setValue(dl_mbps)
                self.graph.add_point(dl_mbps, "down")
        elif "upload" in status:
            if ul_mbps > 0.1:
                self.upload_gauge.setValue(ul_mbps)
                self.graph.add_point(ul_mbps, "up")
                
        self.last_recv = counters.bytes_recv
        self.last_sent = counters.bytes_sent
        self.last_time = now
