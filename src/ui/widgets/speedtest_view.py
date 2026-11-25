import psutil
import time
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame, QTableWidget,
    QTableWidgetItem, QHeaderView, QDialog, QLineEdit, QListWidget, QListWidgetItem,
    QScrollArea, QMessageBox, QFileDialog, QAbstractItemView
)
from PySide6.QtGui import QPainter, QPen, QColor, QFont, QPainterPath, QFontMetrics
from PySide6.QtCore import Qt, QRect, Signal, QTimer
from core.speedtest import SpeedTestWorker, ServerListWorker
from utils.db import DatabaseManager
from utils.i18n import _


class ServerSelectionDialog(QDialog):
    def __init__(self, servers, parent=None):
        super().__init__(parent)
        self.setWindowTitle(_("speed_select_server_title"))
        self.setMinimumSize(440, 480)
        self.resize(480, 520)
        self.setObjectName("ServerDialog")
        self.setStyleSheet("""
            QDialog { background-color: #0F172A; }
            QListWidget {
                background-color: #1E293B; border: 1px solid #334155; border-radius: 10px;
                color: #F1F5F9; font-size: 13px; outline: none;
            }
            QListWidget::item { padding: 10px 12px; border-bottom: 1px solid #334155; }
            QListWidget::item:selected { background-color: #4F46E5; color: #FFFFFF; border-radius: 6px; }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(10)

        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText(_("speed_search_placeholder"))
        layout.addWidget(self.search_bar)

        self.list_widget = QListWidget()
        auto_item = QListWidgetItem(_("speed_auto_select"))
        auto_item.setData(Qt.UserRole, None)
        self.list_widget.addItem(auto_item)

        for s in servers:
            try:
                dist = float(s.get("distance", s.get("d", 0)) or 0)
            except (ValueError, TypeError):
                dist = 0.0
            srv_name = s.get("ui_name", s.get("name", "Server"))
            label_str = f"{srv_name} ({dist:.0f} km)" if dist > 0 else f"{srv_name}"
            item = QListWidgetItem(label_str)
            item.setData(Qt.UserRole, s)
            self.list_widget.addItem(item)

        self.list_widget.setCurrentRow(0)
        layout.addWidget(self.list_widget, 1)

        self.search_bar.textChanged.connect(self.filter_servers)
        self.list_widget.itemDoubleClicked.connect(self.accept)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)
        btn_layout.addStretch()
        cancel_btn = QPushButton(_("btn_cancel", "Cancel"))
        cancel_btn.setObjectName("SecondaryButton")
        cancel_btn.setCursor(Qt.PointingHandCursor)
        cancel_btn.clicked.connect(self.reject)
        self.select_btn = QPushButton(_("speed_select_btn"))
        self.select_btn.setObjectName("PrimaryButton")
        self.select_btn.setCursor(Qt.PointingHandCursor)
        self.select_btn.clicked.connect(self.accept)
        btn_layout.addWidget(cancel_btn)
        btn_layout.addWidget(self.select_btn)
        layout.addLayout(btn_layout)

    def filter_servers(self, text):
        first_visible = -1
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            match = text.lower() in item.text().lower()
            item.setHidden(not match)
            if match and first_visible < 0:
                first_visible = i
        cur = self.list_widget.currentItem()
        if cur is not None and cur.isHidden():
            self.list_widget.setCurrentRow(first_visible if first_visible >= 0 else -1)

    def get_selected_server(self):
        item = self.list_widget.currentItem()
        if item and not item.isHidden():
            return item.data(Qt.UserRole)
        return None


class CircularGauge(QWidget):
    def __init__(self, title, unit, color, max_val=100, parent=None):
        super().__init__(parent)
        self.title = title
        self.unit = unit
        self.color = QColor(color)
        self.value = 0.0
        self.default_max = float(max_val)
        self.max_val = float(max_val)
        self.setMinimumSize(116, 116)

    def reset(self):
        self.value = 0.0
        self.max_val = self.default_max
        self.update()

    def setValue(self, val):
        self.value = float(val)
        if self.value > self.max_val:
            self.max_val = self.value * 1.2
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        width = self.width()
        height = self.height()
        side = max(72, min(width, height) - 20)
        rect = QRect((width - side) // 2, (height - side) // 2, side, side)

        pen = QPen(QColor("#1E293B"))
        pen.setWidth(10)
        pen.setCapStyle(Qt.RoundCap)
        painter.setPen(pen)
        painter.drawArc(rect, 225 * 16, -270 * 16)

        pen.setColor(self.color)
        painter.setPen(pen)
        span = (self.value / self.max_val) * 270 if self.max_val > 0 else 0
        span = min(270.0, max(0.0, span))
        painter.drawArc(rect, 225 * 16, -int(span) * 16)

        painter.setPen(QColor("#FFFFFF"))
        font = QFont("Segoe UI")
        font.setBold(True)
        font.setPixelSize(max(14, int(side * 0.22)))
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignCenter, f"{self.value:.1f}" if self.value < 100 else f"{int(self.value)}")

        font.setPixelSize(max(11, int(side * 0.10)))
        font.setBold(False)
        painter.setFont(font)
        painter.setPen(QColor("#94A3B8"))
        painter.drawText(rect.adjusted(0, int(side * 0.30), 0, 0), Qt.AlignCenter, self.unit)

        title_px = max(11, int(side * 0.10))
        font.setPixelSize(title_px)
        font.setBold(True)
        painter.setFont(font)
        fm = QFontMetrics(font)
        elided_title = fm.elidedText(self.title, Qt.ElideRight, width - 8)
        painter.setPen(self.color)
        painter.drawText(rect.adjusted(-10, -int(side * 0.36), 10, 0), Qt.AlignCenter, elided_title)
        painter.end()


class LiveGraph(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("PanelCard")
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
        if len(self.points_down) > 100:
            self.points_down.pop(0)
        if len(self.points_up) > 100:
            self.points_up.pop(0)
        self.update()

    def clear(self):
        self.points_down = []
        self.points_up = []
        self.max_val = 1.0
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()

        painter.setPen(QPen(QColor("#334155"), 1, Qt.DashLine))
        for i in range(1, 4):
            y = int(h * i / 4)
            painter.drawLine(8, y, w - 8, y)

        if len(self.points_down) > 1:
            self._draw_path(painter, self.points_down, "#10B981")
        if len(self.points_up) > 1:
            self._draw_path(painter, self.points_up, "#6366F1")
        painter.end()

    def _draw_path(self, painter, points, color_hex):
        painter.setPen(QPen(QColor(color_hex), 2))
        path = QPainterPath()
        if len(points) < 2:
            return
        step = (self.width() - 16) / max(10, len(points) - 1)
        for i, p in enumerate(points):
            x = 8 + i * step
            y = self.height() - (p / self.max_val * (self.height() - 20)) - 10
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)

        painter.drawPath(path)
        fill_color = QColor(color_hex)
        fill_color.setAlpha(30)
        path.lineTo(8 + (len(points) - 1) * step, self.height() - 2)
        path.lineTo(8, self.height() - 2)
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
        self._active_phase = ""
        self._closing = False
        self.db = DatabaseManager()

        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 18, 24, 18)
        outer.setSpacing(12)

        # Sticky Header
        header_layout = QHBoxLayout()
        header = QLabel(_("speed_title"))
        header.setObjectName("Title")
        header_layout.addWidget(header)
        header_layout.addStretch()

        self.start_btn = QPushButton(_("speed_start_test"))
        self.start_btn.setObjectName("PrimaryButton")
        self.start_btn.setMinimumSize(176, 38)
        self.start_btn.setCursor(Qt.PointingHandCursor)
        self.start_btn.clicked.connect(self.start_test)
        header_layout.addWidget(self.start_btn)
        outer.addLayout(header_layout)

        # Scrollable Body (eliminates vertical overflow on 768p/800p viewports)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll_content = QWidget()
        self.layout = QVBoxLayout(scroll_content)
        self.layout.setContentsMargins(0, 0, 8, 0)
        self.layout.setSpacing(12)

        # 1. Stats Display (Gauges)
        self.stats_container = QFrame()
        self.stats_container.setObjectName("PanelCard")
        stats_layout = QHBoxLayout(self.stats_container)
        stats_layout.setContentsMargins(14, 14, 14, 14)

        self.download_gauge = CircularGauge(_("speed_gauge_download"), "Mbps", "#10B981", 100)
        self.upload_gauge = CircularGauge(_("speed_gauge_upload"), "Mbps", "#6366F1", 100)
        self.latency_gauge = CircularGauge(_("speed_gauge_ping_label"), "ms", "#F59E0B", 200)
        self.jitter_gauge = CircularGauge(_("speed_gauge_jitter_label"), "ms", "#EC4899", 50)
        self.loss_gauge = CircularGauge(_("speed_gauge_loss_label"), "%", "#EF4444", 10)

        for g in (self.download_gauge, self.upload_gauge, self.latency_gauge, self.jitter_gauge, self.loss_gauge):
            stats_layout.addWidget(g, 1)
        self.layout.addWidget(self.stats_container)

        # 2. Live Chart
        self.graph = LiveGraph()
        self.layout.addWidget(self.graph)

        # 3. Info Bar (ISP, IP, Server)
        self.info_bar = QFrame()
        self.info_bar.setObjectName("PanelCard")
        self.info_bar.setMinimumHeight(74)
        info_layout = QHBoxLayout(self.info_bar)
        info_layout.setContentsMargins(16, 10, 16, 10)
        info_layout.setSpacing(18)

        self._info_labels = {}
        self.isp_label_layout = self._create_info_label("ISP", _("speed_info_isp"), _("speed_info_scanning"))
        self.ip_label_layout = self._create_info_label("PUBLIC IP", _("speed_info_ip"), _("speed_info_scanning"))

        self.server_btn = QPushButton(_("speed_auto_select_short"))
        self.server_btn.setObjectName("SecondaryButton")
        self.server_btn.setCursor(Qt.PointingHandCursor)
        self.server_btn.setMinimumWidth(240)
        self.server_btn.setStyleSheet("text-align: left; padding: 6px 14px; font-size: 12px;")
        self.server_btn.clicked.connect(self.open_server_selection)

        server_layout = QVBoxLayout()
        server_layout.setSpacing(3)
        s_title = QLabel(_("speed_info_server"))
        s_title.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: 700; margin-bottom: 0px;")
        server_layout.addWidget(s_title)
        server_layout.addWidget(self.server_btn)

        info_layout.addLayout(self.isp_label_layout, 1)
        info_layout.addLayout(self.ip_label_layout, 1)
        info_layout.addLayout(server_layout, 2)
        self.layout.addWidget(self.info_bar)

        counters = psutil.net_io_counters()
        self.last_recv = counters.bytes_recv if counters else 0
        self.last_sent = counters.bytes_sent if counters else 0
        self.last_time = time.time()

        # 4. History Table
        history_header_layout = QHBoxLayout()
        h_title = QLabel(_("speed_history_title"))
        h_title.setStyleSheet("font-weight: 700; font-size: 14px; margin-bottom: 0px;")
        history_header_layout.addWidget(h_title)
        history_header_layout.addStretch()

        self.clear_history_btn = QPushButton(_("speed_clear_history"))
        self.clear_history_btn.setObjectName("DangerButton")
        self.clear_history_btn.setCursor(Qt.PointingHandCursor)
        self.clear_history_btn.clicked.connect(self.clear_history)

        self.export_pdf_btn = QPushButton(_("speed_export_pdf"))
        self.export_pdf_btn.setObjectName("SecondaryButton")
        self.export_pdf_btn.setCursor(Qt.PointingHandCursor)
        self.export_pdf_btn.clicked.connect(self.export_pdf)

        history_header_layout.addWidget(self.clear_history_btn)
        history_header_layout.addWidget(self.export_pdf_btn)
        self.layout.addLayout(history_header_layout)

        self.history_table = QTableWidget(0, 6)
        self.history_table.setHorizontalHeaderLabels([
            _("speed_table_datetime"),
            _("speed_table_down"),
            _("speed_table_up"),
            _("speed_table_ping"),
            _("speed_table_jitter"),
            _("speed_table_loss"),
        ])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.history_table.setMinimumHeight(130)
        self.history_table.setMaximumHeight(190)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.verticalHeader().setDefaultSectionSize(32)
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.layout.addWidget(self.history_table)

        self.status_label = QLabel(_("speed_ready"))
        self.status_label.setStyleSheet("color: #94A3B8; font-size: 12px; margin-bottom: 0px;")
        self.layout.addWidget(self.status_label, alignment=Qt.AlignCenter)

        scroll.setWidget(scroll_content)
        outer.addWidget(scroll, 1)

        self.info_ready.connect(self.update_info_labels)

        self.load_history()
        self.quick_fetch_info()
        self.load_servers()

    def load_servers(self):
        self.server_list_worker = ServerListWorker()
        self.server_list_worker.status_update.connect(self._on_server_list_status)
        self.server_list_worker.servers_ready.connect(self.populate_servers)
        self.server_list_worker.finished.connect(self.server_list_worker.deleteLater)
        self.server_list_worker.start()

    def _on_server_list_status(self, status):
        if not self.worker or not self.worker.isRunning():
            self.status_label.setText(status)

    def populate_servers(self, servers):
        self.all_servers = servers
        if not self.worker or not self.worker.isRunning():
            if servers:
                self.status_label.setText(_("speed_servers_loaded").format(len(servers)))
                self.logger.info(f"Loaded {len(servers)} speedtest servers")
            else:
                self.status_label.setText(_("speed_discovery_limited"))
                self.logger.warning("Server list fetch returned empty results")

    def open_server_selection(self):
        dialog = ServerSelectionDialog(self.all_servers, self)
        if dialog.exec():
            server = dialog.get_selected_server()
            if server:
                self.selected_server_data = server
                self.server_btn.setText(f"{server.get('ui_name', server.get('name'))}")
            else:
                self.selected_server_data = None
                self.server_btn.setText(_("speed_auto_select_short"))

    def _create_info_label(self, key, display_title, val):
        layout = QVBoxLayout()
        layout.setSpacing(3)
        t = QLabel(display_title)
        t.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: 700; margin-bottom: 0px;")
        v = QLabel(val)
        v.setStyleSheet("color: #FFFFFF; font-size: 13px; font-weight: 700; margin-bottom: 0px;")
        layout.addWidget(t)
        layout.addWidget(v)
        self._info_labels[key] = v
        return layout

    def update_info_labels(self, info):
        if self._closing:
            return
        self._info_labels["ISP"].setText(info["isp"])
        self._info_labels["PUBLIC IP"].setText(info["ip"])

    def quick_fetch_info(self):
        from core.tools import NetworkTools
        import threading

        def _fetch():
            info = NetworkTools.get_fast_ip_info()
            if info and not self._closing:
                try:
                    self.info_ready.emit(info)
                except RuntimeError:
                    pass

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
        reply = QMessageBox.question(
            self, _("speed_confirm_clear_title"), _("speed_confirm_clear_msg"),
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.db.clear_speedtest_history()
            self.load_history()

    def export_pdf(self):
        history = self.db.get_speedtest_history(100)
        if not history:
            QMessageBox.warning(self, _("msg_warning"), _("speed_no_history"))
            return

        file_path, _filter = QFileDialog.getSaveFileName(
            self, _("speed_export_title"), "BahaaIT_Speedtest_Report.pdf", "PDF Files (*.pdf)"
        )
        if file_path:
            from utils.pdf_generator import PDFReportGenerator
            generator = PDFReportGenerator()
            success, msg = generator.generate_speedtest_report(history, file_path)
            if success:
                QMessageBox.information(self, _("msg_success"), _("speed_export_success"))
            else:
                QMessageBox.critical(self, _("msg_error"), _("speed_export_failed").format(msg))

    def start_test(self):
        if self.worker and self.worker.isRunning():
            return
        self.start_btn.setEnabled(False)
        self.start_btn.setText(_("speed_testing"))
        self.status_label.setText(_("speed_preparing"))
        self._active_phase = "preparing"
        for g in (self.download_gauge, self.upload_gauge, self.latency_gauge, self.jitter_gauge, self.loss_gauge):
            g.reset()
        self.graph.clear()

        self.worker = SpeedTestWorker(server_data=self.selected_server_data)
        self.worker.status_update.connect(self.update_status)
        self.worker.progress_update.connect(self.on_progress)
        self.worker.result_ready.connect(self.on_result)
        self.worker.finished.connect(self.on_finished)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.start()

        counters = psutil.net_io_counters()
        self.last_recv = counters.bytes_recv if counters else 0
        self.last_sent = counters.bytes_sent if counters else 0
        self.last_time = time.time()

        if not hasattr(self, "realtime_timer"):
            self.realtime_timer = QTimer(self)
            self.realtime_timer.timeout.connect(self.update_realtime_gauges)
        self.realtime_timer.start(200)

    def on_progress(self, val, type):
        if type == "down_done":
            self.download_gauge.setValue(val)
        elif type == "up_done":
            self.upload_gauge.setValue(val)

    def update_status(self, status):
        low = str(status).lower()
        if "download" in low or "télécharg" in low:
            self._active_phase = "download"
        elif "upload" in low or "envoi" in low:
            self._active_phase = "upload"
        elif "error" in low or "erreur" in low:
            self._active_phase = "error"
        self.status_label.setText(status)

    def on_result(self, data):
        self._active_phase = "done"
        self.download_gauge.setValue(data["download"])
        self.upload_gauge.setValue(data["upload"])
        self.latency_gauge.setValue(data["ping"])
        self.jitter_gauge.setValue(data["jitter"])
        self.loss_gauge.setValue(data["packet_loss"])

        self._info_labels["ISP"].setText(data["isp"])
        self._info_labels["PUBLIC IP"].setText(data["ip"])

        if self.selected_server_data is None:
            self.server_btn.setText(f"Auto: {data['server']}")

        self.db.save_speedtest(
            data["download"], data["upload"], data["ping"],
            data["jitter"], data["packet_loss"],
            data["server"], data["isp"],
        )
        self.load_history()

    def on_finished(self):
        if hasattr(self, "realtime_timer"):
            self.realtime_timer.stop()
        self.start_btn.setEnabled(True)
        self.start_btn.setText(_("speed_start_test"))

        if self._active_phase != "error":
            self.status_label.setText(_("speed_completed"))
        else:
            for g in (self.download_gauge, self.upload_gauge, self.latency_gauge, self.jitter_gauge, self.loss_gauge):
                g.reset()

    def update_realtime_gauges(self):
        if not self.worker or not self.worker.isRunning():
            return

        now = time.time()
        dt = now - self.last_time
        if dt <= 0:
            return

        counters = psutil.net_io_counters()
        if counters is None:
            return

        dl_mbps = (counters.bytes_recv - self.last_recv) * 8 / (1_000_000 * dt)
        ul_mbps = (counters.bytes_sent - self.last_sent) * 8 / (1_000_000 * dt)

        if self._active_phase == "download" and dl_mbps > 0.1:
            self.download_gauge.setValue(dl_mbps)
            self.graph.add_point(dl_mbps, "down")
        elif self._active_phase == "upload" and ul_mbps > 0.1:
            self.upload_gauge.setValue(ul_mbps)
            self.graph.add_point(ul_mbps, "up")

        self.last_recv = counters.bytes_recv
        self.last_sent = counters.bytes_sent
        self.last_time = now

    def shutdown(self):
        self._closing = True
        if hasattr(self, "realtime_timer"):
            self.realtime_timer.stop()
        if self.server_list_worker is not None and self.server_list_worker.isRunning():
            self.server_list_worker.wait(1000)
        if self.worker is not None and self.worker.isRunning():
            self.worker.wait(1500)
