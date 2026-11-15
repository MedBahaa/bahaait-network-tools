from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel
from PySide6.QtCharts import QChart, QChartView, QLineSeries, QAreaSeries, QDateTimeAxis, QValueAxis
from PySide6.QtCore import Qt, QTimer, QDateTime, QPointF
from PySide6.QtGui import QPainter, QPen, QColor, QLinearGradient, QGradient
import psutil
import time
from utils.i18n import _

class BandwidthChart(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(10)

        # Live speed indicators
        self.stats_layout = QHBoxLayout()
        self.dl_indicator = QLabel(f"{_('bw_download')}: 0.00 KB/s")
        self.dl_indicator.setStyleSheet("color: #10B981; font-weight: bold; font-size: 14px;")
        self.ul_indicator = QLabel(f"{_('bw_upload')}: 0.00 KB/s")
        self.ul_indicator.setStyleSheet("color: #6366F1; font-weight: bold; font-size: 14px;")
        self.stats_layout.addWidget(self.dl_indicator)
        self.stats_layout.addSpacing(20)
        self.stats_layout.addWidget(self.ul_indicator)
        self.stats_layout.addStretch()
        self.layout.addLayout(self.stats_layout)

        # Series Setup
        self.download_line = QLineSeries()
        self.download_area = QAreaSeries(self.download_line)
        self.download_area.setName("Download")
        
        self.upload_line = QLineSeries()
        self.upload_area = QAreaSeries(self.upload_line)
        self.upload_area.setName("Upload")

        # Gradients
        dl_gradient = QLinearGradient(0, 0, 0, 400)
        dl_gradient.setColorAt(0.0, QColor(16, 185, 129, 150)) # #10B981 with alpha
        dl_gradient.setColorAt(1.0, QColor(16, 185, 129, 0))
        dl_gradient.setCoordinateMode(QGradient.ObjectBoundingMode)
        self.download_area.setBrush(dl_gradient)
        self.download_area.setPen(QPen(QColor("#10B981"), 2))

        ul_gradient = QLinearGradient(0, 0, 0, 400)
        ul_gradient.setColorAt(0.0, QColor(99, 102, 241, 150)) # #6366F1 with alpha
        ul_gradient.setColorAt(1.0, QColor(99, 102, 241, 0))
        ul_gradient.setCoordinateMode(QGradient.ObjectBoundingMode)
        self.upload_area.setBrush(ul_gradient)
        self.upload_area.setPen(QPen(QColor("#6366F1"), 2))

        # Chart Setup
        self.chart = QChart()
        self.chart.addSeries(self.download_area)
        self.chart.addSeries(self.upload_area)
        self.chart.setBackgroundVisible(False)
        self.chart.layout().setContentsMargins(0, 0, 0, 0)
        self.chart.legend().hide() # Hide legend for cleaner look, use indicators instead

        # Axes
        self.axis_x = QDateTimeAxis()
        self.axis_x.setFormat("HH:mm:ss")
        self.axis_x.setTickCount(5)
        self.axis_x.setLabelsColor(QColor("#94A3B8"))
        self.axis_x.setGridLineVisible(True)
        self.axis_x.setGridLineColor(QColor(255, 255, 255, 20))
        self.chart.addAxis(self.axis_x, Qt.AlignBottom)
        self.download_area.attachAxis(self.axis_x)
        self.upload_area.attachAxis(self.axis_x)

        self.axis_y = QValueAxis()
        self.axis_y.setLabelFormat("%.1f")
        self.axis_y.setLabelsColor(QColor("#94A3B8"))
        self.axis_y.setGridLineVisible(True)
        self.axis_y.setGridLineColor(QColor(255, 255, 255, 20))
        self.chart.addAxis(self.axis_y, Qt.AlignLeft)
        self.download_area.attachAxis(self.axis_y)
        self.upload_area.attachAxis(self.axis_y)

        self.chart_view = QChartView(self.chart)
        self.chart_view.setRenderHint(QPainter.Antialiasing)
        self.chart_view.setStyleSheet("background: transparent;")
        self.layout.addWidget(self.chart_view)

        # Data tracking (canonical storage in KB/s to avoid unit-mixing)
        self.last_recv = psutil.net_io_counters().bytes_recv
        self.last_sent = psutil.net_io_counters().bytes_sent
        self.last_time = time.time()
        self.max_points = 60
        self.unit = "KB/s"
        self.raw_history = []  # List of (timestamp_ms, dl_kb, ul_kb)
        self.current_dl_mbps = 0.0
        self.current_ul_mbps = 0.0

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_data)
        self.timer.start(1000)

    def update_data(self):
        try:
            counters = psutil.net_io_counters()
            current_recv = counters.bytes_recv
            current_sent = counters.bytes_sent
            current_time = time.time()
            
            elapsed = current_time - self.last_time
            if elapsed <= 0:
                return

            # Calculate speeds in KB/s
            dl_speed_kb = max(0.0, (current_recv - self.last_recv) / 1024.0 / elapsed)
            ul_speed_kb = max(0.0, (current_sent - self.last_sent) / 1024.0 / elapsed)
            
            # Determine display unit for live indicators
            max_current = max(dl_speed_kb, ul_speed_kb)
            if max_current > 1024:
                ind_unit = "MB/s"
                dl_ind = dl_speed_kb / 1024.0
                ul_ind = ul_speed_kb / 1024.0
            else:
                ind_unit = "KB/s"
                dl_ind = dl_speed_kb
                ul_ind = ul_speed_kb

            self.dl_indicator.setText(f"{_('bw_download')}: {dl_ind:.2f} {ind_unit}")
            self.ul_indicator.setText(f"{_('bw_upload')}: {ul_ind:.2f} {ind_unit}")
            
            # Store for external access (in Mbps for gauges)
            self.current_dl_mbps = dl_speed_kb * 8 / 1024.0
            self.current_ul_mbps = ul_speed_kb * 8 / 1024.0
            
            now = QDateTime.currentDateTime().toMSecsSinceEpoch()
            self.raw_history.append((now, dl_speed_kb, ul_speed_kb))
            if len(self.raw_history) > self.max_points:
                self.raw_history.pop(0)

            # Determine consistent unit across the entire visible chart window
            max_window_kb = max(( max(d, u) for _, d, u in self.raw_history ), default=0.0)
            chart_unit = "MB/s" if max_window_kb > 1024 else "KB/s"
            scale = (1.0 / 1024.0) if chart_unit == "MB/s" else 1.0

            if chart_unit != self.unit:
                # Rescale all historical points to the new unit so units never mix
                self.unit = chart_unit
                self.download_line.replace([QPointF(ts, d * scale) for ts, d, _ in self.raw_history])
                self.upload_line.replace([QPointF(ts, u * scale) for ts, _, u in self.raw_history])
            else:
                self.download_line.append(now, dl_speed_kb * scale)
                self.upload_line.append(now, ul_speed_kb * scale)
                if self.download_line.count() > self.max_points:
                    self.download_line.remove(0)
                    self.upload_line.remove(0)

            # Update X Axis Range
            self.axis_x.setRange(QDateTime.fromMSecsSinceEpoch(now - (self.max_points * 1000)), 
                                QDateTime.fromMSecsSinceEpoch(now))
            
            # Dynamic Y Axis Range in consistent chart_unit
            max_val = max_window_kb * scale
            self.axis_y.setTitleText(chart_unit)
            default_min_top = 1.0 if chart_unit == "MB/s" else 10.0
            self.axis_y.setRange(0, max(max_val * 1.2, default_min_top))

            self.last_recv = current_recv
            self.last_sent = current_sent
            self.last_time = current_time
        except Exception as e:
            print(f"Chart update error: {e}")
