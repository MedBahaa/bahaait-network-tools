from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel
from PySide6.QtCharts import QChart, QChartView, QLineSeries, QAreaSeries, QDateTimeAxis, QValueAxis
from PySide6.QtCore import Qt, QTimer, QDateTime, QPointF, QMargins
from PySide6.QtGui import QPainter, QPen, QColor, QLinearGradient, QGradient
import psutil
import time
from utils.i18n import _


class BandwidthChart(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(8)

        # Live speed indicators
        self.stats_layout = QHBoxLayout()
        self.dl_indicator = QLabel(f"{_('bw_download')}: 0.00 KB/s")
        self.dl_indicator.setStyleSheet("color: #10B981; font-weight: 700; font-size: 13px; margin-bottom: 0px;")
        self.ul_indicator = QLabel(f"{_('bw_upload')}: 0.00 KB/s")
        self.ul_indicator.setStyleSheet("color: #818CF8; font-weight: 700; font-size: 13px; margin-bottom: 0px;")
        self.stats_layout.addWidget(self.dl_indicator)
        self.stats_layout.addSpacing(20)
        self.stats_layout.addWidget(self.ul_indicator)
        self.stats_layout.addStretch()
        self.layout.addLayout(self.stats_layout)

        # Series Setup
        self.download_line = QLineSeries()
        self.download_area = QAreaSeries(self.download_line)
        self.download_area.setName(_("bw_download", "Download"))

        self.upload_line = QLineSeries()
        self.upload_area = QAreaSeries(self.upload_line)
        self.upload_area.setName(_("bw_upload", "Upload"))

        # Normalized ObjectBoundingMode gradients (0.0 -> 1.0, not pixel coordinates)
        dl_gradient = QLinearGradient(0.0, 0.0, 0.0, 1.0)
        dl_gradient.setColorAt(0.0, QColor(16, 185, 129, 130))
        dl_gradient.setColorAt(1.0, QColor(16, 185, 129, 8))
        dl_gradient.setCoordinateMode(QGradient.ObjectBoundingMode)
        self.download_area.setBrush(dl_gradient)
        self.download_area.setPen(QPen(QColor("#10B981"), 2))

        ul_gradient = QLinearGradient(0.0, 0.0, 0.0, 1.0)
        ul_gradient.setColorAt(0.0, QColor(99, 102, 241, 130))
        ul_gradient.setColorAt(1.0, QColor(99, 102, 241, 8))
        ul_gradient.setCoordinateMode(QGradient.ObjectBoundingMode)
        self.upload_area.setBrush(ul_gradient)
        self.upload_area.setPen(QPen(QColor("#6366F1"), 2))

        # Chart Setup
        self.chart = QChart()
        self.chart.addSeries(self.download_area)
        self.chart.addSeries(self.upload_area)
        self.chart.setBackgroundVisible(False)
        self.chart.setMargins(QMargins(4, 4, 4, 4))
        self.chart.layout().setContentsMargins(0, 0, 0, 0)
        self.chart.legend().hide()

        axis_pen = QPen(QColor("#334155"))
        grid_color = QColor(255, 255, 255, 20)

        # Axes
        self.axis_x = QDateTimeAxis()
        self.axis_x.setFormat("HH:mm:ss")
        self.axis_x.setTickCount(4)
        self.axis_x.setLabelsColor(QColor("#94A3B8"))
        self.axis_x.setLinePen(axis_pen)
        self.axis_x.setGridLineVisible(True)
        self.axis_x.setGridLineColor(grid_color)
        now_dt = QDateTime.currentDateTime()
        self.axis_x.setRange(now_dt.addSecs(-60), now_dt)
        self.chart.addAxis(self.axis_x, Qt.AlignBottom)
        self.download_area.attachAxis(self.axis_x)
        self.upload_area.attachAxis(self.axis_x)

        self.axis_y = QValueAxis()
        self.axis_y.setLabelFormat("%.1f")
        self.axis_y.setLabelsColor(QColor("#94A3B8"))
        self.axis_y.setTitleBrush(QColor("#94A3B8"))
        self.axis_y.setTitleText("KB/s")
        self.axis_y.setLinePen(axis_pen)
        self.axis_y.setGridLineVisible(True)
        self.axis_y.setGridLineColor(grid_color)
        self.axis_y.setRange(0.0, 10.0)
        self.chart.addAxis(self.axis_y, Qt.AlignLeft)
        self.download_area.attachAxis(self.axis_y)
        self.upload_area.attachAxis(self.axis_y)

        self.chart_view = QChartView(self.chart)
        self.chart_view.setRenderHint(QPainter.Antialiasing)
        self.chart_view.setStyleSheet("background-color: #0F172A; border-radius: 8px;")
        self.layout.addWidget(self.chart_view)

        # Data tracking (canonical storage in KB/s)
        counters = psutil.net_io_counters()
        self.last_recv = counters.bytes_recv if counters else 0
        self.last_sent = counters.bytes_sent if counters else 0
        self.last_time = time.time()
        self.max_points = 60
        self.unit = "KB/s"
        self.raw_history = []
        self.current_dl_mbps = 0.0
        self.current_ul_mbps = 0.0

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_data)
        self.timer.start(1000)

    def update_data(self):
        if not self.isVisible():
            return
        try:
            counters = psutil.net_io_counters()
            if counters is None:
                return
            current_recv = counters.bytes_recv
            current_sent = counters.bytes_sent
            current_time = time.time()

            elapsed = current_time - self.last_time
            if elapsed <= 0:
                return

            dl_speed_kb = max(0.0, (current_recv - self.last_recv) / 1024.0 / elapsed)
            ul_speed_kb = max(0.0, (current_sent - self.last_sent) / 1024.0 / elapsed)

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

            self.current_dl_mbps = dl_speed_kb * 8 / 1024.0
            self.current_ul_mbps = ul_speed_kb * 8 / 1024.0

            now = QDateTime.currentDateTime().toMSecsSinceEpoch()
            self.raw_history.append((now, dl_speed_kb, ul_speed_kb))
            if len(self.raw_history) > self.max_points:
                self.raw_history.pop(0)

            max_window_kb = max((max(d, u) for _, d, u in self.raw_history), default=0.0)
            chart_unit = "MB/s" if max_window_kb > 1024 else "KB/s"
            scale = (1.0 / 1024.0) if chart_unit == "MB/s" else 1.0

            if chart_unit != self.unit:
                self.unit = chart_unit
                self.download_line.replace([QPointF(ts, d * scale) for ts, d, _ in self.raw_history])
                self.upload_line.replace([QPointF(ts, u * scale) for ts, _, u in self.raw_history])
            else:
                self.download_line.append(now, dl_speed_kb * scale)
                self.upload_line.append(now, ul_speed_kb * scale)
                if self.download_line.count() > self.max_points:
                    self.download_line.remove(0)
                    self.upload_line.remove(0)

            self.axis_x.setRange(
                QDateTime.fromMSecsSinceEpoch(now - (self.max_points * 1000)),
                QDateTime.fromMSecsSinceEpoch(now),
            )
            max_val = max_window_kb * scale
            self.axis_y.setTitleText(chart_unit)
            default_min_top = 1.0 if chart_unit == "MB/s" else 10.0
            self.axis_y.setRange(0, max(max_val * 1.2, default_min_top))

            self.last_recv = current_recv
            self.last_sent = current_sent
            self.last_time = current_time
        except Exception:
            pass
