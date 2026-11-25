from PySide6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton
from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
import pyqtgraph as pg
from utils.i18n import _


class LatencyGraphDialog(QDialog):
    def __init__(self, host, parent=None):
        super().__init__(parent)
        self.host = host
        self.history = []
        self.max_points = 60

        self.setWindowTitle(_("lat_title").format(host))
        screen = QGuiApplication.primaryScreen()
        avail = screen.availableGeometry() if screen else None
        w = min(680, int(avail.width() * 0.85)) if avail else 640
        h = min(460, int(avail.height() * 0.80)) if avail else 420
        self.resize(w, h)
        self.setMinimumSize(520, 360)
        self.setStyleSheet("QDialog { background-color: #0F172A; }")

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(12)

        self.label = QLabel(_("lat_monitoring").format(host))
        self.label.setWordWrap(True)
        self.label.setStyleSheet("font-size: 14px; font-weight: 700; color: #818CF8; margin-bottom: 0px;")
        self.layout.addWidget(self.label)

        self.graph_widget = pg.PlotWidget()
        self.graph_widget.setBackground("#0B1220")
        self.graph_widget.setMenuEnabled(False)
        self.graph_widget.setTitle(_("lat_chart_title"), color="#F1F5F9", size="11pt")
        self.graph_widget.setLabel("left", _("lat_axis_latency"), units="ms", color="#CBD5E1")
        self.graph_widget.setLabel("bottom", _("lat_axis_time"), color="#CBD5E1")
        self.graph_widget.getAxis("bottom").setTextPen("#94A3B8")
        self.graph_widget.getAxis("left").setTextPen("#94A3B8")
        self.graph_widget.showGrid(x=True, y=True, alpha=0.25)
        self.graph_widget.enableAutoRange(axis="y", enable=True)

        pen = pg.mkPen(color="#10B981", width=2)
        self.line = self.graph_widget.plot([], [], pen=pen, fillLevel=0, brush=(16, 185, 129, 45))
        self.layout.addWidget(self.graph_widget, 1)

        footer = QHBoxLayout()
        footer.setSpacing(12)
        self.stats_label = QLabel(_("lat_stats_default"))
        self.stats_label.setStyleSheet("color: #94A3B8; font-size: 12px; margin-bottom: 0px;")
        footer.addWidget(self.stats_label, 1)

        close_btn = QPushButton(_("btn_close", "Close"))
        close_btn.setObjectName("SecondaryButton")
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.clicked.connect(self.accept)
        footer.addWidget(close_btn)
        self.layout.addLayout(footer)

    def add_data(self, latency):
        if latency is None:
            return
        try:
            val = float(latency)
        except (TypeError, ValueError):
            return
        self.history.append(val)
        if len(self.history) > self.max_points:
            self.history.pop(0)

        self.line.setData(list(range(len(self.history))), self.history)
        self.update_stats()

    def update_stats(self):
        if not self.history:
            return
        avg = sum(self.history) / len(self.history)
        mx = round(max(self.history), 1)
        self.stats_label.setText(_("lat_stats_summary").format(avg, mx))
