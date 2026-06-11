from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QGridLayout
from PySide6.QtCore import Qt, QTimer
from core.tools import NetworkTools
from ui.widgets.bandwidth_chart import BandwidthChart

class DashboardView(QWidget):
    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(30, 30, 30, 30)
        self.layout.setSpacing(20)
        
        # Header
        header = QLabel("Network Dashboard")
        header.setObjectName("Title")
        self.layout.addWidget(header)
        
        # Real-time Bandwidth Chart
        chart_card = QFrame()
        chart_card.setObjectName("Card")
        chart_layout = QVBoxLayout(chart_card)
        chart_layout.setContentsMargins(30, 25, 30, 25)
        chart_layout.setSpacing(15)
        
        chart_header = QLabel("NETWORK THROUGHPUT")
        chart_header.setObjectName("SubTitle")
        chart_layout.addWidget(chart_header)
        
        self.bandwidth_chart = BandwidthChart()
        self.bandwidth_chart.setMinimumHeight(350) # Slightly taller for better readability
        chart_layout.addWidget(self.bandwidth_chart)
        
        self.layout.addWidget(chart_card)
        self.layout.addStretch()

    def update_info(self):
        pass
