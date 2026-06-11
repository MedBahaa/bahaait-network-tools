from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel
from PySide6.QtCore import Qt
import pyqtgraph as pg

class LatencyGraphDialog(QDialog):
    def __init__(self, host, parent=None):
        super().__init__(parent)
        self.host = host
        self.history = []
        self.max_points = 60
        
        self.setWindowTitle(f"Latency History: {host}")
        self.setMinimumSize(600, 400)
        self.setStyleSheet("background-color: #1E293B;")
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 20, 20, 20)
        
        self.label = QLabel(f"Monitoring latency for {host}")
        self.label.setStyleSheet("font-size: 14px; font-weight: bold; color: #6366F1; margin-bottom: 10px;")
        self.layout.addWidget(self.label)
        
        # Setup PyQtGraph
        pg.setConfigOption('background', '#0F172A')
        pg.setConfigOption('foreground', '#94A3B8')
        
        self.graph_widget = pg.PlotWidget()
        self.graph_widget.setTitle(f"Real-time Latency (ms)", color='#F1F5F9', size='12pt')
        self.graph_widget.setLabel('left', 'Latency', units='ms', color='#F1F5F9')
        self.graph_widget.setLabel('bottom', 'Time (relative updates)', color='#F1F5F9')
        self.graph_widget.showGrid(x=True, y=True, alpha=0.3)
        self.graph_widget.setYRange(0, 100, padding=0.1) # Auto-scales upwards if needed
        self.graph_widget.setStyleSheet("border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px;")
        
        # Create a line reference
        pen = pg.mkPen(color='#10B981', width=2)
        # Using fillLevel for area chart effect
        self.line = self.graph_widget.plot(self.history, pen=pen, fillLevel=0, brush=(16, 185, 129, 50))
        
        self.layout.addWidget(self.graph_widget)
        
        self.stats_label = QLabel("Avg: 0ms | Max: 0ms")
        self.stats_label.setAlignment(Qt.AlignCenter)
        self.stats_label.setStyleSheet("color: #94A3B8; font-size: 12px; margin-top: 10px;")
        self.layout.addWidget(self.stats_label)

    def add_data(self, latency):
        self.history.append(latency)
        if len(self.history) > self.max_points:
            self.history.pop(0)
            
        self.line.setData(self.history)
        self.update_stats()

    def update_stats(self):
        if not self.history: return
        avg = sum(self.history) / len(self.history)
        mx = max(self.history)
        self.stats_label.setText(f"Avg: {avg:.1f}ms | Max: {mx}ms")
