from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QFrame, QGridLayout, QScrollArea, QPushButton, QMessageBox)
from PySide6.QtCore import Qt, QTimer, QThread, Signal, QRectF
from PySide6.QtGui import QPainter, QColor, QPen, QPainterPath
import os

from core.service_checker import AdvancedServiceChecker
from utils.db import DatabaseManager

class Sparkline(QWidget):
    def __init__(self, history_data, parent=None):
        super().__init__(parent)
        self.history = history_data  # List of {"status": "UP", "latency": 50}
        self.setMinimumHeight(30)
        self.setMaximumHeight(30)

    def set_history(self, history):
        self.history = history
        self.update()

    def paintEvent(self, event):
        if not self.history:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        w = self.width()
        h = self.height()
        count = len(self.history)
        if count < 2: return

        # Draw bars for status
        bar_w = (w - (count - 1) * 2) / count
        for i, point in enumerate(self.history):
            status = point.get("status", "UNKNOWN")
            color = QColor("#10B981") if status == "UP" else QColor("#F59E0B") if status == "DEGRADED" else QColor("#F43F5E")
            
            x = i * (bar_w + 2)
            # Use 60% height for bars, centered vertically
            bar_h = h * 0.6
            y = (h - bar_h) / 2
            
            painter.setBrush(color)
            painter.setPen(Qt.NoPen)
            painter.drawRoundedRect(QRectF(x, y, bar_w, bar_h), 2, 2)

class ServiceWorker(QThread):
    # Returns: service_id, status_string
    status_ready = Signal(int, str) 

    def __init__(self, db):
        super().__init__()
        self.db = db

    def run(self):
        services = self.db.get_global_services()
        for svc in services:
            try:
                status, latency = AdvancedServiceChecker.check_service(svc["name"], svc["url"])
                # Log it to DB
                self.db.log_global_service(svc["id"], status, latency)
                # Emit the status
                self.status_ready.emit(svc["id"], status)
            except Exception as e:
                print(f"Error checking {svc['name']}: {e}")
                self.status_ready.emit(svc["id"], "UNKNOWN")

class ServiceStatusView(QWidget):
    service_alert = Signal(str, str) 

    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        self.db = DatabaseManager()
        self.cards = {} # Store UI elements by service_id
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(30, 30, 30, 30)
        self.layout.setSpacing(25)
        
        # Header
        header_container = QFrame()
        header_container.setStyleSheet("background: transparent;")
        header_layout = QHBoxLayout(header_container)
        header_layout.setContentsMargins(0, 0, 0, 0)
        
        title_vbox = QVBoxLayout()
        header = QLabel("GLOBAL STATUS")
        header.setObjectName("Title")
        header.setStyleSheet("font-size: 28px; letter-spacing: 1px;")
        
        subtitle = QLabel("Official Cloud & Enterprise Service Health")
        subtitle.setStyleSheet("color: #94A3B8; font-size: 14px; font-weight: 500;")
        
        title_vbox.addWidget(header)
        title_vbox.addWidget(subtitle)
        header_layout.addLayout(title_vbox)
        
        header_layout.addStretch()
        
        self.refresh_btn = QLabel("● LIVE")
        self.refresh_btn.setStyleSheet("color: #10B981; font-weight: 800; background: rgba(16, 185, 129, 0.1); padding: 8px 15px; border-radius: 10px; font-size: 11px;")
        header_layout.addWidget(self.refresh_btn, 0, Qt.AlignVCenter)
        
        self.layout.addWidget(header_container)
        
        # Note: Add Service Form removed per requirement "user ne peut pas ajouter une plateforme"
        
        # Scroll Area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setObjectName("StatusScrollArea")
        scroll.setStyleSheet("QScrollArea#StatusScrollArea { border: none; background: transparent; }")
        scroll.viewport().setStyleSheet("background: transparent;")
        
        self.container = QWidget()
        self.container.setObjectName("StatusContainer")
        self.container.setStyleSheet("QWidget#StatusContainer { background: transparent; }")
        self.grid = QGridLayout(self.container)
        self.grid.setSpacing(20)
        self.grid.setContentsMargins(0, 0, 0, 0)
        scroll.setWidget(self.container)
        self.layout.addWidget(scroll)
        
        self.setup_ui()
        
        # Auto-refresh timer
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_status)
        self.timer.start(60000) # Refresh every minute
        
        self.refresh_status()

    def setup_ui(self):
        # Clear existing layout
        while self.grid.count():
            item = self.grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
                
        self.cards.clear()
        
        services = self.db.get_global_services()
        
        cols = 3
        for i, svc in enumerate(services):
            card = QFrame()
            card.setObjectName("Card")
            card.setMinimumHeight(160)
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(25, 25, 25, 25)
            card_layout.setSpacing(15)
            
            # Header: Name
            n_label = QLabel(svc["name"].upper())
            n_label.setObjectName("SubTitle")
            n_label.setStyleSheet("letter-spacing: 1.5px; color: #6366F1; font-size: 11px; font-weight: 800;")
            card_layout.addWidget(n_label)
            
            # Status Row
            status_container = QHBoxLayout()
            status_container.setSpacing(12)
            
            dot = QLabel("●")
            dot.setStyleSheet("font-size: 20px; color: #334155;")
            
            s_label = QLabel("CHECKING...")
            s_label.setObjectName("ValueLabel")
            s_label.setStyleSheet("font-size: 22px; font-weight: 900; color: #F1F5F9;")
            
            status_container.addWidget(dot)
            status_container.addWidget(s_label)
            status_container.addStretch()
            card_layout.addLayout(status_container)
            
            # Sparkline
            history = self.db.get_global_service_history(svc["id"], limit=30)
            sparkline = Sparkline(history)
            card_layout.addWidget(sparkline)
            
            footer = QLabel("LATEST 30 CHECKS")
            footer.setStyleSheet("color: #475569; font-size: 9px; font-weight: 800; letter-spacing: 1px;")
            card_layout.addWidget(footer, 0, Qt.AlignRight)
            
            row, col = i // cols, i % cols
            self.grid.addWidget(card, row, col)
            
            last_status = history[-1]["status"] if history else "UNKNOWN"
            
            self.cards[svc["id"]] = {
                "name": svc["name"],
                "status_label": s_label, 
                "dot": dot, 
                "sparkline": sparkline,
                "last_status": last_status
            }
            
            if history:
                self._apply_status_style(s_label, dot, last_status)

    def _apply_status_style(self, label, dot, status):
        label.setText(status)
        if status == "UP":
            label.setStyleSheet("color: #10B981; font-weight: 900; font-size: 22px;")
            dot.setStyleSheet("color: #10B981; font-size: 20px;")
        elif status == "DEGRADED":
            label.setStyleSheet("color: #F59E0B; font-weight: 900; font-size: 22px;")
            dot.setStyleSheet("color: #F59E0B; font-size: 20px;")
        else: # DOWN / UNKNOWN
            label.setStyleSheet("color: #F43F5E; font-weight: 900; font-size: 22px;")
            dot.setStyleSheet("color: #F43F5E; font-size: 20px;")

    def refresh_status(self):
        self.refresh_btn.setText("● SYNCING...")
        self.refresh_btn.setStyleSheet("color: #F59E0B; font-weight: 800; background: rgba(245, 158, 11, 0.1); padding: 8px 15px; border-radius: 10px; font-size: 11px;")
        
        self.worker = ServiceWorker(self.db)
        self.worker.status_ready.connect(self.update_card)
        self.worker.finished.connect(self._on_refresh_finished)
        self.worker.start()

    def _on_refresh_finished(self):
        self.refresh_btn.setText("● LIVE")
        self.refresh_btn.setStyleSheet("color: #10B981; font-weight: 800; background: rgba(16, 185, 129, 0.1); padding: 8px 15px; border-radius: 10px; font-size: 11px;")

    def update_card(self, service_id, status):
        if service_id in self.cards:
            card_info = self.cards[service_id]
            
            # Alert if status changes from UP to DOWN/DEGRADED
            old_status = card_info["last_status"]
            if old_status == "UP" and status in ["DOWN", "DEGRADED"]:
                self.service_alert.emit(card_info["name"], status)
            
            card_info["last_status"] = status
            
            # Update history and sparkline
            history = self.db.get_global_service_history(service_id, limit=30)
            card_info["sparkline"].set_history(history)
            
            # Update labels
            self._apply_status_style(card_info["status_label"], card_info["dot"], status)

