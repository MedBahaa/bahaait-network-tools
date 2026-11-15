import os
import sys
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QProgressBar, QGraphicsDropShadowEffect
from PySide6.QtCore import Qt, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QPixmap, QColor, QPainter, QLinearGradient, QBrush, QPen, QFont, QPainterPath

class PremiumSplashScreen(QWidget):
    def __init__(self, logo_path=None):
        super().__init__()
        # Frameless, stays on top, tool window (doesn't show in taskbar)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        
        self.resize(500, 320)
        self.logo_path = logo_path
        self.fade_animation = None
        
        # Main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(35, 35, 35, 35)
        layout.setSpacing(10)
        
        # 1. Logo
        self.logo_label = QLabel()
        self.logo_label.setAlignment(Qt.AlignCenter)
        self.logo_label.setStyleSheet("background: transparent; margin-bottom: 5px;")
        if self.logo_path and os.path.exists(self.logo_path):
            pixmap = QPixmap(self.logo_path)
            self.logo_label.setPixmap(pixmap.scaled(80, 80, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        layout.addWidget(self.logo_label)
        
        # 2. Brand Title
        self.title_label = QLabel("Bahaa<span style='color: #6366F1;'>IT</span>")
        self.title_label.setFont(QFont("Outfit", 26, QFont.Bold))
        self.title_label.setStyleSheet("color: #FFFFFF; background: transparent; margin-bottom: 2px;")
        self.title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.title_label)
        
        # 3. Subtitle
        self.subtitle_label = QLabel("NETWORK TOOLS")
        self.subtitle_label.setFont(QFont("Inter", 9, QFont.Bold))
        self.subtitle_label.setStyleSheet("color: #06B6D4; letter-spacing: 5px; background: transparent; margin-bottom: 10px;")
        self.subtitle_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.subtitle_label)
        
        layout.addStretch()
        
        # 4. Status Text
        self.status_label = QLabel("Initialisation...")
        self.status_label.setFont(QFont("Inter", 9))
        self.status_label.setStyleSheet("color: #94A3B8; background: transparent; margin-bottom: 2px;")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)
        
        # 5. Glowing Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(5)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: rgba(255, 255, 255, 0.06);
                border: none;
                border-radius: 2.5px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                                            stop:0 #6366F1, stop:1 #06B6D4);
                border-radius: 2.5px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Center on screen
        self.center_on_screen()
        
        # Drop Shadow for "Floating" Look
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(30)
        shadow.setColor(QColor(0, 0, 0, 200))
        shadow.setOffset(0, 10)
        self.setGraphicsEffect(shadow)

    def center_on_screen(self):
        from PySide6.QtGui import QGuiApplication
        screen = QGuiApplication.primaryScreen().geometry()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)

    def paintEvent(self, event):
        # Draw premium rounded gradient card background
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        path = QPainterPath()
        path.addRoundedRect(0, 0, self.width(), self.height(), 16, 16)
        
        # Modern color scheme: Slate 950 to Midnight Blue
        gradient = QLinearGradient(0, 0, 0, self.height())
        gradient.setColorAt(0.0, QColor(11, 16, 30))
        gradient.setColorAt(1.0, QColor(7, 10, 19))
        
        painter.fillPath(path, QBrush(gradient))
        
        # Draw futuristic thin border gradient (Cyberpunk aura)
        border_pen = QPen()
        border_gradient = QLinearGradient(0, 0, self.width(), 0)
        border_gradient.setColorAt(0.0, QColor(99, 102, 241, 120))  # Glowing Indigo
        border_gradient.setColorAt(1.0, QColor(6, 182, 212, 120))   # Glowing Cyan
        border_pen.setBrush(QBrush(border_gradient))
        border_pen.setWidth(1.5)
        painter.setPen(border_pen)
        painter.drawRoundedRect(0.75, 0.75, self.width() - 1.5, self.height() - 1.5, 15.25, 15.25)

    def set_progress(self, value, message=None):
        self.progress_bar.setValue(value)
        if message:
            self.status_label.setText(message)
        # Force Qt event processing so the UI updates in the main thread
        from PySide6.QtWidgets import QApplication
        QApplication.processEvents()

    def show_splash(self):
        self.setWindowOpacity(0.0)
        self.show()
        
        self.fade_animation = QPropertyAnimation(self, b"windowOpacity")
        self.fade_animation.setDuration(350)
        self.fade_animation.setStartValue(0.0)
        self.fade_animation.setEndValue(1.0)
        self.fade_animation.setEasingCurve(QEasingCurve.OutCubic)
        self.fade_animation.start()

    def finish(self, main_window):
        # Graceful fade-out
        self.fade_animation = QPropertyAnimation(self, b"windowOpacity")
        self.fade_animation.setDuration(300)
        self.fade_animation.setStartValue(1.0)
        self.fade_animation.setEndValue(0.0)
        self.fade_animation.setEasingCurve(QEasingCurve.InCubic)
        
        def on_fade_out():
            self.close()
            # Show the main window and bring it to front
            main_window.show()
            main_window.raise_()
            main_window.activateWindow()
            
        self.fade_animation.finished.connect(on_fade_out)
        self.fade_animation.start()
