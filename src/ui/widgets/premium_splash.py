import os
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QProgressBar, QApplication
from PySide6.QtCore import Qt, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import (
    QPixmap, QColor, QPainter, QLinearGradient, QBrush, QPen, QFont, QPainterPath, QGuiApplication
)
from utils.i18n import _


class PremiumSplashScreen(QWidget):
    def __init__(self, logo_path=None):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)

        self.resize(500, 320)
        self.logo_path = logo_path
        self.fade_animation = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(35, 35, 35, 35)
        layout.setSpacing(10)

        # 1. Logo (only added if available)
        self.logo_label = QLabel()
        self.logo_label.setAlignment(Qt.AlignCenter)
        self.logo_label.setStyleSheet("background: transparent; margin-bottom: 4px;")
        if self.logo_path and os.path.exists(self.logo_path):
            pixmap = QPixmap(self.logo_path)
            self.logo_label.setPixmap(pixmap.scaled(80, 80, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            layout.addWidget(self.logo_label)
        else:
            self.logo_label.hide()

        # 2. Brand Title
        self.title_label = QLabel("Bahaa<span style='color: #6366F1;'>IT</span>")
        self.title_label.setFont(QFont("Segoe UI", 26, QFont.Bold))
        self.title_label.setStyleSheet("color: #FFFFFF; background: transparent; margin-bottom: 2px;")
        self.title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.title_label)

        # 3. Subtitle (real QFont letter spacing, supported by Qt)
        self.subtitle_label = QLabel("NETWORK TOOLS")
        sub_font = QFont("Segoe UI", 10, QFont.Bold)
        sub_font.setLetterSpacing(QFont.AbsoluteSpacing, 5)
        self.subtitle_label.setFont(sub_font)
        self.subtitle_label.setStyleSheet("color: #06B6D4; background: transparent; margin-bottom: 8px;")
        self.subtitle_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.subtitle_label)

        layout.addStretch()

        # 4. Status Text
        self.status_label = QLabel(_("splash_init", "Initializing..."))
        self.status_label.setFont(QFont("Segoe UI", 10))
        self.status_label.setWordWrap(True)
        self.status_label.setStyleSheet("color: #94A3B8; background: transparent; margin-bottom: 2px;")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

        # 5. Glowing Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: rgba(255, 255, 255, 0.08);
                border: none;
                border-radius: 3px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                            stop:0 #6366F1, stop:1 #06B6D4);
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.progress_bar)

        self.center_on_screen()

    def center_on_screen(self):
        primary = QGuiApplication.primaryScreen()
        if not primary:
            return
        screen = primary.availableGeometry()
        x = screen.x() + (screen.width() - self.width()) // 2
        y = screen.y() + (screen.height() - self.height()) // 2
        self.move(x, y)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        path = QPainterPath()
        path.addRoundedRect(1, 1, self.width() - 2, self.height() - 2, 16, 16)

        gradient = QLinearGradient(0, 0, 0, self.height())
        gradient.setColorAt(0.0, QColor(11, 16, 30))
        gradient.setColorAt(1.0, QColor(7, 10, 19))

        painter.fillPath(path, QBrush(gradient))

        border_pen = QPen()
        border_gradient = QLinearGradient(0, 0, self.width(), 0)
        border_gradient.setColorAt(0.0, QColor(99, 102, 241, 150))
        border_gradient.setColorAt(1.0, QColor(6, 182, 212, 150))
        border_pen.setBrush(QBrush(border_gradient))
        border_pen.setWidthF(1.5)
        painter.setPen(border_pen)
        painter.drawRoundedRect(1, 1, self.width() - 2, self.height() - 2, 16, 16)
        painter.end()

    def set_progress(self, value, message=None):
        self.progress_bar.setValue(value)
        if message:
            self.status_label.setText(message)
        QApplication.processEvents()

    def show_splash(self):
        self.setWindowOpacity(0.0)
        self.show()

        if self.fade_animation:
            self.fade_animation.stop()
        self.fade_animation = QPropertyAnimation(self, b"windowOpacity")
        self.fade_animation.setDuration(350)
        self.fade_animation.setStartValue(0.0)
        self.fade_animation.setEndValue(1.0)
        self.fade_animation.setEasingCurve(QEasingCurve.OutCubic)
        self.fade_animation.start()

    def finish(self, main_window):
        if self.fade_animation:
            try:
                self.fade_animation.stop()
            except Exception:
                pass
        start_op = self.windowOpacity()
        if start_op <= 0.0:
            start_op = 1.0

        self.fade_animation = QPropertyAnimation(self, b"windowOpacity")
        self.fade_animation.setDuration(280)
        self.fade_animation.setStartValue(start_op)
        self.fade_animation.setEndValue(0.0)
        self.fade_animation.setEasingCurve(QEasingCurve.InCubic)

        def on_fade_out():
            self.close()
            self.deleteLater()
            if main_window is not None:
                main_window.show()
                main_window.raise_()
                main_window.activateWindow()

        self.fade_animation.finished.connect(on_fade_out)
        self.fade_animation.start()
