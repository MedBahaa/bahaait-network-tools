from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QScrollArea
)
from PySide6.QtCore import Qt, QSize, Signal, QPropertyAnimation, QEasingCurve, Property
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtGui import QPixmap, QPainter, QColor, QKeySequence
from utils.i18n import _, TranslationManager
import os
import sys
import webbrowser


class ServiceCard(QFrame):
    def __init__(self, name, desc, url, logo_file, accent_color, assets_dir, parent=None):
        super().__init__(parent)
        self.url = url
        self.setObjectName("ServiceCard")
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.StrongFocus)
        self.setToolTip(url)
        self.setFrameShape(QFrame.StyledPanel)

        self.setMinimumWidth(240)
        self.setMaximumWidth(290)
        self.setMinimumHeight(250)
        self.setMaximumHeight(285)

        self.setStyleSheet("""
            #ServiceCard {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #1E293B, stop:1 #0F172A);
                border: 1px solid rgba(255, 255, 255, 0.08);
                border-radius: 16px;
            }
            #ServiceCard:hover, #ServiceCard:focus {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #232D3F, stop:1 #0F172A);
                border: 1px solid #6366F1;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 22)
        layout.setSpacing(14)

        icon_container = QHBoxLayout()
        self.icon_label = QLabel()
        self.icon_label.setFixedSize(64, 64)
        self.icon_label.setAlignment(Qt.AlignCenter)
        self.icon_label.setStyleSheet(
            "background: rgba(255, 255, 255, 0.04); border-radius: 12px; border: 1px solid rgba(255, 255, 255, 0.07);"
        )

        svg_path = os.path.join(assets_dir, logo_file)
        if os.path.exists(svg_path):
            try:
                with open(svg_path, "r", encoding="utf-8") as f:
                    svg_data = f.read()
                svg_data = svg_data.replace("<svg ", f'<svg fill="{accent_color}" ', 1)
                renderer = QSvgRenderer(svg_data.encode("utf-8"))
                pixmap = QPixmap(QSize(32, 32))
                pixmap.fill(Qt.transparent)
                painter = QPainter(pixmap)
                renderer.render(painter)
                painter.end()
                self.icon_label.setPixmap(pixmap)
            except Exception:
                pass

        icon_container.addWidget(self.icon_label)
        layout.addLayout(icon_container)

        self.title_label = QLabel(name)
        self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setStyleSheet("font-size: 18px; font-weight: 800; color: #F1F5F9; background: transparent; margin-bottom: 0px;")
        layout.addWidget(self.title_label)

        self.desc_label = QLabel(desc)
        self.desc_label.setAlignment(Qt.AlignCenter)
        self.desc_label.setWordWrap(True)
        self.desc_label.setStyleSheet("font-size: 12px; color: #94A3B8; font-weight: 400; background: transparent; margin-bottom: 0px;")
        layout.addWidget(self.desc_label, 1)

        action_layout = QHBoxLayout()
        action_layout.setSpacing(6)
        action_layout.setAlignment(Qt.AlignCenter)

        self.action_label = QLabel(_("svc_check_official", "Consulter"))
        self.action_label.setStyleSheet("font-size: 12px; font-weight: 700; color: #818CF8; background: transparent; margin-bottom: 0px;")
        arrow_lbl = QLabel("->")
        arrow_lbl.setStyleSheet("font-size: 12px; font-weight: 700; color: #818CF8; background: transparent; margin-bottom: 0px;")

        action_layout.addWidget(self.action_label)
        action_layout.addWidget(arrow_lbl)
        layout.addLayout(action_layout)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton and self.rect().contains(event.position().toPoint()):
            webbrowser.open(self.url)
        super().mouseReleaseEvent(event)

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key_Return, Qt.Key_Enter, Qt.Key_Space):
            webbrowser.open(self.url)
            event.accept()
            return
        super().keyPressEvent(event)


class PulsingDot(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(14, 14)
        self._pulse_alpha = 120

        self.anim = QPropertyAnimation(self, b"pulse_alpha", self)
        self.anim.setDuration(1200)
        self.anim.setStartValue(180)
        self.anim.setEndValue(30)
        self.anim.setEasingCurve(QEasingCurve.InOutQuad)
        self.anim.setLoopCount(-1)

    def get_pulse_alpha(self):
        return self._pulse_alpha

    def set_pulse_alpha(self, val):
        self._pulse_alpha = val
        self.update()

    pulse_alpha = Property(int, get_pulse_alpha, set_pulse_alpha)

    def showEvent(self, event):
        super().showEvent(event)
        if self.anim.state() != QPropertyAnimation.Running:
            self.anim.start()

    def hideEvent(self, event):
        if self.anim.state() == QPropertyAnimation.Running:
            self.anim.pause()
        super().hideEvent(event)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setBrush(QColor(16, 185, 129, self._pulse_alpha))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(0, 0, 14, 14)
        painter.setBrush(QColor(16, 185, 129, 255))
        painter.drawEllipse(3, 3, 8, 8)
        painter.end()


class ServiceStatusView(QWidget):
    service_alert = Signal(str, str)

    SERVICES = [
        {
            "name": "Apple",
            "desc": "iCloud, App Store, Apple Music, Apple TV+, iMessage...",
            "url_fr": "https://www.apple.com/fr/support/systemstatus/",
            "url_en": "https://www.apple.com/support/systemstatus/",
            "logo_file": "apple_logo.svg",
            "accent": "#A3AAAE",
        },
        {
            "name": "Netflix",
            "desc": "Streaming, Downloads, Accounts, Billing...",
            "url_fr": "https://help.netflix.com/fr/is-netflix-down",
            "url_en": "https://help.netflix.com/en/is-netflix-down",
            "logo_file": "netflix_logo.svg",
            "accent": "#E50914",
        },
        {
            "name": "PlayStation",
            "desc": "PSN, PS Store, Online Gaming, PS Plus...",
            "url_fr": "https://status.playstation.com/fr-FR/",
            "url_en": "https://status.playstation.com/en-US/",
            "logo_file": "playstation_logo.svg",
            "accent": "#006FCD",
        },
    ]

    def __init__(self, logger):
        super().__init__()
        self.logger = logger

        if getattr(sys, "frozen", False):
            self.assets_dir = os.path.join(sys._MEIPASS, "assets")
        else:
            path1 = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "assets"))
            path2 = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "assets"))
            self.assets_dir = path1 if os.path.exists(os.path.join(path1, "apple_logo.svg")) else path2

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(36, 36, 36, 36)
        self.layout.setSpacing(30)

        header_container = QFrame()
        header_container.setStyleSheet("background: transparent;")
        header_layout = QVBoxLayout(header_container)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(10)

        badge_container = QHBoxLayout()
        badge_container.setSpacing(8)
        badge_container.addStretch()

        self.pulse_dot = PulsingDot()
        badge_text = QLabel(_("svc_official_badge", "OFFICIAL PAGES"))
        badge_text.setStyleSheet("color: #818CF8; font-size: 11px; font-weight: 800; background: transparent; margin-bottom: 0px;")

        badge_container.addWidget(self.pulse_dot)
        badge_container.addWidget(badge_text)
        badge_container.addStretch()
        header_layout.addLayout(badge_container)

        title = QLabel(_("svc_title", "Services Status"))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 32px; font-weight: 900; color: #F1F5F9; margin-bottom: 0px;")
        header_layout.addWidget(title)

        subtitle = QLabel(_("svc_subtitle", "Real-time health status of official platform servers."))
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #94A3B8; font-size: 14px; font-weight: 400; margin-bottom: 0px;")
        header_layout.addWidget(subtitle)

        line_container = QHBoxLayout()
        line_container.addStretch()
        line = QFrame()
        line.setFixedSize(60, 3)
        line.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #6366F1, stop:1 #8B5CF6); border-radius: 1px;")
        line_container.addWidget(line)
        line_container.addStretch()
        header_layout.addLayout(line_container)

        self.layout.addWidget(header_container)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background: transparent;")
        scroll.viewport().setStyleSheet("background: transparent;")

        cards_widget = QWidget()
        cards_widget.setStyleSheet("background: transparent;")
        cards_layout = QHBoxLayout(cards_widget)
        cards_layout.setContentsMargins(0, 0, 0, 0)
        cards_layout.setSpacing(20)

        lang = TranslationManager().language
        cards_layout.addStretch()
        for svc in self.SERVICES:
            desc_key = f"svc_{svc['name'].lower()}_desc"
            url = svc["url_fr"] if lang == "fr" else svc["url_en"]
            card = ServiceCard(
                name=svc["name"],
                desc=_(desc_key, svc["desc"]),
                url=url,
                logo_file=svc["logo_file"],
                accent_color=svc["accent"],
                assets_dir=self.assets_dir,
                parent=self,
            )
            cards_layout.addWidget(card)
        cards_layout.addStretch()

        scroll.setWidget(cards_widget)
        self.layout.addWidget(scroll, 1)

    def shutdown(self) -> None:
        if hasattr(self, "pulse_dot") and self.pulse_dot is not None:
            self.pulse_dot.anim.stop()
