from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QFrame, QScrollArea)
from PySide6.QtCore import Qt, QSize, Signal, QPropertyAnimation, QEasingCurve, Property
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtGui import QPixmap, QPainter, QColor
from utils.i18n import _
import os
import sys
import webbrowser


class ServiceCard(QFrame):
    def __init__(self, name, desc, url, logo_file, accent_color, assets_dir, parent=None):
        super().__init__(parent)
        self.url = url
        self.accent_color = "#6366F1" # Uniform hover accent color
        
        self.setObjectName("ServiceCard")
        self.setCursor(Qt.PointingHandCursor)
        self.setFrameShape(QFrame.StyledPanel)
        
        # Consistent card size (centered and compact)
        self.setFixedWidth(260)
        self.setMinimumHeight(250)
        self.setMaximumHeight(270)
        
        # Initial stylesheet setup - all cards have the SAME visual styling
        self._apply_style(is_hovered=False)
        
        # Vertical Layout inside the card
        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(15)
        
        # 1. Icon Container at the top (centered)
        icon_container = QHBoxLayout()
        self.icon_label = QLabel()
        self.icon_label.setFixedSize(64, 64)
        self.icon_label.setAlignment(Qt.AlignCenter)
        self.icon_label.setStyleSheet("""
            background: rgba(255, 255, 255, 0.03);
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.05);
        """)
        
        # Render brand SVG onto QPixmap
        svg_path = os.path.join(assets_dir, logo_file)
        if os.path.exists(svg_path):
            try:
                with open(svg_path, "r", encoding="utf-8") as f:
                    svg_data = f.read()
                # Inject brand accent color for logo recognition
                svg_data = svg_data.replace("<svg ", f'<svg fill="{accent_color}" ', 1)
                renderer = QSvgRenderer(svg_data.encode("utf-8"))
                pixmap = QPixmap(QSize(30, 30))
                pixmap.fill(Qt.transparent)
                painter = QPainter(pixmap)
                renderer.render(painter)
                painter.end()
                self.icon_label.setPixmap(pixmap)
            except Exception as e:
                print(f"Error loading logo {logo_file}: {e}")
                
        icon_container.addWidget(self.icon_label)
        layout.addLayout(icon_container)
        
        # 2. Text layout (Title and Description wrapped and centered)
        self.title_label = QLabel(name)
        self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setStyleSheet("font-size: 18px; font-weight: 800; color: #F1F5F9; letter-spacing: 0.5px; background: transparent;")
        layout.addWidget(self.title_label)
        
        self.desc_label = QLabel(desc)
        self.desc_label.setAlignment(Qt.AlignCenter)
        self.desc_label.setWordWrap(True)
        self.desc_label.setStyleSheet("font-size: 12px; color: #94A3B8; font-weight: 400; line-height: 1.4; background: transparent;")
        layout.addWidget(self.desc_label, 1)
        
        # 3. Action Link & Arrow at the bottom (centered)
        action_layout = QHBoxLayout()
        action_layout.setSpacing(6)
        action_layout.setAlignment(Qt.AlignCenter)
        
        self.action_label = QLabel(_("svc_check_official", "Consulter"))
        self.action_label.setStyleSheet("font-size: 11px; font-weight: 700; color: #6366F1; letter-spacing: 0.5px; background: transparent;")
        
        self.arrow_label = QLabel("↗")
        self.arrow_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #6366F1; background: transparent;")
        
        action_layout.addWidget(self.action_label)
        action_layout.addWidget(self.arrow_label)
        layout.addLayout(action_layout)

    def _apply_style(self, is_hovered):
        if is_hovered:
            self.setStyleSheet("""
                #ServiceCard {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #232D3F, stop:1 #0F172A);
                    border: 1px solid #6366F1;
                    border-radius: 16px;
                }
            """)
        else:
            self.setStyleSheet("""
                #ServiceCard {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #1E293B, stop:1 #0F172A);
                    border: 1px solid rgba(255, 255, 255, 0.08);
                    border-radius: 16px;
                }
            """)

    def enterEvent(self, event):
        self._apply_style(is_hovered=True)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._apply_style(is_hovered=False)
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            webbrowser.open(self.url)

class PulsingDot(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(14, 14)
        self._pulse_alpha = 100
        
        # Animating the custom property "pulse_alpha"
        self.anim = QPropertyAnimation(self, b"pulse_alpha")
        self.anim.setDuration(1200)
        self.anim.setStartValue(180)
        self.anim.setEndValue(30)
        self.anim.setEasingCurve(QEasingCurve.InOutQuad)
        self.anim.setLoopCount(-1) # Infinite loop
        self.anim.start()

    def get_pulse_alpha(self):
        return self._pulse_alpha

    def set_pulse_alpha(self, val):
        self._pulse_alpha = val
        self.update() # Triggers repaint

    pulse_alpha = Property(int, get_pulse_alpha, set_pulse_alpha)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # 1. Draw outer ring with animated alpha
        outer_color = QColor(16, 185, 129, self._pulse_alpha)
        painter.setBrush(outer_color)
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(0, 0, 14, 14)
        
        # 2. Draw inner solid dot
        inner_color = QColor(16, 185, 129, 255)
        painter.setBrush(inner_color)
        painter.drawEllipse(3, 3, 8, 8)
        
        painter.end()


class ServiceStatusView(QWidget):
    service_alert = Signal(str, str)  # Preserved for compatibility

    SERVICES = [
        {
            "name": "Apple",
            "desc": "iCloud, App Store, Apple Music, Apple TV+, iMessage…",
            "url": "https://www.apple.com/fr/support/systemstatus/",
            "logo_file": "apple_logo.svg",
            "accent": "#A3AAAE",
        },
        {
            "name": "Netflix",
            "desc": "Streaming, Téléchargements, Comptes, Facturation…",
            "url": "https://help.netflix.com/fr/is-netflix-down",
            "logo_file": "netflix_logo.svg",
            "accent": "#E50914",
        },
        {
            "name": "PlayStation",
            "desc": "PSN, PS Store, Jeux en ligne, PS Plus, PS Now…",
            "url": "https://status.playstation.com/fr-FR/",
            "logo_file": "playstation_logo.svg",
            "accent": "#006FCD",
        },
    ]

    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        
        # Assets directory resolution (checking src/assets first, then root assets)
        if getattr(sys, 'frozen', False):
            self.assets_dir = os.path.join(sys._MEIPASS, "assets")
        else:
            path1 = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "assets"))
            path2 = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "assets"))
            if os.path.exists(os.path.join(path1, "apple_logo.svg")):
                self.assets_dir = path1
            else:
                self.assets_dir = path2
            
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(40, 40, 40, 40)
        self.layout.setSpacing(35)
        
        # Header / Title Block (Centralized)
        header_container = QFrame()
        header_container.setStyleSheet("background: transparent;")
        header_layout = QVBoxLayout(header_container)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(12)
        
        # 1. Badge "PAGES OFFICIELLES" (Centered)
        # 1. Badge "PAGES OFFICIELLES" (Centered, no border frame)
        badge_container = QHBoxLayout()
        badge_container.setSpacing(8)
        badge_container.addStretch()
        
        pulse_dot = PulsingDot()
        
        badge_text = QLabel(_("svc_official_badge", "PAGES OFFICIELLES"))
        badge_text.setStyleSheet("color: #818CF8; font-size: 10px; font-weight: 800; letter-spacing: 2px; background: transparent;")
        
        badge_container.addWidget(pulse_dot)
        badge_container.addWidget(badge_text)
        badge_container.addStretch()
        header_layout.addLayout(badge_container)
        
        # 2. Main Title (Centered)
        title = QLabel(_("svc_title", "État des Services"))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("""
            font-size: 34px;
            font-weight: 900;
            color: #F1F5F9;
            letter-spacing: -0.5px;
        """)
        header_layout.addWidget(title)
        
        # 3. Subtitle (Centered)
        subtitle = QLabel(_("svc_subtitle", "Consultez en temps réel l'état des serveurs et services des principales plateformes."))
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #64748B; font-size: 15px; font-weight: 400;")
        header_layout.addWidget(subtitle)
        
        # 4. Colored Line Separator (Centered)
        line_container = QHBoxLayout()
        line_container.addStretch()
        line = QFrame()
        line.setFixedSize(60, 3)
        line.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #6366F1, stop:1 #8B5CF6); border-radius: 1.5px;")
        line_container.addWidget(line)
        line_container.addStretch()
        header_layout.addLayout(line_container)
        
        self.layout.addWidget(header_container)
        
        # 5. Scroll Area & Cards Container (horizontal grid with 3 columns side-by-side, centered)
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
        
        # Add stretches to left and right to group cards in the center
        cards_layout.addStretch()
        for svc in self.SERVICES:
            desc_key = f"svc_{svc['name'].lower()}_desc"
            card = ServiceCard(
                name=svc["name"],
                desc=_(desc_key, svc["desc"]),
                url=svc["url"],
                logo_file=svc["logo_file"],
                accent_color=svc["accent"],
                assets_dir=self.assets_dir,
                parent=self
            )
            cards_layout.addWidget(card)
        cards_layout.addStretch()
            
        scroll.setWidget(cards_widget)
        
        self.layout.addWidget(scroll, 1)
