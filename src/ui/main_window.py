from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QStackedWidget, QLabel, QFrame, QStatusBar, QGraphicsOpacityEffect)
from PySide6.QtCore import Qt, QSize, QTimer, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QIcon, QFont
from ui.widgets.dashboard_view import DashboardView
from ui.widgets.monitor_view import MonitorView
from ui.widgets.tools_view import ToolsView
from ui.widgets.scanner_view import ScannerView
from ui.widgets.config_view import ConfigView
from ui.widgets.settings_view import SettingsView
from ui.widgets.speedtest_view import SpeedtestView
from ui.widgets.browser_view import BrowserView
from ui.widgets.remote_view import RemoteView
from ui.widgets.service_status_view import ServiceStatusView
from ui.widgets.sites_view import SitesView
from utils.config import ConfigManager
from ui.system_tray import SystemTrayManager
from utils.audio import AlarmManager

class MainWindow(QMainWindow):
    def __init__(self, logger, log_handler, auth_manager=None):
        super().__init__()
        self.logger = logger
        self.log_handler = log_handler
        self.auth_manager = auth_manager
        self.config_manager = ConfigManager()
        self.alarm_manager = AlarmManager()
        self.tray_manager = SystemTrayManager(self)
        self.tray_manager.show()
        self._force_quit = False
        
        # Modern Frameless Setup
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowSystemMenuHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        
        self.setWindowTitle("BahaaIT Network Tools")
        
        from PySide6.QtGui import QGuiApplication
        screen = QGuiApplication.primaryScreen().availableGeometry()
        w = min(1280, screen.width())
        h = min(800, screen.height())
        self.setFixedSize(w, h)
        
        # Center the window to avoid hiding taskbar or going out of bounds
        x = screen.x() + (screen.width() - w) // 2
        y = screen.y() + (screen.height() - h) // 2
        self.move(x, y)
        
        # Create central widget
        self.central_widget = QWidget()
        self.central_widget.setObjectName("MainContainer")
        self.setCentralWidget(self.central_widget)
        
        # Main layout (Vertical for Header + Content)
        self.root_layout = QVBoxLayout(self.central_widget)
        self.root_layout.setContentsMargins(0, 0, 0, 0)
        self.root_layout.setSpacing(0)
        
        # 1. Global Header
        self.setup_header()
        
        # 2. Main Content Area (Horizontal for Sidebar + Views)
        self.body_widget = QWidget()
        self.body_layout = QHBoxLayout(self.body_widget)
        self.body_layout.setContentsMargins(0, 0, 0, 0)
        self.body_layout.setSpacing(0)
        
        self.setup_sidebar()
        
        self.content_area = QStackedWidget()
        self.content_area.setObjectName("MainContent")
        self.body_layout.addWidget(self.content_area)
        
        self.root_layout.addWidget(self.header_frame)
        self.root_layout.addWidget(self.body_widget)
        
        # Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        self.load_stylesheet()
        self.setup_views()
        self.update_header_stats()

    def setup_header(self):
        self.header_frame = QFrame()
        self.header_frame.setObjectName("GlobalHeader")
        self.header_layout = QHBoxLayout(self.header_frame)
        self.header_layout.setContentsMargins(30, 0, 30, 0)
        
        # Logo/Brand
        from PySide6.QtGui import QPixmap
        import os
        import sys
        
        if getattr(sys, 'frozen', False):
            base_dir = sys._MEIPASS
            logo_path = os.path.join(base_dir, "src", "assets", "logo.png")
        else:
            base_dir = os.path.join(os.path.dirname(__file__), "..", "..")
            logo_path = os.path.join(os.path.dirname(__file__), "..", "assets", "logo.png")

        if os.path.exists(logo_path):
            logo_label = QLabel()
            pixmap = QPixmap(logo_path)
            logo_label.setPixmap(pixmap.scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            self.header_layout.addWidget(logo_label)
            
        brand = QLabel("BAHAA<span style='color: #6366F1;'>IT</span>")
        brand.setObjectName("LogoLabel")
        self.header_layout.addWidget(brand)
        
        # Application Version (Easy to update here)
        self.APP_VERSION = "v1.0.0"
        version_label = QLabel(self.APP_VERSION)
        version_label.setStyleSheet("color: #6366F1; font-size: 12px; font-weight: bold; margin-left: 5px; margin-bottom: 2px;")
        version_label.setAlignment(Qt.AlignBottom | Qt.AlignLeft)
        self.header_layout.addWidget(version_label)
        
        self.header_layout.addStretch()
        
        # Quick Stats
        self.quick_stats = QHBoxLayout()
        self.quick_stats.setSpacing(40)
        
        self.hostname_stat = self._create_stat_widget("HOSTNAME", "Loading...")
        self.local_ip_stat = self._create_stat_widget("LOCAL IP", "0.0.0.0")
        self.public_ip_stat = self._create_stat_widget("PUBLIC IP", "---.---.---.---")
        self.conn_stat = self._create_stat_widget("CONNECTION", "Checking...")
        
        self.quick_stats.addLayout(self.conn_stat)
        self.quick_stats.addLayout(self.hostname_stat)
        self.quick_stats.addLayout(self.local_ip_stat)
        self.quick_stats.addLayout(self.public_ip_stat)
        
        self.header_layout.addLayout(self.quick_stats)
        self.header_layout.addSpacing(20)
        
        # Window Controls
        self.window_controls = QHBoxLayout()
        self.window_controls.setSpacing(10)
        
        self.min_btn = QPushButton("—")
        self.min_btn.setObjectName("WindowControl")
        self.min_btn.setFixedSize(30, 30)
        self.min_btn.clicked.connect(self.showMinimized)
        
        self.close_btn = QPushButton("✕")
        self.close_btn.setObjectName("WindowControlClose")
        self.close_btn.setFixedSize(30, 30)
        self.close_btn.clicked.connect(self.close)
        
        self.window_controls.addWidget(self.min_btn)
        self.window_controls.addWidget(self.close_btn)
        self.header_layout.addLayout(self.window_controls)
        
        # Update quick stats periodically
        self.header_timer = QTimer(self)
        self.header_timer.timeout.connect(self.update_header_stats)
        self.header_timer.start(10000)

    def _create_stat_widget(self, label, value):
        layout = QVBoxLayout()
        layout.setSpacing(2)
        l = QLabel(label)
        l.setObjectName("SubTitle")
        l.setStyleSheet("font-size: 10px; color: #8f9bb3;")
        v = QLabel(value)
        v.setStyleSheet("font-size: 13px; font-weight: bold; color: #ffffff;")
        layout.addWidget(l)
        layout.addWidget(v)
        # Store ref to value label
        if not hasattr(self, "_header_labels"): self._header_labels = {}
        self._header_labels[label] = v
        return layout

    def update_header_stats(self):
        import threading
        from core.tools import NetworkTools
        
        def _fetch_all():
            # 1. Local Info
            local_info = NetworkTools.get_local_info()
            # 2. Public IP
            pub_ip = NetworkTools.get_public_ip()
            
            # 3. Connection Status
            conn_status = NetworkTools.get_connection_status()
            
            conn_text = f"{conn_status['ssid']} ({conn_status['signal']})" if conn_status['signal'] else conn_status['ssid']
            if conn_status['type'] == 'wifi':
                conn_text = f"📶 {conn_text}"
                color = "#10B981" # Green
            elif conn_status['type'] == 'ethernet':
                conn_text = f"🖧 {conn_text}"
                color = "#6366F1" # Blue
            else:
                conn_text = "❌ Offline"
                color = "#EF4444" # Red
            
            # Update UI (PySide6 allows simple setText from threads usually, 
            # but for safety we could use signals. Here we'll stick to direct for simplicity 
            # as it works well in most cases with these basic widgets)
            self._header_labels["HOSTNAME"].setText(local_info["hostname"])
            self._header_labels["LOCAL IP"].setText(local_info["local_ip"])
            self._header_labels["PUBLIC IP"].setText(pub_ip)
            self._header_labels["CONNECTION"].setText(conn_text)
            self._header_labels["CONNECTION"].setStyleSheet(f"font-size: 13px; font-weight: bold; color: {color};")
            
            if hasattr(self, "dashboard"):
                pass

        threading.Thread(target=_fetch_all, daemon=True).start()

    def setup_sidebar(self):
        self.sidebar = QFrame()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar_layout = QVBoxLayout(self.sidebar)
        self.sidebar_layout.setContentsMargins(0, 15, 0, 40)
        self.sidebar_layout.setSpacing(12)
        
        self.nav_buttons = []
        
        # Navigation Groups
        nav_groups = [
            ("Monitoring", [
                ("Dashboard", 0, "dashboard.svg"),
                ("Live Monitoring", 1, "activity.svg"),
                ("Global Status", 9, "globe.svg"),
            ]),
            ("Tools", [
                ("Network Scanners", 3, "search.svg"),
                ("IT Toolbox", 2, "tool.svg"),
                ("Performance Test", 6, "zap.svg"),
            ]),
            ("Management", [
                ("Web Manager", 7, "browser.svg"),
                ("Remote Terminal", 8, "terminal.svg"),
                ("Sites Manager", 10, "layers.svg"),
            ]),
            ("System", [
                ("Network Config", 4, "sliders.svg"),
                ("App Settings", 5, "settings.svg"),
            ])
        ]
        
        import os
        import sys
        
        if getattr(sys, 'frozen', False):
            icons_dir = os.path.join(sys._MEIPASS, "assets", "icons")
        else:
            icons_dir = os.path.join(os.path.dirname(__file__), "..", "..", "assets", "icons")
        
        for group_name, items in nav_groups:
            # Category Label
            cat_label = QLabel(group_name)
            cat_label.setObjectName("SidebarCategory")
            self.sidebar_layout.addWidget(cat_label)
            self.sidebar_layout.addSpacing(8) # Force physical spacing before first button
            
            for text, index, icon_name in items:
                btn = QPushButton("  " + text) # Ajout d'espaces pour décaler du bord/icône
                btn.setCheckable(True)
                btn.setAutoExclusive(True)
                btn.setMinimumHeight(45)
                btn.setCursor(Qt.PointingHandCursor)
                
                # Set Icon
                icon_path = os.path.join(icons_dir, icon_name)
                if os.path.exists(icon_path):
                    btn.setIcon(QIcon(icon_path))
                
                if index == 0:
                    btn.setChecked(True)
                
                btn.clicked.connect(lambda checked, i=index: self.switch_page(i))
                self.sidebar_layout.addWidget(btn)
                self.nav_buttons.append(btn)
            
        self.sidebar_layout.addStretch()
        
        self.body_layout.addWidget(self.sidebar)

    def switch_page(self, index):
        if self.content_area.currentIndex() == index:
            return
            
        widget = self.content_area.widget(index)
        self.content_area.setCurrentIndex(index)
        
        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)
        
        self.animation = QPropertyAnimation(effect, b"opacity")
        self.animation.setDuration(250)
        self.animation.setStartValue(0.0)
        self.animation.setEndValue(1.0)
        self.animation.setEasingCurve(QEasingCurve.InOutQuad)
        self.animation.start()

    def setup_views(self):
        self.dashboard = DashboardView(self.logger)
        self.monitor = MonitorView(self.logger, self.alarm_manager, self.config_manager)
        self.tools = ToolsView(self.logger)
        self.scanner = ScannerView(self.logger)
        self.config = ConfigView(self.logger, self.config_manager)
        self.settings = SettingsView(self.logger, self.alarm_manager, self.config_manager, self.auth_manager)
        self.speedtest = SpeedtestView(self.logger)
        self.browser_view = BrowserView(self.logger)
        self.remote_view = RemoteView(self.logger)
        self.service_status_view = ServiceStatusView(self.logger)
        self.service_status_view.service_alert.connect(
            lambda name, status: self.tray_manager.notify("Service Alert", f"Global Service '{name}' is currently {status}!")
        )
        self.sites_view = SitesView(self.logger, self.config_manager)
        self.sites_view.open_in_browser.connect(self._open_site_in_browser)
        
        self.content_area.addWidget(self.dashboard)       # Index 0
        self.content_area.addWidget(self.monitor)         # Index 1
        self.content_area.addWidget(self.tools)           # Index 2
        self.content_area.addWidget(self.scanner)         # Index 3
        self.content_area.addWidget(self.config)          # Index 4
        self.content_area.addWidget(self.settings)        # Index 5
        self.content_area.addWidget(self.speedtest)       # Index 6
        self.content_area.addWidget(self.browser_view)    # Index 7
        self.content_area.addWidget(self.remote_view)     # Index 8
        self.content_area.addWidget(self.service_status_view) # Index 9
        self.content_area.addWidget(self.sites_view)      # Index 10

    def _open_site_in_browser(self, ip):
        """Switch to Web Manager and navigate to the given IP/URL."""
        url = ip.strip()
        if not url.startswith("http"):
            url = "http://" + url
        self.browser_view.address_bar.setText(url)
        self.browser_view.navigate()
        self.switch_page(7)
        # Update sidebar button state
        for btn in self.nav_buttons:
            btn.setChecked(False)
        if len(self.nav_buttons) > 7:
            self.nav_buttons[7].setChecked(True)

    def load_stylesheet(self):
        import os
        style_path = os.path.join(os.path.dirname(__file__), "styles.qss")
        if os.path.exists(style_path):
            with open(style_path, "r") as f:
                self.setStyleSheet(f.read())

    def closeEvent(self, event):
        if self._force_quit:
            event.accept()
            import os
            os._exit(0)
            return
            
        if self.config_manager.get("minimize_to_tray", True):
            event.ignore()
            self.hide()
            self.tray_manager.notify("BahaaIT Hidden", "App is still running in the background.")
        else:
            event.accept()
            import os
            os._exit(0)

    def quit_app(self):
        self._force_quit = True
        self.close()
