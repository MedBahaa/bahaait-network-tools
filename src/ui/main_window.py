import os
import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QStackedWidget, QLabel, QFrame, QStatusBar,
    QGraphicsOpacityEffect, QScrollArea
)
from PySide6.QtCore import Qt, QSize, QTimer, QPropertyAnimation, QEasingCurve, Signal
from PySide6.QtGui import QIcon, QFont, QGuiApplication, QPixmap
from ui.widgets.dashboard_view import DashboardView
# The other views (Monitor, Tools, Scanner, Config, Settings, Speedtest, Browser, Remote, ServiceStatus, Sites) are lazy-loaded on demand.
from utils.config import ConfigManager
from ui.system_tray import SystemTrayManager
from utils.audio import AlarmManager
from utils.i18n import _, escape_qt_mnemonic

class MainWindow(QMainWindow):
    stats_updated = Signal(dict)

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
        self.stats_updated.connect(self.on_stats_updated)
        
        # Modern Frameless Resizable Setup
        self.setWindowFlags(
            Qt.Window
            | Qt.FramelessWindowHint
            | Qt.WindowSystemMenuHint
            | Qt.WindowMinimizeButtonHint
            | Qt.WindowMaximizeButtonHint
        )
        self.setAttribute(Qt.WA_TranslucentBackground)
        self._anim_widget = None
        
        self.setWindowTitle("BahaaIT Network Tools")
        
        screen = QGuiApplication.primaryScreen().availableGeometry()
        w = min(1340, screen.width())
        h = min(820, screen.height())
        min_w = min(1120, screen.width())
        min_h = min(680, screen.height())
        self.setMinimumSize(min_w, min_h)
        self.resize(w, h)
        
        # Center the window to avoid hiding taskbar or going out of bounds
        x = screen.x() + (screen.width() - w) // 2
        y = screen.y() + (screen.height() - h) // 2
        self.move(x, y)
        
        # Create central widget
        self.central_widget = QWidget()
        self.central_widget.setObjectName("MainContainer")
        self.central_widget.setProperty("maximized", False)
        self.setCentralWidget(self.central_widget)
        
        # Main layout (Vertical for Header + Content + Integrated Dark StatusBar)
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
        
        # Status Bar integrated directly inside rounded MainContainer
        self.status_bar = QStatusBar()
        self.status_bar.setSizeGripEnabled(True)
        self.status_bar.showMessage(_("main_ready"))
        
        self.root_layout.addWidget(self.header_frame)
        self.root_layout.addWidget(self.body_widget, 1)
        self.root_layout.addWidget(self.status_bar)
        
        self.load_stylesheet()
        self.setup_views()
        self.update_header_stats()
        
        # Setup background preloading queue for lazy-loaded tabs (Indices 1 to 18)
        self.tabs_to_preload = list(range(1, 19))
        # Start preloading 1.5s after showing main window (leaves CPU free for initial rendering)
        QTimer.singleShot(1500, self.preload_next_tab)

    def setup_header(self):
        self.header_frame = QFrame()
        self.header_frame.setObjectName("GlobalHeader")
        self.header_frame.setProperty("maximized", False)
        self.header_layout = QHBoxLayout(self.header_frame)
        self.header_layout.setContentsMargins(24, 6, 20, 6)
        
        if getattr(sys, 'frozen', False):
            base_dir = sys._MEIPASS
            logo_path = os.path.join(base_dir, "src", "assets", "logo.png")
        else:
            logo_path = os.path.join(os.path.dirname(__file__), "..", "assets", "logo.png")

        # Main Header Left side layout (Logo + vertical line divider + brand text + version pill)
        header_left_widget = QWidget()
        header_left_widget.setStyleSheet("background: transparent;")
        header_left_layout = QHBoxLayout(header_left_widget)
        header_left_layout.setContentsMargins(0, 0, 0, 0)
        header_left_layout.setSpacing(12)
        header_left_layout.setAlignment(Qt.AlignVCenter)
        
        if os.path.exists(logo_path):
            logo_label = QLabel()
            pixmap = QPixmap(logo_path)
            logo_label.setPixmap(pixmap.scaled(52, 52, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            header_left_layout.addWidget(logo_label)
            
        v_line = QFrame()
        v_line.setFrameShape(QFrame.VLine)
        v_line.setFrameShadow(QFrame.Plain)
        v_line.setFixedWidth(1)
        v_line.setFixedHeight(44)
        v_line.setStyleSheet("background-color: rgba(255, 255, 255, 0.15); border: none;")
        header_left_layout.addWidget(v_line)
        
        brand_container = QWidget()
        brand_container.setStyleSheet("background: transparent;")
        brand_layout = QVBoxLayout(brand_container)
        brand_layout.setContentsMargins(0, 0, 0, 0)
        brand_layout.setSpacing(2)
        brand_layout.setAlignment(Qt.AlignVCenter)
        
        top_label = QLabel("Bahaa<span style='color: #6366F1;'>IT</span>")
        top_label.setStyleSheet("font-size: 24px; font-weight: 900; color: #FFFFFF; font-family: 'Segoe UI', 'Inter', sans-serif;")
        
        line_container = QWidget()
        line_container.setFixedHeight(5)
        line_container.setFixedWidth(110)
        line_layout = QHBoxLayout(line_container)
        line_layout.setContentsMargins(0, 0, 0, 0)
        line_layout.setSpacing(0)
        
        line = QFrame()
        line.setFixedHeight(2)
        line.setStyleSheet("background-color: #06B6D4; border-radius: 1px;")
        
        dot = QFrame()
        dot.setFixedSize(5, 5)
        dot.setStyleSheet("background-color: #06B6D4; border-radius: 2px;")
        
        line_layout.addWidget(line, 1)
        line_layout.addWidget(dot, 0)
        
        bottom_label = QLabel("<span style='color: #06B6D4;'>Network</span> <span style='color: #6366F1;'>Tools</span>")
        bottom_label.setStyleSheet("font-size: 14px; font-weight: 700; font-family: 'Segoe UI', 'Inter', sans-serif;")
        
        brand_layout.addWidget(top_label)
        brand_layout.addWidget(line_container)
        brand_layout.addWidget(bottom_label)
        
        header_left_layout.addWidget(brand_container)
        
        from utils.updater import CURRENT_VERSION
        self.APP_VERSION = CURRENT_VERSION
        version_label = QLabel(self.APP_VERSION)
        version_label.setStyleSheet(
            "background-color: rgba(99, 102, 241, 0.16); color: #A5B4FC; "
            "border: 1px solid rgba(99, 102, 241, 0.38); border-radius: 6px; "
            "padding: 2px 8px; font-size: 11px; font-weight: 700;"
        )
        header_left_layout.addWidget(version_label, alignment=Qt.AlignVCenter)
        self.header_layout.addWidget(header_left_widget)
        
        self.header_layout.addStretch()
        
        # Quick Stats
        self.quick_stats = QHBoxLayout()
        self.quick_stats.setSpacing(24)
        
        self.hostname_stat = self._create_stat_widget("HOSTNAME", _("hostname", "HOSTNAME"), "Loading...")
        self.local_ip_stat = self._create_stat_widget("LOCAL IP", _("local_ip", "LOCAL IP"), "0.0.0.0")
        self.public_ip_stat = self._create_stat_widget("PUBLIC IP", _("public_ip", "PUBLIC IP"), "---.---.---.---")
        self.conn_stat = self._create_stat_widget("CONNECTION", _("connection", "CONNECTION"), "Checking...")
        self._header_labels["CONNECTION"].setMaximumWidth(195)
        self._header_labels["HOSTNAME"].setMaximumWidth(175)
        
        self.quick_stats.addLayout(self.conn_stat)
        self.quick_stats.addLayout(self.hostname_stat)
        self.quick_stats.addLayout(self.local_ip_stat)
        self.quick_stats.addLayout(self.public_ip_stat)
        
        self.header_layout.addLayout(self.quick_stats)
        self.header_layout.addSpacing(18)
        
        # Window Controls
        self.window_controls = QHBoxLayout()
        self.window_controls.setSpacing(6)
        
        self.min_btn = QPushButton("—")
        self.min_btn.setObjectName("WindowControl")
        self.min_btn.setFixedSize(30, 30)
        self.min_btn.setCursor(Qt.PointingHandCursor)
        self.min_btn.setToolTip(_("win_minimize_tip", "Minimize"))
        self.min_btn.clicked.connect(self.showMinimized)
        
        self.max_btn = QPushButton("□")
        self.max_btn.setObjectName("WindowControl")
        self.max_btn.setFixedSize(30, 30)
        self.max_btn.setCursor(Qt.PointingHandCursor)
        self.max_btn.setToolTip(_("win_maximize_tip", "Maximize"))
        self.max_btn.clicked.connect(self.toggle_maximize)
        
        self.close_btn = QPushButton("×")
        self.close_btn.setObjectName("WindowControlClose")
        self.close_btn.setFixedSize(30, 30)
        self.close_btn.setCursor(Qt.PointingHandCursor)
        self.close_btn.setToolTip(_("win_close_tip", "Close"))
        self.close_btn.clicked.connect(self.close)
        
        self.window_controls.addWidget(self.min_btn)
        self.window_controls.addWidget(self.max_btn)
        self.window_controls.addWidget(self.close_btn)
        self.header_layout.addLayout(self.window_controls)
        
        # Update quick stats periodically
        self.header_timer = QTimer(self)
        self.header_timer.timeout.connect(self.update_header_stats)
        self.header_timer.start(10000)

    def toggle_maximize(self):
        if self.isMaximized():
            self.showNormal()
            is_max = False
            self.max_btn.setText("□")
            self.max_btn.setToolTip(_("win_maximize_tip", "Maximize"))
        else:
            self.showMaximized()
            is_max = True
            self.max_btn.setText("❐")
            self.max_btn.setToolTip(_("win_restore_tip", "Restore Window"))
        for w in (self.central_widget, self.header_frame):
            w.setProperty("maximized", is_max)
            w.style().unpolish(w)
            w.style().polish(w)

    def _create_stat_widget(self, key, display_text, value):
        layout = QVBoxLayout()
        layout.setSpacing(2)
        l = QLabel(display_text)
        l.setObjectName("SubTitle")
        l.setStyleSheet("font-size: 10px; color: #94A3B8; font-weight: 700; margin-bottom: 0px;")
        v = QLabel(value)
        v.setStyleSheet("font-size: 13px; font-weight: 700; color: #FFFFFF; margin-bottom: 0px;")
        layout.addWidget(l)
        layout.addWidget(v)
        if not hasattr(self, "_header_labels"):
            self._header_labels = {}
        self._header_labels[key] = v
        return layout

    def on_stats_updated(self, data):
        self._header_labels["HOSTNAME"].setText(data["hostname"])
        self._header_labels["HOSTNAME"].setToolTip(data["hostname"])
        self._header_labels["LOCAL IP"].setText(data["local_ip"])
        self._header_labels["PUBLIC IP"].setText(data["public_ip"])
        self._header_labels["CONNECTION"].setText(data["conn_text"])
        self._header_labels["CONNECTION"].setToolTip(data["conn_text"])
        self._header_labels["CONNECTION"].setStyleSheet(
            f"font-size: 13px; font-weight: 700; color: {data['color']}; margin-bottom: 0px;"
        )

    def update_header_stats(self):
        import threading
        from core.tools import NetworkTools
        
        def _fetch_all():
            try:
                local_info = NetworkTools.get_local_info()
                pub_ip = NetworkTools.get_public_ip()
                conn_status = NetworkTools.get_connection_status()
                
                conn_text = f"{conn_status['ssid']} ({conn_status['signal']})" if conn_status['signal'] else conn_status['ssid']
                if conn_status['type'] == 'wifi':
                    conn_text = f"Wi-Fi: {conn_text}"
                    color = "#10B981"
                elif conn_status['type'] == 'ethernet':
                    conn_text = f"LAN: {conn_text}"
                    color = "#818CF8"
                else:
                    conn_text = _("main_offline")
                    color = "#EF4444"
                
                self.stats_updated.emit({
                    "hostname": local_info.get("hostname", "Unknown"),
                    "local_ip": local_info.get("local_ip", "0.0.0.0"),
                    "public_ip": pub_ip,
                    "conn_text": conn_text,
                    "color": color
                })
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error fetching header stats: {e}")

        threading.Thread(target=_fetch_all, daemon=True).start()

    def setup_sidebar(self):
        self.sidebar = QFrame()
        self.sidebar.setObjectName("Sidebar")
        outer_sidebar_layout = QVBoxLayout(self.sidebar)
        outer_sidebar_layout.setContentsMargins(0, 8, 0, 16)
        outer_sidebar_layout.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setStyleSheet("background: transparent;")

        scroll_container = QWidget()
        scroll_container.setStyleSheet("background: transparent;")
        self.sidebar_layout = QVBoxLayout(scroll_container)
        self.sidebar_layout.setContentsMargins(0, 6, 0, 20)
        self.sidebar_layout.setSpacing(8)
        
        self.nav_buttons = []
        self.page_nav_buttons = {}
        
        # Navigation Groups
        nav_groups = [
            (_("group_monitoring", "Monitoring"), [
                (_("nav_dashboard", "Dashboard"), 0, "dashboard.svg"),
                (_("nav_live_monitoring", "Live Monitoring"), 1, "activity.svg"),
                (_("nav_snmp_infra", "SNMP Infrastructure"), 11, "layers.svg"),
                (_("nav_syslog_monitor", "Syslog Monitor"), 12, "history.svg"),
                (_("nav_intelligence", "Network Intelligence"), 13, "chart.svg"),
                (_("nav_global_status", "Global Status"), 9, "globe.svg"),
            ]),
            (_("group_tools", "Tools"), [
                (_("nav_scanners", "Network Scanners"), 3, "search.svg"),
                (_("nav_toolbox", "IT Toolbox"), 2, "tool.svg"),
                (_("nav_speedtest", "Performance Test"), 6, "zap.svg"),
            ]),
            (_("group_management", "Management"), [
                (_("nav_web_manager", "Web Manager"), 7, "browser.svg"),
                (_("nav_remote", "Device Access Center"), 8, "terminal.svg"),
                (_("nav_sites", "Sites Manager"), 10, "layers.svg"),
            ]),
            (_("group_infrastructure", "Infrastructure"), [
                (_("nav_topology", "Network Topology"), 14, "globe.svg"),
                (_("nav_inventory", "Device Inventory"), 15, "layers.svg"),
                (_("nav_vlan_mgmt", "VLAN Management"), 16, "sliders.svg"),
                (_("nav_config_backup", "Config & Backups"), 17, "history.svg"),
                (_("nav_audit_trail", "Audit Trail"), 18, "activity.svg"),
            ]),
            (_("group_system", "System"), [
                (_("nav_net_config", "Network Config"), 4, "sliders.svg"),
                (_("nav_settings", "App Settings"), 5, "settings.svg"),
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
            self.sidebar_layout.addSpacing(4)
            
            for text, index, icon_name in items:
                btn = QPushButton("  " + escape_qt_mnemonic(text))
                btn.setCheckable(True)
                btn.setAutoExclusive(True)
                btn.setMinimumHeight(36)
                btn.setCursor(Qt.PointingHandCursor)
                
                # Set Icon
                icon_path = os.path.join(icons_dir, icon_name)
                if os.path.exists(icon_path):
                    btn.setIcon(QIcon(icon_path))
                
                if index == 0:
                    btn.setChecked(True)
                
                btn.setProperty("page_index", index)
                btn.clicked.connect(lambda checked, i=index: self.switch_page(i))
                self.sidebar_layout.addWidget(btn)
                self.nav_buttons.append(btn)
                self.page_nav_buttons[index] = btn
            
        self.sidebar_layout.addStretch()
        scroll.setWidget(scroll_container)
        outer_sidebar_layout.addWidget(scroll)
        
        self.body_layout.addWidget(self.sidebar)

    def _replace_placeholder(self, index, widget):
        placeholder = self.content_area.widget(index)
        self.content_area.removeWidget(placeholder)
        placeholder.deleteLater()
        self.content_area.insertWidget(index, widget)

    def load_tab_by_index(self, index):
        """Loads a tab by its index if not already loaded. Returns True if a load occurred."""
        if index == 1 and self.monitor is None:
            from ui.widgets.monitor_view import MonitorView
            self.monitor = MonitorView(
                self.logger,
                self.alarm_manager,
                self.config_manager,
                tray_manager=self.tray_manager,
            )
            self._replace_placeholder(1, self.monitor)
            return True
            
        elif index == 2 and self.tools is None:
            from ui.widgets.tools_view import ToolsView
            self.tools = ToolsView(self.logger)
            self._replace_placeholder(2, self.tools)
            return True
            
        elif index == 3 and self.scanner is None:
            from ui.widgets.scanner_view import ScannerView
            self.scanner = ScannerView(self.logger)
            self._replace_placeholder(3, self.scanner)
            return True
            
        elif index == 4 and self.config is None:
            from ui.widgets.config_view import ConfigView
            self.config = ConfigView(self.logger, self.config_manager)
            self._replace_placeholder(4, self.config)
            return True
            
        elif index == 5 and self.settings is None:
            from ui.widgets.settings_view import SettingsView
            self.settings = SettingsView(self.logger, self.alarm_manager, self.config_manager, self.auth_manager)
            self._replace_placeholder(5, self.settings)
            return True
            
        elif index == 6 and self.speedtest is None:
            from ui.widgets.speedtest_view import SpeedtestView
            self.speedtest = SpeedtestView(self.logger)
            self._replace_placeholder(6, self.speedtest)
            return True
            
        elif index == 7 and self.browser_view is None:
            from ui.widgets.browser_view import BrowserView
            self.browser_view = BrowserView(self.logger)
            self._replace_placeholder(7, self.browser_view)
            return True
            
        elif index == 8 and self.remote_view is None:
            from ui.widgets.remote_view import RemoteView
            self.remote_view = RemoteView(self.logger)
            self.remote_view.open_in_browser.connect(self._open_site_in_browser)
            self.remote_view.open_in_snmp.connect(self._open_ip_in_snmp)
            self._replace_placeholder(8, self.remote_view)
            return True
            
        elif index == 9 and self.service_status_view is None:
            from ui.widgets.service_status_view import ServiceStatusView
            self.service_status_view = ServiceStatusView(self.logger)
            self._replace_placeholder(9, self.service_status_view)
            return True
            
        elif index == 10 and self.sites_view is None:
            from ui.widgets.sites_view import SitesView
            self.sites_view = SitesView(self.logger, self.config_manager)
            self.sites_view.open_in_browser.connect(self._open_site_in_browser)
            self.sites_view.open_in_access_center.connect(self._open_device_in_access)
            self.sites_view.open_in_topology.connect(self._open_site_in_topology)
            self._replace_placeholder(10, self.sites_view)
            return True

        elif index == 11 and self.snmp_view is None:
            from ui.widgets.snmp_view import SNMPView
            self.snmp_view = SNMPView(self.logger, self.config_manager)
            self._replace_placeholder(11, self.snmp_view)
            return True

        elif index == 12 and self.syslog_view is None:
            from ui.widgets.syslog_view import SyslogView
            self.syslog_view = SyslogView(self.logger, self.config_manager)
            self._replace_placeholder(12, self.syslog_view)
            return True

        elif index == 13 and self.intelligence_view is None:
            from ui.widgets.intelligence_view import IntelligenceView
            self.intelligence_view = IntelligenceView(
                self.logger,
                self.config_manager,
                snmp_snapshots_provider=self._get_live_snmp_snapshots,
            )
            self._replace_placeholder(13, self.intelligence_view)
            return True

        elif index == 14 and self.topology_view is None:
            from ui.widgets.topology_view import TopologyView
            self.topology_view = TopologyView()
            self.topology_view.open_in_access_center.connect(self._open_device_in_access)
            self.topology_view.open_in_browser.connect(self._open_site_in_browser)
            self.topology_view.inventory_updated.connect(self._on_topology_inventory_updated)
            self._replace_placeholder(14, self.topology_view)
            return True

        elif index == 15 and self.inventory_view is None:
            from ui.widgets.inventory_view import InventoryView
            self.inventory_view = InventoryView(self.logger, self.config_manager, auth_manager=self.auth_manager)
            self.inventory_view.open_in_access_center.connect(self._open_device_in_access)
            self.inventory_view.open_in_topology.connect(self._open_device_in_topology)
            self._replace_placeholder(15, self.inventory_view)
            return True

        elif index == 16 and self.vlan_view is None:
            from ui.widgets.vlan_view import VLANView
            self.vlan_view = VLANView()
            self._replace_placeholder(16, self.vlan_view)
            return True

        elif index == 17 and self.backup_view is None:
            from ui.widgets.backup_view import BackupView
            self.backup_view = BackupView(config_manager=self.config_manager)
            self._replace_placeholder(17, self.backup_view)
            return True

        elif index == 18 and self.audit_view is None:
            from ui.widgets.audit_view import AuditView
            self.audit_view = AuditView(auth_manager=self.auth_manager)
            self._replace_placeholder(18, self.audit_view)
            return True
            
        return False

    def preload_next_tab(self):
        """Sequentially preloads tabs in the background when the main thread is idle."""
        if not hasattr(self, "tabs_to_preload") or not self.tabs_to_preload:
            return
            
        # Get the next tab to preload
        index = self.tabs_to_preload.pop(0)
        
        try:
            self.load_tab_by_index(index)
        except Exception as e:
            self.logger.error(f"Error preloading tab {index} in background: {e}")
            
        # Schedule the next preload after a 600ms delay to keep the UI perfectly smooth
        QTimer.singleShot(600, self.preload_next_tab)

    def switch_page(self, index):
        if self.content_area.currentIndex() == index:
            return
            
        # Load the tab immediately if not already preloaded
        self.load_tab_by_index(index)
        
        # Remove from preload queue if it is still there
        if hasattr(self, "tabs_to_preload") and index in self.tabs_to_preload:
            self.tabs_to_preload.remove(index)
            
        widget = self.content_area.widget(index)
        self.content_area.setCurrentIndex(index)
        
        if hasattr(self, "animation") and self.animation is not None:
            try:
                self.animation.stop()
            except Exception:
                pass
        if getattr(self, "_anim_widget", None) is not None:
            try:
                self._anim_widget.setGraphicsEffect(None)
            except Exception:
                pass
            self._anim_widget = None

        # Skip QGraphicsOpacityEffect on native/QGraphics surfaces (BrowserView / TopologyView)
        if index in (7, 14):
            return

        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)
        self._anim_widget = widget
        
        self.animation = QPropertyAnimation(effect, b"opacity", self)
        self.animation.setDuration(120)
        self.animation.setStartValue(0.65)
        self.animation.setEndValue(1.0)
        self.animation.setEasingCurve(QEasingCurve.InOutQuad)
        self.animation.finished.connect(lambda w=widget: (w.setGraphicsEffect(None), setattr(self, "_anim_widget", None)))
        self.animation.start()

    def _get_live_snmp_snapshots(self):
        if getattr(self, "snmp_view", None) is not None:
            return self.snmp_view.get_live_snapshots()
        return {}

    def setup_views(self):
        self.dashboard = DashboardView(self.logger, self.config_manager)
        
        # Lazy loaded views
        self.monitor = None
        self.tools = None
        self.scanner = None
        self.config = None
        self.settings = None
        self.speedtest = None
        self.browser_view = None
        self.remote_view = None
        self.service_status_view = None
        self.sites_view = None
        self.snmp_view = None
        self.syslog_view = None
        self.intelligence_view = None
        self.topology_view = None
        self.inventory_view = None
        self.vlan_view = None
        self.backup_view = None
        self.audit_view = None
        
        self.content_area.addWidget(self.dashboard)       # Index 0
        
        # Add placeholders for all lazy loaded screens (Indices 1 to 18)
        for _ in range(18):
            self.content_area.addWidget(QWidget())

    def _open_device_in_access(self, target, protocol: str = "SSH"):
        self.load_tab_by_index(8)
        if self.remote_view is not None:
            self.remote_view.open_device(target, protocol=protocol)
        self.switch_page(8)
        if 8 in self.page_nav_buttons:
            self.page_nav_buttons[8].setChecked(True)

    def _on_topology_inventory_updated(self):
        if getattr(self, "inventory_view", None) is not None and hasattr(self.inventory_view, "refresh"):
            self.inventory_view.refresh()
        if getattr(self, "sites_view", None) is not None and hasattr(self.sites_view, "refresh"):
            self.sites_view.refresh()

    def _open_site_in_topology(self, site_id: int):
        self.load_tab_by_index(14)
        if self.topology_view is not None:
            if hasattr(self.topology_view, "set_saved_scope"):
                self.topology_view.set_saved_scope()
            idx = self.topology_view.site_combo.findData(int(site_id))
            if idx >= 0:
                self.topology_view.site_combo.setCurrentIndex(idx)
            self.topology_view.refresh()
        self.switch_page(14)
        if 14 in self.page_nav_buttons:
            self.page_nav_buttons[14].setChecked(True)

    def _open_device_in_topology(self, device_id: int):
        self.load_tab_by_index(14)
        if self.topology_view is not None:
            if hasattr(self.topology_view, "set_saved_scope"):
                self.topology_view.set_saved_scope()
            self.topology_view.refresh()
            self.topology_view.canvas.select_device(int(device_id))
        self.switch_page(14)
        if 14 in self.page_nav_buttons:
            self.page_nav_buttons[14].setChecked(True)

    def _open_ip_in_snmp(self, _ip: str):
        self.load_tab_by_index(11)
        self.switch_page(11)
        if 11 in self.page_nav_buttons:
            self.page_nav_buttons[11].setChecked(True)

    def _open_site_in_browser(self, ip):
        """Switch to Web Manager and navigate to the given IP/URL."""
        url = ip.strip()
        if not url.startswith("http"):
            url = "http://" + url
            
        # Ensure browser view is lazy-loaded before using it
        if self.browser_view is None:
            from ui.widgets.browser_view import BrowserView
            self.browser_view = BrowserView(self.logger)
            self._replace_placeholder(7, self.browser_view)
            
        self.browser_view.address_bar.setText(url)
        self.browser_view.navigate()
        self.switch_page(7)
        # Update sidebar button state using page index mapping (7 = Web Manager)
        if 7 in self.page_nav_buttons:
            self.page_nav_buttons[7].setChecked(True)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and hasattr(self, "header_frame"):
            if self.header_frame.geometry().contains(event.position().toPoint()):
                if self.windowHandle() and hasattr(self.windowHandle(), "startSystemMove"):
                    self.windowHandle().startSystemMove()
                    event.accept()
                    return
                self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
                event.accept()
                return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if event.buttons() & Qt.LeftButton and getattr(self, "_drag_pos", None) is not None:
            self.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.LeftButton and hasattr(self, "header_frame"):
            if self.header_frame.geometry().contains(event.position().toPoint()):
                self.toggle_maximize()
                event.accept()
                return
        super().mouseDoubleClickEvent(event)

    def mouseReleaseEvent(self, event):
        self._drag_pos = None
        super().mouseReleaseEvent(event)

    def load_stylesheet(self):
        style_path = os.path.join(os.path.dirname(__file__), "styles.qss")
        if getattr(sys, "frozen", False):
            icons_dir = os.path.join(sys._MEIPASS, "assets", "icons")
        else:
            icons_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "assets", "icons"))
        icons_posix = icons_dir.replace("\\", "/")
        if os.path.exists(style_path):
            with open(style_path, "r", encoding="utf-8") as f:
                qss = f.read().replace("__ICONS_DIR__", icons_posix)
            app = QApplication.instance()
            if app is not None:
                app.setStyleSheet(qss)
            else:
                self.setStyleSheet(qss)

    def _cleanup_before_exit(self):
        """Cleanly stop timers, background threads, tray icon, and DB connections before exit."""
        try:
            if hasattr(self, "header_timer") and self.header_timer:
                self.header_timer.stop()
            if getattr(self, "dashboard", None) is not None:
                if hasattr(self.dashboard, "shutdown"):
                    self.dashboard.shutdown()
                elif hasattr(self.dashboard, "timer"):
                    self.dashboard.timer.stop()
            if getattr(self, "snmp_view", None) is not None:
                self.snmp_view.shutdown()
            if getattr(self, "syslog_view", None) is not None:
                self.syslog_view.shutdown()
            if getattr(self, "intelligence_view", None) is not None:
                self.intelligence_view.shutdown()
            if getattr(self, "monitor", None) is not None:
                if hasattr(self.monitor, "shutdown"):
                    self.monitor.shutdown()
                else:
                    self.monitor.stop_monitor()
            if getattr(self, "remote_view", None) is not None:
                if hasattr(self.remote_view, "shutdown"):
                    self.remote_view.shutdown()
                elif getattr(self.remote_view, "worker", None):
                    self.remote_view.disconnect()
            for attr_name in (
                "scanner", "tools", "speedtest", "settings", "service_status_view",
                "sites_view", "topology_view", "inventory_view", "vlan_view", "backup_view", "audit_view"
            ):
                v_obj = getattr(self, attr_name, None)
                if v_obj is not None and hasattr(v_obj, "shutdown"):
                    v_obj.shutdown()
            if getattr(self, "alarm_manager", None) is not None:
                self.alarm_manager.stop()
            if getattr(self, "tray_manager", None) is not None and getattr(self.tray_manager, "tray_icon", None):
                self.tray_manager.tray_icon.hide()
            if getattr(self, "dashboard", None) is not None and hasattr(self.dashboard, "db"):
                self.dashboard.db.engine.dispose()
            from PySide6.QtWidgets import QApplication
            app = QApplication.instance()
            if app and hasattr(app, "local_server") and app.local_server:
                app.local_server.close()
        except Exception:
            pass

    def closeEvent(self, event):
        if self._force_quit:
            self._cleanup_before_exit()
            event.accept()
            from PySide6.QtWidgets import QApplication
            QApplication.quit()
            return
            
        if self.config_manager.get("minimize_to_tray", False):
            event.ignore()
            self.hide()
            self.tray_manager.notify(_("tray_hidden_title"), _("tray_hidden_msg"))
        else:
            self._cleanup_before_exit()
            event.accept()
            from PySide6.QtWidgets import QApplication
            QApplication.quit()

    def quit_app(self):
        self._force_quit = True
        self.close()
