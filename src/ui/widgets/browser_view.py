from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, 
                             QPushButton, QLabel, QProgressBar)
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWebEngineCore import QWebEnginePage
from PySide6.QtCore import QUrl, Qt

class WebPage(QWebEnginePage):
    def certificateError(self, error):
        # Force accept certificates for local/private network IPs
        url = error.url().toString()
        if any(x in url for x in ["192.168.", "10.", "172.16.", "localhost"]):
            error.acceptCertificate() # Modern way to bypass SSL errors
            return True
        return super().certificateError(error)

class BrowserView(QWidget):
    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        
        # Toolbar
        self.toolbar = QWidget()
        self.toolbar.setFixedHeight(50)
        self.toolbar.setStyleSheet("""
            background-color: #1E293B;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        """)
        self.toolbar_layout = QHBoxLayout(self.toolbar)
        self.toolbar_layout.setContentsMargins(8, 0, 8, 0)
        self.toolbar_layout.setSpacing(6)
        
        self.back_btn = QPushButton("‹")
        self.back_btn.setObjectName("BrowserNav")
        self.back_btn.setToolTip("Back")
        self.back_btn.setFixedSize(36, 36)
        
        self.forward_btn = QPushButton("›")
        self.forward_btn.setObjectName("BrowserNav")
        self.forward_btn.setToolTip("Forward")
        self.forward_btn.setFixedSize(36, 36)
        
        self.reload_btn = QPushButton("⟳")
        self.reload_btn.setObjectName("BrowserNav")
        self.reload_btn.setToolTip("Reload")
        self.reload_btn.setFixedSize(36, 36)
        
        self.address_bar = QLineEdit()
        self.address_bar.setObjectName("BrowserAddressBar")
        self.address_bar.setFixedHeight(34)
        self.address_bar.setStyleSheet("min-height: 34px; margin: 0px;")
        self.address_bar.setPlaceholderText("Enter URL (e.g. 192.168.1.1)...")
        self.address_bar.returnPressed.connect(self.navigate)
        
        self.go_btn = QPushButton("→")
        self.go_btn.setObjectName("BrowserNav")
        self.go_btn.setToolTip("Navigate")
        self.go_btn.setFixedSize(36, 36)
        self.go_btn.clicked.connect(self.navigate)
        
        self.fullscreen_btn = QPushButton("⛶")
        self.fullscreen_btn.setObjectName("BrowserNav")
        self.fullscreen_btn.setToolTip("Toggle Fullscreen")
        self.fullscreen_btn.setFixedSize(36, 36)
        self.fullscreen_btn.clicked.connect(self.toggle_fullscreen)
        
        self.toolbar_layout.addWidget(self.back_btn)
        self.toolbar_layout.addWidget(self.forward_btn)
        self.toolbar_layout.addWidget(self.reload_btn)
        self.toolbar_layout.addWidget(self.address_bar)
        self.toolbar_layout.addWidget(self.go_btn)
        self.toolbar_layout.addWidget(self.fullscreen_btn)
        
        self.layout.addWidget(self.toolbar)
        
        # Progress Bar (slim loading indicator, no spacing)
        self.progress = QProgressBar()
        self.progress.setMaximumHeight(2)
        self.progress.setTextVisible(False)
        self.progress.setContentsMargins(0, 0, 0, 0)
        self.progress.setStyleSheet("QProgressBar { border: none; background: transparent; margin: 0px; padding: 0px; } QProgressBar::chunk { background-color: #6366F1; }")
        self.layout.addWidget(self.progress)
        
        # Browser
        self.browser = QWebEngineView()
        self.page = WebPage(self.browser)
        self.browser.setPage(self.page)
        
        # Settings
        from PySide6.QtWebEngineCore import QWebEngineSettings
        self.browser.settings().setAttribute(QWebEngineSettings.ScrollAnimatorEnabled, True)
        self.browser.settings().setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, True)
        self.browser.settings().setAttribute(QWebEngineSettings.AllowRunningInsecureContent, True)
        
        self.layout.addWidget(self.browser)
        
        # Connect signals
        self.browser.urlChanged.connect(self.update_address_bar)
        self.browser.loadProgress.connect(self.progress.setValue)
        self.browser.loadFinished.connect(lambda: self.progress.setValue(0))
        self.back_btn.clicked.connect(self.browser.back)
        self.forward_btn.clicked.connect(self.browser.forward)
        self.reload_btn.clicked.connect(self.browser.reload)
        
        self.browser.setUrl(QUrl("https://www.google.com"))
        self.address_bar.setText("https://www.google.com")
        self.is_fullscreen = False

    def toggle_fullscreen(self):
        # Find main window to hide sidebar/header
        main_win = self.window()
        self.is_fullscreen = not self.is_fullscreen
        
        if hasattr(main_win, "sidebar"):
            main_win.sidebar.setVisible(not self.is_fullscreen)
        if hasattr(main_win, "header_frame"):
            main_win.header_frame.setVisible(not self.is_fullscreen)
        if hasattr(main_win, "body_layout"):
            main_win.body_layout.setContentsMargins(0, 0, 0, 0)
            
        # Adjust internal margins for true fullscreen look
        if self.is_fullscreen:
            self.toolbar_layout.setContentsMargins(5, 0, 5, 0)
            self.toolbar.setFixedHeight(44)
        else:
            self.toolbar_layout.setContentsMargins(8, 0, 8, 0)
            self.toolbar.setFixedHeight(50)

    def navigate(self):
        url = self.address_bar.text().strip()
        if not url.startswith("http"):
            # Check if it looks like an IP
            if url.replace(".", "").isdigit() or "localhost" in url:
                url = "http://" + url
            else:
                url = "https://" + url
        self.browser.setUrl(QUrl(url))

    def update_address_bar(self, q):
        self.address_bar.setText(q.toString())
