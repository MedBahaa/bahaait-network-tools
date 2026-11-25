import ipaddress
import re
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineSettings
from PySide6.QtCore import QUrl, Qt
from PySide6.QtGui import QKeySequence, QShortcut
from utils.i18n import _


class WebPage(QWebEnginePage):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.certificateError.connect(self._on_certificate_error)

    def _on_certificate_error(self, error):
        # Accept self-signed certificates for local/private RFC1918 network equipment
        host = (error.url().host() or "").strip().lower()
        is_local = host in ("localhost", "127.0.0.1", "::1")
        if not is_local and host:
            try:
                ip_obj = ipaddress.ip_address(host)
                is_local = ip_obj.is_private or ip_obj.is_loopback
            except ValueError:
                is_local = False
        if is_local:
            error.acceptCertificate()
        else:
            error.rejectCertificate()


class BrowserView(QWidget):
    DEFAULT_URL = "https://www.google.com"

    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        self._initial_loaded = False
        self._pending_url = self.DEFAULT_URL
        self._saved_body_margins = None

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)

        # Toolbar (scoped QFrame prevents stylesheet bleed to children)
        self.toolbar = QFrame()
        self.toolbar.setObjectName("BrowserToolbar")
        self.toolbar.setFixedHeight(52)
        self.toolbar.setStyleSheet(
            "#BrowserToolbar { background-color: #1E293B; border-bottom: 1px solid rgba(255, 255, 255, 0.08); }"
        )
        self.toolbar_layout = QHBoxLayout(self.toolbar)
        self.toolbar_layout.setContentsMargins(10, 0, 10, 0)
        self.toolbar_layout.setSpacing(6)

        self.back_btn = QPushButton("<")
        self.back_btn.setObjectName("BrowserNav")
        self.back_btn.setToolTip(_("browser_tooltip_back"))
        self.back_btn.setFixedSize(36, 36)
        self.back_btn.setCursor(Qt.PointingHandCursor)
        self.back_btn.setEnabled(False)

        self.forward_btn = QPushButton(">")
        self.forward_btn.setObjectName("BrowserNav")
        self.forward_btn.setToolTip(_("browser_tooltip_forward"))
        self.forward_btn.setFixedSize(36, 36)
        self.forward_btn.setCursor(Qt.PointingHandCursor)
        self.forward_btn.setEnabled(False)

        self.reload_btn = QPushButton("↻")
        self.reload_btn.setObjectName("BrowserNav")
        self.reload_btn.setToolTip(_("browser_tooltip_reload"))
        self.reload_btn.setFixedSize(36, 36)
        self.reload_btn.setCursor(Qt.PointingHandCursor)

        self.address_bar = QLineEdit()
        self.address_bar.setObjectName("BrowserAddressBar")
        self.address_bar.setFixedHeight(36)
        self.address_bar.setStyleSheet("min-height: 36px; margin: 0px;")
        self.address_bar.setPlaceholderText(_("browser_url_placeholder"))
        self.address_bar.returnPressed.connect(self.navigate)

        self.go_btn = QPushButton("->")
        self.go_btn.setObjectName("BrowserNav")
        self.go_btn.setToolTip(_("browser_tooltip_navigate"))
        self.go_btn.setFixedSize(36, 36)
        self.go_btn.setCursor(Qt.PointingHandCursor)
        self.go_btn.clicked.connect(self.navigate)

        self.fullscreen_btn = QPushButton("⛶")
        self.fullscreen_btn.setObjectName("BrowserNav")
        self.fullscreen_btn.setToolTip(_("browser_tooltip_fullscreen"))
        self.fullscreen_btn.setFixedSize(36, 36)
        self.fullscreen_btn.setCursor(Qt.PointingHandCursor)
        self.fullscreen_btn.clicked.connect(self.toggle_fullscreen)

        self.toolbar_layout.addWidget(self.back_btn)
        self.toolbar_layout.addWidget(self.forward_btn)
        self.toolbar_layout.addWidget(self.reload_btn)
        self.toolbar_layout.addWidget(self.address_bar, 1)
        self.toolbar_layout.addWidget(self.go_btn)
        self.toolbar_layout.addWidget(self.fullscreen_btn)

        self.layout.addWidget(self.toolbar)

        # Progress Bar (hidden when idle)
        self.progress = QProgressBar()
        self.progress.setMaximumHeight(2)
        self.progress.setTextVisible(False)
        self.progress.setContentsMargins(0, 0, 0, 0)
        self.progress.setStyleSheet(
            "QProgressBar { border: none; background: transparent; margin: 0px; padding: 0px; }"
            "QProgressBar::chunk { background-color: #6366F1; }"
        )
        self.progress.setVisible(False)
        self.layout.addWidget(self.progress)

        # Browser
        self.browser = QWebEngineView()
        self.page = WebPage(self.browser)
        self.browser.setPage(self.page)

        settings = self.browser.settings()
        settings.setAttribute(QWebEngineSettings.ScrollAnimatorEnabled, True)
        settings.setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, True)
        settings.setAttribute(QWebEngineSettings.AllowRunningInsecureContent, True)

        self.layout.addWidget(self.browser, 1)

        # Connect signals
        self.browser.urlChanged.connect(self.update_address_bar)
        self.browser.loadStarted.connect(self._on_load_started)
        self.browser.loadProgress.connect(self.progress.setValue)
        self.browser.loadFinished.connect(self._on_load_finished)
        self.back_btn.clicked.connect(self.browser.back)
        self.forward_btn.clicked.connect(self.browser.forward)
        self.reload_btn.clicked.connect(self.browser.reload)

        self._esc_shortcut = QShortcut(QKeySequence(Qt.Key_Escape), self)
        self._esc_shortcut.activated.connect(self._exit_fullscreen_if_active)

        self.address_bar.setText(self.DEFAULT_URL)
        self.is_fullscreen = False

    def showEvent(self, event):
        super().showEvent(event)
        if not self._initial_loaded:
            self._initial_loaded = True
            self.browser.setUrl(QUrl(self._pending_url))

    def hideEvent(self, event):
        self._exit_fullscreen_if_active()
        super().hideEvent(event)

    def _on_load_started(self):
        self.progress.setValue(10)
        self.progress.setVisible(True)

    def _on_load_finished(self, _ok):
        self.progress.setValue(0)
        self.progress.setVisible(False)
        self._update_nav_buttons()

    def _update_nav_buttons(self):
        history = self.browser.history()
        self.back_btn.setEnabled(history.canGoBack())
        self.forward_btn.setEnabled(history.canGoForward())

    def _exit_fullscreen_if_active(self):
        if self.is_fullscreen:
            self.toggle_fullscreen()

    def toggle_fullscreen(self):
        main_win = self.window()
        self.is_fullscreen = not self.is_fullscreen

        if hasattr(main_win, "sidebar"):
            main_win.sidebar.setVisible(not self.is_fullscreen)
        if hasattr(main_win, "header_frame"):
            main_win.header_frame.setVisible(not self.is_fullscreen)
        if hasattr(main_win, "body_layout"):
            if self.is_fullscreen:
                if self._saved_body_margins is None:
                    self._saved_body_margins = main_win.body_layout.contentsMargins()
                main_win.body_layout.setContentsMargins(0, 0, 0, 0)
            elif self._saved_body_margins is not None:
                main_win.body_layout.setContentsMargins(self._saved_body_margins)
                self._saved_body_margins = None

        if self.is_fullscreen:
            self.toolbar_layout.setContentsMargins(6, 0, 6, 0)
            self.toolbar.setFixedHeight(44)
            self.fullscreen_btn.setText("⤡")
            self.fullscreen_btn.setToolTip(_("win_restore_tip", "Exit Fullscreen (Esc)"))
        else:
            self.toolbar_layout.setContentsMargins(10, 0, 10, 0)
            self.toolbar.setFixedHeight(52)
            self.fullscreen_btn.setText("⛶")
            self.fullscreen_btn.setToolTip(_("browser_tooltip_fullscreen"))

    def navigate(self):
        url = self.address_bar.text().strip()
        if not url:
            return
        if "://" not in url:
            if re.match(r"^(?:localhost|\d{1,3}(?:\.\d{1,3}){3}|\[?[0-9a-fA-F:]+\]?)(?::\d+)?(?:/|$)", url, re.I):
                url = "http://" + url
            else:
                url = "https://" + url
        self._initial_loaded = True
        self._pending_url = url
        self.browser.setUrl(QUrl(url))

    def update_address_bar(self, q):
        self.address_bar.setText(q.toString())
        self._update_nav_buttons()
