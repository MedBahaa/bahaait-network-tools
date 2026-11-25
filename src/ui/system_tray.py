import os
import sys
from PySide6.QtWidgets import QApplication, QSystemTrayIcon, QMenu, QStyle
from PySide6.QtGui import QIcon, QAction, QPixmap, QColor
from PySide6.QtCore import QObject
from utils.i18n import _


class SystemTrayManager(QObject):
    def __init__(self, parent_window):
        super().__init__(parent_window)
        self.window = parent_window

        self.tray_icon = QSystemTrayIcon(self.window)

        icon = QApplication.windowIcon()
        if icon.isNull():
            icon = self.window.windowIcon()

        if icon.isNull():
            if getattr(sys, "frozen", False):
                icon_path = os.path.join(sys._MEIPASS, "assets", "app_icon.ico")
            else:
                icon_path = os.path.join(os.path.dirname(__file__), "..", "..", "assets", "app_icon.ico")
            if os.path.exists(icon_path):
                icon = QIcon(icon_path)
            else:
                icon = self.window.style().standardIcon(QStyle.SP_ComputerIcon)
                if icon.isNull():
                    pixmap = QPixmap(32, 32)
                    pixmap.fill(QColor("#6366F1"))
                    icon = QIcon(pixmap)

        self.tray_icon.setIcon(icon)
        self.tray_icon.setToolTip("BahaaIT Network Tools")

        self.menu = QMenu(parent_window)
        self.menu.setStyleSheet("""
            QMenu { background-color: #1E293B; color: #F1F5F9; border: 1px solid #334155; border-radius: 8px; padding: 4px; }
            QMenu::item { padding: 6px 18px; border-radius: 6px; }
            QMenu::item:selected { background-color: #4F46E5; color: #FFFFFF; }
            QMenu::separator { height: 1px; background: #334155; margin: 4px 8px; }
        """)

        show_action = QAction(_("tray_show"), self)
        show_action.triggered.connect(self._restore_window)
        self.menu.addAction(show_action)

        self.menu.addSeparator()

        quit_action = QAction(_("tray_quit"), self)
        quit_action.triggered.connect(self.window.quit_app)
        self.menu.addAction(quit_action)

        self.tray_icon.setContextMenu(self.menu)
        self.tray_icon.activated.connect(self.on_activated)
        self.tray_icon.messageClicked.connect(self._restore_window)

    def _restore_window(self):
        if self.window:
            self.window.showNormal()
            self.window.raise_()
            self.window.activateWindow()

    def show(self):
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray_icon.show()

    def on_activated(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            if self.window.isVisible() and not self.window.isMinimized():
                self.window.hide()
            else:
                self._restore_window()

    def notify(self, title, message):
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray_icon.showMessage(title, message, QSystemTrayIcon.Information, 3000)
