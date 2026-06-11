from PySide6.QtWidgets import QSystemTrayIcon, QMenu, QStyle
from PySide6.QtGui import QIcon, QAction, QPixmap, QPainter, QColor
from PySide6.QtCore import QObject, Qt

class SystemTrayManager(QObject):
    def __init__(self, parent_window):
        super().__init__()
        self.window = parent_window
        
        # Create Tray Icon
        self.tray_icon = QSystemTrayIcon(self.window)
        
        # Try to use a standard icon as placeholder
        icon = self.window.style().standardIcon(QStyle.SP_ComputerIcon)
        if icon.isNull():
            # Create a simple colored square as fallback
            pixmap = QPixmap(32, 32)
            pixmap.fill(QColor("#3d5afe"))
            icon = QIcon(pixmap)
            
        self.tray_icon.setIcon(icon)
        self.tray_icon.setToolTip("BahaaIT Network Tools")
        
        # Create Menu
        self.menu = QMenu()
        
        show_action = QAction("Show BahaaIT", self)
        show_action.triggered.connect(self.window.showNormal)
        self.menu.addAction(show_action)
        
        self.menu.addSeparator()
        
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.window.quit_app)
        self.menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(self.menu)
        self.tray_icon.activated.connect(self.on_activated)
        
    def show(self):
        self.tray_icon.show()
        
    def on_activated(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            if self.window.isVisible():
                self.window.hide()
            else:
                self.window.showNormal()
                self.window.activateWindow()

    def notify(self, title, message):
        self.tray_icon.showMessage(title, message, QSystemTrayIcon.Information, 3000)
