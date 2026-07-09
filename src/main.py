import sys
import os
import subprocess

# Fix for PyInstaller Windowed mode (sys.stdout is None)
if sys.stdout is None or sys.stderr is None:
    devnull = open(os.devnull, 'w')
    if sys.stdout is None:
        sys.stdout = devnull
    if sys.stderr is None:
        sys.stderr = devnull

# Force all subprocesses to hide the console window on Windows
if os.name == 'nt':
    _original_popen = subprocess.Popen
    class _PatchedPopen(_original_popen):
        def __init__(self, *args, **kwargs):
            if 'creationflags' not in kwargs:
                kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
            else:
                kwargs['creationflags'] |= subprocess.CREATE_NO_WINDOW
            super().__init__(*args, **kwargs)
    subprocess.Popen = _PatchedPopen

# Add src to path if needed
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__))))

from PySide6.QtWidgets import QApplication
from ui.main_window import MainWindow
from ui.widgets.login_view import LoginDialog
from utils.logger import setup_logger
from utils.admin import is_admin, run_as_admin
from utils.auth import AuthManager
from utils.updater import AutoUpdater
import json

from utils.config import ConfigManager

def main():
    # Force Windows to associate the process with the shortcut's AppID for taskbar icon
    if os.name == 'nt':
        import ctypes
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Bahaa.BahaaIT.NetworkTools.3")
        except Exception:
            pass

    # 0. Load settings for flags from centralized config manager
    config_manager = ConfigManager()
    if config_manager.get("disable_ssl", False):
        os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--ignore-certificate-errors --ignore-ssl-errors"
    else:
        if "QTWEBENGINE_CHROMIUM_FLAGS" in os.environ:
            del os.environ["QTWEBENGINE_CHROMIUM_FLAGS"]

    # 1. Setup Logger
    logger, log_handler = setup_logger()
    logger.info("BahaaIT Network Tools Starting...")

    # 3. Create App
    app = QApplication(sys.argv)
    app.setApplicationName("BahaaIT Network Tools")
    
    from PySide6.QtGui import QIcon
    if getattr(sys, 'frozen', False):
        icon_path = os.path.join(sys._MEIPASS, "assets", "app_icon.ico")
    else:
        icon_path = os.path.join(os.path.dirname(__file__), "..", "assets", "app_icon.ico")
    app.setWindowIcon(QIcon(icon_path))
    
    # 3.1 Single Instance check using QLocalServer/QLocalSocket
    from PySide6.QtNetwork import QLocalServer, QLocalSocket
    server_name = "BahaaIT_Single_Instance_Lock"
    socket = QLocalSocket()
    socket.connectToServer(server_name)
    if socket.waitForConnected(500):
        # Already running! Send message to show existing window
        socket.write(b"SHOW")
        socket.waitForBytesWritten(500)
        socket.disconnectFromServer()
        logger.info("Another instance is already running. Exiting.")
        sys.exit(0)
        
    # Start local server to listen for new attempts
    server = QLocalServer()
    server.removeServer(server_name)
    server.listen(server_name)
    app.local_server = server  # Store reference to prevent garbage collection
    
    # 3.2 Show Splash Screen immediately
    from PySide6.QtWidgets import QSplashScreen
    from PySide6.QtGui import QPixmap
    from PySide6.QtCore import Qt
    
    if getattr(sys, 'frozen', False):
        logo_path = os.path.join(sys._MEIPASS, "src", "assets", "logo.png")
    else:
        logo_path = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
        
    splash = None
    if os.path.exists(logo_path):
        pixmap = QPixmap(logo_path)
        splash = QSplashScreen(pixmap, Qt.WindowStaysOnTopHint)
        splash.showMessage("BahaaIT Network Tools — Chargement...", Qt.AlignBottom | Qt.AlignCenter, Qt.white)
        splash.show()
        app.processEvents()
    
    # Auth
    auth_manager = AuthManager()
    
    # 4. Show Main Window
    window = MainWindow(logger, log_handler, auth_manager)
    
    # Connect local server to show main window on future launch attempts
    def handle_new_connection():
        client = server.nextPendingConnection()
        if client.waitForReadyRead(1000):
            data = client.readAll().data()
            if data == b"SHOW":
                window.showNormal()
                window.activateWindow()
                window.raise_()
    server.newConnection.connect(handle_new_connection)
    
    window.show()
    
    # Hide splash screen when window is ready
    if splash:
        splash.finish(window)
    
    # 5. Check for updates (silent on startup)
    window.updater = AutoUpdater(window)
    window.updater.check_for_updates(silent=True)
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
