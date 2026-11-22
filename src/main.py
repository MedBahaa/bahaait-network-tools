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
            flags = kwargs.get('creationflags', 0)
            # DETACHED_PROCESS (0x00000008) and CREATE_NEW_CONSOLE (0x00000010) cannot be combined with CREATE_NO_WINDOW
            if not (flags & (getattr(subprocess, 'DETACHED_PROCESS', 0x00000008) | getattr(subprocess, 'CREATE_NEW_CONSOLE', 0x00000010))):
                kwargs['creationflags'] = flags | subprocess.CREATE_NO_WINDOW
            super().__init__(*args, **kwargs)
    subprocess.Popen = _PatchedPopen

# Add src to path if needed
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__))))

from PySide6.QtWidgets import QApplication
from ui.main_window import MainWindow
from utils.logger import setup_logger
from utils.auth import AuthManager
from utils.updater import AutoUpdater
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
    if config_manager.get("disable_ssl", True):
        os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--ignore-certificate-errors --ignore-ssl-errors"
    else:
        if "QTWEBENGINE_CHROMIUM_FLAGS" in os.environ:
            del os.environ["QTWEBENGINE_CHROMIUM_FLAGS"]

    # 1. Setup Logger
    logger, log_handler = setup_logger()
    logger.info("BahaaIT Network Tools Starting...")

    # 3. Create App
    from PySide6.QtCore import Qt, QUrl, QStandardPaths
    from PySide6.QtWidgets import QFileDialog
    QApplication.setAttribute(Qt.AA_DontUseNativeDialogs, True)
    app = QApplication(sys.argv)
    app.setApplicationName("BahaaIT Network Tools")

    # Configure QFileDialog globally with Desktop, Documents & Downloads shortcuts in sidebar
    def _default_sidebar_urls():
        urls = [QUrl("file:")]
        seen = set()
        candidates = [
            QStandardPaths.writableLocation(QStandardPaths.DesktopLocation),
            os.path.join(os.path.expanduser("~"), "Desktop"),
            QStandardPaths.writableLocation(QStandardPaths.DocumentsLocation),
            os.path.join(os.path.expanduser("~"), "Documents"),
            QStandardPaths.writableLocation(QStandardPaths.DownloadLocation),
            os.path.join(os.path.expanduser("~"), "Downloads"),
        ]
        for p in candidates:
            if p and os.path.isdir(p):
                norm = os.path.normcase(os.path.abspath(p))
                if norm not in seen:
                    seen.add(norm)
                    urls.append(QUrl.fromLocalFile(os.path.abspath(p)))
        return urls

    def _widen_file_dialog_sidebar(dlg):
        from PySide6.QtWidgets import QSplitter, QListView
        sidebar = dlg.findChild(QListView, "sidebar")
        if sidebar:
            sidebar.setMinimumWidth(185)
        splitter = dlg.findChild(QSplitter, "splitter")
        if splitter:
            splitter.setSizes([195, 625])

    def _resolve_initial_dir_and_file(dir_arg: str):
        desktop = QStandardPaths.writableLocation(QStandardPaths.DesktopLocation)
        if not desktop or not os.path.isdir(desktop):
            desktop = os.path.expanduser("~")
        if not dir_arg:
            return desktop, ""
        if os.path.isdir(dir_arg):
            return dir_arg, ""
        parent = os.path.dirname(dir_arg)
        base = os.path.basename(dir_arg)
        if parent and os.path.isdir(parent):
            return parent, base
        return desktop, base

    def _enhanced_apply_default_suffix(dlg, filter_str: str):
        import re
        m = re.search(r'\*\.([a-zA-Z0-9]+)', filter_str or "")
        if m:
            dlg.setDefaultSuffix(m.group(1))

    def _enhanced_get_save_file_name(parent=None, caption="", dir="", filter="", selectedFilter="", options=QFileDialog.Option(0)):
        start_dir, base_file = _resolve_initial_dir_and_file(dir)
        dlg = QFileDialog(parent, caption, start_dir, filter)
        dlg.setAcceptMode(QFileDialog.AcceptSave)
        dlg.setFileMode(QFileDialog.AnyFile)
        dlg.setOptions(options | QFileDialog.DontUseNativeDialog)
        dlg.setSidebarUrls(_default_sidebar_urls())
        _enhanced_apply_default_suffix(dlg, selectedFilter or filter)
        dlg.resize(820, 480)
        _widen_file_dialog_sidebar(dlg)
        if selectedFilter:
            dlg.selectNameFilter(selectedFilter)
        if base_file:
            dlg.selectFile(base_file)
        if dlg.exec():
            files = dlg.selectedFiles()
            return (files[0] if files else "", dlg.selectedNameFilter())
        return ("", "")

    def _enhanced_get_open_file_name(parent=None, caption="", dir="", filter="", selectedFilter="", options=QFileDialog.Option(0)):
        start_dir, base_file = _resolve_initial_dir_and_file(dir)
        dlg = QFileDialog(parent, caption, start_dir, filter)
        dlg.setAcceptMode(QFileDialog.AcceptOpen)
        dlg.setFileMode(QFileDialog.ExistingFile)
        dlg.setOptions(options | QFileDialog.DontUseNativeDialog)
        dlg.setSidebarUrls(_default_sidebar_urls())
        dlg.resize(820, 480)
        _widen_file_dialog_sidebar(dlg)
        if selectedFilter:
            dlg.selectNameFilter(selectedFilter)
        if base_file:
            dlg.selectFile(base_file)
        if dlg.exec():
            files = dlg.selectedFiles()
            return (files[0] if files else "", dlg.selectedNameFilter())
        return ("", "")

    QFileDialog.getSaveFileName = staticmethod(_enhanced_get_save_file_name)
    QFileDialog.getOpenFileName = staticmethod(_enhanced_get_open_file_name)
    
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
    
    # Check if application should start silently (minimized to system tray)
    is_silent = "--silent" in sys.argv
    
    # 3.2 Show Splash Screen immediately (Premium Custom Widget) - only if not running silently
    from ui.widgets.premium_splash import PremiumSplashScreen
    
    if getattr(sys, 'frozen', False):
        logo_path = os.path.join(sys._MEIPASS, "src", "assets", "logo.png")
    else:
        logo_path = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
        
    splash = None
    if not is_silent:
        splash = PremiumSplashScreen(logo_path)
        splash.show_splash()
        splash.set_progress(15, "Initialisation du moteur système...")
    
    # Auth
    if splash:
        splash.set_progress(45, "Vérification des droits d'accès...")
    auth_manager = AuthManager()
    
    # 4. Show Main Window
    if splash:
        splash.set_progress(75, "Chargement du thème & de l'interface...")
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
    
    if splash:
        splash.set_progress(100, "Prêt !")
        # Hide splash screen with smooth fade-out and reveal main window
        splash.finish(window)
    elif is_silent:
        # If starting silently, do not call window.show() or splash.finish().
        # The window remains hidden and the application runs in background tray icon.
        logger.info("Application started silently in background.")
    
    # 5. Check for updates (silent on startup)
    window.updater = AutoUpdater(window)
    window.updater.check_for_updates(silent=True)
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
