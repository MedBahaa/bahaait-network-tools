import sys
import os

# Fix for PyInstaller Windowed mode (sys.stdout is None)
if sys.stdout is None or sys.stderr is None:
    devnull = open(os.devnull, 'w')
    if sys.stdout is None:
        sys.stdout = devnull
    if sys.stderr is None:
        sys.stderr = devnull

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

def load_settings():
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

def main():
    # 0. Load settings for flags
    settings = load_settings()
    if settings.get("disable_ssl", False):
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
    
    # Auth
    auth_manager = AuthManager()
    
    if not auth_manager.is_authenticated():
        login_dialog = LoginDialog(auth_manager)
        if login_dialog.exec() != LoginDialog.Accepted:
            sys.exit(0)
    
    # 4. Show Main Window
    window = MainWindow(logger, log_handler, auth_manager)
    window.show()
    
    # 5. Check for updates (silent on startup)
    updater = AutoUpdater(window)
    updater.check_for_updates(silent=True)
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
