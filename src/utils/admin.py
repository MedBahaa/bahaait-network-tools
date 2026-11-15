import ctypes
import subprocess
import sys
import os

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def run_as_admin():
    if is_admin():
        return True
    
    # Release single-instance lock if held so the elevated instance can start
    try:
        from PySide6.QtWidgets import QApplication
        from PySide6.QtNetwork import QLocalServer
        app = QApplication.instance()
        if app and hasattr(app, "local_server") and app.local_server:
            app.local_server.close()
            QLocalServer.removeServer("BahaaIT_Single_Instance_Lock")
    except Exception:
        pass

    # Re-run the program with admin rights (properly quoting paths with spaces)
    params = subprocess.list2cmdline(sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    sys.exit()
