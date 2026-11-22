import os
import sys
from PySide6.QtWidgets import QApplication

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

# Ensure a single QApplication exists for all unit & UI tests in the same pytest session
_app = QApplication.instance() or QApplication(sys.argv)
