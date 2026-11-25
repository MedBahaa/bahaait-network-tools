import re
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTextEdit, QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from utils.db import DatabaseManager
from utils.i18n import _


class HostHistoryDialog(QDialog):
    def __init__(self, host, logs, parent=None, db: DatabaseManager = None):
        super().__init__(parent)
        self.setWindowTitle(_("hist_title").format(host))
        screen = QGuiApplication.primaryScreen()
        avail = screen.availableGeometry() if screen else None
        w = min(680, int(avail.width() * 0.85)) if avail else 640
        h = min(480, int(avail.height() * 0.80)) if avail else 440
        self.resize(w, h)
        self.setMinimumSize(520, 360)
        self.host = host
        self.logs = list(logs or [])
        self._db = db

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(12)

        header = QLabel(_("hist_activity_log").format(host))
        header.setObjectName("Title")
        header.setWordWrap(True)
        header.setStyleSheet("font-size: 20px; font-weight: 800; color: #FFFFFF; margin-bottom: 0px;")
        self.layout.addWidget(header)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setStyleSheet("""
            QTextEdit {
                background-color: #0B1220;
                color: #F1F5F9;
                font-family: 'Consolas', monospace;
                font-size: 12px;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 10px;
            }
        """)
        if self.logs:
            self.log_area.setPlainText("\n".join(self.logs))
        else:
            self.log_area.setPlaceholderText(_("hist_cleared", "No history recorded."))
        self.layout.addWidget(self.log_area, 1)

        btns = QHBoxLayout()
        btns.setSpacing(10)
        export_btn = QPushButton(_("hist_export_btn"))
        export_btn.setObjectName("PrimaryButton")
        export_btn.setCursor(Qt.PointingHandCursor)
        export_btn.clicked.connect(self.export_log)

        clear_btn = QPushButton(_("hist_clear_btn"))
        clear_btn.setObjectName("DangerButton")
        clear_btn.setCursor(Qt.PointingHandCursor)
        clear_btn.clicked.connect(self.clear_history)

        close_btn = QPushButton(_("hist_close_btn"))
        close_btn.setObjectName("SecondaryButton")
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.clicked.connect(self.accept)

        btns.addStretch()
        btns.addWidget(export_btn)
        btns.addWidget(clear_btn)
        btns.addWidget(close_btn)
        self.layout.addLayout(btns)

    def clear_history(self):
        reply = QMessageBox.question(
            self, _("hist_clear_title"), _("hist_clear_confirm").format(self.host),
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            db = self._db or DatabaseManager()
            db.clear_host_history(self.host)
            self.logs = []
            self.log_area.clear()
            self.log_area.setPlaceholderText(_("hist_cleared"))

    def export_log(self):
        if not self.logs:
            QMessageBox.information(self, _("hist_export_title"), _("hist_cleared", "No history to export."))
            return
        safe_host = re.sub(r'[<>:"/\\|?*]', "_", str(self.host))
        file_path, _filter = QFileDialog.getSaveFileName(
            self, _("hist_export_title"), f"log_{safe_host}.txt", "Text Files (*.txt)"
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(_("hist_export_header").format(self.host) + "\n")
                    f.write("-" * 50 + "\n")
                    f.write("\n".join(self.logs))
                QMessageBox.information(self, _("msg_success"), _("hist_export_success"))
            except Exception as e:
                QMessageBox.critical(self, _("msg_error"), _("hist_export_error").format(str(e)))
