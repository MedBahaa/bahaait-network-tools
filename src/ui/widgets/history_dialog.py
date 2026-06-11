from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTextEdit, QFileDialog, QMessageBox)
from PySide6.QtCore import Qt
from utils.db import DatabaseManager

class HostHistoryDialog(QDialog):
    def __init__(self, host, logs, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"History - {host}")
        self.setMinimumSize(600, 400)
        self.host = host
        self.logs = logs # List of strings

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(15)
        
        header = QLabel(f"Activity Log: {host}")
        header.setObjectName("Title")
        header.setStyleSheet("font-size: 20px; color: #FFFFFF;")
        self.layout.addWidget(header)
        
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setStyleSheet("""
            QTextEdit {
                background-color: #0F172A; 
                color: #F1F5F9; 
                font-family: 'Consolas', monospace; 
                font-size: 12px;
                border: 1px solid #1E293B;
                border-radius: 10px;
                padding: 10px;
            }
        """)
        self.log_area.setPlainText("\n".join(self.logs))
        self.layout.addWidget(self.log_area)
        
        btns = QHBoxLayout()
        export_btn = QPushButton("Export Log")
        export_btn.setObjectName("PrimaryButton")
        export_btn.setFixedHeight(40)
        export_btn.setMinimumWidth(120)
        export_btn.setCursor(Qt.PointingHandCursor)
        export_btn.clicked.connect(self.export_log)
        
        clear_btn = QPushButton("Clear Log")
        clear_btn.setObjectName("DangerButton") # Styled in QSS
        clear_btn.setFixedHeight(40)
        clear_btn.setMinimumWidth(120)
        clear_btn.setCursor(Qt.PointingHandCursor)
        clear_btn.clicked.connect(self.clear_history)
        
        close_btn = QPushButton("Close")
        close_btn.setObjectName("SecondaryButton")
        close_btn.setFixedHeight(40)
        close_btn.setMinimumWidth(100)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.clicked.connect(self.accept)
        
        btns.addStretch()
        btns.addWidget(export_btn)
        btns.addWidget(clear_btn)
        btns.addWidget(close_btn)
        self.layout.addLayout(btns)

    def clear_history(self):
        reply = QMessageBox.question(self, "Clear History", f"Are you sure you want to clear all history for {self.host}?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            db = DatabaseManager()
            db.clear_host_history(self.host)
            self.log_area.clear()
            self.log_area.append("<span style='color: #94A3B8;'>History cleared successfully.</span>")

    def export_log(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Log", f"log_{self.host}.txt", "Text Files (*.txt)")
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(f"BahaaIT Network Tools - Activity Log for {self.host}\n")
                    f.write("-" * 50 + "\n")
                    f.write(self.log_area.toPlainText())
                QMessageBox.information(self, "Success", "Log exported successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export: {str(e)}")
