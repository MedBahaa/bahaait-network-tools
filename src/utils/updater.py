import requests
import os
import json
import threading
from PySide6.QtWidgets import QMessageBox
from PySide6.QtCore import QObject, Signal, Slot

GITHUB_REPO = "MedBahaa/bahaait-network-tools"
CURRENT_VERSION = "v1.0.0"

class UpdateWorker(QObject):
    update_available = Signal(str, str, str)  # latest_version, release_notes, download_url
    no_update_or_error = Signal(bool, str, str)  # is_error, title, message

    def __init__(self, silent, parent=None):
        super().__init__(parent)
        self.silent = silent

    def run(self):
        threading.Thread(target=self._do_check, daemon=True).start()

    def _do_check(self):
        url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                latest_version = data.get("tag_name", "v1.0.0")
                
                if latest_version != CURRENT_VERSION:
                    release_notes = data.get("body", "Pas de notes de mise à jour.")
                    download_url = data.get("html_url", f"https://github.com/{GITHUB_REPO}/releases/latest")
                    self.update_available.emit(latest_version, release_notes, download_url)
                else:
                    self.no_update_or_error.emit(False, "À jour", "Vous utilisez déjà la dernière version.")
            else:
                self.no_update_or_error.emit(True, "Erreur", f"Impossible de vérifier les mises à jour. Code : {response.status_code}")
        except Exception as e:
            self.no_update_or_error.emit(True, "Erreur de mise à jour", f"Une erreur est survenue :\n{str(e)}")

class AutoUpdater(QObject):
    finished = Signal()

    def __init__(self, parent_widget=None):
        super().__init__(parent_widget)
        self.parent = parent_widget
        self.worker = None

    def check_for_updates(self, silent=True):
        self.worker = UpdateWorker(silent, self)
        self.worker.update_available.connect(self._on_update_available)
        self.worker.no_update_or_error.connect(self._on_no_update_or_error)
        self.worker.run()

    @Slot(str, str, str)
    def _on_update_available(self, latest_version, release_notes, download_url):
        if self.parent:
            msg = QMessageBox(self.parent)
            msg.setWindowTitle("Mise à jour disponible")
            msg.setText(f"La version {latest_version} est disponible !")
            msg.setInformativeText(f"Notes de mise à jour :\n{release_notes}\n\nVoulez-vous la télécharger maintenant ?")
            
            # French buttons: "Mettre à jour" and "Plus tard"
            update_btn = msg.addButton("Mettre à jour", QMessageBox.AcceptRole)
            later_btn = msg.addButton("Plus tard", QMessageBox.RejectRole)
            
            msg.setStyleSheet("""
                QMessageBox {
                    background-color: #0F172A;
                    color: #F8FAFC;
                }
                QLabel {
                    color: #F8FAFC;
                    font-size: 13px;
                }
                QPushButton {
                    background-color: #3B82F6;
                    color: white;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 6px;
                    font-weight: bold;
                    min-width: 100px;
                    font-size: 13px;
                }
                QPushButton:hover {
                    background-color: #2563EB;
                }
                QPushButton:pressed {
                    background-color: #1D4ED8;
                }
            """)
            
            msg.exec()
            
            if msg.clickedButton() == update_btn:
                import webbrowser
                webbrowser.open(download_url)
        self.finished.emit()

    @Slot(bool, str, str)
    def _on_no_update_or_error(self, is_error, title, message):
        if not self.worker.silent and self.parent:
            msg = QMessageBox(self.parent)
            msg.setWindowTitle(title)
            msg.setText(message)
            msg.setIcon(QMessageBox.Warning if is_error else QMessageBox.Information)
            
            msg.setStyleSheet("""
                QMessageBox {
                    background-color: #0F172A;
                    color: #F8FAFC;
                }
                QLabel {
                    color: #F8FAFC;
                    font-size: 13px;
                }
                QPushButton {
                    background-color: #3B82F6;
                    color: white;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 6px;
                    font-weight: bold;
                    min-width: 100px;
                    font-size: 13px;
                }
                QPushButton:hover {
                    background-color: #2563EB;
                }
            """)
            msg.exec()
        self.finished.emit()
