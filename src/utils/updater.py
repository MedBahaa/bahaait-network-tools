import requests
import os
import json
import sys
import subprocess
import threading
from PySide6.QtWidgets import QMessageBox, QProgressDialog
from PySide6.QtCore import QObject, Signal, Slot, Qt

GITHUB_REPO = "MedBahaa/bahaait-network-tools"
CURRENT_VERSION = "v2.0.0"

class UpdateWorker(QObject):
    update_available = Signal(str, str, str, str)  # latest_version, release_notes, download_url, exe_url
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
                    
                    # Search for exe asset
                    exe_url = ""
                    assets = data.get("assets", [])
                    for asset in assets:
                        asset_name = asset.get("name", "")
                        if asset_name.endswith(".exe"):
                            exe_url = asset.get("browser_download_url", "")
                            break
                    
                    self.update_available.emit(latest_version, release_notes, download_url, exe_url)
                else:
                    self.no_update_or_error.emit(False, "À jour", "Vous utilisez déjà la dernière version.")
            else:
                self.no_update_or_error.emit(True, "Erreur", f"Impossible de vérifier les mises à jour. Code : {response.status_code}")
        except Exception as e:
            self.no_update_or_error.emit(True, "Erreur de mise à jour", f"Une erreur est survenue :\n{str(e)}")

class DownloadWorker(QObject):
    progress = Signal(int)
    finished = Signal(str)
    error = Signal(str)

    def __init__(self, download_url, parent=None):
        super().__init__(parent)
        self.url = download_url
        self.temp_path = ""
        self.is_cancelled = False

    def run(self):
        threading.Thread(target=self._download, daemon=True).start()

    def cancel(self):
        self.is_cancelled = True

    def _download(self):
        try:
            import tempfile
            filename = self.url.split("/")[-1]
            if not filename.endswith(".exe"):
                filename = "BahaaIT_Setup.exe"
            
            temp_dir = tempfile.gettempdir()
            self.temp_path = os.path.join(temp_dir, filename)
            
            response = requests.get(self.url, stream=True, timeout=15)
            if response.status_code == 200:
                total_length = response.headers.get('content-length')
                
                if total_length is None:
                    with open(self.temp_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=4096):
                            if self.is_cancelled:
                                return
                            f.write(chunk)
                    self.progress.emit(100)
                else:
                    total_length = int(total_length)
                    downloaded = 0
                    with open(self.temp_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=4096):
                            if self.is_cancelled:
                                return
                            downloaded += len(chunk)
                            f.write(chunk)
                            percentage = int((downloaded / total_length) * 100)
                            self.progress.emit(percentage)
                
                if not self.is_cancelled:
                    self.finished.emit(self.temp_path)
            else:
                self.error.emit(f"HTTP Error {response.status_code}")
        except Exception as e:
            self.error.emit(str(e))

class AutoUpdater(QObject):
    finished = Signal()

    def __init__(self, parent_widget=None):
        super().__init__(parent_widget)
        self.parent = parent_widget
        self.worker = None
        self.download_worker = None
        self.progress_dialog = None
        self.fallback_url = ""

    def check_for_updates(self, silent=True):
        self.worker = UpdateWorker(silent, self)
        self.worker.update_available.connect(self._on_update_available)
        self.worker.no_update_or_error.connect(self._on_no_update_or_error)
        self.worker.run()

    @Slot(str, str, str, str)
    def _on_update_available(self, latest_version, release_notes, download_url, exe_url):
        self.fallback_url = download_url
        if self.parent:
            msg = QMessageBox(self.parent)
            msg.setWindowTitle("Mise à jour disponible")
            msg.setText(f"La version {latest_version} est disponible !")
            msg.setInformativeText(f"Notes de mise à jour :\n{release_notes}\n\nVoulez-vous la télécharger et l'installer maintenant ?")
            
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
                if exe_url:
                    self._start_download(exe_url)
                else:
                    # Fallback to browser if no exe asset is present
                    import webbrowser
                    webbrowser.open(download_url)
                    self.finished.emit()
            else:
                self.finished.emit()
        else:
            self.finished.emit()

    def _start_download(self, exe_url):
        self.progress_dialog = QProgressDialog("Téléchargement de la mise à jour...", "Annuler", 0, 100, self.parent)
        self.progress_dialog.setWindowTitle("Mise à jour")
        self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.progress_dialog.setMinimumDuration(0)
        self.progress_dialog.setStyleSheet("""
            QProgressDialog {
                background-color: #0F172A;
                color: #F8FAFC;
            }
            QLabel {
                color: #F8FAFC;
                font-size: 13px;
            }
            QProgressBar {
                background-color: #334155;
                border: none;
                border-radius: 6px;
                text-align: center;
                color: white;
                font-weight: bold;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3B82F6, stop:1 #10B981);
                border-radius: 6px;
            }
            QPushButton {
                background-color: #EF4444;
                color: white;
                border: none;
                padding: 6px 14px;
                border-radius: 4px;
                font-weight: bold;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #DC2626;
            }
        """)
        
        self.download_worker = DownloadWorker(exe_url, self)
        self.download_worker.progress.connect(self._on_download_progress)
        self.download_worker.finished.connect(self._on_download_finished)
        self.download_worker.error.connect(self._on_download_error)
        
        self.progress_dialog.canceled.connect(self._on_download_cancelled)
        self.progress_dialog.show()
        
        self.download_worker.run()

    @Slot(int)
    def _on_download_progress(self, val):
        if self.progress_dialog:
            self.progress_dialog.setValue(val)

    @Slot(str)
    def _on_download_finished(self, file_path):
        if self.progress_dialog:
            self.progress_dialog.close()
        
        # Start installer detached
        try:
            if os.name == 'nt':
                subprocess.Popen([file_path], shell=True, creationflags=subprocess.DETACHED_PROCESS)
            else:
                subprocess.Popen([file_path])
            
            # Close application
            from PySide6.QtWidgets import QApplication
            QApplication.quit()
            sys.exit(0)
        except Exception as e:
            QMessageBox.critical(self.parent, "Erreur d'installation", f"Impossible de démarrer l'installateur :\n{str(e)}")
            self.finished.emit()

    @Slot(str)
    def _on_download_error(self, err_msg):
        if self.progress_dialog:
            self.progress_dialog.close()
            
        # Error notification and fallback to browser download
        msg = QMessageBox(self.parent)
        msg.setWindowTitle("Erreur de téléchargement")
        msg.setText("Le téléchargement direct a échoué.")
        msg.setInformativeText(f"Raison : {err_msg}\n\nVoulez-vous ouvrir la page de téléchargement dans votre navigateur ?")
        
        yes_btn = msg.addButton("Oui", QMessageBox.YesRole)
        no_btn = msg.addButton("Non", QMessageBox.NoRole)
        
        msg.setStyleSheet("""
            QMessageBox {
                background-color: #0F172A;
                color: #F8FAFC;
            }
            QLabel {
                color: #F8FAFC;
            }
            QPushButton {
                background-color: #3B82F6;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #2563EB;
            }
        """)
        msg.exec()
        
        if msg.clickedButton() == yes_btn:
            import webbrowser
            webbrowser.open(self.fallback_url)
            
        self.finished.emit()

    def _on_download_cancelled(self):
        if self.download_worker:
            self.download_worker.cancel()
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
