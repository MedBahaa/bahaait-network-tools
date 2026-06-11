import requests
import os
import json
from PySide6.QtWidgets import QMessageBox

GITHUB_REPO = "MedBahaa/bahaait-network-tools"
CURRENT_VERSION = "v1.0.0"

class AutoUpdater:
    def __init__(self, parent_widget=None):
        self.parent = parent_widget

    def check_for_updates(self, silent=True):
        url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                latest_version = data.get("tag_name", "v1.0.0")
                
                if latest_version != CURRENT_VERSION:
                    release_notes = data.get("body", "No release notes provided.")
                    download_url = data.get("html_url", f"https://github.com/{GITHUB_REPO}/releases/latest")
                    
                    if self.parent:
                        msg = QMessageBox(self.parent)
                        msg.setWindowTitle("Update Available")
                        msg.setText(f"Version {latest_version} is available!")
                        msg.setInformativeText(f"Release Notes:\n{release_notes}")
                        
                        download_btn = msg.addButton("Download", QMessageBox.AcceptRole)
                        ignore_btn = msg.addButton("Ignore", QMessageBox.RejectRole)
                        
                        msg.exec()
                        
                        if msg.clickedButton() == download_btn:
                            import webbrowser
                            webbrowser.open(download_url)
                    return True, latest_version
                else:
                    if not silent and self.parent:
                        QMessageBox.information(self.parent, "Up to date", "You are using the latest version.")
            else:
                if response.status_code == 404:
                    if not silent and self.parent:
                        QMessageBox.information(self.parent, "No updates", "No releases found on GitHub yet.")
                else:
                    if not silent and self.parent:
                        QMessageBox.warning(self.parent, "Error", f"Failed to check for updates. Status code: {response.status_code}")
        except Exception as e:
            if not silent and self.parent:
                QMessageBox.critical(self.parent, "Update Error", f"An error occurred while checking for updates:\n{str(e)}")
            
        return False, CURRENT_VERSION
