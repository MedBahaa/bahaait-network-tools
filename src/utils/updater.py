import html
import json
import os
import re
import subprocess
import sys
import threading
import webbrowser
from typing import Optional

from PySide6.QtCore import QObject, Qt, Signal, Slot
from PySide6.QtGui import QGuiApplication, QPixmap
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressDialog,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)
import requests

from utils.i18n import _

GITHUB_REPO = "MedBahaa/bahaait-network-tools"
CURRENT_VERSION = "v3.6.0"


def _resolve_logo_path() -> str:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        p = os.path.join(sys._MEIPASS, "src", "assets", "logo.png")
        if os.path.exists(p):
            return p
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "assets", "logo.png"))


def _format_inline_markdown(escaped_text: str) -> str:
    """Convert escaped Markdown inline tokens (code, bold, italic, URLs) to HTML."""
    out = re.sub(
        r"`([^`]+)`",
        r'<code style="background-color:#1E293B;color:#38BDF8;padding:1px 5px;'
        r'border-radius:4px;font-family:Consolas,monospace;font-size:12px;">\1</code>',
        escaped_text,
    )
    out = re.sub(r"\*\*(.+?)\*\*", r'<strong style="color:#F8FAFC;">\1</strong>', out)
    out = re.sub(r"(?<!\*)\*([^*]+?)\*(?!\*)", r'<em style="color:#CBD5E1;">\1</em>', out)
    out = re.sub(
        r"(https?://[^\s<]+)",
        r'<a href="\1" style="color:#38BDF8;text-decoration:none;">\1</a>',
        out,
    )
    return out


def markdown_to_quantum_html(md_text: str) -> str:
    """Safely render GitHub release notes Markdown into Quantum Midnight HTML for QTextBrowser."""
    raw = str(md_text or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not raw:
        raw = _("upd_no_notes", "No release notes.")

    chunks = ['<div style="font-family:\'Segoe UI\',sans-serif;font-size:12.5px;color:#CBD5E1;line-height:1.45;">']
    in_ul = False
    in_ol = False

    def _close_lists() -> None:
        nonlocal in_ul, in_ol
        if in_ul:
            chunks.append("</ul>")
            in_ul = False
        if in_ol:
            chunks.append("</ol>")
            in_ol = False

    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            _close_lists()
            chunks.append('<div style="height:6px;"></div>')
            continue

        if stripped in ("---", "***", "___"):
            _close_lists()
            chunks.append('<hr style="border:none;border-top:1px solid #334155;margin:10px 0;"/>')
            continue

        # Headings #, ##, ###
        m_hdr = re.match(r"^(#{1,3})\s+(.*)$", stripped)
        if m_hdr:
            _close_lists()
            level = len(m_hdr.group(1))
            txt = _format_inline_markdown(html.escape(m_hdr.group(2).strip()))
            if level == 1:
                chunks.append(f'<h2 style="color:#F8FAFC;font-size:15px;font-weight:bold;margin:6px 0 6px 0;">{txt}</h2>')
            elif level == 2:
                chunks.append(f'<h3 style="color:#818CF8;font-size:13.5px;font-weight:bold;margin:12px 0 6px 0;">{txt}</h3>')
            else:
                chunks.append(f'<h4 style="color:#38BDF8;font-size:12.5px;font-weight:bold;margin:8px 0 4px 0;">{txt}</h4>')
            continue

        # Indented nested bullet (two+ leading spaces before - / *)
        m_sub = re.match(r"^\s{2,}[-*]\s+(.*)$", line)
        if m_sub:
            _close_lists()
            txt = _format_inline_markdown(html.escape(m_sub.group(1).strip()))
            chunks.append(f'<p style="margin:2px 0 3px 20px;color:#94A3B8;">&#8226; {txt}</p>')
            continue

        # Top-level unordered bullet
        m_ul = re.match(r"^[-*•]\s+(.*)$", stripped)
        if m_ul:
            if in_ol:
                chunks.append("</ol>")
                in_ol = False
            if not in_ul:
                chunks.append('<ul style="margin:4px 0 8px 18px;padding-left:0;">')
                in_ul = True
            txt = _format_inline_markdown(html.escape(m_ul.group(1).strip()))
            chunks.append(f'<li style="margin:3px 0;color:#CBD5E1;">{txt}</li>')
            continue

        # Ordered list item
        m_ol = re.match(r"^(\d+)\.\s+(.*)$", stripped)
        if m_ol:
            if in_ul:
                chunks.append("</ul>")
                in_ul = False
            if not in_ol:
                chunks.append('<ol style="margin:4px 0 6px 18px;padding-left:0;">')
                in_ol = True
            txt = _format_inline_markdown(html.escape(m_ol.group(2).strip()))
            chunks.append(f'<li style="margin:5px 0 3px 0;color:#F1F5F9;">{txt}</li>')
            continue

        _close_lists()
        txt = _format_inline_markdown(html.escape(stripped))
        chunks.append(f'<p style="margin:4px 0;color:#E2E8F0;">{txt}</p>')

    _close_lists()
    chunks.append("</div>")
    return "".join(chunks)


class UpdateAvailableDialog(QDialog):
    """Fixed-proportion, scrollable Quantum Midnight dialog for OTA update announcements."""

    def __init__(
        self,
        current_version: str,
        latest_version: str,
        release_notes: str,
        download_url: str = "",
        has_installer: bool = True,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.download_url = str(download_url or "").strip()
        self.setWindowTitle(_("upd_available_title", "Update Available"))

        # Clamp dialog geometry cleanly so it never overflows smaller laptop displays
        target_w, target_h = 660, 560
        min_w, min_h = 580, 480
        max_w, max_h = 820, 680
        screen = QGuiApplication.primaryScreen()
        if screen is not None:
            avail = screen.availableGeometry()
            max_w = max(320, min(max_w, int(avail.width() * 0.85)))
            max_h = max(320, min(max_h, int(avail.height() * 0.85)))
            min_w = min(min_w, max_w)
            min_h = min(min_h, max_h)
            target_w = max(min_w, min(target_w, max_w))
            target_h = max(min_h, min(target_h, max_h))

        self.setMinimumSize(min_w, min_h)
        self.setMaximumSize(820, 680)
        self.resize(target_w, target_h)
        self.setStyleSheet("""
            QDialog {
                background-color: #0F172A;
                color: #F8FAFC;
            }
            QLabel {
                color: #F8FAFC;
            }
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Top Indigo -> Cyan gradient accent strip
        accent_bar = QFrame()
        accent_bar.setFixedHeight(3)
        accent_bar.setStyleSheet(
            "background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #6366F1, stop:1 #06B6D4); border: none;"
        )
        root.addWidget(accent_bar)

        body = QVBoxLayout()
        body.setContentsMargins(22, 18, 22, 18)
        body.setSpacing(14)
        root.addLayout(body, 1)

        # Hero Header Card
        hero = QFrame()
        hero.setStyleSheet(
            "QFrame { background-color: #1E293B; border: 1px solid #334155; border-radius: 10px; }"
        )
        h_lay = QHBoxLayout(hero)
        h_lay.setContentsMargins(16, 14, 16, 14)
        h_lay.setSpacing(14)

        logo_lbl = QLabel()
        logo_lbl.setFixedSize(44, 44)
        logo_lbl.setStyleSheet("border: none; background: transparent;")
        logo_path = _resolve_logo_path()
        if os.path.exists(logo_path):
            pix = QPixmap(logo_path).scaled(44, 44, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            logo_lbl.setPixmap(pix)
        else:
            logo_lbl.setText("IT")
            logo_lbl.setAlignment(Qt.AlignCenter)
            logo_lbl.setStyleSheet(
                "background-color: #4F46E5; color: #FFFFFF; font-weight: bold; border-radius: 10px; font-size: 16px;"
            )
        h_lay.addWidget(logo_lbl)

        h_text = QVBoxLayout()
        h_text.setSpacing(6)

        badge = QLabel(_("upd_badge_new", "NEW UPDATE AVAILABLE"))
        badge.setStyleSheet(
            "background-color: #1E1B4B; color: #38BDF8; border: 1px solid #4F46E5; "
            "border-radius: 4px; padding: 2px 8px; font-size: 10px; font-weight: bold;"
        )
        badge_row = QHBoxLayout()
        badge_row.setContentsMargins(0, 0, 0, 0)
        badge_row.addWidget(badge)
        badge_row.addStretch()
        h_text.addLayout(badge_row)

        self.headline_lbl = QLabel(_("upd_available_msg", "Version {} is available!").format(latest_version))
        self.headline_lbl.setStyleSheet("font-size: 16px; font-weight: bold; color: #FFFFFF; border: none;")
        h_text.addWidget(self.headline_lbl)

        ver_row = QHBoxLayout()
        ver_row.setContentsMargins(0, 0, 0, 0)
        ver_row.setSpacing(8)
        cur_pill = QLabel(f"{_('upd_lbl_current', 'Current')}: {current_version}")
        cur_pill.setStyleSheet(
            "background-color: #0F172A; color: #94A3B8; border: 1px solid #334155; "
            "border-radius: 5px; padding: 2px 8px; font-size: 11px; font-family: Consolas;"
        )
        arrow_lbl = QLabel("->")
        arrow_lbl.setStyleSheet("color: #64748B; font-weight: bold; border: none;")
        new_pill = QLabel(f"{_('upd_lbl_latest', 'New')}: {latest_version}")
        new_pill.setStyleSheet(
            "background-color: #064E3B; color: #34D399; border: 1px solid #10B981; "
            "border-radius: 5px; padding: 2px 8px; font-size: 11px; font-weight: bold; font-family: Consolas;"
        )
        ver_row.addWidget(cur_pill)
        ver_row.addWidget(arrow_lbl)
        ver_row.addWidget(new_pill)
        ver_row.addStretch()
        h_text.addLayout(ver_row)

        h_lay.addLayout(h_text, 1)
        body.addWidget(hero)

        # Scrollable Release Notes Card
        notes_card = QFrame()
        notes_card.setStyleSheet(
            "QFrame { background-color: #0B1220; border: 1px solid #334155; border-radius: 10px; }"
        )
        nc_lay = QVBoxLayout(notes_card)
        nc_lay.setContentsMargins(14, 12, 14, 12)
        nc_lay.setSpacing(8)

        nhdr = QHBoxLayout()
        nlbl = QLabel(_("upd_notes_header", "What's New — Release Notes"))
        nlbl.setStyleSheet("color: #CBD5E1; font-size: 12.5px; font-weight: bold; border: none;")
        nhdr.addWidget(nlbl)
        nhdr.addStretch()
        tag_pill = QLabel(str(latest_version))
        tag_pill.setStyleSheet(
            "color: #94A3B8; background-color: #1E293B; border: 1px solid #334155; "
            "border-radius: 4px; padding: 1px 7px; font-size: 11px; font-family: Consolas;"
        )
        nhdr.addWidget(tag_pill)
        nc_lay.addLayout(nhdr)

        self.notes_browser = QTextBrowser()
        self.notes_browser.setReadOnly(True)
        self.notes_browser.setOpenExternalLinks(True)
        self.notes_browser.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.notes_browser.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.notes_browser.setStyleSheet("""
            QTextBrowser {
                background-color: #0B1220;
                color: #CBD5E1;
                border: none;
                padding: 4px;
            }
            QScrollBar:vertical {
                background: #0F172A;
                width: 8px;
                border-radius: 4px;
                margin: 2px 0;
            }
            QScrollBar::handle:vertical {
                background: #334155;
                min-height: 28px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical:hover {
                background: #6366F1;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: #0B1220;
                border-radius: 4px;
            }
        """)
        self.notes_browser.setHtml(markdown_to_quantum_html(release_notes))
        nc_lay.addWidget(self.notes_browser, 1)
        body.addWidget(notes_card, 1)

        # Pinned Footer Action Bar
        hint_lbl = QLabel(_("upd_footer_hint", "The installer will download automatically and launch safely."))
        hint_lbl.setStyleSheet("color: #94A3B8; font-size: 11px;")
        hint_lbl.setWordWrap(True)

        foot = QHBoxLayout()
        foot.setSpacing(10)

        self.github_btn = QPushButton(_("upd_btn_github", "View on GitHub"))
        self.github_btn.setCursor(Qt.PointingHandCursor)
        self.github_btn.setEnabled(bool(self.download_url))
        self.github_btn.clicked.connect(self._open_release_page)
        self.github_btn.setStyleSheet("""
            QPushButton {
                background-color: #1E293B;
                color: #CBD5E1;
                border: 1px solid #334155;
                border-radius: 7px;
                padding: 8px 14px;
                font-size: 12.5px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #334155;
                color: #FFFFFF;
            }
        """)

        self.later_btn = QPushButton(_("upd_btn_later", "Later"))
        self.later_btn.setCursor(Qt.PointingHandCursor)
        self.later_btn.clicked.connect(self.reject)
        self.later_btn.setStyleSheet("""
            QPushButton {
                background-color: #1E293B;
                color: #E2E8F0;
                border: 1px solid #475569;
                border-radius: 7px;
                padding: 8px 16px;
                font-size: 12.5px;
                font-weight: 600;
                min-width: 90px;
            }
            QPushButton:hover {
                background-color: #334155;
            }
        """)

        cta_label = _("upd_btn_download_install", "Download && Install") if has_installer else _("upd_btn_update", "Update")
        self.update_btn = QPushButton(cta_label)
        self.update_btn.setCursor(Qt.PointingHandCursor)
        self.update_btn.setDefault(True)
        self.update_btn.clicked.connect(self.accept)
        self.update_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #4F46E5, stop:1 #2563EB);
                color: #FFFFFF;
                border: none;
                border-radius: 7px;
                padding: 8px 18px;
                font-size: 12.5px;
                font-weight: bold;
                min-width: 140px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #6366F1, stop:1 #3B82F6);
            }
            QPushButton:pressed {
                background-color: #1D4ED8;
            }
        """)

        foot.addWidget(self.github_btn)
        foot.addStretch()
        foot.addWidget(self.later_btn)
        foot.addWidget(self.update_btn)

        body.addWidget(hint_lbl)
        body.addLayout(foot)

    def _open_release_page(self) -> None:
        if self.download_url:
            webbrowser.open(self.download_url)

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
                latest_version = data.get("tag_name", "2.0.0")
                
                if latest_version.lower().strip() != CURRENT_VERSION.lower().strip():
                    release_notes = data.get("body", _("upd_no_notes"))
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
                    self.no_update_or_error.emit(False, _("upd_up_to_date_title"), _("upd_up_to_date_msg"))
            else:
                self.no_update_or_error.emit(True, _("upd_error"), _("upd_check_error").format(response.status_code))
        except Exception as e:
            self.no_update_or_error.emit(True, _("upd_update_error_title"), _("upd_update_error_msg").format(str(e)))

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
            dlg = UpdateAvailableDialog(
                current_version=CURRENT_VERSION,
                latest_version=latest_version,
                release_notes=release_notes,
                download_url=download_url,
                has_installer=bool(exe_url),
                parent=self.parent,
            )
            accepted = dlg.exec() == QDialog.Accepted

            if accepted:
                if exe_url:
                    self._start_download(exe_url)
                else:
                    webbrowser.open(download_url)
                    self.finished.emit()
            else:
                self.finished.emit()
        else:
            self.finished.emit()

    def _start_download(self, exe_url):
        self.progress_dialog = QProgressDialog(_("upd_downloading"), _("upd_btn_cancel"), 0, 100, self.parent)
        self.progress_dialog.setWindowTitle(_("upd_download_title"))
        self.progress_dialog.setMinimumWidth(440)
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
            QMessageBox.critical(self.parent, _("upd_install_error_title"), _("upd_install_error_msg").format(str(e)))
            self.finished.emit()

    @Slot(str)
    def _on_download_error(self, err_msg):
        if self.progress_dialog:
            self.progress_dialog.close()
            
        # Error notification and fallback to browser download
        msg = QMessageBox(self.parent)
        msg.setWindowTitle(_("upd_download_error_title"))
        msg.setText(_("upd_download_error_msg"))
        msg.setInformativeText(_("upd_download_error_info").format(err_msg))
        
        yes_btn = msg.addButton(_("upd_btn_yes"), QMessageBox.YesRole)
        no_btn = msg.addButton(_("upd_btn_no"), QMessageBox.NoRole)
        
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
