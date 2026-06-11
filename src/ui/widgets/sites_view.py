from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTableWidget, QTableWidgetItem, QLineEdit, 
                             QHeaderView, QMessageBox, QFrame, QComboBox, QFileDialog,
                             QSizePolicy, QAbstractItemView)
from PySide6.QtCore import Qt, QThread, Signal, QSize
from PySide6.QtGui import QColor, QIcon
import subprocess
import platform
import threading
import csv
import os

class PingWorker(QThread):
    """Worker thread for pinging a single host."""
    result = Signal(int, str, float)  # row_index, status ("up"/"down"), latency_ms
    
    def __init__(self, row_index, ip):
        super().__init__()
        self.row_index = row_index
        self.ip = ip
    
    def run(self):
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            cmd = ["ping", param, "1", "-w", "2000", self.ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5,
                                    creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == "windows" else 0)
            
            if result.returncode == 0:
                # Parse latency from output
                import re
                output = result.stdout
                # Windows: Average = XXms  |  Linux: time=XX.X ms
                match = re.search(r'(?:time[=<]|Average\s*=\s*)(\d+\.?\d*)\s*ms', output, re.IGNORECASE)
                latency = float(match.group(1)) if match else 0.0
                self.result.emit(self.row_index, "up", latency)
            else:
                self.result.emit(self.row_index, "down", 0.0)
        except Exception:
            self.result.emit(self.row_index, "down", 0.0)


class SitesView(QWidget):
    open_in_browser = Signal(str)  # Signal to open URL in Web Manager
    
    def __init__(self, logger, config_manager):
        super().__init__()
        self.logger = logger
        self.config = config_manager
        self.ping_workers = []
        self._editing_index = -1  # -1 = add mode, >= 0 = editing that index
        
        # Path to icons
        self.icons_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..", "assets", "icons")
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(30, 25, 30, 30)
        self.layout.setSpacing(18)
        
        # ── Header Row: Title + Ping All ──
        header_row = QHBoxLayout()
        header_row.setContentsMargins(0, 0, 0, 0)
        
        header = QLabel("Sites & Equipment Manager")
        header.setObjectName("Title")
        header_row.addWidget(header)
        
        header_row.addStretch()
        
        self.ping_all_btn = QPushButton("  Ping All")
        self.ping_all_btn.setObjectName("PrimaryButton")
        self._set_btn_icon(self.ping_all_btn, "activity.svg")
        self.ping_all_btn.setFixedHeight(38)
        self.ping_all_btn.setMinimumWidth(140)
        self.ping_all_btn.setCursor(Qt.PointingHandCursor)
        self.ping_all_btn.clicked.connect(self.ping_all)
        header_row.addWidget(self.ping_all_btn)
        
        self.layout.addLayout(header_row)
        
        # ── Add Equipment Form Card ──
        form_card = QFrame()
        form_card.setObjectName("Card")
        form_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        form_layout = QHBoxLayout(form_card)
        form_layout.setContentsMargins(20, 18, 20, 18)
        form_layout.setSpacing(12)
        
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Equipment Name (e.g. Peplink 1)")
        self.name_input.setFixedHeight(35)
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("IP Address or URL")
        self.ip_input.setFixedHeight(35)
        
        self.site_input = QLineEdit()
        self.site_input.setPlaceholderText("Site Name (e.g. Paris Office)")
        self.site_input.setFixedHeight(35)
        
        self.add_btn = QPushButton("Add Equipment")
        self.add_btn.setObjectName("PrimaryButton")
        self.add_btn.setFixedHeight(35)
        self.add_btn.setMinimumWidth(150)
        self.add_btn.setCursor(Qt.PointingHandCursor)
        self.add_btn.clicked.connect(self.add_site)
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("DangerButton")
        self.cancel_btn.setFixedHeight(35)
        self.cancel_btn.setMinimumWidth(90)
        self.cancel_btn.setCursor(Qt.PointingHandCursor)
        self.cancel_btn.clicked.connect(self.cancel_edit)
        self.cancel_btn.setVisible(False)
        
        form_layout.addWidget(self.name_input, 2)
        form_layout.addWidget(self.ip_input, 2)
        form_layout.addWidget(self.site_input, 2)
        form_layout.addWidget(self.add_btn)
        form_layout.addWidget(self.cancel_btn)
        
        self.layout.addWidget(form_card)
        
        # ── Toolbar Row: Filter + Import/Export ──
        toolbar_row = QHBoxLayout()
        toolbar_row.setContentsMargins(0, 0, 0, 0)
        toolbar_row.setSpacing(12)
        
        # Filter by Site
        filter_label = QLabel("Filter by Site:")
        filter_label.setStyleSheet("color: #94A3B8; font-weight: 600; font-size: 12px; margin-bottom: 0px;")
        toolbar_row.addWidget(filter_label)
        
        self.site_filter = QComboBox()
        self.site_filter.setFixedHeight(35)
        self.site_filter.setMinimumWidth(180)
        self.site_filter.addItem("All Sites")
        self.site_filter.currentIndexChanged.connect(self.apply_filter)
        toolbar_row.addWidget(self.site_filter)
        
        toolbar_row.addStretch()
        
        # Import CSV Button
        self.import_btn = QPushButton(" Import CSV")
        self.import_btn.setObjectName("SecondaryButton")
        self._set_btn_icon(self.import_btn, "layers.svg")
        self.import_btn.setFixedHeight(35)
        self.import_btn.setMinimumWidth(140)
        self.import_btn.setCursor(Qt.PointingHandCursor)
        self.import_btn.clicked.connect(self.import_csv)
        toolbar_row.addWidget(self.import_btn)
        
        # Export PDF Button
        self.export_btn = QPushButton(" Export PDF")
        self.export_btn.setObjectName("SecondaryButton")
        self._set_btn_icon(self.export_btn, "history.svg") # Using history as a 'report' icon
        self.export_btn.setFixedHeight(35)
        self.export_btn.setMinimumWidth(140)
        self.export_btn.setCursor(Qt.PointingHandCursor)
        self.export_btn.clicked.connect(self.export_pdf)
        toolbar_row.addWidget(self.export_btn)
        
        self.layout.addLayout(toolbar_row)
        
        # ── Equipment Table ──
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Name", "IP Address", "Site", "Status", "Actions"])
        
        # Table Alignment & Sizing
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        header.setSectionResizeMode(4, QHeaderView.Fixed)
        self.table.setColumnWidth(3, 120)
        self.table.setColumnWidth(4, 165)
        
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #1E293B;
                alternate-background-color: #161E2D;
                border: 1px solid rgba(255, 255, 255, 0.05);
                border-radius: 12px;
                gridline-color: transparent;
            }
            QTableWidget::item {
                padding-left: 20px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.02);
            }
            QHeaderView::section {
                background-color: #0F172A;
                padding-left: 20px;
                text-align: left;
                font-weight: bold;
                text-transform: uppercase;
                letter-spacing: 1px;
                font-size: 11px;
            }
        """)
        self.layout.addWidget(self.table)
        
        # ── Stats Footer ──
        self.stats_label = QLabel("")
        self.stats_label.setStyleSheet("color: #64748B; font-size: 11px; margin-top: 2px; margin-bottom: 0px;")
        self.layout.addWidget(self.stats_label)
        
        self.refresh_table()

    def _set_btn_icon(self, btn, icon_name):
        icon_path = os.path.join(self.icons_dir, icon_name)
        if os.path.exists(icon_path):
            btn.setIcon(QIcon(icon_path))
            btn.setIconSize(QSize(16, 16))

    # ───────────────────────── CRUD Operations ─────────────────────────
    
    def add_site(self):
        name = self.name_input.text().strip()
        ip = self.ip_input.text().strip()
        site = self.site_input.text().strip()
        
        if not name or not ip:
            QMessageBox.warning(self, "Error", "Name and IP are required.")
            return
        
        sites = self.config.get("sites")
        
        if self._editing_index >= 0:
            # Update existing entry
            if self._editing_index < len(sites):
                sites[self._editing_index] = {"name": name, "ip": ip, "site": site}
                self.config.set("sites", sites)
            self._exit_edit_mode()
        else:
            # Add new entry
            sites.append({"name": name, "ip": ip, "site": site})
            self.config.set("sites", sites)
        
        self.name_input.clear()
        self.ip_input.clear()
        self.site_input.clear()
        
        self.refresh_table()
    
    def edit_site(self, index):
        """Populate the form with the site data and switch to edit mode."""
        sites = self.config.get("sites")
        if 0 <= index < len(sites):
            site = sites[index]
            self._editing_index = index
            self.name_input.setText(site["name"])
            self.ip_input.setText(site["ip"])
            self.site_input.setText(site.get("site", ""))
            self.add_btn.setText("Save Changes")
            self.add_btn.setStyleSheet("background-color: #F59E0B; color: #000;")
            self.cancel_btn.setVisible(True)
            self.name_input.setFocus()
    
    def cancel_edit(self):
        """Cancel edit mode and clear the form."""
        self._exit_edit_mode()
        self.name_input.clear()
        self.ip_input.clear()
        self.site_input.clear()
    
    def _exit_edit_mode(self):
        """Reset form back to add mode."""
        self._editing_index = -1
        self.add_btn.setText("Add Equipment")
        self.add_btn.setStyleSheet("")
        self.cancel_btn.setVisible(False)

    def delete_site(self, index):
        sites = self.config.get("sites")
        if 0 <= index < len(sites):
            name = sites[index]["name"]
            del sites[index]
            self.config.set("sites", sites)
            self.refresh_table()

    # ───────────────────────── Table Rendering ─────────────────────────
    
    def refresh_table(self):
        """Rebuild the table and update the filter dropdown."""
        sites = self.config.get("sites")
        
        # Update filter dropdown
        current_filter = self.site_filter.currentText()
        self.site_filter.blockSignals(True)
        self.site_filter.clear()
        self.site_filter.addItem("All Sites")
        
        unique_sites = sorted(set(s.get("site", "") for s in sites if s.get("site", "")))
        for site_name in unique_sites:
            self.site_filter.addItem(site_name)
        
        idx = self.site_filter.findText(current_filter)
        self.site_filter.setCurrentIndex(idx if idx >= 0 else 0)
        self.site_filter.blockSignals(False)
        
        self._populate_table(sites)
    
    def _populate_table(self, sites):
        active_filter = self.site_filter.currentText()
        
        if active_filter != "All Sites":
            filtered = [s for s in sites if s.get("site", "") == active_filter]
        else:
            filtered = sites
        
        self.table.setRowCount(0)
        
        for i, site in enumerate(filtered):
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setRowHeight(row, 50)
            
            # Find real index
            all_sites = self.config.get("sites")
            real_index = next((j for j, s in enumerate(all_sites) 
                              if s["name"] == site["name"] and s["ip"] == site["ip"]), i)
            
            # Name - Centered
            name_item = QTableWidgetItem(site["name"])
            name_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 0, name_item)
            
            # IP Address - Centered
            ip_item = QTableWidgetItem(site["ip"])
            ip_item.setTextAlignment(Qt.AlignCenter)
            ip_item.setForeground(QColor("#6366F1")) 
            self.table.setItem(row, 1, ip_item)
            
            # Site - Centered
            site_item = QTableWidgetItem(site.get("site", "—"))
            site_item.setTextAlignment(Qt.AlignCenter)
            site_item.setForeground(QColor("#94A3B8"))
            self.table.setItem(row, 2, site_item)
            
            # Status - Centered
            status_item = QTableWidgetItem("—")
            status_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 3, status_item)
            
            # Actions
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(6, 0, 6, 0)
            action_layout.setSpacing(6)
            action_layout.setAlignment(Qt.AlignCenter)
            
            ping_btn = QPushButton()
            ping_btn.setFixedSize(32, 32)
            ping_btn.setCursor(Qt.PointingHandCursor)
            ping_btn.setToolTip("Quick Ping")
            self._set_btn_icon(ping_btn, "zap.svg")
            ping_btn.setStyleSheet("background: rgba(99, 102, 241, 0.1); border: 1px solid rgba(99, 102, 241, 0.2); border-radius: 6px;")
            ping_btn.clicked.connect(lambda checked, r=row, s=site: self.quick_ping(r, s))
            
            browse_btn = QPushButton()
            browse_btn.setFixedSize(32, 32)
            browse_btn.setCursor(Qt.PointingHandCursor)
            browse_btn.setToolTip("Open in Web Manager")
            self._set_btn_icon(browse_btn, "browser.svg")
            browse_btn.setStyleSheet("background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 6px;")
            browse_btn.clicked.connect(lambda checked, s=site: self.open_in_browser.emit(s["ip"]))
            
            edit_btn = QPushButton()
            edit_btn.setFixedSize(32, 32)
            edit_btn.setCursor(Qt.PointingHandCursor)
            edit_btn.setToolTip("Edit")
            self._set_btn_icon(edit_btn, "edit.svg")
            edit_btn.setStyleSheet("background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.2); border-radius: 6px;")
            edit_btn.clicked.connect(lambda checked, idx=real_index: self.edit_site(idx))
            
            delete_btn = QPushButton()
            delete_btn.setFixedSize(32, 32)
            delete_btn.setCursor(Qt.PointingHandCursor)
            delete_btn.setToolTip("Delete")
            self._set_btn_icon(delete_btn, "trash.svg")
            delete_btn.setStyleSheet("background: rgba(244, 63, 94, 0.1); border: 1px solid rgba(244, 63, 94, 0.2); border-radius: 6px;")
            delete_btn.clicked.connect(lambda checked, idx=real_index: self.delete_site(idx))
            
            action_layout.addWidget(ping_btn)
            action_layout.addWidget(browse_btn)
            action_layout.addWidget(edit_btn)
            action_layout.addWidget(delete_btn)
            self.table.setCellWidget(row, 4, action_widget)
        
        total = len(self.config.get("sites"))
        shown = len(filtered)
        unique_sites_count = len(set(s.get("site", "") for s in self.config.get("sites") if s.get("site", "")))
        self.stats_label.setText(f"Showing {shown} of {total} equipment(s)  •  {unique_sites_count} site(s)")

    # ───────────────────────── Filter ─────────────────────────
    
    def apply_filter(self):
        sites = self.config.get("sites")
        self._populate_table(sites)

    # ───────────────────────── Ping Functions ─────────────────────────
    
    def quick_ping(self, row, site):
        ip = site["ip"]
        clean_ip = self._clean_ip(ip)
        
        status_item = self.table.item(row, 3)
        if status_item:
            status_item.setText("...")
            status_item.setForeground(QColor("#F59E0B"))
        
        worker = PingWorker(row, clean_ip)
        worker.result.connect(self._update_ping_result)
        worker.start()
        self.ping_workers.append(worker)
    
    def ping_all(self):
        self.ping_all_btn.setEnabled(False)
        self.ping_all_btn.setText(" Pinging...")
        
        row_count = self.table.rowCount()
        if row_count == 0:
            self.ping_all_btn.setEnabled(True)
            self.ping_all_btn.setText(" Ping All")
            return
        
        self._pending_pings = row_count
        
        for row in range(row_count):
            ip_item = self.table.item(row, 1)
            if ip_item:
                ip = ip_item.text()
                clean_ip = self._clean_ip(ip)
                status_item = self.table.item(row, 3)
                if status_item:
                    status_item.setText("...")
                    status_item.setForeground(QColor("#F59E0B"))
                
                worker = PingWorker(row, clean_ip)
                worker.result.connect(self._update_ping_result)
                worker.result.connect(self._check_ping_all_done)
                worker.start()
                self.ping_workers.append(worker)
    
    def _update_ping_result(self, row, status, latency):
        if row >= self.table.rowCount(): return
        status_item = self.table.item(row, 3)
        if not status_item: return
            
        if status == "up":
            status_item.setText(f"{latency:.0f} ms")
            status_item.setForeground(QColor("#10B981"))
        else:
            status_item.setText("Down")
            status_item.setForeground(QColor("#F43F5E"))
    
    def _check_ping_all_done(self, row, status, latency):
        if hasattr(self, '_pending_pings'):
            self._pending_pings -= 1
            if self._pending_pings <= 0:
                self.ping_all_btn.setEnabled(True)
                self.ping_all_btn.setText(" Ping All")
                del self._pending_pings
    
    def _clean_ip(self, ip):
        import re
        ip = re.sub(r'^https?://', '', ip)
        ip = re.split(r'[:/]', ip)[0]
        return ip

    def import_csv(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Import Equipment from CSV", "", "CSV Files (*.csv)")
        if not file_path: return
        try:
            imported = 0
            sites = self.config.get("sites")
            with open(file_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    name = (row.get("Name") or row.get("Equipment") or "").strip()
                    ip = (row.get("IP Address") or row.get("IP") or "").strip()
                    site = (row.get("Site") or row.get("Location") or "").strip()
                    if name and ip:
                        sites.append({"name": name, "ip": ip, "site": site})
                        imported += 1
            self.config.set("sites", sites)
            self.refresh_table()
            QMessageBox.information(self, "Import Complete", f"Imported {imported} equipment(s).")
        except Exception as e:
            QMessageBox.critical(self, "Import Error", str(e))

    def export_pdf(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Export to PDF", "BahaaIT_Report.pdf", "PDF Files (*.pdf)")
        if not file_path: return
        try:
            from PySide6.QtGui import QTextDocument
            from PySide6.QtPrintSupport import QPrinter
            sites = self.config.get("sites")
            html = "<h1>Sites & Equipment Report</h1><table><tr><th>#</th><th>Name</th><th>IP</th><th>Site</th></tr>"
            for i, site in enumerate(sites, 1):
                html += f"<tr><td>{i}</td><td>{site['name']}</td><td>{site['ip']}</td><td>{site.get('site', '—')}</td></tr>"
            html += "</table>"
            printer = QPrinter(QPrinter.HighResolution)
            printer.setOutputFormat(QPrinter.PdfFormat)
            printer.setOutputFileName(file_path)
            doc = QTextDocument()
            doc.setHtml(html)
            doc.print_(printer)
            QMessageBox.information(self, "Export Complete", "PDF saved.")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))
