from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTableWidget, QTableWidgetItem, QLineEdit, 
                             QHeaderView, QFileDialog, QMessageBox, QTextEdit)
from PySide6.QtCore import Qt, QDateTime, QTimer
from PySide6.QtGui import QIcon, QColor
import os
from core.monitor import PingWorker
from ui.widgets.latency_graph import LatencyGraphDialog
from ui.widgets.history_dialog import HostHistoryDialog
from utils.db import DatabaseManager
from utils.pdf_generator import PDFReportGenerator
from utils.email_notifier import EmailNotifier
from utils.i18n import _

class MonitorView(QWidget):
    def __init__(self, logger, alarm_manager=None, config_manager=None):
        super().__init__()
        self.logger = logger
        self.alarm_manager = alarm_manager
        self.config = config_manager
        self.worker = None
        self.db = DatabaseManager()
        self.email_notifier = EmailNotifier(self.logger, self.config)
        self.is_monitoring_active = False
        self.graph_dialogs = {} # {host: dialog}
        
        # Load from config or use defaults
        saved_hosts = self.db.get_hosts() # Load from DB for labels
        self.hosts = {}
        for h in saved_hosts:
            self.hosts[h['address']] = {
                "label": h['label'] or "N/A",
                "active": True, 
                "status": "N/A", 
                "latency": 0, 
                "logs": [],
                "consecutive_down": 0,
                "email_sent_down": False
            }
        
        # Load saved alarm
        if self.config and self.alarm_manager:
            saved_sound = self.config.get("alarm_sound")
            if saved_sound and os.path.exists(saved_sound):
                self.alarm_manager.set_source(saved_sound)
            
            saved_enabled = self.config.get("alarm_enabled")
            self.alarm_manager.set_enabled(saved_enabled)
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(30, 30, 30, 30)
        
        # Header
        header_layout = QHBoxLayout()
        header = QLabel(_("mon_header_ping", "Ping Monitor"))
        header.setObjectName("Title")
        header_layout.addWidget(header)
        
        self.status_label = QLabel(_("mon_status_stopped", "Stopped"))
        self.status_label.setStyleSheet("color: #ff5252; font-weight: bold;")
        header_layout.addWidget(self.status_label)
        header_layout.addStretch()
        
        self.layout.addLayout(header_layout)
        
        # Controls
        controls = QHBoxLayout()
        controls.setSpacing(15)
        
        self.label_input = QLineEdit()
        self.label_input.setPlaceholderText(_("mon_name_optional_placeholder", "Device Name (optional)..."))
        self.label_input.setFixedWidth(200)
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText(_("mon_ip_placeholder", "IP Address or Hostname..."))
        self.ip_input.returnPressed.connect(self.add_host)
        
        self.add_btn = QPushButton(_("mon_btn_add", "Add Host"))
        self.add_btn.setObjectName("SecondaryButton")
        self.add_btn.setMinimumWidth(120)
        self.add_btn.clicked.connect(self.add_host)
        
        self.start_btn = QPushButton(_("mon_btn_start", "Start Monitor"))
        self.start_btn.setObjectName("PrimaryButton")
        self.start_btn.setMinimumWidth(150)
        self.start_btn.clicked.connect(self.toggle_monitor)
        
        controls.addWidget(self.label_input)
        controls.addWidget(self.ip_input)
        controls.addWidget(self.add_btn)
        controls.addWidget(self.start_btn)
        self.layout.addLayout(controls)
        
        # Table
        self.table = QTableWidget(0, 5) # Label, Host, Status, Latency, Actions
        self.table.setHorizontalHeaderLabels([
            _("mon_table_name", "DEVICE NAME").upper(), 
            _("mon_table_host", "HOST ADDRESS").upper(), 
            _("mon_table_status", "STATUS").upper(), 
            _("mon_table_latency", "LATENCY").upper(), 
            _("mon_table_actions", "ACTIONS").upper()
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Fixed)
        self.table.setColumnWidth(4, 220) # Increased width to avoid overlap
        
        # Lock row height
        self.table.verticalHeader().setDefaultSectionSize(50)
        self.table.verticalHeader().setVisible(False) # Hide row numbers for cleaner look
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        
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
        
        # Event Log
        self.layout.addWidget(QLabel(_("mon_event_log", "Event Log") + ":"))
        self.event_log = QTextEdit()
        self.event_log.setReadOnly(True)
        self.event_log.setMaximumHeight(150)
        self.event_log.setStyleSheet("""
            QTextEdit {
                background-color: #000000;
                color: #00ff00;
                font-family: 'Consolas', monospace;
                font-size: 11px;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 10px;
            }
        """)
        self.layout.addWidget(self.event_log)
        
        clear_log_btn = QPushButton(_("mon_btn_clear", "Clear Log"))
        clear_log_btn.setObjectName("SecondaryButton")
        clear_log_btn.setFixedWidth(100)
        clear_log_btn.clicked.connect(self.event_log.clear)
        
        self.export_log_btn = QPushButton(_("mon_btn_export", "Export Log"))
        self.export_log_btn.setObjectName("SecondaryButton")
        self.export_log_btn.setMinimumWidth(120)
        self.export_log_btn.clicked.connect(self.export_log)
        
        self.export_pdf_btn = QPushButton(_("mon_btn_export_pdf", "Export PDF"))
        self.export_pdf_btn.setObjectName("SecondaryButton")
        self.export_pdf_btn.setMinimumWidth(120)
        self.export_pdf_btn.clicked.connect(self.export_pdf)
        
        log_btns = QHBoxLayout()
        log_btns.addStretch()
        log_btns.addWidget(self.export_log_btn)
        log_btns.addWidget(self.export_pdf_btn)
        log_btns.addWidget(clear_log_btn)
        self.layout.addLayout(log_btns)
        
        self.refresh_table()

    def add_log_entry(self, message, level="INFO"):
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd HH:mm:ss")
        color = "#00ff00" # Green for INFO
        if level == "WARNING": color = "#ff9800" # Orange
        elif level == "ERROR": color = "#ff5252" # Red
        
        log_msg = f'<span style="color: #888;">[{timestamp}]</span> <span style="color: {color};">[{level}]</span> {message}'
        self.event_log.append(log_msg)


    def export_log(self):
        if self.event_log.toPlainText().strip() == "":
            QMessageBox.warning(self, _("msg_warning"), _("mon_log_empty"))
            return
            
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self, _("mon_export_log_title"), "", "Text Files (*.txt);;CSV Files (*.csv)"
        )
        
        if file_path:
            try:
                content = self.event_log.toPlainText()
                if selected_filter == "CSV Files (*.csv)":
                    # Simple conversion for CSV (cleaning HTML tags if any)
                    import re
                    clean_content = re.sub(r'<[^>]+>', '', content)
                    # Add CSV headers if needed
                else:
                    import re
                    clean_content = re.sub(r'<[^>]+>', '', content)
                
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(clean_content)
                self.add_log_entry(_("mon_log_exported").format(file_path))
                QMessageBox.information(self, _("msg_success"), _("mon_export_success"))
            except Exception as e:
                self.add_log_entry(_("mon_export_fail_log").format(str(e)), "ERROR")
                QMessageBox.critical(self, _("msg_error"), _("mon_export_fail_msg").format(str(e)))

    def export_pdf(self):
        if not self.hosts:
            QMessageBox.warning(self, _("msg_warning"), _("mon_no_hosts"))
            return
            
        file_path, _filter = QFileDialog.getSaveFileName(
            self, _("mon_export_pdf_title"), "BahaaIT_Network_Report.pdf", "PDF Files (*.pdf)"
        )
        
        if file_path:
            data = []
            for ip, info in self.hosts.items():
                history = self.db.get_host_history(ip, limit=100)
                if history:
                    up_count = sum(1 for log in history if log["status"] == "UP")
                    availability = (up_count / len(history)) * 100.0
                else:
                    availability = 100.0 if info["status"] == "UP" else 0.0
                data.append({
                    "label": info["label"],
                    "ip": ip,
                    "status": info["status"],
                    "latency": info["latency"],
                    "availability": availability
                })
                
            event_log_text = self.event_log.toPlainText()
            generator = PDFReportGenerator()
            success, msg = generator.generate_monitor_report(data, file_path, event_log_text)
            
            if success:
                self.add_log_entry(_("mon_pdf_generated").format(file_path))
                QMessageBox.information(self, _("msg_success"), _("mon_pdf_export_success"))
            else:
                self.add_log_entry(_("mon_pdf_fail_log").format(msg), "ERROR")
                QMessageBox.critical(self, _("msg_error"), _("mon_pdf_fail_msg").format(msg))

    def add_host(self):
        host = self.ip_input.text().strip()
        label = self.label_input.text().strip() or "Device"
        if host:
            # Update local memory
            self.hosts[host] = {
                "label": label, 
                "active": self.hosts[host]["active"] if host in self.hosts else True, 
                "status": self.hosts[host]["status"] if host in self.hosts else "N/A", 
                "latency": self.hosts[host]["latency"] if host in self.hosts else 0, 
                "logs": self.hosts[host]["logs"] if host in self.hosts else [],
                "consecutive_down": self.hosts[host]["consecutive_down"] if host in self.hosts else 0,
                "email_sent_down": self.hosts[host]["email_sent_down"] if host in self.hosts else False
            }
            # Update Database
            self.db.add_host(host, label)
            
            if self.config:
                self.config.set("monitored_hosts", list(self.hosts.keys()))
                
            self.ip_input.clear()
            self.label_input.clear()
            self.add_log_entry(f"Host updated/added: {host} ({label})")
            self.refresh_table()
            self.sync_worker()

    def toggle_pause(self, host):
        if host in self.hosts:
            self.hosts[host]["active"] = not self.hosts[host]["active"]
            status = "resumed" if self.hosts[host]["active"] else "paused"
            if not self.hosts[host]["active"]:
                self.hosts[host]["status"] = "PAUSED"
                self.hosts[host]["latency"] = 0
            self.add_log_entry(f"Host {host} {status}")
            self.refresh_table()
            self.sync_worker()

    def delete_host(self, host):
        if host in self.hosts:
            del self.hosts[host]
            self.db.delete_host(host)
            if self.config:
                self.config.set("monitored_hosts", list(self.hosts.keys()))
            self.add_log_entry(f"Host deleted: {host}", "WARNING")
            self.refresh_table()
            self.sync_worker()

    def sync_worker(self):
        if self.worker and self.worker.isRunning():
            hosts_data = {h: data["active"] for h, data in self.hosts.items()}
            self.worker.update_hosts(hosts_data)

    def refresh_table(self):
        self.table.setRowCount(0)
        for host, data in self.hosts.items():
            row = self.table.rowCount()
            self.table.insertRow(row)
            
            label_item = QTableWidgetItem(data["label"])
            label_item.setTextAlignment(Qt.AlignCenter)
            label_item.setForeground(QColor("#818CF8"))
            self.table.setItem(row, 0, label_item)
            
            host_item = QTableWidgetItem(host)
            host_item.setTextAlignment(Qt.AlignCenter)
            host_item.setForeground(QColor("#6366F1"))
            self.table.setItem(row, 1, host_item)
            
            status_item = QTableWidgetItem(data["status"])
            status_item.setTextAlignment(Qt.AlignCenter)
            if data["status"] == "UP":
                status_item.setForeground(Qt.green)
            elif data["status"] == "DOWN":
                status_item.setForeground(Qt.red)
            elif data["status"] == "PAUSED":
                status_item.setForeground(Qt.gray)
                
            self.table.setItem(row, 2, status_item)
            
            latency_item = QTableWidgetItem(f"{data['latency']} ms" if data["latency"] > 0 else "N/A")
            latency_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 3, latency_item)
            
            # Action Buttons
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(10, 0, 10, 0)
            action_layout.setSpacing(10)
            action_layout.setAlignment(Qt.AlignCenter)
            
            import sys
            if getattr(sys, 'frozen', False):
                icons_dir = os.path.join(sys._MEIPASS, "assets", "icons")
            else:
                icons_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..", "assets", "icons")
            
            pause_icon = "pause.svg" if data["active"] else "play.svg"
            pause_btn = QPushButton()
            pause_btn.setFixedSize(32, 32)
            pause_btn.setCursor(Qt.PointingHandCursor)
            pause_btn.setIcon(QIcon(os.path.join(icons_dir, pause_icon)))
            pause_btn.setToolTip(_("mon_tooltip_pause"))
            pause_btn.setStyleSheet("background: rgba(99, 102, 241, 0.1); border: 1px solid rgba(99, 102, 241, 0.2); border-radius: 6px;")
            pause_btn.clicked.connect(lambda checked, h=host: self.toggle_pause(h))
            
            graph_btn = QPushButton()
            graph_btn.setFixedSize(32, 32)
            graph_btn.setCursor(Qt.PointingHandCursor)
            graph_btn.setIcon(QIcon(os.path.join(icons_dir, "activity.svg"))) # Swapped 'chart.svg' to 'activity.svg' to match feather icon standard
            graph_btn.setToolTip(_("mon_tooltip_graph"))
            graph_btn.setStyleSheet("background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 6px;")
            graph_btn.clicked.connect(lambda checked, h=host: self.show_graph(h))

            history_btn = QPushButton()
            history_btn.setFixedSize(32, 32)
            history_btn.setCursor(Qt.PointingHandCursor)
            history_btn.setIcon(QIcon(os.path.join(icons_dir, "history.svg"))) # Reverted to history.svg
            history_btn.setToolTip(_("mon_tooltip_history"))
            history_btn.setStyleSheet("background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.2); border-radius: 6px;")
            history_btn.clicked.connect(lambda checked, h=host: self.show_history(h))
            
            delete_btn = QPushButton()
            delete_btn.setFixedSize(32, 32)
            delete_btn.setCursor(Qt.PointingHandCursor)
            delete_btn.setIcon(QIcon(os.path.join(icons_dir, "trash.svg")))
            delete_btn.setToolTip(_("mon_tooltip_delete"))
            delete_btn.setStyleSheet("background: rgba(244, 63, 94, 0.1); border: 1px solid rgba(244, 63, 94, 0.2); border-radius: 6px;")
            delete_btn.clicked.connect(lambda checked, h=host: self.delete_host(h))
            
            action_layout.addWidget(pause_btn)
            action_layout.addWidget(graph_btn)
            action_layout.addWidget(history_btn)
            action_layout.addWidget(delete_btn)
            
            self.table.setCellWidget(row, 4, action_widget)

    def show_history(self, host):
        if host in self.hosts:
            history = self.db.get_host_history(host, limit=200)
            formatted_history = []
            for h in history:
                resp = h['response'] if h.get('response') else "No details"
                formatted_history.append(f"[{h['timestamp']}] {resp}")
            dialog = HostHistoryDialog(host, formatted_history, self)
            dialog.exec()

    def show_graph(self, host):
        if host not in self.graph_dialogs or not self.graph_dialogs[host].isVisible():
            dialog = LatencyGraphDialog(host, self)
            self.graph_dialogs[host] = dialog
            dialog.show()
        else:
            self.graph_dialogs[host].raise_()
            self.graph_dialogs[host].activateWindow()

    def toggle_monitor(self):
        if not self.start_btn.isEnabled():
            return
            
        if self.is_monitoring_active:
            self.stop_monitor()
        else:
            self.start_monitor()

    def start_monitor(self):
        if self.is_monitoring_active:
            return
        self.is_monitoring_active = True
        self.start_btn.setEnabled(False) # Prevent fast simultaneous double-clicks during startup
        
        hosts_data = {h: data["active"] for h, data in self.hosts.items()}
        self.worker = PingWorker(hosts_data)
        self.worker.result_ready.connect(self.on_result)
        self.worker.finished.connect(self.on_monitor_finished)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.start()
        
        self.add_log_entry(_("mon_log_started", "Monitoring started"))
        self.start_btn.setText(_("mon_btn_stop", "Stop Monitor"))
        self.start_btn.setStyleSheet("background-color: #ff5252;")
        self.status_label.setText(_("mon_status_running", "Running"))
        self.status_label.setStyleSheet("color: #4caf50;")
        
        # Safely enable button back after a short transition period
        QTimer.singleShot(250, lambda: self.start_btn.setEnabled(True) if self.is_monitoring_active else None)

    def stop_monitor(self):
        if not self.is_monitoring_active:
            return
        self.is_monitoring_active = False
        
        # Stop alarm immediately
        if self.alarm_manager:
            self.alarm_manager.stop()
            
        if self.worker:
            self.start_btn.setEnabled(False)
            self.start_btn.setText(_("mon_btn_stopping", "Stopping..."))
            self.start_btn.setStyleSheet("background-color: #64748B; color: #E2E8F0;")
            self.worker.stop()
        else:
            self.on_monitor_finished()

    def on_monitor_finished(self):
        self.start_btn.setEnabled(True)
        self.start_btn.setText(_("mon_btn_start", "Start Monitor"))
        self.start_btn.setStyleSheet("")
        self.status_label.setText(_("mon_status_stopped", "Stopped"))
        self.status_label.setStyleSheet("color: #ff5252;")
        self.add_log_entry(_("mon_log_stopped", "Monitoring stopped"), "WARNING")
        self.worker = None

    def on_result(self, data):
        # Ignore stray signals if monitoring has been stopped
        if not self.is_monitoring_active:
            return
            
        host = data["host"]
        if host in self.hosts:
            old_status = self.hosts[host]["status"]
            self.hosts[host]["status"] = data["status"]
            self.hosts[host]["latency"] = data["latency"]
            
            # Record in Database
            self.db.save_log(host, data["status"], data["latency"], data["response"])
            
            # Keep a small buffer in memory for quick UI refresh if needed, 
            # but history is now DB-backed.
            timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd HH:mm:ss")
            log_entry = f"[{timestamp}] Status: {data['status']} ({data['latency']} ms)"
            self.hosts[host]["logs"].append(log_entry)
            if len(self.hosts[host]["logs"]) > 100:
                self.hosts[host]["logs"].pop(0)

            # Update Graph if open
            if host in self.graph_dialogs and self.graph_dialogs[host].isVisible():
                self.graph_dialogs[host].add_data(data["latency"])
            
            # Initialize tracking properties
            if "consecutive_down" not in self.hosts[host]:
                self.hosts[host]["consecutive_down"] = 0
            if "email_sent_down" not in self.hosts[host]:
                self.hosts[host]["email_sent_down"] = False

            # Update consecutive down counter
            if data["status"] == "DOWN":
                self.hosts[host]["consecutive_down"] += 1
            else:
                self.hosts[host]["consecutive_down"] = 0

            # Log status change
            if old_status != data["status"] and old_status != "N/A":
                level = "INFO" if data["status"] == "UP" else "ERROR"
                self.add_log_entry(f"Status changed for {host}: {old_status} -> {data['status']}", level)
                
            # Send email notifications based on consecutive failures config
            threshold = self.config.get("email_consecutive_down_threshold", 1) if self.config else 1
            label = self.hosts[host]["label"]

            if data["status"] == "DOWN":
                # Only trigger email once threshold is met and we haven't already sent a DOWN email
                if self.hosts[host]["consecutive_down"] >= threshold and not self.hosts[host]["email_sent_down"]:
                    self.email_notifier.send_status_email_async(
                        host=host,
                        label=label,
                        status="DOWN",
                        latency=data["latency"],
                        details=data["response"]
                    )
                    self.hosts[host]["email_sent_down"] = True
            elif data["status"] == "UP":
                # Trigger recovery email only if a DOWN email was previously sent
                if self.hosts[host]["email_sent_down"]:
                    self.email_notifier.send_status_email_async(
                        host=host,
                        label=label,
                        status="UP",
                        latency=data["latency"],
                        details=data["response"]
                    )
                self.hosts[host]["email_sent_down"] = False
            
            # Update specific row
            for row in range(self.table.rowCount()):
                if self.table.item(row, 1).text() == host: # Now index 1
                    status_item = QTableWidgetItem(data["status"])
                    status_item.setTextAlignment(Qt.AlignCenter)
                    if data["status"] == "UP":
                        status_item.setForeground(Qt.green)
                    elif data["status"] == "DOWN":
                        status_item.setForeground(Qt.red)
                    else:
                        status_item.setForeground(Qt.gray)
                    
                    self.table.setItem(row, 2, status_item)
                    
                    latency_item = QTableWidgetItem(f"{data['latency']} ms" if data["latency"] > 0 else "N/A")
                    latency_item.setTextAlignment(Qt.AlignCenter)
                    self.table.setItem(row, 3, latency_item)
                    break
            
            # Check overall status for alarm
            any_down = any(d["status"] == "DOWN" and d["active"] for d in self.hosts.values())
            
            if any_down:
                if self.alarm_manager:
                    self.alarm_manager.play()
            else:
                if self.alarm_manager:
                    self.alarm_manager.stop()
