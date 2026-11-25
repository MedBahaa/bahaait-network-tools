import html
import re
from datetime import datetime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QMessageBox,
    QPushButton, QLineEdit, QTextEdit, QComboBox, QTabWidget, QCheckBox, QFileDialog
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QIntValidator
from core.tools import NetworkTools
from utils.i18n import _


class UniversalToolWorker(QThread):
    output_ready = Signal(str)

    def __init__(self, tool_name, target, port=None, infinite_ping=False, ping_count=4):
        super().__init__()
        self.tool_name = tool_name
        self.target = target
        self.port = port
        self.infinite_ping = infinite_ping
        self.ping_count = ping_count
        self._process = None
        self.is_running = True

    def run(self):
        try:
            if self.tool_name == "Ping":
                self._process = NetworkTools.ping(self.target, count=self.ping_count, infinite=self.infinite_ping)
                if hasattr(self._process, "stdout") and self._process.stdout:
                    for line in self._process.stdout:
                        if not self.is_running:
                            break
                        self.output_ready.emit(line.strip())
                    self._process.wait()
                else:
                    self.output_ready.emit(str(self._process))
            elif self.tool_name == "NSLookup":
                self.output_ready.emit(NetworkTools.nslookup(self.target))
            elif self.tool_name == "Netstat":
                self.output_ready.emit(NetworkTools.netstat())
            elif self.tool_name == "Whois":
                self.output_ready.emit(_("tool_fetching_rdap"))
                self.output_ready.emit(NetworkTools.whois(self.target))
            elif self.tool_name == "Port Checker":
                self.output_ready.emit(NetworkTools.check_port(self.target, self.port))
            elif self.tool_name == "Load Balancing":
                self.output_ready.emit(_("tool_checking_multi_ip"))
                self.output_ready.emit(NetworkTools.get_multi_public_ips())
            elif self.tool_name == "Traceroute":
                self._process = NetworkTools.tracert(self.target)
                if hasattr(self._process, "stdout") and self._process.stdout:
                    for line in self._process.stdout:
                        if not self.is_running:
                            break
                        self.output_ready.emit(line.strip())
                    self._process.wait()
                else:
                    self.output_ready.emit(str(self._process))
        except Exception as e:
            self.output_ready.emit(_("tool_error_exec").format(self.tool_name, str(e)))

    def stop(self):
        self.is_running = False
        if self._process:
            try:
                self._process.terminate()
            except Exception:
                pass
            self._process = None


class TerminalTab(QWidget):
    def __init__(self, tool_name, target, worker):
        super().__init__()
        self.worker = worker
        self.tool_name = tool_name
        self.target = target
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(5, 5, 5, 5)
        self.layout.setSpacing(0)

        # Scoped Terminal Toolbar (ID selector prevents background bleeding onto buttons!)
        self.toolbar = QFrame()
        self.toolbar.setObjectName("TerminalToolbar")
        self.toolbar.setMinimumHeight(42)
        self.toolbar.setStyleSheet(
            "QFrame#TerminalToolbar { background-color: #1E293B; border: 1px solid #334155; "
            "border-bottom: none; border-top-left-radius: 10px; border-top-right-radius: 10px; }"
        )
        toolbar_layout = QHBoxLayout(self.toolbar)
        toolbar_layout.setContentsMargins(14, 4, 14, 4)
        toolbar_layout.setSpacing(8)

        self.status_label = QLabel(_("tool_status_running"))
        self.status_label.setStyleSheet("color: #818CF8; font-weight: 700; font-size: 12px; margin-bottom: 0px;")

        self.stop_btn = QPushButton(_("btn_stop", "Stop"))
        self.stop_btn.setObjectName("DangerButton")
        self.stop_btn.setCursor(Qt.PointingHandCursor)
        self.stop_btn.setStyleSheet("padding: 4px 12px; font-size: 12px; border-radius: 6px;")
        self.stop_btn.clicked.connect(self.stop_process)

        self.clear_btn = QPushButton(_("tool_clear"))
        self.clear_btn.setObjectName("SecondaryButton")
        self.clear_btn.setCursor(Qt.PointingHandCursor)
        self.clear_btn.setStyleSheet("padding: 4px 12px; font-size: 12px; border-radius: 6px;")
        self.clear_btn.clicked.connect(self.clear_output)

        self.export_btn = QPushButton(_("tool_export_log"))
        self.export_btn.setObjectName("SecondaryButton")
        self.export_btn.setCursor(Qt.PointingHandCursor)
        self.export_btn.setStyleSheet("padding: 4px 12px; font-size: 12px; border-radius: 6px;")
        self.export_btn.clicked.connect(self.export_log)

        toolbar_layout.addWidget(self.status_label)
        toolbar_layout.addStretch()
        toolbar_layout.addWidget(self.stop_btn)
        toolbar_layout.addWidget(self.clear_btn)
        toolbar_layout.addWidget(self.export_btn)
        self.layout.addWidget(self.toolbar)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("""
            QTextEdit {
                background-color: #090D16;
                color: #F1F5F9;
                font-family: 'Consolas', 'Cascadia Code', monospace;
                font-size: 13px;
                border: 1px solid #334155;
                border-top-left-radius: 0px;
                border-top-right-radius: 0px;
                border-bottom-left-radius: 10px;
                border-bottom-right-radius: 10px;
                padding: 10px;
            }
        """)
        self.layout.addWidget(self.output)

        self.worker.output_ready.connect(self.append_text)
        self.worker.finished.connect(self.on_finished)

    def stop_process(self):
        if self.worker and self.worker.isRunning():
            self.stop_btn.setEnabled(False)
            self.worker.stop()

    def append_text(self, text):
        time_str = datetime.now().strftime("%H:%M:%S")
        lines = str(text).split("\n")
        timestamped_lines = []
        for line in lines:
            safe = html.escape(line)
            if line.strip():
                timestamped_lines.append(f"<span style='color: #64748B;'>[{time_str}]</span> {safe}")
            else:
                timestamped_lines.append(safe)

        formatted_text = "<br>".join(timestamped_lines).replace("  ", "&nbsp;&nbsp;")

        colorized_text = formatted_text
        low = str(text).lower()
        if "reply from" in low or "réponse de" in low or "bytes=" in low:
            colorized_text = f"<span style='color: #10B981;'>{formatted_text}</span>"
        elif "timed out" in low or "délai" in low or "erreur" in low or low.startswith("error"):
            colorized_text = f"<span style='color: #F43F5E;'>{formatted_text}</span>"
        elif "reachable" in low or "open" in low or "ouvert" in low:
            colorized_text = f"<span style='color: #FBBF24;'>{formatted_text}</span>"

        colorized_text = re.sub(
            r"(?<![#=;\d])(\d{1,3}(?:\.\d{1,3}){3})(?![\d])",
            r"<span style='color: #22D3EE;'>\1</span>",
            colorized_text,
        )
        colorized_text = re.sub(r"(\d+\s*ms)", r"<span style='color: #EAB308;'>\1</span>", colorized_text)

        self.output.append(colorized_text)
        self.output.verticalScrollBar().setValue(self.output.verticalScrollBar().maximum())

    def clear_output(self):
        self.output.clear()

    def export_log(self):
        safe_tgt = re.sub(r'[<>:"/\\|?*]', "_", str(self.target or "Local"))
        file_path, _filter = QFileDialog.getSaveFileName(
            self, _("tool_export_log_title"), f"log_{self.tool_name}_{safe_tgt}.txt", "Text Files (*.txt)"
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(self.output.toPlainText())
                QMessageBox.information(self, _("msg_success"), _("mon_export_success", "Exported successfully."))
            except Exception as exc:
                QMessageBox.critical(self, _("msg_error"), str(exc))

    def on_finished(self):
        self.stop_btn.setEnabled(False)
        self.status_label.setText(_("tool_status_finished"))
        self.status_label.setStyleSheet("color: #10B981; font-weight: 700; font-size: 12px; margin-bottom: 0px;")
        self.output.append(f"<span style='color: #94A3B8;'>{html.escape(_('tool_process_finished'))}</span>")


class ToolsView(QWidget):
    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        self.active_workers = {}

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(24, 22, 24, 22)
        self.layout.setSpacing(12)

        header = QLabel(_("tool_hub_title"))
        header.setObjectName("Title")
        self.layout.addWidget(header)

        # Controls Container (ID selector keeps QSS scoped to container only!)
        controls_container = QFrame()
        controls_container.setObjectName("FilterBar")
        controls = QHBoxLayout(controls_container)
        controls.setContentsMargins(14, 10, 14, 10)
        controls.setSpacing(10)

        self.tool_selector = QComboBox()
        self.tool_selector.addItems(["Ping", "Traceroute", "NSLookup", "Netstat", "Whois", "Port Checker", "Load Balancing"])
        self.tool_selector.setMinimumWidth(155)
        self.tool_selector.currentIndexChanged.connect(self.on_tool_changed)

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText(_("tool_placeholder_target"))
        self.target_input.setMinimumWidth(180)
        self.target_input.returnPressed.connect(self.run_tool)

        self.port_input = QLineEdit()
        self.port_input.setValidator(QIntValidator(1, 65535, self))
        self.port_input.setPlaceholderText(_("tool_placeholder_port"))
        self.port_input.setFixedWidth(84)
        self.port_input.setVisible(False)
        self.port_input.returnPressed.connect(self.run_tool)

        self.ping_infinite_cb = QCheckBox(_("tool_infinite_ping"))
        self.ping_infinite_cb.setCursor(Qt.PointingHandCursor)

        self.run_btn = QPushButton(_("tool_new_session"))
        self.run_btn.setObjectName("PrimaryButton")
        self.run_btn.setCursor(Qt.PointingHandCursor)
        self.run_btn.clicked.connect(self.run_tool)

        self.clear_all_btn = QPushButton(_("tool_close_all"))
        self.clear_all_btn.setObjectName("DangerButton")
        self.clear_all_btn.setCursor(Qt.PointingHandCursor)
        self.clear_all_btn.clicked.connect(self.close_all_tabs)

        controls.addWidget(self.tool_selector)
        controls.addWidget(self.target_input, 1)
        controls.addWidget(self.port_input)
        controls.addWidget(self.ping_infinite_cb)
        controls.addWidget(self.run_btn)
        controls.addWidget(self.clear_all_btn)
        self.layout.addWidget(controls_container)

        self.empty_hint = QLabel(_("tool_placeholder_target", "Enter a target IP or hostname above and click New Session."))
        self.empty_hint.setAlignment(Qt.AlignCenter)
        self.empty_hint.setStyleSheet("color: #64748B; font-size: 13px; padding: 28px;")

        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.setMovable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)
        self.layout.addWidget(self.empty_hint)
        self.layout.addWidget(self.tab_widget, 1)
        self.tab_widget.hide()

        self.on_tool_changed()

    def on_tool_changed(self):
        tool = self.tool_selector.currentText()
        is_port_check = tool == "Port Checker"
        is_ping = tool == "Ping"
        needs_target = tool not in ("Netstat", "Load Balancing")

        self.port_input.setVisible(is_port_check)
        self.ping_infinite_cb.setVisible(is_ping)
        self.target_input.setEnabled(needs_target)

        if is_port_check:
            self.target_input.setPlaceholderText(_("tool_placeholder_host"))
        elif not needs_target:
            self.target_input.setPlaceholderText("Local")
        else:
            self.target_input.setPlaceholderText(_("tool_placeholder_target"))

    def run_tool(self):
        tool = self.tool_selector.currentText()
        target = self.target_input.text().strip()
        port = self.port_input.text().strip() if self.port_input.isVisible() else None

        if not target and tool not in ("Netstat", "Load Balancing"):
            QMessageBox.warning(self, _("msg_warning", "Warning"), _("scan_error_invalid_msg", "Please enter a target host or IP."))
            return
        if tool == "Port Checker" and not port:
            QMessageBox.warning(self, _("msg_warning", "Warning"), _("tool_placeholder_port", "Please enter a TCP port (1-65535)."))
            return

        worker = UniversalToolWorker(
            tool,
            target,
            port,
            infinite_ping=self.ping_infinite_cb.isChecked() if tool == "Ping" else False,
            ping_count=4,
        )

        time_str = datetime.now().strftime("%H:%M")
        suffix = " (Inf)" if (tool == "Ping" and self.ping_infinite_cb.isChecked()) else ""
        tab_name = f"[{time_str}] {tool}{suffix}: {target if target else 'Local'}"
        terminal_tab = TerminalTab(tool, target, worker)

        self.empty_hint.hide()
        self.tab_widget.show()
        index = self.tab_widget.addTab(terminal_tab, tab_name)
        self.tab_widget.setCurrentIndex(index)

        key = id(terminal_tab)
        self.active_workers[key] = worker
        worker.finished.connect(lambda k=key, w=worker: self._on_worker_done(k, w))
        worker.start()

    def _on_worker_done(self, key, worker):
        if self.active_workers.get(key) is worker:
            del self.active_workers[key]
        worker.deleteLater()

    def close_tab(self, index):
        widget = self.tab_widget.widget(index)
        key = id(widget)
        w = self.active_workers.pop(key, None)
        if w is not None:
            w.stop()
            w.wait(1500)
        self.tab_widget.removeTab(index)
        if widget is not None:
            widget.deleteLater()
        if self.tab_widget.count() == 0:
            self.tab_widget.hide()
            self.empty_hint.show()

    def close_all_tabs(self):
        for i in reversed(range(self.tab_widget.count())):
            self.close_tab(i)

    def shutdown(self):
        self.close_all_tabs()
