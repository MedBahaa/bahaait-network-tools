from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QLineEdit, QTextEdit, QComboBox, QTabWidget, QTabBar, QCheckBox, QSpinBox, QFileDialog)
from PySide6.QtCore import Qt, QThread, Signal
from core.tools import NetworkTools

class UniversalToolWorker(QThread):
    output_ready = Signal(str)
    # Note: Using the built-in 'finished' signal of QThread

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
                if hasattr(self._process, 'stdout'):
                    for line in self._process.stdout:
                        if not self.is_running: break
                        self.output_ready.emit(line.strip())
                    self._process.wait()
                else:
                    self.output_ready.emit(str(self._process))
            elif self.tool_name == "NSLookup":
                res = NetworkTools.nslookup(self.target)
                self.output_ready.emit(res)
            elif self.tool_name == "Netstat":
                res = NetworkTools.netstat()
                self.output_ready.emit(res)
            elif self.tool_name == "Whois":
                self.output_ready.emit("Fetching RDAP info...")
                res = NetworkTools.whois(self.target)
                self.output_ready.emit(res)
            elif self.tool_name == "Port Checker":
                res = NetworkTools.check_port(self.target, self.port)
                self.output_ready.emit(res)
            elif self.tool_name == "Load Balancing":
                self.output_ready.emit("Checking multi-provider IP status...")
                res = NetworkTools.get_multi_public_ips()
                self.output_ready.emit(res)
            elif self.tool_name == "Traceroute":
                self._process = NetworkTools.tracert(self.target)
                for line in self._process.stdout:
                    if not self.is_running: break
                    self.output_ready.emit(line.strip())
                self._process.wait()
        except Exception as e:
            self.output_ready.emit(f"Error executing {self.tool_name}: {str(e)}")

    def stop(self):
        self.is_running = False
        if self._process:
            try:
                self._process.terminate()
            except:
                pass
            self._process = None
        self.terminate()
        self.wait()

class TerminalTab(QWidget):
    def __init__(self, tool_name, target, worker):
        super().__init__()
        self.worker = worker
        self.tool_name = tool_name
        self.target = target
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(5, 5, 5, 5)
        self.layout.setSpacing(0)
        
        # Terminal Toolbar
        self.toolbar = QWidget()
        self.toolbar.setFixedHeight(40)
        self.toolbar.setStyleSheet("background-color: #1E293B; border-top-left-radius: 8px; border-top-right-radius: 8px;")
        toolbar_layout = QHBoxLayout(self.toolbar)
        toolbar_layout.setContentsMargins(15, 0, 15, 0)
        
        self.status_label = QLabel("● RUNNING")
        self.status_label.setStyleSheet("color: #6366F1; font-weight: bold; font-size: 11px;")
        
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setFixedWidth(60)
        self.clear_btn.setCursor(Qt.PointingHandCursor)
        self.clear_btn.setStyleSheet("background: transparent; color: #94A3B8; border: none; font-size: 11px;")
        self.clear_btn.clicked.connect(self.clear_output)
        
        self.export_btn = QPushButton("Export Log")
        self.export_btn.setFixedWidth(80)
        self.export_btn.setCursor(Qt.PointingHandCursor)
        self.export_btn.setStyleSheet("background: transparent; color: #94A3B8; border: none; font-size: 11px;")
        self.export_btn.clicked.connect(self.export_log)
        
        toolbar_layout.addWidget(self.status_label)
        toolbar_layout.addStretch()
        toolbar_layout.addWidget(self.clear_btn)
        toolbar_layout.addWidget(self.export_btn)
        
        self.layout.addWidget(self.toolbar)
        
        # Terminal Output
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("""
            QTextEdit {
                background-color: #0F172A; 
                color: #F1F5F9; 
                font-family: 'Consolas', 'Cascadia Code', monospace; 
                font-size: 13px; 
                border: 1px solid #1E293B;
                border-bottom-left-radius: 8px;
                border-bottom-right-radius: 8px;
                padding: 10px;
            }
        """)
        self.layout.addWidget(self.output)
        
        self.worker.output_ready.connect(self.append_text)
        self.worker.finished.connect(self.on_finished)
        
    def append_text(self, text):
        import re
        from datetime import datetime
        time_str = datetime.now().strftime("%H:%M:%S")
        
        # Split multi-line input and add timestamp to each non-empty line
        lines = text.split("\n")
        timestamped_lines = []
        for line in lines:
            if line.strip():
                timestamped_lines.append(f"<span style='color: #64748B;'>[{time_str}]</span> {line}")
            else:
                timestamped_lines.append(line)
        
        processed_text = "\n".join(timestamped_lines)
        
        # Prepare text for HTML (convert newlines and spaces)
        formatted_text = processed_text.replace("\n", "<br>").replace("  ", "&nbsp;&nbsp;")
        
        # Colorization Logic
        colorized_text = formatted_text
        if "Reply from" in formatted_text or "Réponse de" in formatted_text or "bytes=" in formatted_text:
            colorized_text = f"<span style='color: #10B981;'>{formatted_text}</span>" # Green
        elif "timed out" in formatted_text.lower() or "délai" in formatted_text.lower() or "error" in formatted_text.lower():
            colorized_text = f"<span style='color: #F43F5E;'>{formatted_text}</span>" # Red
        elif "reachable" in formatted_text.lower() or "open" in formatted_text.lower():
            colorized_text = f"<span style='color: #FBBF24;'>{formatted_text}</span>" # Yellow
        
        # Highlight IP Addresses (Cyan) - Regex updated to avoid breaking existing HTML tags
        colorized_text = re.sub(r"(?<![#=])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", r"<span style='color: #22D3EE;'>\1</span>", colorized_text)
        
        # Highlight Latencies (Yellow-ish)
        colorized_text = re.sub(r"(\d+\s*ms)", r"<span style='color: #EAB308;'>\1</span>", colorized_text)
            
        self.output.append(colorized_text)
        self.output.verticalScrollBar().setValue(self.output.verticalScrollBar().maximum())
        
    def clear_output(self):
        self.output.clear()
        
    def export_log(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Terminal Log", f"log_{self.tool_name}_{self.target}.txt", "Text Files (*.txt)")
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.output.toPlainText())

    def on_finished(self):
        self.status_label.setText("● FINISHED")
        self.status_label.setStyleSheet("color: #10B981; font-weight: bold; font-size: 11px;")
        self.output.append("<span style='color: #94A3B8;'>[PROCESS FINISHED]</span>")

class ToolsView(QWidget):
    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        self.active_workers = {} # {tab_index: worker}
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(30, 30, 30, 30)
        
        # Header
        header = QLabel("IT Terminal Hub")
        header.setObjectName("Title")
        self.layout.addWidget(header)
        
        # Controls Container
        controls_container = QWidget()
        controls_container.setObjectName("ControlsContainer")
        controls_container.setFixedHeight(55)
        controls_container.setStyleSheet("background-color: #1E293B; border-radius: 12px;")
        controls = QHBoxLayout(controls_container)
        controls.setContentsMargins(15, 0, 15, 0)
        controls.setSpacing(12)
        
        self.tool_selector = QComboBox()
        self.tool_selector.addItems(["Ping", "Traceroute", "NSLookup", "Netstat", "Whois", "Port Checker", "Load Balancing"])
        self.tool_selector.setFixedHeight(35)
        self.tool_selector.setFixedWidth(180)
        self.tool_selector.currentIndexChanged.connect(self.on_tool_changed)
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Target (IP or Domain)...")
        self.target_input.setFixedHeight(35)
        self.target_input.setFixedWidth(220)
        self.target_input.returnPressed.connect(self.run_tool)
        
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Port...")
        self.port_input.setFixedWidth(80)
        self.port_input.setFixedHeight(35)
        self.port_input.setVisible(False)
        self.port_input.returnPressed.connect(self.run_tool)
        
        # Ping Options
        self.ping_infinite_cb = QCheckBox("Infinite (-t)")
        self.ping_infinite_cb.setFixedHeight(35)
        self.ping_infinite_cb.setStyleSheet("color: #94A3B8; font-weight: bold;")
        self.ping_infinite_cb.stateChanged.connect(self.on_tool_changed)
        
        self.run_btn = QPushButton("NEW SESSION")
        self.run_btn.setObjectName("PrimaryButton")
        self.run_btn.setFixedHeight(35)
        self.run_btn.setMinimumWidth(150)
        self.run_btn.setCursor(Qt.PointingHandCursor)
        self.run_btn.clicked.connect(self.run_tool)

        self.clear_all_btn = QPushButton("CLOSE ALL")
        self.clear_all_btn.setObjectName("DangerButton")
        self.clear_all_btn.setFixedHeight(35)
        self.clear_all_btn.setMinimumWidth(120)
        self.clear_all_btn.setCursor(Qt.PointingHandCursor)
        self.clear_all_btn.clicked.connect(self.close_all_tabs)
        
        controls.addWidget(self.tool_selector, 0, Qt.AlignVCenter)
        controls.addWidget(self.target_input, 0, Qt.AlignVCenter)
        controls.addWidget(self.port_input, 0, Qt.AlignVCenter)
        controls.addWidget(self.ping_infinite_cb, 0, Qt.AlignVCenter)
        
        controls.addStretch(1)
        
        controls.addWidget(self.run_btn, 0, Qt.AlignVCenter)
        controls.addWidget(self.clear_all_btn, 0, Qt.AlignVCenter)
        
        self.layout.addWidget(controls_container)
        
        # Tab Widget
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.setMovable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane { border: none; background: #0F172A; }
            QTabBar::tab { background: #1E293B; color: #94A3B8; padding: 10px 20px; border-top-left-radius: 8px; border-top-right-radius: 8px; margin-right: 4px; min-width: 150px; font-weight: bold; }
            QTabBar::tab:selected { background: #6366F1; color: white; border-bottom: 2px solid #10B981; }
            QTabBar::close-button { 
                background: rgba(255, 255, 255, 0.1); 
                border-radius: 4px;
                subcontrol-position: right;
                margin: 2px;
            }
            QTabBar::close-button:hover { background: #F43F5E; }
        """)
        self.layout.addWidget(self.tab_widget)
        
        self.on_tool_changed() # Initial state

    def on_tool_changed(self):
        tool = self.tool_selector.currentText()
        is_port_check = tool == "Port Checker"
        is_ping = tool == "Ping"
        
        self.port_input.setVisible(is_port_check)
        self.ping_infinite_cb.setVisible(is_ping)
        
        if is_port_check:
            self.target_input.setPlaceholderText("Host...")
        else:
            self.target_input.setPlaceholderText("Target (IP or Domain)...")

    def run_tool(self):
        tool = self.tool_selector.currentText()
        target = self.target_input.text().strip()
        port = self.port_input.text().strip() if self.port_input.isVisible() else None
        
        if not target and tool not in ["Netstat", "Load Balancing"]:
            return
            
        # Create Worker
        worker = UniversalToolWorker(
            tool, 
            target, 
            port, 
            infinite_ping=self.ping_infinite_cb.isChecked() if tool == "Ping" else False,
            ping_count=4
        )
        
        # Create Tab
        from datetime import datetime
        time_str = datetime.now().strftime("%H:%M")
        suffix = " (Inf)" if (tool == "Ping" and self.ping_infinite_cb.isChecked()) else ""
        tab_name = f"[{time_str}] {tool}{suffix}: {target if target else 'Local'}"
        terminal_tab = TerminalTab(tool, target, worker)
        
        index = self.tab_widget.addTab(terminal_tab, tab_name)
        self.tab_widget.setCurrentIndex(index)
        
        # Store worker by widget ID
        self.active_workers[id(terminal_tab)] = worker
        
        worker.start()

    def close_tab(self, index):
        widget = self.tab_widget.widget(index)
        if id(widget) in self.active_workers:
            self.active_workers[id(widget)].stop()
            del self.active_workers[id(widget)]
        self.tab_widget.removeTab(index)

    def close_all_tabs(self):
        for i in reversed(range(self.tab_widget.count())):
            self.close_tab(i)
