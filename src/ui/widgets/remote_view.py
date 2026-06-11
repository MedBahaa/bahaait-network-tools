from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QLineEdit, QTextEdit, QFrame, QComboBox)
from PySide6.QtCore import Qt, QThread, Signal
import socket
import serial
import paramiko
import getpass

class RemoteView(QWidget):
    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(30, 30, 30, 30)
        
        # Header
        header = QLabel("Remote Access (PuTTY Style)")
        header.setObjectName("Title")
        self.layout.addWidget(header)
        
        # Connection Panel
        conn_panel = QFrame()
        conn_panel.setObjectName("Card")
        from PySide6.QtWidgets import QSizePolicy
        conn_panel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        
        conn_layout = QHBoxLayout(conn_panel)
        conn_layout.setContentsMargins(20, 20, 20, 20)
        conn_layout.setSpacing(15)
        
        def create_group(label_text, widget):
            group_layout = QVBoxLayout()
            group_layout.setSpacing(2)
            lbl = QLabel(label_text)
            lbl.setStyleSheet("font-weight: bold; color: #94A3B8; font-size: 11px; margin-bottom: 0px;")
            widget.setFixedHeight(35)
            group_layout.addWidget(lbl)
            group_layout.addWidget(widget)
            return group_layout

        # Field Initializations
        self.protocol_selector = QComboBox()
        self.protocol_selector.addItems(["SSH", "Telnet", "Serial"])
        self.protocol_selector.setFixedWidth(100)
        self.protocol_selector.currentIndexChanged.connect(self.on_protocol_changed)
        
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("192.168.1.1")
        self.host_input.setMinimumWidth(200)
        
        self.port_input = QLineEdit("22")
        self.port_input.setFixedWidth(70)
        

        
        self.serial_line = QLineEdit("COM1")
        self.serial_line.setFixedWidth(120)
        
        self.speed_input = QLineEdit("9600")
        self.speed_input.setFixedWidth(100)

        # Connect Button
        self.connect_btn = QPushButton("Connect")
        self.connect_btn.setObjectName("PrimaryButton")
        self.connect_btn.setFixedHeight(35)
        self.connect_btn.setMinimumWidth(120)
        self.connect_btn.setCursor(Qt.PointingHandCursor)
        self.connect_btn.clicked.connect(self.toggle_connection)

        # Labels for serial mode (stored as attributes to toggle visibility)
        self.l_host = QLabel("HOST / IP:")
        self.l_port = QLabel("PORT:")
        self.l_serial = QLabel("SERIAL LINE:")
        self.l_speed = QLabel("SPEED:")

        # Layout Assembly
        conn_layout.addLayout(create_group("TYPE:", self.protocol_selector))
        
        # IP/SSH Group
        self.ssh_container = QWidget()
        ssh_layout = QHBoxLayout(self.ssh_container)
        ssh_layout.setContentsMargins(0, 0, 0, 0)
        
        self.group_host = create_group("HOST / IP:", self.host_input)
        self.group_port = create_group("PORT:", self.port_input)
        
        ssh_layout.addLayout(self.group_host)
        ssh_layout.addLayout(self.group_port)
        
        # Serial Group
        self.serial_container = QWidget()
        serial_layout = QHBoxLayout(self.serial_container)
        serial_layout.setContentsMargins(0, 0, 0, 0)
        self.group_serial = create_group("SERIAL LINE:", self.serial_line)
        self.group_speed = create_group("SPEED:", self.speed_input)
        serial_layout.addLayout(self.group_serial)
        serial_layout.addLayout(self.group_speed)
        
        self.serial_container.setVisible(False)

        conn_layout.addWidget(self.ssh_container)
        conn_layout.addWidget(self.serial_container)
        
        conn_layout.addStretch()
        
        # Vertical alignment for button (needs a small spacer to match inputs level)
        btn_layout = QVBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(self.connect_btn)
        conn_layout.addLayout(btn_layout)
        
        self.layout.addWidget(conn_panel)
        
        # Terminal Output
        self.terminal = QTextEdit()
        self.terminal.setReadOnly(True)
        self.terminal.setStyleSheet("background-color: #000000; color: #ffffff; font-family: 'Consolas', monospace;")
        self.layout.addWidget(self.terminal)
        
        # Command Input
        self.cmd_input = QLineEdit()
        self.cmd_input.setPlaceholderText("Type command and press Enter...")
        self.cmd_input.returnPressed.connect(self.send_command)
        self.cmd_input.setEnabled(False)
        self.cmd_input.installEventFilter(self)
        self.layout.addWidget(self.cmd_input)
        
        self.command_history = []
        self.history_index = -1
        
        self.worker = None
        self.shell = None

    def eventFilter(self, obj, event):
        from PySide6.QtCore import QEvent
        if obj == self.cmd_input and event.type() == QEvent.KeyPress:
            if event.key() == Qt.Key_Up:
                if self.command_history and self.history_index < len(self.command_history) - 1:
                    self.history_index += 1
                    self.cmd_input.setText(self.command_history[len(self.command_history) - 1 - self.history_index])
                return True
            elif event.key() == Qt.Key_Down:
                if self.history_index > 0:
                    self.history_index -= 1
                    self.cmd_input.setText(self.command_history[len(self.command_history) - 1 - self.history_index])
                elif self.history_index == 0:
                    self.history_index = -1
                    self.cmd_input.clear()
                return True
            
            # Ctrl+C Shortcut (Interrupt)
            elif event.modifiers() == Qt.ControlModifier and event.key() == Qt.Key_C:
                self.send_control_sequence('\x03', '^C') # ETX
                return True
                
            # Cisco Break Shortcut (Ctrl+Shift+6)
            elif (event.modifiers() == (Qt.ControlModifier | Qt.ShiftModifier)) and event.key() == Qt.Key_6:
                self.send_control_sequence('\x1e', '[BREAK]') # RS
                return True
                
        return super().eventFilter(obj, event)
    
    def send_control_sequence(self, char, label):
        if self.shell:
            try:
                if hasattr(self.shell, 'send'):
                    self.shell.send(char.encode('utf-8'))
                elif hasattr(self.shell, 'write'):
                    self.shell.write(char.encode('utf-8'))
                # Professional representation of control sequences
                self.handle_terminal_output(f"\x1b[91m {label} \x1b[0m")
            except:
                pass

    def on_protocol_changed(self):
        proto = self.protocol_selector.currentText()
        is_serial = proto == "Serial"
        
        # Visibility via Containers
        self.ssh_container.setVisible(not is_serial)
        self.serial_container.setVisible(is_serial)
        
        # Default Ports
        if proto == "SSH": self.port_input.setText("22")
        elif proto == "Telnet": self.port_input.setText("23")

    def toggle_connection(self):
        if self.worker and self.worker.isRunning():
            self.disconnect()
        else:
            self.connect()

    def connect(self):
        proto = self.protocol_selector.currentText()
        self.connect_btn.setEnabled(False)
        self.terminal.clear()
        
        if proto == "SSH":
            host = self.host_input.text().strip()
            port = int(self.port_input.text() or "22")
            self.terminal.append(f"[*] Connecting to {host}:{port} via SSH...")
            self.worker = SSHWorker(host, port)
        elif proto == "Telnet":
            host = self.host_input.text().strip()
            port = int(self.port_input.text() or "23")
            self.terminal.append(f"[*] Connecting to {host}:{port} via Telnet...")
            self.worker = TelnetWorker(host, port)
        elif proto == "Serial":
            line = self.serial_line.text().strip()
            speed = int(self.speed_input.text() or "9600")
            self.terminal.append(f"[*] Opening {line} at {speed} baud...")
            self.worker = SerialWorker(line, speed)
            
        self.worker.output_ready.connect(self.handle_terminal_output)
        self.worker.connected.connect(self.on_connected)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.start()

    def on_connected(self, shell):
        self.shell = shell
        self.terminal.append("[+] Connected successfully.")
        self.connect_btn.setText("Disconnect")
        self.connect_btn.setStyleSheet("background-color: #ff5252;")
        self.connect_btn.setEnabled(True)
        self.cmd_input.setEnabled(True)
        self.cmd_input.setFocus()

    def on_error(self, err):
        self.terminal.append(f"[-] Error: {err}")
        self.connect_btn.setEnabled(True)
        self.connect_btn.setText("Connect")

    def disconnect(self):
        if self.worker:
            self.worker.stop()
        self.terminal.append("[*] Disconnected.")
        self.connect_btn.setText("Connect")
        self.connect_btn.setStyleSheet("")
        self.cmd_input.setEnabled(False)

    def send_command(self):
        cmd = self.cmd_input.text()
        if cmd and self.shell:
            self.command_history.append(cmd)
            self.history_index = -1
            self.handle_terminal_output(f"\n\x1b[36m$ {cmd}\x1b[0m\n")
            try:
                if hasattr(self.shell, 'send'):
                    # Fix: socket.send requires bytes, not str
                    self.shell.send((cmd + "\n").encode('utf-8'))
                elif hasattr(self.shell, 'write'):
                    self.shell.write((cmd + "\n").encode('utf-8'))
            except Exception as e:
                self.terminal.append(f"<br><span style='color: #ff5252;'>[!] Send Error: {e}</span>")
            self.cmd_input.clear()

    def handle_terminal_output(self, data):
        # 1. Clean carriage returns
        data = data.replace('\r\n', '\n').replace('\r', '')
        
        # 2. ANSI to HTML color converter
        import re
        ansi_color_map = {
            '30': '#000000', '31': '#EF4444', '32': '#10B981', '33': '#F59E0B',
            '34': '#3B82F6', '35': '#8B5CF6', '36': '#06B6D4', '37': '#F1F5F9',
            '90': '#64748B', '91': '#F87171', '92': '#34D399', '93': '#FCD34D',
            '94': '#60A5FA', '95': '#A78BFA', '96': '#22D3EE', '97': '#FFFFFF'
        }
        
        data = data.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        
        parts = re.split(r'\x1b\[([\d;]+)m', data)
        html_out = ""
        is_bold = False
        current_color = None
        
        for i, part in enumerate(parts):
            if i % 2 == 0:
                html_out += part
            else:
                codes = part.split(';')
                for code in codes:
                    if code == '0':
                        if current_color or is_bold:
                            html_out += '</span>'
                            current_color = None
                            is_bold = False
                    elif code == '1':
                        is_bold = True
                    elif code in ansi_color_map:
                        if current_color or is_bold:
                            html_out += '</span>'
                        current_color = ansi_color_map[code]
                        style = f"color: {current_color};"
                        if is_bold:
                            style += " font-weight: bold;"
                        html_out += f'<span style="{style}">'
                        
        if current_color or is_bold:
            html_out += '</span>'
            
        html_out = html_out.replace('\n', '<br>')
        
        # 3. Insert and Auto-Scroll
        from PySide6.QtGui import QTextCursor
        self.terminal.moveCursor(QTextCursor.End)
        self.terminal.insertHtml(html_out)
        self.terminal.moveCursor(QTextCursor.End)
        
class SSHWorker(QThread):
    output_ready = Signal(str)
    connected = Signal(object)
    error_occurred = Signal(str)
    
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.running = True
        self.client = None
        self.shell = None

    def run(self):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Use current system user for the initial SSH connection
            user = getpass.getuser()
            
            try:
                # Use an empty string for password to allow the initial connection
                # which then drops into the AP's internal login prompt (PuTTY style).
                self.client.connect(
                    self.host, 
                    port=self.port, 
                    username=user,
                    password="",
                    allow_agent=True, 
                    look_for_keys=True,
                    timeout=20,
                    banner_timeout=40
                )
            except Exception as e:
                # Fallback to 'admin' with empty password (common for many APs)
                try:
                    self.client.connect(self.host, port=self.port, username="admin", password="", timeout=10)
                except:
                    self.error_occurred.emit(f"SSH Error: {str(e)}")
                    return
            
            self.shell = self.client.invoke_shell()
            self.shell.setblocking(0)
            self.connected.emit(self.shell)
            
            while self.running:
                if self.shell.recv_ready():
                    data = self.shell.recv(4096).decode('utf-8', errors='ignore')
                    if data:
                        self.output_ready.emit(data)
                self.msleep(10)
                
        except Exception as e:
            self.error_occurred.emit(str(e))
        finally:
            if self.client:
                self.client.close()

    def stop(self):
        self.running = False
        self.wait()

class TelnetWorker(QThread):
    output_ready = Signal(str)
    connected = Signal(object)
    error_occurred = Signal(str)
    
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.running = True

    def run(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((self.host, self.port))
            s.setblocking(False)
            self.connected.emit(s)
            
            while self.running:
                try:
                    data = s.recv(1024).decode('utf-8', errors='ignore')
                    if data: self.output_ready.emit(data)
                except BlockingIOError:
                    pass
                self.msleep(100)
        except Exception as e:
            self.error_occurred.emit(str(e))

    def stop(self):
        self.running = False
        self.wait()

class SerialWorker(QThread):
    output_ready = Signal(str)
    connected = Signal(object)
    error_occurred = Signal(str)
    
    def __init__(self, port, baud):
        super().__init__()
        self.port = port
        self.baud = baud
        self.running = True

    def run(self):
        try:
            ser = serial.Serial(self.port, self.baud, timeout=0.1)
            self.connected.emit(ser)
            
            while self.running:
                if ser.in_waiting:
                    data = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
                    self.output_ready.emit(data)
                self.msleep(100)
        except Exception as e:
            self.error_occurred.emit(str(e))

    def stop(self):
        self.running = False
        self.wait()
