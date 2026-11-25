import getpass  # Required by tests & local default username resolution
import os
import re
import socket
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

import paramiko
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.audit_logger import AuditLogger
from core.inventory_manager import InventoryManager
from core.ssh_access import (
    VENDOR_QUICK_COMMANDS,
    DeviceAccessService,
    SSHProfileManager,
    classify_command_tier,
)
from core.vlan_manager import detect_vlan_vendor_profile
from utils.db import DatabaseManager
from utils.i18n import _, escape_qt_mnemonic
from utils.infra_security import redact_sensitive_text

try:
    import serial
    import serial.tools.list_ports
    PYSERIAL_AVAILABLE = True
except Exception:
    PYSERIAL_AVAILABLE = False

_ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def _ansi_to_plain(text: str) -> str:
    return _ANSI_ESCAPE_RE.sub("", text or "")


class SSHWorker(QThread):
    """Paramiko SSH shell thread using strict known_hosts verification (never auto-trusts unknown keys)."""

    output_received = Signal(str)
    connected = Signal(str)
    disconnected = Signal(str)
    error_occurred = Signal(str)
    host_key_confirm_requested = Signal(str, int, str, str, object)

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str = "",
        key_path: str = "",
        policy_mode: str = "TOFU_CONFIRM",
        known_hosts_path: Optional[str] = None,
        timeout_sec: int = 15,
        access_service: Optional[DeviceAccessService] = None,
    ) -> None:
        super().__init__()
        self.host = host
        self.port = int(port or 22)
        self.username = username
        self.password = password
        self.key_path = key_path
        self.policy_mode = policy_mode
        self.known_hosts_path = known_hosts_path
        self.timeout_sec = int(timeout_sec or 15)
        self.access_service = access_service or DeviceAccessService(DatabaseManager(), known_hosts_path=known_hosts_path)

        self._client: Optional[paramiko.SSHClient] = None
        self._channel = None
        self._running = False
        self._send_lock = threading.Lock()

    def _confirm_unknown_key(self, host: str, port: int, key_type: str, fingerprint: str) -> bool:
        holder: Dict[str, Any] = {"event": threading.Event(), "accepted": False}
        self.host_key_confirm_requested.emit(host, int(port), key_type, fingerprint, holder)
        holder["event"].wait(timeout=60.0)
        accepted = bool(holder.get("accepted"))
        self.access_service.record_host_key_trust(host, port, key_type, fingerprint, accepted)
        return accepted

    def run(self) -> None:
        self._running = True
        client = paramiko.SSHClient()
        policy = self.access_service.create_host_key_policy(
            policy_mode=self.policy_mode,
            confirm_callback=self._confirm_unknown_key if self.policy_mode == "TOFU_CONFIRM" else None,
            port=self.port,
        )
        client.set_missing_host_key_policy(policy)

        try:
            kwargs: Dict[str, Any] = {
                "hostname": self.host,
                "port": self.port,
                "username": self.username,
                "timeout": self.timeout_sec,
                "look_for_keys": bool(not self.password and not self.key_path),
                "allow_agent": False,
            }
            if self.password:
                kwargs["password"] = self.password
            if self.key_path:
                kwargs["key_filename"] = self.key_path

            # Validate any previously pinned fingerprint explicitly when present
            client.connect(**kwargs)
            transport = client.get_transport()
            if transport and transport.is_active():
                srv_key = transport.get_remote_server_key()
                res = self.access_service.known_hosts.verify_host_key(self.host, self.port, srv_key)
                if res.status == "MISMATCH":
                    raise paramiko.SSHException(
                        f"HOST KEY MISMATCH for {self.host}:{self.port}! Expected {res.expected_fingerprint}, got {res.fingerprint}"
                    )

            self._client = client
            self._channel = client.invoke_shell(term="vt100", width=120, height=40)
            self._channel.settimeout(0.2)
            self.connected.emit(f"SSH connected to {self.username}@{self.host}:{self.port} (Host Key Verified)")

            while self._running and self._channel and not self._channel.closed:
                if self._channel.recv_ready():
                    chunk = self._channel.recv(4096).decode("utf-8", errors="replace")
                    if chunk:
                        self.output_received.emit(_ansi_to_plain(chunk))
                else:
                    time.sleep(0.05)
        except Exception as exc:
            if self._running:
                self.error_occurred.emit(str(exc))
        finally:
            self.stop()
            self.disconnected.emit(f"SSH session closed ({self.host}:{self.port})")

    def send_command(self, cmd: str) -> None:
        with self._send_lock:
            if self._channel and not self._channel.closed:
                payload = cmd if cmd.endswith("\n") else f"{cmd}\n"
                self._channel.send(payload.encode("utf-8"))

    def send_raw(self, data: str) -> None:
        with self._send_lock:
            if self._channel and not self._channel.closed:
                self._channel.send(data.encode("utf-8"))

    def stop(self) -> None:
        self._running = False
        try:
            if self._channel:
                self._channel.close()
        except Exception:
            pass
        try:
            if self._client:
                self._client.close()
        except Exception:
            pass


class TelnetWorker(QThread):
    """Lightweight raw-socket Telnet client compatible with Python 3.14+."""

    output_received = Signal(str)
    connected = Signal(str)
    disconnected = Signal(str)
    error_occurred = Signal(str)

    def __init__(self, host: str, port: int = 23, timeout_sec: int = 10) -> None:
        super().__init__()
        self.host = host
        self.port = int(port or 23)
        self.timeout_sec = int(timeout_sec or 10)
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._lock = threading.Lock()

    @staticmethod
    def _strip_iac(data: bytes) -> bytes:
        out = bytearray()
        i = 0
        n = len(data)
        while i < n:
            if data[i] == 255 and i + 2 < n:
                i += 3
            else:
                out.append(data[i])
                i += 1
        return bytes(out)

    def run(self) -> None:
        self._running = True
        try:
            self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout_sec)
            self._sock.settimeout(0.2)
            self.connected.emit(f"Telnet connected to {self.host}:{self.port} (Unencrypted legacy protocol)")
            while self._running and self._sock:
                try:
                    chunk = self._sock.recv(4096)
                    if not chunk:
                        break
                    clean = self._strip_iac(chunk).decode("utf-8", errors="replace")
                    if clean:
                        self.output_received.emit(_ansi_to_plain(clean))
                except socket.timeout:
                    continue
        except Exception as exc:
            if self._running:
                self.error_occurred.emit(str(exc))
        finally:
            self.stop()
            self.disconnected.emit(f"Telnet session closed ({self.host}:{self.port})")

    def send_command(self, cmd: str) -> None:
        with self._lock:
            if self._sock:
                payload = cmd if cmd.endswith("\n") else f"{cmd}\r\n"
                self._sock.sendall(payload.encode("utf-8"))

    def stop(self) -> None:
        self._running = False
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass


class SerialWorker(QThread):
    """Local Serial Console (RS-232 / USB COM) worker."""

    output_received = Signal(str)
    connected = Signal(str)
    disconnected = Signal(str)
    error_occurred = Signal(str)

    def __init__(self, port_name: str, baudrate: int = 9600) -> None:
        super().__init__()
        self.port_name = port_name
        self.baudrate = int(baudrate or 9600)
        self._ser = None
        self._running = False

    def run(self) -> None:
        if not PYSERIAL_AVAILABLE:
            self.error_occurred.emit("pyserial package is not installed.")
            return
        self._running = True
        try:
            self._ser = serial.Serial(self.port_name, self.baudrate, timeout=0.2)
            self.connected.emit(f"Serial console open on {self.port_name} @ {self.baudrate} baud")
            while self._running and self._ser and self._ser.is_open:
                waiting = self._ser.in_waiting
                if waiting:
                    data = self._ser.read(waiting).decode("utf-8", errors="replace")
                    self.output_received.emit(_ansi_to_plain(data))
                else:
                    time.sleep(0.05)
        except Exception as exc:
            if self._running:
                self.error_occurred.emit(str(exc))
        finally:
            self.stop()
            self.disconnected.emit(f"Serial port closed ({self.port_name})")

    def send_command(self, cmd: str) -> None:
        if self._ser and self._ser.is_open:
            payload = cmd if cmd.endswith("\r") or cmd.endswith("\n") else f"{cmd}\r\n"
            self._ser.write(payload.encode("utf-8"))

    def stop(self) -> None:
        self._running = False
        try:
            if self._ser and self._ser.is_open:
                self._ser.close()
        except Exception:
            pass


class SSHProfileDialog(QDialog):
    """Create / manage DPAPI-protected reusable SSH profiles."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(_("acc_prof_dlg_title", "New SSH Credential Profile"))
        screen = QApplication.primaryScreen().availableGeometry() if QApplication.primaryScreen() else None
        max_h = int(screen.height() * 0.85) if screen else 640
        self.setMinimumWidth(480)
        self.setMaximumHeight(max_h)
        self.setStyleSheet("QDialog { background-color: #0F172A; color: #F1F5F9; }")

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(12)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll_body = QWidget()
        form = QFormLayout(scroll_body)
        form.setSpacing(10)

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("e.g. Core-Switches-Prod")
        self.vendor_combo = QComboBox()
        self.vendor_combo.addItems(["cisco_ios", "ruckus_icx", "fortinet_fortigate", "generic_ssh"])
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(22)
        self.user_edit = QLineEdit(getpass.getuser())
        self.auth_combo = QComboBox()
        self.auth_combo.addItems(["PASSWORD", "KEY", "KEY_WITH_PASSPHRASE"])
        self.auth_combo.currentTextChanged.connect(self._on_auth_changed)
        self.secret_edit = QLineEdit()
        self.secret_edit.setEchoMode(QLineEdit.Password)

        key_row = QHBoxLayout()
        self.key_path_edit = QLineEdit()
        self.browse_btn = QPushButton("Browse...")
        self.browse_btn.setObjectName("SecondaryButton")
        self.browse_btn.setCursor(Qt.PointingHandCursor)
        self.browse_btn.clicked.connect(self._browse_key)
        key_row.addWidget(self.key_path_edit, 1)
        key_row.addWidget(self.browse_btn)

        self.policy_combo = QComboBox()
        self.policy_combo.addItems(["STRICT", "TOFU_CONFIRM"])

        form.addRow(_("acc_prof_name", "Profile Name:") + " *", self.name_edit)
        form.addRow(_("acc_prof_vendor", "Vendor Profile:"), self.vendor_combo)
        form.addRow(_("acc_prof_port", "SSH Port:"), self.port_spin)
        form.addRow(_("acc_prof_user", "Username:") + " *", self.user_edit)
        form.addRow(_("acc_prof_auth", "Auth Method:"), self.auth_combo)
        form.addRow(_("acc_prof_secret", "Password / Passphrase:"), self.secret_edit)
        form.addRow(_("acc_prof_key", "Private Key File:"), key_row)
        form.addRow(_("acc_prof_hk", "Host Key Policy:"), self.policy_combo)
        scroll.setWidget(scroll_body)
        root.addWidget(scroll, 1)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        ok_b = btns.button(QDialogButtonBox.Ok)
        cancel_b = btns.button(QDialogButtonBox.Cancel)
        if ok_b:
            ok_b.setObjectName("PrimaryButton")
            ok_b.setCursor(Qt.PointingHandCursor)
        if cancel_b:
            cancel_b.setObjectName("SecondaryButton")
            cancel_b.setCursor(Qt.PointingHandCursor)
        btns.accepted.connect(self._on_accept)
        btns.rejected.connect(self.reject)
        root.addWidget(btns)

        self._on_auth_changed(self.auth_combo.currentText())

    def _on_auth_changed(self, method: str) -> None:
        uses_key = method in ("KEY", "KEY_WITH_PASSPHRASE")
        uses_secret = method in ("PASSWORD", "KEY_WITH_PASSPHRASE")
        self.key_path_edit.setEnabled(uses_key)
        self.browse_btn.setEnabled(uses_key)
        self.secret_edit.setEnabled(uses_secret)

    def _on_accept(self) -> None:
        if not self.name_edit.text().strip() or not self.user_edit.text().strip():
            QMessageBox.warning(
                self,
                _("msg_warning", "Warning"),
                "Profile Name and Username are required.",
            )
            return
        self.accept()

    def _browse_key(self) -> None:
        path, _flt = QFileDialog.getOpenFileName(self, "Select Private Key", os.path.expanduser("~/.ssh"))
        if path:
            self.key_path_edit.setText(path)

    def get_payload(self) -> Dict[str, Any]:
        return {
            "name": self.name_edit.text().strip(),
            "vendor_profile": self.vendor_combo.currentText(),
            "port": self.port_spin.value(),
            "username": self.user_edit.text().strip(),
            "auth_method": self.auth_combo.currentText(),
            "secret": self.secret_edit.text(),
            "private_key_path": self.key_path_edit.text().strip(),
            "host_key_policy": self.policy_combo.currentText(),
        }


class CommandConfirmDialog(QDialog):
    """Explicit confirmation dialog for MODIFYING / DESTRUCTIVE remote commands."""

    def __init__(self, command: str, tier: str, reason: str, target_label: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(_("acc_cmd_confirm_title", "Confirm Guarded CLI Command"))
        self.setMinimumWidth(500)
        self.setStyleSheet("QDialog { background-color: #0F172A; color: #F1F5F9; }")

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(10)
        color = "#F43F5E" if tier == "DESTRUCTIVE" else "#F59E0B"
        hdr = QLabel(f"[{tier}] Target: {target_label}\n{reason}")
        hdr.setWordWrap(True)
        hdr.setStyleSheet(f"color: {color}; font-weight: bold;")
        root.addWidget(hdr)

        cmd_box = QTextEdit(command)
        cmd_box.setReadOnly(True)
        cmd_box.setMaximumHeight(110)
        cmd_box.setStyleSheet("background-color: #020617; color: #38BDF8; font-family: Consolas; border: 1px solid #334155;")
        root.addWidget(cmd_box)

        form = QFormLayout()
        self.ticket_edit = QLineEdit()
        self.ticket_edit.setPlaceholderText("CHG-001 (optional ticket ref)")
        form.addRow(_("vlan_confirm_ticket", "Change Ticket:"), self.ticket_edit)
        root.addLayout(form)

        self.chk = QCheckBox(_("acc_cmd_confirm_chk", "I confirm executing this modifying/destructive command."))
        self.chk.setCursor(Qt.PointingHandCursor)
        root.addWidget(self.chk)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        ok_b = btns.button(QDialogButtonBox.Ok)
        cancel_b = btns.button(QDialogButtonBox.Cancel)
        ok_b.setObjectName("DangerButton" if tier == "DESTRUCTIVE" else "PrimaryButton")
        ok_b.setCursor(Qt.PointingHandCursor)
        ok_b.setEnabled(False)
        if cancel_b:
            cancel_b.setObjectName("SecondaryButton")
            cancel_b.setCursor(Qt.PointingHandCursor)
        self.chk.toggled.connect(ok_b.setEnabled)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        root.addWidget(btns)

    def ticket_ref(self) -> str:
        return self.ticket_edit.text().strip()


class RemoteSessionTab(QWidget):
    """Individual terminal & guarded command execution tab inside Device Access Center."""

    def __init__(
        self,
        access_service: DeviceAccessService,
        session_label: str = "Session",
        device_dict: Optional[Dict[str, Any]] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.access_service = access_service
        self.session_label = session_label
        self.device_dict: Dict[str, Any] = dict(device_dict or {})
        self.worker: Optional[QThread] = None
        self._transcript: List[str] = []
        self._extra_secrets: List[str] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(6)

        self.terminal = QTextEdit()
        self.terminal.setReadOnly(True)
        self.terminal.setFont(QFont("Consolas", 10))
        self.terminal.setStyleSheet(
            "QTextEdit { background-color: #020617; color: #E2E8F0; border: 1px solid #334155; border-radius: 6px; padding: 8px; }"
        )
        root.addWidget(self.terminal, 1)

        cmd_row = QHBoxLayout()
        cmd_row.setSpacing(8)
        self.cmd_input = QLineEdit()
        self.cmd_input.setPlaceholderText(_("acc_cmd_ph", "Enter CLI command (READ_ONLY runs directly; MODIFYING/DESTRUCTIVE asks confirmation)..."))
        self.cmd_input.returnPressed.connect(self.send_entered_command)
        cmd_row.addWidget(self.cmd_input, 1)

        self.send_btn = QPushButton(_("acc_btn_send", "Send"))
        self.send_btn.setObjectName("PrimaryButton")
        self.send_btn.setCursor(Qt.PointingHandCursor)
        self.send_btn.clicked.connect(self.send_entered_command)
        cmd_row.addWidget(self.send_btn)
        root.addLayout(cmd_row)

    def append_raw(self, chunk: str) -> None:
        clean = redact_sensitive_text(chunk, extra_secrets=self._extra_secrets)
        self._transcript.append(clean)
        self.terminal.moveCursor(QTextCursor.End)
        self.terminal.insertPlainText(clean)
        self.terminal.moveCursor(QTextCursor.End)

    def append_line(self, text: str) -> None:
        clean = redact_sensitive_text(text, extra_secrets=self._extra_secrets)
        self._transcript.append(clean)
        self.terminal.moveCursor(QTextCursor.End)
        self.terminal.insertPlainText(clean if clean.endswith("\n") else f"{clean}\n")
        self.terminal.moveCursor(QTextCursor.End)

    def _on_worker_finished(self, worker_ref: QThread) -> None:
        if self.worker is worker_ref:
            self.worker = None

    def start_ssh(
        self,
        host: str,
        port: int,
        username: str,
        password: str = "",
        key_path: str = "",
        policy_mode: str = "TOFU_CONFIRM",
    ) -> None:
        self.disconnect_session()
        if password:
            self._extra_secrets.append(password)
        w = SSHWorker(
            host=host,
            port=port,
            username=username,
            password=password,
            key_path=key_path,
            policy_mode=policy_mode,
            access_service=self.access_service,
        )
        w.output_received.connect(self.append_raw)
        w.connected.connect(self.append_line)
        w.disconnected.connect(self.append_line)
        w.error_occurred.connect(lambda e: self.append_line(f"[ERROR] {e}"))
        w.host_key_confirm_requested.connect(self._prompt_host_key)
        w.finished.connect(lambda w_ref=w: self._on_worker_finished(w_ref))
        self.worker = w
        w.start()

    def start_telnet(self, host: str, port: int = 23) -> None:
        self.disconnect_session()
        w = TelnetWorker(host=host, port=port)
        w.output_received.connect(self.append_raw)
        w.connected.connect(self.append_line)
        w.disconnected.connect(self.append_line)
        w.error_occurred.connect(lambda e: self.append_line(f"[ERROR] {e}"))
        w.finished.connect(lambda w_ref=w: self._on_worker_finished(w_ref))
        self.worker = w
        w.start()

    def start_serial(self, port_name: str, baudrate: int = 9600) -> None:
        self.disconnect_session()
        w = SerialWorker(port_name=port_name, baudrate=baudrate)
        w.output_received.connect(self.append_raw)
        w.connected.connect(self.append_line)
        w.disconnected.connect(self.append_line)
        w.error_occurred.connect(lambda e: self.append_line(f"[ERROR] {e}"))
        w.finished.connect(lambda w_ref=w: self._on_worker_finished(w_ref))
        self.worker = w
        w.start()

    def _prompt_host_key(self, host: str, port: int, key_type: str, fingerprint: str, holder: dict) -> None:
        ans = QMessageBox.question(
            self,
            _("acc_hk_title", "Verify SSH Host Key"),
            f"Unknown SSH host key for {host}:{port}\nType: {key_type}\nSHA-256: {fingerprint}\n\nTrust and store in known_hosts?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        holder["accepted"] = ans == QMessageBox.Yes
        holder["event"].set()

    def send_entered_command(self) -> None:
        cmd = self.cmd_input.text().strip()
        if not cmd:
            return
        self.send_guarded_command(cmd)
        self.cmd_input.clear()

    def send_guarded_command(self, cmd: str) -> None:
        vendor_prof = detect_vlan_vendor_profile(
            self.device_dict.get("vendor", ""),
            self.device_dict.get("model", ""),
            self.device_dict.get("role", ""),
        )
        if vendor_prof == "unsupported":
            vendor_prof = "generic_ssh"
        tier, reason = classify_command_tier(cmd, vendor_profile=vendor_prof)

        confirmed = False
        ticket = ""
        if tier != "READ_ONLY":
            dlg = CommandConfirmDialog(cmd, tier, reason, self.session_label, self)
            if dlg.exec() != QDialog.Accepted:
                self.access_service.audit.record_event(
                    operation="SSH_COMMAND_BLOCKED",
                    result="BLOCKED",
                    device_id=self.device_dict.get("id"),
                    device_name=self.device_dict.get("hostname", self.session_label),
                    device_ip=self.device_dict.get("management_ip", ""),
                    command_tier=tier,
                    new_value={"command": cmd},
                    detail="Operator cancelled modifying/destructive command confirmation.",
                    extra_secrets=self._extra_secrets,
                )
                self.append_line(f"[BLOCKED {tier}] Command cancelled by operator: {cmd}")
                return
            confirmed = True
            ticket = dlg.ticket_ref()

        if self.worker and hasattr(self.worker, "send_command"):
            self.worker.send_command(cmd)
            self.access_service.audit.record_event(
                operation="SSH_COMMAND_EXECUTED",
                result="SUCCESS",
                device_id=self.device_dict.get("id"),
                device_name=self.device_dict.get("hostname", self.session_label),
                device_ip=self.device_dict.get("management_ip", ""),
                command_tier=tier,
                new_value={"command": cmd, "confirmed": confirmed},
                ticket_ref=ticket,
                detail=reason,
                extra_secrets=self._extra_secrets,
            )
        else:
            self.append_line(f"[LOCAL GUARDED PREVIEW {tier}] Not connected -> {cmd}")

    def disconnect_session(self) -> None:
        if self.worker:
            if hasattr(self.worker, "stop"):
                self.worker.stop()
            if self.worker.isRunning():
                self.worker.quit()
                self.worker.wait(2000)
            self.worker = None


class RemoteView(QWidget):
    """Enterprise Device Access Center: Multi-session SSH/Telnet/Serial + Guarded CLI + RDP/HTTPS/SNMP."""

    open_in_browser = Signal(str)
    open_in_snmp = Signal(str)

    def __init__(
        self,
        logger: Any = None,
        db: Optional[DatabaseManager] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        if isinstance(logger, DatabaseManager) and db is None:
            db = logger
            logger = None
        self.logger = logger
        self.db = db or DatabaseManager()
        self.audit = AuditLogger(self.db)
        self.inventory = InventoryManager(self.db, audit_logger=self.audit)
        self.profile_mgr = SSHProfileManager(self.db, audit_logger=self.audit)
        self.access_service = DeviceAccessService(self.db, audit_logger=self.audit)

        self._setup_ui()
        self.refresh_selectors()

    @property
    def worker(self) -> Optional[QThread]:
        tab = self.session_tabs.currentWidget()
        return getattr(tab, "worker", None) if tab else None

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(10)

        # Header Row 1: Title + Wrapped Subtitle
        lbl_t = QLabel(_("acc_title", "Network Access & Device Administration"))
        lbl_t.setObjectName("Title")
        lbl_t.setStyleSheet("font-size: 20px; font-weight: bold; color: #F8FAFC;")
        lbl_s = QLabel(_("acc_subtitle", "Multi-session SSH (strict known_hosts), Telnet, Serial, Guarded CLI & RDP/HTTPS links"))
        lbl_s.setWordWrap(True)
        lbl_s.setStyleSheet("color: #94A3B8; font-size: 12px;")
        root.addWidget(lbl_t)
        root.addWidget(lbl_s)

        # Header Row 2: Quick Action Launchers
        hdr_btns = QHBoxLayout()
        hdr_btns.setSpacing(8)
        self.btn_web = QPushButton(_("acc_btn_https", "Open HTTPS Web UI"))
        self.btn_web.setToolTip(_("acc_btn_https", "Open HTTPS Web UI"))
        self.btn_web.clicked.connect(self._launch_web)
        self.btn_rdp = QPushButton(_("acc_btn_rdp", "Launch RDP (mstsc)"))
        self.btn_rdp.setToolTip(_("acc_btn_rdp", "Launch RDP (mstsc)"))
        self.btn_rdp.clicked.connect(self._launch_rdp)
        self.btn_snmp = QPushButton(_("acc_btn_snmp", "Inspect in SNMP"))
        self.btn_snmp.setToolTip(_("acc_btn_snmp", "Inspect in SNMP"))
        self.btn_snmp.clicked.connect(self._launch_snmp)
        self.btn_export_log = QPushButton(_("acc_btn_export", "Export Redacted Log"))
        self.btn_export_log.setToolTip(_("acc_btn_export", "Export Redacted Log"))
        self.btn_export_log.clicked.connect(self._export_active_log)
        for b in (self.btn_web, self.btn_rdp, self.btn_snmp, self.btn_export_log):
            b.setObjectName("SecondaryButton")
            b.setCursor(Qt.PointingHandCursor)
            hdr_btns.addWidget(b)
        hdr_btns.addStretch()
        root.addLayout(hdr_btns)

        # 2-Row Connection Toolbar (scoped #FilterBar prevents border leak)
        conn = QFrame()
        conn.setObjectName("FilterBar")
        c_l = QGridLayout(conn)
        c_l.setContentsMargins(12, 10, 12, 10)
        c_l.setHorizontalSpacing(8)
        c_l.setVerticalSpacing(8)

        lbl_dev = QLabel(_("acc_lbl_dev", "Device:"))
        self.device_combo = QComboBox()
        self.device_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.device_combo.setMinimumWidth(160)
        self.device_combo.currentIndexChanged.connect(self._on_device_picked)

        lbl_proto = QLabel(_("acc_lbl_proto", "Protocol:"))
        self.proto_combo = QComboBox()
        self.proto_combo.addItems(["SSH", "Telnet", "Serial COM"])
        self.proto_combo.currentTextChanged.connect(self._on_proto_changed)

        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("IP / Host or COM1")
        self.host_edit.setMinimumWidth(140)

        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(22)
        self.port_spin.setMinimumWidth(84)

        lbl_prof = QLabel(_("acc_lbl_prof", "SSH Profile:"))
        self.profile_combo = QComboBox()
        self.profile_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.profile_combo.setMinimumWidth(185)
        self.profile_combo.currentIndexChanged.connect(self._on_profile_picked)

        self.btn_new_prof = QPushButton("+Profile")
        self.btn_new_prof.setObjectName("SecondaryButton")
        self.btn_new_prof.setCursor(Qt.PointingHandCursor)
        self.btn_new_prof.setToolTip(_("acc_prof_dlg_title", "New SSH Credential Profile"))
        self.btn_new_prof.clicked.connect(self._create_profile_dialog)

        self.user_edit = QLineEdit(getpass.getuser())
        self.user_edit.setPlaceholderText("Username")

        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.Password)
        self.pass_edit.setPlaceholderText("Password / Pass")

        self.connect_btn = QPushButton(_("acc_btn_connect", "Connect Tab"))
        self.connect_btn.setObjectName("PrimaryButton")
        self.connect_btn.setCursor(Qt.PointingHandCursor)
        self.connect_btn.clicked.connect(self.connect_session)

        self.disconnect_btn = QPushButton(_("acc_btn_disconnect", "Disconnect"))
        self.disconnect_btn.setObjectName("DangerButton")
        self.disconnect_btn.setCursor(Qt.PointingHandCursor)
        self.disconnect_btn.clicked.connect(self.disconnect)

        # Row 0: Target selection
        c_l.addWidget(lbl_dev, 0, 0)
        c_l.addWidget(self.device_combo, 0, 1, 1, 2)
        c_l.addWidget(lbl_proto, 0, 3)
        c_l.addWidget(self.proto_combo, 0, 4)
        c_l.addWidget(self.host_edit, 0, 5, 1, 2)
        c_l.addWidget(self.port_spin, 0, 7)

        # Row 1: Credentials & Session Actions
        c_l.addWidget(lbl_prof, 1, 0)
        c_l.addWidget(self.profile_combo, 1, 1)
        c_l.addWidget(self.btn_new_prof, 1, 2)
        c_l.addWidget(self.user_edit, 1, 3, 1, 2)
        c_l.addWidget(self.pass_edit, 1, 5)
        c_l.addWidget(self.connect_btn, 1, 6)
        c_l.addWidget(self.disconnect_btn, 1, 7)

        c_l.setColumnStretch(1, 2)
        c_l.setColumnStretch(5, 2)
        root.addWidget(conn)

        # Vendor Quick Diagnostic Commands Bar
        qbar = QHBoxLayout()
        qbar.setSpacing(8)
        qbar.addWidget(QLabel(_("acc_quick_cmds", "Safe Read-Only Diagnostics:")))
        self.quick_cmd_row = QHBoxLayout()
        self.quick_cmd_row.setSpacing(6)
        qbar.addLayout(self.quick_cmd_row)
        qbar.addStretch()
        root.addLayout(qbar)

        # Multi-session Tabs
        self.session_tabs = QTabWidget()
        self.session_tabs.setTabsClosable(True)
        self.session_tabs.tabCloseRequested.connect(self._close_session_tab)
        root.addWidget(self.session_tabs, 1)

        self._add_new_tab("Session 1")
        self._rebuild_quick_commands("generic_ssh")

    def refresh_selectors(self) -> None:
        self.device_combo.blockSignals(True)
        self.device_combo.clear()
        self.device_combo.addItem(_("acc_manual_target", "(Manual target)"), None)
        for d in self.inventory.list_devices():
            self.device_combo.addItem(f"{d['hostname']} ({d['management_ip']} | {d['vendor']})", d)
        self.device_combo.blockSignals(False)

        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()
        self.profile_combo.addItem(_("acc_no_prof", "(Inline credentials)"), None)
        for p in self.profile_mgr.list_profiles():
            self.profile_combo.addItem(f"{p['name']} ({p['username']})", p["id"])
        self.profile_combo.blockSignals(False)

    def _on_proto_changed(self, proto: str) -> None:
        if proto == "SSH":
            self.port_spin.setValue(22)
        elif proto == "Telnet":
            self.port_spin.setValue(23)
        else:
            if PYSERIAL_AVAILABLE:
                ports = [p.device for p in serial.tools.list_ports.comports()]
                if ports and not self.host_edit.text().strip():
                    self.host_edit.setText(ports[0])

    def _on_device_picked(self) -> None:
        d = self.device_combo.currentData()
        if not isinstance(d, dict):
            return
        self.host_edit.setText(str(d.get("management_ip") or ""))
        if d.get("ssh_profile_id"):
            idx = self.profile_combo.findData(d["ssh_profile_id"])
            if idx >= 0:
                self.profile_combo.setCurrentIndex(idx)
        vprof = detect_vlan_vendor_profile(d.get("vendor", ""), d.get("model", ""), d.get("role", ""))
        self._rebuild_quick_commands("generic_ssh" if vprof == "unsupported" else vprof)

    def _on_profile_picked(self) -> None:
        pid = self.profile_combo.currentData()
        if not pid:
            self.pass_edit.clear()
            return
        prof = self.profile_mgr.get_profile(int(pid), include_secret=True)
        if prof:
            self.port_spin.setValue(int(prof["port"]))
            self.user_edit.setText(prof["username"])
            self.pass_edit.setText(prof.get("secret", ""))
            self._rebuild_quick_commands(prof.get("vendor_profile", "generic_ssh"))

    def _rebuild_quick_commands(self, vendor_profile: str) -> None:
        while self.quick_cmd_row.count() > 0:
            item = self.quick_cmd_row.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        cmds = VENDOR_QUICK_COMMANDS.get(vendor_profile, VENDOR_QUICK_COMMANDS["generic_ssh"])
        for label, cmd in cmds:
            btn = QPushButton(escape_qt_mnemonic(label))
            btn.setObjectName("TableActionButton")
            btn.setCursor(Qt.PointingHandCursor)
            btn.setToolTip(cmd)
            btn.clicked.connect(lambda _chk=False, c=cmd: self._run_quick_cmd(c))
            self.quick_cmd_row.addWidget(btn)

    def _run_quick_cmd(self, cmd: str) -> None:
        tab = self.session_tabs.currentWidget()
        if isinstance(tab, RemoteSessionTab):
            tab.send_guarded_command(cmd)

    def _create_profile_dialog(self) -> None:
        dlg = SSHProfileDialog(self)
        if dlg.exec() == QDialog.Accepted:
            try:
                created = self.profile_mgr.create_profile(dlg.get_payload())
                self.refresh_selectors()
                idx = self.profile_combo.findData(created["id"])
                if idx >= 0:
                    self.profile_combo.setCurrentIndex(idx)
            except Exception as exc:
                QMessageBox.critical(self, "Profile Error", str(exc))

    def _add_new_tab(self, title: str, device_dict: Optional[Dict[str, Any]] = None) -> RemoteSessionTab:
        tab = RemoteSessionTab(self.access_service, session_label=title, device_dict=device_dict)
        idx = self.session_tabs.addTab(tab, title)
        self.session_tabs.setCurrentIndex(idx)
        return tab

    def _close_session_tab(self, index: int) -> None:
        w = self.session_tabs.widget(index)
        if isinstance(w, RemoteSessionTab):
            w.disconnect_session()
        if self.session_tabs.count() > 1:
            self.session_tabs.removeTab(index)
            if w:
                w.deleteLater()

    def connect_session(self) -> None:
        host = self.host_edit.text().strip()
        if not host:
            QMessageBox.warning(
                self,
                _("acc_title", "Device Access"),
                "Please enter a target IP / Hostname or serial COM port.",
            )
            return
        proto = self.proto_combo.currentText()
        dev = self.device_combo.currentData()
        dev_dict = dev if isinstance(dev, dict) else {"hostname": host, "management_ip": host}
        tab_title = f"{proto}:{dev_dict.get('hostname', host)}"
        active = self.session_tabs.currentWidget()
        if not isinstance(active, RemoteSessionTab) or active.worker is not None:
            active = self._add_new_tab(tab_title, device_dict=dev_dict)
        else:
            active.device_dict = dev_dict
            active.session_label = tab_title
            self.session_tabs.setTabText(self.session_tabs.currentIndex(), tab_title)

        pid = self.profile_combo.currentData()
        key_path = ""
        policy_mode = "TOFU_CONFIRM"
        if pid:
            prof = self.profile_mgr.get_profile(int(pid), include_secret=True)
            if prof:
                key_path = prof.get("private_key_path", "")
                policy_mode = prof.get("host_key_policy", "TOFU_CONFIRM")

        if proto == "SSH":
            active.start_ssh(
                host=host,
                port=self.port_spin.value(),
                username=self.user_edit.text().strip(),
                password=self.pass_edit.text(),
                key_path=key_path,
                policy_mode=policy_mode,
            )
        elif proto == "Telnet":
            active.start_telnet(host=host, port=self.port_spin.value())
        else:
            active.start_serial(port_name=host, baudrate=9600)

    def disconnect(self) -> None:
        tab = self.session_tabs.currentWidget()
        if isinstance(tab, RemoteSessionTab):
            tab.disconnect_session()

    def open_device(self, device_or_ip: Any, protocol: str = "SSH") -> None:
        self.refresh_selectors()
        if isinstance(device_or_ip, dict):
            ip = str(device_or_ip.get("management_ip") or "")
            self.host_edit.setText(ip)
            vprof = detect_vlan_vendor_profile(
                device_or_ip.get("vendor", ""),
                device_or_ip.get("model", ""),
                device_or_ip.get("role", ""),
            )
            self._rebuild_quick_commands("generic_ssh" if vprof == "unsupported" else vprof)
        else:
            self.host_edit.setText(str(device_or_ip or ""))
        idx = self.proto_combo.findText(protocol)
        if idx >= 0:
            self.proto_combo.setCurrentIndex(idx)

    def _launch_web(self) -> None:
        host = self.host_edit.text().strip()
        if not host:
            return
        url = self.access_service.build_web_admin_url(host, https=True)
        self.open_in_browser.emit(url)

    def _launch_rdp(self) -> None:
        host = self.host_edit.text().strip()
        if not host:
            return
        try:
            args = self.access_service.build_rdp_launch_args(host)
            kwargs: Dict[str, Any] = {}
            if os.name == "nt":
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            subprocess.Popen(args, **kwargs)
            self.audit.record_event(operation="RDP_LAUNCHED", result="SUCCESS", device_ip=host, command_tier="SYSTEM")
        except Exception as exc:
            QMessageBox.critical(self, "RDP Error", str(exc))

    def _launch_snmp(self) -> None:
        host = self.host_edit.text().strip()
        if host:
            self.open_in_snmp.emit(host)

    def _export_active_log(self) -> None:
        tab = self.session_tabs.currentWidget()
        if not isinstance(tab, RemoteSessionTab):
            return
        path, _flt = QFileDialog.getSaveFileName(self, "Export Redacted Session Log", "session_log.txt", "Text Files (*.txt)")
        if not path:
            return
        try:
            self.access_service.export_session_log(tab._transcript, path, extra_secrets=tab._extra_secrets)
            QMessageBox.information(self, _("msg_success", "Success"), f"Session log exported to:\n{path}")
        except Exception as exc:
            QMessageBox.critical(self, _("msg_error", "Error"), str(exc))

    def shutdown(self) -> None:
        for i in range(self.session_tabs.count()):
            w = self.session_tabs.widget(i)
            if isinstance(w, RemoteSessionTab):
                w.disconnect_session()
