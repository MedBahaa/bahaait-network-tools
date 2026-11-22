import base64
from dataclasses import dataclass
import getpass
import hashlib
import os
import re
import subprocess
from typing import Callable, Dict, Iterable, Optional, Tuple, Union
import zlib

import paramiko

from utils.auth import decrypt_data, encrypt_data

_DPAPI_PREFIX = "DPAPI:"
_PLAIN_B64_PREFIX = "PLAIN_B64:"
_FILE_MAGIC = b"BHITENC1:"

ConfirmHostKeyCallback = Callable[[str, int, str, str], bool]


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a sensitive credential string with Windows DPAPI."""
    raw = str(plaintext or "")
    if not raw:
        return ""
    raw_bytes = raw.encode("utf-8")
    if os.name == "nt":
        enc = encrypt_data(raw_bytes)
        return _DPAPI_PREFIX + base64.b64encode(enc).decode("ascii")
    return _PLAIN_B64_PREFIX + base64.b64encode(raw_bytes).decode("ascii")


def decrypt_secret(blob: str) -> str:
    """Decrypt a DPAPI-protected credential string."""
    val = str(blob or "").strip()
    if not val:
        return ""
    if val.startswith(_DPAPI_PREFIX):
        enc = base64.b64decode(val[len(_DPAPI_PREFIX):].encode("ascii"))
        return decrypt_data(enc).decode("utf-8")
    if val.startswith(_PLAIN_B64_PREFIX):
        if os.name == "nt":
            raise ValueError("Plaintext secret fallback is not permitted on Windows")
        return base64.b64decode(val[len(_PLAIN_B64_PREFIX):].encode("ascii")).decode("utf-8")
    raise ValueError("Unsupported encrypted secret format")


def compute_sha256(data: Union[bytes, str]) -> str:
    """Return lowercase hexadecimal SHA-256 digest of bytes or UTF-8 string."""
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    return hashlib.sha256(raw).hexdigest()


def verify_sha256(data: Union[bytes, str], expected_hex: str) -> bool:
    """Constant-time comparison of computed SHA-256 digest against expected hex."""
    actual = compute_sha256(data)
    expected = str(expected_hex or "").strip().lower()
    if len(actual) != len(expected):
        return False
    diff = 0
    for a, b in zip(actual, expected):
        diff |= ord(a) ^ ord(b)
    return diff == 0


_CHK_MARKER = b"|CHK:"


def encrypt_file_bytes(raw: Union[bytes, str]) -> bytes:
    """Compress and encrypt configuration backup payload at rest via DPAPI."""
    payload = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
    compressed = zlib.compress(payload, level=6)
    enc = encrypt_data(compressed)
    trailer = _CHK_MARKER + compute_sha256(enc).encode("ascii")
    return _FILE_MAGIC + enc + trailer


def decrypt_file_bytes(stored: bytes) -> bytes:
    """Decrypt and decompress a configuration backup payload."""
    if not stored.startswith(_FILE_MAGIC):
        raise ValueError("Invalid encrypted backup header (tampered or unencrypted file)")
    body = stored[len(_FILE_MAGIC):]
    if _CHK_MARKER in body:
        enc, chk_bytes = body.rsplit(_CHK_MARKER, 1)
        chk_hex = chk_bytes.decode("ascii", errors="ignore")
        if len(chk_hex) != 64 or not verify_sha256(enc, chk_hex):
            raise ValueError("Encrypted backup payload integrity check failed (file tampered)")
    else:
        enc = body
    compressed = decrypt_data(enc)
    return zlib.decompress(compressed)


def restrict_file_permissions(file_path: str) -> None:
    """Restrict sensitive file permissions to the current user where supported."""
    try:
        os.chmod(file_path, 0o600)
    except OSError:
        pass
    if os.name == "nt":
        try:
            user = getpass.getuser()
            subprocess.run(
                ["icacls", file_path, "/inheritance:r", "/grant:r", f"{user}:(R,W)"],
                capture_output=True,
                timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW,
                check=False,
            )
        except Exception:
            pass


def save_encrypted_backup(content: Union[bytes, str], file_path: str) -> Tuple[int, str]:
    """Write an encrypted configuration backup file and return (raw_size, sha256_hex)."""
    raw_bytes = content.encode("utf-8") if isinstance(content, str) else bytes(content)
    checksum = compute_sha256(raw_bytes)
    encrypted = encrypt_file_bytes(raw_bytes)
    parent = os.path.dirname(os.path.abspath(file_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(encrypted)
    restrict_file_permissions(file_path)
    return len(raw_bytes), checksum


def load_encrypted_backup(file_path: str, expected_sha256: Optional[str] = None) -> str:
    """Load, decrypt, and verify integrity of a stored configuration backup."""
    with open(file_path, "rb") as f:
        stored = f.read()
    raw_bytes = decrypt_file_bytes(stored)
    if expected_sha256 and not verify_sha256(raw_bytes, expected_sha256):
        raise ValueError(f"Backup SHA-256 checksum mismatch for {file_path}")
    return raw_bytes.decode("utf-8", errors="replace")


# Patterns intentionally covering Cisco IOS, Ruckus ICX, Fortinet FortiOS, PEM keys, and generic CLI secrets
_REDACT_PATTERNS: Tuple[Tuple[re.Pattern, str], ...] = (
    (
        re.compile(
            r"(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)[\s\S]*?(-----END [A-Z0-9 ]*PRIVATE KEY-----)",
            re.MULTILINE,
        ),
        r"\1\n[REDACTED_PRIVATE_KEY]\n\2",
    ),
    (
        re.compile(
            r"(\b(?:enable\s+secret|enable\s+password|enable\s+super-user-password)\s+(?:\d+\s+)?)(\S+)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(\busername\s+\S+(?:\s+privilege\s+\d+)?\s+(?:secret|password)\s+(?:\d+\s+)?)(\S+)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(\bsnmp-server\s+community\s+)(\S+)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(\b(?:snmp-server\s+user\b[^\n]*?\b(?:auth\s+\S+|priv\s+(?:\S+\s+)?))|\b(?:radius-server|tacacs-server|tacacs)\s+(?:\S+\s+)?key\s+(?:\d+\s+)?)(\S+)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(\b(?:pre-shared-key|isakmp\s+key|wireguard\s+key|shared-secret|wpa-psk)\s+(?:key\s+)?)(\S+)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(\bset\s+(?:password|passwd|psksecret|secret|passphrase|auth-pwd|priv-pwd|enc-key|private-key|community|key)\s+(?:ENC\s+)?)(\"?[^\s\r\n]+\"?)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(\bpassword\s+(?:\d+\s+)?)(\S+)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"((?:api[_-]?key|token|secret|auth_password|priv_password)\s*[:=]\s*)([\"']?[^\s,;\"']+[\"']?)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
)


def redact_sensitive_text(text: str, extra_secrets: Iterable[str] = ()) -> str:
    """Scrub passwords, SNMP communities, keys, and tokens before displaying or logging."""
    result = str(text or "")
    if not result:
        return ""
    for secret in extra_secrets or ():
        s = str(secret or "")
        if len(s) >= 2:
            result = result.replace(s, "[REDACTED]")
    for pattern, repl in _REDACT_PATTERNS:
        result = pattern.sub(repl, result)
    return result


def redact_dict(payload: Dict[str, object], extra_secrets: Iterable[str] = ()) -> Dict[str, object]:
    """Deep-copy a dictionary masking sensitive keys and secret patterns."""
    sensitive_keys = ("password", "secret", "token", "community", "passphrase", "private_key", "encrypted_secret")
    cleaned: Dict[str, object] = {}
    for k, v in (payload or {}).items():
        kl = str(k).lower()
        if any(sk in kl for sk in sensitive_keys) and v:
            cleaned[str(k)] = "[REDACTED]"
        elif isinstance(v, dict):
            cleaned[str(k)] = redact_dict(v, extra_secrets=extra_secrets)
        elif isinstance(v, str):
            cleaned[str(k)] = redact_sensitive_text(v, extra_secrets=extra_secrets)
        elif isinstance(v, list):
            cleaned[str(k)] = [
                redact_sensitive_text(item, extra_secrets=extra_secrets) if isinstance(item, str) else item
                for item in v
            ]
        else:
            cleaned[str(k)] = v
    return cleaned


def key_sha256_fingerprint(key: paramiko.PKey) -> str:
    """Compute canonical OpenSSH SHA-256 fingerprint for a Paramiko PKey."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


@dataclass(frozen=True)
class HostKeyCheckResult:
    status: str  # TRUSTED, UNKNOWN, MISMATCH
    hostname: str
    port: int
    key_type: str
    fingerprint: str
    expected_fingerprint: str = ""


class KnownHostsStore:
    """Manages strict SSH host key verification against a local OpenSSH known_hosts store."""

    def __init__(self, path: Optional[str] = None) -> None:
        if path is None:
            app_data = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
            base_dir = os.path.join(app_data, "BahaaIT")
            os.makedirs(base_dir, exist_ok=True)
            self.path = os.path.join(base_dir, "known_hosts")
        else:
            self.path = path
            parent = os.path.dirname(os.path.abspath(self.path))
            if parent:
                os.makedirs(parent, exist_ok=True)

    @staticmethod
    def _host_token(hostname: str, port: int) -> str:
        clean_host = str(hostname or "").strip().lower()
        return clean_host if int(port) == 22 else f"[{clean_host}]:{int(port)}"

    def _load_entries(self) -> Dict[Tuple[str, str], str]:
        """Return {(host_token, key_type): sha256_fingerprint} from known_hosts file."""
        entries: Dict[Tuple[str, str], str] = {}
        if not os.path.exists(self.path):
            return entries
        with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 3:
                    continue
                hosts_csv, key_type, key_b64 = parts[0], parts[1], parts[2]
                try:
                    blob = base64.b64decode(key_b64.encode("ascii"))
                    fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
                except Exception:
                    continue
                for h_tok in hosts_csv.split(","):
                    entries[(h_tok.strip().lower(), key_type)] = fp
        return entries

    def verify_host_key(self, hostname: str, port: int, key: paramiko.PKey) -> HostKeyCheckResult:
        token = self._host_token(hostname, port)
        key_type = key.get_name()
        fp = key_sha256_fingerprint(key)
        entries = self._load_entries()

        # Check matching host+key_type first, or detect mismatch for the same host under same or different key
        expected = entries.get((token, key_type))
        if expected is not None:
            status = "TRUSTED" if expected == fp else "MISMATCH"
            return HostKeyCheckResult(
                status=status,
                hostname=hostname,
                port=int(port),
                key_type=key_type,
                fingerprint=fp,
                expected_fingerprint=expected,
            )

        # If host exists with a different key_type, report UNKNOWN unless no entry at all
        same_host_fps = [v for (h, _kt), v in entries.items() if h == token]
        if same_host_fps:
            return HostKeyCheckResult(
                status="MISMATCH",
                hostname=hostname,
                port=int(port),
                key_type=key_type,
                fingerprint=fp,
                expected_fingerprint=same_host_fps[0],
            )

        return HostKeyCheckResult(
            status="UNKNOWN",
            hostname=hostname,
            port=int(port),
            key_type=key_type,
            fingerprint=fp,
        )

    def trust_host_key(self, hostname: str, port: int, key: paramiko.PKey) -> str:
        """Persist a verified SSH host key into known_hosts (after explicit approval)."""
        token = self._host_token(hostname, port)
        key_type = key.get_name()
        key_b64 = key.get_base64()
        new_line = f"{token} {key_type} {key_b64}\n"

        existing_lines = []
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[0].lower() == token and parts[1] == key_type:
                        continue
                    existing_lines.append(line)
        existing_lines.append(new_line)
        with open(self.path, "w", encoding="utf-8") as f:
            f.writelines(existing_lines)
        restrict_file_permissions(self.path)
        return key_sha256_fingerprint(key)

    def remove_host_key(self, hostname: str, port: int = 22) -> bool:
        token = self._host_token(hostname, port)
        if not os.path.exists(self.path):
            return False
        kept = []
        removed = False
        with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.strip().split()
                if parts and parts[0].lower() == token:
                    removed = True
                    continue
                kept.append(line)
        if removed:
            with open(self.path, "w", encoding="utf-8") as f:
                f.writelines(kept)
        return removed


class StrictVerifyHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Paramiko host-key policy enforcing known_hosts verification (never AutoAdd)."""

    def __init__(
        self,
        store: KnownHostsStore,
        policy_mode: str = "STRICT",
        confirm_callback: Optional[ConfirmHostKeyCallback] = None,
        port: int = 22,
    ) -> None:
        self.store = store
        self.policy_mode = str(policy_mode or "STRICT").upper()
        self.confirm_callback = confirm_callback
        self.port = int(port)

    @staticmethod
    def _parse_host_port(raw_hostname: str, default_port: int) -> Tuple[str, int]:
        if raw_hostname.startswith("[") and "]:" in raw_hostname:
            host_part, port_part = raw_hostname[1:].split("]:", 1)
            try:
                return host_part, int(port_part)
            except ValueError:
                return host_part, default_port
        return raw_hostname, default_port

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        host, port = self._parse_host_port(hostname, self.port)
        res = self.store.verify_host_key(host, port, key)
        if res.status == "TRUSTED":
            return
        if res.status == "MISMATCH":
            raise paramiko.SSHException(
                f"SSH HOST KEY MISMATCH for {host}:{port} ({res.key_type})! "
                f"Expected {res.expected_fingerprint}, got {res.fingerprint}. Possible MITM attack."
            )
        if self.policy_mode == "TOFU_CONFIRM" and self.confirm_callback is not None:
            approved = bool(self.confirm_callback(host, port, res.key_type, res.fingerprint))
            if approved:
                self.store.trust_host_key(host, port, key)
                return
        raise paramiko.SSHException(
            f"Unknown SSH host key for {host}:{port} ({res.key_type} {res.fingerprint}). "
            "Strict host key verification blocked untrusted connection."
        )
