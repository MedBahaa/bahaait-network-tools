import base64
from dataclasses import dataclass, field, asdict
import json
import os
from typing import Any, Dict, Iterable, Optional

from utils.auth import decrypt_data, encrypt_data


SUPPORTED_SNMP_VERSIONS = ("v1", "v2c", "v3")
SUPPORTED_SECURITY_LEVELS = ("noAuthNoPriv", "authNoPriv", "authPriv")
SUPPORTED_AUTH_PROTOCOLS = ("NONE", "MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512")
SUPPORTED_PRIV_PROTOCOLS = ("NONE", "DES", "3DES", "AES", "AES128", "AES192", "AES256")

_DPAPI_PREFIX = "DPAPI:"
_PLAIN_B64_PREFIX = "PLAIN_B64:"


def normalize_snmp_version(raw: str) -> str:
    val = str(raw or "").strip().lower()
    mapping = {
        "1": "v1",
        "v1": "v1",
        "2": "v2c",
        "2c": "v2c",
        "v2": "v2c",
        "v2c": "v2c",
        "3": "v3",
        "v3": "v3",
    }
    if val not in mapping:
        raise ValueError(f"Unsupported SNMP version: '{raw}'")
    return mapping[val]


@dataclass
class SNMPCredentials:
    """SNMP v1 / v2c / v3 credentials with automatic secret masking and validation."""

    version: str = "v2c"
    community: str = ""
    username: str = ""
    security_level: str = "noAuthNoPriv"
    auth_protocol: str = "SHA"
    auth_password: str = ""
    priv_protocol: str = "AES"
    priv_password: str = ""
    context_name: str = ""

    def __repr__(self) -> str:
        masked_comm = "***" if self.community else ""
        masked_auth = "***" if self.auth_password else ""
        masked_priv = "***" if self.priv_password else ""
        return (
            f"SNMPCredentials(version={self.version!r}, community={masked_comm!r}, "
            f"username={self.username!r}, security_level={self.security_level!r}, "
            f"auth_protocol={self.auth_protocol!r}, auth_password={masked_auth!r}, "
            f"priv_protocol={self.priv_protocol!r}, priv_password={masked_priv!r}, "
            f"context_name={self.context_name!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()

    def validate(self) -> None:
        self.version = normalize_snmp_version(self.version)
        if self.version in ("v1", "v2c"):
            if not str(self.community or "").strip():
                raise ValueError(f"SNMP {self.version} requires a non-empty community string.")
            return

        # SNMP v3
        if not str(self.username or "").strip():
            raise ValueError("SNMP v3 requires a non-empty security username.")
        if self.security_level not in SUPPORTED_SECURITY_LEVELS:
            raise ValueError(f"Unsupported SNMP v3 security level: '{self.security_level}'")

        auth_proto = str(self.auth_protocol or "NONE").upper()
        priv_proto = str(self.priv_protocol or "NONE").upper()

        if self.security_level in ("authNoPriv", "authPriv"):
            if auth_proto not in SUPPORTED_AUTH_PROTOCOLS or auth_proto == "NONE":
                raise ValueError(f"Invalid SNMP v3 authentication protocol: '{self.auth_protocol}'")
            if len(str(self.auth_password or "")) < 8:
                raise ValueError("SNMP v3 authentication password must be at least 8 characters.")
            self.auth_protocol = auth_proto

        if self.security_level == "authPriv":
            if priv_proto not in SUPPORTED_PRIV_PROTOCOLS or priv_proto == "NONE":
                raise ValueError(f"Invalid SNMP v3 privacy protocol: '{self.priv_protocol}'")
            if len(str(self.priv_password or "")) < 8:
                raise ValueError("SNMP v3 privacy password must be at least 8 characters.")
            self.priv_protocol = priv_proto

    def secret_values(self) -> Iterable[str]:
        for secret in (self.community, self.auth_password, self.priv_password):
            if secret and len(secret) >= 2:
                yield secret

    def to_masked_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "community": "***" if self.community else "",
            "username": self.username,
            "security_level": self.security_level,
            "auth_protocol": self.auth_protocol,
            "auth_password": "***" if self.auth_password else "",
            "priv_protocol": self.priv_protocol,
            "priv_password": "***" if self.priv_password else "",
            "context_name": self.context_name,
        }


def scrub_secrets(text: str, creds: Optional[SNMPCredentials] = None) -> str:
    """Remove any SNMP community strings or SNMPv3 passwords from diagnostic text."""
    out = str(text or "")
    if creds is None:
        return out
    for secret in creds.secret_values():
        out = out.replace(secret, "***")
    return out


def encrypt_credentials(creds: SNMPCredentials) -> str:
    """Validate and encrypt SNMP credentials using Windows DPAPI."""
    creds.validate()
    payload_bytes = json.dumps(asdict(creds), ensure_ascii=False).encode("utf-8")
    if os.name == "nt":
        encrypted = encrypt_data(payload_bytes)
        return _DPAPI_PREFIX + base64.b64encode(encrypted).decode("ascii")
    return _PLAIN_B64_PREFIX + base64.b64encode(payload_bytes).decode("ascii")


def decrypt_credentials(blob: str) -> SNMPCredentials:
    """Decrypt stored SNMP credentials produced by encrypt_credentials."""
    if not blob or not isinstance(blob, str):
        raise ValueError("Missing or invalid encrypted SNMP credential blob.")

    if blob.startswith(_DPAPI_PREFIX):
        b64_part = blob[len(_DPAPI_PREFIX):]
        raw_enc = base64.b64decode(b64_part.encode("ascii"), validate=True)
        decrypted = decrypt_data(raw_enc)
        data = json.loads(decrypted.decode("utf-8"))
        valid_fields = set(SNMPCredentials.__dataclass_fields__)
        return SNMPCredentials(**{k: v for k, v in data.items() if k in valid_fields})

    if blob.startswith(_PLAIN_B64_PREFIX):
        b64_part = blob[len(_PLAIN_B64_PREFIX):]
        raw_dec = base64.b64decode(b64_part.encode("ascii"), validate=True)
        data = json.loads(raw_dec.decode("utf-8"))
        valid_fields = set(SNMPCredentials.__dataclass_fields__)
        return SNMPCredentials(**{k: v for k, v in data.items() if k in valid_fields})

    raise ValueError("Unrecognized SNMP credential encryption format.")
