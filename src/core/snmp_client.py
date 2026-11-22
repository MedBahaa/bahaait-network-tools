import asyncio
from dataclasses import dataclass, field
import time
from typing import Any, Dict, List, Optional, Tuple
import weakref

from core.monitoring_state import validate_target_address
from core.snmp_profiles import STD_OIDS, SNMPVendorProfile, detect_vendor_and_profile, get_profile
from utils.snmp_credentials import SNMPCredentials, scrub_secrets


class SNMPError(Exception):
    """Base SNMP exception with credential-safe error messages."""


class SNMPTimeoutError(SNMPError):
    """Raised when an SNMP request times out."""


class SNMPAuthError(SNMPError):
    """Raised on invalid SNMP community, USM username, auth key, or privacy key."""


class SNMPTransportError(SNMPError):
    """Raised on socket/transport/protocol failure."""


class _UnsupportedOIDSentinel:
    pass


UNSUPPORTED_OID = _UnsupportedOIDSentinel()


def convert_snmp_value(val: Any) -> Any:
    """Normalize a PySNMP object value into a standard Python scalar, or UNSUPPORTED_OID."""
    type_name = getattr(type(val), "__name__", "")
    if type_name in ("NoSuchObject", "NoSuchInstance", "EndOfMibView", "Null"):
        return UNSUPPORTED_OID

    if type_name == "IpAddress":
        return val.prettyPrint()

    if type_name == "ObjectIdentifier":
        return str(val).lstrip(".")

    if type_name in (
        "Integer",
        "Integer32",
        "Counter32",
        "Counter64",
        "Gauge32",
        "Unsigned32",
        "TimeTicks",
    ):
        try:
            return int(val)
        except Exception:
            return UNSUPPORTED_OID

    if hasattr(val, "asOctets"):
        raw_bytes = bytes(val.asOctets())
        try:
            decoded = raw_bytes.decode("utf-8")
            if all(ch.isprintable() or ch in ("\r", "\n", "\t") for ch in decoded):
                return decoded.strip()
        except UnicodeDecodeError:
            pass
        return "0x" + raw_bytes.hex()

    return str(val)


def oid_bytes_to_hex(val: Any) -> bytes:
    """Decode either a raw OctetString/bytes/0x-prefixed hex/latin1 str returned by convert_snmp_value."""
    if isinstance(val, bytes):
        return val
    if isinstance(val, str):
        if val.startswith("0x"):
            try:
                return bytes.fromhex(val[2:])
            except ValueError:
                return b""
        return val.encode("latin1", errors="ignore")
    return b""


def octet_to_mac(val: Any) -> str:
    """Format an SNMP ifPhysAddress value as AA:BB:CC:DD:EE:FF."""
    raw = oid_bytes_to_hex(val)
    if len(raw) == 6:
        return ":".join(f"{b:02X}" for b in raw)
    return ""


@dataclass
class SNMPDiscoveryResult:
    ip_address: str
    port: int
    snmp_version: str
    reachable: bool
    rtt_ms: float = 0.0
    sys_descr: str = ""
    sys_object_id: str = ""
    sys_uptime_ticks: int = 0
    sys_name: str = ""
    sys_location: str = ""
    sys_services: int = 0
    vendor: str = "Generic"
    model: str = ""
    firmware: str = ""
    device_type: str = "Network Device"
    profile_name: str = "generic_switch"
    capabilities: Dict[str, bool] = field(default_factory=dict)
    error: str = ""


class BaseSNMPTransport:
    """Abstract async SNMP transport for decoupling PySNMP from unit tests & simulators."""

    async def get(
        self,
        ip: str,
        port: int,
        creds: SNMPCredentials,
        oids: List[str],
        timeout_sec: float = 2.0,
        retries: int = 1,
    ) -> Dict[str, Any]:
        raise NotImplementedError

    async def walk(
        self,
        ip: str,
        port: int,
        creds: SNMPCredentials,
        base_oid: str,
        timeout_sec: float = 2.0,
        retries: int = 1,
        max_rows: Optional[int] = None,
    ) -> List[Tuple[str, Any]]:
        raise NotImplementedError


class PySNMPTransport(BaseSNMPTransport):
    """Production async SNMPv1/v2c/v3 transport powered by pysnmp.hlapi.v3arch.asyncio."""

    _GET_BATCH_SIZE = 25

    def __init__(self) -> None:
        self._engines_by_loop: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, Any]" = (
            weakref.WeakKeyDictionary()
        )

    def _get_engine(self) -> Any:
        from pysnmp.hlapi.v3arch.asyncio import SnmpEngine

        loop = asyncio.get_running_loop()
        eng = self._engines_by_loop.get(loop)
        if eng is None:
            eng = SnmpEngine()
            self._engines_by_loop[loop] = eng
        return eng

    @staticmethod
    def _build_auth_data(creds: SNMPCredentials) -> Any:
        from pysnmp.hlapi.v3arch.asyncio import (
            CommunityData,
            UsmUserData,
            usm3DESEDEPrivProtocol,
            usmAesCfb128Protocol,
            usmAesCfb192Protocol,
            usmAesCfb256Protocol,
            usmDESPrivProtocol,
            usmHMAC128SHA224AuthProtocol,
            usmHMAC192SHA256AuthProtocol,
            usmHMAC256SHA384AuthProtocol,
            usmHMAC384SHA512AuthProtocol,
            usmHMACMD5AuthProtocol,
            usmHMACSHAAuthProtocol,
            usmNoAuthProtocol,
            usmNoPrivProtocol,
        )

        creds.validate()
        if creds.version == "v1":
            return CommunityData(creds.community, mpModel=0)
        if creds.version == "v2c":
            return CommunityData(creds.community, mpModel=1)

        auth_map = {
            "NONE": usmNoAuthProtocol,
            "MD5": usmHMACMD5AuthProtocol,
            "SHA": usmHMACSHAAuthProtocol,
            "SHA224": usmHMAC128SHA224AuthProtocol,
            "SHA256": usmHMAC192SHA256AuthProtocol,
            "SHA384": usmHMAC256SHA384AuthProtocol,
            "SHA512": usmHMAC384SHA512AuthProtocol,
        }
        priv_map = {
            "NONE": usmNoPrivProtocol,
            "DES": usmDESPrivProtocol,
            "3DES": usm3DESEDEPrivProtocol,
            "AES": usmAesCfb128Protocol,
            "AES128": usmAesCfb128Protocol,
            "AES192": usmAesCfb192Protocol,
            "AES256": usmAesCfb256Protocol,
        }

        if creds.security_level == "noAuthNoPriv":
            return UsmUserData(creds.username)
        if creds.security_level == "authNoPriv":
            return UsmUserData(
                creds.username,
                authKey=creds.auth_password,
                authProtocol=auth_map[creds.auth_protocol.upper()],
            )
        return UsmUserData(
            creds.username,
            authKey=creds.auth_password,
            privKey=creds.priv_password,
            authProtocol=auth_map[creds.auth_protocol.upper()],
            privProtocol=priv_map[creds.priv_protocol.upper()],
        )

    @staticmethod
    def _raise_for_snmp_error(err_ind: Any, err_status: Any, creds: SNMPCredentials) -> None:
        if err_ind:
            msg = scrub_secrets(str(err_ind), creds)
            low = msg.lower()
            if "timeout" in low or "no snmp response" in low or "requesttimedout" in low:
                raise SNMPTimeoutError(msg)
            auth_markers = (
                "authentication",
                "decryption",
                "wrongdigest",
                "unknownusername",
                "usmstats",
                "authorization",
                "securitylevel",
                "notintimewindow",
                "unknownsecurityname",
            )
            if any(m in low for m in auth_markers):
                raise SNMPAuthError(msg)
            raise SNMPTransportError(msg)

        if err_status:
            status_str = scrub_secrets(
                err_status.prettyPrint() if hasattr(err_status, "prettyPrint") else str(err_status),
                creds,
            )
            low = status_str.lower()
            if "authorization" in low or "noaccess" in low:
                raise SNMPAuthError(status_str)
            if "nosuchname" in low:
                return
            raise SNMPTransportError(f"SNMP errorStatus: {status_str}")

    async def get(
        self,
        ip: str,
        port: int,
        creds: SNMPCredentials,
        oids: List[str],
        timeout_sec: float = 2.0,
        retries: int = 1,
    ) -> Dict[str, Any]:
        from pysnmp.hlapi.v3arch.asyncio import (
            ContextData,
            ObjectIdentity,
            ObjectType,
            UdpTransportTarget,
            get_cmd,
        )

        if not oids:
            return {}

        engine = self._get_engine()
        auth_data = self._build_auth_data(creds)
        ctx = ContextData(contextName=creds.context_name or "")
        target = await UdpTransportTarget.create((ip, int(port)), timeout=float(timeout_sec), retries=int(retries))

        results: Dict[str, Any] = {}
        for i in range(0, len(oids), self._GET_BATCH_SIZE):
            chunk = oids[i : i + self._GET_BATCH_SIZE]
            var_objs = [ObjectType(ObjectIdentity(oid)) for oid in chunk]
            try:
                err_ind, err_status, _err_idx, var_binds = await get_cmd(
                    engine, auth_data, target, ctx, *var_objs, lookupMib=False
                )
            except SNMPError:
                raise
            except Exception as e:
                raise SNMPTransportError(scrub_secrets(str(e), creds)) from e

            if err_ind:
                self._raise_for_snmp_error(err_ind, None, creds)
            if err_status:
                status_text = err_status.prettyPrint() if hasattr(err_status, "prettyPrint") else str(err_status)
                if "nosuchname" not in status_text.lower():
                    self._raise_for_snmp_error(None, err_status, creds)
                # SNMPv1 returns noSuchName when a multi-OID GET hits an unsupported OID; query individually
                if len(chunk) > 1:
                    for single_oid in chunk:
                        sub = await self.get(ip, port, creds, [single_oid], timeout_sec=timeout_sec, retries=retries)
                        results.update(sub)
                continue

            for oid_obj, val_obj in var_binds:
                oid_key = str(oid_obj).lstrip(".")
                norm_val = convert_snmp_value(val_obj)
                if norm_val is not UNSUPPORTED_OID:
                    results[oid_key] = norm_val

        return results

    async def walk(
        self,
        ip: str,
        port: int,
        creds: SNMPCredentials,
        base_oid: str,
        timeout_sec: float = 2.0,
        retries: int = 1,
        max_rows: Optional[int] = None,
    ) -> List[Tuple[str, Any]]:
        from pysnmp.hlapi.v3arch.asyncio import (
            ContextData,
            ObjectIdentity,
            ObjectType,
            UdpTransportTarget,
            bulk_walk_cmd,
            walk_cmd,
        )

        engine = self._get_engine()
        auth_data = self._build_auth_data(creds)
        ctx = ContextData(contextName=creds.context_name or "")
        target = await UdpTransportTarget.create((ip, int(port)), timeout=float(timeout_sec), retries=int(retries))
        clean_base = str(base_oid).strip().lstrip(".")
        var_obj = ObjectType(ObjectIdentity(clean_base))

        rows: List[Tuple[str, Any]] = []
        if creds.version in ("v2c", "v3"):
            gen = bulk_walk_cmd(
                engine, auth_data, target, ctx, 0, 16, var_obj, lexicographicMode=False, lookupMib=False
            )
        else:
            gen = walk_cmd(
                engine, auth_data, target, ctx, var_obj, lexicographicMode=False, lookupMib=False
            )

        try:
            async for err_ind, err_status, _err_idx, var_binds in gen:
                if err_ind:
                    self._raise_for_snmp_error(err_ind, None, creds)
                if err_status:
                    status_text = err_status.prettyPrint() if hasattr(err_status, "prettyPrint") else str(err_status)
                    if "nosuchname" in status_text.lower():
                        break
                    self._raise_for_snmp_error(None, err_status, creds)

                for oid_obj, val_obj in var_binds:
                    oid_key = str(oid_obj).lstrip(".")
                    if oid_key != clean_base and not oid_key.startswith(clean_base + "."):
                        return rows
                    if getattr(type(val_obj), "__name__", "") == "EndOfMibView":
                        return rows
                    norm_val = convert_snmp_value(val_obj)
                    if norm_val is not UNSUPPORTED_OID:
                        rows.append((oid_key, norm_val))
                        if max_rows is not None and len(rows) >= max_rows:
                            return rows
        except SNMPError:
            raise
        except Exception as e:
            raise SNMPTransportError(scrub_secrets(str(e), creds)) from e

        return rows


class SNMPClient:
    """High-level vendor-independent SNMP v1/v2c/v3 client with discovery & credential scrubbing."""

    def __init__(self, transport: Optional[BaseSNMPTransport] = None):
        self.transport = transport or PySNMPTransport()

    @staticmethod
    def _validate_host(ip_address: str) -> str:
        ok, cleaned = validate_target_address(ip_address)
        if not ok:
            raise ValueError(f"Invalid SNMP target address: {cleaned}")
        return cleaned

    async def get_oids(
        self,
        ip_address: str,
        creds: SNMPCredentials,
        oids: List[str],
        port: int = 161,
        timeout_sec: float = 2.0,
        retries: int = 1,
    ) -> Dict[str, Any]:
        target = self._validate_host(ip_address)
        creds.validate()
        return await self.transport.get(
            target, int(port), creds, oids, timeout_sec=float(timeout_sec), retries=int(retries)
        )

    async def walk_oid(
        self,
        ip_address: str,
        creds: SNMPCredentials,
        base_oid: str,
        port: int = 161,
        timeout_sec: float = 2.0,
        retries: int = 1,
        max_rows: Optional[int] = None,
    ) -> List[Tuple[str, Any]]:
        target = self._validate_host(ip_address)
        creds.validate()
        return await self.transport.walk(
            target,
            int(port),
            creds,
            base_oid,
            timeout_sec=float(timeout_sec),
            retries=int(retries),
            max_rows=max_rows,
        )

    async def _has_oid_or_table(
        self,
        ip_address: str,
        creds: SNMPCredentials,
        oid_list: Tuple[str, ...],
        port: int,
        timeout_sec: float,
        retries: int,
    ) -> bool:
        for oid in oid_list:
            try:
                if oid.endswith(".0"):
                    res = await self.transport.get(
                        ip_address, port, creds, [oid], timeout_sec=timeout_sec, retries=retries
                    )
                    if res:
                        return True
                else:
                    rows = await self.transport.walk(
                        ip_address,
                        port,
                        creds,
                        oid,
                        timeout_sec=timeout_sec,
                        retries=retries,
                        max_rows=1,
                    )
                    if rows:
                        return True
            except SNMPError:
                continue
        return False

    async def test_connectivity(
        self,
        ip_address: str,
        creds: SNMPCredentials,
        port: int = 161,
        timeout_sec: float = 2.0,
        retries: int = 1,
    ) -> Dict[str, Any]:
        try:
            target = self._validate_host(ip_address)
            creds.validate()
            t0 = time.perf_counter()
            sys_vals = await self.transport.get(
                target,
                int(port),
                creds,
                [STD_OIDS["sysDescr"], STD_OIDS["sysObjectID"], STD_OIDS["sysUpTime"], STD_OIDS["sysName"]],
                timeout_sec=float(timeout_sec),
                retries=int(retries),
            )
            rtt_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            if not sys_vals:
                return {
                    "reachable": False,
                    "rtt_ms": 0.0,
                    "sys_name": "",
                    "sys_descr": "",
                    "error": "No supported MIB-II System OIDs returned.",
                }
            return {
                "reachable": True,
                "rtt_ms": rtt_ms,
                "sys_name": str(sys_vals.get(STD_OIDS["sysName"], "")),
                "sys_descr": str(sys_vals.get(STD_OIDS["sysDescr"], "")),
                "error": "",
            }
        except Exception as e:
            return {
                "reachable": False,
                "rtt_ms": 0.0,
                "sys_name": "",
                "sys_descr": "",
                "error": scrub_secrets(str(e), creds),
            }

    async def discover_device(
        self,
        ip_address: str,
        creds: SNMPCredentials,
        port: int = 161,
        timeout_sec: float = 2.0,
        retries: int = 1,
        profile_override: str = "",
    ) -> SNMPDiscoveryResult:
        target = self._validate_host(ip_address)
        creds.validate()
        t0 = time.perf_counter()

        sys_oids = [
            STD_OIDS["sysDescr"],
            STD_OIDS["sysObjectID"],
            STD_OIDS["sysUpTime"],
            STD_OIDS["sysName"],
            STD_OIDS["sysLocation"],
            STD_OIDS["sysServices"],
        ]
        try:
            sys_vals = await self.transport.get(
                target, int(port), creds, sys_oids, timeout_sec=float(timeout_sec), retries=int(retries)
            )
        except SNMPError as e:
            return SNMPDiscoveryResult(
                ip_address=target,
                port=int(port),
                snmp_version=creds.version,
                reachable=False,
                error=scrub_secrets(str(e), creds),
            )

        rtt_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        sys_descr = str(sys_vals.get(STD_OIDS["sysDescr"], ""))
        sys_object_id = str(sys_vals.get(STD_OIDS["sysObjectID"], ""))
        sys_uptime = int(sys_vals.get(STD_OIDS["sysUpTime"], 0) or 0)
        sys_name = str(sys_vals.get(STD_OIDS["sysName"], ""))
        sys_location = str(sys_vals.get(STD_OIDS["sysLocation"], ""))
        sys_services = int(sys_vals.get(STD_OIDS["sysServices"], 0) or 0)

        detected = detect_vendor_and_profile(sys_object_id, sys_descr, sys_services)
        profile_name = profile_override or detected["profile_name"]
        profile: SNMPVendorProfile = get_profile(profile_name)

        model = detected["model"]
        firmware = detected["firmware"]

        # Enrich model / firmware from profile OIDs if exposed
        if profile.model_oids:
            for oid in profile.model_oids:
                try:
                    if oid.endswith(".0"):
                        res = await self.transport.get(target, port, creds, [oid], timeout_sec, retries)
                        if res and str(next(iter(res.values()))).strip():
                            model = str(next(iter(res.values()))).strip()
                            break
                    else:
                        rows = await self.transport.walk(target, port, creds, oid, timeout_sec, retries, max_rows=1)
                        if rows and str(rows[0][1]).strip():
                            model = str(rows[0][1]).strip()
                            break
                except SNMPError:
                    continue

        if profile.firmware_oids:
            for oid in profile.firmware_oids:
                try:
                    if oid.endswith(".0"):
                        res = await self.transport.get(target, port, creds, [oid], timeout_sec, retries)
                        if res and str(next(iter(res.values()))).strip():
                            firmware = str(next(iter(res.values()))).strip()
                            break
                    else:
                        rows = await self.transport.walk(target, port, creds, oid, timeout_sec, retries, max_rows=1)
                        if rows and str(rows[0][1]).strip():
                            firmware = str(rows[0][1]).strip()
                            break
                except SNMPError:
                    continue

        # Detect true hardware/MIB capabilities without inventing unsupported values
        cap_ifaces = await self._has_oid_or_table(
            target, creds, (STD_OIDS["ifNumber"], STD_OIDS["ifIndex"]), port, timeout_sec, retries
        )
        cap_cpu = await self._has_oid_or_table(
            target, creds, profile.cpu_oids or (STD_OIDS["hrProcessorLoad"],), port, timeout_sec, retries
        )
        mem_probes = tuple(profile.memory_pct_oids) + tuple(profile.memory_used_oids) + (STD_OIDS["hrMemorySize"],)
        cap_mem = await self._has_oid_or_table(target, creds, mem_probes, port, timeout_sec, retries)
        cap_temp = (
            await self._has_oid_or_table(target, creds, profile.temperature_value_oids, port, timeout_sec, retries)
            if profile.temperature_value_oids
            else False
        )
        cap_poe = (
            await self._has_oid_or_table(target, creds, profile.poe_budget_oids, port, timeout_sec, retries)
            if profile.poe_budget_oids
            else False
        )
        cap_vlan = (
            await self._has_oid_or_table(target, creds, profile.vlan_name_oids, port, timeout_sec, retries)
            if profile.vlan_name_oids
            else False
        )

        capabilities = {
            "interfaces": cap_ifaces,
            "cpu": cap_cpu,
            "memory": cap_mem,
            "temperature": cap_temp,
            "poe": cap_poe,
            "vlans": cap_vlan,
        }

        return SNMPDiscoveryResult(
            ip_address=target,
            port=int(port),
            snmp_version=creds.version,
            reachable=bool(sys_vals),
            rtt_ms=rtt_ms,
            sys_descr=sys_descr,
            sys_object_id=sys_object_id,
            sys_uptime_ticks=sys_uptime,
            sys_name=sys_name,
            sys_location=sys_location,
            sys_services=sys_services,
            vendor=detected["vendor"] if not profile_override else profile.vendor,
            model=model,
            firmware=firmware,
            device_type=detected["device_type"] if not profile_override else profile.device_type,
            profile_name=profile.name,
            capabilities=capabilities,
        )
