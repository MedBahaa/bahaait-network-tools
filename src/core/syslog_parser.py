from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Dict, Optional, Tuple, Union


SYSLOG_SEVERITIES: Dict[int, str] = {
    0: "Emergency",
    1: "Alert",
    2: "Critical",
    3: "Error",
    4: "Warning",
    5: "Notice",
    6: "Informational",
    7: "Debug",
}

SYSLOG_FACILITIES: Dict[int, str] = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    10: "authpriv",
    11: "ftp",
    12: "ntp",
    13: "audit",
    14: "alert",
    15: "clock",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7",
}

DEFAULT_MAX_MESSAGE_BYTES = 8192

_MONTHS: Dict[str, int] = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

_FORTINET_LEVEL_MAP: Dict[str, int] = {
    "emergency": 0,
    "emerg": 0,
    "alert": 1,
    "critical": 2,
    "crit": 2,
    "error": 3,
    "err": 3,
    "warning": 4,
    "warn": 4,
    "notice": 5,
    "information": 6,
    "informational": 6,
    "info": 6,
    "debug": 7,
}

_PRI_RE = re.compile(r"^<([^>]*)>")
_RFC5424_RE = re.compile(r"^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$")
_ISO_PREFIX_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}")
_FORTI_KV_RE = re.compile(r'([A-Za-z0-9_.-]+)=("(?:\\.|[^"])*"|\S+)')
_CISCO_SEQ_RE = re.compile(r"^(\d+):\s*")
_PRE_HOST_BSD_RE = re.compile(
    r"^([A-Za-z0-9._-]+):\s+(?=[*.]?(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\b)",
    re.IGNORECASE,
)
_BSD_TS_RE = re.compile(
    r"^[*.]?(?P<mon>(?i:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec))\s+"
    r"(?P<day>\d{1,2})(?:\s+(?P<year>\d{4}))?\s+"
    r"(?P<hms>\d{2}:\d{2}:\d{2})(?:\.\d+)?"
    r"(?:\s+(?P<tz>UTC|GMT|CET|CEST|EET|EEST|EST|EDT|CST|CDT|MST|MDT|PST|PDT|BST|IST|JST|[+-]\d{2}:?\d{2})(?=:|\s|$))?:?\s*"
)
_CISCO_MNEM_RE = re.compile(r"^%([A-Z0-9_]+-\d-[A-Z0-9_]+):")
_BSD_HOST_TAG_RE = re.compile(r"^([A-Za-z0-9._-]+)\s+([A-Za-z0-9_./-]+)(?:\[([^\]]+)\])?:\s*(.*)$")
_BSD_TAG_ONLY_RE = re.compile(r"^([A-Za-z0-9_./-]+)(?:\[([^\]]+)\])?:\s*(.*)$")


@dataclass
class ParsedSyslogMessage:
    source_ip: str = ""
    hostname: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    facility: int = 1
    facility_name: str = "user"
    severity: int = 6
    severity_name: str = "Informational"
    app_name: str = ""
    proc_id: str = ""
    msg_id: str = ""
    message: str = ""
    raw_message: str = ""
    rfc_version: str = "RAW"
    structured_data: Dict[str, Any] = field(default_factory=dict)
    malformed: bool = False
    truncated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _decode_rfc5424_sd(rest: str) -> Tuple[Dict[str, Dict[str, str]], str]:
    """Parse RFC 5424 STRUCTURED-DATA blocks and return (sd_dict, remaining_message)."""
    s = rest.lstrip()
    if not s:
        return {}, ""
    if s.startswith("-"):
        tail = s[1:].lstrip(" ")
        if tail.startswith("\ufeff"):
            tail = tail[1:]
        return {}, tail

    if not s.startswith("["):
        tail = s[1:] if s.startswith("\ufeff") else s
        return {}, tail

    blocks: list[str] = []
    idx = 0
    n = len(s)
    while idx < n:
        while idx < n and s[idx] == " ":
            idx += 1
        if idx >= n or s[idx] != "[":
            break
        start = idx + 1
        idx += 1
        in_quotes = False
        escaped = False
        closed = False
        while idx < n:
            ch = s[idx]
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_quotes = not in_quotes
            elif ch == "]" and not in_quotes:
                blocks.append(s[start:idx])
                idx += 1
                closed = True
                break
            idx += 1
        if not closed:
            break

    sd: Dict[str, Dict[str, str]] = {}
    for block in blocks:
        parts = block.strip().split(None, 1)
        if not parts:
            continue
        sd_id = parts[0]
        params: Dict[str, str] = {}
        if len(parts) > 1:
            for km in re.finditer(r'([A-Za-z0-9_.-]+)="((?:\\.|[^"])*)"', parts[1]):
                val = km.group(2).replace('\\"', '"').replace("\\\\", "\\").replace("\\]", "]")
                params[km.group(1)] = val
        sd[sd_id] = params

    msg = s[idx:].lstrip(" ")
    if msg.startswith("\ufeff"):
        msg = msg[1:]
    return sd, msg


def _parse_iso_to_naive_utc(ts_str: str, fallback: datetime) -> Tuple[datetime, bool]:
    if ts_str == "-":
        return fallback, False
    try:
        norm = ts_str[:-1] + "+00:00" if ts_str.endswith(("Z", "z")) else ts_str
        dt = datetime.fromisoformat(norm)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt, False
    except ValueError:
        return fallback, True


def _parse_bsd_timestamp(
    mon_str: str, day_str: str, hms_str: str, year_str: Optional[str], ref: datetime
) -> Optional[datetime]:
    month = _MONTHS.get(mon_str.lower())
    if month is None:
        return None
    day = int(day_str)
    hh, mm, ss = (int(x) for x in hms_str.split(":"))
    if year_str is not None:
        year = int(year_str)
    else:
        year = ref.year
        if month == 12 and ref.month == 1:
            year -= 1
    try:
        return datetime(year, month, day, hh, mm, ss)
    except ValueError:
        return None


def _parse_tz_offset(tz_str: str) -> Optional[timedelta]:
    m = re.match(r"^([+-])(\d{2}):?(\d{2})$", str(tz_str or "").strip())
    if not m:
        return None
    sign = 1 if m.group(1) == "+" else -1
    return timedelta(hours=sign * int(m.group(2)), minutes=sign * int(m.group(3)))


def parse_syslog_message(
    raw: Union[bytes, str],
    source_ip: str = "",
    received_at: Optional[datetime] = None,
    max_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
) -> ParsedSyslogMessage:
    """Safely parse raw UDP Syslog (RFC 5424, RFC 3164, Fortinet/Cisco/Ruckus, or malformed text)."""
    received_utc = received_at or datetime.utcnow()
    truncated = False
    malformed = False

    if isinstance(raw, (bytes, bytearray)):
        raw_bytes = bytes(raw)
        if len(raw_bytes) > max_bytes:
            raw_bytes = raw_bytes[:max_bytes]
            truncated = True
        text = raw_bytes.decode("utf-8", errors="replace")
    else:
        text = "" if raw is None else str(raw)
        encoded = text.encode("utf-8", errors="replace")
        if len(encoded) > max_bytes:
            text = encoded[:max_bytes].decode("utf-8", errors="replace")
            truncated = True

    if "\ufffd" in text:
        malformed = True

    text = text.replace("\x00", "").rstrip("\r\n")
    raw_message = text.strip()
    if not raw_message:
        return ParsedSyslogMessage(
            source_ip=source_ip,
            hostname=source_ip,
            timestamp=received_utc,
            facility=1,
            facility_name=SYSLOG_FACILITIES[1],
            severity=6,
            severity_name=SYSLOG_SEVERITIES[6],
            message="",
            raw_message="",
            rfc_version="RAW",
            malformed=True,
            truncated=truncated,
        )

    facility = 1
    severity = 6
    has_valid_pri = False
    body = raw_message

    pri_match = _PRI_RE.match(raw_message)
    if pri_match:
        pri_inner = pri_match.group(1)
        if pri_inner.isdigit() and 0 <= int(pri_inner) <= 191:
            pri = int(pri_inner)
            facility = pri // 8
            severity = pri % 8
            has_valid_pri = True
        else:
            malformed = True
        body = raw_message[pri_match.end() :].lstrip()

    fac_name = SYSLOG_FACILITIES.get(facility, "user")
    sev_name = SYSLOG_SEVERITIES.get(severity, "Informational")

    # 1. Try RFC 5424 (<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD [MSG])
    m5424 = _RFC5424_RE.match(body)
    if m5424:
        ver_str, ts_str, host_str, app_str, proc_str, msg_id_str, tail = m5424.groups()
        if int(ver_str) >= 1 and (ts_str == "-" or _ISO_PREFIX_RE.match(ts_str)):
            msg_ts, ts_bad = _parse_iso_to_naive_utc(ts_str, received_utc)
            if ts_bad:
                malformed = True
            sd, msg_text = _decode_rfc5424_sd(tail)
            return ParsedSyslogMessage(
                source_ip=source_ip,
                hostname=source_ip if host_str == "-" else host_str,
                timestamp=msg_ts,
                facility=facility,
                facility_name=fac_name,
                severity=severity,
                severity_name=sev_name,
                app_name="" if app_str == "-" else app_str,
                proc_id="" if proc_str == "-" else proc_str,
                msg_id="" if msg_id_str == "-" else msg_id_str,
                message=msg_text,
                raw_message=raw_message,
                rfc_version="RFC5424",
                structured_data=sd,
                malformed=malformed,
                truncated=truncated,
            )

    # 2. Try Fortinet FortiGate key-value syslog payload
    if "date=" in body and "time=" in body and ("devname=" in body or "logid=" in body or "devid=" in body):
        kv: Dict[str, str] = {}
        for km in _FORTI_KV_RE.finditer(body):
            v = km.group(2)
            if v.startswith('"') and v.endswith('"'):
                v = v[1:-1].replace('\\"', '"')
            kv[km.group(1)] = v

        fg_ts = received_utc
        if "date" in kv and "time" in kv:
            try:
                fg_ts = datetime.strptime(f"{kv['date']} {kv['time']}", "%Y-%m-%d %H:%M:%S")
                if "tz" in kv and (offset := _parse_tz_offset(kv["tz"])) is not None:
                    fg_ts = fg_ts - offset
            except ValueError:
                pass

        if not has_valid_pri and "level" in kv:
            lvl_sev = _FORTINET_LEVEL_MAP.get(kv["level"].lower())
            if lvl_sev is not None:
                severity = lvl_sev
                sev_name = SYSLOG_SEVERITIES[severity]

        return ParsedSyslogMessage(
            source_ip=source_ip,
            hostname=kv.get("devname") or source_ip,
            timestamp=fg_ts,
            facility=facility,
            facility_name=fac_name,
            severity=severity,
            severity_name=sev_name,
            app_name=kv.get("subtype") or kv.get("type") or "fortigate",
            message=kv.get("msg") or body,
            raw_message=raw_message,
            rfc_version="RFC3164",
            structured_data=kv,
            malformed=malformed,
            truncated=truncated,
        )

    # 3. Try RFC 3164 (BSD) + Cisco/Ruckus timestamp header variants
    work = body
    pre_host = ""
    seq_m = _CISCO_SEQ_RE.match(work)
    if seq_m:
        after_seq = work[seq_m.end() :]
        if _BSD_TS_RE.match(after_seq) or _PRE_HOST_BSD_RE.match(after_seq) or _CISCO_MNEM_RE.match(after_seq):
            work = after_seq

    pre_host_m = _PRE_HOST_BSD_RE.match(work)
    if pre_host_m:
        pre_host = pre_host_m.group(1)
        work = work[pre_host_m.end() :]

    ts_m = _BSD_TS_RE.match(work)
    if ts_m:
        bsd_ts = _parse_bsd_timestamp(
            ts_m.group("mon"),
            ts_m.group("day"),
            ts_m.group("hms"),
            ts_m.group("year"),
            received_utc,
        )
        msg_ts = bsd_ts or received_utc
        if bsd_ts is None:
            malformed = True

        rem = work[ts_m.end() :].lstrip()
        hostname = pre_host or source_ip
        app_name = ""
        proc_id = ""
        message = rem

        mnem_m = _CISCO_MNEM_RE.match(rem)
        if mnem_m:
            app_name = mnem_m.group(1)
            message = rem
        else:
            ht_m = _BSD_HOST_TAG_RE.match(rem)
            if ht_m:
                if not pre_host:
                    hostname = ht_m.group(1)
                app_name = ht_m.group(2)
                proc_id = ht_m.group(3) or ""
                message = ht_m.group(4)
                if message.startswith("%"):
                    cm2 = _CISCO_MNEM_RE.match(message)
                    if cm2:
                        app_name = cm2.group(1)
            else:
                # Handle HOST %CISCO-MNEM: message
                host_cisco_m = re.match(r"^([A-Za-z0-9._-]+)\s+(%([A-Z0-9_]+-\d-[A-Z0-9_]+):.*)$", rem)
                if host_cisco_m:
                    if not pre_host:
                        hostname = host_cisco_m.group(1)
                    app_name = host_cisco_m.group(3)
                    message = host_cisco_m.group(2)
                else:
                    tag_m = _BSD_TAG_ONLY_RE.match(rem)
                    if tag_m:
                        app_name = tag_m.group(1)
                        proc_id = tag_m.group(2) or ""
                        message = tag_m.group(3)

        return ParsedSyslogMessage(
            source_ip=source_ip,
            hostname=hostname,
            timestamp=msg_ts,
            facility=facility,
            facility_name=fac_name,
            severity=severity,
            severity_name=sev_name,
            app_name=app_name,
            proc_id=proc_id,
            message=message,
            raw_message=raw_message,
            rfc_version="RFC3164",
            malformed=malformed,
            truncated=truncated,
        )

    # 4. Raw fallback (with valid PRI vs unparseable/no-PRI message)
    app_name = ""
    cm = _CISCO_MNEM_RE.match(body)
    if cm:
        app_name = cm.group(1)
    if not has_valid_pri:
        malformed = True

    return ParsedSyslogMessage(
        source_ip=source_ip,
        hostname=source_ip,
        timestamp=received_utc,
        facility=facility,
        facility_name=fac_name,
        severity=severity,
        severity_name=sev_name,
        app_name=app_name,
        message=body,
        raw_message=raw_message,
        rfc_version="RAW",
        malformed=malformed,
        truncated=truncated,
    )
