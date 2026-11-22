import ipaddress
import re
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


class HostState(str, Enum):
    UP = "UP"
    DEGRADED = "DEGRADED"
    DOWN = "DOWN"
    RECOVERING = "RECOVERING"
    PAUSED = "PAUSED"
    UNKNOWN = "UNKNOWN"


class ProbeOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    TIMEOUT = "TIMEOUT"
    DNS_ERROR = "DNS_ERROR"
    ENGINE_ERROR = "ENGINE_ERROR"


_SHELL_FORBIDDEN_CHARS = set(";|&$`<>\n\r\t '\"\\")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
)


def validate_target_address(raw: str) -> Tuple[bool, str]:
    """Validate and normalize a host IP address or RFC-1123 hostname.

    Rejects shell metacharacters and whitespace to prevent command injection.
    Returns (True, cleaned_address) or (False, error_message).
    """
    if not isinstance(raw, str):
        return False, "Target address must be a string."

    cleaned = raw.strip()
    if not cleaned:
        return False, "Target address cannot be empty."

    if any(ch in _SHELL_FORBIDDEN_CHARS for ch in cleaned):
        return False, "Target contains forbidden characters."

    if cleaned.lower().startswith(("http://", "https://")):
        parsed = urlparse(cleaned)
        host_part = parsed.hostname or ""
    else:
        # Strip optional :port only if single colon (IPv4/hostname:port) and not raw IPv6
        if cleaned.count(":") == 1 and not cleaned.startswith("["):
            host_part, port_part = cleaned.split(":", 1)
            if not port_part.isdigit():
                return False, "Invalid port specification in target address."
        else:
            host_part = cleaned.strip("[]")

    host_part = host_part.strip()
    if not host_part or any(ch in _SHELL_FORBIDDEN_CHARS for ch in host_part):
        return False, "Invalid target host."

    try:
        ip_obj = ipaddress.ip_address(host_part)
        return True, str(ip_obj)
    except ValueError:
        pass

    if _HOSTNAME_RE.match(host_part):
        return True, host_part

    return False, f"Invalid IP address or hostname: '{host_part}'"


@dataclass
class MonitoringPolicyConfig:
    probe_interval_ms: int = 1000
    timeout_ms: int = 1000
    warning_failures: int = 3
    critical_failures: int = 5
    recovery_successes: int = 3
    rolling_window_sec: int = 60
    packet_loss_warn_pct: float = 10.0
    latency_warn_ms: float = 150.0
    jitter_warn_ms: float = 30.0
    min_probes_for_quality_warn: int = 5
    sound_enabled: bool = True
    email_enabled: bool = True
    windows_notify_enabled: bool = True
    repeat_alert_interval_sec: int = 0

    def validate(self) -> None:
        if self.probe_interval_ms < 100:
            raise ValueError("probe_interval_ms must be >= 100 ms")
        if self.timeout_ms < 100:
            raise ValueError("timeout_ms must be >= 100 ms")
        if self.warning_failures < 1:
            raise ValueError("warning_failures must be >= 1")
        if self.critical_failures < self.warning_failures:
            raise ValueError("critical_failures must be >= warning_failures")
        if self.recovery_successes < 1:
            raise ValueError("recovery_successes must be >= 1")
        if self.rolling_window_sec < 10:
            raise ValueError("rolling_window_sec must be >= 10 seconds")
        if not (0.0 < self.packet_loss_warn_pct <= 100.0):
            raise ValueError("packet_loss_warn_pct must be between 0 and 100")
        if self.latency_warn_ms <= 0.0:
            raise ValueError("latency_warn_ms must be > 0")
        if self.jitter_warn_ms <= 0.0:
            raise ValueError("jitter_warn_ms must be > 0")
        if self.min_probes_for_quality_warn < 1:
            raise ValueError("min_probes_for_quality_warn must be >= 1")
        if self.repeat_alert_interval_sec < 0:
            raise ValueError("repeat_alert_interval_sec must be >= 0")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "MonitoringPolicyConfig":
        if not data:
            return cls()
        valid_fields = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in valid_fields and v is not None}
        cfg = cls(**filtered)
        return cfg


@dataclass
class StateTransition:
    host_address: str
    previous_state: HostState
    new_state: HostState
    changed: bool
    reason: str
    details: str
    timestamp_mono: float
    timestamp_utc: datetime


class HostStateMachine:
    """Finite state machine with hysteresis for host health monitoring."""

    def __init__(
        self,
        host_address: str,
        policy: Optional[MonitoringPolicyConfig] = None,
        initial_state: HostState = HostState.UNKNOWN,
    ):
        self.host_address = host_address
        self.policy = policy or MonitoringPolicyConfig()
        self.state: HostState = initial_state
        self.consecutive_failures: int = 0
        self.consecutive_successes: int = 0
        self.clean_quality_streak: int = 0
        self.degraded_reason: str = ""
        self.down_since_mono: Optional[float] = None
        self.loss_eval_after_mono: Optional[float] = None

    def update_policy(self, policy: MonitoringPolicyConfig) -> None:
        self.policy = policy

    def _compute_post_recovery_loss(
        self, window_samples: Optional[List[Any]]
    ) -> Tuple[int, int, float]:
        """Compute valid/timeout counts from window_samples after loss_eval_after_mono."""
        if not window_samples:
            return 0, 0, 0.0
        cutoff = self.loss_eval_after_mono
        valid = 0
        timeouts = 0
        for s in window_samples:
            if cutoff is not None and s.timestamp_mono <= cutoff:
                continue
            if s.outcome == ProbeOutcome.SUCCESS:
                valid += 1
            elif s.outcome == ProbeOutcome.TIMEOUT:
                valid += 1
                timeouts += 1
        loss_pct = (timeouts / valid) * 100.0 if valid > 0 else 0.0
        return valid, timeouts, loss_pct

    def _check_quality_warning(
        self,
        quality_snapshot: Optional[Any],
        window_samples: Optional[List[Any]] = None,
        hysteresis_factor: float = 1.0,
    ) -> Tuple[bool, str, str]:
        if quality_snapshot is None:
            return False, "", ""

        valid_probes = getattr(quality_snapshot, "valid_probes", 0)
        timeout_count = getattr(quality_snapshot, "timeout_count", 0)
        loss_pct = getattr(quality_snapshot, "packet_loss_pct", 0.0)
        avg_lat = getattr(quality_snapshot, "avg_latency_ms", 0.0)
        jitter = getattr(quality_snapshot, "jitter_ms", 0.0)

        if self.loss_eval_after_mono is not None and window_samples is not None:
            valid_probes, timeout_count, loss_pct = self._compute_post_recovery_loss(window_samples)

        min_probes = self.policy.min_probes_for_quality_warn
        loss_thresh = self.policy.packet_loss_warn_pct * hysteresis_factor
        lat_thresh = self.policy.latency_warn_ms * hysteresis_factor
        jit_thresh = self.policy.jitter_warn_ms * hysteresis_factor

        # Require >= 2 timeouts in rolling window so a single isolated drop never triggers DEGRADED
        if valid_probes >= min_probes and timeout_count >= 2 and loss_pct >= loss_thresh:
            return True, "PACKET_LOSS", f"Packet loss {loss_pct:.1f}% >= {loss_thresh:.1f}%"

        if valid_probes >= min_probes and avg_lat >= lat_thresh:
            return True, "HIGH_LATENCY", f"Average latency {avg_lat:.1f}ms >= {lat_thresh:.1f}ms"

        if valid_probes >= min_probes and jitter >= jit_thresh:
            return True, "HIGH_JITTER", f"Jitter {jitter:.1f}ms >= {jit_thresh:.1f}ms"

        return False, "", ""

    def process_probe(
        self,
        outcome: ProbeOutcome,
        quality_snapshot: Optional[Any],
        now_mono: float,
        now_utc: datetime,
        window_samples: Optional[List[Any]] = None,
    ) -> StateTransition:
        prev = self.state

        if prev == HostState.PAUSED:
            return StateTransition(
                host_address=self.host_address,
                previous_state=prev,
                new_state=prev,
                changed=False,
                reason="PAUSED",
                details="Host monitoring is paused.",
                timestamp_mono=now_mono,
                timestamp_utc=now_utc,
            )

        if outcome == ProbeOutcome.ENGINE_ERROR:
            return StateTransition(
                host_address=self.host_address,
                previous_state=prev,
                new_state=prev,
                changed=False,
                reason="ENGINE_ERROR_IGNORED",
                details="Monitoring engine/scheduler error excluded from status state.",
                timestamp_mono=now_mono,
                timestamp_utc=now_utc,
            )

        if outcome in (ProbeOutcome.TIMEOUT, ProbeOutcome.DNS_ERROR):
            self.consecutive_failures += 1
            self.consecutive_successes = 0
            self.clean_quality_streak = 0

            if prev == HostState.RECOVERING:
                self.state = HostState.DOWN
                self.down_since_mono = self.down_since_mono or now_mono
                return StateTransition(
                    host_address=self.host_address,
                    previous_state=prev,
                    new_state=self.state,
                    changed=True,
                    reason="RECOVERY_INTERRUPTED",
                    details=f"Probe failed during recovery ({outcome.value}).",
                    timestamp_mono=now_mono,
                    timestamp_utc=now_utc,
                )

            if self.consecutive_failures >= self.policy.critical_failures:
                self.state = HostState.DOWN
                if self.down_since_mono is None:
                    self.down_since_mono = now_mono
                return StateTransition(
                    host_address=self.host_address,
                    previous_state=prev,
                    new_state=self.state,
                    changed=(prev != self.state),
                    reason="CONFIRMED_OUTAGE",
                    details=f"{self.consecutive_failures} consecutive probe failures ({outcome.value}).",
                    timestamp_mono=now_mono,
                    timestamp_utc=now_utc,
                )

            if self.consecutive_failures >= self.policy.warning_failures and prev != HostState.DOWN:
                self.state = HostState.DEGRADED
                self.degraded_reason = "CONSECUTIVE_FAILURES"
                return StateTransition(
                    host_address=self.host_address,
                    previous_state=prev,
                    new_state=self.state,
                    changed=(prev != self.state),
                    reason="CONSECUTIVE_FAILURES",
                    details=f"{self.consecutive_failures} consecutive probe failures ({outcome.value}).",
                    timestamp_mono=now_mono,
                    timestamp_utc=now_utc,
                )

            # Isolated 1-2 failures: stay UP (or UNKNOWN -> stay non-alerting) unless rolling packet loss already degraded
            if prev == HostState.UP:
                degraded, reason, details = self._check_quality_warning(quality_snapshot, window_samples, 1.0)
                if degraded:
                    self.state = HostState.DEGRADED
                    self.degraded_reason = reason
                    return StateTransition(
                        host_address=self.host_address,
                        previous_state=prev,
                        new_state=self.state,
                        changed=True,
                        reason=reason,
                        details=details,
                        timestamp_mono=now_mono,
                        timestamp_utc=now_utc,
                    )

            return StateTransition(
                host_address=self.host_address,
                previous_state=prev,
                new_state=self.state,
                changed=False,
                reason="ISOLATED_FAILURE",
                details=f"Transient failure {self.consecutive_failures}/{self.policy.warning_failures}.",
                timestamp_mono=now_mono,
                timestamp_utc=now_utc,
            )

        # ProbeOutcome.SUCCESS
        self.consecutive_successes += 1
        self.consecutive_failures = 0

        if prev == HostState.DOWN:
            if self.policy.recovery_successes <= 1:
                self.state = HostState.UP
                self.down_since_mono = None
                self.degraded_reason = ""
                self.loss_eval_after_mono = now_mono
                return StateTransition(
                    host_address=self.host_address,
                    previous_state=prev,
                    new_state=self.state,
                    changed=True,
                    reason="RECOVERED",
                    details="Host recovered after successful probe.",
                    timestamp_mono=now_mono,
                    timestamp_utc=now_utc,
                )
            self.state = HostState.RECOVERING
            return StateTransition(
                host_address=self.host_address,
                previous_state=prev,
                new_state=self.state,
                changed=True,
                reason="RECOVERY_STARTED",
                details=f"Recovery probe 1/{self.policy.recovery_successes} succeeded.",
                timestamp_mono=now_mono,
                timestamp_utc=now_utc,
            )

        if prev == HostState.RECOVERING:
            if self.consecutive_successes >= self.policy.recovery_successes:
                self.down_since_mono = None
                self.loss_eval_after_mono = now_mono
                # Check latency/jitter only (ignore historical outage timeouts)
                if quality_snapshot is not None:
                    avg_lat = getattr(quality_snapshot, "avg_latency_ms", 0.0)
                    jitter = getattr(quality_snapshot, "jitter_ms", 0.0)
                    if avg_lat >= self.policy.latency_warn_ms:
                        self.state = HostState.DEGRADED
                        self.degraded_reason = "HIGH_LATENCY"
                        return StateTransition(
                            host_address=self.host_address,
                            previous_state=prev,
                            new_state=self.state,
                            changed=True,
                            reason="HIGH_LATENCY",
                            details=f"Recovered connectivity, but latency remains elevated ({avg_lat:.1f}ms).",
                            timestamp_mono=now_mono,
                            timestamp_utc=now_utc,
                        )
                    if jitter >= self.policy.jitter_warn_ms:
                        self.state = HostState.DEGRADED
                        self.degraded_reason = "HIGH_JITTER"
                        return StateTransition(
                            host_address=self.host_address,
                            previous_state=prev,
                            new_state=self.state,
                            changed=True,
                            reason="HIGH_JITTER",
                            details=f"Recovered connectivity, but jitter remains elevated ({jitter:.1f}ms).",
                            timestamp_mono=now_mono,
                            timestamp_utc=now_utc,
                        )

                self.state = HostState.UP
                self.degraded_reason = ""
                return StateTransition(
                    host_address=self.host_address,
                    previous_state=prev,
                    new_state=self.state,
                    changed=True,
                    reason="RECOVERED",
                    details=f"Host recovered after {self.consecutive_successes} consecutive successful probes.",
                    timestamp_mono=now_mono,
                    timestamp_utc=now_utc,
                )
            return StateTransition(
                host_address=self.host_address,
                previous_state=prev,
                new_state=self.state,
                changed=False,
                reason="RECOVERY_IN_PROGRESS",
                details=f"Recovery probe {self.consecutive_successes}/{self.policy.recovery_successes} succeeded.",
                timestamp_mono=now_mono,
                timestamp_utc=now_utc,
            )

        # prev is UNKNOWN, UP, or DEGRADED
        if prev == HostState.DEGRADED:
            # Hysteresis: require clean probes below 90% of warn threshold
            still_bad, reason, details = self._check_quality_warning(
                quality_snapshot, window_samples, hysteresis_factor=0.9
            )
            if still_bad:
                self.clean_quality_streak = 0
                if self.degraded_reason == "CONSECUTIVE_FAILURES" and reason == "PACKET_LOSS":
                    # When degraded by consecutive failures, recovery_successes clean probes recover
                    if self.consecutive_successes >= self.policy.recovery_successes:
                        self.state = HostState.UP
                        self.degraded_reason = ""
                        self.loss_eval_after_mono = now_mono
                        return StateTransition(
                            host_address=self.host_address,
                            previous_state=prev,
                            new_state=self.state,
                            changed=True,
                            reason="QUALITY_RECOVERED",
                            details=f"Recovered after {self.consecutive_successes} consecutive successful probes.",
                            timestamp_mono=now_mono,
                            timestamp_utc=now_utc,
                        )
                return StateTransition(
                    host_address=self.host_address,
                    previous_state=prev,
                    new_state=self.state,
                    changed=False,
                    reason=reason,
                    details=details,
                    timestamp_mono=now_mono,
                    timestamp_utc=now_utc,
                )

            self.clean_quality_streak += 1
            if (
                self.clean_quality_streak >= self.policy.recovery_successes
                and self.consecutive_successes >= self.policy.recovery_successes
            ):
                self.state = HostState.UP
                self.degraded_reason = ""
                self.loss_eval_after_mono = now_mono
                return StateTransition(
                    host_address=self.host_address,
                    previous_state=prev,
                    new_state=self.state,
                    changed=True,
                    reason="QUALITY_RECOVERED",
                    details="Metrics normalized below warning thresholds.",
                    timestamp_mono=now_mono,
                    timestamp_utc=now_utc,
                )
            return StateTransition(
                host_address=self.host_address,
                previous_state=prev,
                new_state=self.state,
                changed=False,
                reason="RECOVERING_QUALITY",
                details=f"Clean quality streak {self.clean_quality_streak}/{self.policy.recovery_successes}.",
                timestamp_mono=now_mono,
                timestamp_utc=now_utc,
            )

        # prev is UNKNOWN or UP
        degraded, reason, details = self._check_quality_warning(quality_snapshot, window_samples, 1.0)
        if degraded:
            self.state = HostState.DEGRADED
            self.degraded_reason = reason
            self.clean_quality_streak = 0
            return StateTransition(
                host_address=self.host_address,
                previous_state=prev,
                new_state=self.state,
                changed=(prev != self.state),
                reason=reason,
                details=details,
                timestamp_mono=now_mono,
                timestamp_utc=now_utc,
            )

        self.state = HostState.UP
        self.degraded_reason = ""
        return StateTransition(
            host_address=self.host_address,
            previous_state=prev,
            new_state=self.state,
            changed=(prev != HostState.UP),
            reason="NORMAL",
            details="Host responding within configured thresholds.",
            timestamp_mono=now_mono,
            timestamp_utc=now_utc,
        )

    def pause(self, now_mono: float, now_utc: datetime) -> StateTransition:
        prev = self.state
        self.state = HostState.PAUSED
        self.consecutive_failures = 0
        self.consecutive_successes = 0
        self.clean_quality_streak = 0
        self.degraded_reason = ""
        return StateTransition(
            host_address=self.host_address,
            previous_state=prev,
            new_state=HostState.PAUSED,
            changed=(prev != HostState.PAUSED),
            reason="PAUSED",
            details="Monitoring paused by user.",
            timestamp_mono=now_mono,
            timestamp_utc=now_utc,
        )

    def resume(self, now_mono: float, now_utc: datetime) -> StateTransition:
        prev = self.state
        self.state = HostState.UNKNOWN
        self.consecutive_failures = 0
        self.consecutive_successes = 0
        self.clean_quality_streak = 0
        self.degraded_reason = ""
        self.down_since_mono = None
        return StateTransition(
            host_address=self.host_address,
            previous_state=prev,
            new_state=HostState.UNKNOWN,
            changed=(prev != HostState.UNKNOWN),
            reason="RESUMED",
            details="Monitoring resumed by user.",
            timestamp_mono=now_mono,
            timestamp_utc=now_utc,
        )
