import asyncio
import ssl
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple


PingCheckFn = Callable[[str, float], Awaitable[Tuple[bool, float]]]
DnsCheckFn = Callable[[str], Awaitable[Tuple[bool, str]]]
HttpsCheckFn = Callable[[str], Awaitable[Tuple[bool, str]]]


@dataclass
class WANCorrelationVerdict:
    verdict_code: str
    severity: str
    probable_cause: str
    evidence: List[str]
    confidence: str
    recommended_actions: List[str]
    targets: Dict[str, Dict[str, Any]]
    timestamp_utc: datetime

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class WANMonitor:
    """Multi-target Internet Connectivity Correlation Engine (Gateway + 8.8.8.8 + 1.1.1.1 + DNS/HTTPS)."""

    def __init__(
        self,
        gateway_ip: str = "",
        primary_wan_ip: str = "8.8.8.8",
        secondary_wan_ip: str = "1.1.1.1",
        dns_test_domain: str = "google.com",
        https_test_hosts: Optional[List[str]] = None,
        timeout_sec: float = 1.5,
        ping_fn: Optional[PingCheckFn] = None,
        dns_fn: Optional[DnsCheckFn] = None,
        https_fn: Optional[HttpsCheckFn] = None,
    ):
        self.gateway_ip = gateway_ip.strip()
        self.primary_wan_ip = primary_wan_ip
        self.secondary_wan_ip = secondary_wan_ip
        self.dns_test_domain = dns_test_domain
        self.https_test_hosts = https_test_hosts or ["1.1.1.1", "www.google.com"]
        self.timeout_sec = float(timeout_sec)
        self._ping_fn = ping_fn or self._default_ping
        self._dns_fn = dns_fn or self._default_dns_check
        self._https_fn = https_fn or self._default_https_check

    @staticmethod
    def detect_gateway_ip() -> str:
        try:
            from core.scanner import Scanner
            from core.tools import NetworkTools
            info = NetworkTools.get_local_info()
            return Scanner()._detect_default_gateway(
                info.get("interface", "Unknown"),
                info.get("local_ip", ""),
            )
        except Exception:
            return ""

    @staticmethod
    async def _default_ping(ip: str, timeout: float) -> Tuple[bool, float]:
        if not ip:
            return False, 0.0
        try:
            from icmplib import async_ping
            res = await async_ping(ip, count=1, timeout=timeout)
            if res.is_alive:
                return True, round(float(res.avg_rtt), 2)
            return False, 0.0
        except Exception:
            return False, 0.0

    @staticmethod
    async def _default_dns_check(domain: str) -> Tuple[bool, str]:
        loop = asyncio.get_running_loop()
        t0 = time.perf_counter()
        try:
            res = await asyncio.wait_for(loop.getaddrinfo(domain, 443), timeout=2.0)
            ms = (time.perf_counter() - t0) * 1000.0
            ip = res[0][4][0] if res else "resolved"
            return True, f"{domain} -> {ip} ({ms:.0f} ms)"
        except Exception as e:
            return False, f"DNS lookup failed for {domain}: {e}"

    @staticmethod
    async def _default_https_check(host: str) -> Tuple[bool, str]:
        t0 = time.perf_counter()
        ctx = ssl.create_default_context()
        writer = None
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 443, ssl=ctx),
                timeout=2.5,
            )
            ms = (time.perf_counter() - t0) * 1000.0
            return True, f"HTTPS/TLS handshake OK with {host} ({ms:.0f} ms)"
        except Exception as e:
            return False, f"HTTPS check failed for {host}: {e}"
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass

    @staticmethod
    def correlate(
        gateway_up: bool,
        google_up: bool,
        cloudflare_up: bool,
        dns_ok: Optional[bool] = None,
        https_ok: Optional[bool] = None,
        latencies: Optional[Dict[str, float]] = None,
        gateway_ip: str = "Gateway",
        primary_wan_ip: str = "8.8.8.8",
        secondary_wan_ip: str = "1.1.1.1",
        dns_detail: str = "",
        https_detail: str = "",
    ) -> WANCorrelationVerdict:
        lats = latencies or {}
        targets = {
            "gateway": {"target": gateway_ip, "up": gateway_up, "latency_ms": lats.get("gateway", 0.0)},
            "primary_wan": {"target": primary_wan_ip, "up": google_up, "latency_ms": lats.get("primary_wan", 0.0)},
            "secondary_wan": {"target": secondary_wan_ip, "up": cloudflare_up, "latency_ms": lats.get("secondary_wan", 0.0)},
            "dns": {"ok": dns_ok, "detail": dns_detail},
            "https": {"ok": https_ok, "detail": https_detail},
        }
        now_utc = datetime.utcnow()
        evidence = [
            f"Gateway ({gateway_ip}): {'UP' if gateway_up else 'DOWN'} ({lats.get('gateway', 0.0):.1f} ms)",
            f"Google DNS ({primary_wan_ip}): {'UP' if google_up else 'DOWN'} ({lats.get('primary_wan', 0.0):.1f} ms)",
            f"Cloudflare DNS ({secondary_wan_ip}): {'UP' if cloudflare_up else 'DOWN'} ({lats.get('secondary_wan', 0.0):.1f} ms)",
        ]
        if dns_ok is not None:
            evidence.append(f"DNS Resolution: {'OK' if dns_ok else 'FAILED'} {dns_detail}".strip())
        if https_ok is not None:
            evidence.append(f"HTTPS Reachability: {'OK' if https_ok else 'FAILED'} {https_detail}".strip())

        # Case 1: All three ICMP targets reachable
        if gateway_up and google_up and cloudflare_up:
            if dns_ok is False:
                return WANCorrelationVerdict(
                    verdict_code="DNS_FAILURE",
                    severity="WARNING",
                    probable_cause="WAN IP connectivity is operational, but DNS name resolution failed.",
                    evidence=evidence,
                    confidence="HIGH",
                    recommended_actions=[
                        "Check configured primary/secondary DNS servers on the active adapter or DHCP.",
                        "Flush local DNS resolver cache (ipconfig /flushdns).",
                        "Test querying 1.1.1.1 or 8.8.8.8 directly with NSLookup.",
                    ],
                    targets=targets,
                    timestamp_utc=now_utc,
                )
            if https_ok is False:
                return WANCorrelationVerdict(
                    verdict_code="HTTPS_BLOCKED_OR_PROXY",
                    severity="WARNING",
                    probable_cause="ICMP and DNS succeed, but outbound HTTPS (TCP/443) failed.",
                    evidence=evidence,
                    confidence="MEDIUM",
                    recommended_actions=[
                        "Verify firewall outbound TCP/443 rules or corporate web proxy settings.",
                        "Check system clock accuracy for TLS certificate validation.",
                    ],
                    targets=targets,
                    timestamp_utc=now_utc,
                )
            return WANCorrelationVerdict(
                verdict_code="HEALTHY",
                severity="INFO",
                probable_cause="Local LAN gateway and WAN Internet connectivity are operating normally.",
                evidence=evidence,
                confidence="HIGH",
                recommended_actions=["No action required."],
                targets=targets,
                timestamp_utc=now_utc,
            )

        # Case 2: Gateway UP, BOTH external WAN ICMP targets DOWN
        if gateway_up and not google_up and not cloudflare_up:
            if https_ok is True:
                return WANCorrelationVerdict(
                    verdict_code="ICMP_FILTERED_WAN_OK",
                    severity="WARNING",
                    probable_cause="External ICMP ping is blocked/filtered upstream, but HTTPS Internet connectivity is working.",
                    evidence=evidence,
                    confidence="HIGH",
                    recommended_actions=[
                        "Do NOT declare an ISP outage — verify upstream firewall ICMP rate-limiting or policies.",
                        "Rely on HTTPS/DNS checks in addition to ICMP on this network.",
                    ],
                    targets=targets,
                    timestamp_utc=now_utc,
                )
            if https_ok is False and dns_ok is False:
                return WANCorrelationVerdict(
                    verdict_code="WAN_OUTAGE_CONFIRMED",
                    severity="CRITICAL",
                    probable_cause="Confirmed WAN / ISP outage: local gateway responds, but ICMP, DNS and HTTPS all fail.",
                    evidence=evidence,
                    confidence="HIGH",
                    recommended_actions=[
                        "Check WAN interface / fiber ONT / DSL modem status on the main router.",
                        "Contact the ISP or failover to backup WAN link.",
                    ],
                    targets=targets,
                    timestamp_utc=now_utc,
                )
            # ICMP failed alone without secondary confirmation -> SUSPECTED, never CONFIRMED
            return WANCorrelationVerdict(
                verdict_code="WAN_OUTAGE_SUSPECTED",
                severity="WARNING",
                probable_cause="Potential WAN or ISP disruption (both 8.8.8.8 and 1.1.1.1 ICMP timed out; secondary confirmation incomplete).",
                evidence=evidence,
                confidence="MEDIUM",
                recommended_actions=[
                    "Run DNS & HTTPS confirmation tests before escalating as a full ISP outage.",
                    "Inspect router WAN status and firewall outbound ICMP rules.",
                ],
                targets=targets,
                timestamp_utc=now_utc,
            )

        # Case 3: Gateway DOWN AND external targets DOWN
        if not gateway_up and not google_up and not cloudflare_up:
            if https_ok is True:
                return WANCorrelationVerdict(
                    verdict_code="ICMP_FILTERED_WAN_OK",
                    severity="WARNING",
                    probable_cause="All ICMP targets timed out (gateway and WAN), yet HTTPS succeeded.",
                    evidence=evidence,
                    confidence="MEDIUM",
                    recommended_actions=["Inspect local/host firewall blocking outbound ICMP echo requests."],
                    targets=targets,
                    timestamp_utc=now_utc,
                )
            return WANCorrelationVerdict(
                verdict_code="LAN_GATEWAY_ISSUE",
                severity="CRITICAL",
                probable_cause="Potential local LAN, Wi-Fi, switch, or default gateway outage.",
                evidence=evidence,
                confidence="HIGH" if https_ok is False else "MEDIUM",
                recommended_actions=[
                    "Check Ethernet cable, Wi-Fi association, VLAN assignment, and IP configuration.",
                    "Verify the local router/gateway power and ARP reachability.",
                ],
                targets=targets,
                timestamp_utc=now_utc,
            )

        # Case 4: Gateway UP, one WAN target UP, one DOWN
        if gateway_up and (google_up != cloudflare_up):
            failed_name = f"Cloudflare ({secondary_wan_ip})" if google_up else f"Google ({primary_wan_ip})"
            return WANCorrelationVerdict(
                verdict_code="DESTINATION_ROUTING_ISSUE",
                severity="WARNING",
                probable_cause=f"Potential destination-specific routing or ICMP issue affecting {failed_name} only.",
                evidence=evidence,
                confidence="MEDIUM",
                recommended_actions=[
                    f"Run Traceroute toward {secondary_wan_ip if google_up else primary_wan_ip}.",
                    "Internet access remains available via alternate destinations.",
                ],
                targets=targets,
                timestamp_utc=now_utc,
            )

        # Case 5: Gateway DOWN but at least one WAN target UP -> gateway simply drops ICMP to self
        return WANCorrelationVerdict(
            verdict_code="GATEWAY_ICMP_BLOCKED",
            severity="INFO",
            probable_cause="Internet connectivity is operational, while the local gateway blocks/ignores ICMP ping.",
            evidence=evidence,
            confidence="HIGH",
            recommended_actions=["Gateway firewall policy likely ignores ICMP echo; no outage detected."],
            targets=targets,
            timestamp_utc=now_utc,
        )

    async def run_check(self, include_secondary_checks: bool = True) -> WANCorrelationVerdict:
        gw = self.gateway_ip
        if not gw:
            loop = asyncio.get_running_loop()
            gw = await loop.run_in_executor(None, self.detect_gateway_ip)
            if gw:
                self.gateway_ip = gw

        gw_res, google_res, cf_res = await asyncio.gather(
            self._ping_fn(gw, self.timeout_sec) if gw else asyncio.sleep(0, result=(False, 0.0)),
            self._ping_fn(self.primary_wan_ip, self.timeout_sec),
            self._ping_fn(self.secondary_wan_ip, self.timeout_sec),
        )
        gw_up, gw_rtt = gw_res
        google_up, google_rtt = google_res
        cf_up, cf_rtt = cf_res

        dns_ok: Optional[bool] = None
        dns_detail = ""
        https_ok: Optional[bool] = None
        https_detail = ""

        if include_secondary_checks:
            dns_ok, dns_detail = await self._dns_fn(self.dns_test_domain)
            # Try configured HTTPS hosts until one succeeds
            for h in self.https_test_hosts:
                ok_h, det_h = await self._https_fn(h)
                https_ok = ok_h
                https_detail = det_h
                if ok_h:
                    break

        return self.correlate(
            gateway_up=gw_up,
            google_up=google_up,
            cloudflare_up=cf_up,
            dns_ok=dns_ok,
            https_ok=https_ok,
            latencies={
                "gateway": gw_rtt,
                "primary_wan": google_rtt,
                "secondary_wan": cf_rtt,
            },
            gateway_ip=gw or "Unknown Gateway",
            primary_wan_ip=self.primary_wan_ip,
            secondary_wan_ip=self.secondary_wan_ip,
            dns_detail=dns_detail,
            https_detail=https_detail,
        )
