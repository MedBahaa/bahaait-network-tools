import socket
import concurrent.futures
from typing import List, Dict, Any, Tuple
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
from PySide6.QtCore import QObject, Signal
from icmplib import ping as icmp_ping, NameLookupError, SocketPermissionError

class Scanner(QObject):
    progress_signal = Signal(int)
    result_signal = Signal(dict)
    finished_signal = Signal()

    def __init__(self):
        super().__init__()
        self.running = True

    def scan_ports(self, target: str, port_range: Tuple[int, int]=(1, 1024), fast_mode: bool=True) -> List[int]:
        import asyncio
        if fast_mode:
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
            ports = list(common_ports)
        else:
            ports = list(range(port_range[0], port_range[1] + 1))

        total = len(ports)
        opened = []
        count = 0

        async def check_port_async(port, sem):
            nonlocal count
            async with sem:
                if not self.running:
                    return
                try:
                    conn = asyncio.open_connection(target, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=0.4)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except:
                        pass
                    opened.append(port)
                    self.result_signal.emit({"target": target, "port": port, "status": "OPEN"})
                except Exception:
                    self.result_signal.emit({"target": target, "port": port, "status": "CLOSED"})
                finally:
                    count += 1
                    self.progress_signal.emit(int((count / total) * 100))

        async def run_scan():
            sem = asyncio.Semaphore(200)
            tasks = [check_port_async(p, sem) for p in ports]
            await asyncio.gather(*tasks)

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(run_scan())
            loop.close()
        except Exception as e:
            print(f"Async Scan Error: {e}")
        finally:
            self.finished_signal.emit()
            
        return sorted(opened)

    def scan_lan(self, network_prefix: str="192.168.1") -> List[Dict[str, Any]]:
        """ICMP-based LAN scan for a /24 subnet."""
        total = 254
        results = []

        def check_ip(i: int) -> Dict[str, Any] | None:
            ip = f"{network_prefix}.{i}"
            try:
                response = icmp_ping(ip, count=1, timeout=0.5)
                if response.is_alive:
                    hostname = "Unknown"
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        pass
                        
                    mac = "N/A"
                    try:
                        import subprocess
                        arp_out = subprocess.check_output(f"arp -a {ip}", shell=True, creationflags=subprocess.CREATE_NO_WINDOW).decode(errors='ignore')
                        for line in arp_out.splitlines():
                            parts = line.split()
                            if len(parts) >= 2 and parts[0] == ip:
                                mac = parts[1].replace('-', ':').upper()
                                break
                    except:
                        pass
                        
                    return {"ip": ip, "hostname": hostname, "status": "UP", "mac": mac}
                return None
            except:
                return None

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
                future_to_ip = {executor.submit(check_ip, i): i for i in range(1, 255)}
                count = 0
                for future in concurrent.futures.as_completed(future_to_ip):
                    if not self.running:
                        break
                    res = future.result()
                    if res:
                        results.append(res)
                        self.result_signal.emit(res)
                    count += 1
                    self.progress_signal.emit(int((count / total) * 100))
                    
        finally:
            self.finished_signal.emit()
        return results

    def scan_lan_arp(self, ip_range: str) -> List[Dict[str, Any]]:
        """Smart LAN scan: ARP table + ARP broadcast + ICMP fallback.
        Handles /16 networks by reading the local ARP table instead of
        scanning 65K hosts."""
        results = []
        
        try:
            import ipaddress
            network = ipaddress.ip_network(ip_range, strict=False)
            prefix_len = network.prefixlen
        except:
            prefix_len = 24
        
        # For large networks (/16 or bigger), use ARP table scan
        if prefix_len < 24:
            return self._scan_arp_table(ip_range)
        
        # For /24 networks, try Scapy ARP first, then fallback to ICMP
        delegated = False
        try:
            if not SCAPY_AVAILABLE:
                delegated = True
                return self.scan_lan(ip_range.rsplit('.', 1)[0])

            arp_request = scapy.ARP(pdst=ip_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
            
            total = max(len(answered_list), 1)
            for i, element in enumerate(answered_list):
                if not self.running:
                    break
                ip = element[1].psrc
                mac = element[1].hwsrc.upper()
                
                hostname = "Unknown"
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    pass
                
                res = {"ip": ip, "mac": mac, "hostname": hostname, "status": "UP"}
                results.append(res)
                self.result_signal.emit(res)
                self.progress_signal.emit(int(((i+1) / total) * 100))
            
            # If Scapy found nothing, fallback to ICMP scan
            if not results:
                delegated = True
                return self.scan_lan(ip_range.rsplit('.', 1)[0])
                
        except Exception as e:
            print(f"Scapy Error: {e}")
            delegated = True
            return self.scan_lan(ip_range.rsplit('.', 1)[0])
        finally:
            if not delegated:
                self.finished_signal.emit()
        return results

    def _scan_arp_table(self, ip_range: str) -> List[Dict[str, Any]]:
        """Read the OS ARP table to discover all known hosts on the network.
        Much faster than scanning 65K hosts for /16 networks."""
        import subprocess, re, ipaddress
        results = []
        
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
        except:
            network = None
        
        try:
            # Step 1: Read the ARP table
            arp_output = subprocess.check_output(
                "arp -a", shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            ).decode(errors='ignore')
            
            entries = []
            for line in arp_output.splitlines():
                match = re.match(r'\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)\s+(\S+)', line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace('-', ':').upper()
                    entry_type = match.group(3)
                    
                    # Skip broadcast and multicast
                    if mac == 'FF:FF:FF:FF:FF:FF':
                        continue
                    if ip.endswith('.255'):
                        continue
                    
                    # Filter by network range if specified
                    if network:
                        try:
                            if ipaddress.ip_address(ip) not in network:
                                continue
                        except:
                            continue
                    
                    entries.append((ip, mac))
            
            # Step 1b: Add this PC (not in its own ARP table)
            try:
                local_ip = socket.gethostbyname(socket.gethostname())
                local_hostname = socket.gethostname()
                # Get local MAC address
                local_mac = "N/A"
                try:
                    import re as _re
                    ipconfig_out = subprocess.check_output(
                        "getmac /FO CSV /NH", shell=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    ).decode(errors='ignore')
                    for line in ipconfig_out.splitlines():
                        # Only match valid MAC format (XX-XX-XX-XX-XX-XX)
                        mac_match = _re.search(r'([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})', line)
                        if mac_match:
                            local_mac = mac_match.group(1).replace('-', ':').upper()
                            break
                except:
                    pass
                
                # Only add if within the scanned network
                if network:
                    import ipaddress as _ipa
                    if _ipa.ip_address(local_ip) in network:
                        # Avoid duplicates
                        if not any(e[0] == local_ip for e in entries):
                            entries.insert(0, (local_ip, local_mac))
            except:
                pass
            
            total = max(len(entries), 1)
            self.progress_signal.emit(30)
            
            # Step 2: Enrich with hostname via reverse DNS
            def resolve_host(ip_mac):
                ip, mac = ip_mac
                hostname = "Unknown"
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    pass
                return {"ip": ip, "mac": mac, "hostname": hostname, "status": "UP"}
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(resolve_host, e): e for e in entries}
                count = 0
                for future in concurrent.futures.as_completed(futures):
                    if not self.running:
                        break
                    res = future.result()
                    results.append(res)
                    self.result_signal.emit(res)
                    count += 1
                    self.progress_signal.emit(30 + int((count / total) * 70))
                    
        except Exception as e:
            print(f"ARP Table Scan Error: {e}")
        finally:
            self.finished_signal.emit()
        return results

    def traceroute(self, target: str) -> None:
        """Real-time traceroute using system tracert command.
        Streams results hop-by-hop instead of waiting for completion."""
        import subprocess, re
        try:
            process = subprocess.Popen(
                ["tracert", "-d", "-w", "2000", target],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors='replace',
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            hop_num = 0
            for line in process.stdout:
                if not self.running:
                    try:
                        process.terminate()
                    except:
                        pass
                    break
                line = line.strip()
                if not line:
                    continue
                
                # Skip header lines (no leading digit = not a hop line)
                if not re.match(r'\s*\d+\s', line):
                    continue
                
                # Format 1: Standard hop with 3 RTT values
                #   1     3 ms     2 ms     1 ms  10.10.1.10
                #   3     *        *        *     Délai d'attente...
                match_std = re.match(
                    r'\s*(\d+)\s+'                          # Hop number
                    r'([<\d]+\s*ms|\*)\s+'                  # RTT1
                    r'([<\d]+\s*ms|\*)\s+'                  # RTT2
                    r'([<\d]+\s*ms|\*)\s+'                  # RTT3
                    r'(\d+\.\d+\.\d+\.\d+)',                # IP address
                    line
                )
                
                # Format 2: Error report (French Windows)
                #   3  81.192.87.73  rapports : Impossible de joindre...
                match_err = re.match(
                    r'\s*(\d+)\s+'                          # Hop number
                    r'(\d+\.\d+\.\d+\.\d+)\s+'              # IP address
                    r'.*(?:rapports|reports)',               # Error keyword
                    line
                )
                
                # Format 3: Timeout with no IP
                #   3     *        *        *     Délai...
                #   3     *        *        *     Request timed out.
                match_timeout = re.match(
                    r'\s*(\d+)\s+'
                    r'\*\s+\*\s+\*\s+',
                    line
                )
                
                if match_std:
                    hop_num = int(match_std.group(1))
                    p1 = match_std.group(2).strip()
                    p2 = match_std.group(3).strip()
                    p3 = match_std.group(4).strip()
                    ip = match_std.group(5).strip()
                    
                    status = "UP"
                    if p1 == "*" and p2 == "*" and p3 == "*":
                        status = "TIMEOUT"
                    
                    self.result_signal.emit({
                        "hop": str(hop_num), "ip": ip,
                        "p1": p1, "p2": p2, "p3": p3, "status": status
                    })
                    
                elif match_err:
                    hop_num = int(match_err.group(1))
                    ip = match_err.group(2).strip()
                    
                    self.result_signal.emit({
                        "hop": str(hop_num), "ip": ip,
                        "p1": "!", "p2": "!", "p3": "!",
                        "status": "UNREACHABLE"
                    })
                    
                elif match_timeout:
                    hop_num = int(match_timeout.group(1))
                    
                    self.result_signal.emit({
                        "hop": str(hop_num), "ip": "* * *",
                        "p1": "*", "p2": "*", "p3": "*",
                        "status": "TIMEOUT"
                    })
                    
                else:
                    continue
                
                self.progress_signal.emit(min(95, int((hop_num / 30) * 100)))
                    
            process.wait()
                
        except Exception as e:
            print(f"Traceroute Error: {e}")
            self.result_signal.emit({"hop": "0", "ip": str(e), "p1": "*", "p2": "*", "p3": "*", "status": "ERROR"})
        finally:
            self.finished_signal.emit()

    @staticmethod
    def parse_wifi_output(output: str, hidden_label: str = "<Hidden Network>") -> List[Dict[str, Any]]:
        """Parse French or English 'netsh wlan show networks mode=bssid' output."""
        import re
        import unicodedata

        def _clean_text(s: str) -> str:
            # Normalize non-breaking spaces and CP850/UTF-8 artifacts
            s = s.replace("\u00a0", " ").replace("\xff", " ").replace("┬á", " ")
            return re.sub(r"\s+", " ", s).strip()

        def _norm_key(s: str) -> str:
            s = _clean_text(s)
            return "".join(
                c for c in unicodedata.normalize("NFD", s)
                if unicodedata.category(c) != "Mn"
            ).lower().strip()

        networks = []
        current_net = None
        current_bssid = None

        for raw_line in output.splitlines():
            line = _clean_text(raw_line)
            if not line:
                continue

            # Match SSID header: "SSID 1 : MyNetwork" (allow any spacing/chars before colon, avoid BSSID)
            ssid_match = re.match(r'^SSID\s+\d+[^:]*:\s*(.*)$', line, re.IGNORECASE)
            if ssid_match:
                if current_net is not None:
                    networks.append(current_net)
                ssid_val = ssid_match.group(1).strip()
                current_net = {
                    "ssid": ssid_val if ssid_val else hidden_label,
                    "auth": "",
                    "encryption": "",
                    "bssids": []
                }
                current_bssid = None
                continue

            if current_net is None:
                continue

            # Match BSSID header: "BSSID 1 : a4:2b:8c:11:22:33"
            bssid_match = re.match(r'^BSSID\s+\d+[^:]*:\s*([0-9a-fA-F:-]{17})', line, re.IGNORECASE)
            if bssid_match:
                current_bssid = {
                    "bssid": bssid_match.group(1).replace("-", ":").upper(),
                    "signal_pct": 0,
                    "radio": "",
                    "band": "",
                    "channel": ""
                }
                current_net["bssids"].append(current_bssid)
                continue

            if ":" not in line:
                continue

            key_raw, val_raw = line.split(":", 1)
            key = _norm_key(key_raw)
            val = _clean_text(val_raw)

            if current_bssid is None:
                if "authentification" in key or "authentication" in key:
                    current_net["auth"] = val
                elif "chiffrement" in key or "encryption" in key:
                    current_net["encryption"] = val
            else:
                if key == "signal" or key.startswith("signal"):
                    m_sig = re.search(r'(\d+)\s*%', val)
                    if m_sig:
                        current_bssid["signal_pct"] = int(m_sig.group(1))
                elif "radio" in key:
                    current_bssid["radio"] = val
                elif key in ("bande", "band") or key.startswith("band"):
                    current_bssid["band"] = val.replace(",", ".")
                elif key in ("canal", "channel"):
                    m_ch = re.search(r'(\d+)', val)
                    current_bssid["channel"] = m_ch.group(1) if m_ch else val

        if current_net is not None:
            networks.append(current_net)

        results: List[Dict[str, Any]] = []
        for net in networks:
            ssid = net["ssid"]
            auth = net["auth"] or "Open"
            enc = net["encryption"]
            sec_base = f"{auth} / {enc}" if enc and enc.lower() not in ("aucun", "none", "") else auth

            bssids = net["bssids"]
            if not bssids:
                results.append({
                    "ssid": ssid,
                    "bssid": "N/A",
                    "signal": "0%",
                    "signal_pct": 0,
                    "channel": "N/A",
                    "security": sec_base,
                    "status": "LOW"
                })
                continue

            for b in bssids:
                sig_pct = b["signal_pct"]
                ch_str = b["channel"]
                band_str = b["band"]

                if not band_str and ch_str.isdigit():
                    ch_num = int(ch_str)
                    if 1 <= ch_num <= 14:
                        band_str = "2.4 GHz"
                    elif 32 <= ch_num <= 177:
                        band_str = "5 GHz"
                    else:
                        band_str = "6 GHz"

                if ch_str and band_str:
                    channel_display = f"Ch {ch_str} ({band_str})"
                elif ch_str:
                    channel_display = f"Ch {ch_str}"
                elif band_str:
                    channel_display = band_str
                else:
                    channel_display = "N/A"

                radio_str = b["radio"]
                security_display = f"{sec_base} ({radio_str})" if radio_str else sec_base
                status = "UP" if sig_pct >= 70 else ("WARN" if sig_pct >= 40 else "LOW")

                results.append({
                    "ssid": ssid,
                    "bssid": b["bssid"],
                    "signal": f"{sig_pct}%",
                    "signal_pct": sig_pct,
                    "channel": channel_display,
                    "security": security_display,
                    "status": status
                })

        results.sort(key=lambda item: item.get("signal_pct", 0), reverse=True)
        return results

    def scan_wifi(self, filter_text: str = "") -> List[Dict[str, Any]]:
        """Scan surrounding Wi-Fi networks and BSSIDs using netsh wlan."""
        import subprocess
        from utils.i18n import _
        results: List[Dict[str, Any]] = []
        try:
            self.progress_signal.emit(20)
            proc = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=10
            )
            raw_bytes = proc.stdout or b""
            try:
                output = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                output = raw_bytes.decode("cp850", errors="replace")

            self.progress_signal.emit(60)
            parsed = self.parse_wifi_output(output, hidden_label=_("wifi_hidden_ssid"))

            flt = (filter_text or "").strip().lower()
            if flt:
                parsed = [
                    item for item in parsed
                    if flt in item["ssid"].lower()
                    or flt in item["bssid"].lower()
                    or flt in item["channel"].lower()
                    or flt in item["security"].lower()
                ]

            if not parsed:
                info_msg = _("wifi_adapter_unavailable") if proc.returncode != 0 else _("wifi_no_networks")
                fallback_row = {
                    "ssid": _("wifi_no_networks"),
                    "bssid": "-",
                    "signal": "0%",
                    "signal_pct": 0,
                    "channel": "-",
                    "security": info_msg,
                    "status": "WARN"
                }
                results.append(fallback_row)
                self.result_signal.emit(fallback_row)
            else:
                total = len(parsed)
                for idx, item in enumerate(parsed):
                    if not self.running:
                        break
                    results.append(item)
                    self.result_signal.emit(item)
                    self.progress_signal.emit(60 + int(((idx + 1) / total) * 40))

        except Exception as e:
            err_row = {
                "ssid": _("wifi_no_networks"),
                "bssid": "-",
                "signal": "0%",
                "signal_pct": 0,
                "channel": "-",
                "security": str(e),
                "status": "WARN"
            }
            results.append(err_row)
            self.result_signal.emit(err_row)
        finally:
            self.finished_signal.emit()
        return results

    def _ping_host(self, host: str, timeout: float = 1.5) -> Tuple[bool, float]:
        """Ping a host via icmplib with subprocess fallback if raw sockets are restricted."""
        import subprocess
        import re
        try:
            res = icmp_ping(host, count=1, timeout=timeout)
            if res.is_alive:
                return True, float(res.avg_rtt)
        except Exception:
            pass

        try:
            out = subprocess.check_output(
                ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host],
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=timeout + 2.0
            ).decode("cp850", errors="replace")
            if "ttl=" in out.lower():
                m_time = re.search(r'(?:temps|time)\s*[=<]\s*(\d+)\s*ms', out, re.IGNORECASE)
                rtt = float(m_time.group(1)) if m_time else 1.0
                return True, rtt
        except Exception:
            pass
        return False, 0.0

    def _detect_default_gateway(self, interface_name: str, local_ip: str) -> str:
        """Detect default gateway IP using NetworkConfig or ipconfig fallback."""
        import subprocess
        import re
        try:
            from core.net_config import NetworkConfig
            if interface_name and interface_name != "Unknown":
                cfg = NetworkConfig.get_interface_config(interface_name)
                gw = cfg.get("gateway", "")
                if gw and re.match(r'^\d+\.\d+\.\d+\.\d+$', gw):
                    return gw
        except Exception:
            pass

        try:
            out = subprocess.check_output(
                "ipconfig",
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=5
            ).decode("cp850", errors="replace")
            for line in out.splitlines():
                low = line.lower()
                if "passerelle" in low or "gateway" in low:
                    m_ip = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if m_ip and m_ip.group(1) != "0.0.0.0":
                        return m_ip.group(1)
        except Exception:
            pass

        if local_ip and local_ip.count(".") == 3 and not local_ip.startswith("127."):
            return f"{local_ip.rsplit('.', 1)[0]}.1"
        return ""

    def run_smart_diagnostic(self, target_domain: str = "") -> List[Dict[str, Any]]:
        """Execute automated 5-step network troubleshooting chain."""
        import time
        from urllib.parse import urlparse
        from core.tools import NetworkTools
        from utils.i18n import _

        results: List[Dict[str, Any]] = []
        raw_domain = (target_domain or "").strip()
        if "://" in raw_domain:
            raw_domain = urlparse(raw_domain).hostname or "google.com"
        else:
            raw_domain = raw_domain.split("/")[0].strip()
        domain = raw_domain if raw_domain else "google.com"

        try:
            # Step 1: Local Network Adapter
            info = NetworkTools.get_local_info()
            local_ip = info.get("local_ip", "127.0.0.1")
            iface = info.get("interface", "Unknown")
            cidr = info.get("network_cidr", local_ip)
            adapter_ok = bool(
                local_ip
                and local_ip != "127.0.0.1"
                and not local_ip.startswith("169.254.")
            )
            step1 = {
                "step": _("diag_step_adapter"),
                "detail": f"{iface} ({local_ip})",
                "status": "OK" if adapter_ok else "FAIL",
                "latency": cidr if adapter_ok else _("diag_adapter_disconnected")
            }
            results.append(step1)
            self.result_signal.emit(step1)
            self.progress_signal.emit(20)
            if not self.running:
                return results

            # Step 2: Local Default Gateway
            gw_ip = self._detect_default_gateway(iface, local_ip) if adapter_ok else ""
            gw_ok = False
            gw_rtt = 0.0
            if adapter_ok and gw_ip:
                gw_ok, gw_rtt = self._ping_host(gw_ip, timeout=1.5)
                step2 = {
                    "step": _("diag_step_gateway"),
                    "detail": gw_ip,
                    "status": "OK" if gw_ok else "FAIL",
                    "latency": f"{gw_rtt:.0f} ms" if gw_ok else "TIMEOUT"
                }
            else:
                step2 = {
                    "step": _("diag_step_gateway"),
                    "detail": gw_ip or "N/A",
                    "status": "FAIL",
                    "latency": _("diag_no_gateway")
                }
            results.append(step2)
            self.result_signal.emit(step2)
            self.progress_signal.emit(40)
            if not self.running:
                return results

            # Step 3: WAN Internet Connectivity (8.8.8.8 / 1.1.1.1)
            wan_ok = False
            wan_rtt = 0.0
            wan_target = "8.8.8.8"
            if adapter_ok:
                wan_ok, wan_rtt = self._ping_host("8.8.8.8", timeout=1.5)
                if not wan_ok:
                    wan_ok, wan_rtt = self._ping_host("1.1.1.1", timeout=1.5)
                    if wan_ok:
                        wan_target = "1.1.1.1"
            step3 = {
                "step": _("diag_step_internet"),
                "detail": f"WAN ({wan_target})",
                "status": "OK" if wan_ok else "FAIL",
                "latency": f"{wan_rtt:.0f} ms" if wan_ok else "TIMEOUT"
            }
            results.append(step3)
            self.result_signal.emit(step3)
            self.progress_signal.emit(60)
            if not self.running:
                return results

            # Step 4: DNS Resolution
            dns_ok = False
            dns_ms = 0.0
            resolved_ip = ""
            if adapter_ok:
                t0 = time.perf_counter()
                try:
                    resolved_ip = socket.gethostbyname(domain)
                    dns_ms = (time.perf_counter() - t0) * 1000.0
                    dns_ok = bool(resolved_ip)
                except Exception:
                    dns_ok = False

            step4 = {
                "step": _("diag_step_dns"),
                "detail": f"{domain} -> {resolved_ip}" if dns_ok else domain,
                "status": "OK" if dns_ok else "FAIL",
                "latency": f"{dns_ms:.0f} ms" if dns_ok else _("diag_dns_failed")
            }
            results.append(step4)
            self.result_signal.emit(step4)
            self.progress_signal.emit(80)
            if not self.running:
                return results

            # Step 5: Global Diagnostic Verdict
            if adapter_ok and gw_ok and wan_ok and dns_ok:
                v_status = "OK"
                v_detail = _("diag_verdict_all_ok")
                v_result = "100% OK"
            elif not adapter_ok:
                v_status = "FAIL"
                v_detail = _("diag_verdict_adapter_fail")
                v_result = _("diag_action_check_cable_wifi")
            elif not gw_ok and not wan_ok:
                v_status = "FAIL"
                v_detail = _("diag_verdict_gateway_fail")
                v_result = _("diag_action_check_router_vlan")
            elif gw_ok and not wan_ok and not dns_ok:
                v_status = "FAIL"
                v_detail = _("diag_verdict_wan_fail")
                v_result = _("diag_action_check_isp_wan")
            elif wan_ok and not dns_ok:
                v_status = "WARN"
                v_detail = _("diag_verdict_dns_fail")
                v_result = _("diag_action_check_dns")
            elif not gw_ok and (wan_ok or dns_ok):
                v_status = "WARN"
                v_detail = _("diag_verdict_gw_icmp_blocked")
                v_result = _("diag_action_icmp_filtered")
            else:
                v_status = "WARN"
                v_detail = _("diag_verdict_partial")
                v_result = "PARTIAL"

            step5 = {
                "step": _("diag_step_verdict"),
                "detail": v_detail,
                "status": v_status,
                "latency": v_result
            }
            results.append(step5)
            self.result_signal.emit(step5)
            self.progress_signal.emit(100)

        finally:
            self.finished_signal.emit()
        return results
