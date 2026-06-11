import socket
import concurrent.futures
from typing import List, Dict, Any, Tuple
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
from PySide6.QtCore import QObject, Signal
from icmplib import ping as icmp_ping, traceroute as icmp_traceroute, NameLookupError, SocketPermissionError

class Scanner(QObject):
    progress_signal = Signal(int)
    result_signal = Signal(dict)
    finished_signal = Signal()

    def __init__(self):
        super().__init__()

    def scan_ports(self, target: str, port_range: Tuple[int, int]=(1, 1024), fast_mode: bool=True) -> List[int]:
        if fast_mode:
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
            ports = common_ports
        else:
            ports = range(port_range[0], port_range[1] + 1)

        total = len(ports)
        opened = []

        def check_port(port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((target, port)) == 0:
                    return port
            return None

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                future_to_port = {executor.submit(check_port, port): port for port in ports}
                count = 0
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future_to_port[future]
                    res = future.result()
                    if res:
                        opened.append(res)
                        self.result_signal.emit({"target": target, "port": res, "status": "OPEN"})
                    else:
                        self.result_signal.emit({"target": target, "port": port, "status": "CLOSED"})
                    count += 1
                    self.progress_signal.emit(int((count / total) * 100))
        finally:
            self.finished_signal.emit()
        return opened

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
        try:
            if not SCAPY_AVAILABLE:
                return self.scan_lan(ip_range.rsplit('.', 1)[0])

            arp_request = scapy.ARP(pdst=ip_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
            
            total = max(len(answered_list), 1)
            for i, element in enumerate(answered_list):
                ip = element[1].psrc
                mac = element[1].hwsrc.upper()
                
                hostname = "Unknown"
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    pass
                
                res = {"ip": ip, "mac": mac, "hostname": hostname, "status": "UP"}
                results.append(res)
                self.result_signal.emit(res)
                self.progress_signal.emit(int(((i+1) / total) * 100))
            
            # If Scapy found nothing, fallback to ICMP scan
            if not results:
                return self.scan_lan(ip_range.rsplit('.', 1)[0])
                
        except Exception as e:
            print(f"Scapy Error: {e}")
            return self.scan_lan(ip_range.rsplit('.', 1)[0])
        finally:
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
