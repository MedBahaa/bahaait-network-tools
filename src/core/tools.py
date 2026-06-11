import subprocess
import platform
import re

class NetworkTools:
    @staticmethod
    def ping(host, count=4, infinite=False):
        if platform.system().lower() == 'windows':
            param = '-t' if infinite else '-n'
        else:
            param = '-c' # No direct infinite flag on linux usually, but -c can be huge
            
        command = ['ping', param]
        if not infinite or platform.system().lower() != 'windows':
            command.append(str(count))
        command.append(host)
        
        # Always return Popen for real-time streaming in the UI
        return subprocess.Popen(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True, 
            encoding='cp850' if platform.system().lower() == 'windows' else None
        )

    @staticmethod
    def tracert(host):
        command = ['tracert', host] if platform.system().lower() == 'windows' else ['traceroute', host]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='cp850' if platform.system().lower() == 'windows' else None)
        return process

    @staticmethod
    def nslookup(host):
        command = ['nslookup', host]
        try:
            return subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True, encoding='cp850' if platform.system().lower() == 'windows' else None)
        except subprocess.CalledProcessError as e:
            return e.output

    @staticmethod
    def netstat():
        command = ['netstat', '-an']
        try:
            return subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True, encoding='cp850' if platform.system().lower() == 'windows' else None)
        except subprocess.CalledProcessError as e:
            return e.output

    @staticmethod
    def get_public_ip():
        import requests
        try:
            response = requests.get('https://api.ipify.org', timeout=5)
            return response.text
        except:
            return "Unknown"

    @staticmethod
    def get_fast_ip_info():
        try:
            import speedtest
            st = speedtest.Speedtest(secure=True)
            client = st.get_config()['client']
            return {
                "ip": client.get("ip", "Unknown"),
                "isp": client.get("isp", "Unknown")
            }
        except:
            return None

    @staticmethod
    def get_local_info():
        import socket
        import psutil
        import ipaddress
        hostname = socket.gethostname()
        
        # Default fallback values
        local_ip = "127.0.0.1"
        netmask = "255.255.255.0"
        
        # Try to find the active primary IP by attempting a connection
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            active_ip = s.getsockname()[0]
            s.close()
        except:
            active_ip = None

        interfaces_list = []
        if_addrs = psutil.net_if_addrs()
        
        active_interface = None
        for interface, addrs in if_addrs.items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    interfaces_list.append(f"{interface}: {addr.address}")
                    # Prioritize the interface used for external traffic
                    if active_ip and addr.address == active_ip:
                        local_ip = addr.address
                        netmask = addr.netmask
                        active_interface = interface
                    # Otherwise pick the first non-loopback interface
                    elif not active_ip and addr.address != "127.0.0.1" and local_ip == "127.0.0.1":
                        local_ip = addr.address
                        netmask = addr.netmask
                        active_interface = interface
        
        # Calculate Network CIDR (e.g. 192.168.1.0/24)
        network_cidr = "192.168.1.0/24" # Safe default
        try:
            if local_ip != "127.0.0.1" and netmask:
                network = ipaddress.IPv4Interface(f"{local_ip}/{netmask}").network
                network_cidr = str(network)
        except Exception:
            # Fallback to simple prefix if ipaddress fails
            prefix = ".".join(local_ip.split(".")[:-1])
            network_cidr = f"{prefix}.0/24"

        return {
            "hostname": hostname,
            "local_ip": local_ip,
            "netmask": netmask,
            "active_interface": active_interface,
            "network_cidr": network_cidr,
            "interfaces": interfaces_list
        }
    @staticmethod
    def whois(domain):
        import requests
        try:
            # Use RDAP (Registration Data Access Protocol) which is the modern WHOIS
            response = requests.get(f"https://rdap.org/domain/{domain}", timeout=10)
            if response.status_code == 200:
                # Return JSON formatted string for better readability in the UI
                import json
                return json.dumps(response.json(), indent=2)
            else:
                return f"RDAP lookup failed for {domain} (Status: {response.status_code})"
        except Exception as e:
            return f"Whois lookup error: {str(e)}"

    @staticmethod
    def check_port(host, port):
        import socket
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                result = s.connect_ex((host, int(port)))
                if result == 0:
                    return f"Port {port} on {host} is OPEN"
                else:
                    return f"Port {port} on {host} is CLOSED (Code: {result})"
        except Exception as e:
            return f"Port check error: {str(e)}"

    @staticmethod
    def get_multi_public_ips():
        import requests
        providers = {
            "ifconfig.me": "https://ifconfig.me/ip",
            "ipify.org": "https://api.ipify.org",
            "icanhazip.com": "https://icanhazip.com",
            "ident.me": "https://ident.me"
        }
        results = []
        for name, url in providers.items():
            try:
                res = requests.get(url, timeout=3)
                results.append(f"{name}: {res.text.strip()}")
            except:
                results.append(f"{name}: FAILED")
        return "\n".join(results)

    @staticmethod
    def check_http_status(url):
        import requests
        try:
            response = requests.get(url, timeout=5)
            if response.status_code < 400:
                return "UP"
            else:
                return f"DOWN ({response.status_code})"
        except Exception:
            return "DOWN"

    @staticmethod
    def get_connection_status():
        import subprocess
        import platform
        import socket
        
        if platform.system().lower() == 'windows':
            try:
                output = subprocess.check_output(['netsh', 'wlan', 'show', 'interfaces'], 
                                                 stderr=subprocess.STDOUT, text=True, encoding='cp850', timeout=2)
                
                # 'connecté' in French or 'connected' in English
                if "connect" in output.lower():
                    ssid = "Unknown"
                    signal = "0%"
                    for line in output.split('\n'):
                        line = line.strip()
                        if line.startswith("SSID") and not line.startswith("BSSID"):
                            parts = line.split(":")
                            if len(parts) > 1:
                                ssid = parts[1].strip()
                        elif line.startswith("Signal"):
                            parts = line.split(":")
                            if len(parts) > 1:
                                signal = parts[1].strip()
                    
                    if ssid != "Unknown":
                        return {"type": "wifi", "ssid": ssid, "signal": signal}
            except Exception:
                pass
                
            try:
                import psutil
                stats = psutil.net_if_stats()
                for iface, stat in stats.items():
                    iface_lower = iface.lower()
                    # Skip virtual/loopback interfaces
                    if any(v in iface_lower for v in ["loopback", "vmware", "virtual", "wsl", "veth"]):
                        continue
                    # If it's up and not Wi-Fi (handled above), assume it's a wired LAN
                    if stat.isup and "wi-fi" not in iface_lower and "wireless" not in iface_lower:
                        return {"type": "ethernet", "ssid": "Ethernet", "signal": "LAN"}
            except:
                pass
                
        return {"type": "disconnected", "ssid": "Offline", "signal": ""}
