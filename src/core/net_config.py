import subprocess
import psutil
import socket
import re

class NetworkConfig:
    @staticmethod
    def set_static_ip(interface_name, ip, mask, gateway):
        """netsh interface ipv4 set address name='Interface' static ip mask gateway"""
        cmd = f'netsh interface ipv4 set address name="{interface_name}" static {ip} {mask} {gateway}'
        return NetworkConfig._run_cmd(cmd)

    @staticmethod
    def set_dhcp(interface_name):
        cmd = f'netsh interface ipv4 set address name="{interface_name}" source=dhcp'
        cmd_dns = f'netsh interface ipv4 set dns name="{interface_name}" source=dhcp'
        res1 = NetworkConfig._run_cmd(cmd)
        res2 = NetworkConfig._run_cmd(cmd_dns)
        return res1 and res2

    @staticmethod
    def set_dns(interface_name, dns1, dns2=None):
        cmd1 = f'netsh interface ipv4 set dns name="{interface_name}" static {dns1} primary'
        res1 = NetworkConfig._run_cmd(cmd1)
        if dns2:
            cmd2 = f'netsh interface ipv4 add dns name="{interface_name}" {dns2} index=2'
            NetworkConfig._run_cmd(cmd2)
        return res1
    @staticmethod
    def get_interface_config(interface_name):
        config = {"ip": "", "mask": "", "gateway": "", "dns1": "", "dns2": ""}
        
        # Get IP and Mask via psutil
        addrs = psutil.net_if_addrs()
        if interface_name in addrs:
            for addr in addrs[interface_name]:
                if addr.family == socket.AF_INET:
                    config["ip"] = addr.address
                    config["mask"] = addr.netmask
        
        # Get Gateway and DNS via netsh
        try:
            res = subprocess.run(f'netsh interface ipv4 show config name="{interface_name}"', 
                                 shell=True, capture_output=True, text=True, encoding='cp850')
            output = res.stdout
            
            # Gateway (supports English and French CP850/UTF-8 encodings)
            gw_match = re.search(r"(?:Default Gateway|Passerelle par d.faut)\s*:\s*([\d\.]+)", output, re.IGNORECASE)
            if gw_match:
                config["gateway"] = gw_match.group(1)
            
            # Parse DNS section specifically (handles both Static and DHCP DNS in FR/EN)
            dns_list = []
            in_dns_block = False
            for line in output.splitlines():
                if "dns" in line.lower() and ":" in line:
                    in_dns_block = True
                    ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                    if ip_match:
                        dns_list.append(ip_match.group(1))
                elif in_dns_block:
                    # Indented continuation line for secondary DNS (no colon)
                    if ":" not in line:
                        ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                        if ip_match:
                            dns_list.append(ip_match.group(1))
                        else:
                            in_dns_block = False
                    else:
                        in_dns_block = False

            if len(dns_list) > 0:
                config["dns1"] = dns_list[0]
            if len(dns_list) > 1:
                config["dns2"] = dns_list[1]
            
        except Exception:
            pass
            
        return config

    @staticmethod
    def _run_cmd(cmd):
        try:
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error executing command: {e.stderr}")
            return False
