import time
from typing import Dict, Tuple, Any
from PySide6.QtCore import QThread, Signal
from icmplib import ping as icmp_ping, NameLookupError, SocketPermissionError

class PingWorker(QThread):
    result_ready = Signal(dict) # host, status, latency, response

    def __init__(self, hosts_data: Dict[str, bool]):
        """hosts_data: {host: is_active}"""
        super().__init__()
        self.hosts_data: Dict[str, bool] = hosts_data
        self.running: bool = True

    def run(self) -> None:
        while self.running:
            for host, active in list(self.hosts_data.items()):
                if not self.running: break
                if not active: continue
                
                status, latency, response = self.ping_host(host)
                self.result_ready.emit({
                    "host": host,
                    "status": status,
                    "latency": latency,
                    "response": response
                })
                time.sleep(0.1)
            time.sleep(1)

    def update_hosts(self, new_hosts_data: Dict[str, bool]) -> None:
        self.hosts_data = new_hosts_data

    def ping_host(self, host: str) -> Tuple[str, int, str]:
        try:
            host_to_ping = host
            if "http://" in host or "https://" in host:
                host_to_ping = host.replace("http://", "").replace("https://", "").split("/")[0]

            # privileged=False avoids needing strict admin rights if the OS allows it (like Linux ping group),
            # but Windows usually requires Admin or running as a service for raw sockets.
            # Fortunately icmplib has a fallback.
            response = icmp_ping(host_to_ping, count=1, timeout=1)
            
            if response.is_alive:
                latency = int(response.avg_rtt)
                if latency == 0:
                    latency = 1
                return "UP", latency, f"Reply from {response.address}: time={latency}ms"
            else:
                return "DOWN", 0, "Request timed out."
        except NameLookupError:
            return "DOWN", 0, "Could not resolve host."
        except SocketPermissionError:
            return "DOWN", 0, "Socket permission error (Admin rights required)."
        except Exception as e:
            return "DOWN", 0, str(e)

    def stop(self) -> None:
        self.running = False
        self.wait()
