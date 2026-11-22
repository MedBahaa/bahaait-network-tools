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


def create_monitoring_stack(
    db=None,
    config_manager=None,
    alarm_manager=None,
    tray_manager=None,
    logger=None,
) -> Dict[str, Any]:
    """Assemble and return the full v3.4.0 Intelligent Ping Monitoring backend stack."""
    from core.alert_manager import AlertManager
    from core.incident_manager import IncidentManager
    from core.monitoring_state import MonitoringPolicyConfig
    from core.monitoring_statistics import MonitoringStatisticsService
    from core.ping_engine import AsyncPingEngine
    from core.wan_monitor import WANMonitor
    from utils.db import DatabaseManager
    from utils.notification_manager import NotificationDispatcher

    db_mgr = db or DatabaseManager()
    policy_dict = db_mgr.get_policy(host_id=None)
    global_policy = MonitoringPolicyConfig.from_dict(policy_dict)

    dispatcher = NotificationDispatcher(
        alarm_manager=alarm_manager,
        tray_manager=tray_manager,
        config_manager=config_manager,
        logger=logger,
    )
    incident_mgr = IncidentManager(db_mgr)
    alert_mgr = AlertManager(db_mgr, dispatcher=dispatcher, config_manager=config_manager, logger=logger)
    stats_svc = MonitoringStatisticsService(db_mgr)
    wan_mon = WANMonitor()
    engine = AsyncPingEngine(
        db=db_mgr,
        global_policy=global_policy,
        alert_manager=alert_mgr,
        incident_manager=incident_mgr,
        wan_monitor=wan_mon,
    )
    return {
        "db": db_mgr,
        "global_policy": global_policy,
        "dispatcher": dispatcher,
        "incident_manager": incident_mgr,
        "alert_manager": alert_mgr,
        "statistics_service": stats_svc,
        "wan_monitor": wan_mon,
        "engine": engine,
    }
