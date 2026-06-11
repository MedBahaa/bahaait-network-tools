import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

Base = declarative_base()

class Host(Base):
    __tablename__ = 'hosts'
    id = Column(Integer, primary_key=True, autoincrement=True)
    address = Column(String, unique=True, nullable=False)
    label = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    logs = relationship("MonitoringLog", back_populates="host", cascade="all, delete")

class MonitoringLog(Base):
    __tablename__ = 'monitoring_logs'
    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey('hosts.id'), index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    status = Column(String)
    latency = Column(Integer)
    response = Column(String, nullable=True)
    host = relationship("Host", back_populates="logs")

class SpeedTestLog(Base):
    __tablename__ = 'speed_tests'
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    download = Column(Float)
    upload = Column(Float)
    ping = Column(Float)
    jitter = Column(Float)
    packet_loss = Column(Float)
    server = Column(String)
    isp = Column(String)

class GlobalService(Base):
    __tablename__ = 'global_services'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False)
    url = Column(String, nullable=False)
    is_custom = Column(Boolean, default=False)
    logs = relationship("GlobalServiceLog", back_populates="service", cascade="all, delete")

class GlobalServiceLog(Base):
    __tablename__ = 'global_service_logs'
    id = Column(Integer, primary_key=True, autoincrement=True)
    service_id = Column(Integer, ForeignKey('global_services.id'), index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    status = Column(String)
    latency = Column(Integer)
    service = relationship("GlobalService", back_populates="logs")

class DatabaseManager:
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.db_path = os.path.join(base_dir, "bahaait_network.db")
        else:
            self.db_path = db_path
            
        # Using connect_args={'check_same_thread': False} for multithreaded PySide6 compatibility
        self.engine = create_engine(f"sqlite:///{self.db_path}", connect_args={'check_same_thread': False})
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        
        self._init_default_global_services()

    def _init_default_global_services(self):
        default_services = [
            ("Apple Services", "https://www.apple.com/support/systemstatus/data/index.json"),
            ("Netflix", "https://help.netflix.com/en/is-netflix-down"),
            ("PlayStation Network", "https://status.playstation.com/fr-be/"),
            ("GitHub", "https://www.githubstatus.com/api/v2/status.json"),
            ("Discord", "https://discordstatus.com/api/v2/status.json"),
            ("Microsoft 365", "https://status.office.com"),
            ("AWS", "https://health.aws.amazon.com"),
            ("Google Cloud", "https://status.cloud.google.com"),
            ("WhatsApp", "https://www.whatsapp.com")
        ]
        
        with self.Session() as session:
            count = session.query(GlobalService).count()
            if count == 0:
                for name, url in default_services:
                    svc = GlobalService(name=name, url=url, is_custom=False)
                    session.add(svc)
                session.commit()

    def add_host(self, address: str, label: Optional[str] = None) -> bool:
        try:
            with self.Session() as session:
                host = session.query(Host).filter_by(address=address).first()
                if host:
                    host.label = label
                else:
                    new_host = Host(address=address, label=label)
                    session.add(new_host)
                session.commit()
                return True
        except Exception as e:
            print(f"DB Error (add_host): {e}")
            return False

    def get_hosts(self) -> List[Dict[str, Any]]:
        with self.Session() as session:
            hosts = session.query(Host).all()
            return [{"id": h.id, "address": h.address, "label": h.label, "is_active": h.is_active} for h in hosts]

    def delete_host(self, address: str) -> None:
        with self.Session() as session:
            host = session.query(Host).filter_by(address=address).first()
            if host:
                session.delete(host)
                session.commit()

    def clear_host_history(self, address: str) -> None:
        with self.Session() as session:
            host = session.query(Host).filter_by(address=address).first()
            if host:
                session.query(MonitoringLog).filter_by(host_id=host.id).delete()
                session.commit()

    def save_log(self, address: str, status: str, latency: int, response: Optional[str] = None) -> None:
        try:
            with self.Session() as session:
                host = session.query(Host).filter_by(address=address).first()
                if not host:
                    host = Host(address=address)
                    session.add(host)
                    session.flush() # To get the host.id immediately
                
                log = MonitoringLog(host_id=host.id, status=status, latency=latency, response=response)
                session.add(log)
                session.commit()
        except Exception as e:
            print(f"DB Error (save_log): {e}")

    def get_host_history(self, address: str, limit: int = 100) -> List[Dict[str, Any]]:
        with self.Session() as session:
            host = session.query(Host).filter_by(address=address).first()
            if not host:
                return []
            logs = session.query(MonitoringLog).filter_by(host_id=host.id).order_by(MonitoringLog.timestamp.desc()).limit(limit).all()
            return [{"timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "status": log.status, "latency": log.latency, "response": log.response} for log in logs]

    def get_uptime_stats(self, address: str, days: int = 30) -> None:
        pass

    def save_speedtest(self, download: float, upload: float, ping: float, jitter: float, packet_loss: float, server: str, isp: str) -> None:
        try:
            with self.Session() as session:
                st = SpeedTestLog(
                    download=download, upload=upload, ping=ping, 
                    jitter=jitter, packet_loss=packet_loss, 
                    server=server, isp=isp
                )
                session.add(st)
                session.commit()
        except Exception as e:
            print(f"DB Error (save_speedtest): {e}")

    def get_speedtest_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self.Session() as session:
            tests = session.query(SpeedTestLog).order_by(SpeedTestLog.timestamp.desc()).limit(limit).all()
            return [
                {
                    "timestamp": t.timestamp.strftime("%Y-%m-%d %H:%M:%S"), 
                    "download": t.download, 
                    "upload": t.upload, 
                    "ping": t.ping, 
                    "jitter": t.jitter, 
                    "packet_loss": t.packet_loss, 
                    "server": t.server, 
                    "isp": t.isp
                } for t in tests
            ]

    def clear_speedtest_history(self) -> None:
        with self.Session() as session:
            session.query(SpeedTestLog).delete()
            session.commit()

    def cleanup_old_logs(self, days: int = 30) -> None:
        cutoff = datetime.utcnow() - timedelta(days=days)
        with self.Session() as session:
            session.query(MonitoringLog).filter(MonitoringLog.timestamp < cutoff).delete()
            session.query(GlobalServiceLog).filter(GlobalServiceLog.timestamp < cutoff).delete()
            session.commit()

    # --- Global Services Methods ---
    def get_global_services(self) -> List[Dict[str, Any]]:
        with self.Session() as session:
            services = session.query(GlobalService).all()
            return [{"id": s.id, "name": s.name, "url": s.url, "is_custom": s.is_custom} for s in services]

    def add_global_service(self, name: str, url: str, is_custom: bool = True) -> bool:
        try:
            with self.Session() as session:
                if session.query(GlobalService).filter_by(name=name).first():
                    return False # Already exists
                new_svc = GlobalService(name=name, url=url, is_custom=is_custom)
                session.add(new_svc)
                session.commit()
                return True
        except Exception as e:
            print(f"DB Error (add_global_service): {e}")
            return False

    def delete_global_service(self, service_id: int) -> None:
        with self.Session() as session:
            svc = session.query(GlobalService).filter_by(id=service_id, is_custom=True).first()
            if svc:
                session.delete(svc)
                session.commit()

    def log_global_service(self, service_id: int, status: str, latency: int) -> None:
        try:
            with self.Session() as session:
                log = GlobalServiceLog(service_id=service_id, status=status, latency=latency)
                session.add(log)
                session.commit()
        except Exception as e:
            print(f"DB Error (log_global_service): {e}")

    def get_global_service_history(self, service_id: int, limit: int = 20) -> List[Dict[str, Any]]:
        with self.Session() as session:
            logs = session.query(GlobalServiceLog).filter_by(service_id=service_id).order_by(GlobalServiceLog.timestamp.desc()).limit(limit).all()
            # Reverse to have chronological order for sparklines
            res = [{"status": log.status, "latency": log.latency, "timestamp": log.timestamp} for log in logs]
            res.reverse()
            return res
