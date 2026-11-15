import os
import sys
import json
import subprocess
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import pytest

# Ensure src is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from utils.db import DatabaseManager, MonitoringLog, Host
from utils.config import ConfigManager
from utils.auth import encrypt_data, decrypt_data, custom_match
from core.tools import NetworkTools
from core.scanner import Scanner
from core.net_config import NetworkConfig
from core.speedtest import ServerListWorker


class TestDatabase:
    def test_add_and_get_host(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "test.db"))
        assert db.add_host("192.168.1.1", "Router") is True
        hosts = db.get_hosts()
        assert len(hosts) == 1
        assert hosts[0]["address"] == "192.168.1.1"
        assert hosts[0]["label"] == "Router"
        assert hosts[0]["is_active"] is True

        # Updating label of existing host
        assert db.add_host("192.168.1.1", "Core Router") is True
        hosts = db.get_hosts()
        assert len(hosts) == 1
        assert hosts[0]["label"] == "Core Router"

    def test_save_and_get_host_history(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "test.db"))
        db.add_host("8.8.8.8", "Google DNS")
        db.save_log("8.8.8.8", "UP", 15, "15ms")
        db.save_log("8.8.8.8", "DOWN", 0, "Timeout")

        history = db.get_host_history("8.8.8.8")
        assert len(history) == 2
        statuses = {h["status"] for h in history}
        assert statuses == {"UP", "DOWN"}

    def test_clear_host_history(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "test.db"))
        db.save_log("1.1.1.1", "UP", 10, "10ms")
        assert len(db.get_host_history("1.1.1.1")) == 1
        db.clear_host_history("1.1.1.1")
        assert len(db.get_host_history("1.1.1.1")) == 0

    def test_delete_host_cascade(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "test.db"))
        db.add_host("10.0.0.1", "Switch")
        db.save_log("10.0.0.1", "UP", 5, "5ms")
        db.delete_host("10.0.0.1")
        assert db.get_hosts() == []
        assert db.get_host_history("10.0.0.1") == []

    def test_cleanup_old_logs(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "test.db"))
        db.add_host("8.8.4.4", "Backup DNS")
        with db.Session() as session:
            host = session.query(Host).filter_by(address="8.8.4.4").first()
            old_log = MonitoringLog(
                host_id=host.id,
                status="UP",
                latency=20,
                timestamp=datetime.utcnow() - timedelta(days=45)
            )
            recent_log = MonitoringLog(
                host_id=host.id,
                status="UP",
                latency=12,
                timestamp=datetime.utcnow()
            )
            session.add_all([old_log, recent_log])
            session.commit()

        db.cleanup_old_logs(days=30)
        history = db.get_host_history("8.8.4.4")
        assert len(history) == 1
        assert history[0]["latency"] == 12

    def test_speedtest_history(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "test.db"))
        db.save_speedtest(150.5, 45.2, 12.0, 2.5, 0.0, "Paris - Orange", "Orange")
        history = db.get_speedtest_history()
        assert len(history) == 1
        assert history[0]["download"] == 150.5
        assert history[0]["upload"] == 45.2
        assert history[0]["server"] == "Paris - Orange"

        latest = db.get_latest_speedtest()
        assert latest is not None
        assert latest["download"] == 150.5

        db.clear_speedtest_history()
        assert db.get_speedtest_history() == []

    def test_global_services_crud(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "test.db"))
        db._init_default_global_services()
        services = db.get_global_services()
        initial_count = len(services)
        assert initial_count >= 9

        assert db.add_global_service("Custom API", "https://example.com", is_custom=True) is True
        assert db.add_global_service("Custom API", "https://example.com", is_custom=True) is False
        services_after = db.get_global_services()
        assert len(services_after) == initial_count + 1

        custom_svc = next(s for s in services_after if s["name"] == "Custom API")
        db.log_global_service(custom_svc["id"], "UP", 42)
        hist = db.get_global_service_history(custom_svc["id"])
        assert len(hist) == 1
        assert hist[0]["latency"] == 42

        db.delete_global_service(custom_svc["id"])
        assert len(db.get_global_services()) == initial_count


class TestConfig:
    def test_default_config_creation(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        cfg = ConfigManager()
        assert cfg.get("language") == "fr"
        assert isinstance(cfg.get("monitored_hosts"), list)

    def test_set_and_persist(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        cfg = ConfigManager()
        cfg.set("language", "en")
        cfg.set("minimize_to_tray", True)

        cfg2 = ConfigManager()
        assert cfg2.get("language") == "en"
        assert cfg2.get("minimize_to_tray") is True

    def test_password_encryption_in_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        cfg = ConfigManager()
        cfg.set("email_smtp_password", "MySuperSecretPass123!")

        with open(cfg.config_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        # Stored password on disk must not be plaintext
        assert raw_data["email_smtp_password"] != "MySuperSecretPass123!"

        # Reloading must decrypt back to original password
        cfg_reloaded = ConfigManager()
        assert cfg_reloaded.get("email_smtp_password") == "MySuperSecretPass123!"

        # 16-character plaintext password (valid base64 length) must not crash or corrupt via DPAPI
        assert cfg_reloaded.decrypt_value("rgsrodggtfbpshaj") == "rgsrodggtfbpshaj"
        # Encrypting an already encrypted value must be idempotent
        enc_once = cfg_reloaded.encrypt_value("MySuperSecretPass123!")
        assert cfg_reloaded.encrypt_value(enc_once) == enc_once

    def test_corrupted_json_fallback(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        base_dir = tmp_path / "BahaaIT"
        base_dir.mkdir(parents=True, exist_ok=True)
        config_file = base_dir / "config.json"
        config_file.write_text("{corrupted_json: true", encoding="utf-8")

        cfg = ConfigManager()
        assert cfg.get("language") == ConfigManager.DEFAULT_CONFIG["language"]


class TestAuth:
    def test_dpapi_roundtrip(self):
        secret = b"Sensitive session token payload"
        encrypted = encrypt_data(secret)
        if os.name == "nt":
            assert encrypted != secret
        decrypted = decrypt_data(encrypted)
        assert decrypted == secret

    def test_custom_match_bypass(self):
        jwt_pattern = r"^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$"
        assert custom_match(jwt_pattern, "sb_publishable_abc123") is True
        assert custom_match(jwt_pattern, "invalid_key") is None


class TestNetworkTools:
    def test_port_scan_open_port(self):
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 0
            mock_sock_cls.return_value.__enter__.return_value = mock_sock

            res = NetworkTools.check_port("127.0.0.1", 80)
            assert "OPEN" in res

    def test_port_scan_closed_port(self):
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 10061
            mock_sock_cls.return_value.__enter__.return_value = mock_sock

            res = NetworkTools.check_port("127.0.0.1", 9999)
            assert "CLOSED" in res

    def test_dns_lookup_success(self):
        with patch("subprocess.check_output", return_value="Name: google.com\nAddress: 142.250.180.14\n"):
            res = NetworkTools.nslookup("google.com")
            assert "142.250.180.14" in res

    def test_dns_lookup_failure(self):
        err = subprocess.CalledProcessError(1, ["nslookup", "invalid.local"], output="Non-existent domain")
        with patch("subprocess.check_output", side_effect=err):
            res = NetworkTools.nslookup("invalid.local")
            assert "Non-existent domain" in res

    def test_traceroute_parsing(self):
        scanner = Scanner()
        emitted_hops = []
        scanner.result_signal.connect(lambda d: emitted_hops.append(d))

        fake_stdout = [
            "Détermination de l'itinéraire vers 8.8.8.8 avec un maximum de 30 sauts :\n",
            "  1     2 ms     1 ms     1 ms  192.168.1.1\n",
            "  2     *        *        *     Délai d'attente de la demande dépassé.\n",
            "  3  81.192.87.73  rapports : Impossible de joindre l'hôte de destination.\n",
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = fake_stdout
        mock_proc.wait.return_value = 0

        with patch("subprocess.Popen", return_value=mock_proc):
            scanner.traceroute("8.8.8.8")

        assert len(emitted_hops) == 3
        assert emitted_hops[0]["status"] == "UP"
        assert emitted_hops[0]["ip"] == "192.168.1.1"
        assert emitted_hops[1]["status"] == "TIMEOUT"
        assert emitted_hops[2]["status"] == "UNREACHABLE"


class TestBugFixes:
    def test_bug6_sites_ping_french_and_unreachable(self):
        from ui.widgets.sites_view import PingWorker

        # Case 1: Subprocess fallback with French Windows ping output ("temps=14 ms")
        fr_stdout = (
            "Envoi d'une requête 'ping' sur 192.168.1.1 avec 32 octets de données :\n"
            "Réponse de 192.168.1.1 : octets=32 temps=14 ms TTL=64\n"
            "Statistiques Ping pour 192.168.1.1:\n"
            "    Minimum = 14ms, Maximum = 14ms, Moyenne = 14ms\n"
        )
        worker_fr = PingWorker(0, "192.168.1.1")
        results_fr = []
        worker_fr.result.connect(lambda row, status, lat: results_fr.append((row, status, lat)))

        with patch("icmplib.ping", side_effect=PermissionError("No raw socket")), \
             patch("subprocess.run", return_value=MagicMock(returncode=0, stdout=fr_stdout)):
            worker_fr.run()

        assert results_fr == [(0, "up", 14.0)]

        # Case 2: Windows ping returning returncode=0 when router says "Destination host unreachable" / "Impossible de joindre l'hôte"
        unreachable_stdout = (
            "Envoi d'une requête 'ping' sur 192.168.1.99 avec 32 octets de données :\n"
            "Réponse de 192.168.1.50 : Impossible de joindre l'hôte de destination.\n"
        )
        worker_down = PingWorker(1, "192.168.1.99")
        results_down = []
        worker_down.result.connect(lambda row, status, lat: results_down.append((row, status, lat)))

        with patch("icmplib.ping", side_effect=PermissionError("No raw socket")), \
             patch("subprocess.run", return_value=MagicMock(returncode=0, stdout=unreachable_stdout)):
            worker_down.run()

        assert results_down == [(1, "down", 0.0)]

    def test_bug7_net_config_dns_parsing_french_and_english(self):
        # Exact French Windows 11 netsh format with non-breaking spaces (\u00a0) before colons
        fr_netsh_output = (
            "Configuration pour l’interface «\u00a0Wi-Fi\u00a0»\n"
            "    DHCP activé:                          Oui\n"
            "    Adresse IP\u00a0:                           192.168.82.11\n"
            "    Préfixe de sous-réseau\u00a0:               192.168.0.0/16 (masque 255.255.0.0)\n"
            "    Passerelle par défaut\u00a0:               192.168.0.1\n"
            "    Métrique de passerelle\u00a0:              0\n"
            "    Métrique de l’interface\u00a0:             30\n"
            "    Serveurs DNS configurés via DHCP\u00a0:     8.8.8.8\n"
            "                                           8.8.4.4\n"
            "    Enregistrer avec le suffixe :           Principale uniquement\n"
        )
        with patch("subprocess.run", return_value=MagicMock(stdout=fr_netsh_output)):
            cfg = NetworkConfig.get_interface_config("Wi-Fi")
            assert cfg["gateway"] == "192.168.0.1"
            # Must be 8.8.8.8 and NOT 192.168.0.0 from Subnet Prefix!
            assert cfg["dns1"] == "8.8.8.8"
            assert cfg["dns2"] == "8.8.4.4"

        en_netsh_output = """
Configuration for interface "Ethernet"
    DHCP enabled:                         No
    IP Address:                           10.0.0.25
    Subnet Prefix:                        10.0.0.0/24 (mask 255.255.255.0)
    Default Gateway:                      10.0.0.1
    Gateway Metric:                       0
    InterfaceMetric:                      25
    Statically Configured DNS Servers:    1.1.1.1
                                          1.0.0.1
    Register with which suffix:           Primary only
"""
        with patch("subprocess.run", return_value=MagicMock(stdout=en_netsh_output)):
            cfg_en = NetworkConfig.get_interface_config("Ethernet")
            assert cfg_en["gateway"] == "10.0.0.1"
            assert cfg_en["dns1"] == "1.1.1.1"
            assert cfg_en["dns2"] == "1.0.0.1"

    def test_bug11_speedtest_international_servers_normalization(self):
        worker = ServerListWorker()
        emitted_servers = []
        worker.servers_ready.connect(lambda srv_list: emitted_servers.extend(srv_list))

        mock_st = MagicMock()
        mock_st.servers = {
            100.0: [{"id": "1", "name": "Casablanca", "sponsor": "IAM", "country": "Morocco", "d": 12.5, "host": "speed.iam.ma:8080"}]
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"id": 2, "name": "Paris", "sponsor": "Orange", "country": "France", "distance": "1850", "host": "paris.speedtest.orange.fr:8080"}
        ]

        with patch("speedtest.Speedtest", return_value=mock_st), \
             patch("requests.get", return_value=mock_resp):
            worker.run()

        assert len(emitted_servers) == 2
        intl_srv = next(s for s in emitted_servers if s["id"] == "2")
        assert isinstance(intl_srv["distance"], float)
        assert intl_srv["distance"] == 1850.0
        assert intl_srv["d"] == 1850.0
        assert intl_srv["url"].startswith("http://")

    def test_bug12_scanner_arp_fallback_single_finished_signal(self):
        scanner = Scanner()
        finished_count = 0

        def on_finished():
            nonlocal finished_count
            finished_count += 1

        scanner.finished_signal.connect(on_finished)

        with patch.object(scanner, "scan_lan", side_effect=lambda prefix: (scanner.finished_signal.emit(), [])[1]):
            with patch("core.scanner.SCAPY_AVAILABLE", False):
                scanner.scan_lan_arp("192.168.1.0/24")

        assert finished_count == 1

    def test_bug13_remote_view_getpass_imported(self):
        import ui.widgets.remote_view as rv
        assert hasattr(rv, "getpass")
        assert callable(rv.getpass.getuser)

    def test_bug15_db_set_host_active_and_uptime_stats(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "test_uptime.db"))
        db.add_host("192.168.1.10", "NAS")
        assert db.set_host_active("192.168.1.10", False) is True
        hosts = db.get_hosts()
        assert hosts[0]["is_active"] is False

        assert db.set_host_active("192.168.1.10", True) is True
        assert db.get_hosts()[0]["is_active"] is True

        db.save_log("192.168.1.10", "UP", 10, "10ms")
        db.save_log("192.168.1.10", "UP", 20, "20ms")
        db.save_log("192.168.1.10", "DOWN", 0, "Timeout")

        stats = db.get_uptime_stats("192.168.1.10", days=30)
        assert stats["total"] == 3
        assert stats["up"] == 2
        assert stats["down"] == 1
        assert stats["uptime_percent"] == 66.67
        assert stats["avg_latency"] == 15.0
