import json
import os

def get_obfuscated_credentials():
    e_parts = ["bahaaitnetworktools", "@gmail.com"]
    p_parts = ["rgsr", "odgg", "tfbp", "shaj"]
    return "".join(e_parts), "".join(p_parts)

class ConfigManager:
    DEFAULT_CONFIG = {
        "alarm_sound": "",
        "alarm_enabled": True,
        "minimize_to_tray": False,
        "language": "fr",
        "monitored_hosts": ["8.8.8.8", "1.1.1.1", "google.com"],
        "sites": [
            {"name": "HQ Router", "ip": "192.168.1.1", "site": "Main Office"},
            {"name": "Core Switch", "ip": "10.0.0.1", "site": "Data Center"}
        ],
        "email_alerts_enabled": False,
        "email_alert_on_down": True,
        "email_alert_on_up": True,
        "email_use_custom_smtp": False,
        "email_smtp_host": "",
        "email_smtp_port": "",
        "email_smtp_user": "",
        "email_smtp_password": "",
        "email_sender": "",
        "email_recipient": get_obfuscated_credentials()[0]
    }

    def __init__(self):
        app_data = os.environ.get('LOCALAPPDATA', os.path.expanduser('~'))
        base_dir = os.path.join(app_data, 'BahaaIT')
        os.makedirs(base_dir, exist_ok=True)
        self.config_path = os.path.join(base_dir, "config.json")
        self.config = self.load()

    def encrypt_value(self, value: str) -> str:
        if not value:
            return ""
        try:
            from utils.auth import encrypt_data
            encrypted_bytes = encrypt_data(value.encode('utf-8'))
            return base64.b64encode(encrypted_bytes).decode('utf-8')
        except Exception:
            return value

    def decrypt_value(self, value: str) -> str:
        if not value:
            return ""
        try:
            from utils.auth import decrypt_data
            decoded_bytes = base64.b64decode(value.encode('utf-8'), validate=True)
            decrypted_bytes = decrypt_data(decoded_bytes)
            return decrypted_bytes.decode('utf-8')
        except Exception:
            return value

    def load(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if "email_smtp_password" in data:
                        data["email_smtp_password"] = self.decrypt_value(data["email_smtp_password"])
                    # Merge with default to ensure all keys exist
                    return {**self.DEFAULT_CONFIG, **data}
            except Exception:
                return self.DEFAULT_CONFIG.copy()
        return self.DEFAULT_CONFIG.copy()

    def save(self):
        try:
            config_copy = self.config.copy()
            if "email_smtp_password" in config_copy:
                config_copy["email_smtp_password"] = self.encrypt_value(config_copy["email_smtp_password"])
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(config_copy, f, indent=4)
        except Exception as e:
            print(f"Failed to save config: {e}")

    def get(self, key, default=None):
        return self.config.get(key, default)

    def set(self, key, value):
        self.config[key] = value
        self.save()
