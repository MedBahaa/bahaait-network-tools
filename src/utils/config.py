import json
import os

class ConfigManager:
    DEFAULT_CONFIG = {
        "alarm_sound": "",
        "alarm_enabled": True,
        "monitored_hosts": ["8.8.8.8", "1.1.1.1", "google.com"],
        "sites": [
            {"name": "HQ Router", "ip": "192.168.1.1", "site": "Main Office"},
            {"name": "Core Switch", "ip": "10.0.0.1", "site": "Data Center"}
        ]
    }

    def __init__(self):
        self.config_path = os.path.join(os.path.dirname(__file__), "..", "config.json")
        self.config = self.load()

    def load(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # Merge with default to ensure all keys exist
                    return {**self.DEFAULT_CONFIG, **data}
            except:
                return self.DEFAULT_CONFIG.copy()
        return self.DEFAULT_CONFIG.copy()

    def save(self):
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            print(f"Failed to save config: {e}")

    def get(self, key, default=None):
        return self.config.get(key, default)

    def set(self, key, value):
        self.config[key] = value
        self.save()
