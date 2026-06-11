import json
import os
from supabase import Client

class CloudSyncManager:
    def __init__(self, auth_manager):
        self.auth_manager = auth_manager
        self.client: Client = self.auth_manager.client

    def backup_config(self, config_dict):
        if not self.auth_manager.is_authenticated():
            return False, "Not authenticated"
            
        user_id = self.auth_manager.user.id
        file_path = f"{user_id}/config.json"
        
        try:
            # We assume a storage bucket named 'user-configs' exists
            # Create it in your supabase dashboard
            data = json.dumps(config_dict).encode('utf-8')
            
            # Upsert
            try:
                self.client.storage.from_("user-configs").update(file_path, data, {"contentType": "application/json"})
            except:
                self.client.storage.from_("user-configs").upload(file_path, data, {"contentType": "application/json"})
                
            return True, "Configuration backed up to Cloud successfully."
        except Exception as e:
            return False, f"Cloud Sync Error: {str(e)}"

    def restore_config(self):
        if not self.auth_manager.is_authenticated():
            return False, None
            
        user_id = self.auth_manager.user.id
        file_path = f"{user_id}/config.json"
        
        try:
            res = self.client.storage.from_("user-configs").download(file_path)
            config_dict = json.loads(res)
            return True, config_dict
        except Exception as e:
            return False, f"Could not restore configuration: {str(e)}"
