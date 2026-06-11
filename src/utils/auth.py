from supabase import create_client, Client
import supabase._sync.client
import os
import json
import re

SUPABASE_URL = "https://ufanechaalahberrysnh.supabase.co"
SUPABASE_KEY = "sb_publishable_J_Ak_zokAZZ3eUAhypHcvw_c-_hUAvT"

class AuthManager:
    def __init__(self):
        # Monkey-patch to bypass strict JWT validation for new 'sb_publishable_' keys
        original_match = supabase._sync.client.re.match
        supabase._sync.client.re.match = lambda p, s, *a: True
        try:
            self.client: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
        finally:
            supabase._sync.client.re.match = original_match
            
        self.session_file = os.path.join(os.path.dirname(__file__), "..", "..", "session.json")
        self.user = None
        self.load_session()

    def load_session(self):
        if os.path.exists(self.session_file):
            try:
                with open(self.session_file, "r") as f:
                    data = json.load(f)
                    # Simple restore using refresh token or just assume active for demo
                    # Supabase python client handles some session persistence, but we can do it manually
                    res = self.client.auth.set_session(data.get("access_token"), data.get("refresh_token"))
                    if res.user:
                        self.user = res.user
            except:
                pass

    def save_session(self, session):
        try:
            with open(self.session_file, "w") as f:
                json.dump({
                    "access_token": session.access_token,
                    "refresh_token": session.refresh_token
                }, f)
        except Exception as e:
            print(f"Error saving session: {e}")

    def clear_session(self):
        if os.path.exists(self.session_file):
            os.remove(self.session_file)

    def login(self, email, password):
        try:
            res = self.client.auth.sign_in_with_password({"email": email, "password": password})
            self.user = res.user
            if res.session:
                self.save_session(res.session)
            return True, "Login successful"
        except Exception as e:
            return False, str(e)

    def register(self, email, password):
        try:
            res = self.client.auth.sign_up({"email": email, "password": password})
            return True, "Registration successful. Please check your email to verify."
        except Exception as e:
            return False, str(e)

    def logout(self):
        self.client.auth.sign_out()
        self.user = None
        self.clear_session()
        
    def is_authenticated(self):
        return self.user is not None
