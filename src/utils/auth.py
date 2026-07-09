from supabase import create_client, Client
import supabase._sync.client
import os
import json
import re
import base64
import ctypes
from ctypes import wintypes

# Obfuscated Supabase credentials to prevent plain strings in binaries
SUPABASE_URL = base64.b64decode(b"aHR0cHM6Ly91ZmFuZWNoYWFsYWhiZXJyeXNuaC5zdXBhYmFzZS5jbw==").decode("utf-8")
SUPABASE_KEY = base64.b64decode(b"c2JfcHVibGlzaGFibGVfSl9Ba196b2tBWlozZVVBaHlwSGN2d19jLV9oVUF2VA==").decode("utf-8")

# Windows DPAPI definitions for secure token encryption
class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', ctypes.POINTER(ctypes.c_char))
    ]

def encrypt_data(data: bytes) -> bytes:
    """Encrypts data using Windows DPAPI (CryptProtectData)."""
    if os.name != 'nt':
        return data
    crypt32 = ctypes.windll.crypt32
    in_blob = DATA_BLOB()
    in_blob.cbData = len(data)
    in_blob.pbData = ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_char))
    out_blob = DATA_BLOB()
    success = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        wintypes.LPCWSTR("BahaaIT Session"),
        None, None, None, 0,
        ctypes.byref(out_blob)
    )
    if not success:
        raise ctypes.WinError()
    encrypted_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    return encrypted_bytes

def decrypt_data(data: bytes) -> bytes:
    """Decrypts data using Windows DPAPI (CryptUnprotectData)."""
    if os.name != 'nt':
        return data
    crypt32 = ctypes.windll.crypt32
    in_blob = DATA_BLOB()
    in_blob.cbData = len(data)
    in_blob.pbData = ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_char))
    out_blob = DATA_BLOB()
    success = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None, None, None, None, 0,
        ctypes.byref(out_blob)
    )
    if not success:
        raise ctypes.WinError()
    decrypted_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    return decrypted_bytes

original_match = supabase._sync.client.re.match

def custom_match(pattern, string, flags=0):
    """Targeted regex bypass specifically for Supabase publishable keys."""
    if pattern == r"^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$":
        if string.startswith("sb_publishable_"):
            return True
    return original_match(pattern, string, flags)

class AuthManager:
    def __init__(self):
        # Apply the targeted monkey-patch only during create_client
        supabase._sync.client.re.match = custom_match
        try:
            self.client: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
        finally:
            supabase._sync.client.re.match = original_match
            
        app_data = os.environ.get('LOCALAPPDATA', os.path.expanduser('~'))
        base_dir = os.path.join(app_data, 'BahaaIT')
        os.makedirs(base_dir, exist_ok=True)
        self.session_file = os.path.join(base_dir, "session.json")
        self.user = None
        
        # Load session asynchronously in a background thread to prevent blocking main UI thread at startup
        import threading
        threading.Thread(target=self.load_session, daemon=True).start()


    def load_session(self):
        if os.path.exists(self.session_file):
            try:
                with open(self.session_file, "rb") as f:
                    encrypted_data = f.read()
                decrypted_bytes = decrypt_data(encrypted_data)
                data = json.loads(decrypted_bytes.decode('utf-8'))
                res = self.client.auth.set_session(data.get("access_token"), data.get("refresh_token"))
                if res.user:
                    self.user = res.user
            except Exception:
                pass

    def save_session(self, session):
        try:
            data = json.dumps({
                "access_token": session.access_token,
                "refresh_token": session.refresh_token
            }).encode('utf-8')
            encrypted_data = encrypt_data(data)
            with open(self.session_file, "wb") as f:
                f.write(encrypted_data)
        except Exception as e:
            print(f"Error saving session: {e}")

    def clear_session(self):
        if os.path.exists(self.session_file):
            try:
                os.remove(self.session_file)
            except Exception:
                pass

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
        try:
            self.client.auth.sign_out()
        except Exception:
            pass
        self.user = None
        self.clear_session()
        
    def is_authenticated(self):
        return self.user is not None
