import speedtest
import time
import re
from PySide6.QtCore import QThread, Signal

class SpeedTestWorker(QThread):
    result_ready = Signal(dict)
    status_update = Signal(str)
    progress_update = Signal(float, str) # value, type (down/up)

    def __init__(self, server_data=None):
        super().__init__()
        self.server_data = server_data
        self._st = None

    def run(self):
        try:
            self.status_update.emit("Initializing Professional Engine...")
            st = speedtest.Speedtest(secure=True)
            
            if self.server_data:
                self.status_update.emit(f"Connecting to {self.server_data['name']}...")
                st.servers = {0: [self.server_data]}
                best = st.get_best_server()
            else:
                self.status_update.emit("Selecting optimal server...")
                best = st.get_best_server()
            
            # 1. Real Latency, Jitter & Packet Loss Test
            # Extract host without port
            host = best['host'].split(':')[0]
            self.status_update.emit(f"Analyzing Quality (Host: {host})...")
            
            import subprocess
            import platform
            
            pings = []
            count = 10
            lost = 0
            
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            # We use a 1s timeout for each ping
            for i in range(count):
                self.status_update.emit(f"Quality Check: {i+1}/{count}")
                try:
                    # Handle both English (time=) and French (temps=) or just the value before ms
                    cmd = ['ping', param, '1', '-w', '1000', host]
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1.5)
                    
                    if proc.returncode == 0:
                        # Improved regex: looks for digits followed by ms, regardless of 'time' or 'temps'
                        # Standard format: ... time=12ms ... or ... temps=12 ms ...
                        match = re.search(r"(?:time|temps|ms)[=< ]+(\d+\.?\d*)\s*ms", proc.stdout, re.IGNORECASE)
                        if match:
                            pings.append(float(match.group(1)))
                        else:
                            # Fallback: just find any number followed by ms
                            match = re.search(r"(\d+\.?\d*)\s*ms", proc.stdout, re.IGNORECASE)
                            if match:
                                pings.append(float(match.group(1)))
                            else:
                                lost += 1
                    else:
                        lost += 1
                except:
                    lost += 1
                time.sleep(0.1)
            
            jitter = 0
            avg_ping = best['latency'] # Fallback
            if pings:
                avg_ping = sum(pings) / len(pings)
                if len(pings) > 1:
                    diffs = [abs(pings[i] - pings[i-1]) for i in range(1, len(pings))]
                    jitter = sum(diffs) / len(diffs)
            
            packet_loss = (lost / count) * 100
            
            client_info = st.results.client
            isp = client_info.get("isp", "Unknown")
            
            # 2. Download with Progress Simulation
            self.status_update.emit(f"ISP: {isp} | Testing Download...")
            self.progress_update.emit(0, "down")
            st.download(threads=15)
            # Emit intermediate download result so UI can show the final average immediately
            intermediate_res = st.results.dict()
            self.progress_update.emit(intermediate_res["download"] / 1_000_000, "down_done")
            
            # 3. Upload with Progress Simulation
            self.status_update.emit(f"ISP: {isp} | Testing Upload...")
            self.progress_update.emit(0, "up")
            st.upload(threads=15)
            res = st.results.dict()
            self.progress_update.emit(res["upload"] / 1_000_000, "up_done")
            
            res = st.results.dict()
            
            # Final result assembly
            # If our manual ping burst failed (pings empty), fallback to library result
            final_ping = round(avg_ping, 2)
            if not pings and "ping" in res:
                final_ping = round(res["ping"], 2)
                
            self.result_ready.emit({
                "download": round(res["download"] / 1_000_000, 2),
                "upload": round(res["upload"] / 1_000_000, 2),
                "ping": final_ping,
                "jitter": round(jitter, 2),
                "packet_loss": round(packet_loss, 1),
                "server": res["server"]["name"],
                "sponsor": res["server"]["sponsor"],
                "isp": isp,
                "ip": client_info.get("ip", "0.0.0.0")
            })
        except Exception as e:
            import traceback
            error_msg = f"Speedtest Error: {str(e)}"
            print(f"{error_msg}\n{traceback.format_exc()}")
            self.status_update.emit(error_msg)

class ServerListWorker(QThread):
    servers_ready = Signal(list)
    status_update = Signal(str)
    
    def run(self):
        try:
            self.status_update.emit("Loading available servers...")
            import speedtest
            
            final_list = []
            try:
                st = speedtest.Speedtest(secure=True)
                st.get_servers()
                
                added = 0
                for dist in sorted(st.servers.keys()):
                    for s in st.servers[dist]:
                        final_list.append({**s, 'distance': dist})
                        added += 1
                        if added >= 20: break
                    if added >= 20: break
            except Exception as e:
                self.status_update.emit(f"Local discovery error: {str(e)}")
                
            # Add specific International servers (USA, France)
            try:
                import requests
                self.status_update.emit("Fetching International servers...")
                for city in ["Paris", "New York", "London", "Frankfurt"]:
                    try:
                        res = requests.get(f"https://www.speedtest.net/api/js/servers?engine=js&search={city}&limit=3", timeout=3)
                        data = res.json()
                        for s in data:
                            # Convert id to string to match speedtest-cli format
                            s['id'] = str(s['id'])
                            if not any(x['id'] == s['id'] for x in final_list):
                                final_list.append(s)
                    except:
                        continue
            except Exception as e:
                self.logger.warning(f"Failed to fetch international servers: {e}")
            
            # Final UI cleanup for names
            for s in final_list:
                sponsor = s.get('sponsor', 'Unknown')
                s['ui_name'] = f"{s.get('name', 'Server')} ({sponsor})"
            
            self.servers_ready.emit(final_list)
            self.status_update.emit(f"Ready: {len(final_list)} servers available.")
        except Exception as e:
            self.status_update.emit(f"List Error: {str(e)}")
            self.servers_ready.emit([])
