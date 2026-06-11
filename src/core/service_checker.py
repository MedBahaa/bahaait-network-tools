import requests
import time
import json
import re

class AdvancedServiceChecker:
    @staticmethod
    def check_service(name, url):
        """
        Returns a tuple: (status_string, latency_ms)
        status_string: "UP", "DOWN", "DEGRADED", "UNKNOWN"
        """
        start_time = time.time()
        
        try:
            # 1. Atlassian Statuspage API (GitHub, Discord, Reddit, etc.)
            if "status.json" in url or "api/v2/status.json" in url:
                return AdvancedServiceChecker._parse_atlassian_status(url)
                
            # 2. Apple System Status
            if "apple.com" in url and "systemstatus" in url:
                return AdvancedServiceChecker._parse_apple_status(url)
                
            # 3. Netflix Help Page
            if "netflix.com" in url:
                return AdvancedServiceChecker._parse_netflix_status(url)
                
            # 4. Fallback: Smart HTTP Ping
            return AdvancedServiceChecker._smart_ping(url)
            
        except requests.exceptions.RequestException as e:
            return ("DOWN", 0)
        except Exception as e:
            return ("UNKNOWN", 0)

    @staticmethod
    def _parse_atlassian_status(url):
        start = time.time()
        resp = requests.get(url, timeout=10)
        latency = int((time.time() - start) * 1000)
        
        if resp.status_code == 200:
            data = resp.json()
            indicator = data.get("status", {}).get("indicator", "none")
            if indicator == "none":
                return ("UP", latency)
            elif indicator in ["minor", "maintenance"]:
                return ("DEGRADED", latency)
            else:
                return ("DOWN", latency)
        return ("DOWN", latency)

    @staticmethod
    def _parse_apple_status(url):
        start = time.time()
        # Apple's actual JSON URL
        json_url = "https://www.apple.com/support/systemstatus/data/system_status_en_US.js"
            
        try:
            resp = requests.get(json_url, timeout=10)
            latency = int((time.time() - start) * 1000)
            
            if resp.status_code == 200:
                # Apple returns valid JSON in this file
                data = resp.json()
                services = data.get("services", [])
                
                # Expert Fix: Only count ACTIVE outages (where eventStatus is not 'resolved')
                active_outages = []
                for s in services:
                    events = s.get("events", [])
                    active_events = [e for e in events if e.get("eventStatus") != "resolved"]
                    if active_events:
                        active_outages.append(s)
                
                if len(active_outages) > 0:
                    return ("DEGRADED", latency)
                return ("UP", latency)
        except Exception as e:
            print(f"Apple Status Parse Error: {e}")
                
        return ("DOWN", 1000) # Fallback if API fails

    @staticmethod
    def _parse_netflix_status(url):
        start = time.time()
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        resp = requests.get(url, headers=headers, timeout=10)
        latency = int((time.time() - start) * 1000)
        
        if resp.status_code == 200:
            html = resp.text.lower()
            if "netflix is up" in html or "we are not currently experiencing" in html or "up" in html:
                return ("UP", latency)
            elif "experiencing issues" in html or "interrupted" in html:
                return ("DOWN", latency)
            else:
                # If we can't parse HTML perfectly, rely on Smart Ping logic
                if latency > 1500:
                    return ("DEGRADED", latency)
                return ("UP", latency)
        return ("DOWN", latency)

    @staticmethod
    def _smart_ping(url):
        start = time.time()
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        resp = requests.get(url, headers=headers, timeout=10)
        latency = int((time.time() - start) * 1000)
        
        if resp.status_code < 400:
            if latency > 1500:
                return ("DEGRADED", latency)
            return ("UP", latency)
        else:
            return ("DOWN", latency)
