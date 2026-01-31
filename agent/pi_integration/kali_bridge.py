"""Kali Bridge - SSH connection to Kali Pi for remote tool execution"""
import subprocess
from typing import Optional


class KaliBridge:
    def __init__(self, host: str = None, user: str = "kali", port: int = 22):
        import os
        self.host = host or os.environ.get("BLACK_KALI_HOST")
        self.user = user or os.environ.get("BLACK_KALI_USER", "kali")
        self.port = port
        self.connected = False
    
    def connect(self) -> bool:
        if not self.host:
            print("[!] No Kali host configured. Set BLACK_KALI_HOST environment variable.")
            return False
        
        try:
            result = subprocess.run(
                ["ssh", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes", 
                 f"{self.user}@{self.host}", "echo", "connected"],
                capture_output=True, text=True, timeout=10
            )
            self.connected = result.returncode == 0
            return self.connected
        except Exception as e:
            print(f"[!] Kali connection failed: {e}")
            return False
    
    def disconnect(self):
        self.connected = False
    
    def execute(self, command: str, timeout: int = 30) -> Optional[str]:
        if not self.connected:
            if not self.connect():
                return None
        
        try:
            result = subprocess.run(
                ["ssh", f"{self.user}@{self.host}", command],
                capture_output=True, text=True, timeout=timeout
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            print(f"[!] Command timed out after {timeout}s")
            return None
        except Exception as e:
            print(f"[!] Execution failed: {e}")
            return None
