import asyncio
import socket
import struct
import time
import threading
from collections import defaultdict
from core.utils import random_string


class OOBServer:
    def __init__(self, http_port=8888, dns_port=5353, domain="oob.local"):
        self.http_port = http_port
        self.dns_port = dns_port
        self.domain = domain
        self.interactions = defaultdict(list)
        self._running = False
        self._http_server = None
        self._dns_server = None
        self._lock = threading.Lock()
    
    def generate_token(self, length=12):
        return random_string(length)
    
    def get_callback_url(self, token):
        return f"http://{self.domain}:{self.http_port}/{token}"
    
    def get_dns_hostname(self, token):
        return f"{token}.{self.domain}"
    
    async def start(self):
        self._running = True
        await asyncio.gather(
            self._run_http_server(),
            self._run_dns_server(),
        )
    
    def start_background(self):
        self._running = True
        self._http_thread = threading.Thread(target=self._run_http_sync, daemon=True)
        self._dns_thread = threading.Thread(target=self._run_dns_sync, daemon=True)
        self._http_thread.start()
        self._dns_thread.start()
    
    def stop(self):
        self._running = False
        if self._http_server:
            self._http_server.close()
        if self._dns_server:
            self._dns_server.close()
    
    def check_interaction(self, token):
        with self._lock:
            return self.interactions.get(token, [])
    
    def has_interaction(self, token):
        with self._lock:
            return len(self.interactions.get(token, [])) > 0
    
    def clear_interactions(self, token=None):
        with self._lock:
            if token:
                self.interactions.pop(token, None)
            else:
                self.interactions.clear()
    
    def get_all_interactions(self):
        with self._lock:
            return dict(self.interactions)
    
    def _record_interaction(self, token, interaction_type, data):
        with self._lock:
            self.interactions[token].append({
                "type": interaction_type,
                "timestamp": time.time(),
                "data": data,
            })
    
    async def _run_http_server(self):
        try:
            server = await asyncio.start_server(
                self._handle_http_request,
                "0.0.0.0",
                self.http_port
            )
            self._http_server = server
            async with server:
                await server.serve_forever()
        except Exception:
            pass
    
    async def _handle_http_request(self, reader, writer):
        try:
            data = await reader.read(4096)
            request = data.decode("utf-8", errors="ignore")
            
            lines = request.split("\r\n")
            if lines:
                first_line = lines[0]
                parts = first_line.split()
                if len(parts) >= 2:
                    method = parts[0]
                    path = parts[1]
                    
                    token = path.strip("/").split("/")[0].split("?")[0]
                    
                    if token:
                        headers = {}
                        for line in lines[1:]:
                            if ": " in line:
                                key, value = line.split(": ", 1)
                                headers[key.lower()] = value
                        
                        client_addr = writer.get_extra_info("peername")
                        
                        self._record_interaction(token, "http", {
                            "method": method,
                            "path": path,
                            "headers": headers,
                            "client_ip": client_addr[0] if client_addr else None,
                            "raw": request[:500],
                        })
            
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 2\r\n"
                "Connection: close\r\n"
                "\r\n"
                "OK"
            )
            writer.write(response.encode())
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
    
    def _run_http_sync(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self._run_http_server())
    
    def _run_dns_sync(self):
        try:
            self._dns_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._dns_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._dns_server.bind(("0.0.0.0", self.dns_port))
            self._dns_server.settimeout(1)
            
            while self._running:
                try:
                    data, addr = self._dns_server.recvfrom(512)
                    self._handle_dns_query(data, addr)
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception:
            pass
        finally:
            if self._dns_server:
                self._dns_server.close()
    
    async def _run_dns_server(self):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._run_dns_sync)
    
    def _handle_dns_query(self, data, addr):
        try:
            transaction_id = data[:2]
            
            offset = 12
            labels = []
            while offset < len(data):
                length = data[offset]
                if length == 0:
                    break
                offset += 1
                labels.append(data[offset:offset + length].decode("utf-8", errors="ignore"))
                offset += length
            
            queried_name = ".".join(labels)
            
            if queried_name.endswith(f".{self.domain}"):
                token = queried_name.replace(f".{self.domain}", "").split(".")[0]
                
                self._record_interaction(token, "dns", {
                    "query": queried_name,
                    "client_ip": addr[0],
                })
            
            response = self._build_dns_response(transaction_id, data, "127.0.0.1")
            self._dns_server.sendto(response, addr)
        except Exception:
            pass
    
    def _build_dns_response(self, transaction_id, query, ip_addr):
        flags = struct.pack(">H", 0x8180)
        counts = struct.pack(">HHHH", 1, 1, 0, 0)
        
        question_end = 12
        while question_end < len(query) and query[question_end] != 0:
            question_end += query[question_end] + 1
        question_end += 5
        
        question = query[12:question_end]
        
        answer = struct.pack(">H", 0xc00c)
        answer += struct.pack(">HH", 1, 1)
        answer += struct.pack(">I", 60)
        answer += struct.pack(">H", 4)
        answer += socket.inet_aton(ip_addr)
        
        response = transaction_id + flags + counts
        response += question
        response += answer
        
        return response


class OOBClient:
    def __init__(self, server_host="localhost", http_port=8888, dns_port=5353, domain="oob.local"):
        self.server_host = server_host
        self.http_port = http_port
        self.dns_port = dns_port
        self.domain = domain
        self._tokens = {}
    
    def generate_payload(self, payload_type="http"):
        token = random_string(12)
        self._tokens[token] = {
            "type": payload_type,
            "created": time.time(),
            "triggered": False,
        }
        
        if payload_type == "http":
            return f"http://{self.server_host}:{self.http_port}/{token}", token
        elif payload_type == "dns":
            return f"{token}.{self.domain}", token
        elif payload_type == "both":
            return {
                "http": f"http://{self.server_host}:{self.http_port}/{token}",
                "dns": f"{token}.{self.domain}",
            }, token
        
        return None, token
    
    async def check_interaction(self, token, server_url=None):
        if server_url:
            import aiohttp
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"{server_url}/check/{token}") as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return data.get("interactions", [])
            except:
                pass
        return []
    
    def get_tokens(self):
        return dict(self._tokens)
    
    def clear_tokens(self):
        self._tokens.clear()


class OOBManager:
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, config=None):
        if self._initialized:
            return
        
        self.config = config or {}
        self.server = None
        self.client = None
        self._initialized = True
    
    def setup_server(self, http_port=8888, dns_port=5353, domain="oob.local"):
        self.server = OOBServer(http_port, dns_port, domain)
        return self.server
    
    def setup_client(self, server_host="localhost", http_port=8888, dns_port=5353, domain="oob.local"):
        self.client = OOBClient(server_host, http_port, dns_port, domain)
        return self.client
    
    def start_server_background(self):
        if self.server:
            self.server.start_background()
    
    def generate_http_payload(self):
        if self.client:
            return self.client.generate_payload("http")
        return None, None
    
    def generate_dns_payload(self):
        if self.client:
            return self.client.generate_payload("dns")
        return None, None
    
    def check(self, token):
        if self.server:
            return self.server.check_interaction(token)
        return []
    
    def has_triggered(self, token):
        if self.server:
            return self.server.has_interaction(token)
        return False
