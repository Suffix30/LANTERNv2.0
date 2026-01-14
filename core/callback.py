import asyncio
import socket
import struct
import threading
import time
import random
import string
from collections import defaultdict

class CallbackServer:
    def __init__(self, config):
        self.config = config
        self.http_port = config.get("callback_http_port", 8888)
        self.dns_port = config.get("callback_dns_port", 5353)
        self.interactions = defaultdict(list)
        self.tokens = {}
        self.running = False
        self.http_server = None
        self.dns_server = None
        
    def generate_token(self, vuln_type, target, param=None):
        token = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        self.tokens[token] = {
            "type": vuln_type,
            "target": target,
            "param": param,
            "created": time.time(),
        }
        return token
    
    def get_callback_url(self, token):
        host = self.config.get("callback_host", "127.0.0.1")
        return f"http://{host}:{self.http_port}/{token}"
    
    def get_callback_domain(self, token):
        host = self.config.get("callback_host", "127.0.0.1")
        return f"{token}.{host}"
    
    def get_interactions(self, token):
        return self.interactions.get(token, [])
    
    def has_interaction(self, token):
        return token in self.interactions and len(self.interactions[token]) > 0
    
    async def start(self):
        self.running = True
        
        self.http_thread = threading.Thread(target=self._run_http_server, daemon=True)
        self.http_thread.start()
        
        self.dns_thread = threading.Thread(target=self._run_dns_server, daemon=True)
        self.dns_thread.start()
        
        await asyncio.sleep(0.5)
    
    async def stop(self):
        self.running = False
        if self.http_server:
            self.http_server.close()
        if self.dns_server:
            self.dns_server.close()
    
    def _run_http_server(self):
        from http.server import HTTPServer, BaseHTTPRequestHandler
        
        parent = self
        
        class CallbackHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass
            
            def do_GET(self):
                token = self.path.strip("/").split("/")[0].split("?")[0]
                if token in parent.tokens:
                    parent.interactions[token].append({
                        "protocol": "HTTP",
                        "method": "GET",
                        "path": self.path,
                        "headers": dict(self.headers),
                        "client": self.client_address[0],
                        "time": time.time(),
                    })
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
            
            def do_POST(self):
                token = self.path.strip("/").split("/")[0].split("?")[0]
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length) if content_length > 0 else b""
                
                if token in parent.tokens:
                    parent.interactions[token].append({
                        "protocol": "HTTP",
                        "method": "POST",
                        "path": self.path,
                        "headers": dict(self.headers),
                        "body": body.decode("utf-8", errors="ignore")[:1000],
                        "client": self.client_address[0],
                        "time": time.time(),
                    })
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
        
        try:
            self.http_server = HTTPServer(("0.0.0.0", self.http_port), CallbackHandler)
            while self.running:
                self.http_server.handle_request()
        except:
            pass
    
    def _run_dns_server(self):
        try:
            self.dns_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.dns_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.dns_server.bind(("0.0.0.0", self.dns_port))
            self.dns_server.settimeout(1)
            
            while self.running:
                try:
                    data, addr = self.dns_server.recvfrom(512)
                    domain = self._parse_dns_query(data)
                    
                    if domain:
                        parts = domain.lower().split(".")
                        for part in parts:
                            if part in self.tokens:
                                self.interactions[part].append({
                                    "protocol": "DNS",
                                    "domain": domain,
                                    "client": addr[0],
                                    "time": time.time(),
                                })
                                break
                        
                        response = self._build_dns_response(data)
                        self.dns_server.sendto(response, addr)
                except socket.timeout:
                    continue
                except:
                    pass
        except:
            pass
    
    def _parse_dns_query(self, data):
        try:
            pos = 12
            domain_parts = []
            
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    break
                pos += 1
                domain_parts.append(data[pos:pos+length].decode())
                pos += length
            
            return ".".join(domain_parts)
        except:
            return None
    
    def _build_dns_response(self, query):
        try:
            response = bytearray(query)
            response[2] = 0x81
            response[3] = 0x80
            response[6] = 0x00
            response[7] = 0x01
            
            response += struct.pack(">H", 0xc00c)
            response += struct.pack(">H", 1)
            response += struct.pack(">H", 1)
            response += struct.pack(">I", 60)
            response += struct.pack(">H", 4)
            response += struct.pack("BBBB", 127, 0, 0, 1)
            
            return bytes(response)
        except:
            return query
    
    def _parse_dns_header(self, data):
        if len(data) < 12:
            return None
        txn_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
        return {
            "txn_id": txn_id,
            "flags": flags,
            "questions": qdcount,
            "answers": ancount,
            "authority": nscount,
            "additional": arcount
        }


class InteractionChecker:
    def __init__(self, callback_server):
        self.server = callback_server
        self.pending_checks = {}
    
    def register_check(self, token, callback):
        self.pending_checks[token] = callback
    
    async def wait_for_interactions(self, timeout=10):
        await asyncio.sleep(timeout)
        
        results = []
        for token, callback in self.pending_checks.items():
            if self.server.has_interaction(token):
                token_info = self.server.tokens.get(token, {})
                interactions = self.server.get_interactions(token)
                results.append({
                    "token": token,
                    "info": token_info,
                    "interactions": interactions,
                })
        
        return results
