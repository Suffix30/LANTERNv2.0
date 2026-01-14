import asyncio
import json
import time
from typing import Dict, Set, Optional
from dataclasses import dataclass, asdict


@dataclass
class Finding:
    id: str
    module: str
    severity: str
    description: str
    url: str
    target: str
    parameter: Optional[str]
    evidence: Optional[str]
    timestamp: float
    scanner_id: str


class CollabServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port
        self.clients: Set = set()
        self.findings: Dict[str, Finding] = {}
        self.finding_hashes: Set[str] = set()
        self.server = None
    
    def _hash_finding(self, finding: dict) -> str:
        key = f"{finding.get('url', '')}:{finding.get('description', '')}:{finding.get('parameter', '')}"
        return str(hash(key))
    
    async def start(self):
        self.server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        print(f"[Collab] Server started on ws://{self.host}:{self.port}")
        async with self.server:
            await self.server.serve_forever()
    
    async def _handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        print(f"[Collab] Client connected: {addr}")
        self.clients.add(writer)
        
        try:
            await self._send_existing_findings(writer)
            
            while True:
                data = await reader.readline()
                if not data:
                    break
                
                message = json.loads(data.decode())
                await self._process_message(message, writer)
        except Exception as e:
            print(f"[Collab] Client error: {e}")
        finally:
            self.clients.discard(writer)
            writer.close()
            await writer.wait_closed()
            print(f"[Collab] Client disconnected: {addr}")
    
    async def _send_existing_findings(self, writer):
        for finding in self.findings.values():
            message = {
                "type": "finding",
                "data": asdict(finding)
            }
            writer.write((json.dumps(message) + "\n").encode())
            await writer.drain()
    
    async def _process_message(self, message: dict, sender):
        msg_type = message.get("type")
        
        if msg_type == "finding":
            finding_data = message.get("data", {})
            finding_hash = self._hash_finding(finding_data)
            
            if finding_hash not in self.finding_hashes:
                self.finding_hashes.add(finding_hash)
                
                finding = Finding(
                    id=finding_hash,
                    module=finding_data.get("module", ""),
                    severity=finding_data.get("severity", ""),
                    description=finding_data.get("description", ""),
                    url=finding_data.get("url", ""),
                    target=finding_data.get("target", ""),
                    parameter=finding_data.get("parameter"),
                    evidence=finding_data.get("evidence"),
                    timestamp=time.time(),
                    scanner_id=finding_data.get("scanner_id", "unknown")
                )
                
                self.findings[finding_hash] = finding
                
                await self._broadcast(message, exclude=sender)
                
                ack = {"type": "ack", "finding_id": finding_hash, "status": "new"}
                sender.write((json.dumps(ack) + "\n").encode())
                await sender.drain()
            else:
                ack = {"type": "ack", "finding_id": finding_hash, "status": "duplicate"}
                sender.write((json.dumps(ack) + "\n").encode())
                await sender.drain()
        
        elif msg_type == "ping":
            pong = {"type": "pong", "timestamp": time.time()}
            sender.write((json.dumps(pong) + "\n").encode())
            await sender.drain()
        
        elif msg_type == "stats":
            stats = {
                "type": "stats",
                "total_findings": len(self.findings),
                "clients": len(self.clients),
                "by_severity": self._count_by_severity()
            }
            sender.write((json.dumps(stats) + "\n").encode())
            await sender.drain()
    
    async def _broadcast(self, message: dict, exclude=None):
        data = (json.dumps(message) + "\n").encode()
        for client in self.clients:
            if client != exclude:
                try:
                    client.write(data)
                    await client.drain()
                except:
                    pass
    
    def _count_by_severity(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in self.findings.values():
            if finding.severity in counts:
                counts[finding.severity] += 1
        return counts


class CollabClient:
    def __init__(self, server_url: str, scanner_id: str):
        self.server_url = server_url
        self.scanner_id = scanner_id
        self.reader = None
        self.writer = None
        self.connected = False
        self.received_findings: Set[str] = set()
    
    async def connect(self):
        try:
            host, port = self._parse_url(self.server_url)
            self.reader, self.writer = await asyncio.open_connection(host, port)
            self.connected = True
            print(f"[Collab] Connected to {self.server_url}")
            
            asyncio.create_task(self._receive_loop())
            return True
        except Exception as e:
            print(f"[Collab] Connection failed: {e}")
            return False
    
    def _parse_url(self, url: str):
        url = url.replace("ws://", "").replace("wss://", "")
        if ":" in url:
            host, port = url.split(":")
            return host, int(port)
        return url, 8080
    
    async def _receive_loop(self):
        try:
            while self.connected:
                data = await self.reader.readline()
                if not data:
                    break
                
                message = json.loads(data.decode())
                await self._handle_message(message)
        except Exception as e:
            print(f"[Collab] Receive error: {e}")
        finally:
            self.connected = False
    
    async def _handle_message(self, message: dict):
        msg_type = message.get("type")
        
        if msg_type == "finding":
            finding = message.get("data", {})
            finding_id = finding.get("id", "")
            
            if finding_id not in self.received_findings:
                self.received_findings.add(finding_id)
                severity = finding.get("severity", "INFO")
                desc = finding.get("description", "")[:50]
                scanner = finding.get("scanner_id", "unknown")
                print(f"[Collab] [{severity}] {desc}... (from {scanner})")
        
        elif msg_type == "ack":
            status = message.get("status")
            if status == "duplicate":
                pass
    
    async def send_finding(self, finding: dict):
        if not self.connected:
            return False
        
        finding["scanner_id"] = self.scanner_id
        message = {
            "type": "finding",
            "data": finding
        }
        
        try:
            self.writer.write((json.dumps(message) + "\n").encode())
            await self.writer.drain()
            return True
        except:
            return False
    
    async def get_stats(self):
        if not self.connected:
            return None
        
        message = {"type": "stats"}
        self.writer.write((json.dumps(message) + "\n").encode())
        await self.writer.drain()
    
    async def disconnect(self):
        self.connected = False
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()


async def run_collab_server(host="0.0.0.0", port=8080):
    server = CollabServer(host, port)
    await server.start()
