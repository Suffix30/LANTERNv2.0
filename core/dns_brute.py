import asyncio
import socket
import struct
import random
import time
from collections import defaultdict
from typing import List, Set, Dict, Optional, Tuple


class DNSPacket:
    QTYPE_A = 1
    QTYPE_AAAA = 28
    QTYPE_CNAME = 5
    QCLASS_IN = 1
    
    @staticmethod
    def build_query(domain: str, qtype: int = 1) -> Tuple[bytes, int]:
        transaction_id = random.randint(0, 65535)
        flags = 0x0100
        qdcount = 1
        ancount = 0
        nscount = 0
        arcount = 0
        
        header = struct.pack(">HHHHHH", transaction_id, flags, qdcount, ancount, nscount, arcount)
        
        question = b""
        for label in domain.split("."):
            question += bytes([len(label)]) + label.encode("ascii")
        question += b"\x00"
        question += struct.pack(">HH", qtype, DNSPacket.QCLASS_IN)
        
        return header + question, transaction_id
    
    @staticmethod
    def parse_response(data: bytes) -> Dict:
        if len(data) < 12:
            return {"valid": False}
        
        transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
        
        rcode = flags & 0x000F
        
        result = {
            "valid": True,
            "transaction_id": transaction_id,
            "rcode": rcode,
            "answers": [],
            "is_nxdomain": rcode == 3,
            "has_answer": ancount > 0,
        }
        
        offset = 12
        for _ in range(qdcount):
            while offset < len(data) and data[offset] != 0:
                if data[offset] >= 192:
                    offset += 2
                    break
                offset += data[offset] + 1
            else:
                offset += 1
            offset += 4
        
        for _ in range(ancount):
            if offset >= len(data):
                break
            
            while offset < len(data):
                if data[offset] >= 192:
                    offset += 2
                    break
                if data[offset] == 0:
                    offset += 1
                    break
                offset += data[offset] + 1
            
            if offset + 10 > len(data):
                break
            
            rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
            offset += 10
            
            if offset + rdlength > len(data):
                break
            
            rdata = data[offset:offset+rdlength]
            offset += rdlength
            
            if rtype == DNSPacket.QTYPE_A and rdlength == 4:
                ip = ".".join(str(b) for b in rdata)
                result["answers"].append({"type": "A", "ip": ip, "ttl": ttl})
            elif rtype == DNSPacket.QTYPE_AAAA and rdlength == 16:
                ip = ":".join(f"{rdata[i]:02x}{rdata[i+1]:02x}" for i in range(0, 16, 2))
                result["answers"].append({"type": "AAAA", "ip": ip, "ttl": ttl})
            elif rtype == DNSPacket.QTYPE_CNAME:
                result["answers"].append({"type": "CNAME", "ttl": ttl})
        
        return result


class ResolverPool:
    DEFAULT_RESOLVERS = [
        "8.8.8.8", "8.8.4.4",
        "1.1.1.1", "1.0.0.1",
        "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220",
        "64.6.64.6", "64.6.65.6",
        "77.88.8.8", "77.88.8.1",
        "94.140.14.14", "94.140.15.15",
    ]
    
    def __init__(self, resolvers: List[str] = None, max_per_resolver: int = 50):
        self.resolvers = resolvers or self.DEFAULT_RESOLVERS.copy()
        self.max_per_resolver = max_per_resolver
        self._counts = defaultdict(int)
        self._failures = defaultdict(int)
        self._lock = asyncio.Lock()
        self._last_reset = time.monotonic()
    
    async def get_resolver(self) -> str:
        async with self._lock:
            now = time.monotonic()
            if now - self._last_reset > 1.0:
                self._counts.clear()
                self._last_reset = now
            
            available = [r for r in self.resolvers if self._counts[r] < self.max_per_resolver and self._failures[r] < 10]
            
            if not available:
                self._counts.clear()
                available = self.resolvers.copy()
            
            resolver = random.choice(available)
            self._counts[resolver] += 1
            return resolver
    
    async def report_failure(self, resolver: str):
        async with self._lock:
            self._failures[resolver] += 1
    
    async def report_success(self, resolver: str):
        async with self._lock:
            self._failures[resolver] = max(0, self._failures[resolver] - 1)


class AsyncDNSResolver:
    def __init__(self, timeout: float = 2.0, retries: int = 2):
        self.timeout = timeout
        self.retries = retries
        self.pool = ResolverPool()
        self._transport = None
        self._protocol = None
        self._pending = {}
        self._lock = asyncio.Lock()
    
    async def _ensure_socket(self):
        if self._transport is None:
            loop = asyncio.get_event_loop()
            self._transport, self._protocol = await loop.create_datagram_endpoint(
                lambda: DNSProtocol(self._pending),
                family=socket.AF_INET,
            )
    
    async def resolve(self, domain: str, qtype: int = 1) -> Optional[Dict]:
        await self._ensure_socket()
        
        for attempt in range(self.retries + 1):
            resolver = await self.pool.get_resolver()
            query, txid = DNSPacket.build_query(domain, qtype)
            
            future = asyncio.Future()
            async with self._lock:
                self._pending[txid] = future
            
            try:
                self._transport.sendto(query, (resolver, 53))
                result = await asyncio.wait_for(future, timeout=self.timeout)
                await self.pool.report_success(resolver)
                return result
            except asyncio.TimeoutError:
                await self.pool.report_failure(resolver)
            except Exception:
                await self.pool.report_failure(resolver)
            finally:
                async with self._lock:
                    self._pending.pop(txid, None)
        
        return None
    
    async def close(self):
        if self._transport:
            self._transport.close()
            self._transport = None


class DNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, pending: Dict):
        self._pending = pending
    
    def datagram_received(self, data: bytes, addr):
        if len(data) >= 2:
            txid = struct.unpack(">H", data[:2])[0]
            future = self._pending.get(txid)
            if future and not future.done():
                result = DNSPacket.parse_response(data)
                future.set_result(result)
    
    def error_received(self, exc):
        pass


class WildcardDetector:
    def __init__(self, resolver: AsyncDNSResolver):
        self.resolver = resolver
        self._cache = {}
    
    async def detect(self, domain: str) -> Optional[Set[str]]:
        if domain in self._cache:
            return self._cache[domain]
        
        wildcard_ips = set()
        
        random_subs = [
            f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=12))}.{domain}"
            for _ in range(3)
        ]
        
        for sub in random_subs:
            result = await self.resolver.resolve(sub)
            if result and result.get("has_answer"):
                for answer in result.get("answers", []):
                    if answer.get("type") == "A":
                        wildcard_ips.add(answer["ip"])
        
        if len(wildcard_ips) >= 2:
            self._cache[domain] = wildcard_ips
            return wildcard_ips
        
        self._cache[domain] = None
        return None


class DNSBruteForcer:
    def __init__(
        self,
        concurrency: int = 500,
        timeout: float = 2.0,
        retries: int = 2,
        resolvers: List[str] = None,
    ):
        self.concurrency = concurrency
        self.resolver = AsyncDNSResolver(timeout=timeout, retries=retries)
        if resolvers:
            self.resolver.pool.resolvers = resolvers
        self.wildcard_detector = WildcardDetector(self.resolver)
        self._found = set()
        self._lock = asyncio.Lock()
        self._stats = {
            "total": 0,
            "resolved": 0,
            "wildcard_filtered": 0,
            "errors": 0,
            "start_time": 0,
        }
    
    async def brute(
        self,
        domain: str,
        wordlist: List[str],
        callback=None,
    ) -> Set[str]:
        self._found.clear()
        self._stats = {
            "total": len(wordlist),
            "resolved": 0,
            "wildcard_filtered": 0,
            "errors": 0,
            "start_time": time.monotonic(),
        }
        
        wildcard_ips = await self.wildcard_detector.detect(domain)
        
        semaphore = asyncio.Semaphore(self.concurrency)
        
        async def check_subdomain(word: str):
            async with semaphore:
                subdomain = f"{word}.{domain}"
                
                result = await self.resolver.resolve(subdomain)
                
                if result and result.get("has_answer"):
                    ips = {a["ip"] for a in result.get("answers", []) if a.get("type") == "A"}
                    
                    if wildcard_ips and ips.issubset(wildcard_ips):
                        async with self._lock:
                            self._stats["wildcard_filtered"] += 1
                        return
                    
                    async with self._lock:
                        self._found.add(subdomain)
                        self._stats["resolved"] += 1
                    
                    if callback:
                        await callback(subdomain, list(ips))
                elif result is None:
                    async with self._lock:
                        self._stats["errors"] += 1
        
        tasks = [check_subdomain(word) for word in wordlist]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        await self.resolver.close()
        
        return self._found
    
    def get_stats(self) -> Dict:
        elapsed = time.monotonic() - self._stats["start_time"]
        checked = self._stats["resolved"] + self._stats["wildcard_filtered"] + self._stats["errors"]
        return {
            "total_words": self._stats["total"],
            "checked": checked,
            "found": len(self._found),
            "wildcard_filtered": self._stats["wildcard_filtered"],
            "errors": self._stats["errors"],
            "elapsed_seconds": elapsed,
            "rate_per_second": checked / max(elapsed, 0.001),
        }


class SubdomainWordlist:
    BUILTIN = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2", "ns3", "ns4",
        "admin", "administrator", "api", "dev", "development", "staging", "stage", "prod",
        "test", "testing", "qa", "beta", "alpha", "demo", "preview", "sandbox", "uat",
        "app", "apps", "application", "mobile", "m", "web", "www1", "www2", "www3",
        "secure", "ssl", "vpn", "remote", "gateway", "portal", "login", "auth", "oauth",
        "sso", "id", "identity", "account", "accounts", "my", "user", "users", "profile",
        "customer", "customers", "client", "clients", "partner", "partners", "vendor",
        "blog", "news", "media", "press", "ir", "investor", "investors", "about",
        "shop", "store", "ecommerce", "cart", "checkout", "pay", "payment", "billing",
        "support", "help", "helpdesk", "ticket", "tickets", "service", "services", "desk",
        "docs", "doc", "documentation", "wiki", "kb", "knowledge", "faq", "guide",
        "cdn", "static", "assets", "img", "images", "image", "css", "js", "media",
        "files", "file", "download", "downloads", "upload", "uploads", "content",
        "db", "database", "mysql", "postgres", "mongo", "redis", "elastic", "sql",
        "jenkins", "gitlab", "github", "bitbucket", "jira", "confluence", "bamboo",
        "grafana", "kibana", "prometheus", "monitoring", "metrics", "status", "health",
        "ci", "cd", "build", "deploy", "release", "production", "integration",
        "internal", "intranet", "extranet", "corp", "corporate", "office", "hq",
        "hr", "crm", "erp", "sales", "marketing", "finance", "legal", "ops",
        "backup", "bak", "old", "new", "temp", "tmp", "archive", "legacy",
        "v1", "v2", "v3", "api-v1", "api-v2", "rest", "graphql", "grpc",
        "aws", "azure", "gcp", "cloud", "s3", "storage", "bucket", "blob",
        "proxy", "cache", "edge", "lb", "loadbalancer", "haproxy", "nginx",
        "git", "svn", "repo", "repository", "code", "source", "src",
        "forum", "community", "social", "chat", "slack", "teams", "discord",
        "mail1", "mail2", "mx", "mx1", "mx2", "email", "smtp1", "smtp2",
        "ns", "dns", "dns1", "dns2", "resolver", "nameserver",
        "dev1", "dev2", "test1", "test2", "stage1", "stage2",
        "web1", "web2", "web3", "app1", "app2", "server1", "server2",
        "api1", "api2", "api-dev", "api-test", "api-prod", "api-staging",
        "panel", "cpanel", "whm", "plesk", "webmin", "manager", "manage",
        "console", "dashboard", "control", "controlpanel", "backend",
        "search", "elastic", "elasticsearch", "solr", "sphinx",
        "log", "logs", "logging", "syslog", "audit", "trace",
        "queue", "mq", "rabbitmq", "kafka", "activemq", "sqs",
        "docker", "k8s", "kubernetes", "container", "registry",
        "secret", "secrets", "vault", "key", "keys", "token",
        "webhook", "hooks", "callback", "notify", "notification",
        "ws", "websocket", "socket", "stream", "streaming",
        "video", "audio", "rtmp", "hls", "live", "broadcast",
        "owa", "outlook", "exchange", "autodiscover", "activesync",
        "sharepoint", "onedrive", "o365", "office365", "microsoft",
        "ldap", "ad", "directory", "dc", "domain", "kerberos",
        "vpn1", "vpn2", "ipsec", "openvpn", "wireguard",
        "fw", "firewall", "waf", "ids", "ips", "security",
        "analytics", "track", "tracking", "pixel", "beacon",
        "report", "reports", "reporting", "bi", "tableau",
        "survey", "feedback", "review", "reviews", "ratings",
        "data", "dataset", "datalake", "warehouse", "etl",
        "scheduler", "cron", "job", "jobs", "worker", "workers",
        "ai", "ml", "machine", "learning", "model", "inference",
        "sandbox1", "sandbox2", "poc", "prototype", "experiment",
    ]
    
    @classmethod
    def load_from_file(cls, filepath: str) -> List[str]:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
        except:
            return cls.BUILTIN
    
    @classmethod
    def generate_mutations(cls, base_words: List[str], depth: int = 1) -> List[str]:
        mutations = set(base_words)
        
        prefixes = ["dev", "test", "staging", "prod", "old", "new", "v2", "api"]
        suffixes = ["01", "02", "1", "2", "dev", "test", "prod", "int", "ext"]
        
        for word in base_words[:100]:
            for prefix in prefixes:
                mutations.add(f"{prefix}-{word}")
                mutations.add(f"{prefix}{word}")
            for suffix in suffixes:
                mutations.add(f"{word}-{suffix}")
                mutations.add(f"{word}{suffix}")
        
        if depth > 1:
            for w1 in base_words[:50]:
                for w2 in base_words[:50]:
                    if w1 != w2:
                        mutations.add(f"{w1}-{w2}")
        
        return list(mutations)


async def brute_subdomains(
    domain: str,
    wordlist: List[str] = None,
    concurrency: int = 500,
    callback=None,
) -> Set[str]:
    if wordlist is None:
        wordlist = SubdomainWordlist.BUILTIN
    
    bruter = DNSBruteForcer(concurrency=concurrency)
    return await bruter.brute(domain, wordlist, callback=callback)
