import random
import string
import re
import hashlib
import aiofiles
import struct
import uuid
import time
from urllib.parse import urlparse, parse_qs
from pathlib import Path


class BloomFilter:
    FNV_PRIME_32 = 0x01000193
    FNV_OFFSET_32 = 0x811c9dc5
    FNV_PRIME_64 = 0x00000100000001B3
    FNV_OFFSET_64 = 0xcbf29ce484222325
    
    def __init__(self, capacity=1000000, error_rate=0.001):
        self.capacity = capacity
        self.error_rate = error_rate
        import math
        self.size = int(-capacity * math.log(error_rate) / (math.log(2) ** 2))
        self.num_hashes = int((self.size / capacity) * math.log(2))
        self.num_hashes = max(2, min(self.num_hashes, 10))
        self.bit_array = bytearray((self.size + 7) // 8)
        self.count = 0
    
    def _fnv1a_32(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        h = self.FNV_OFFSET_32
        for byte in data:
            h ^= byte
            h = (h * self.FNV_PRIME_32) & 0xFFFFFFFF
        return h
    
    def _fnv1a_64(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        h = self.FNV_OFFSET_64
        for byte in data:
            h ^= byte
            h = (h * self.FNV_PRIME_64) & 0xFFFFFFFFFFFFFFFF
        return h
    
    def _city_hash_32(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        length = len(data)
        if length <= 4:
            h = length * 0xcc9e2d51
            for i, b in enumerate(data):
                h ^= b << (i * 8)
            h = ((h >> 16) ^ h) * 0x85ebca6b
            h = ((h >> 13) ^ h) * 0xc2b2ae35
            return ((h >> 16) ^ h) & 0xFFFFFFFF
        
        h = length ^ 0xdeadbeef
        for i in range(0, length - 3, 4):
            k = struct.unpack('<I', data[i:i+4])[0] if i + 4 <= length else 0
            k = (k * 0xcc9e2d51) & 0xFFFFFFFF
            k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
            k = (k * 0x1b873593) & 0xFFFFFFFF
            h ^= k
            h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
            h = (h * 5 + 0xe6546b64) & 0xFFFFFFFF
        
        remaining = data[-(length % 4):] if length % 4 else b''
        k = 0
        for i, b in enumerate(remaining):
            k |= b << (i * 8)
        k = (k * 0xcc9e2d51) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * 0x1b873593) & 0xFFFFFFFF
        h ^= k
        
        h ^= length
        h = ((h >> 16) ^ h) * 0x85ebca6b & 0xFFFFFFFF
        h = ((h >> 13) ^ h) * 0xc2b2ae35 & 0xFFFFFFFF
        return ((h >> 16) ^ h) & 0xFFFFFFFF
    
    def _get_hash_values(self, item):
        if isinstance(item, str):
            item = item.encode('utf-8')
        h1 = self._fnv1a_64(item)
        h2 = self._city_hash_32(item)
        h3 = self._fnv1a_32(item)
        hashes = []
        for i in range(self.num_hashes):
            combined = (h1 + i * h2 + (i * i) * h3) % self.size
            hashes.append(combined)
        return hashes
    
    def _set_bit(self, position):
        byte_idx = position // 8
        bit_idx = position % 8
        self.bit_array[byte_idx] |= (1 << bit_idx)
    
    def _get_bit(self, position):
        byte_idx = position // 8
        bit_idx = position % 8
        return (self.bit_array[byte_idx] >> bit_idx) & 1
    
    def add(self, item):
        for pos in self._get_hash_values(item):
            self._set_bit(pos)
        self.count += 1
    
    def check(self, item):
        for pos in self._get_hash_values(item):
            if not self._get_bit(pos):
                return False
        return True
    
    def __contains__(self, item):
        return self.check(item)
    
    def __len__(self):
        return self.count
    
    def clear(self):
        self.bit_array = bytearray((self.size + 7) // 8)
        self.count = 0
    
    def stats(self):
        set_bits = sum(bin(byte).count('1') for byte in self.bit_array)
        fill_ratio = set_bits / self.size
        import math
        actual_fpr = (1 - math.exp(-self.num_hashes * self.count / self.size)) ** self.num_hashes
        return {
            "capacity": self.capacity,
            "count": self.count,
            "size_bits": self.size,
            "size_bytes": len(self.bit_array),
            "num_hashes": self.num_hashes,
            "fill_ratio": fill_ratio,
            "estimated_fpr": actual_fpr,
            "target_fpr": self.error_rate,
        }


class Finding:
    SEVERITY_LEVELS = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    
    def __init__(self, module, severity, description, url=None, parameter=None, 
                 evidence=None, parent=None, tags=None, scope_distance=0):
        self.id = str(uuid.uuid4())
        self.module = module
        self.severity = severity
        self.description = description
        self.url = url
        self.parameter = parameter
        self.evidence = evidence
        self.timestamp = time.time()
        self.parent = parent
        self.parent_id = parent.id if parent else None
        self.tags = set(tags) if tags else set()
        self.scope_distance = scope_distance
        self.children = []
        self._hash = None
        
        if parent:
            parent.add_child(self)
            self.scope_distance = parent.scope_distance + 1
    
    @property
    def hash(self):
        if self._hash is None:
            data = f"{self.module}:{self.url}:{self.parameter}:{self.description}"
            self._hash = hashlib.blake2b(data.encode(), digest_size=16).hexdigest()
        return self._hash
    
    def add_child(self, child):
        self.children.append(child)
    
    def add_tag(self, tag):
        self.tags.add(tag)
    
    def remove_tag(self, tag):
        self.tags.discard(tag)
    
    def has_tag(self, tag):
        return tag in self.tags
    
    def get_chain(self):
        chain = [self]
        current = self.parent
        while current:
            chain.insert(0, current)
            current = current.parent
        return chain
    
    def get_chain_description(self):
        chain = self.get_chain()
        return " → ".join(f.description[:30] for f in chain)
    
    def to_dict(self):
        return {
            "id": self.id,
            "hash": self.hash,
            "module": self.module,
            "severity": self.severity,
            "description": self.description,
            "url": self.url,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "parent_id": self.parent_id,
            "tags": list(self.tags),
            "scope_distance": self.scope_distance,
            "chain": self.get_chain_description() if self.parent else None,
        }
    
    @classmethod
    def from_dict(cls, data, parent=None):
        finding = cls(
            module=data.get("module"),
            severity=data.get("severity"),
            description=data.get("description"),
            url=data.get("url"),
            parameter=data.get("parameter"),
            evidence=data.get("evidence"),
            parent=parent,
            tags=data.get("tags"),
            scope_distance=data.get("scope_distance", 0),
        )
        finding.id = data.get("id", finding.id)
        finding.timestamp = data.get("timestamp", finding.timestamp)
        return finding
    
    def __eq__(self, other):
        if isinstance(other, Finding):
            return self.hash == other.hash
        return False
    
    def __hash__(self):
        return hash(self.hash)
    
    def __repr__(self):
        return f"<Finding {self.severity} {self.module}: {self.description[:40]}>"
    
    def __lt__(self, other):
        if isinstance(other, Finding):
            return self.SEVERITY_LEVELS.get(self.severity, 5) < self.SEVERITY_LEVELS.get(other.severity, 5)
        return NotImplemented


class FindingStore:
    def __init__(self):
        self.findings = {}
        self.by_module = {}
        self.by_severity = {}
        self.by_url = {}
        self.roots = []
    
    def add(self, finding):
        if finding.hash in self.findings:
            return False
        
        self.findings[finding.hash] = finding
        
        self.by_module.setdefault(finding.module, []).append(finding)
        self.by_severity.setdefault(finding.severity, []).append(finding)
        
        if finding.url:
            self.by_url.setdefault(finding.url, []).append(finding)
        
        if not finding.parent:
            self.roots.append(finding)
        
        return True
    
    def get(self, hash_id):
        return self.findings.get(hash_id)
    
    def get_by_module(self, module):
        return self.by_module.get(module, [])
    
    def get_by_severity(self, severity):
        return self.by_severity.get(severity, [])
    
    def get_by_url(self, url):
        return self.by_url.get(url, [])
    
    def get_chains(self):
        chains = []
        for root in self.roots:
            if root.children:
                chains.append(root.get_chain())
        return chains
    
    def get_all(self, sort_by_severity=True):
        findings = list(self.findings.values())
        if sort_by_severity:
            findings.sort()
        return findings
    
    def count(self):
        return len(self.findings)
    
    def stats(self):
        return {
            "total": len(self.findings),
            "by_severity": {s: len(f) for s, f in self.by_severity.items()},
            "by_module": {m: len(f) for m, f in self.by_module.items()},
            "chains": len([r for r in self.roots if r.children]),
        }


class TokenBucketLimiter:
    def __init__(self, rate=100, burst=None, name="default"):
        self.rate = rate
        self.burst = burst if burst else rate * 2
        self.name = name
        self.tokens = float(self.burst)
        self.last_update = time.monotonic()
        self._lock = None
        self.total_requests = 0
        self.total_waits = 0
        self.total_wait_time = 0.0
        self._backoff_factor = 1.0
        self._success_streak = 0
    
    @property
    def lock(self):
        import asyncio
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock
    
    def _refill(self):
        now = time.monotonic()
        elapsed = now - self.last_update
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last_update = now
    
    async def acquire(self, tokens=1):
        import asyncio
        async with self.lock:
            self._refill()
            self.total_requests += 1
            
            adjusted_tokens = tokens * self._backoff_factor
            
            if self.tokens >= adjusted_tokens:
                self.tokens -= adjusted_tokens
                return 0.0
            
            wait_time = (adjusted_tokens - self.tokens) / self.rate
            self.total_waits += 1
            self.total_wait_time += wait_time
            
            await asyncio.sleep(wait_time)
            self._refill()
            self.tokens -= adjusted_tokens
            return wait_time
    
    def record_response(self, status_code):
        if status_code == 429:
            self._backoff_factor = min(self._backoff_factor * 1.5, 10.0)
            self._success_streak = 0
        elif 200 <= status_code < 400:
            self._success_streak += 1
            if self._success_streak >= 10:
                self._backoff_factor = max(self._backoff_factor * 0.9, 1.0)
                self._success_streak = 0
    
    async def __aenter__(self):
        await self.acquire()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
    
    def stats(self):
        return {
            "name": self.name,
            "rate": self.rate,
            "burst": self.burst,
            "current_tokens": self.tokens,
            "backoff_factor": self._backoff_factor,
            "total_requests": self.total_requests,
            "total_waits": self.total_waits,
            "total_wait_time": self.total_wait_time,
            "avg_wait_time": self.total_wait_time / max(self.total_waits, 1),
        }


class ScanMetrics:
    def __init__(self, window_size=60):
        self.window_size = window_size
        self.buffer_size = window_size * 10
        self._buffer = [0.0] * self.buffer_size
        self._index = 0
        self._count = 0
        self.start_time = time.monotonic()
        self.total_requests = 0
        self.total_findings = 0
        self.by_module = {}
        self.by_severity = {}
        self.errors = 0
    
    def record_request(self):
        now = time.monotonic()
        self._buffer[self._index] = now
        self._index = (self._index + 1) % self.buffer_size
        self._count = min(self._count + 1, self.buffer_size)
        self.total_requests += 1
    
    def record_finding(self, module, severity):
        self.total_findings += 1
        self.by_module[module] = self.by_module.get(module, 0) + 1
        self.by_severity[severity] = self.by_severity.get(severity, 0) + 1
    
    def record_error(self):
        self.errors += 1
    
    def get_rps(self):
        if self._count == 0:
            return 0.0
        now = time.monotonic()
        cutoff = now - self.window_size
        count = 0
        for i in range(self._count):
            idx = (self._index - 1 - i) % self.buffer_size
            if self._buffer[idx] >= cutoff:
                count += 1
            else:
                break
        return count / self.window_size
    
    def get_elapsed(self):
        return time.monotonic() - self.start_time
    
    def stats(self):
        elapsed = self.get_elapsed()
        return {
            "elapsed_seconds": elapsed,
            "elapsed_formatted": self._format_time(elapsed),
            "total_requests": self.total_requests,
            "total_findings": self.total_findings,
            "requests_per_second": self.get_rps(),
            "avg_rps": self.total_requests / max(elapsed, 1),
            "errors": self.errors,
            "by_module": self.by_module.copy(),
            "by_severity": self.by_severity.copy(),
        }
    
    def _format_time(self, seconds):
        m, s = divmod(int(seconds), 60)
        h, m = divmod(m, 60)
        if h:
            return f"{h}h {m}m {s}s"
        elif m:
            return f"{m}m {s}s"
        return f"{s}s"


class ResponseBaseline:
    DYNAMIC_HEADER_PATTERNS = [
        r'^date$', r'^last-modified$', r'^expires$', r'^age$',
        r'^x-request-id$', r'^x-correlation-id$', r'^x-trace-id$',
        r'^etag$', r'^x-runtime$', r'^x-response-time$',
        r'^set-cookie$', r'^x-xss-protection$', r'^cf-ray$',
        r'^x-amz-', r'^x-cache', r'^via$', r'^server-timing$',
    ]
    
    DYNAMIC_CONTENT_PATTERNS = [
        (r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', 'TIMESTAMP'),
        (r'\b\d{10,13}\b', 'UNIX_TIMESTAMP'),
        (r'[a-f0-9]{32}', 'MD5_HASH'),
        (r'[a-f0-9]{40}', 'SHA1_HASH'),
        (r'[a-f0-9]{64}', 'SHA256_HASH'),
        (r'[A-Za-z0-9_-]{20,}\.{0,1}[A-Za-z0-9_-]*\.{0,1}[A-Za-z0-9_-]*', 'JWT_TOKEN'),
        (r'csrf[_-]?token["\s:=]+["\']?([a-zA-Z0-9_-]+)', 'CSRF_TOKEN'),
        (r'nonce["\s:=]+["\']?([a-zA-Z0-9_-]+)', 'NONCE'),
        (r'session[_-]?id["\s:=]+["\']?([a-zA-Z0-9_-]+)', 'SESSION_ID'),
        (r'__[a-z]+["\s:=]+["\']?([a-zA-Z0-9_-]+)', 'HIDDEN_FIELD'),
    ]
    
    def __init__(self, http_client):
        self.http = http_client
        self.baselines = {}
        self._dynamic_patterns = []
        self._ignore_headers = set()
    
    async def establish(self, url, method="GET", data=None, json_data=None):
        cache_buster1 = f"_cb={random_string(6)}"
        cache_buster2 = f"_cb={random_string(6)}"
        
        sep = "&" if "?" in url else "?"
        url1 = f"{url}{sep}{cache_buster1}"
        url2 = f"{url}{sep}{cache_buster2}"
        
        if method == "GET":
            resp1 = await self.http.get(url1)
            resp2 = await self.http.get(url2)
        else:
            resp1 = await self.http.post(url1, data=data, json=json_data)
            resp2 = await self.http.post(url2, data=data, json=json_data)
        
        if resp1.get("status") != resp2.get("status"):
            return None
        
        dynamic_headers = self._find_dynamic_headers(resp1.get("headers", {}), resp2.get("headers", {}))
        self._ignore_headers.update(dynamic_headers)
        
        dynamic_content = self._find_dynamic_content(resp1.get("text", ""), resp2.get("text", ""))
        self._dynamic_patterns.extend(dynamic_content)
        
        self.baselines[url] = {
            "status": resp1.get("status"),
            "length": len(resp1.get("text", "")),
            "headers": {k: v for k, v in resp1.get("headers", {}).items() if k.lower() not in self._ignore_headers},
            "content": self._normalize_content(resp1.get("text", "")),
            "word_count": len(resp1.get("text", "").split()),
            "line_count": resp1.get("text", "").count("\n"),
            "structure_hash": self._structure_hash(resp1.get("text", "")),
        }
        
        return self.baselines[url]
    
    def _find_dynamic_headers(self, headers1, headers2):
        dynamic = set()
        
        for pattern in self.DYNAMIC_HEADER_PATTERNS:
            for header in headers1.keys():
                if re.match(pattern, header.lower()):
                    dynamic.add(header.lower())
        
        for key in set(headers1.keys()) | set(headers2.keys()):
            if headers1.get(key) != headers2.get(key):
                dynamic.add(key.lower())
        
        return dynamic
    
    def _find_dynamic_content(self, content1, content2):
        dynamic = []
        
        for pattern, name in self.DYNAMIC_CONTENT_PATTERNS:
            matches1 = set(re.findall(pattern, content1, re.IGNORECASE))
            matches2 = set(re.findall(pattern, content2, re.IGNORECASE))
            
            if matches1 != matches2:
                dynamic.append((pattern, name))
        
        return dynamic
    
    def _normalize_content(self, content):
        normalized = content
        
        for pattern, name in self._dynamic_patterns + self.DYNAMIC_CONTENT_PATTERNS:
            normalized = re.sub(pattern, f'[{name}]', normalized, flags=re.IGNORECASE)
        
        return normalized
    
    def _structure_hash(self, content):
        tag_pattern = r'<(\w+)[^>]*>'
        tags = re.findall(tag_pattern, content[:5000])
        structure = ":".join(tags[:50])
        return hashlib.blake2b(structure.encode(), digest_size=8).hexdigest()
    
    async def compare(self, url, response=None, method="GET", data=None, json_data=None):
        if url not in self.baselines:
            await self.establish(url, method, data, json_data)
        
        baseline = self.baselines.get(url)
        if not baseline:
            return {"match": True, "reasons": [], "confidence": 0}
        
        if response is None:
            if method == "GET":
                response = await self.http.get(url)
            else:
                response = await self.http.post(url, data=data, json=json_data)
        
        differences = []
        
        if response.get("status") != baseline["status"]:
            differences.append(("status", baseline["status"], response.get("status")))
        
        current_len = len(response.get("text", ""))
        len_diff = abs(current_len - baseline["length"])
        len_ratio = len_diff / max(baseline["length"], 1)
        
        if len_ratio > 0.1:
            differences.append(("length", baseline["length"], current_len, f"{len_ratio:.1%}"))
        
        current_words = len(response.get("text", "").split())
        word_ratio = abs(current_words - baseline["word_count"]) / max(baseline["word_count"], 1)
        
        if word_ratio > 0.15:
            differences.append(("words", baseline["word_count"], current_words))
        
        current_struct = self._structure_hash(response.get("text", ""))
        if current_struct != baseline["structure_hash"]:
            differences.append(("structure", baseline["structure_hash"], current_struct))
        
        for header, value in response.get("headers", {}).items():
            if header.lower() in self._ignore_headers:
                continue
            if header in baseline["headers"] and baseline["headers"][header] != value:
                differences.append(("header", header, baseline["headers"].get(header), value))
        
        is_different = len(differences) > 0
        confidence = min(len(differences) / 3, 1.0) if is_different else 0
        
        return {
            "match": not is_different,
            "different": is_different,
            "reasons": differences,
            "confidence": confidence,
            "length_diff": len_diff,
            "length_ratio": len_ratio,
        }
    
    async def check_reflection(self, url, payload, param_name=None):
        from core.http import inject_param
        if param_name:
            test_url = inject_param(url, param_name, payload)
        else:
            test_url = url
        
        response = await self.http.get(test_url)
        
        if payload in response.get("text", ""):
            context = get_reflection_context(response.get("text", ""), payload)
            return {
                "reflected": True,
                "context": context,
                "url": test_url,
            }
        
        return {"reflected": False, "context": None, "url": test_url}


class EventDispatcher:
    def __init__(self):
        self._handlers = {
            "on_finding": [],
            "on_critical": [],
            "on_high": [],
            "on_chain": [],
            "on_start": [],
            "on_finish": [],
            "on_module_start": [],
            "on_module_finish": [],
            "on_error": [],
        }
    
    def on(self, event_type, handler):
        if event_type in self._handlers:
            self._handlers[event_type].append(handler)
        return self
    
    def on_finding(self, handler):
        return self.on("on_finding", handler)
    
    def on_critical(self, handler):
        return self.on("on_critical", handler)
    
    def on_high(self, handler):
        return self.on("on_high", handler)
    
    def on_chain(self, handler):
        return self.on("on_chain", handler)
    
    def on_start(self, handler):
        return self.on("on_start", handler)
    
    def on_finish(self, handler):
        return self.on("on_finish", handler)
    
    def on_module_start(self, handler):
        return self.on("on_module_start", handler)
    
    def on_module_finish(self, handler):
        return self.on("on_module_finish", handler)
    
    def on_error(self, handler):
        return self.on("on_error", handler)
    
    async def emit(self, event_type, *args, **kwargs):
        handlers = self._handlers.get(event_type, [])
        for handler in handlers:
            try:
                import asyncio
                if asyncio.iscoroutinefunction(handler):
                    await handler(*args, **kwargs)
                else:
                    handler(*args, **kwargs)
            except Exception:
                pass
    
    async def emit_finding(self, finding):
        await self.emit("on_finding", finding)
        
        severity = finding.get("severity", "")
        if severity == "CRITICAL":
            await self.emit("on_critical", finding)
        elif severity == "HIGH":
            await self.emit("on_high", finding)
        
        if finding.get("chain"):
            await self.emit("on_chain", finding)
    
    async def emit_start(self, scan_info):
        await self.emit("on_start", scan_info)
    
    async def emit_finish(self, results):
        await self.emit("on_finish", results)
    
    async def emit_module_start(self, module_name, target):
        await self.emit("on_module_start", module_name, target)
    
    async def emit_module_finish(self, module_name, target, findings):
        await self.emit("on_module_finish", module_name, target, findings)
    
    async def emit_error(self, error, context=None):
        await self.emit("on_error", error, context)
    
    def remove_handler(self, event_type, handler):
        if event_type in self._handlers:
            try:
                self._handlers[event_type].remove(handler)
            except ValueError:
                pass
    
    def clear_handlers(self, event_type=None):
        if event_type:
            self._handlers[event_type] = []
        else:
            for key in self._handlers:
                self._handlers[key] = []


def random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def random_int(min_val=1000, max_val=9999):
    return random.randint(min_val, max_val)

def load_payloads(name):
    """Synchronous payload loading for module initialization."""
    payload_file = Path(__file__).parent.parent / "payloads" / f"{name}.txt"
    if payload_file.exists():
        with open(payload_file, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return []

async def load_payloads_async(name):
    """Async payload loading for use in async scan contexts."""
    payload_file = Path(__file__).parent.parent / "payloads" / f"{name}.txt"
    if payload_file.exists():
        async with aiofiles.open(payload_file, "r", encoding="utf-8", errors="ignore") as f:
            content = await f.read()
            return [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]
    return []

def hash_string(s):
    return hashlib.md5(s.encode()).hexdigest()[:8]

def extract_params(url):
    parsed = urlparse(url)
    return list(parse_qs(parsed.query, keep_blank_values=True).keys())

def is_same_origin(url1, url2):
    p1, p2 = urlparse(url1), urlparse(url2)
    return p1.netloc == p2.netloc

def find_in_response(text, patterns):
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return pattern
    return None

def response_diff(resp1, resp2):
    if resp1["status"] != resp2["status"]:
        return True
    if abs(len(resp1["text"]) - len(resp2["text"])) > 100:
        return True
    return False


class ResponseDiffer:
    def __init__(self, threshold=0.1):
        self.threshold = threshold
        self.baselines = {}
    
    def set_baseline(self, key, response):
        self.baselines[key] = {
            "status": response.get("status"),
            "length": len(response.get("text", "")),
            "headers": response.get("headers", {}),
            "word_count": len(response.get("text", "").split()),
            "line_count": response.get("text", "").count("\n"),
            "content_hash": hash_string(response.get("text", "")[:1000]),
        }
    
    def compare(self, key, response):
        if key not in self.baselines:
            return {"different": False, "reason": "no_baseline"}
        
        baseline = self.baselines[key]
        diffs = []
        
        if response.get("status") != baseline["status"]:
            diffs.append(f"status:{baseline['status']}→{response.get('status')}")
        
        curr_len = len(response.get("text", ""))
        len_diff = abs(curr_len - baseline["length"])
        len_ratio = len_diff / max(baseline["length"], 1)
        
        if len_ratio > self.threshold:
            diffs.append(f"length:{baseline['length']}→{curr_len}({len_ratio:.1%})")
        
        curr_words = len(response.get("text", "").split())
        word_diff = abs(curr_words - baseline["word_count"])
        word_ratio = word_diff / max(baseline["word_count"], 1)
        
        if word_ratio > self.threshold:
            diffs.append(f"words:{baseline['word_count']}→{curr_words}")
        
        curr_lines = response.get("text", "").count("\n")
        line_diff = abs(curr_lines - baseline["line_count"])
        
        if line_diff > 5:
            diffs.append(f"lines:{baseline['line_count']}→{curr_lines}")
        
        curr_hash = hash_string(response.get("text", "")[:1000])
        if curr_hash != baseline["content_hash"]:
            diffs.append("content_changed")
        
        return {
            "different": len(diffs) > 0,
            "reasons": diffs,
            "length_diff": len_diff,
            "length_ratio": len_ratio,
        }
    
    def detect_blind_vuln(self, responses, payloads):
        if len(responses) < 2:
            return None
        
        true_responses = []
        false_responses = []
        
        for i, (resp, payload) in enumerate(zip(responses, payloads)):
            is_true_condition = any(x in payload.lower() for x in ["1=1", "true", "or 1", "sleep"])
            
            if is_true_condition:
                true_responses.append((i, resp))
            else:
                false_responses.append((i, resp))
        
        if not true_responses or not false_responses:
            return None
        
        true_lens = [len(r[1].get("text", "")) for r in true_responses]
        false_lens = [len(r[1].get("text", "")) for r in false_responses]
        
        avg_true = sum(true_lens) / len(true_lens)
        avg_false = sum(false_lens) / len(false_lens)
        
        len_diff = abs(avg_true - avg_false)
        
        if len_diff > 50:
            return {
                "type": "boolean_blind",
                "confidence": min(len_diff / 100, 1.0),
                "true_avg_len": avg_true,
                "false_avg_len": avg_false,
                "diff": len_diff,
            }
        
        return None
    
    def detect_time_based(self, responses, times, threshold=2.0):
        if len(responses) != len(times):
            return None
        
        normal_times = []
        delayed_times = []
        
        for i, (resp, elapsed) in enumerate(zip(responses, times)):
            if elapsed > threshold:
                delayed_times.append((i, elapsed))
            else:
                normal_times.append((i, elapsed))
        
        if delayed_times and normal_times:
            avg_normal = sum(t[1] for t in normal_times) / len(normal_times)
            avg_delayed = sum(t[1] for t in delayed_times) / len(delayed_times)
            
            if avg_delayed > avg_normal + threshold:
                return {
                    "type": "time_based",
                    "confidence": min((avg_delayed - avg_normal) / threshold, 1.0),
                    "normal_avg": avg_normal,
                    "delayed_avg": avg_delayed,
                    "delayed_indices": [t[0] for t in delayed_times],
                }
        
        return None

def encode_payload(payload, encoding="url"):
    if encoding == "url":
        from urllib.parse import quote
        return quote(payload)
    elif encoding == "double_url":
        from urllib.parse import quote
        return quote(quote(payload))
    elif encoding == "html":
        return payload.replace("<", "&lt;").replace(">", "&gt;")
    elif encoding == "unicode":
        return "".join(f"\\u{ord(c):04x}" for c in payload)
    return payload

def get_reflection_context(text, marker):
    if marker not in text:
        return None
    idx = text.find(marker)
    start = max(0, idx - 50)
    end = min(len(text), idx + len(marker) + 50)
    snippet = text[start:end]
    if re.search(r'<script[^>]*>[^<]*' + re.escape(marker), text, re.IGNORECASE):
        return "script"
    if re.search(r'<[^>]+' + re.escape(marker), text):
        return "attribute"
    if re.search(r'<style[^>]*>[^<]*' + re.escape(marker), text, re.IGNORECASE):
        return "style"
    if re.search(r'<!--[^>]*' + re.escape(marker), text):
        return "comment"
    return "html"


class TargetWordlist:
    def __init__(self):
        self._words = {}
        self._domain_parts = set()
        self._path_parts = set()
        self._param_names = set()
        self._param_values = set()
        self._headers = set()
        self._common_suffixes = ["", "s", "es", "ed", "ing", "er", "tion", "ment"]
        self._common_prefixes = ["", "get", "set", "is", "has", "add", "del", "new", "old", "my", "all"]
        self._separators = ["", "_", "-", ".", "/"]
        self._case_transforms = ["lower", "upper", "title", "camel"]
    
    def add_url(self, url):
        parsed = urlparse(url)
        
        domain = parsed.netloc.lower()
        for part in domain.replace(".", " ").replace("-", " ").replace("_", " ").split():
            if len(part) > 2:
                self._domain_parts.add(part)
                self._add_word(part, "domain")
        
        path = parsed.path
        for segment in path.split("/"):
            if segment:
                clean = re.sub(r'\.[a-z]+$', '', segment)
                if clean and len(clean) > 1:
                    self._path_parts.add(clean)
                    self._add_word(clean, "path")
                    for token in self._tokenize(clean):
                        self._add_word(token, "path_token")
        
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            for name, values in params.items():
                self._param_names.add(name)
                self._add_word(name, "param")
                for token in self._tokenize(name):
                    self._add_word(token, "param_token")
                for val in values:
                    if val and len(val) > 2 and len(val) < 50 and not val.isdigit():
                        self._param_values.add(val)
                        self._add_word(val, "value")
    
    def add_response(self, text, content_type="text/html"):
        if "json" in content_type.lower():
            self._extract_json_keys(text)
        elif "html" in content_type.lower():
            self._extract_html_tokens(text)
        else:
            self._extract_text_tokens(text)
    
    def add_header(self, name, value):
        self._headers.add(name.lower())
        self._add_word(name, "header")
        
        if value and len(value) > 2 and len(value) < 100:
            for token in self._tokenize(value):
                if len(token) > 2:
                    self._add_word(token, "header_value")
    
    def _add_word(self, word, source):
        word = word.lower().strip()
        if not word or len(word) < 2 or len(word) > 50:
            return
        if word.isdigit():
            return
        if word in self._words:
            self._words[word]["count"] += 1
            self._words[word]["sources"].add(source)
        else:
            self._words[word] = {"count": 1, "sources": {source}}
    
    def _tokenize(self, text):
        tokens = []
        
        camel_split = re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)', text)
        tokens.extend([t.lower() for t in camel_split if len(t) > 1])
        
        snake_split = re.split(r'[_\-\.]', text)
        tokens.extend([t.lower() for t in snake_split if len(t) > 1])
        
        num_split = re.split(r'\d+', text)
        tokens.extend([t.lower() for t in num_split if len(t) > 1])
        
        return list(set(tokens))
    
    def _extract_json_keys(self, text):
        try:
            import json
            data = json.loads(text)
            self._walk_json(data)
        except:
            key_pattern = r'"([a-zA-Z_][a-zA-Z0-9_]{1,30})":'
            for match in re.findall(key_pattern, text):
                self._add_word(match, "json_key")
    
    def _walk_json(self, obj, depth=0):
        if depth > 10:
            return
        if isinstance(obj, dict):
            for key, val in obj.items():
                self._add_word(key, "json_key")
                for token in self._tokenize(key):
                    self._add_word(token, "json_token")
                self._walk_json(val, depth + 1)
        elif isinstance(obj, list):
            for item in obj[:20]:
                self._walk_json(item, depth + 1)
        elif isinstance(obj, str) and len(obj) > 2 and len(obj) < 50:
            if not obj.isdigit() and re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', obj):
                self._add_word(obj, "json_value")
    
    def _extract_html_tokens(self, text):
        id_pattern = r'id=["\']([a-zA-Z][a-zA-Z0-9_-]{1,30})["\']'
        for match in re.findall(id_pattern, text, re.IGNORECASE):
            self._add_word(match, "html_id")
            for token in self._tokenize(match):
                self._add_word(token, "html_token")
        
        class_pattern = r'class=["\']([^"\']+)["\']'
        for match in re.findall(class_pattern, text, re.IGNORECASE):
            for cls in match.split():
                self._add_word(cls, "html_class")
                for token in self._tokenize(cls):
                    self._add_word(token, "html_token")
        
        name_pattern = r'name=["\']([a-zA-Z][a-zA-Z0-9_-]{1,30})["\']'
        for match in re.findall(name_pattern, text, re.IGNORECASE):
            self._add_word(match, "html_name")
        
        data_pattern = r'data-([a-zA-Z][a-zA-Z0-9_-]{1,30})='
        for match in re.findall(data_pattern, text, re.IGNORECASE):
            self._add_word(match, "html_data")
    
    def _extract_text_tokens(self, text):
        word_pattern = r'\b[a-zA-Z][a-zA-Z0-9_]{2,20}\b'
        for match in re.findall(word_pattern, text)[:500]:
            self._add_word(match, "text")
    
    def get_words(self, min_count=1, sources=None):
        result = []
        for word, info in self._words.items():
            if info["count"] >= min_count:
                if sources is None or info["sources"] & set(sources):
                    result.append((word, info["count"], info["sources"]))
        return sorted(result, key=lambda x: x[1], reverse=True)
    
    def generate_mutations(self, base_words=None, max_mutations=1000):
        if base_words is None:
            base_words = [w[0] for w in self.get_words(min_count=2)[:50]]
        
        mutations = set()
        
        for word in base_words:
            mutations.add(word)
            mutations.add(word.lower())
            mutations.add(word.upper())
            mutations.add(word.title())
            
            for suffix in self._common_suffixes[:5]:
                mutations.add(word + suffix)
            
            for prefix in self._common_prefixes[:5]:
                if prefix:
                    mutations.add(prefix + word)
                    mutations.add(prefix + "_" + word)
                    mutations.add(prefix + word.title())
        
        high_value = [w[0] for w in self.get_words(min_count=3)[:20]]
        for i, w1 in enumerate(high_value[:10]):
            for w2 in high_value[i+1:i+5]:
                for sep in self._separators[:3]:
                    mutations.add(w1 + sep + w2)
                    mutations.add(w2 + sep + w1)
        
        for word in base_words[:30]:
            for i in range(1, 4):
                mutations.add(word + str(i))
                mutations.add(word + "_" + str(i))
            mutations.add(word + "_id")
            mutations.add(word + "_key")
            mutations.add(word + "_token")
            mutations.add(word + "_api")
            mutations.add("api_" + word)
            mutations.add("get_" + word)
            mutations.add("set_" + word)
        
        return list(mutations)[:max_mutations]
    
    def generate_path_mutations(self, max_paths=500):
        paths = set()
        
        base_paths = list(self._path_parts)[:30]
        for path in base_paths:
            paths.add("/" + path)
            paths.add("/api/" + path)
            paths.add("/api/v1/" + path)
            paths.add("/api/v2/" + path)
            paths.add("/" + path + "/")
            paths.add("/" + path + ".json")
            paths.add("/" + path + ".xml")
            paths.add("/" + path + "/list")
            paths.add("/" + path + "/all")
            paths.add("/" + path + "/new")
            paths.add("/" + path + "/create")
            paths.add("/" + path + "/edit")
            paths.add("/" + path + "/delete")
            paths.add("/" + path + "/1")
            paths.add("/" + path + "/admin")
        
        high_value = [w[0] for w in self.get_words(min_count=2, sources={"path", "json_key", "param"})[:15]]
        for word in high_value:
            paths.add("/" + word)
            paths.add("/api/" + word)
            paths.add("/" + word + "s")
            paths.add("/admin/" + word)
        
        return list(paths)[:max_paths]
    
    def generate_param_mutations(self, max_params=300):
        params = set()
        
        base_params = list(self._param_names)[:20]
        for param in base_params:
            params.add(param)
            params.add(param + "_id")
            params.add(param + "Id")
            params.add(param + "_key")
            params.add("old_" + param)
            params.add("new_" + param)
        
        high_value = [w[0] for w in self.get_words(min_count=2, sources={"json_key", "html_name"})[:20]]
        for word in high_value:
            params.add(word)
            params.add(word + "_id")
            params.add(word + "Id")
        
        common_params = ["id", "user_id", "userId", "token", "key", "api_key", "apiKey", 
                        "secret", "password", "pass", "username", "email", "name",
                        "page", "limit", "offset", "sort", "order", "filter", "search",
                        "callback", "redirect", "url", "next", "return", "ref", "source"]
        params.update(common_params)
        
        return list(params)[:max_params]
    
    def stats(self):
        return {
            "total_words": len(self._words),
            "domain_parts": len(self._domain_parts),
            "path_parts": len(self._path_parts),
            "param_names": len(self._param_names),
            "param_values": len(self._param_values),
            "headers": len(self._headers),
            "top_words": self.get_words(min_count=2)[:10],
        }
