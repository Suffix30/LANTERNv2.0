import hashlib
import json
import time
import asyncio
from typing import Dict, Optional, Any
from collections import OrderedDict
from pathlib import Path
from dataclasses import dataclass


@dataclass
class CacheEntry:
    response: Dict
    timestamp: float
    ttl: int
    hits: int = 0
    
    def is_expired(self) -> bool:
        return time.time() > self.timestamp + self.ttl
    
    def age(self) -> float:
        return time.time() - self.timestamp


class ResponseCache:
    def __init__(self, max_size: int = 10000, default_ttl: int = 300, persist_path: Optional[Path] = None):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.persist_path = persist_path
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = asyncio.Lock()
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "expirations": 0,
        }
        
        if persist_path and persist_path.exists():
            self._load_from_disk()
    
    def _generate_key(self, url: str, method: str = "GET", headers: Optional[Dict] = None, body: Optional[str] = None) -> str:
        key_parts = [method.upper(), url]
        
        if headers:
            cache_relevant_headers = ["Authorization", "Cookie", "Accept", "Content-Type"]
            for h in cache_relevant_headers:
                if h in headers:
                    key_parts.append(f"{h}:{headers[h]}")
        
        if body:
            key_parts.append(f"body:{body[:200]}")
        
        key_string = "|".join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()[:32]
    
    async def get(self, url: str, method: str = "GET", headers: Optional[Dict] = None) -> Optional[Dict]:
        key = self._generate_key(url, method, headers)
        
        async with self._lock:
            if key not in self._cache:
                self._stats["misses"] += 1
                return None
            
            entry = self._cache[key]
            
            if entry.is_expired():
                del self._cache[key]
                self._stats["expirations"] += 1
                self._stats["misses"] += 1
                return None
            
            entry.hits += 1
            self._stats["hits"] += 1
            
            self._cache.move_to_end(key)
            
            return entry.response
    
    async def set(self, url: str, response: Dict, method: str = "GET", headers: Optional[Dict] = None, ttl: Optional[int] = None) -> None:
        key = self._generate_key(url, method, headers)
        ttl = ttl if ttl is not None else self.default_ttl
        
        async with self._lock:
            if len(self._cache) >= self.max_size:
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
                self._stats["evictions"] += 1
            
            self._cache[key] = CacheEntry(
                response=response,
                timestamp=time.time(),
                ttl=ttl,
            )
    
    async def invalidate(self, url: str, method: str = "GET") -> bool:
        key = self._generate_key(url, method)
        
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False
    
    async def invalidate_pattern(self, pattern: str) -> int:
        import re
        count = 0
        regex = re.compile(pattern)
        
        async with self._lock:
            keys_to_delete = []
            for key in self._cache:
                if regex.search(key):
                    keys_to_delete.append(key)
            
            for key in keys_to_delete:
                del self._cache[key]
                count += 1
        
        return count
    
    async def clear(self) -> int:
        async with self._lock:
            count = len(self._cache)
            self._cache.clear()
            return count
    
    async def cleanup_expired(self) -> int:
        count = 0
        
        async with self._lock:
            keys_to_delete = []
            for key, entry in self._cache.items():
                if entry.is_expired():
                    keys_to_delete.append(key)
            
            for key in keys_to_delete:
                del self._cache[key]
                count += 1
                self._stats["expirations"] += 1
        
        return count
    
    def get_stats(self) -> Dict[str, Any]:
        total = self._stats["hits"] + self._stats["misses"]
        hit_rate = self._stats["hits"] / total if total > 0 else 0
        
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "hits": self._stats["hits"],
            "misses": self._stats["misses"],
            "hit_rate": round(hit_rate * 100, 2),
            "evictions": self._stats["evictions"],
            "expirations": self._stats["expirations"],
        }
    
    def _load_from_disk(self) -> None:
        if not self.persist_path:
            return
        
        try:
            with open(self.persist_path, "r") as f:
                data = json.load(f)
                
            for key, entry_data in data.get("cache", {}).items():
                entry = CacheEntry(
                    response=entry_data["response"],
                    timestamp=entry_data["timestamp"],
                    ttl=entry_data["ttl"],
                    hits=entry_data.get("hits", 0),
                )
                
                if not entry.is_expired():
                    self._cache[key] = entry
        except (json.JSONDecodeError, KeyError, IOError):
            pass
    
    async def save_to_disk(self) -> bool:
        if not self.persist_path:
            return False
        
        async with self._lock:
            data = {
                "cache": {},
                "stats": self._stats,
                "timestamp": time.time(),
            }
            
            for key, entry in self._cache.items():
                if not entry.is_expired():
                    data["cache"][key] = {
                        "response": entry.response,
                        "timestamp": entry.timestamp,
                        "ttl": entry.ttl,
                        "hits": entry.hits,
                    }
        
        try:
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.persist_path, "w") as f:
                json.dump(data, f)
            return True
        except IOError:
            return False


class CacheManager:
    def __init__(self, config: Dict = None):
        config = config or {}
        
        self.enabled = config.get("cache_enabled", True)
        self.max_size = config.get("cache_max_size", 10000)
        self.default_ttl = config.get("cache_ttl", 300)
        
        persist_path = config.get("cache_persist_path")
        if persist_path:
            persist_path = Path(persist_path)
        
        self._cache = ResponseCache(
            max_size=self.max_size,
            default_ttl=self.default_ttl,
            persist_path=persist_path,
        )
        
        self._nocache_patterns = config.get("nocache_patterns", [
            r"/login", r"/logout", r"/auth", r"/api/token",
            r"\?.*=", r"POST", r"PUT", r"DELETE",
        ])
    
    def _should_cache(self, url: str, method: str) -> bool:
        if not self.enabled:
            return False
        
        if method.upper() not in ["GET", "HEAD"]:
            return False
        
        import re
        for pattern in self._nocache_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return False
        
        return True
    
    async def get_cached_response(self, url: str, method: str = "GET", headers: Optional[Dict] = None) -> Optional[Dict]:
        if not self._should_cache(url, method):
            return None
        
        return await self._cache.get(url, method, headers)
    
    async def cache_response(self, url: str, response: Dict, method: str = "GET", headers: Optional[Dict] = None, ttl: Optional[int] = None) -> None:
        if not self._should_cache(url, method):
            return
        
        await self._cache.set(url, response, method, headers, ttl)
    
    async def invalidate(self, url: str, method: str = "GET") -> bool:
        return await self._cache.invalidate(url, method)
    
    async def clear(self) -> int:
        return await self._cache.clear()
    
    def get_stats(self) -> Dict:
        return self._cache.get_stats()
    
    async def save(self) -> bool:
        return await self._cache.save_to_disk()


_global_cache: Optional[CacheManager] = None


def get_cache_manager(config: Dict = None) -> CacheManager:
    global _global_cache
    if _global_cache is None:
        _global_cache = CacheManager(config or {})
    return _global_cache


def set_cache_manager(cache: CacheManager) -> None:
    global _global_cache
    _global_cache = cache
