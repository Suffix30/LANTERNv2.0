import os
import json
import hashlib
import aiofiles
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Optional
from collections import defaultdict


class LearnedPayloads:
    def __init__(self, payloads_dir: Path = None):
        if payloads_dir is None:
            payloads_dir = Path(__file__).parent.parent / "payloads"
        self.payloads_dir = payloads_dir
        self.learned_dir = payloads_dir / "learned"
        self.learned_dir.mkdir(exist_ok=True)
        self.index_file = self.learned_dir / "index.json"
        self._cache: Dict[str, Set[str]] = defaultdict(set)
        self._new_payloads: Dict[str, List[dict]] = defaultdict(list)
        self._seen_hashes: Set[str] = set()
        self._load_index()
    
    def _load_index(self):
        if self.index_file.exists():
            try:
                with open(self.index_file, "r") as f:
                    data = json.load(f)
                    for category, payloads in data.get("payloads", {}).items():
                        for p in payloads:
                            self._cache[category].add(p["payload"])
                            self._seen_hashes.add(p["hash"])
            except:
                pass
    
    def _hash_payload(self, payload: str) -> str:
        return hashlib.md5(payload.encode()).hexdigest()[:12]
    
    def add_successful(self, category: str, payload: str, context: dict = None):
        payload = payload.strip()
        if not payload or len(payload) < 3:
            return False
        
        payload_hash = self._hash_payload(payload)
        
        if payload_hash in self._seen_hashes:
            return False
        
        if payload in self._cache[category]:
            return False
        
        self._seen_hashes.add(payload_hash)
        self._cache[category].add(payload)
        
        self._new_payloads[category].append({
            "payload": payload,
            "hash": payload_hash,
            "timestamp": datetime.now().isoformat(),
            "context": context or {},
        })
        
        return True
    
    def add_mutation(self, category: str, original: str, mutation: str, target: str = None):
        if mutation == original:
            return False
        
        return self.add_successful(category, mutation, {
            "type": "mutation",
            "original": original[:100],
            "target": target,
        })
    
    def add_bypass(self, category: str, payload: str, waf: str = None, target: str = None):
        return self.add_successful(category, payload, {
            "type": "waf_bypass",
            "waf": waf,
            "target": target,
        })
    
    def add_custom(self, category: str, payload: str, vuln_type: str, evidence: str = None):
        return self.add_successful(category, payload, {
            "type": "discovered",
            "vuln_type": vuln_type,
            "evidence": evidence[:200] if evidence else None,
        })
    
    def get_learned(self, category: str) -> List[str]:
        return list(self._cache.get(category, set()))
    
    def get_all_categories(self) -> List[str]:
        return list(self._cache.keys())
    
    def get_stats(self) -> dict:
        return {
            "total": sum(len(v) for v in self._cache.values()),
            "new_this_session": sum(len(v) for v in self._new_payloads.values()),
            "categories": {k: len(v) for k, v in self._cache.items()},
        }
    
    async def save(self):
        if not any(self._new_payloads.values()):
            return 0
        
        saved_count = 0
        
        existing_data = {"payloads": {}, "metadata": {}}
        if self.index_file.exists():
            try:
                async with aiofiles.open(self.index_file, "r") as f:
                    content = await f.read()
                    existing_data = json.loads(content)
            except:
                pass
        
        for category, new_payloads in self._new_payloads.items():
            if not new_payloads:
                continue
            
            if category not in existing_data["payloads"]:
                existing_data["payloads"][category] = []
            
            existing_data["payloads"][category].extend(new_payloads)
            saved_count += len(new_payloads)
            
            category_file = self.learned_dir / f"{category}.txt"
            async with aiofiles.open(category_file, "a") as f:
                for p in new_payloads:
                    await f.write(p["payload"] + "\n")
        
        existing_data["metadata"]["last_updated"] = datetime.now().isoformat()
        existing_data["metadata"]["total_payloads"] = sum(len(v) for v in existing_data["payloads"].values())
        
        async with aiofiles.open(self.index_file, "w") as f:
            await f.write(json.dumps(existing_data, indent=2))
        
        self._new_payloads.clear()
        
        return saved_count
    
    def save_sync(self):
        if not any(self._new_payloads.values()):
            return 0
        
        saved_count = 0
        
        existing_data = {"payloads": {}, "metadata": {}}
        if self.index_file.exists():
            try:
                with open(self.index_file, "r") as f:
                    existing_data = json.load(f)
            except:
                pass
        
        for category, new_payloads in self._new_payloads.items():
            if not new_payloads:
                continue
            
            if category not in existing_data["payloads"]:
                existing_data["payloads"][category] = []
            
            existing_data["payloads"][category].extend(new_payloads)
            saved_count += len(new_payloads)
            
            category_file = self.learned_dir / f"{category}.txt"
            with open(category_file, "a") as f:
                for p in new_payloads:
                    f.write(p["payload"] + "\n")
        
        existing_data["metadata"]["last_updated"] = datetime.now().isoformat()
        existing_data["metadata"]["total_payloads"] = sum(len(v) for v in existing_data["payloads"].values())
        
        with open(self.index_file, "w") as f:
            json.dump(existing_data, indent=2, fp=f)
        
        self._new_payloads.clear()
        
        return saved_count


_global_learned: Optional[LearnedPayloads] = None


def get_learned_payloads() -> LearnedPayloads:
    global _global_learned
    if _global_learned is None:
        _global_learned = LearnedPayloads()
    return _global_learned


def load_payloads_with_learned(name: str) -> List[str]:
    from core.utils import load_payloads
    
    base_payloads = load_payloads(name)
    
    learned = get_learned_payloads()
    learned_payloads = learned.get_learned(name)
    
    if learned_payloads:
        combined = learned_payloads + [p for p in base_payloads if p not in learned_payloads]
        return combined
    
    return base_payloads


def record_successful_payload(category: str, payload: str, context: dict = None) -> bool:
    learned = get_learned_payloads()
    return learned.add_successful(category, payload, context)


def record_successful_mutation(category: str, original: str, mutation: str, target: str = None) -> bool:
    learned = get_learned_payloads()
    return learned.add_mutation(category, original, mutation, target)


def record_waf_bypass(category: str, payload: str, waf: str = None, target: str = None) -> bool:
    learned = get_learned_payloads()
    return learned.add_bypass(category, payload, waf, target)


async def save_learned_payloads() -> int:
    learned = get_learned_payloads()
    return await learned.save()


def get_learned_stats() -> dict:
    learned = get_learned_payloads()
    return learned.get_stats()
