import re
import ipaddress
from typing import List, Set, Optional, Pattern
from urllib.parse import urlparse
from pathlib import Path
from dataclasses import dataclass


@dataclass
class ScopeRule:
    pattern: str
    rule_type: str
    is_exclude: bool = False
    compiled: Optional[Pattern] = None
    
    def __post_init__(self):
        if self.rule_type == "regex":
            self.compiled = re.compile(self.pattern, re.IGNORECASE)


class ScopeManager:
    def __init__(self, config: Optional[dict] = None):
        config = config or {}
        
        self._include_rules: List[ScopeRule] = []
        self._exclude_rules: List[ScopeRule] = []
        self._include_domains: Set[str] = set()
        self._exclude_domains: Set[str] = set()
        self._include_ips: List[ipaddress.IPv4Network] = []
        self._exclude_ips: List[ipaddress.IPv4Network] = []
        self._include_paths: List[Pattern] = []
        self._exclude_paths: List[Pattern] = []
        
        self._strict_mode = config.get("strict_scope", False)
        self._allow_subdomains = config.get("allow_subdomains", True)
        
        if "scope_file" in config:
            self.load_from_file(Path(config["scope_file"]))
        
        for domain in config.get("include_domains", []):
            self.add_domain(domain, exclude=False)
        
        for domain in config.get("exclude_domains", []):
            self.add_domain(domain, exclude=True)
        
        for pattern in config.get("exclude_patterns", []):
            self.add_pattern(pattern, exclude=True)
    
    def add_domain(self, domain: str, exclude: bool = False) -> None:
        domain = domain.lower().strip()
        
        if domain.startswith("*."):
            domain = domain[2:]
        
        if exclude:
            self._exclude_domains.add(domain)
        else:
            self._include_domains.add(domain)
    
    def add_ip_range(self, cidr: str, exclude: bool = False) -> None:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if exclude:
                self._exclude_ips.append(network)
            else:
                self._include_ips.append(network)
        except ValueError:
            pass
    
    def add_pattern(self, pattern: str, exclude: bool = False) -> None:
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            rule = ScopeRule(pattern=pattern, rule_type="regex", is_exclude=exclude, compiled=compiled)
            
            if exclude:
                self._exclude_rules.append(rule)
            else:
                self._include_rules.append(rule)
        except re.error:
            pass
    
    def add_path_pattern(self, pattern: str, exclude: bool = False) -> None:
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            if exclude:
                self._exclude_paths.append(compiled)
            else:
                self._include_paths.append(compiled)
        except re.error:
            pass
    
    def load_from_file(self, filepath: Path) -> int:
        if not filepath.exists():
            return 0
        
        count = 0
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                
                if not line or line.startswith("#"):
                    continue
                
                exclude = False
                if line.startswith("-"):
                    exclude = True
                    line = line[1:].strip()
                elif line.startswith("+"):
                    line = line[1:].strip()
                
                if line.startswith("regex:"):
                    self.add_pattern(line[6:], exclude=exclude)
                elif line.startswith("ip:"):
                    self.add_ip_range(line[3:], exclude=exclude)
                elif line.startswith("path:"):
                    self.add_path_pattern(line[5:], exclude=exclude)
                else:
                    self.add_domain(line, exclude=exclude)
                
                count += 1
        
        return count
    
    def is_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        host = parsed.netloc.split(":")[0].lower()
        path = parsed.path
        
        for rule in self._exclude_rules:
            if rule.compiled and rule.compiled.search(url):
                return False
        
        if host in self._exclude_domains:
            return False
        
        for domain in self._exclude_domains:
            if host.endswith(f".{domain}"):
                return False
        
        for pattern in self._exclude_paths:
            if pattern.search(path):
                return False
        
        try:
            ip = ipaddress.ip_address(host)
            for network in self._exclude_ips:
                if ip in network:
                    return False
        except ValueError:
            pass
        
        if not self._include_domains and not self._include_rules and not self._include_ips:
            if self._strict_mode:
                return False
            return True
        
        if host in self._include_domains:
            return True
        
        if self._allow_subdomains:
            for domain in self._include_domains:
                if host.endswith(f".{domain}"):
                    return True
        
        for rule in self._include_rules:
            if rule.compiled and rule.compiled.search(url):
                return True
        
        for pattern in self._include_paths:
            if pattern.search(path):
                return True
        
        try:
            ip = ipaddress.ip_address(host)
            for network in self._include_ips:
                if ip in network:
                    return True
        except ValueError:
            pass
        
        if self._strict_mode:
            return False
        
        return not bool(self._include_domains or self._include_rules or self._include_ips)
    
    def filter_urls(self, urls: List[str]) -> List[str]:
        return [url for url in urls if self.is_in_scope(url)]
    
    def get_stats(self) -> dict:
        return {
            "include_domains": len(self._include_domains),
            "exclude_domains": len(self._exclude_domains),
            "include_rules": len(self._include_rules),
            "exclude_rules": len(self._exclude_rules),
            "include_ips": len(self._include_ips),
            "exclude_ips": len(self._exclude_ips),
            "include_paths": len(self._include_paths),
            "exclude_paths": len(self._exclude_paths),
            "strict_mode": self._strict_mode,
            "allow_subdomains": self._allow_subdomains,
        }
    
    def export_to_file(self, filepath: Path) -> int:
        count = 0
        with open(filepath, "w") as f:
            f.write("# Lantern Scope Configuration\n")
            f.write("# Lines starting with - are excluded\n")
            f.write("# Lines starting with + or no prefix are included\n\n")
            
            f.write("# Included Domains\n")
            for domain in self._include_domains:
                f.write(f"+{domain}\n")
                count += 1
            
            f.write("\n# Excluded Domains\n")
            for domain in self._exclude_domains:
                f.write(f"-{domain}\n")
                count += 1
            
            f.write("\n# Regex Patterns\n")
            for rule in self._include_rules:
                f.write(f"+regex:{rule.pattern}\n")
                count += 1
            for rule in self._exclude_rules:
                f.write(f"-regex:{rule.pattern}\n")
                count += 1
        
        return count
    
    def clear(self) -> None:
        self._include_rules.clear()
        self._exclude_rules.clear()
        self._include_domains.clear()
        self._exclude_domains.clear()
        self._include_ips.clear()
        self._exclude_ips.clear()
        self._include_paths.clear()
        self._exclude_paths.clear()


_global_scope: Optional[ScopeManager] = None


def get_scope_manager(config: dict = None) -> ScopeManager:
    global _global_scope
    if _global_scope is None:
        _global_scope = ScopeManager(config or {})
    return _global_scope


def set_scope_manager(scope: ScopeManager) -> None:
    global _global_scope
    _global_scope = scope


def is_in_scope(url: str) -> bool:
    scope = get_scope_manager()
    return scope.is_in_scope(url)
