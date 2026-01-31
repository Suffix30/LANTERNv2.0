import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SCOPE_FILE = Path(__file__).parent / "scope.txt"


def validate_request(prompt: str) -> bool:
    prompt_lower = prompt.lower()
    scope_markers = ["http://", "https://", "scope", "authorized", "permission", "allowed", "pentest", "test"]
    if any(marker in prompt_lower for marker in scope_markers):
        return True
    return False


def load_scope_config() -> dict[str, Any]:
    config: dict[str, Any] = {
        "allowed_domains": [],
        "blocked_domains": [],
        "allowed_ips": [],
        "blocked_patterns": [],
        "require_https": False,
        "max_threads": 100,
        "exploit_allowed": True,
    }
    
    if not SCOPE_FILE.exists():
        return config
    
    try:
        lines = SCOPE_FILE.read_text(encoding="utf-8").strip().splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            if line.startswith("+"):
                domain = line[1:].strip()
                if domain.startswith("ip:"):
                    config["allowed_ips"].append(domain[3:])
                else:
                    config["allowed_domains"].append(domain)
            
            elif line.startswith("-"):
                item = line[1:].strip()
                if item.startswith("regex:"):
                    config["blocked_patterns"].append(item[6:])
                elif item.startswith("path:"):
                    config["blocked_patterns"].append(re.escape(item[5:]))
                else:
                    config["blocked_domains"].append(item)
            
            elif line.startswith("require_https"):
                config["require_https"] = True
            
            elif line.startswith("max_threads:"):
                try:
                    config["max_threads"] = int(line.split(":")[1].strip())
                except ValueError:
                    pass
            
            elif line.startswith("no_exploit"):
                config["exploit_allowed"] = False
    
    except Exception:
        pass
    
    return config


def validate_target(target: str, scope_config: dict[str, Any] | None = None) -> tuple[bool, str]:
    if not target or target == "<target>":
        return False, "No valid target specified"
    
    config = scope_config or load_scope_config()
    
    try:
        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path
        domain = domain.split(":")[0]
    except Exception:
        return False, f"Invalid target URL: {target}"
    
    if config.get("require_https") and not target.startswith("https://"):
        return False, "HTTPS required by scope policy"
    
    blocked = config.get("blocked_domains", [])
    for blocked_domain in blocked:
        if blocked_domain.startswith("*."):
            if domain.endswith(blocked_domain[1:]):
                return False, f"Domain {domain} blocked by wildcard {blocked_domain}"
        elif domain == blocked_domain or domain.endswith("." + blocked_domain):
            return False, f"Domain {domain} is blocked"
    
    for pattern in config.get("blocked_patterns", []):
        if re.search(pattern, target):
            return False, f"Target matches blocked pattern: {pattern}"
    
    allowed = config.get("allowed_domains", [])
    if allowed:
        is_allowed = False
        for allowed_domain in allowed:
            if allowed_domain.startswith("*."):
                if domain.endswith(allowed_domain[1:]):
                    is_allowed = True
                    break
            elif domain == allowed_domain or domain.endswith("." + allowed_domain):
                is_allowed = True
                break
        
        if not is_allowed:
            return False, f"Domain {domain} not in allowed scope"
    
    return True, "Target validated"


def validate_plan(cmd: list[str], scope_config: dict[str, Any] | None = None) -> tuple[bool, str]:
    config = scope_config or load_scope_config()
    
    target = None
    exploit_requested = False
    threads = 50
    
    i = 0
    while i < len(cmd):
        arg = cmd[i]
        
        if arg in ("-t", "--target") and i + 1 < len(cmd):
            target = cmd[i + 1]
            i += 2
            continue
        
        if arg == "--exploit":
            exploit_requested = True
        
        if arg == "--threads" and i + 1 < len(cmd):
            try:
                threads = int(cmd[i + 1])
            except ValueError:
                pass
        
        i += 1
    
    if target:
        valid, reason = validate_target(target, config)
        if not valid:
            return False, reason
    
    if exploit_requested and not config.get("exploit_allowed", True):
        return False, "Exploitation mode disabled by scope policy"
    
    max_threads = config.get("max_threads", 100)
    if threads > max_threads:
        return False, f"Thread count {threads} exceeds policy maximum {max_threads}"
    
    return True, "Plan validated"


def is_safe_target(target: str) -> bool:
    safe_domains = [
        "testphp.vulnweb.com",
        "testhtml5.vulnweb.com",
        "testasp.vulnweb.com",
        "demo.testfire.net",
        "zero.webappsecurity.com",
        "localhost",
        "127.0.0.1",
        "dvwa",
        "juice-shop",
        "webgoat",
        "hackazon",
        "mutillidae",
        "bwapp",
    ]
    
    target_lower = target.lower()
    for safe in safe_domains:
        if safe in target_lower:
            return True
    
    return False


def get_policy_summary() -> str:
    config = load_scope_config()
    
    lines = ["Agent BLACK Policy Summary:", ""]
    
    allowed = config.get("allowed_domains", [])
    if allowed:
        lines.append(f"Allowed Domains: {', '.join(allowed)}")
    else:
        lines.append("Allowed Domains: Any (no restrictions)")
    
    blocked = config.get("blocked_domains", [])
    if blocked:
        lines.append(f"Blocked Domains: {', '.join(blocked)}")
    
    patterns = config.get("blocked_patterns", [])
    if patterns:
        lines.append(f"Blocked Patterns: {len(patterns)} regex rules")
    
    if config.get("require_https"):
        lines.append("HTTPS Required: Yes")
    
    lines.append(f"Max Threads: {config.get('max_threads', 100)}")
    lines.append(f"Exploitation Allowed: {'Yes' if config.get('exploit_allowed', True) else 'No'}")
    
    return "\n".join(lines)
