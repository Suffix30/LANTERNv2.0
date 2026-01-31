import argparse
import sys
import asyncio
import aiofiles
import yaml
from pathlib import Path
from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.live import Live
from rich import box
from core.engine import Scanner
from core.reporter import Reporter

PRESETS_DIR = Path(__file__).parent.parent / "presets"

console = Console()

BANNER = """[bold cyan]
 ██▓    ▄▄▄       ███▄    █ ▄▄▄█████▓▓█████  ██▀███   ███▄    █ 
▓██▒   ▒████▄     ██ ▀█   █ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒ ██ ▀█   █ 
▒██░   ▒██  ▀█▄  ▓██  ▀█ ██▒▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒▓██  ▀█ ██▒
▒██░   ░██▄▄▄▄██ ▓██▒  ▐▌██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄  ▓██▒  ▐▌██▒
░██████▒▓█   ▓██▒▒██░   ▓██░  ▒██▒ ░ ░▒████▒░██▓ ▒██▒▒██░   ▓██░
░ ▒░▓  ░▒▒   ▓▒█░░ ▒░   ▒ ▒   ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░   ▒ ▒ 
░ ░ ▒  ░ ▒   ▒▒ ░░ ░░   ░ ▒░    ░     ░ ░  ░  ░▒ ░ ▒░░ ░░   ░ ▒░
  ░ ░    ░   ▒      ░   ░ ░   ░         ░     ░░   ░    ░   ░ ░ 
    ░  ░     ░  ░         ░             ░  ░   ░              ░ 
[/][dim]                 Web Vulnerability Scanner v2.0
                    Made by: NET ( Gaspberry )[/]
"""

ALL_MODULES = [
    "sqli", "xss", "ssrf", "lfi", "ssti", "cmdi", "xxe", "crlf", "hpp",
    "auth", "jwt", "oauth", "mfa", "session", "cookie", "csrf", "ldap",
    "idor", "massassign", "cors", "accessctl",
    "api", "graphql", "websocket", "apiver",
    "dom", "prototype", "clickjack",
    "payment", "race", "captcha", "account", "logic",
    "headers", "ssl", "cache", "upload", "download",
    "fingerprint", "disclosure", "secrets", "subdomain", "dork", "cve", "dirbust",
    "smuggle", "deserial", "fuzz", "redirect", "techdetect",
    "waf", "takeover", "cloud", "paramfind", "csp", "h2smuggle", "cachepois",
    "cdn", "brokenlinks", "embed",
    "hostinject", "emailinject",
]

FAST_MODULES = [
    "waf", "headers", "cors", "disclosure", "fingerprint", "secrets", 
    "clickjack", "cve", "ssl", "cookie", "dork", "techdetect"
]

DEEP_MODULES = [
    "sqli", "xss", "ssrf", "lfi", "ssti", "cmdi", "xxe", "ldap",
    "oauth", "mfa", "jwt", "massassign", "prototype",
    "fuzz", "smuggle", "crlf", "upload", "hpp", "cache", 
    "race", "dom", "session", "deserial", "payment", "account", "download", "dirbust"
]

CHAIN_MODULES = {
    "auth_bypass": ["waf", "sqli", "ldap", "auth", "jwt", "oauth", "mfa", "session"],
    "data_theft": ["waf", "sqli", "ssrf", "lfi", "xxe", "idor", "disclosure", "dirbust", "cloud"],
    "rce": ["waf", "cmdi", "ssti", "deserial", "upload", "ssrf"],
    "xss_chain": ["waf", "csp", "xss", "dom", "prototype", "cors", "csrf"],
    "api_attack": ["waf", "api", "graphql", "massassign", "jwt", "idor"],
    "enum": ["waf", "dirbust", "subdomain", "takeover", "disclosure", "fingerprint", "techdetect", "dork", "cloud"],
    "cloud": ["cloud", "ssrf", "disclosure", "dirbust"],
    "takeover": ["takeover", "subdomain"],
    "full_recon": ["waf", "techdetect", "fingerprint", "subdomain", "takeover", "cloud", "dirbust", "disclosure", "dork", "paramfind", "csp"],
    "injection": ["waf", "paramfind", "sqli", "xss", "ssti", "cmdi", "lfi", "xxe", "crlf"],
    "smuggle": ["waf", "h2smuggle", "smuggle", "cachepois"],
    "cache": ["cachepois", "headers", "cors"],
    "poisoning": ["hostinject", "emailinject", "crlf", "cachepois", "redirect", "cache"],
    "business_logic": ["logic", "payment", "race", "account", "massassign"],
}

def parse_args():
    parser = argparse.ArgumentParser(
        description="Lantern - Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-t", "--target", help="Target URL or file containing URLs")
    parser.add_argument("-m", "--modules", help="Comma-separated modules (default: all)")
    parser.add_argument("-o", "--output", help="Output report filename (without extension)")
    parser.add_argument("--format", choices=["html", "json", "md", "jira", "obsidian", "all"], default="html", help="Report format")
    parser.add_argument("--obsidian", action="store_true", help="Also export to Obsidian vault (in addition to --format)")
    parser.add_argument("--obsidian-vault", type=str, help="Path to Obsidian vault (or set BLACK_OBSIDIAN_VAULT env var)")
    parser.add_argument("-H", "--header", action="append", help="Custom header (can be used multiple times)")
    parser.add_argument("-c", "--cookies", help="Cookies string")
    parser.add_argument("--threads", type=int, default=50, help="Concurrent requests (default: 50)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10)")
    parser.add_argument("--crawl", action="store_true", help="Crawl target to discover URLs")
    parser.add_argument("--crawl-depth", type=int, default=3, help="Crawl depth (default: 3)")
    parser.add_argument("--aggressive", action="store_true", help="Aggressive mode (more payloads, WAF bypass)")
    parser.add_argument("--stealth", action="store_true", help="Stealth mode (slower, randomized)")
    parser.add_argument("--fast", action="store_true", help="Fast mode (quick checks only)")
    parser.add_argument("--deep", action="store_true", help="Deep mode (thorough injection testing)")
    parser.add_argument("--preset", type=str, help="Use preset profile (fast, thorough, api, stealth, exploit)")
    parser.add_argument("--list-presets", action="store_true", help="List available presets")
    parser.add_argument("--chain", choices=list(CHAIN_MODULES.keys()),
                        help="Attack chain mode")
    parser.add_argument("--exploit", action="store_true", help="Enable auto-exploitation (extract data, dump creds)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--callback-host", help="Callback server host for OOB detection")
    parser.add_argument("--list", action="store_true", help="List available modules")
    parser.add_argument("--list-chains", action="store_true", help="List attack chain presets")
    parser.add_argument("--resume", action="store_true", help="Resume from last checkpoint")
    parser.add_argument("--collab-server", type=str, help="Start collab server (e.g., 0.0.0.0:8080)")
    parser.add_argument("--collab-client", type=str, help="Connect to collab server (e.g., ws://team.local:8080)")
    parser.add_argument("--no-banner", action="store_true", help="Hide banner")
    parser.add_argument("--smart", action="store_true", help="Smart module selection based on tech detection")
    parser.add_argument("--tech-detect", action="store_true", help="Run technology detection only")
    parser.add_argument("--dns-brute", action="store_true", help="High-speed DNS subdomain brute force")
    parser.add_argument("--dns-wordlist", type=str, help="Custom wordlist for DNS brute force")
    parser.add_argument("--dns-concurrency", type=int, default=500, help="DNS brute force concurrency (default: 500)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--ci", action="store_true", help="CI/CD mode with exit codes")
    parser.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default="HIGH", help="Fail on severity (default: HIGH)")
    parser.add_argument("--sarif", type=str, help="Output SARIF report for GitHub/GitLab")
    parser.add_argument("--junit", type=str, help="Output JUnit XML for CI pipelines")
    parser.add_argument("--scope-file", type=str, help="Scope configuration file")
    parser.add_argument("--include-domain", action="append", help="Include domain in scope")
    parser.add_argument("--exclude-domain", action="append", help="Exclude domain from scope")
    parser.add_argument("--exclude-pattern", action="append", help="Exclude URL pattern (regex)")
    parser.add_argument("--cache", action="store_true", help="Enable response caching")
    parser.add_argument("--cache-ttl", type=int, default=300, help="Cache TTL in seconds (default: 300)")
    parser.add_argument("--auth-config", type=str, help="Authentication configuration YAML file")
    parser.add_argument("--workflow", type=str, help="Run business logic workflow YAML file")
    parser.add_argument("--workflow-attack", type=str, help="Run specific attack from workflow")
    parser.add_argument("--oob-server", action="store_true", help="Start built-in OOB callback server")
    parser.add_argument("--oob-port", type=int, default=8888, help="OOB HTTP server port (default: 8888)")
    parser.add_argument("--oob-dns-port", type=int, default=5353, help="OOB DNS server port (default: 5353)")
    parser.add_argument("--analyze-js", action="store_true", help="Deep JavaScript analysis (endpoints, secrets, DOM sinks, BaaS credential exploitation)")
    parser.add_argument("--cve-scan", action="store_true", help="Scan for known CVEs based on detected technologies")
    parser.add_argument("--generate-pocs", action="store_true", help="Generate PoC files for each finding")
    parser.add_argument("--fuzz-params", action="store_true", help="Intelligent parameter fuzzing with boundary values")
    parser.add_argument("--diff-baseline", action="store_true", help="Establish response baselines for anomaly detection")
    parser.add_argument("--list-workflows", action="store_true", help="List available attack workflows")
    return parser.parse_args()

def show_modules():
    table = Table(title="Available Modules", box=box.ROUNDED, border_style="cyan")
    table.add_column("Module", style="bold green")
    table.add_column("Description", style="white")
    table.add_column("Type", style="dim")
    modules_info = {
        "sqli": ("SQL Injection + boolean/time detection, auto extraction, MSSQL/Azure", "Injection"),
        "xss": ("Cross-Site Scripting + reflection analysis, DOM sinks", "Injection"),
        "ssrf": ("Server-Side Request Forgery + OOB blind detection", "Server-Side"),
        "lfi": ("Local File Inclusion + auto-escalation chain", "Server-Side"),
        "ssti": ("Server-Side Template Injection + OOB RCE, filter bypass", "Server-Side"),
        "cmdi": ("OS Command Injection + OOB callbacks, filter bypass", "Injection"),
        "xxe": ("XML External Entity + OOB blind, error-based, UTF bypass", "Injection"),
        "crlf": ("CRLF Injection", "Injection"),
        "hpp": ("HTTP Parameter Pollution", "Injection"),
        "auth": ("Authentication Testing + multi-role, privilege escalation", "Auth"),
        "jwt": ("JWT Attacks + JWK/JKU/KID injection, secret cracking", "Auth"),
        "oauth": ("OAuth Misconfiguration + code injection, token exchange", "Auth"),
        "mfa": ("MFA/2FA Bypass + race condition, time-based, SMS intercept", "Auth"),
        "session": ("Session Management", "Auth"),
        "cookie": ("Cookie Security", "Auth"),
        "csrf": ("Cross-Site Request Forgery", "Auth"),
        "ldap": ("LDAP Injection + timing-based, error-based extraction", "Injection"),
        "idor": ("Insecure Direct Object Reference + cross-user testing", "Access"),
        "massassign": ("Mass Assignment", "Access"),
        "cors": ("CORS Misconfiguration", "Access"),
        "api": ("REST API Testing", "API"),
        "graphql": ("GraphQL Security + JS discovery, auto-extraction", "API"),
        "websocket": ("WebSocket Security + race, JWT bypass, subscription hijack", "API"),
        "dom": ("DOM-based + js_analyzer, DOM clobbering, CSTI", "Client"),
        "prototype": ("Prototype Pollution", "Client"),
        "clickjack": ("Clickjacking", "Client"),
        "payment": ("E-commerce/Payment Security", "Business"),
        "race": ("Race Conditions + double-spend detection", "Business"),
        "captcha": ("CAPTCHA Bypass", "Business"),
        "account": ("Account Security", "Business"),
        "logic": ("Business Logic + workflow integration, payment bypass", "Business"),
        "accessctl": ("Access Control + horizontal/vertical privesc, JWT manipulation", "Access"),
        "headers": ("Security Headers", "Config"),
        "ssl": ("SSL/TLS Config", "Config"),
        "cache": ("Cache Poisoning", "Config"),
        "upload": ("File Upload + confidence scoring, PoC data", "Config"),
        "download": ("File Download", "Config"),
        "fingerprint": ("Tech Fingerprinting", "Recon"),
        "disclosure": ("Info Disclosure + .git/.env parsing, secrets extraction", "Recon"),
        "secrets": ("Secrets Scanner", "Recon"),
        "subdomain": ("High-Speed Subdomain Brute + Takeover", "Recon"),
        "techdetect": ("Technology Stack Detection", "Recon"),
        "dork": ("Google Dorks", "Recon"),
        "cve": ("CVE Scanner", "Recon"),
        "smuggle": ("HTTP Smuggling + timing-based verification", "Advanced"),
        "deserial": ("Deserialization + OOB verification, PHAR, SnakeYAML", "Advanced"),
        "fuzz": ("Parameter Fuzzer", "Advanced"),
        "redirect": ("Open Redirect", "Advanced"),
        "waf": ("WAF Detection & Bypass", "Recon"),
        "takeover": ("Subdomain Takeover", "Recon"),
        "cloud": ("Cloud Storage Misconfiguration", "Recon"),
        "paramfind": ("Parameter Discovery", "Recon"),
        "csp": ("Content-Security-Policy Bypass", "Config"),
        "h2smuggle": ("HTTP/2 Smuggling", "Advanced"),
        "cachepois": ("Cache Poisoning", "Advanced"),
        "apiver": ("API Version Discovery", "API"),
        "cdn": ("CDN Detection", "Config"),
        "brokenlinks": ("Broken Link Checker", "Recon"),
        "embed": ("Embedded Objects (iframe/embed/object)", "Client"),
        "hostinject": ("Host / Password Reset Poisoning", "Auth"),
        "emailinject": ("Email Header Injection", "Injection"),
    }
    for mod, (desc, mod_type) in modules_info.items():
        table.add_row(mod, desc, mod_type)
    console.print(table)

def show_chains():
    table = Table(title="Attack Chains", box=box.ROUNDED, border_style="red")
    table.add_column("Chain", style="bold red")
    table.add_column("Modules", style="white")
    table.add_column("Goal", style="dim")
    
    chain_info = {
        "auth_bypass": ("sqli, auth, jwt, oauth, mfa, session", "Bypass authentication"),
        "data_theft": ("sqli, ssrf, lfi, xxe, idor, disclosure", "Extract sensitive data"),
        "rce": ("cmdi, ssti, deserial, upload, ssrf", "Remote code execution"),
        "xss_chain": ("xss, dom, prototype, cors, csrf", "Client-side attacks"),
        "api_attack": ("api, graphql, massassign, jwt, idor", "API exploitation"),
    }
    
    for chain, (mods, goal) in chain_info.items():
        table.add_row(chain, mods, goal)
    console.print(table)

def parse_headers(header_list):
    headers = {}
    if header_list:
        for h in header_list:
            if ":" in h:
                key, value = h.split(":", 1)
                headers[key.strip()] = value.strip()
    return headers


def load_preset(preset_name):
    preset_file = PRESETS_DIR / f"{preset_name}.yml"
    if not preset_file.exists():
        return None
    
    with open(preset_file, "r") as f:
        return yaml.safe_load(f)


def list_presets():
    presets = []
    if PRESETS_DIR.exists():
        for preset_file in PRESETS_DIR.glob("*.yml"):
            try:
                with open(preset_file, "r") as f:
                    data = yaml.safe_load(f)
                    presets.append({
                        "name": data.get("name", preset_file.stem),
                        "description": data.get("description", ""),
                        "modules": len(data.get("modules", [])),
                    })
            except:
                pass
    return presets


def show_presets():
    table = Table(title="Available Presets", box=box.ROUNDED, border_style="cyan")
    table.add_column("Name", style="bold green")
    table.add_column("Description", style="white")
    table.add_column("Modules", style="dim", justify="right")
    
    for preset in list_presets():
        table.add_row(preset["name"], preset["description"], str(preset["modules"]))
    
    console.print(table)


def show_workflows():
    table = Table(title="Pre-built Attack Workflows", box=box.ROUNDED, border_style="red")
    table.add_column("Workflow", style="bold red")
    table.add_column("Description", style="white")
    table.add_column("Attack Types", style="dim")
    
    workflows_info = {
        "payment_bypass": ("Payment/checkout flow attacks", "zero price, negative qty, coupon stacking, skip payment"),
        "auth_bypass": ("Authentication bypass attacks", "IDOR, JWT none alg, session fixation, password reset"),
        "api_abuse": ("API exploitation attacks", "mass assignment, GraphQL introspection, BOLA, rate limit bypass"),
        "file_upload": ("File upload bypass & RCE", "webshell, double ext, null byte, SVG XSS/XXE, polyglot"),
        "ssrf_chain": ("SSRF to cloud metadata", "AWS/GCP/Azure metadata, gopher://, Redis RCE, DNS rebinding"),
        "sqli_escalate": ("SQLi to shell escalation", "union extract, file read/write, xp_cmdshell, COPY RCE"),
    }
    
    for name, (desc, attacks) in workflows_info.items():
        table.add_row(name, desc, attacks)
    
    console.print(table)
    console.print("\n[dim]Usage: lantern -t <url> --workflow workflows/<name>.yml[/]")
    console.print("[dim]Run specific attack: lantern -t <url> --workflow workflows/<name>.yml --workflow-attack <attack_name>[/]")


def generate_stats_table(scanner, findings_count, severity_counts, progress_pct):
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold white")
    table.add_column("Metric2", style="cyan")
    table.add_column("Value2", style="bold white")
    
    http_stats = scanner.http.get_stats() if scanner.http else {}
    metrics = http_stats.get("metrics", {})
    rate_limiter = http_stats.get("rate_limiter", {})
    
    rps = metrics.get("requests_per_second", 0)
    elapsed = metrics.get("elapsed_formatted", "0s")
    total_reqs = metrics.get("total_requests", 0)
    errors = metrics.get("errors", 0)
    
    backoff = rate_limiter.get("backoff_factor", 1.0)
    rate_waits = rate_limiter.get("total_waits", 0)
    
    table.add_row(
        "Requests/sec", f"{rps:.1f}",
        "Total Requests", f"{total_reqs:,}"
    )
    table.add_row(
        "Elapsed", elapsed,
        "Errors", f"[red]{errors}[/]" if errors > 0 else "0"
    )
    table.add_row(
        "Progress", f"{progress_pct:.1f}%",
        "Rate Waits", f"[yellow]{rate_waits}[/]" if rate_waits > 0 else "0"
    )
    
    if backoff > 1.0:
        table.add_row(
            "Backoff", f"[yellow]{backoff:.1f}x[/]",
            "", ""
        )
    
    findings_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    findings_table.add_column("Sev", width=10)
    findings_table.add_column("Cnt", width=5, justify="right")
    
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        cnt = severity_counts.get(sev, 0)
        if cnt > 0:
            color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}.get(sev)
            findings_table.add_row(f"[{color}]{sev}[/]", f"[{color}]{cnt}[/]")
    
    stats_panel = Panel(
        Group(table, findings_table),
        title=f"[bold cyan]Live Stats[/] | Findings: {findings_count}",
        border_style="cyan",
        padding=(0, 1),
    )
    
    return stats_panel


async def load_targets(target):
    targets = []
    if Path(target).exists():
        async with aiofiles.open(target, "r") as f:
            content = await f.read()
            targets = [line.strip() for line in content.splitlines() if line.strip()]
    else:
        targets = [target]
    return targets

async def main():
    args = parse_args()
    
    if not args.no_banner:
        console.print(BANNER)
    
    if args.list:
        show_modules()
        return
    
    if hasattr(args, 'list_chains') and args.list_chains:
        show_chains()
        return
    
    if hasattr(args, 'list_presets') and args.list_presets:
        show_presets()
        return
    
    if hasattr(args, 'list_workflows') and args.list_workflows:
        show_workflows()
        return
    
    if hasattr(args, 'collab_server') and args.collab_server:
        from core.collab import run_collab_server
        host, port = "0.0.0.0", 8080
        if ":" in args.collab_server:
            host, port = args.collab_server.rsplit(":", 1)
            port = int(port)
        else:
            host = args.collab_server
        console.print(f"[bold cyan]Starting collaboration server on {host}:{port}[/]")
        await run_collab_server(host, port)
        return
    
    oob_manager = None
    if getattr(args, 'oob_server', False):
        from core.oob import OOBManager
        oob_manager = OOBManager()
        oob_manager.setup_server(
            http_port=getattr(args, 'oob_port', 8888),
            dns_port=getattr(args, 'oob_dns_port', 5353),
        )
        oob_manager.start_server_background()
        console.print(f"[bold cyan]OOB Server started:[/] HTTP:{args.oob_port} DNS:{args.oob_dns_port}")
    
    if getattr(args, 'workflow', None) and not args.target:
        console.print("[bold red]Error:[/] Workflow requires a target. Use -t <url>")
        sys.exit(1)
    
    if not args.target:
        console.print("[bold red]Error:[/] Target required. Use -t <url> or -t <file>")
        sys.exit(1)
    
    targets = await load_targets(args.target)
    
    preset_config = {}
    if hasattr(args, 'preset') and args.preset:
        preset_config = load_preset(args.preset) or {}
        if not preset_config:
            console.print(f"[bold red]Error:[/] Preset '{args.preset}' not found. Use --list-presets")
            sys.exit(1)
    
    if args.modules:
        modules = args.modules.split(",")
    elif preset_config.get("modules"):
        modules = preset_config["modules"]
    elif hasattr(args, 'chain') and args.chain:
        modules = CHAIN_MODULES.get(args.chain, ALL_MODULES)
    elif args.fast:
        modules = FAST_MODULES
    elif args.deep:
        modules = DEEP_MODULES
    else:
        modules = ALL_MODULES
    
    headers = parse_headers(args.header)
    
    if args.cookies:
        headers["Cookie"] = args.cookies
    
    preset_cfg = preset_config.get("config", {})
    
    config = {
        "threads": args.threads if args.threads != 50 else preset_cfg.get("threads", 50),
        "timeout": args.timeout if args.timeout != 10 else preset_cfg.get("timeout", 10),
        "aggressive": args.aggressive or preset_cfg.get("aggressive", False),
        "stealth": args.stealth or preset_cfg.get("stealth", False),
        "proxy": args.proxy,
        "headers": headers,
        "crawl": args.crawl or preset_cfg.get("crawl", False),
        "crawl_depth": args.crawl_depth if args.crawl_depth != 3 else preset_cfg.get("crawl_depth", 3),
        "callback_host": args.callback_host,
        "exploit": getattr(args, 'exploit', False) or preset_cfg.get("exploit", False),
        "chain": getattr(args, 'chain', None) or preset_cfg.get("chain", None),
        "resume": getattr(args, 'resume', False),
        "verbose": args.verbose,
        "rate_limit": preset_cfg.get("rate_limit", 100),
        "cache_enabled": getattr(args, 'cache', False),
        "cache_ttl": getattr(args, 'cache_ttl', 300),
        "scope_file": getattr(args, 'scope_file', None),
        "include_domains": getattr(args, 'include_domain', None) or [],
        "exclude_domains": getattr(args, 'exclude_domain', None) or [],
        "exclude_patterns": getattr(args, 'exclude_pattern', None) or [],
        "auth_config": getattr(args, 'auth_config', None),
        "workflow": getattr(args, 'workflow', None),
        "workflow_attack": getattr(args, 'workflow_attack', None),
        "oob_manager": oob_manager if getattr(args, 'oob_server', False) else None,
        "analyze_js": getattr(args, 'analyze_js', False),
        "cve_scan": getattr(args, 'cve_scan', False),
        "generate_pocs": getattr(args, 'generate_pocs', False),
        "fuzz_params": getattr(args, 'fuzz_params', False),
        "diff_baseline": getattr(args, 'diff_baseline', False),
    }
    
    if config.get("scope_file") or config.get("include_domains") or config.get("exclude_domains"):
        from core.scope import get_scope_manager
        scope = get_scope_manager(config)
        config["scope_manager"] = scope
    
    if getattr(args, 'dns_brute', False):
        from core.dns_brute import DNSBruteForcer, SubdomainWordlist
        from urllib.parse import urlparse
        
        for t in targets:
            parsed = urlparse(t)
            domain = (parsed.netloc or parsed.path).replace("www.", "")
            if ":" in domain:
                domain = domain.split(":")[0]
            
            parts = domain.split(".")
            base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
            
            console.print(f"\n[bold cyan]DNS Brute Force:[/] {base_domain}")
            
            wordlist = SubdomainWordlist.BUILTIN
            if getattr(args, 'dns_wordlist', None):
                wordlist = SubdomainWordlist.load_from_file(args.dns_wordlist)
            
            bruter = DNSBruteForcer(
                concurrency=getattr(args, 'dns_concurrency', 500),
            )
            
            found_count = [0]
            
            async def on_found(subdomain, ips):
                found_count[0] += 1
                console.print(f"  [green]+[/] {subdomain} -> {', '.join(ips)}")
            
            await bruter.brute(base_domain, wordlist, callback=on_found)
            
            stats = bruter.get_stats()
            console.print(f"\n[bold]Results:[/] {stats['found']} subdomains @ {stats['rate_per_second']:.0f} req/s")
        
        if not getattr(args, 'tech_detect', False) and not args.modules:
            return
    
    if getattr(args, 'tech_detect', False):
        from core.tech_detect import TechFingerprinter
        from core.http import HttpClient
        
        console.print("\n[bold cyan]Technology Detection[/]")
        
        for t in targets:
            async with HttpClient(config) as http:
                fingerprinter = TechFingerprinter(http)
                result = await fingerprinter.fingerprint(t)
                
                tech_table = Table(title=f"Technologies: {t}", box=box.ROUNDED, border_style="cyan")
                tech_table.add_column("Technology", style="bold green")
                tech_table.add_column("Version", style="yellow")
                tech_table.add_column("Category", style="dim")
                tech_table.add_column("Confidence", style="cyan")
                
                for tech in result.get("technologies", []):
                    tech_table.add_row(
                        tech["name"],
                        tech.get("version") or "-",
                        tech["category"],
                        f"{tech['confidence']}%"
                    )
                
                console.print(tech_table)
                
                if result.get("recommended_modules"):
                    console.print(f"\n[bold]Recommended Modules:[/] {', '.join(result['recommended_modules'])}")
        
        if not args.modules and not getattr(args, 'smart', False):
            return
    
    if getattr(args, 'smart', False) and not args.modules:
        from core.tech_detect import TechFingerprinter
        from core.http import HttpClient
        
        console.print("\n[bold cyan]Smart Module Selection[/]")
        
        smart_modules = set()
        for t in targets[:1]:
            async with HttpClient(config) as http:
                fingerprinter = TechFingerprinter(http)
                result = await fingerprinter.fingerprint(t)
                
                module_mapping = {
                    "sqli": "sqli", "xss": "xss", "lfi": "lfi", "ssrf": "ssrf",
                    "ssti": "ssti", "cmdi": "cmdi", "xxe": "xxe", "upload": "upload",
                    "deserial": "deserial", "prototype": "prototype", "graphql": "graphql",
                    "api": "apiver", "idor": "idor", "auth": "auth",
                }
                
                for rec in result.get("recommended_modules", []):
                    if rec in module_mapping:
                        smart_modules.add(module_mapping[rec])
                
                tech_names = [t["name"] for t in result.get("technologies", [])]
                console.print(f"  [dim]Detected:[/] {', '.join(tech_names[:10])}")
        
        if smart_modules:
            modules = list(set(modules) | smart_modules)
            console.print(f"  [green]Added modules:[/] {', '.join(smart_modules)}")
    
    config["dns_concurrency"] = getattr(args, 'dns_concurrency', 500)
    
    if getattr(args, 'workflow', None):
        from core.workflow import WorkflowEngine
        from core.http import HttpClient
        from core.auth_manager import create_auth_manager
        
        console.print(f"\n[bold cyan]Workflow Mode:[/] {args.workflow}")
        
        async with HttpClient(config) as http:
            auth_manager = None
            if getattr(args, 'auth_config', None):
                auth_data = yaml.safe_load(open(args.auth_config))
                auth_manager = create_auth_manager(http, auth_data.get("authentication", {}))
                auth_manager.set_base_url(targets[0])
                auth_manager.add_credentials_from_dict(auth_data.get("authentication", {}).get("roles", {}))
                console.print(f"  [dim]Auth config loaded with {len(auth_manager.credentials)} roles[/]")
            
            engine = WorkflowEngine(http, auth_manager, targets[0])
            workflow = engine.load_workflow(args.workflow)
            
            console.print(f"  [dim]Workflow:[/] {workflow.name} - {workflow.description}")
            console.print(f"  [dim]Steps:[/] {len(workflow.steps)}, [dim]Attacks:[/] {len(workflow.attacks)}")
            
            if getattr(args, 'workflow_attack', None):
                result = await engine.execute_attack(workflow, args.workflow_attack)
                if result.success:
                    console.print(f"\n[bold red]VULNERABILITY FOUND:[/] {result.vulnerability}")
                    console.print(f"  Evidence: {result.evidence}")
                else:
                    console.print(f"\n[green]Attack '{args.workflow_attack}' did not find vulnerability[/]")
            else:
                results = await engine.fuzz_workflow(workflow)
                vulns_found = [r for r in results if r.success]
                
                if vulns_found:
                    console.print(f"\n[bold red]Found {len(vulns_found)} vulnerabilities:[/]")
                    for r in vulns_found:
                        console.print(f"  - [{r.severity}] {r.attack_name}: {r.vulnerability}")
                else:
                    console.print(f"\n[green]No vulnerabilities found in workflow attacks[/]")
        
        return
    
    if getattr(args, 'analyze_js', False):
        from core.js_analyzer import create_analyzer
        from core.http import HttpClient
        
        console.print("\n[bold cyan]JavaScript Analysis[/]")
        
        for t in targets:
            async with HttpClient(config) as http:
                analyzer = create_analyzer()
                result = await analyzer.analyze_url(http, t)
                
                console.print(f"\n[bold]Target:[/] {t}")
                console.print(f"  [dim]Scripts analyzed:[/] {result.scripts_analyzed}")
                
                if result.endpoints:
                    console.print(f"\n  [bold green]Endpoints Found ({len(result.endpoints)}):[/]")
                    for ep in result.endpoints[:10]:
                        console.print(f"    [{ep.method}] {ep.url}")
                        if ep.parameters:
                            console.print(f"        Params: {', '.join(ep.parameters[:5])}")
                
                if result.secrets:
                    console.print(f"\n  [bold red]Secrets Found ({len(result.secrets)}):[/]")
                    for secret in result.secrets[:10]:
                        console.print(f"    [{secret.severity}] {secret.secret_type}: {secret.value[:30]}...")
                
                if result.dom_sinks:
                    tainted = [s for s in result.dom_sinks if s.tainted]
                    console.print(f"\n  [bold yellow]DOM Sinks ({len(result.dom_sinks)}, {len(tainted)} tainted):[/]")
                    for sink in tainted[:5]:
                        console.print(f"    [{sink.sink_type}] Line {sink.line_number} - Source: {sink.source}")
                
                if result.frameworks_detected:
                    console.print(f"\n  [dim]Frameworks:[/] {', '.join(result.frameworks_detected)}")
        
        if not args.modules:
            return
    
    if getattr(args, 'cve_scan', False):
        from core.cve_db import create_cve_db
        from core.http import HttpClient
        
        console.print("\n[bold cyan]CVE Scanning[/]")
        
        cve_db = create_cve_db()
        console.print(f"  [dim]Loaded {cve_db.get_cve_count()} CVEs for {len(cve_db.get_all_products())} products[/]")
        
        for t in targets:
            async with HttpClient(config) as http:
                resp = await http.get(t)
                fingerprints = {
                    "headers": str(resp.get("headers", {})),
                    "body": resp.get("text", "")[:5000],
                }
                
                identified = cve_db.identify_product(fingerprints)
                
                if identified:
                    console.print(f"\n[bold]Target:[/] {t}")
                    for product, version in identified:
                        cves = cve_db.get_cves_for_product(product, version)
                        console.print(f"  [cyan]{product}[/] {version or '(unknown version)'}: {len(cves)} potential CVEs")
                        
                        for cve in cves[:5]:
                            result = await cve_db.test_cve(http, t, cve, args.callback_host)
                            status = "[red]VULNERABLE[/]" if result.vulnerable else "[dim]Not vulnerable[/]"
                            console.print(f"    {cve.id} (CVSS {cve.cvss}): {status}")
        
        if not args.modules:
            return
    
    chain_mode = getattr(args, 'chain', None)
    mode = f"Chain: {chain_mode}" if chain_mode else "Aggressive" if args.aggressive else "Stealth" if args.stealth else "Fast" if args.fast else "Deep" if args.deep else "Smart" if getattr(args, 'smart', False) else "Normal"
    
    console.print(Panel(
        f"[bold]Target(s):[/] {len(targets)}\n"
        f"[bold]Modules:[/] {len(modules)} ({', '.join(modules[:5])}{'...' if len(modules) > 5 else ''})\n"
        f"[bold]Threads:[/] {config['threads']}\n"
        f"[bold]Mode:[/] {mode}\n"
        f"[bold]Crawl:[/] {'Enabled (depth: ' + str(args.crawl_depth) + ')' if args.crawl else 'Disabled'}",
        title="Scan Configuration",
        border_style="cyan"
    ))
    
    scanner = Scanner(targets, modules, config)
    
    if hasattr(args, 'collab_client') and args.collab_client:
        console.print(f"[cyan]Connecting to collaboration server: {args.collab_client}[/]")
        connected = await scanner.connect_collab(args.collab_client)
        if connected:
            console.print("[green]Connected to collab server - findings will be shared in real-time[/]")
        else:
            console.print("[yellow]Warning: Could not connect to collab server, continuing solo[/]")
    
    if args.crawl:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            crawl_task = progress.add_task("[yellow]Crawling...", total=None)
            crawl_results = await scanner.crawl_targets()
            progress.update(crawl_task, completed=True, total=1)
            
            total_urls = sum(len(r.get("urls", [])) for r in crawl_results.values())
            total_forms = sum(len(r.get("forms", [])) for r in crawl_results.values())
            total_params = sum(len(r.get("params", {})) for r in crawl_results.values())
            
            console.print(f"  [dim]Discovered:[/] {total_urls} URLs, {total_forms} forms, {total_params} endpoints with params")
    
    total_tasks = len(modules) * len(scanner.get_all_targets())
    completed_tasks = 0
    findings_count = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    recent_findings = []
    
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )
    task = progress.add_task("[cyan]Scanning...", total=total_tasks)
    
    def make_display():
        progress_pct = (completed_tasks / max(total_tasks, 1)) * 100
        stats_panel = generate_stats_table(scanner, findings_count, severity_counts, progress_pct)
        
        findings_lines = []
        for f in recent_findings[-8:]:
            color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}.get(f["severity"], "white")
            findings_lines.append(f"[{color}][{f['severity']}][/] {f['module']}: {f['description'][:60]}")
        
        findings_text = "\n".join(findings_lines) if findings_lines else "[dim]No findings yet...[/]"
        findings_panel = Panel(findings_text, title="Recent Findings", border_style="green", padding=(0, 1))
        
        return Group(stats_panel, progress, findings_panel)
    
    with Live(make_display(), console=console, refresh_per_second=4, transient=True) as live:
        async for update in scanner.run():
            if update["type"] == "progress":
                completed_tasks += 1
                progress.update(task, completed=completed_tasks)
            elif update["type"] == "finding":
                findings_count += 1
                severity_counts[update["severity"]] = severity_counts.get(update["severity"], 0) + 1
                recent_findings.append(update)
            elif update["type"] == "status" and args.verbose:
                pass
            
            live.update(make_display())
    
    results = scanner.get_results()
    
    summary_table = Table(title="Scan Summary", box=box.ROUNDED, border_style="green")
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="right")
    
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for r in results:
        severity_counts[r["severity"]] = severity_counts.get(r["severity"], 0) + 1
    
    for sev, count in severity_counts.items():
        color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}.get(sev, "white")
        if count > 0:
            summary_table.add_row(f"[{color}]{sev}[/]", str(count))
    
    console.print(summary_table)
    
    if args.output:
        reporter = Reporter(results, targets, modules)
        saved = []
        report_format = getattr(args, 'format', 'html')
        
        if getattr(args, 'generate_pocs', False):
            poc_result = await reporter.save_with_pocs(
                args.output,
                include_formats=["html", "json", "sarif", "markdown"] if report_format == "all" else [report_format]
            )
            console.print(f"\n[bold green]Reports with PoCs saved:[/] {poc_result['directory']}")
            console.print(f"  Generated {poc_result['poc_count']} PoC files")
            saved = poc_result['files']
        else:
            if report_format in ["html", "all"]:
                html_path = await reporter.save_html(f"{args.output}.html")
                saved.append(html_path)
            
            if report_format in ["json", "all"]:
                json_path = await reporter.save_json(f"{args.output}.json")
                saved.append(json_path)
            
            if report_format in ["md", "all"]:
                md_path = await reporter.save_markdown(f"{args.output}.md")
                saved.append(md_path)
            
            if report_format in ["jira", "all"]:
                jira_path = await reporter.save_jira_csv(f"{args.output}_jira.csv")
                saved.append(jira_path)
            
            if report_format in ["obsidian", "all"] or getattr(args, 'obsidian', False):
                import os
                vault_path = getattr(args, 'obsidian_vault', None) or os.environ.get("BLACK_OBSIDIAN_VAULT")
                obsidian_result = await reporter.save_obsidian(vault_path)
                saved.append(obsidian_result["main_report"])
                console.print(f"[bold purple]Obsidian:[/] {obsidian_result['directory']} ({len(obsidian_result['findings'])} findings)")
            
            console.print(f"\n[bold green]Reports saved:[/] {', '.join(saved)}")
    
    crit_high = severity_counts["CRITICAL"] + severity_counts["HIGH"]
    if crit_high > 0:
        console.print(f"\n[bold red]⚠ {crit_high} CRITICAL/HIGH findings require immediate attention![/]")
    
    console.print(f"\n[bold cyan]Scan complete.[/] Found [bold]{len(results)}[/] potential vulnerabilities.")
    
    if getattr(args, 'ci', False) or getattr(args, 'sarif', None) or getattr(args, 'junit', None):
        from core.cicd import CICDReporter, CICDConfig
        from pathlib import Path as P
        
        cicd_config = CICDConfig(
            fail_on=getattr(args, 'fail_on', 'HIGH'),
            exit_codes=getattr(args, 'ci', False),
            sarif_output=P(args.sarif) if getattr(args, 'sarif', None) else None,
            junit_output=P(args.junit) if getattr(args, 'junit', None) else None,
        )
        
        cicd = CICDReporter(cicd_config)
        cicd.write_outputs(results, targets[0] if targets else "")
        
        if getattr(args, 'sarif', None):
            console.print(f"[green]SARIF report saved:[/] {args.sarif}")
        if getattr(args, 'junit', None):
            console.print(f"[green]JUnit report saved:[/] {args.junit}")
        
        if getattr(args, 'ci', False):
            exit_code = cicd.calculate_exit_code(results)
            if exit_code != 0:
                console.print(f"\n[bold red]CI/CD: Exiting with code {exit_code}[/]")
            sys.exit(exit_code)


def run():
    asyncio.run(main())
