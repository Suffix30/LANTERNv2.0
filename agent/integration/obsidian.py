#!/usr/bin/env python3
import os
import json
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any

class ObsidianIntegration:
    
    def __init__(self, vault_path: Optional[str] = None):
        self.vault_path = Path(vault_path) if vault_path else self._detect_vault()
        self.templates_dir = Path(__file__).parent.parent / "obsidian_templates"
        
    def _detect_vault(self) -> Optional[Path]:
        env_path = os.environ.get("BLACK_OBSIDIAN_VAULT")
        if env_path and Path(env_path).exists():
            return Path(env_path)
        
        common_locations = [
            Path.home() / "Documents" / "Obsidian" / "Security",
            Path.home() / "Documents" / "Security Vault",
            Path.home() / "Obsidian" / "Security",
            Path.home() / "Security",
        ]
        
        for loc in common_locations:
            if loc.exists() and (loc / ".obsidian").exists():
                return loc
        
        return None
    
    def init_vault(self, vault_path: str, vault_name: str = "Security Vault") -> Dict:
        if vault_path.startswith("~"):
            vault_path = str(Path.home() / vault_path[2:])
        vault = Path(vault_path) / vault_name
        
        folders = [
            "Targets/Bug Bounty",
            "Targets/HTB/Easy",
            "Targets/HTB/Medium", 
            "Targets/HTB/Hard",
            "Targets/HTB/Insane",
            "Targets/THM/Easy",
            "Targets/THM/Medium",
            "Targets/THM/Hard",
            "Targets/VulnLab",
            "Targets/PG Practice",
            "Targets/Custom Labs",
            "Writeups/HTB",
            "Writeups/THM",
            "Writeups/CTF",
            "Writeups/Bug Bounty",
            "Methodology/Web",
            "Methodology/Network",
            "Methodology/AD",
            "Methodology/Linux Privesc",
            "Methodology/Windows Privesc",
            "Payloads/SQLi",
            "Payloads/XSS",
            "Payloads/SSRF",
            "Payloads/LFI",
            "Payloads/RCE",
            "Payloads/Custom",
            "Tools",
            "Cheatsheets",
            "LANTERN Reports",
            "Overwatch Sessions",
            "Templates",
            "Assets",
        ]
        
        for folder in folders:
            (vault / folder).mkdir(parents=True, exist_ok=True)
        
        (vault / ".obsidian").mkdir(exist_ok=True)
        
        self._create_templates(vault)
        self._create_mocs(vault)
        self._create_tool_notes(vault)
        
        self.vault_path = vault
        
        return {
            "status": "success",
            "vault_path": str(vault),
            "folders_created": len(folders),
            "message": f"Vault initialized at {vault}"
        }
    
    def _create_templates(self, vault: Path):
        templates = {
            "Target Template.md": '''---
tags: [target, {{platform}}, {{difficulty}}]
platform: {{platform}}
ip: {{ip}}
hostname: {{hostname}}
os: {{os}}
difficulty: {{difficulty}}
status: not-started
pwned_user: false
pwned_root: false
date_started: {{date}}
---

# {{name}}

## Quick Info
| Property | Value |
|----------|-------|
| Platform | [[{{platform}}]] |
| IP | `{{ip}}` |
| Hostname | `{{hostname}}` |
| OS | {{os}} |
| Difficulty | {{difficulty}} |

## Recon

### Port Scan
```bash
nmap -sCV -oA nmap/{{name}} {{ip}}
```

### Web Enumeration
```bash
lantern -t http://{{ip}} --crawl --smart -o {{name}}_scan
```

## Findings
- 

## Exploitation

### Initial Access


### Privilege Escalation


## Flags
- [ ] User: 
- [ ] Root: 

## Lessons Learned

## References
- 
''',
            "Finding Template.md": '''---
tags: [finding, {{severity}}, {{vuln_type}}]
target: "[[{{target}}]]"
severity: {{severity}}
vuln_type: {{vuln_type}}
status: {{status}}
date_found: {{date}}
---

# {{title}}

## Summary
{{summary}}

## Affected Component
- URL: `{{url}}`
- Parameter: `{{parameter}}`
- Method: {{method}}

## Proof of Concept

### Request
```http
{{request}}
```

### Response
```http
{{response}}
```

## Reproduction Steps
1. 
2. 
3. 

## Impact
{{impact}}

## Remediation
{{remediation}}

## Payloads Used
{{payloads}}

## Related
- [[{{target}}]]
''',
            "Writeup Template.md": '''---
tags: [writeup, {{platform}}, {{difficulty}}]
platform: {{platform}}
box_name: {{name}}
difficulty: {{difficulty}}
os: {{os}}
date_pwned: {{date}}
time_to_pwn: 
---

# {{name}} - Writeup

## Box Info
| Property | Value |
|----------|-------|
| Platform | {{platform}} |
| Difficulty | {{difficulty}} |
| OS | {{os}} |
| Release Date | |
| Retire Date | |

## Summary
Brief overview of the box and attack path.

## Enumeration

### Nmap

### Web

### Other Services

## Foothold

## User Flag

## Privilege Escalation

## Root Flag

## Lessons Learned
- 

## Tools Used
- [[LANTERN]]
- 

## References
- 
''',
            "Bug Bounty Report Template.md": '''---
tags: [bounty, {{program}}, {{severity}}]
program: {{program}}
severity: {{severity}}
status: {{status}}
submitted_date: {{date}}
bounty_amount: 
---

# {{title}}

## Program
[[{{program}}]]

## Vulnerability Type
{{vuln_type}}

## Severity
{{severity}}

## Summary
One paragraph description.

## Steps to Reproduce
1. 
2. 
3. 

## Proof of Concept

### Request
```http

```

### Response
```http

```

## Impact
What can an attacker do with this?

## Remediation
How should they fix it?

## Timeline
| Date | Event |
|------|-------|
| {{date}} | Reported |
| | Triaged |
| | Fixed |
| | Bounty Paid |

## Attachments
- 
''',
            "Session Log Template.md": '''---
tags: [session, {{target}}]
target: "[[{{target}}]]"
date: {{date}}
duration: 
status: {{status}}
---

# Session: {{target}} - {{date}}

## Objective
What are you trying to accomplish?

## Progress

### Recon


### Findings


### Exploitation Attempts


## Next Steps
- [ ] 

## Notes

## Commands Run
```bash

```

## LANTERN Output
![[LANTERN Reports/{{target}}_scan.md]]
''',
        }
        
        template_dir = vault / "Templates"
        for name, content in templates.items():
            (template_dir / name).write_text(content, encoding="utf-8")
    
    def _create_mocs(self, vault: Path):
        home_md = '''# Security Vault

Welcome to your security knowledge base.

## Quick Links
- [[Targets MOC|Active Targets]]
- [[Writeups MOC|Writeups]]
- [[Methodology MOC|Methodology]]
- [[Tools MOC|Tools]]
- [[Payloads MOC|Payloads]]

## Recent Activity
```dataview
TABLE file.mtime as "Modified", tags
FROM ""
SORT file.mtime DESC
LIMIT 10
```

## Stats
```dataview
TABLE length(rows) as Count
FROM "Targets"
GROUP BY platform
```
'''
        
        targets_moc = '''# Targets MOC

## By Platform

### [[HackTheBox]]
```dataview
TABLE difficulty, status, pwned_user, pwned_root
FROM "Targets/HTB"
SORT difficulty ASC
```

### [[TryHackMe]]
```dataview
TABLE difficulty, status
FROM "Targets/THM"
SORT difficulty ASC
```

### [[Bug Bounty]]
```dataview
TABLE status, severity
FROM "Targets/Bug Bounty"
```

## By Status
### In Progress
```dataview
LIST
FROM "Targets"
WHERE status = "in-progress"
```

### Completed
```dataview
LIST
FROM "Targets"
WHERE pwned_root = true
```
'''
        
        methodology_moc = '''# Methodology MOC

## Phases
1. [[Recon]]
2. [[Enumeration]]
3. [[Exploitation]]
4. [[Post Exploitation]]
5. [[Privilege Escalation]]
6. [[Reporting]]

## By Category
- [[Web Testing]]
- [[Network Pentesting]]
- [[Active Directory]]
- [[Linux Privesc]]
- [[Windows Privesc]]
- [[Mobile Testing]]
- [[API Testing]]

## Cheatsheets
```dataview
LIST
FROM "Cheatsheets"
```
'''
        
        (vault / "Home.md").write_text(home_md, encoding="utf-8")
        (vault / "Targets MOC.md").write_text(targets_moc, encoding="utf-8")
        (vault / "Methodology MOC.md").write_text(methodology_moc, encoding="utf-8")
    
    def _create_tool_notes(self, vault: Path):
        lantern_note = '''---
tags: [tool, scanner, web]
---

# LANTERN

Web vulnerability scanner with automatic exploitation.

## Quick Reference

### Basic Scan
```bash
lantern -t https://target.com -o report
```

### Full Scan with Crawling
```bash
lantern -t https://target.com --crawl --deep --exploit -o report
```

### Specific Modules
```bash
lantern -t https://target.com -m sqli,xss,ssrf --aggressive
```

### Presets
```bash
lantern -t https://target.com --preset fast
lantern -t https://target.com --preset thorough
lantern -t https://target.com --preset api
```

### Attack Chains
```bash
lantern -t https://target.com --chain rce
lantern -t https://target.com --chain auth_bypass
lantern -t https://target.com --chain data_theft
```

## Agent BLACK

### Chat Mode
```bash
black chat
```

### Overwatch (Situational Awareness)
```bash
black overwatch --snapshot    # One-time analysis
black overwatch --watch       # Continuous monitoring
```

### Autonomous Scanning
```bash
black autonomous https://target.com "find SQL injection"
```

## Modules
62 modules covering injection, auth, API, recon, and business logic.

## Links
- [GitHub](https://github.com/Suffix30/LANTERNv2.0)
- [[LANTERN Reports]]
'''
        
        (vault / "Tools" / "LANTERN.md").write_text(lantern_note, encoding="utf-8")
    
    def export_lantern_report(self, report_data: Dict, target_name: str) -> Path:
        if not self.vault_path:
            raise ValueError("No Obsidian vault configured")
        
        date_str = datetime.now().strftime("%Y-%m-%d")
        sanitized_name = re.sub(r'[^\w\-.]', '_', target_name)
        
        report_dir = self.vault_path / "LANTERN Reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        
        findings_summary = []
        if "findings" in report_data:
            for finding in report_data["findings"]:
                severity = finding.get("severity", "INFO")
                title = finding.get("title", "Unknown")
                findings_summary.append(f"- **{severity}**: {title}")
        
        content = f'''---
tags: [lantern, scan, {sanitized_name}]
target: {target_name}
scan_date: {date_str}
total_findings: {len(report_data.get("findings", []))}
---

# LANTERN Scan: {target_name}

## Scan Info
| Property | Value |
|----------|-------|
| Target | `{target_name}` |
| Date | {date_str} |
| Findings | {len(report_data.get("findings", []))} |

## Findings Summary
{chr(10).join(findings_summary) if findings_summary else "No findings"}

## Details
'''
        
        if "findings" in report_data:
            for finding in report_data["findings"]:
                content += f'''
### {finding.get("title", "Unknown")}
- **Severity**: {finding.get("severity", "INFO")}
- **URL**: `{finding.get("url", "N/A")}`
- **Description**: {finding.get("description", "N/A")}

'''
        
        report_path = report_dir / f"{sanitized_name}_{date_str}.md"
        report_path.write_text(content, encoding="utf-8")
        
        return report_path
    
    def export_overwatch_session(self, analysis: str, context: Dict) -> Path:
        if not self.vault_path:
            raise ValueError("No Obsidian vault configured")
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
        
        session_dir = self.vault_path / "Overwatch Sessions"
        session_dir.mkdir(parents=True, exist_ok=True)
        
        terminals_info = []
        for term in context.get("terminals", [])[:5]:
            cwd = term.get("cwd", "unknown")
            folder = cwd.split("\\")[-1] if "\\" in cwd else cwd.split("/")[-1]
            terminals_info.append(f"- `{folder}`")
        
        content = f'''---
tags: [overwatch, session]
date: {datetime.now().strftime("%Y-%m-%d")}
time: {datetime.now().strftime("%H:%M")}
terminals: {len(context.get("terminals", []))}
---

# Overwatch Session - {timestamp}

## Environment
- Terminals: {len(context.get("terminals", []))}
- Browser Tabs: {len(context.get("browser_tabs", []))}
- Recent Files: {len(context.get("recent_reports", []))}

## Active Terminals
{chr(10).join(terminals_info) if terminals_info else "None detected"}

## Analysis
```
{analysis}
```

## Notes

'''
        
        session_path = session_dir / f"session_{timestamp}.md"
        session_path.write_text(content, encoding="utf-8")
        
        return session_path
    
    def create_target_note(
        self,
        name: str,
        platform: str = "Custom",
        ip: str = "",
        hostname: str = "",
        os: str = "Unknown",
        difficulty: str = "Unknown"
    ) -> Path:
        if not self.vault_path:
            raise ValueError("No Obsidian vault configured")
        
        platform_map = {
            "htb": "Targets/HTB",
            "hackthebox": "Targets/HTB",
            "thm": "Targets/THM",
            "tryhackme": "Targets/THM",
            "vulnlab": "Targets/VulnLab",
            "pg": "Targets/PG Practice",
            "bounty": "Targets/Bug Bounty",
        }
        
        folder = platform_map.get(platform.lower(), f"Targets/{platform}")
        target_dir = self.vault_path / folder
        target_dir.mkdir(parents=True, exist_ok=True)
        
        date_str = datetime.now().strftime("%Y-%m-%d")
        sanitized_name = re.sub(r'[^\w\-.]', '_', name)
        
        content = f'''---
tags: [target, {platform.lower()}, {difficulty.lower()}]
platform: {platform}
ip: {ip}
hostname: {hostname}
os: {os}
difficulty: {difficulty}
status: not-started
pwned_user: false
pwned_root: false
date_started: {date_str}
---

# {name}

## Quick Info
| Property | Value |
|----------|-------|
| Platform | [[{platform}]] |
| IP | `{ip}` |
| Hostname | `{hostname}` |
| OS | {os} |
| Difficulty | {difficulty} |

## Recon

### Port Scan
```bash
nmap -sCV -oA nmap/{sanitized_name} {ip}
```

### Web Enumeration
```bash
lantern -t http://{ip or hostname} --crawl --smart -o {sanitized_name}_scan
```

## Findings
- 

## Exploitation

### Initial Access


### Privilege Escalation


## Flags
- [ ] User: 
- [ ] Root: 

## Lessons Learned

## References
- 
'''
        
        target_path = target_dir / f"{sanitized_name}.md"
        target_path.write_text(content, encoding="utf-8")
        
        return target_path
    
    def quick_note(self, content: str, target: Optional[str] = None) -> Path:
        if not self.vault_path:
            raise ValueError("No Obsidian vault configured")
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        
        note_content = f'''---
tags: [quick-note]
date: {datetime.now().strftime("%Y-%m-%d")}
target: {f"[[{target}]]" if target else ""}
---

# Quick Note - {timestamp}

{content}
'''
        
        notes_dir = self.vault_path / "Quick Notes"
        notes_dir.mkdir(parents=True, exist_ok=True)
        
        note_path = notes_dir / f"note_{timestamp}.md"
        note_path.write_text(note_content, encoding="utf-8")
        
        return note_path
    
    def read_methodology(self, topic: str) -> Optional[str]:
        if not self.vault_path:
            return None
        
        search_dirs = [
            self.vault_path / "Methodology",
            self.vault_path / "Cheatsheets",
            self.vault_path / "Payloads",
        ]
        
        for search_dir in search_dirs:
            if not search_dir.exists():
                continue
            
            for md_file in search_dir.rglob("*.md"):
                if topic.lower() in md_file.stem.lower():
                    return md_file.read_text(encoding="utf-8")
        
        return None
    
    def get_vault_stats(self) -> Dict:
        if not self.vault_path:
            return {"error": "No vault configured"}
        
        stats = {
            "vault_path": str(self.vault_path),
            "targets": 0,
            "writeups": 0,
            "findings": 0,
            "notes": 0,
        }
        
        targets_dir = self.vault_path / "Targets"
        if targets_dir.exists():
            stats["targets"] = len(list(targets_dir.rglob("*.md")))
        
        writeups_dir = self.vault_path / "Writeups"
        if writeups_dir.exists():
            stats["writeups"] = len(list(writeups_dir.rglob("*.md")))
        
        return stats


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Agent BLACK Obsidian Integration")
    subparsers = parser.add_subparsers(dest="command")
    
    init_parser = subparsers.add_parser("init", help="Initialize a new security vault")
    init_parser.add_argument("path", help="Path to create vault")
    init_parser.add_argument("--name", default="Security Vault", help="Vault name")
    
    target_parser = subparsers.add_parser("target", help="Create a target note")
    target_parser.add_argument("name", help="Target name")
    target_parser.add_argument("--platform", default="Custom", help="Platform (HTB, THM, etc)")
    target_parser.add_argument("--ip", default="", help="Target IP")
    target_parser.add_argument("--os", default="Unknown", help="Operating system")
    target_parser.add_argument("--difficulty", default="Unknown", help="Difficulty level")
    
    note_parser = subparsers.add_parser("note", help="Create a quick note")
    note_parser.add_argument("content", help="Note content")
    note_parser.add_argument("--target", help="Link to target")
    
    stats_parser = subparsers.add_parser("stats", help="Show vault statistics")
    
    args = parser.parse_args()
    
    obsidian = ObsidianIntegration()
    
    if args.command == "init":
        result = obsidian.init_vault(args.path, args.name)
        print(f"[+] {result['message']}")
        print(f"[+] Created {result['folders_created']} folders")
        print(f"\n[*] Set your vault path:")
        print(f'    export BLACK_OBSIDIAN_VAULT="{result["vault_path"]}"')
    
    elif args.command == "target":
        path = obsidian.create_target_note(
            args.name,
            platform=args.platform,
            ip=args.ip,
            os=args.os,
            difficulty=args.difficulty
        )
        print(f"[+] Created target note: {path}")
    
    elif args.command == "note":
        path = obsidian.quick_note(args.content, target=args.target)
        print(f"[+] Created note: {path}")
    
    elif args.command == "stats":
        stats = obsidian.get_vault_stats()
        print(f"Vault: {stats.get('vault_path', 'Not configured')}")
        print(f"Targets: {stats.get('targets', 0)}")
        print(f"Writeups: {stats.get('writeups', 0)}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
