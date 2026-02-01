# LANTERN Command Reference

Complete command reference for LANTERN Web Vulnerability Scanner and Agent BLACK.

## Table of Contents
- [Basic Usage](#basic-usage)
- [Target Options](#target-options)
- [Module Selection](#module-selection)
- [Attack Chains](#attack-chains)
- [Output & Reporting](#output--reporting)
- [Scan Modes](#scan-modes)
- [Advanced Options](#advanced-options)
- [Agent BLACK](#agent-black)

---

## Basic Usage

```bash
# Basic scan
lantern -t https://target.com

# Scan with specific modules
lantern -t https://target.com -m sqli,xss,headers

# Scan with output file
lantern -t https://target.com -o report --format html

# Multiple targets from file
lantern -t targets.txt -m sqli
```

---

## Target Options

| Flag | Description | Example |
|------|-------------|---------|
| `-t, --target` | Target URL or file | `-t https://example.com` |
| `--crawl` | Crawl to discover URLs | `--crawl` |
| `--crawl-depth` | Crawl depth (default: 3) | `--crawl-depth 5` |
| `-H, --header` | Custom header | `-H "Authorization: Bearer token"` |
| `-c, --cookies` | Cookies string | `-c "session=abc123"` |
| `--proxy` | Proxy URL | `--proxy http://127.0.0.1:8080` |

### Examples

```bash
# Scan with authentication header
lantern -t https://api.target.com -H "Authorization: Bearer eyJ..." -m api

# Scan through proxy (Burp/ZAP)
lantern -t https://target.com --proxy http://127.0.0.1:8080

# Crawl and scan
lantern -t https://target.com --crawl --crawl-depth 4 -m sqli,xss
```

---

## Module Selection

### List All Modules

```bash
lantern --list
```

### Core Injection Modules

| Module | Description |
|--------|-------------|
| `sqli` | SQL Injection |
| `xss` | Cross-Site Scripting |
| `ssti` | Server-Side Template Injection |
| `cmdi` | Command Injection |
| `lfi` | Local File Inclusion |
| `xxe` | XML External Entity |
| `ssrf` | Server-Side Request Forgery |
| `crlf` | CRLF Injection |
| `ldap` | LDAP Injection |

### Authentication Modules

| Module | Description |
|--------|-------------|
| `auth` | Authentication bypass |
| `jwt` | JWT vulnerabilities |
| `oauth` | OAuth flaws |
| `mfa` | MFA bypass |
| `session` | Session management |
| `cookie` | Cookie security |
| `csrf` | Cross-Site Request Forgery |

### API & Modern Web

| Module | Description |
|--------|-------------|
| `api` | REST API testing |
| `graphql` | GraphQL vulnerabilities |
| `websocket` | WebSocket testing |
| `cors` | CORS misconfigurations |
| `dom` | DOM-based vulnerabilities |
| `prototype` | Prototype pollution |

### Recon & Discovery

| Module | Description |
|--------|-------------|
| `fingerprint` | Technology fingerprinting |
| `techdetect` | Tech stack detection |
| `subdomain` | Subdomain enumeration |
| `dirbust` | Directory brute force |
| `disclosure` | Information disclosure |
| `secrets` | Secret/credential detection |
| `dork` | Google dork checks |

### Infrastructure

| Module | Description |
|--------|-------------|
| `headers` | Security headers |
| `ssl` | SSL/TLS issues |
| `waf` | WAF detection/bypass |
| `cloud` | Cloud misconfigs |
| `takeover` | Subdomain takeover |
| `cve` | Known CVE scanning |

### Examples

```bash
# Injection testing
lantern -t https://target.com -m sqli,xss,ssti,cmdi

# API security assessment
lantern -t https://api.target.com -m api,graphql,jwt,cors

# Full recon
lantern -t https://target.com -m fingerprint,subdomain,dirbust,disclosure
```

---

## Attack Chains

Pre-configured module combinations for specific attack scenarios.

```bash
lantern --list-chains
```

| Chain | Modules | Use Case |
|-------|---------|----------|
| `auth_bypass` | waf, sqli, ldap, auth, jwt, oauth, mfa, session | Break authentication |
| `data_theft` | waf, sqli, ssrf, lfi, xxe, idor, disclosure, dirbust, cloud | Extract sensitive data |
| `rce` | waf, cmdi, ssti, deserial, upload, ssrf | Remote code execution |
| `xss_chain` | waf, csp, xss, dom, prototype, cors, csrf | Client-side attacks |
| `api_attack` | waf, api, graphql, massassign, jwt, idor | API exploitation |
| `injection` | waf, paramfind, sqli, xss, ssti, cmdi, lfi, xxe, crlf | All injection types |
| `full_recon` | waf, techdetect, fingerprint, subdomain, takeover, cloud, dirbust, disclosure, dork, paramfind, csp | Complete reconnaissance |

### Examples

```bash
# Authentication bypass chain
lantern -t https://target.com --chain auth_bypass

# Data exfiltration chain
lantern -t https://target.com --chain data_theft --exploit

# Full reconnaissance
lantern -t https://target.com --chain full_recon
```

---

## Output & Reporting

| Flag | Description | Example |
|------|-------------|---------|
| `-o, --output` | Output filename | `-o scan_report` |
| `--format` | Report format | `--format html` |
| `--obsidian` | Export to Obsidian | `--obsidian` |
| `--sarif` | SARIF for GitHub/GitLab | `--sarif report.sarif` |
| `--junit` | JUnit XML for CI | `--junit results.xml` |

### Format Options

- `html` - HTML report with styling
- `json` - Machine-readable JSON
- `md` - Markdown format
- `jira` - JIRA-compatible CSV
- `obsidian` - Obsidian markdown
- `all` - Generate all formats

### Examples

```bash
# HTML report
lantern -t https://target.com -o report --format html

# All formats
lantern -t https://target.com -o full_scan --format all

# CI/CD integration
lantern -t https://target.com --ci --sarif results.sarif --fail-on HIGH
```

---

## Scan Modes

| Flag | Description |
|------|-------------|
| `--fast` | Quick checks, minimal payloads |
| `--deep` | Thorough testing, more payloads |
| `--aggressive` | Maximum payloads, WAF bypass |
| `--stealth` | Slow, randomized, evasive |
| `--smart` | Auto-select modules based on tech |

### Presets

```bash
lantern --list-presets
```

| Preset | Description |
|--------|-------------|
| `fast` | Quick security check |
| `thorough` | Comprehensive testing |
| `api` | API-focused assessment |
| `stealth` | Evasive scanning |
| `exploit` | Aggressive with exploitation |

### Examples

```bash
# Fast scan
lantern -t https://target.com --fast

# Deep thorough scan
lantern -t https://target.com --deep --aggressive

# Stealth mode (IDS evasion)
lantern -t https://target.com --stealth

# Use preset
lantern -t https://target.com --preset thorough
```

---

## Advanced Options

### Authentication

```bash
# Using auth config file
lantern -t https://target.com --auth-config auth.yml

# Example auth.yml
# type: bearer
# token: eyJhbGciOiJIUzI1NiIs...
```

### Scope Control

```bash
# Scope file
lantern -t https://target.com --scope-file scope.yml

# Include/exclude domains
lantern -t https://target.com --include-domain api.target.com --exclude-domain cdn.target.com

# Exclude patterns
lantern -t https://target.com --exclude-pattern "logout|signout"
```

### Performance

```bash
# Thread control
lantern -t https://target.com --threads 100 --timeout 15

# With caching
lantern -t https://target.com --cache --cache-ttl 600
```

### Special Features

```bash
# JavaScript analysis
lantern -t https://target.com --analyze-js

# CVE scanning
lantern -t https://target.com --cve-scan

# Parameter fuzzing
lantern -t https://target.com --fuzz-params

# Generate PoC files
lantern -t https://target.com --generate-pocs

# OOB detection server
lantern -t https://target.com --oob-server --callback-host your-server.com
```

---

## Agent BLACK

AI-powered security companion for LANTERN.

### Basic Commands

```bash
# Interactive chat
black chat

# Check status
black status

# List capabilities
black capabilities
```

### Autonomous Mode

```bash
# Full phased attack
black autonomous https://target.com --attack

# Quick exploitation
black autonomous https://target.com --fast

# With LLM planning
black autonomous https://target.com --llm
```

### Adaptive Learning

```bash
# Run improvement cycle
black adapt https://target.com

# Continuous improvement (5 generations)
black adapt https://target.com --continuous 5

# Parallel exploration
black adapt https://target.com --branch 3

# Check status
black adapt --full-status
```

### Goal Management

```bash
# Show current goal
black goals

# Switch goals
black goals --switch accuracy
black goals --switch coverage
black goals --switch precision

# View history
black goals --history
```

### Safety & Validation

```bash
# Safety summary
black safety

# Check specific improvement
black safety --check improvement.json

# View flagged items
black safety --flagged
```

### Visualization

```bash
# ASCII tree
black visualize --tree

# HTML visualization
black visualize --html

# Progress chart
black visualize --progress
```

### Lineage Tracking

```bash
# Show improvement tree
black lineage

# Summary view
black lineage --summary

# Stepping stones
black lineage --stones
```

### Overwatch Mode

```bash
# Interactive analysis
black overwatch

# One-time snapshot
black overwatch --snapshot

# Continuous monitoring
black overwatch --watch --interval 5
```

### Benchmark

```bash
# Run full benchmark
black benchmark

# Filter by tags
black benchmark --tags injection

# Compare results
black benchmark --compare before.json after.json
```

### Transfer Testing

```bash
# Test cross-module transfer
black transfer --module sqli

# Test cross-target transfer
black transfer --target http://other-target.com
```

### PWN/CTF Mode

```bash
# CTF utilities
black pwn

# Decode/encode
black pwn decode <string>

# Hash cracking
black pwn crack <hash>
```

### Obsidian Integration

```bash
# Initialize vault
black obsidian init ~/Documents/Security

# Add target
black obsidian target BoxName --platform HTB --ip 10.10.10.1

# Quick note
black obsidian note "Found SQL injection in login"

# Vault stats
black obsidian stats
```

---

## Quick Reference Card

```bash
# Fast scan
lantern -t URL --fast

# Full scan with report
lantern -t URL -o report --format all

# Injection testing
lantern -t URL -m sqli,xss,ssti --aggressive

# API assessment
lantern -t URL --chain api_attack

# Stealth scan
lantern -t URL --preset stealth

# Agent BLACK attack
black autonomous URL --attack

# CI/CD integration
lantern -t URL --ci --fail-on HIGH --sarif output.sarif
```
