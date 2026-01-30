# LANTERN Test Lab

Pre-configured vulnerable web applications for testing LANTERN's scanning capabilities.

## Quick Start

### Windows
```cmd
cd lab
start-lab.bat
```

Or PowerShell:
```powershell
cd lab
.\start-lab.ps1
```

### Linux/Mac
```bash
cd lab
chmod +x start-lab.sh
./start-lab.sh
```

## Lab Targets

| Application | URL | Vulnerabilities |
|-------------|-----|-----------------|
| **Juice Shop** | http://localhost:3001 | XSS, SQLi, JWT attacks, Auth bypass, IDOR, File upload, NoSQL injection |
| **WebGoat** | http://localhost:3002 | IDOR, XXE, Deserialization, Path traversal, JWT, SQLi, XSS |
| **Mutillidae** | http://localhost:3003 | LDAP injection, XML injection, SSRF, SQLi, XSS, CMDi, CSRF |

## Test Commands

### Full Aggressive Scan
```bash
lantern -t http://localhost:3001 --aggressive --exploit --crawl -o juice_shop_full
```

### Module-Specific Testing

**SQL Injection:**
```bash
lantern -t http://localhost:3002 -m sqli --aggressive --exploit --deep
```

**XSS + DOM:**
```bash
lantern -t http://localhost:3001 -m xss,dom,prototype --aggressive --exploit --crawl
```

**Command Injection + SSTI:**
```bash
lantern -t http://localhost:3002 -m cmdi,ssti --aggressive --exploit --oob-server
```

**XXE + Deserialization:**
```bash
lantern -t http://localhost:3003 -m xxe,deserial --aggressive --exploit --oob-server
```

**LDAP Injection:**
```bash
lantern -t http://localhost:3004 -m ldap --aggressive --exploit
```

**JWT Attacks:**
```bash
lantern -t http://localhost:3001 -m jwt --aggressive --exploit
```

### Attack Chain Testing

**RCE Chain:**
```bash
lantern -t http://localhost:3002 --chain rce --exploit --oob-server
```

**Auth Bypass Chain:**
```bash
lantern -t http://localhost:3001 --chain auth_bypass --exploit
```

**Data Theft Chain:**
```bash
lantern -t http://localhost:3002 --chain data_theft --exploit
```

### Workflow Testing

**Payment Bypass (Hackazon):**
```bash
lantern -t http://localhost:3005 --workflow workflows/payment_bypass.yml
```

**Auth Bypass (Juice Shop):**
```bash
lantern -t http://localhost:3001 --workflow workflows/auth_bypass.yml
```

**File Upload (DVWA):**
```bash
lantern -t http://localhost:3002 --workflow workflows/file_upload.yml
```

**SSRF Chain (Mutillidae):**
```bash
lantern -t http://localhost:3004 --workflow workflows/ssrf_chain.yml --oob-server
```

**SQLi Escalation (DVWA):**
```bash
lantern -t http://localhost:3002 --workflow workflows/sqli_escalate.yml
```

### OOB Blind Testing
```bash
lantern -t http://localhost:3004 --oob-server -m ssrf,xxe,sqli,cmdi --aggressive --exploit
```

### JavaScript Analysis (Juice Shop)
```bash
lantern -t http://localhost:3001 --analyze-js -m xss,dom,secrets --exploit
```

## Lab Management

**Check status:**
```bash
./start-lab.sh status      # Linux/Mac
start-lab.bat status       # Windows
```

**Stop lab:**
```bash
./start-lab.sh stop        # Linux/Mac
start-lab.bat stop         # Windows
```

**Restart lab:**
```bash
./start-lab.sh restart     # Linux/Mac
start-lab.bat restart      # Windows
```

## Default Credentials

| Application | Username | Password |
|-------------|----------|----------|
| DVWA | admin | password |
| WebGoat | webgoat | webgoat |
| Mutillidae | admin | admin |
| Juice Shop | (register any account) | - |

## DVWA Setup

After first start, navigate to http://localhost:3002 and:
1. Click "Create / Reset Database"
2. Login with admin / password
3. Set security level to "Low" for initial testing

## Troubleshooting

**Containers won't start:**
```bash
docker logs lantern-juice-shop
docker logs lantern-dvwa
```

**Port conflicts:**
Edit `docker-compose.yml` and change the left side of port mappings (e.g., `3001:3000` to `4001:3000`)

**Out of disk space:**
```bash
docker system prune -a
```

## Requirements

- Docker Desktop (Windows/Mac) or Docker Engine (Linux)
- Docker Compose v2+
- ~5GB disk space for all images
- 4GB+ RAM recommended
