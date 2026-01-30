param(
    [Parameter(Position=0)]
    [ValidateSet("start", "stop", "status", "restart")]
    [string]$Action = "start"
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "    LANTERN Vulnerable Lab Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Set-Location $PSScriptRoot

function Test-Docker {
    try {
        $null = docker info 2>&1
        if ($LASTEXITCODE -ne 0) { throw }
        Write-Host "[OK] Docker is running" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Docker is not running. Please start Docker Desktop." -ForegroundColor Red
        return $false
    }
}

function Test-Compose {
    try {
        $null = docker compose version 2>&1
        if ($LASTEXITCODE -eq 0) {
            $script:ComposeCmd = "docker compose"
            Write-Host "[OK] Docker Compose available" -ForegroundColor Green
            return $true
        }
    }
    catch {}
    
    try {
        $null = docker-compose version 2>&1
        if ($LASTEXITCODE -eq 0) {
            $script:ComposeCmd = "docker-compose"
            Write-Host "[OK] Docker Compose available" -ForegroundColor Green
            return $true
        }
    }
    catch {}
    
    Write-Host "[ERROR] Docker Compose not found" -ForegroundColor Red
    return $false
}

function Start-Lab {
    Write-Host ""
    Write-Host "[*] Starting vulnerable lab containers..." -ForegroundColor Yellow
    Write-Host "    This may take a few minutes on first run (downloading images)..." -ForegroundColor Gray
    Write-Host ""
    
    if ($ComposeCmd -eq "docker compose") {
        docker compose up -d
    } else {
        docker-compose up -d
    }
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "    Lab Started Successfully!" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Available targets:" -ForegroundColor White
        Write-Host ""
        Write-Host "  Juice Shop     " -NoNewline; Write-Host "http://localhost:3001" -ForegroundColor Cyan -NoNewline; Write-Host "  (XSS, SQLi, JWT, Auth bypass)"
        Write-Host "  DVWA           " -NoNewline; Write-Host "http://localhost:3002" -ForegroundColor Cyan -NoNewline; Write-Host "  (SQLi, XSS, CSRF, CMDi, Upload)"
        Write-Host "  WebGoat        " -NoNewline; Write-Host "http://localhost:3003" -ForegroundColor Cyan -NoNewline; Write-Host "  (IDOR, XXE, Deserialization)"
        Write-Host "  Mutillidae     " -NoNewline; Write-Host "http://localhost:3004" -ForegroundColor Cyan -NoNewline; Write-Host "  (LDAP, XML, SSRF, SQLi)"
        Write-Host "  Hackazon       " -NoNewline; Write-Host "http://localhost:3005" -ForegroundColor Cyan -NoNewline; Write-Host "  (E-commerce, Payment bypass)"
        Write-Host "  XVWA           " -NoNewline; Write-Host "http://localhost:3006" -ForegroundColor Cyan -NoNewline; Write-Host "  (XSS, SQLi, SSRF, LFI)"
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "    Quick Test Commands" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "# Full scan on Juice Shop:" -ForegroundColor Gray
        Write-Host "lantern -t http://localhost:3001 --aggressive --exploit -o juice_report" -ForegroundColor White
        Write-Host ""
        Write-Host "# SQLi + XSS on DVWA:" -ForegroundColor Gray
        Write-Host "lantern -t http://localhost:3002 -m sqli,xss,cmdi --aggressive --exploit" -ForegroundColor White
        Write-Host ""
        Write-Host "# Auth bypass workflow:" -ForegroundColor Gray
        Write-Host "lantern -t http://localhost:3001 --workflow workflows/auth_bypass.yml" -ForegroundColor White
        Write-Host ""
        Write-Host "# OOB blind testing:" -ForegroundColor Gray
        Write-Host "lantern -t http://localhost:3004 --oob-server -m ssrf,xxe,sqli --exploit" -ForegroundColor White
        Write-Host ""
    }
    else {
        Write-Host "[ERROR] Failed to start lab. Check Docker logs." -ForegroundColor Red
        exit 1
    }
}

function Stop-Lab {
    Write-Host "[*] Stopping lab containers..." -ForegroundColor Yellow
    if ($ComposeCmd -eq "docker compose") {
        docker compose down
    } else {
        docker-compose down
    }
    Write-Host "[OK] Lab stopped" -ForegroundColor Green
}

function Get-LabStatus {
    Write-Host "[*] Lab status:" -ForegroundColor Yellow
    docker ps --filter "name=lantern-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
}

if (-not (Test-Docker)) { exit 1 }
if (-not (Test-Compose)) { exit 1 }

switch ($Action) {
    "start" {
        Start-Lab
    }
    "stop" {
        Stop-Lab
    }
    "status" {
        Get-LabStatus
    }
    "restart" {
        Stop-Lab
        Start-Lab
    }
}
