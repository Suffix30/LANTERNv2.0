$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "    LANTERN Full Lab Test Suite" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportDir = "./reports/$timestamp"
New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null

Write-Host "[*] Reports will be saved to: $ReportDir" -ForegroundColor Yellow
Write-Host ""

function Run-Scan {
    param(
        [string]$Name,
        [string]$Target,
        [string]$Modules,
        [string]$Extra = ""
    )
    
    Write-Host "[*] Running: $Name" -ForegroundColor White
    Write-Host "    Target: $Target" -ForegroundColor Gray
    Write-Host "    Modules: $Modules" -ForegroundColor Gray
    
    $cmd = "lantern -t $Target -m $Modules --aggressive --exploit $Extra -o `"$ReportDir/$Name`" --no-banner"
    Invoke-Expression $cmd
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    [OK] Completed: $Name" -ForegroundColor Green
    } else {
        Write-Host "    [WARN] Issues with: $Name" -ForegroundColor Yellow
    }
    Write-Host ""
}

Write-Host "========================================" -ForegroundColor Yellow
Write-Host "    Phase 1: Injection Testing" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Run-Scan -Name "juice_sqli_xss" -Target "http://localhost:3001" -Modules "sqli,xss,dom" -Extra "--crawl"
Run-Scan -Name "dvwa_injections" -Target "http://localhost:3002" -Modules "sqli,xss,cmdi,ssti" -Extra "--deep"
Run-Scan -Name "mutillidae_ldap" -Target "http://localhost:3004" -Modules "ldap,sqli,xss"

Write-Host "========================================" -ForegroundColor Yellow
Write-Host "    Phase 2: Auth & Session Testing" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Run-Scan -Name "juice_auth" -Target "http://localhost:3001" -Modules "jwt,auth,session,idor" -Extra "--crawl"
Run-Scan -Name "webgoat_auth" -Target "http://localhost:3003" -Modules "jwt,session,csrf"

Write-Host "========================================" -ForegroundColor Yellow
Write-Host "    Phase 3: RCE Module Testing" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Run-Scan -Name "dvwa_rce" -Target "http://localhost:3002" -Modules "cmdi,ssti,upload,deserial" -Extra "--oob-server"
Run-Scan -Name "xvwa_rce" -Target "http://localhost:3006" -Modules "cmdi,lfi,ssrf,xxe" -Extra "--oob-server"

Write-Host "========================================" -ForegroundColor Yellow
Write-Host "    Phase 4: Blind/OOB Testing" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Run-Scan -Name "mutillidae_oob" -Target "http://localhost:3004" -Modules "ssrf,xxe,sqli" -Extra "--oob-server"

Write-Host "========================================" -ForegroundColor Yellow
Write-Host "    Phase 5: Attack Chains" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "[*] Running RCE chain on DVWA..." -ForegroundColor White
lantern -t http://localhost:3002 --chain rce --exploit -o "$ReportDir/chain_rce" --no-banner

Write-Host "[*] Running auth_bypass chain on Juice Shop..." -ForegroundColor White
lantern -t http://localhost:3001 --chain auth_bypass --exploit -o "$ReportDir/chain_auth" --no-banner

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "    Test Suite Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Reports saved to: $ReportDir" -ForegroundColor Cyan
Write-Host ""
Get-ChildItem $ReportDir
