#!/bin/bash

echo "========================================"
echo "    LANTERN Full Lab Test Suite"
echo "========================================"
echo ""

REPORT_DIR="./reports/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$REPORT_DIR"

echo "[*] Reports will be saved to: $REPORT_DIR"
echo ""

run_scan() {
    local name=$1
    local target=$2
    local modules=$3
    local extra=$4
    
    echo "[*] Running: $name"
    echo "    Target: $target"
    echo "    Modules: $modules"
    
    lantern -t "$target" -m "$modules" --aggressive --exploit $extra -o "$REPORT_DIR/$name" --no-banner
    
    if [ $? -eq 0 ]; then
        echo "    [OK] Completed: $name"
    else
        echo "    [WARN] Issues with: $name"
    fi
    echo ""
}

echo "========================================" 
echo "    Phase 1: Injection Testing"
echo "========================================"
run_scan "juice_sqli_xss" "http://localhost:3001" "sqli,xss,dom" "--crawl"
run_scan "dvwa_injections" "http://localhost:3002" "sqli,xss,cmdi,ssti" "--deep"
run_scan "mutillidae_ldap" "http://localhost:3004" "ldap,sqli,xss" ""

echo "========================================" 
echo "    Phase 2: Auth & Session Testing"
echo "========================================"
run_scan "juice_auth" "http://localhost:3001" "jwt,auth,session,idor" "--crawl"
run_scan "webgoat_auth" "http://localhost:3003" "jwt,session,csrf" ""

echo "========================================" 
echo "    Phase 3: RCE Module Testing"
echo "========================================"
run_scan "dvwa_rce" "http://localhost:3002" "cmdi,ssti,upload,deserial" "--oob-server"
run_scan "xvwa_rce" "http://localhost:3006" "cmdi,lfi,ssrf,xxe" "--oob-server"

echo "========================================" 
echo "    Phase 4: Blind/OOB Testing"
echo "========================================"
run_scan "mutillidae_oob" "http://localhost:3004" "ssrf,xxe,sqli" "--oob-server"

echo "========================================" 
echo "    Phase 5: Attack Chains"
echo "========================================"
echo "[*] Running RCE chain on DVWA..."
lantern -t http://localhost:3002 --chain rce --exploit -o "$REPORT_DIR/chain_rce" --no-banner

echo "[*] Running auth_bypass chain on Juice Shop..."
lantern -t http://localhost:3001 --chain auth_bypass --exploit -o "$REPORT_DIR/chain_auth" --no-banner

echo ""
echo "========================================"
echo "    Test Suite Complete!"
echo "========================================"
echo ""
echo "Reports saved to: $REPORT_DIR"
echo ""
ls -la "$REPORT_DIR"
