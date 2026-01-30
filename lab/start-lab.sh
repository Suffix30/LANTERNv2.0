#!/bin/bash

echo "========================================"
echo "    LANTERN Vulnerable Lab Setup"
echo "========================================"
echo ""

cd "$(dirname "$0")"

check_docker() {
    if ! command -v docker &> /dev/null; then
        echo "[ERROR] Docker is not installed. Please install Docker first."
        echo "        https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        echo "[ERROR] Docker daemon is not running. Please start Docker."
        exit 1
    fi
    
    echo "[OK] Docker is running"
}

check_compose() {
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        echo "[ERROR] Docker Compose not found. Please install it."
        exit 1
    fi
    echo "[OK] Docker Compose available"
}

start_lab() {
    echo ""
    echo "[*] Starting vulnerable lab containers..."
    echo "    This may take a few minutes on first run (downloading images)..."
    echo ""
    
    $COMPOSE_CMD up -d
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "========================================"
        echo "    Lab Started Successfully!"
        echo "========================================"
        echo ""
        echo "Available targets:"
        echo ""
        echo "  Juice Shop     http://localhost:3001  (XSS, SQLi, JWT, Auth bypass)"
        echo "  DVWA           http://localhost:3002  (SQLi, XSS, CSRF, CMDi, Upload)"
        echo "  WebGoat        http://localhost:3003  (IDOR, XXE, Deserialization)"
        echo "  Mutillidae     http://localhost:3004  (LDAP, XML, SSRF, SQLi)"
        echo "  Hackazon       http://localhost:3005  (E-commerce, Payment bypass)"
        echo "  XVWA           http://localhost:3006  (XSS, SQLi, SSRF, LFI)"
        echo ""
        echo "========================================"
        echo "    Quick Test Commands"
        echo "========================================"
        echo ""
        echo "# Full scan on Juice Shop:"
        echo "lantern -t http://localhost:3001 --aggressive --exploit -o juice_report"
        echo ""
        echo "# SQLi + XSS on DVWA:"
        echo "lantern -t http://localhost:3002 -m sqli,xss,cmdi --aggressive --exploit"
        echo ""
        echo "# Auth bypass workflow:"
        echo "lantern -t http://localhost:3001 --workflow workflows/auth_bypass.yml"
        echo ""
        echo "# OOB blind testing:"
        echo "lantern -t http://localhost:3004 --oob-server -m ssrf,xxe,sqli --exploit"
        echo ""
    else
        echo "[ERROR] Failed to start lab. Check Docker logs."
        exit 1
    fi
}

stop_lab() {
    echo "[*] Stopping lab containers..."
    $COMPOSE_CMD down
    echo "[OK] Lab stopped"
}

status_lab() {
    echo "[*] Lab status:"
    docker ps --filter "name=lantern-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
}

case "${1:-start}" in
    start)
        check_docker
        check_compose
        start_lab
        ;;
    stop)
        check_compose
        stop_lab
        ;;
    status)
        status_lab
        ;;
    restart)
        check_docker
        check_compose
        stop_lab
        start_lab
        ;;
    *)
        echo "Usage: $0 {start|stop|status|restart}"
        exit 1
        ;;
esac
