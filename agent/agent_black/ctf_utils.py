import base64
import binascii
import hashlib
import re
import json
import subprocess
import tempfile
import os
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from urllib.parse import unquote, quote


FLAG_PATTERNS = [
    r'flag\{[^}]+\}',
    r'FLAG\{[^}]+\}',
    r'ctf\{[^}]+\}',
    r'CTF\{[^}]+\}',
    r'meta\{[^}]+\}',
    r'MetaCTF\{[^}]+\}',
    r'KCTF\{[^}]+\}',
    r'knight\{[^}]+\}',
    r'picoCTF\{[^}]+\}',
    r'HTB\{[^}]+\}',
    r'THM\{[^}]+\}',
    r'BLACKFLAG\{[^}]+\}',
    r'0xL4ugh\{[^}]+\}',
]


def detect_encoding(data: str) -> List[str]:
    encodings = []
    if re.match(r'^[A-Za-z0-9+/=]+$', data) and len(data) % 4 == 0:
        encodings.append("base64")
    if re.match(r'^[0-9a-fA-F]+$', data) and len(data) % 2 == 0:
        encodings.append("hex")
    if re.match(r'^[01\s]+$', data):
        encodings.append("binary")
    if '%' in data:
        encodings.append("url_encoded")
    if '&#' in data or '&lt;' in data:
        encodings.append("html_entities")
    if re.match(r'^[A-Z2-7=]+$', data, re.IGNORECASE):
        encodings.append("base32")
    if '\\x' in data or '\\u' in data:
        encodings.append("escape_sequences")
    rot_match = re.search(r'[a-zA-Z]{4,}', data)
    if rot_match:
        encodings.append("possible_rot")
    return encodings


def decode_base64(data: str) -> Tuple[bool, str]:
    try:
        decoded = base64.b64decode(data).decode('utf-8', errors='replace')
        return True, decoded
    except:
        try:
            decoded = base64.b64decode(data + '==').decode('utf-8', errors='replace')
            return True, decoded
        except:
            return False, ""


def decode_hex(data: str) -> Tuple[bool, str]:
    try:
        decoded = bytes.fromhex(data.replace(' ', '')).decode('utf-8', errors='replace')
        return True, decoded
    except:
        return False, ""


def decode_binary(data: str) -> Tuple[bool, str]:
    try:
        binary = data.replace(' ', '')
        chars = [chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8)]
        return True, ''.join(chars)
    except:
        return False, ""


def decode_url(data: str) -> Tuple[bool, str]:
    try:
        return True, unquote(data)
    except:
        return False, ""


def decode_base32(data: str) -> Tuple[bool, str]:
    try:
        decoded = base64.b32decode(data.upper()).decode('utf-8', errors='replace')
        return True, decoded
    except:
        return False, ""


def rot_decode(data: str, n: int = 13) -> str:
    result = []
    for char in data:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + n) % 26 + base))
        else:
            result.append(char)
    return ''.join(result)


def try_all_rot(data: str) -> List[Tuple[int, str]]:
    results = []
    for i in range(1, 26):
        decoded = rot_decode(data, i)
        results.append((i, decoded))
    return results


def xor_decode(data: bytes, key: bytes) -> bytes:
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])


def xor_single_byte_attack(data: bytes) -> List[Tuple[int, str]]:
    results = []
    for key in range(256):
        try:
            decoded = xor_decode(data, bytes([key]))
            decoded_str = decoded.decode('utf-8', errors='replace')
            if decoded_str.isprintable() or search_flags(decoded_str):
                results.append((key, decoded_str))
        except:
            pass
    return results


def auto_decode(data: str, max_depth: int = 5) -> List[Dict[str, Any]]:
    results = []
    current = data
    depth = 0
    chain = []
    
    while depth < max_depth:
        encodings = detect_encoding(current)
        if not encodings:
            break
            
        decoded = False
        for enc in encodings:
            success = False
            result = ""
            
            if enc == "base64":
                success, result = decode_base64(current)
            elif enc == "hex":
                success, result = decode_hex(current)
            elif enc == "binary":
                success, result = decode_binary(current)
            elif enc == "url_encoded":
                success, result = decode_url(current)
            elif enc == "base32":
                success, result = decode_base32(current)
            
            if success and result != current:
                chain.append({"encoding": enc, "result": result})
                current = result
                decoded = True
                
                flags = search_flags(result)
                if flags:
                    results.append({
                        "chain": chain.copy(),
                        "final": result,
                        "flags_found": flags
                    })
                break
        
        if not decoded:
            break
        depth += 1
    
    if chain:
        results.append({
            "chain": chain,
            "final": current,
            "flags_found": search_flags(current)
        })
    
    return results


def search_flags(text: str) -> List[str]:
    flags = []
    for pattern in FLAG_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        flags.extend(matches)
    return list(set(flags))


def identify_hash(hash_str: str) -> List[str]:
    hash_str = hash_str.strip().lower()
    length = len(hash_str)
    possibilities = []
    
    hash_lengths = {
        32: ["MD5", "NTLM", "MD4"],
        40: ["SHA-1", "RIPEMD-160"],
        56: ["SHA-224"],
        64: ["SHA-256", "SHA3-256", "BLAKE2s"],
        96: ["SHA-384", "SHA3-384"],
        128: ["SHA-512", "SHA3-512", "BLAKE2b", "Whirlpool"],
    }
    
    if length in hash_lengths:
        possibilities.extend(hash_lengths[length])
    
    if hash_str.startswith('$1$'):
        possibilities.append("MD5 Crypt")
    elif hash_str.startswith('$2a$') or hash_str.startswith('$2b$'):
        possibilities.append("bcrypt")
    elif hash_str.startswith('$5$'):
        possibilities.append("SHA-256 Crypt")
    elif hash_str.startswith('$6$'):
        possibilities.append("SHA-512 Crypt")
    elif hash_str.startswith('$argon2'):
        possibilities.append("Argon2")
    
    return possibilities


def hash_string(data: str, algo: str = "md5") -> str:
    algos = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }
    if algo.lower() in algos:
        return algos[algo.lower()](data.encode()).hexdigest()
    return ""


def crack_hash_wordlist(hash_str: str, wordlist: Optional[List[str]] = None, algo: str = "md5") -> Optional[str]:
    if wordlist is None:
        wordlist = [
            "admin", "password", "123456", "root", "flag", "secret", "test",
            "letmein", "welcome", "monkey", "dragon", "master", "qwerty",
            "login", "passw0rd", "abc123", "111111", "admin123", "password1",
            "1234567890", "password123", "iloveyou", "sunshine", "princess",
            "football", "baseball", "soccer", "hockey", "batman", "trustno1"
        ]
    
    hash_str = hash_str.lower().strip()
    for word in wordlist:
        word = word.strip()
        if hash_string(word, algo) == hash_str:
            return word
    return None


def analyze_binary_file(file_path: str) -> Dict[str, Any]:
    result = {
        "file_path": file_path,
        "exists": False,
        "size": 0,
        "magic_bytes": "",
        "file_type": "unknown",
        "strings_found": [],
        "flags_found": [],
        "interesting_strings": []
    }
    
    path = Path(file_path)
    if not path.exists():
        return result
    
    result["exists"] = True
    result["size"] = path.stat().st_size
    
    with open(path, 'rb') as f:
        magic = f.read(16)
        result["magic_bytes"] = magic.hex()
    
    magic_signatures = {
        b'\x7fELF': "ELF Binary",
        b'MZ': "Windows PE/EXE",
        b'\x89PNG': "PNG Image",
        b'\xff\xd8\xff': "JPEG Image",
        b'GIF8': "GIF Image",
        b'PK\x03\x04': "ZIP Archive",
        b'\x1f\x8b': "GZIP Archive",
        b'BZh': "BZIP2 Archive",
        b'%PDF': "PDF Document",
        b'\x00\x00\x00\x1c\x66\x74\x79\x70': "MP4 Video",
        b'RIFF': "WAV/AVI",
        b'\xca\xfe\xba\xbe': "Mach-O (Fat Binary)",
        b'\xfe\xed\xfa\xce': "Mach-O (32-bit)",
        b'\xfe\xed\xfa\xcf': "Mach-O (64-bit)",
    }
    
    for sig, ftype in magic_signatures.items():
        if magic.startswith(sig):
            result["file_type"] = ftype
            break
    
    try:
        with open(path, 'rb') as f:
            content = f.read()
        
        strings = re.findall(rb'[\x20-\x7e]{4,}', content)
        result["strings_found"] = [s.decode('ascii', errors='ignore') for s in strings[:100]]
        
        for s in result["strings_found"]:
            flags = search_flags(s)
            result["flags_found"].extend(flags)
            
            interesting_patterns = [
                r'password', r'secret', r'key', r'token', r'flag',
                r'admin', r'root', r'http://', r'https://', r'ftp://',
                r'/etc/passwd', r'/bin/sh', r'\.flag', r'ctf'
            ]
            for pattern in interesting_patterns:
                if re.search(pattern, s, re.IGNORECASE):
                    result["interesting_strings"].append(s)
                    break
    except Exception as e:
        result["error"] = str(e)
    
    return result


def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
    pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
    strings = re.findall(pattern, data)
    return [s.decode('ascii', errors='ignore') for s in strings]


def analyze_js_source(code: str) -> Dict[str, Any]:
    result = {
        "variables": [],
        "functions": [],
        "strings": [],
        "base64_strings": [],
        "urls": [],
        "comments": [],
        "suspicious_patterns": [],
        "flags_found": []
    }
    
    result["variables"] = re.findall(r'(?:var|let|const)\s+(\w+)', code)
    result["functions"] = re.findall(r'function\s+(\w+)', code)
    result["strings"] = re.findall(r'["\']([^"\']{4,})["\']', code)
    result["urls"] = re.findall(r'https?://[^\s"\'<>]+', code)
    result["comments"] = re.findall(r'//.*|/\*[\s\S]*?\*/', code)
    
    for s in result["strings"]:
        if re.match(r'^[A-Za-z0-9+/=]+$', s) and len(s) > 8:
            success, decoded = decode_base64(s)
            if success:
                result["base64_strings"].append({"encoded": s, "decoded": decoded})
                flags = search_flags(decoded)
                result["flags_found"].extend(flags)
    
    suspicious = [
        (r'eval\s*\(', "eval() usage"),
        (r'atob\s*\(', "Base64 decode (atob)"),
        (r'btoa\s*\(', "Base64 encode (btoa)"),
        (r'document\.cookie', "Cookie access"),
        (r'localStorage', "LocalStorage access"),
        (r'fetch\s*\(', "Fetch API"),
        (r'XMLHttpRequest', "XHR request"),
        (r'\.innerHTML\s*=', "innerHTML assignment"),
        (r'fromCharCode', "Character code conversion"),
        (r'debugger', "Debugger statement"),
    ]
    
    for pattern, desc in suspicious:
        if re.search(pattern, code):
            result["suspicious_patterns"].append(desc)
    
    flags = search_flags(code)
    result["flags_found"].extend(flags)
    
    return result


def analyze_html_source(html: str) -> Dict[str, Any]:
    result = {
        "forms": [],
        "inputs": [],
        "scripts": [],
        "comments": [],
        "hidden_elements": [],
        "links": [],
        "flags_found": []
    }
    
    result["forms"] = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', html, re.IGNORECASE)
    result["inputs"] = re.findall(r'<input[^>]*name=["\']([^"\']*)["\']', html, re.IGNORECASE)
    result["scripts"] = re.findall(r'<script[^>]*>([\s\S]*?)</script>', html, re.IGNORECASE)
    result["comments"] = re.findall(r'<!--([\s\S]*?)-->', html)
    result["hidden_elements"] = re.findall(r'<[^>]*(?:hidden|type=["\']hidden["\'])[^>]*>', html, re.IGNORECASE)
    result["links"] = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)
    
    for comment in result["comments"]:
        flags = search_flags(comment)
        result["flags_found"].extend(flags)
    
    for script in result["scripts"]:
        js_analysis = analyze_js_source(script)
        result["flags_found"].extend(js_analysis["flags_found"])
    
    flags = search_flags(html)
    result["flags_found"].extend(flags)
    
    result["flags_found"] = list(set(result["flags_found"]))
    return result


def frequency_analysis(text: str) -> Dict[str, int]:
    freq = {}
    for char in text.upper():
        if char.isalpha():
            freq[char] = freq.get(char, 0) + 1
    return dict(sorted(freq.items(), key=lambda x: x[1], reverse=True))


def substitution_cipher_hint(text: str) -> Dict[str, Any]:
    freq = frequency_analysis(text)
    english_freq = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    
    suggestions = {}
    sorted_chars = list(freq.keys())
    for i, char in enumerate(sorted_chars[:10]):
        if i < len(english_freq):
            suggestions[char] = english_freq[i]
    
    return {
        "frequency": freq,
        "suggestions": suggestions,
        "hint": "Most common letters in English: E, T, A, O, I, N"
    }


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    result = []
    key = key.upper()
    key_index = 0
    
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            decrypted = chr((ord(char.upper()) - ord('A') - shift) % 26 + base)
            result.append(decrypted if char.isupper() else decrypted.lower())
            key_index += 1
        else:
            result.append(char)
    
    return ''.join(result)


def run_command(command: str, timeout: int = 30) -> Dict[str, Any]:
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def quick_solve(data: str, challenge_type: str = "auto") -> Dict[str, Any]:
    results = {
        "input": data[:100] + "..." if len(data) > 100 else data,
        "type_detected": challenge_type,
        "attempts": [],
        "flags_found": []
    }
    
    flags = search_flags(data)
    if flags:
        results["flags_found"].extend(flags)
        results["attempts"].append({"method": "direct_search", "success": True})
        return results
    
    decode_results = auto_decode(data)
    if decode_results:
        results["attempts"].append({"method": "auto_decode", "results": decode_results})
        for dr in decode_results:
            results["flags_found"].extend(dr.get("flags_found", []))
    
    if challenge_type in ["auto", "crypto"]:
        rot_results = try_all_rot(data)
        for rot, decoded in rot_results:
            flags = search_flags(decoded)
            if flags:
                results["attempts"].append({"method": f"ROT{rot}", "decoded": decoded})
                results["flags_found"].extend(flags)
    
    hash_types = identify_hash(data)
    if hash_types:
        results["attempts"].append({"method": "hash_identify", "types": hash_types})
        cracked = crack_hash_wordlist(data)
        if cracked:
            results["attempts"].append({"method": "hash_crack", "cracked": cracked})
    
    results["flags_found"] = list(set(results["flags_found"]))
    return results


def encode_url(data: str) -> str:
    return quote(data, safe='')


def encode_base64(data: str) -> str:
    return base64.b64encode(data.encode()).decode()


def encode_hex(data: str) -> str:
    return data.encode().hex()


def write_to_temp(data: bytes, suffix: str = ".bin") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return path


def get_env_hints() -> Dict[str, str]:
    hints = {}
    ctf_vars = ['CTF_FLAG', 'FLAG', 'SECRET', 'PASSWORD', 'KEY', 'TOKEN']
    for var in ctf_vars:
        value = os.environ.get(var)
        if value:
            hints[var] = value
    return hints


def add_flag_pattern(pattern: str) -> None:
    if pattern not in FLAG_PATTERNS:
        FLAG_PATTERNS.append(pattern)


def decode_hex_safe(data: str) -> Tuple[bool, str]:
    try:
        decoded = binascii.unhexlify(data.replace(' ', ''))
        return True, decoded.decode('utf-8', errors='replace')
    except (binascii.Error, ValueError):
        return False, ""


def run_external_tool(tool: str, args: List[str], input_file: Optional[str] = None) -> Dict[str, Any]:
    cmd = [tool] + args
    if input_file:
        cmd.append(input_file)
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Tool timed out"}
    except FileNotFoundError:
        return {"success": False, "error": f"Tool '{tool}' not found"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def solve_web_challenge(url: str, hint: str = "") -> Dict[str, Any]:
    results = {
        "url": url,
        "checks_performed": [],
        "findings": [],
        "flags_found": []
    }
    
    try:
        import urllib.request
        import ssl
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            html = response.read().decode('utf-8', errors='replace')
            headers = dict(response.headers)
        
        results["checks_performed"].append("GET request")
        
        html_analysis = analyze_html_source(html)
        results["findings"].append({"type": "html_analysis", "data": html_analysis})
        results["flags_found"].extend(html_analysis["flags_found"])
        
        for header, value in headers.items():
            flags = search_flags(str(value))
            if flags:
                results["flags_found"].extend(flags)
                results["findings"].append({"type": "header_flag", "header": header, "flags": flags})
        
        common_paths = [
            "/robots.txt", "/.git/config", "/.env", "/flag.txt", "/flag",
            "/secret", "/admin", "/backup", "/config.php", "/.htaccess",
            "/sitemap.xml", "/.svn/entries", "/WEB-INF/web.xml",
            "/backup.sql", "/dump.sql", "/.bash_history", "/id_rsa"
        ]
        
        base_url = url.rstrip('/')
        for path in common_paths:
            try:
                req = urllib.request.Request(base_url + path, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3, context=ctx) as r:
                    content = r.read().decode('utf-8', errors='replace')
                    if r.status == 200 and len(content) > 0:
                        results["checks_performed"].append(f"Found: {path}")
                        flags = search_flags(content)
                        if flags:
                            results["flags_found"].extend(flags)
                            results["findings"].append({"type": "path_discovery", "path": path, "flags": flags})
            except:
                pass
                    
    except Exception as e:
        results["error"] = str(e)
    
    results["flags_found"] = list(set(results["flags_found"]))
    return results


def save_session(filepath: Optional[str] = None, found_flags: List[str] = None, 
                 challenge_history: List[Dict] = None) -> str:
    if filepath is None:
        filepath = os.path.join(tempfile.gettempdir(), f"ctf_session_{os.getpid()}.json")
    
    session_data = {
        "found_flags": found_flags or [],
        "challenge_history": challenge_history or [],
        "flag_patterns": FLAG_PATTERNS
    }
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(session_data, f, indent=2)
    
    return filepath


def load_session(filepath: str) -> Optional[Dict[str, Any]]:
    if not os.path.exists(filepath):
        return None
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            session_data = json.load(f)
        
        loaded_patterns = session_data.get("flag_patterns", [])
        for pattern in loaded_patterns:
            add_flag_pattern(pattern)
        
        return session_data
    except (json.JSONDecodeError, KeyError):
        return None


def load_challenge_file(filepath: str) -> Dict[str, Any]:
    if not os.path.exists(filepath):
        return {"error": f"File not found: {filepath}"}
    
    ext = os.path.splitext(filepath)[1].lower()
    
    result = {
        "filepath": filepath,
        "size": os.path.getsize(filepath),
        "extension": ext,
        "flags_found": []
    }
    
    if ext == '.json':
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            result["data"] = data
            result["flags_found"] = search_flags(json.dumps(data))
        except json.JSONDecodeError as e:
            result["error"] = f"Invalid JSON: {e}"
    elif ext in ['.txt', '.md', '.html', '.js', '.py', '.php', '.xml', '.yml', '.yaml']:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            result["content_preview"] = content[:1000]
            result["flags_found"] = search_flags(content)
            
            if ext in ['.html', '.php']:
                html_analysis = analyze_html_source(content)
                result["html_analysis"] = html_analysis
                result["flags_found"].extend(html_analysis["flags_found"])
            elif ext == '.js':
                js_analysis = analyze_js_source(content)
                result["js_analysis"] = js_analysis
                result["flags_found"].extend(js_analysis["flags_found"])
        except Exception as e:
            result["error"] = str(e)
    else:
        result.update(analyze_binary_file(filepath))
    
    result["flags_found"] = list(set(result["flags_found"]))
    return result


def export_findings(found_flags: List[str], challenge_history: List[Dict] = None,
                   output_path: Optional[str] = None) -> str:
    if output_path is None:
        output_path = os.path.join(os.getcwd(), "ctf_findings.json")
    
    findings = {
        "flags": list(set(found_flags)),
        "total_flags": len(set(found_flags)),
        "challenges_attempted": len(challenge_history) if challenge_history else 0,
        "history": challenge_history or []
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(findings, f, indent=2)
    
    return output_path


def xor_multi_byte_attack(data: bytes, max_key_len: int = 4) -> List[Dict[str, Any]]:
    results = []
    
    for key_len in range(1, max_key_len + 1):
        for key_int in range(256 ** key_len):
            key = key_int.to_bytes(key_len, 'big')
            try:
                decoded = xor_decode(data, key)
                decoded_str = decoded.decode('utf-8', errors='replace')
                flags = search_flags(decoded_str)
                if flags:
                    results.append({
                        "key": key.hex(),
                        "key_len": key_len,
                        "decoded": decoded_str[:200],
                        "flags": flags
                    })
            except:
                pass
            
            if key_len > 1 and key_int > 1000:
                break
    
    return results


def caesar_bruteforce(data: str) -> List[Dict[str, Any]]:
    results = []
    for shift in range(26):
        decoded = rot_decode(data, shift)
        flags = search_flags(decoded)
        score = sum(1 for c in decoded.lower() if c in 'etaoinshrdlu')
        results.append({
            "shift": shift,
            "decoded": decoded,
            "flags": flags,
            "english_score": score
        })
    
    results.sort(key=lambda x: (-len(x["flags"]), -x["english_score"]))
    return results


def atbash_decode(data: str) -> str:
    result = []
    for char in data:
        if char.isalpha():
            if char.isupper():
                result.append(chr(ord('Z') - (ord(char) - ord('A'))))
            else:
                result.append(chr(ord('z') - (ord(char) - ord('a'))))
        else:
            result.append(char)
    return ''.join(result)


def morse_decode(data: str) -> str:
    morse_dict = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z', '.----': '1', '..---': '2', '...--': '3',
        '....-': '4', '.....': '5', '-....': '6', '--...': '7',
        '---..': '8', '----.': '9', '-----': '0'
    }
    
    words = data.strip().split('   ')
    decoded_words = []
    
    for word in words:
        letters = word.split(' ')
        decoded_word = ''
        for letter in letters:
            letter = letter.strip()
            if letter in morse_dict:
                decoded_word += morse_dict[letter]
            elif letter:
                decoded_word += '?'
        decoded_words.append(decoded_word)
    
    return ' '.join(decoded_words)


def bacon_decode(data: str, use_ab: bool = True) -> str:
    bacon_dict = {
        'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D',
        'AABAA': 'E', 'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H',
        'ABAAA': 'I', 'ABAAB': 'J', 'ABABA': 'K', 'ABABB': 'L',
        'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O', 'ABBBB': 'P',
        'BAAAA': 'Q', 'BAAAB': 'R', 'BAABA': 'S', 'BAABB': 'T',
        'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X',
        'BBAAA': 'Y', 'BBAAB': 'Z'
    }
    
    if not use_ab:
        cleaned = ''
        for c in data:
            if c.isupper():
                cleaned += 'B'
            elif c.islower():
                cleaned += 'A'
        data = cleaned
    
    data = ''.join(c for c in data.upper() if c in 'AB')
    
    result = ''
    for i in range(0, len(data) - 4, 5):
        chunk = data[i:i+5]
        if chunk in bacon_dict:
            result += bacon_dict[chunk]
    
    return result


def rail_fence_decode(data: str, rails: int = 3) -> str:
    if rails < 2:
        return data
    
    n = len(data)
    fence = [['' for _ in range(n)] for _ in range(rails)]
    
    rail = 0
    direction = 1
    for i in range(n):
        fence[rail][i] = '*'
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    
    idx = 0
    for r in range(rails):
        for c in range(n):
            if fence[r][c] == '*' and idx < n:
                fence[r][c] = data[idx]
                idx += 1
    
    result = ''
    rail = 0
    direction = 1
    for i in range(n):
        result += fence[rail][i]
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    
    return result


def print_ctf_summary(results: Dict[str, Any]) -> None:
    print("\n" + "=" * 60)
    print("CTF ANALYSIS SUMMARY")
    print("=" * 60)
    
    flags = results.get("flags_found", [])
    if flags:
        print(f"\n🚩 FLAGS FOUND ({len(flags)}):")
        for flag in flags:
            print(f"   → {flag}")
    else:
        print("\n❌ No flags found")
    
    attempts = results.get("attempts", [])
    if attempts:
        print(f"\n📋 METHODS TRIED ({len(attempts)}):")
        for attempt in attempts:
            method = attempt.get("method", "unknown")
            if attempt.get("success"):
                print(f"   ✓ {method}")
            elif attempt.get("cracked"):
                print(f"   ✓ {method}: {attempt['cracked']}")
            elif attempt.get("types"):
                print(f"   ? {method}: {', '.join(attempt['types'])}")
            else:
                print(f"   - {method}")
    
    print("\n" + "=" * 60)
