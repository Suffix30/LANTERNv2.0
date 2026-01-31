# CTF Reverse Engineering Knowledge

## Binary Analysis Workflow

### 1. Initial Identification
```bash
file binary          # Identify file type (ELF, PE, Mach-O)
strings binary       # Extract readable strings
strings -n 8 binary  # Min 8 char strings
xxd binary | head    # View hex dump
```

### 2. Static Analysis
```bash
# Disassembly
objdump -d binary
radare2 binary       # r2 -A binary
ghidra               # GUI decompiler

# Symbols
nm binary            # List symbols
readelf -s binary    # ELF symbols
```

### 3. Dynamic Analysis
```bash
ltrace ./binary      # Library calls
strace ./binary      # System calls
gdb ./binary         # Debugger
```

## Hash Cracking Techniques

### MD5 Hash Cracking
```bash
# John the Ripper
john --format=raw-md5 --wordlist=rockyou.txt hashes.txt

# Hashcat (GPU)
hashcat -m 0 -a 0 hashes.txt rockyou.txt     # Dictionary
hashcat -m 0 -a 3 hashes.txt ?a?a?a?a        # Brute force

# Online lookups
# - CrackStation.net
# - md5decrypt.net
# - hashes.com
```

### Common Hash Patterns in CTFs
1. **Single char hashes**: MD5 of single characters (a-z, 0-9)
2. **Position-based**: MD5(position + char) or MD5(char + position)
3. **Double hashing**: MD5(MD5(input))
4. **Salted**: MD5(salt + input) or MD5(input + salt)
5. **Custom format**: MD5(prefix + position + char)

### Python Hash Cracking Template
```python
import hashlib

def crack_md5(target_hashes, charset, format_func):
    cracked = {}
    for idx, target in enumerate(target_hashes):
        for c in charset:
            test = format_func(idx, c)
            if hashlib.md5(test.encode()).hexdigest() == target:
                cracked[idx] = c
                break
    return cracked

# Example format functions
formats = [
    lambda i, c: c,                    # Single char
    lambda i, c: f"{i}{c}",            # pos + char
    lambda i, c: f"{c}{i}",            # char + pos
    lambda i, c: f"{i:02x}{c}",        # hex_pos + char
    lambda i, c: f"flag{i}{c}",        # prefix + pos + char
]
```

## ELF Binary Tips
- Magic bytes: `7F 45 4C 46` (\\x7fELF)
- Entry point: Check with `readelf -h`
- Sections: `.text` (code), `.data` (data), `.rodata` (strings)
- Large binaries may have padding or embedded files

## Common CTF Flag Formats
- `KCTF{...}` - KnightCTF
- `FLAG{...}` - Generic
- `flag{...}` - Lowercase
- `HTB{...}` - HackTheBox
- `picoCTF{...}` - picoCTF

## Tools for RE
- **Ghidra**: Free decompiler from NSA
- **IDA Pro/Free**: Industry standard disassembler
- **radare2**: CLI reverse engineering framework
- **Binary Ninja**: Modern RE platform
- **Cutter**: GUI for radare2

## Remote Resources for Cracking
- **Remote Kali Host**: John the Ripper, hashcat (CPU) - set BLACK_KALI_HOST
- **GPU Host**: hashcat with CUDA acceleration - set BLACK_GPU_HOST
- **Local**: Static analysis, scripting
