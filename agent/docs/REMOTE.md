# Agent BLACK Remote Attacks Guide

Agent BLACK can execute security tools either **locally** (if you're on Linux) or on a **remote Kali host** (for Windows/macOS users).

## Do You Need This Guide?

### If you're on Linux (Kali, Arch, Ubuntu, etc.)
**You probably don't need a remote host!** Agent BLACK automatically runs tools locally on Linux. Just install the tools you need:

```bash
# Arch
sudo pacman -S john hashcat aircrack-ng hackrf

# Debian/Ubuntu/Kali
sudo apt install john hashcat aircrack-ng hackrf
```

Skip to [Using Tools Locally](#using-tools-locally) below.

### If you're on Windows/macOS
You'll need a remote Linux host for advanced attacks. Keep reading.

---

## Overview

Some security tools work best on dedicated hardware or Linux:
- **Hash cracking** - GPU-accelerated hashcat
- **WiFi attacks** - Requires monitor mode capable adapter
- **RF attacks** - HackRF SDR hardware
- **Exploit development** - Kali toolset

Agent BLACK connects via SSH to execute these remotely (or runs them locally on Linux).

## Prerequisites

### Remote Host Requirements
- Kali Linux (or similar security distro)
- SSH server running
- Required tools installed (hashcat, aircrack-ng, etc.)
- Network accessible from your machine

### SSH Key Setup (Recommended)

Set up passwordless SSH:

```bash
# Generate key if you don't have one
ssh-keygen -t ed25519

# Copy to Kali host
ssh-copy-id kali@192.168.1.100

# Test connection
ssh kali@192.168.1.100 "echo 'Connected!'"
```

## Configuration

### Environment Variables

```bash
# Remote Kali Host
export BLACK_KALI_HOST=192.168.1.100
export BLACK_KALI_USER=kali
export BLACK_KALI_PORT=22

# GPU Host (if different from Kali)
export BLACK_GPU_HOST=192.168.1.50
export BLACK_GPU_USER=user
```

### Config File

Create `agent/config/config.yaml`:

```yaml
kali:
  host: 192.168.1.100
  user: kali
  port: 22

gpu:
  host: 192.168.1.50
  user: user
```

## Hash Cracking

### Setup on Kali

```bash
# Install hashcat
sudo apt update
sudo apt install hashcat john

# For GPU support (NVIDIA)
sudo apt install nvidia-driver nvidia-cuda-toolkit
```

### Using in Agent BLACK

```
[YOU] > crack hashes

[BLACK] Enter hashes (one per line, Ctrl+D when done):
5f4dcc3b5aa765d61d8327deb882cf99
e99a18c428cb38d5f260853678922e03
^D

[*] Attempting crack via remote Kali host...
[*] Trying john with rockyou.txt...
[CRACKED] 5f4dcc3b5aa765d61d8327deb882cf99 : password
[CRACKED] e99a18c428cb38d5f260853678922e03 : abc123
```

### Programmatic Usage

```python
from agents.agent_black import AgentBlack

agent = AgentBlack()

# Crack with john
result = agent.crack_hash("5f4dcc3b5aa765d61d8327deb882cf99")
print(result)

# Crack with hashcat (specify hash type)
result = agent.crack_hash_hashcat(
    "5f4dcc3b5aa765d61d8327deb882cf99",
    hash_type=0,  # MD5
    wordlist="/usr/share/wordlists/rockyou.txt"
)
```

### Hash Types for Hashcat

| Type | Mode |
|------|------|
| MD5 | 0 |
| SHA1 | 100 |
| SHA256 | 1400 |
| NTLM | 1000 |
| bcrypt | 3200 |
| WPA | 22000 |

## WiFi Attacks

### Setup on Kali

```bash
# Install aircrack-ng suite
sudo apt install aircrack-ng

# Check wireless adapter
iwconfig
```

### Using in Agent BLACK

```
[YOU] > wifi scan

[BLACK] Scanning nearby networks...
[*] Found 12 networks:

ESSID                  BSSID              CH  ENC     SIGNAL
MyNetwork             AA:BB:CC:DD:EE:FF   6   WPA2    -45
Neighbor_5G           11:22:33:44:55:66   36  WPA2    -62
...

[YOU] > monitor mode

[BLACK] Enabling monitor mode on wlan0...
[+] Monitor mode enabled: wlan0mon

[YOU] > capture MyNetwork

[BLACK] Starting capture on channel 6...
[*] Target: AA:BB:CC:DD:EE:FF (MyNetwork)
[*] Capturing to /tmp/capture-001.cap
```

### Programmatic Usage

```python
agent = AgentBlack()

# Scan networks
result = agent.wifi_scan("wlan0")
print(result["stdout"])

# Enable monitor mode
result = agent.wifi_monitor_mode("wlan0", enable=True)

# Capture traffic
result = agent.wifi_capture(
    interface="wlan0mon",
    channel=6,
    bssid="AA:BB:CC:DD:EE:FF",
    output="/tmp/capture"
)
```

## HackRF / SDR

### Setup on Kali

```bash
# Install HackRF tools
sudo apt install hackrf gnuradio

# Test device
hackrf_info
```

### Using in Agent BLACK

```
[YOU] > hackrf info

[BLACK] Checking HackRF status...
Found HackRF One
Serial number: 0000000000000000
Firmware version: 2023.01.1

[YOU] > hackrf scan 433mhz

[BLACK] Scanning 433 MHz band...
[*] Frequency range: 430-436 MHz
[*] Found signals at:
    433.92 MHz - Strong signal (likely remote/sensor)
    434.00 MHz - Weak signal

[YOU] > hackrf capture 433.92mhz

[BLACK] Capturing at 433.92 MHz...
[*] Recording to /tmp/rf_capture.raw
[*] Duration: 5 seconds
[+] Captured 10000000 samples

[YOU] > hackrf replay

[BLACK] Replaying last capture at 433.92 MHz...
[*] Transmitting /tmp/rf_capture.raw
[+] Transmission complete
```

### Programmatic Usage

```python
agent = AgentBlack()

# Check HackRF
result = agent.hackrf_info()

# Spectrum sweep
result = agent.hackrf_sweep(freq_start=430000000, freq_end=440000000)

# Capture signal
result = agent.hackrf_capture(freq=433920000, duration_samples=10000000)
print(result["capture_file"])

# Replay signal
result = agent.hackrf_replay("/tmp/rf_capture.raw", freq=433920000)
```

### Common RF Frequencies

| Frequency | Use |
|-----------|-----|
| 315 MHz | Car key fobs (US) |
| 433.92 MHz | Car key fobs (EU), sensors, remotes |
| 868 MHz | European ISM band |
| 915 MHz | US ISM band |
| 2.4 GHz | WiFi, Bluetooth |

## Custom Commands

Execute any command on the remote host:

```
[YOU] > exec nmap -sV 192.168.1.1

[BLACK] Executing on Kali...
Starting Nmap 7.94 ( https://nmap.org )
...
```

### Programmatic Usage

```python
agent = AgentBlack()

# Execute on remote Kali
result = agent.kali_exec("nmap -sV 192.168.1.1", timeout=120)
print(result["stdout"])

# Or use ssh_execute for custom host
result = agent.ssh_execute(
    host="192.168.1.100",
    user="kali",
    command="whoami",
    timeout=30
)
```

## Security Considerations

1. **SSH Keys** - Use SSH keys instead of passwords
2. **Firewall** - Limit SSH access to trusted IPs
3. **Separate Network** - Keep attack hardware on isolated network
4. **Legal** - Only attack systems you have permission to test

## Troubleshooting

### "No remote host configured"

Set the environment variable:
```bash
export BLACK_KALI_HOST=192.168.1.100
```

### "SSH connection failed"

1. Check SSH is running on Kali: `sudo systemctl status ssh`
2. Test connection: `ssh kali@192.168.1.100`
3. Check firewall: `sudo ufw status`

### "Permission denied"

1. Check SSH key is copied: `ssh-copy-id kali@host`
2. Check user permissions on Kali

### "Command not found"

Install the required tool on Kali:
```bash
sudo apt install <tool-name>
```

### HackRF not detected

```bash
# Check USB connection
lsusb | grep HackRF

# Check permissions
sudo chmod 666 /dev/bus/usb/XXX/YYY

# Add udev rules
echo 'SUBSYSTEM=="usb", ATTR{idVendor}=="1d50", ATTR{idProduct}=="6089", MODE="0666"' | sudo tee /etc/udev/rules.d/52-hackrf.rules
sudo udevadm control --reload-rules
```

### WiFi adapter not in monitor mode

```bash
# Kill interfering processes
sudo airmon-ng check kill

# Start monitor mode
sudo airmon-ng start wlan0
```

---

## Using Tools Locally

If you're on Linux and have the tools installed, Agent BLACK runs them locally without any SSH configuration.

### Verify Local Mode

```python
from agents.agent_black import AgentBlack

agent = AgentBlack()
print(agent.is_linux)      # True
print(agent.local_mode)    # True (if no remote host configured)
print(agent.get_status())  # execution_mode: "local"
```

### Install Tools (Arch Linux)

```bash
# Hash cracking
sudo pacman -S john hashcat

# WiFi
sudo pacman -S aircrack-ng

# HackRF/SDR
sudo pacman -S hackrf gnuradio

# Network tools
sudo pacman -S nmap masscan
```

### Install Tools (Debian/Ubuntu/Kali)

```bash
# Hash cracking
sudo apt install john hashcat

# WiFi
sudo apt install aircrack-ng

# HackRF/SDR
sudo apt install hackrf gnuradio

# Network tools
sudo apt install nmap masscan
```

### Install Tools (Fedora)

```bash
# Hash cracking
sudo dnf install john hashcat

# WiFi
sudo dnf install aircrack-ng

# HackRF/SDR
sudo dnf install hackrf gnuradio
```

### Using in Chat

When on Linux with tools installed:
```
[YOU] > crack hashes
[BLACK] Running john locally...  # No remote host needed

[YOU] > hackrf scan 433mhz
[BLACK] Scanning with local HackRF...  # Runs on your machine

[YOU] > wifi scan
[BLACK] Scanning with local adapter...  # Uses your WiFi card
```

### GPU Acceleration for Hashcat

If you have an NVIDIA GPU on your Linux machine:

```bash
# Arch
sudo pacman -S cuda nvidia-utils

# Ubuntu
sudo apt install nvidia-driver-535 nvidia-cuda-toolkit

# Test
hashcat -I  # Should show your GPU
```

### HackRF Permissions

```bash
# Add udev rule for non-root access
echo 'SUBSYSTEM=="usb", ATTR{idVendor}=="1d50", ATTR{idProduct}=="6089", MODE="0666"' | sudo tee /etc/udev/rules.d/52-hackrf.rules
sudo udevadm control --reload-rules

# Test
hackrf_info
```

### WiFi Monitor Mode on Linux

```bash
# Check your adapter
iw list | grep -A 10 "Supported interface modes"

# If it shows "monitor", you're good
# Enable monitor mode
sudo ip link set wlan0 down
sudo iw wlan0 set monitor control
sudo ip link set wlan0 up

# Or use airmon-ng
sudo airmon-ng start wlan0
```
