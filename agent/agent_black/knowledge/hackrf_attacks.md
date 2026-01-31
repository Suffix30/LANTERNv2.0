# HackRF One SDR Knowledge

## Device Specs
- Frequency: 1 MHz to 6 GHz
- Sample rate: up to 20 Msps
- Half-duplex (TX or RX, not both)
- 8-bit samples

## Common Target Frequencies
| Frequency | Use |
|-----------|-----|
| 315 MHz | US car fobs, garage doors |
| 433.92 MHz | EU car fobs, weather stations, doorbells |
| 868 MHz | EU IoT, smart home |
| 915 MHz | US IoT, LoRa, smart meters |
| 1.575 GHz | GPS L1 |
| 2.4 GHz | WiFi, Bluetooth, Zigbee, drones |
| 5.8 GHz | WiFi 5GHz, FPV drones |

## Basic Commands

### Check Device
```bash
hackrf_info
```

### Capture RF Signal
```bash
hackrf_transfer -r capture.raw -f 433920000 -s 2000000 -n 20000000
```
- `-r` = receive to file
- `-f` = frequency in Hz
- `-s` = sample rate
- `-n` = number of samples

### Replay/Transmit Signal
```bash
hackrf_transfer -t capture.raw -f 433920000 -s 2000000 -x 40
```
- `-t` = transmit from file
- `-x` = TX gain (0-47)

## Attack Types

### Rolling Code Bypass (RollJam)
1. Jam signal while capturing
2. Victim retries, capture second code
3. Replay first code later
4. Second code still valid

### Replay Attack
1. Capture: `hackrf_transfer -r signal.raw -f 315000000 -s 2000000`
2. Analyze with inspectrum
3. Replay: `hackrf_transfer -t signal.raw -f 315000000 -s 2000000 -x 40`

### GPS Spoofing (illegal!)
- Use gps-sdr-sim to generate fake GPS
- Requires precise timing

## Analysis Tools
- **inspectrum**: Visual signal analysis
- **rtl_433**: Auto-decode common protocols
- **Universal Radio Hacker**: GUI for analyze/replay
- **GNU Radio**: Complex signal processing

## Signal Analysis Workflow
1. Capture raw IQ data
2. Open in inspectrum
3. Find signal bursts
4. Measure symbol rate
5. Identify modulation (OOK, FSK, etc.)
6. Decode protocol
7. Replay or craft custom signals

## Safety
- Transmitting without license is illegal in most countries
- Only test on YOUR OWN devices
- Use Faraday cage for testing
- Check local RF regulations
