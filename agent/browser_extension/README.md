# Agent BLACK Browser Extension

Gives Agent BLACK awareness of your browser tabs for full situational awareness during CTFs and bug bounties.

## Installation

1. Open Chrome/Edge and go to `chrome://extensions/`
2. Enable "Developer mode" (toggle in top right)
3. Click "Load unpacked"
4. Select this folder (`browser_extension/`)

## What It Does

- Tracks all open tabs (URLs and titles)
- Detects which tab is active
- Sends state to Agent BLACK every 5 seconds
- Works offline (saves locally when agent not running)

## Privacy

- Runs 100% locally
- No data sent to external servers
- Only communicates with localhost:8765 (Agent BLACK)

## Usage with Overwatch Mode

```bash
# Terminal 1: Start the browser bridge server
python black_overwatch.py --server

# Terminal 2: Or just use overwatch mode
python black_overwatch.py
```

Then Agent BLACK can see:
- All your open tabs (HackTheBox, CTF challenges, documentation)
- What page you're currently viewing
- Research you've done

## Example Output

```
BROWSER TABS:
  - HackTheBox: Machine "Photobomb" - https://app.hackthebox.com/machines/...
  - PortSwigger: SQL Injection - https://portswigger.net/web-security/sql-injection
  - GitHub: PayloadsAllTheThings - https://github.com/swisskyrepo/PayloadsAllTheThings
  - Target: http://10.10.11.182/
```

Agent BLACK uses this to understand:
- What machine/challenge you're working on
- What research you've done
- What you might be stuck on
