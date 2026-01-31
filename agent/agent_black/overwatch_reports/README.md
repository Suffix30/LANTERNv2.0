# Overwatch Reports

This folder stores situational analysis reports from Agent BLACK's Overwatch mode.

Reports are auto-saved when running:
```bash
black overwatch --snapshot
```

## File Naming

Files are named: `overwatch_YYYYMMDD_HHMMSS.txt`

Example: `overwatch_20260130_143022.txt`

## Options

```bash
# Auto-save to this folder (default)
black overwatch --snapshot

# Save to custom location
black overwatch --snapshot --export /path/to/report.txt

# Don't save (print only)
black overwatch --snapshot --no-save
```

## Note

This folder is in `.gitignore` - reports contain personal scan/terminal data and should not be committed.
