# Quick Start Guide

Get scanning in under 5 minutes.

## Installation

```bash
# Quick install via pip
pip install git+https://github.com/Suffix30/LANTERNv2.0.git

# Verify installation
lantern --help
```

### Alternative: From Source

```bash
git clone https://github.com/Suffix30/LANTERNv2.0.git
cd LANTERNv2.0
pip install -e .
```

### Update to Latest

```bash
pip install --upgrade git+https://github.com/Suffix30/LANTERNv2.0.git
```

## Your First Scan

```bash
# Basic scan
lantern -t https://example.com

# Scan specific vulnerabilities
lantern -t https://example.com -m sqli,xss,headers

# Generate HTML report
lantern -t https://example.com -o my_report --format html
```

## Understanding Output

LANTERN uses severity levels:

| Level | Color | Meaning |
|-------|-------|---------|
| CRITICAL | Red | Immediate exploitation possible |
| HIGH | Orange | Serious vulnerability |
| MEDIUM | Yellow | Should be fixed |
| LOW | Blue | Minor issue |
| INFO | Gray | Informational finding |

## Common Use Cases

### Web Application Test
```bash
lantern -t https://target.com --crawl -m sqli,xss,csrf --format html
```

### API Security
```bash
lantern -t https://api.target.com -m api,jwt,cors -H "Authorization: Bearer TOKEN"
```

### Quick Recon
```bash
lantern -t https://target.com --chain full_recon --fast
```

### CI/CD Integration
```bash
lantern -t https://target.com --ci --fail-on HIGH --sarif results.sarif
```

## Next Steps

- [Full Command Reference](COMMANDS.md)
- [Module Documentation](modules/)
- [Advanced Features](guides/advanced.md)
- [Agent BLACK Setup](../agent/docs/SETUP.md)
