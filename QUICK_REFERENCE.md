# WP-Scan Quick Reference Card

## Quick Start
```bash
./wp-scan-mod.sh /path/to/wordpress              # Full scan
./wp-scan-mod.sh --help                          # Show all options
./wp-scan-mod.sh --menu /path/to/wordpress       # Interactive menu
```

## 19 Security Modules

| # | Module | Flag | What It Scans |
|---|--------|------|---------------|
| 1 | **Recent** | `--recent` | Files modified in last 60 min |
| 2 | **Suspicious** | `--suspicious` | Known backdoor filenames |
| 3 | **Uploads** | `--uploads` | Non-month dirs in uploads |
| 4 | **Uploads-PHP** | `--uploads-php` | PHP files in uploads |
| 5 | **Backdoor** | `--backdoor` | Dangerous PHP functions |
| 6 | **Obfuscation** | `--obfuscation` | Encoded/obfuscated code |
| 7 | **PHP Shell** | `--phpshell` | Web shell signatures |
| 8 | **Hidden** | `--hidden` | Hidden dotfiles |
| 9 | **Superglobal** | `--superglobal` | Direct user input execution |
| 10 | **cURL** | `--curl` | External connections |
| 11 | **WP Version** | `--wpver` | WordPress version check |
| 12 | **Permissions** | `--perms` | World-writable files |
| 13 | **Immutable** | `--immutable` | Locked files (+i attribute) |
| 14 | **Verification** | `--verification` | SEO verification files |
| 15 | **Access Logs** | `--access-logs` | Suspicious HTTP requests |
| 16 | **Dyn-Exec** | `--dyn-exec` | Dynamic code execution |
| 17 | **One-Liner** | `--oneliner` | Tiny malicious files |
| 18 | **WP-CLI** | `--wp-cli` | Deep WordPress checks |
| 19 | **Image Headers** | `--image-headers` | Malicious code in images |

## Common Use Cases

### Quick Security Check
```bash
./wp-scan-mod.sh --only backdoor,phpshell,uploads-php,image-headers /var/www/html
```

### After Hack Recovery
```bash
./wp-scan-mod.sh --scan-all --sc --zip /backup/quarantine.zip /var/www/html
```

### Daily Automated Scan
```bash
./wp-scan-mod.sh --email admin@example.com /var/www/html
```

### Upload Directory Focus
```bash
./wp-scan-mod.sh --only uploads,uploads-php,image-headers /var/www/html
```

### Check Recent Changes
```bash
./wp-scan-mod.sh --only recent --sc /var/www/html
```

## Key Options

### Output Control
- `--sc` - Show code context around matches
- `--json` - JSON output for parsing
- `--zip <file>` - Archive flagged files

### Module Selection
- `--only <modules>` - Run specific modules only
- `--skip <modules>` - Exclude specific modules
- `--scan-all` - Force all modules on

### Email Reporting
- `--email <addr>` - Send report if warnings found
- `--email-always` - Always send email
- `--email-subject <text>` - Custom subject

### Exit Behavior
- `--exit-code binary` - Exit 0/1 (default)
- `--exit-code count` - Exit with warning count

## Disable Specific Modules
```bash
# Prefix with --no-
./wp-scan-mod.sh --no-access-logs --no-modsec-logs /var/www/html
```

## Cron Examples

```bash
# Daily full scan at 2 AM
0 2 * * * /root/shell-scripts/wp-scan/wp-scan-mod.sh --email admin@example.com /var/www/html

# Hourly quick check
0 * * * * /root/shell-scripts/wp-scan/wp-scan-mod.sh --only recent,image-headers /var/www/html

# Weekly deep scan with archive
0 3 * * 0 /root/shell-scripts/wp-scan/wp-scan-mod.sh --scan-all --zip /backup/scan-$(date +\%F).zip /var/www/html
```

## What Gets Detected

### Backdoors
- eval(), base64_decode(), exec(), system()
- Web shells (C99, R57, WSO, B374K)
- Obfuscated code (gzinflate, str_rot13)
- Dynamic execution patterns
- One-liner shells

### Uploads
- PHP files in wp-content/uploads/
- Suspicious directory structures
- **Malicious code in image headers** ✨ NEW

### Access Patterns
- Failed login attempts
- Scanner activity (sqlmap, nikto)
- SQL injection attempts
- Directory traversal attempts
- Suspicious user agents

### File Issues
- Recently modified files
- World-writable permissions
- Immutable backdoors
- Hidden dotfiles
- Verification files

## Performance

| Scan Type | Time | Modules |
|-----------|------|---------|
| **Quick** | 10-30s | recent, image-headers, uploads-php |
| **Standard** | 1-3 min | All code scanning modules |
| **Full** | 3-10 min | All modules including logs |
| **Deep** | 5-20 min | Full + WP-CLI + access-logs |

## Exit Codes

- **0** = Clean (no warnings)
- **1** = Warnings found (binary mode)
- **1-254** = Warning count (count mode)

## Tips

✅ **DO:**
- Run scans regularly (daily/weekly)
- Use --sc to review code context
- Archive findings with --zip
- Review all warnings manually
- Exclude your admin IPs from log scans

❌ **DON'T:**
- Ignore warnings (check them all)
- Run during peak traffic (for full scans)
- Delete files without review
- Forget to check access logs
- Skip updating WordPress after cleaning

## File Locations

```
wp-scan/
├── wp-scan-mod.sh              # Main script
├── lib/
│   ├── core.sh                 # Core functionality
│   ├── dispatcher.sh           # Module dispatcher
│   └── menu.sh                 # Interactive menu
├── modules/
│   ├── recent.sh
│   ├── backdoor.sh
│   ├── image_headers.sh        # ✨ NEW
│   └── ... (19 modules total)
├── COMPLETE_OPTIONS_GUIDE.md   # Full documentation
├── IMAGE_HEADERS_FEATURE.md    # Image scanner docs
└── README.md                   # Project readme
```

## Getting Help

```bash
./wp-scan-mod.sh --help                    # Show all options
cat COMPLETE_OPTIONS_GUIDE.md             # Full documentation
cat IMAGE_HEADERS_FEATURE.md              # Image scanner guide
```

## Environment Variables

```bash
export WP_SCAN_EMAIL_TO="admin@example.com"
export WP_SCAN_EMAIL_FROM="scanner@example.com"
export WP_SCAN_EXCLUDED_IPS_FILE="./excluded-ips.txt"
export WP_CLI_BIN="/usr/local/bin/wp"
```

---

**Version:** 1.1 (with Image Header Scanner)  
**Last Updated:** 2026-07-05  
**Total Modules:** 19
