# WP-Scan Complete Options Guide

## Overview
WP-Scan is a comprehensive WordPress security scanner with 19 security modules that can detect various types of malware, backdoors, and security issues.

---

## Command Line Syntax

```bash
./wp-scan-mod.sh [options] /path/to/wordpress
```

---

## Global Options

### Email Notifications
- `--email <address>` - Send report when warnings are found
- `--email-always` - Always send email, even with no warnings
- `--email-from <address>` - Set sender address for email
- `--email-subject <text>` - Custom email subject (status will be appended)

**Environment Variables:**
- `WP_SCAN_EMAIL_TO` - Default email recipient
- `WP_SCAN_EMAIL_FROM` - Default sender address
- `WP_SCAN_EMAIL_SUBJECT` - Default email subject
- `WP_SCAN_EMAIL_ALWAYS` - Set to 1 to always send email

### Module Selection
- `--menu` - Interactive menu to select scan modules
- `--only <modules>` - Run only specified modules (comma or space separated)
- `--skip <modules>` - Skip specified modules
- `--scan-all` - Force enable all modules

### Output Options
- `--sc` - Show code context (2 lines before/after matched signatures)
- `--json` - Output minimal JSON summary at the end
- `--exit-code <mode>` - Set exit code behavior:
  - `binary` (default): Exit 0 if clean, 1 if warnings
  - `count`: Exit with warning count (0-254)

### File Management
- `--zip <filename.zip>` - Archive all flagged files into a zip file
- `--with-cache` - Include cache directories in scans (excluded by default)

### Site Type
- `--no-wordpress` - Scan generic PHP site (skip WordPress-specific checks)

### Help
- `--help` - Show usage information

---

## Scan Modules (19 Total)

All modules are **enabled by default**. Use `--no-<module>` to disable or `--only` to run specific ones.

### 1. Recent Files (`--recent` / `--no-recent`)
**What it does:** Finds files modified in the last 60 minutes
**Why it matters:** Recently modified files may indicate active compromise
**Output:** List of recently changed files with timestamps

### 2. Suspicious Names (`--suspicious` / `--no-suspicious`)
**What it does:** Checks for common backdoor file/directory names
**Detects:**
- cg-bin, phpshell, c99, r57, webshell, wso
- adminer.php, phpmyadmin
- xmlrpc.php, enmnnu.php
**Why it matters:** Attackers often use recognizable backdoor names

### 3. Uploads Directory (`--uploads` / `--no-uploads`)
**What it does:** Scans wp-content/uploads for suspicious directories
**Detects:** Non-month directories (anything not 01-12)
**Why it matters:** Attackers create fake month folders to hide files

### 4. PHP in Uploads (`--uploads-php` / `--no-uploads-php`)
**What it does:** Finds executable PHP files in uploads directory
**Detects:**
- .php, .phtml, .php5, .php7, .phar, .inc files
- Double-extension files (image.jpg.php)
**Why it matters:** Uploads should only contain media files, not executables

### 5. Backdoor Functions (`--backdoor` / `--no-backdoor`)
**What it does:** Searches PHP files for high-risk functions
**Detects:** eval(), base64_decode(), shell_exec(), passthru(), system(), exec(), popen(), proc_open(), assert()
**Filters:** Excludes wp-includes/, wp-admin/, plugins/, themes/
**Why it matters:** These functions are commonly used in backdoors

### 6. Obfuscated Code (`--obfuscation` / `--no-obfuscation`)
**What it does:** Finds code obfuscation patterns
**Detects:**
- base64_decode, gzinflate, gzuncompress, gzdecode
- str_rot13, strrev, str_replace
- rawurldecode, urldecode
- preg_replace with /e modifier
- create_function
**Why it matters:** Obfuscation hides malicious code from detection

### 7. PHP Shells (`--phpshell` / `--no-phpshell`)
**What it does:** Searches for known web shell signatures
**Detects:**
- Known shells: C99, R57, WSO, B374K, FilesMan, IndoXploit
- Shell features: File manager, upload forms, symlinks
- Common patterns: php_uname, posix_geteuid, cmd=
- Suspicious filenames: *wso*.php, *c99*.php, shell.php
**Advanced checks:**
- Decoder + exec chains (base64_decode + eval in same file)
- Dangerous stream wrappers (php://input, data://, phar://)
- Stealth toggles (error_reporting(0), @eval)
- Variable function calls with superglobals
- High-entropy blobs in small PHP files

### 8. Hidden Files (`--hidden` / `--no-hidden`)
**What it does:** Finds hidden dotfiles in web root
**Detects:** .* files (excludes .git, .svn, .hg, .well-known)
**Why it matters:** Hidden files can contain secrets or backdoors

### 9. Superglobal Backdoors (`--superglobal` / `--no-superglobal`)
**What it does:** Finds code that executes user input directly
**Detects:** $_GET/$_POST/$_REQUEST/$_COOKIE used with eval/system/exec
**Why it matters:** Direct path to remote code execution

### 10. cURL Calls (`--curl` / `--no-curl`)
**What it does:** Finds curl_init() calls to external domains
**Filters:** Excludes wp-includes/, themes/, plugins/
**Why it matters:** Backdoors often phone home to C&C servers

### 11. WordPress Version (`--wpver` / `--no-wpver`)
**What it does:** Checks WordPress version from wp-includes/version.php
**Why it matters:** Outdated versions have known vulnerabilities

### 12. File Permissions (`--perms` / `--no-perms`)
**What it does:** Finds world-writable files (permissions: 777, 666, etc.)
**Filters:** Excludes cache/ and uploads/
**Why it matters:** World-writable files can be modified by anyone

### 13. Immutable Files (`--immutable` / `--no-immutable`)
**What it does:** Finds files with the immutable attribute (+i)
**Requires:** lsattr command (e2fsprogs package)
**Why it matters:** Immutable backdoors can't be deleted normally

### 14. Verification Files (`--verification` / `--no-verification`)
**What it does:** Finds search engine verification files
**Detects:**
- google*.html, bing*.html, yandex*.html
- .well-known/ directory files
**Why it matters:** Attackers may claim site ownership

### 15. Access Logs (`--access-logs` / `--no-access-logs`)
**What it does:** Scans web server access logs for suspicious requests
**Locations:**
- /home/\<user\>/access-logs/
- /home/\<user\>/logs/
**Detects:**
- Attempts to access .env, wp-config.php
- Admin/login attempts
- PHP file access in uploads
- Version control exposure (.git, .svn)
- PHPMyAdmin/Adminer access
- Scanner user agents (sqlmap, nikto, nmap, etc.)
- SQL injection attempts
- Directory traversal attempts
- Suspicious file extensions (.bak, .old, .swp)
**Features:**
- Parses both plain text and .gz compressed logs
- Extracts HTTP status codes
- Shows IP-based filtering support
- Provides heuristic analysis

### 16. ModSecurity Logs (`--modsec-logs` / `--no-modsec-logs`)
**What it does:** Scans ModSecurity audit/debug logs
**Locations:**
- /var/log/apache2/, /var/log/httpd/
- /var/log/nginx/
- /var/log/modsecurity/
**Detects:** Access denied events, rule triggers, blocked requests
**Features:**
- Shows rule IDs
- Extracts URIs and client IPs
- Summarizes top triggered rules

### 17. Dynamic Execution (`--dyn-exec` / `--no-dyn-exec`)
**What it does:** Finds patterns of dynamic function execution
**Detects:** Variable assignments containing function names as strings
**Example:** `$func = 'eval'; $func($code);`
**Why it matters:** Bypasses simple pattern matching

### 18. One-Liner Shells (`--oneliner` / `--no-oneliner`)
**What it does:** Finds tiny PHP files (< 5 lines) with dangerous functions
**Why it matters:** Compact backdoors are easy to hide

### 19. Image Headers (`--image-headers` / `--no-image-headers`) **[NEW]**
**What it does:** Scans image file headers for malicious PHP code
**Scans:** First 1KB of .jpg, .jpeg, .png, .gif, .webp, .ico, .svg, .bmp files
**Detects:**
- PHP tags (<?php, <?=)
- Dangerous functions in image headers
- Stealth techniques
**Performance:** Scans up to 10,000 images quickly
**Why it matters:** Common attack vector when servers are misconfigured

### 20. WP-CLI Checks (`--wp-cli` / `--no-wp-cli`)
**What it does:** Deep WordPress checks using WP-CLI
**Requires:** wp-cli installed and functional
**Checks:**
- Core file integrity (--verify-core flag)
- Plugin vulnerabilities
- Plugin checksums (wp plugin verify-checksums)
- Inactive plugins/themes
- User security (admin users, users with no role)
- Database status
- Suspicious options
**Optional:** Core file restoration (--restore-core flag)

---

## Interactive Menu Mode

```bash
./wp-scan-mod.sh --menu /path/to/wordpress
```

### Menu Options:
```
 1) recent                   (Recently modified files)
 2) suspicious               (Suspicious file/directory names)
 3) uploads                  (Non-month directories in uploads)
 4) uploads-php              (PHP files in uploads)
 5) backdoor                 (High-risk backdoor functions)
 6) obfuscation              (Obfuscated code)
 7) phpshell                 (PHP shell signatures)
 8) hidden                   (Hidden dotfiles)
 9) superglobal              (Superglobal backdoor patterns)
10) curl                     (cURL calls)
11) wpver                    (WordPress version)
12) perms                    (File permissions)
13) immutable                (Immutable files)
14) verification             (Verification files)
15) access-logs              (Access logs scan)
16) dyn-exec                 (Dynamic execution patterns)
17) oneliner                 (One-liner shells)
18) wp-cli                   (WP-CLI deep checks)
19) image-headers            (Image header malware scan)
```

### Menu Commands:
- `a` or `all` - Enable all modules
- `n` or `none` - Disable all modules
- `r` or `run` - Run scan with current selection
- `c` or `console` - Exit menu
- `q` or `quit` - Abort scan
- Numbers or names to toggle individual modules

---

## Usage Examples

### Basic Scans
```bash
# Full scan (all modules enabled)
./wp-scan-mod.sh /var/www/html

# Scan specific site
./wp-scan-mod.sh /home/username/public_html

# Quick security scan (most important checks)
./wp-scan-mod.sh --only backdoor,phpshell,uploads-php,superglobal,image-headers /var/www/html
```

### Email Reporting
```bash
# Send email on warnings
./wp-scan-mod.sh --email admin@example.com /var/www/html

# Always send email
./wp-scan-mod.sh --email admin@example.com --email-always /var/www/html

# Custom subject
./wp-scan-mod.sh --email admin@example.com --email-subject "Daily WP Scan" /var/www/html
```

### Advanced Options
```bash
# Show code context for matches
./wp-scan-mod.sh --sc /var/www/html

# Create zip of flagged files
./wp-scan-mod.sh --zip /tmp/suspicious-files.zip /var/www/html

# JSON output for automation
./wp-scan-mod.sh --json /var/www/html

# Exit code = warning count
./wp-scan-mod.sh --exit-code count /var/www/html
```

### Module Combinations
```bash
# Recent changes + backdoor scan
./wp-scan-mod.sh --only recent,backdoor /var/www/html

# Skip long-running modules
./wp-scan-mod.sh --skip access-logs,modsec-logs,wp-cli /var/www/html

# Upload security focus
./wp-scan-mod.sh --only uploads,uploads-php,image-headers /var/www/html

# Code pattern analysis
./wp-scan-mod.sh --only backdoor,obfuscation,phpshell,dyn-exec,oneliner,superglobal /var/www/html
```

### Scheduled Scans (Cron)
```bash
# Daily full scan with email
0 2 * * * /root/shell-scripts/wp-scan/wp-scan-mod.sh --email admin@example.com /var/www/html

# Hourly quick scan
0 * * * * /root/shell-scripts/wp-scan/wp-scan-mod.sh --only recent,image-headers /var/www/html

# Weekly deep scan
0 3 * * 0 /root/shell-scripts/wp-scan/wp-scan-mod.sh --scan-all --zip /backup/wp-scan-$(date +\%F).zip /var/www/html
```

---

## Output Interpretation

### Warning Levels
- `!!! WARNING:` - Potential security issue found (requires review)
- `OK:` - Check completed, no issues found
- `INFO:` - Informational message

### False Positives
The scanner may flag legitimate code. Always manually review findings:
- **Themes/Plugins** - May use base64_decode or eval legitimately
- **Admin tools** - PHPMyAdmin, Adminer are legitimate (but secure them!)
- **Development files** - .git folders, backup files should be removed from production

### Next Steps After Detection
1. **Review flagged files** - Check the code manually
2. **Use --sc flag** - See code context around matches
3. **Check access logs** - Look for exploitation attempts
4. **Isolate malware** - Use --zip to archive suspicious files
5. **Clean site** - Remove malicious code
6. **Update everything** - WordPress core, plugins, themes
7. **Change credentials** - Passwords, API keys, database passwords
8. **Harden security** - Fix permissions, update .htaccess, enable firewall

---

## Performance Tips

### Fast Scans
```bash
# Quick triage (< 30 seconds)
./wp-scan-mod.sh --only recent,uploads-php,image-headers /var/www/html

# Skip resource-intensive modules
./wp-scan-mod.sh --skip access-logs,modsec-logs /var/www/html
```

### Large Sites
- Use `--only` to target specific issues
- Run full scans during off-peak hours
- Consider `--with-cache` only if cache directories are suspect

### Multiple Sites
```bash
# Scan all sites on server
for site in /home/*/public_html; do
    echo "Scanning $site..."
    ./wp-scan-mod.sh --email admin@example.com "$site"
done
```

---

## Exit Codes

### Binary Mode (default)
- `0` - Clean scan, no warnings
- `1` - Warnings found

### Count Mode (`--exit-code count`)
- `0` - Clean scan
- `1-254` - Number of warnings found
- `254` - 254 or more warnings

---

## Environment Variables

```bash
# Email configuration
export WP_SCAN_EMAIL_TO="security@example.com"
export WP_SCAN_EMAIL_FROM="scanner@example.com"
export WP_SCAN_EMAIL_SUBJECT="WordPress Security Scan"
export WP_SCAN_EMAIL_ALWAYS=1

# IP exclusion list
export WP_SCAN_EXCLUDED_IPS_FILE="/root/.wp-scan-excluded-ips.txt"

# WP-CLI path
export WP_CLI_BIN="/usr/local/bin/wp"

# Run scan
./wp-scan-mod.sh /var/www/html
```

---

## Troubleshooting

### WP-CLI Not Found
```bash
# Check if wp-cli is installed
which wp

# Install wp-cli
curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar
sudo mv wp-cli.phar /usr/local/bin/wp

# Or specify path
export WP_CLI_BIN=/path/to/wp
```

### Email Not Sending
```bash
# Check if sendmail/msmtp is installed
which sendmail
which msmtp

# Test email manually
echo "Test" | mail -s "Test" user@example.com
```

### Permission Denied
```bash
# Run as root or with sudo
sudo ./wp-scan-mod.sh /var/www/html

# Or ensure script is executable
chmod +x wp-scan-mod.sh
```

---

## Best Practices

1. **Run regularly** - Schedule daily or weekly scans
2. **Review all warnings** - Don't ignore findings
3. **Keep logs** - Archive scan results for comparison
4. **Combine with backups** - Scan before backup to avoid archiving malware
5. **Update scanner** - Keep wp-scan updated for new detection patterns
6. **Use --sc flag** - Always review code context
7. **Archive suspicious files** - Use --zip before cleaning
8. **Document findings** - Keep records of incidents
9. **Test in dev first** - Verify scanner behavior on test sites
10. **Exclude known-good IPs** - Use excluded-ips.txt for your admin IPs

---

## Support & Documentation

- Main script: `wp-scan-mod.sh`
- Documentation: `README.md`, `IMAGE_HEADERS_FEATURE.md`
- Changes log: `CHANGES.md`
- This guide: `COMPLETE_OPTIONS_GUIDE.md`

For questions or issues, review the documentation files included with the scanner.
