# wp-scan

Generic WordPress and site security scanner (Bash) that surfaces suspicious changes and high‑risk patterns quickly. Runs on Linux/WSL and scans a target webroot for common indicators of compromise.

## Features

- **Recent changes**: list files modified in the last 60 minutes
- **Suspicious names**: flag common backdoor file/dir names (c99, r57, wso, adminer.php, etc.)
- **Uploads sanity**: detect non‑month directories under `wp-content/uploads`
- **Uploads PHP**: flag any `*.php` files inside `wp-content/uploads` (often malicious)
- **Backdoor signatures**: find usage of `eval`, `base64_decode`, `shell_exec`, `system`, `exec`, `passthru`, etc.
- **Obfuscation**: find `base64_decode`, `gzinflate`, `str_rot13`, `strrev`, `assert`, `create_function` patterns
- **PHP shells**: detect known signatures and common filenames (C99, R57, WSO, B374K, FilesMan, …)
- **Dynamic execution**: detect patterns where function names are built from variables or strings to evade static analysis
- **One-liner shells**: find very small PHP files (< 5 lines) that contain dangerous functions, a common backdoor tactic
- **Immutable files**: detect files with the immutable (`+i`) attribute, a strong indicator of rootkits or persistent backdoors
- **WP-CLI deep checks**: perform context-aware WordPress checks (if `wp` command is available):
    - **Core integrity**: verify core files against official checksums.
    - **Plugin/Theme status**: list inactive plugins/themes and known vulnerabilities.
    - **User security**: list admin users and flag users with no role.
    - **Database status**: report database size and suspicious options.
- **Hidden dotfiles**: flag `.*` files (excluding VCS and `.well-known`) that may hide config/secrets
- **Superglobal backdoors**: spot `$_GET/$_POST/$_REQUEST/$_COOKIE` driving `eval/exec/system/...`
- **cURL calls**: list files that make cURL requests (frequent in data exfil/backdoors)
- **WordPress version**: report detected WP version for manual CVE checks
- **Permissions**: surface world‑writable files outside cache/uploads
- **Verification files**: detect top‑level verification HTML and any files in `.well-known` (fixes prior search)
- **Access logs**: scan `/home/<user>/access-logs` and `/home/<user>/logs` for suspicious request patterns (webshell probes, traversal, SQLi markers, etc.)
- **ModSecurity logs**: scan common ModSecurity audit/debug logs under `/var/log/*` for access denials and rule hits (rule id/message/uri/client when present)
- **Excluded IPs (results)**: hide known/noisy IPs from access-log scan output via `excluded-ips.txt` or `--exclude-ips-file` (scan still reads all logs)
- **Email notifications**: send the full report via mail/sendmail/msmtp when warnings are found
- **JSON output**: machine‑readable summary for automation
- **Exit code control**: choose between binary 0/1 or counts (capped to 254)
- **Interactive menu**: choose which modules to run without CLI flags (menu shows the trigger flag for each module)
- **Non‑WordPress mode**: skip WP‑specific checks safely for generic sites

## Requirements

- Bash (Linux/WSL)
- Standard tools: `find`, `grep`, `sed`, `tee`, `mktemp`
- Optional for email: `mail`, `sendmail`, or `msmtp`
- **Optional for WP-CLI module**: `wp` (WP-CLI) and `jq` (for parsing JSON output from WP-CLI)
- **Optional for immutable file module**: `lsattr` (from `e2fsprogs`)

## Usage

```bash
bash wp-scan.sh [options] /path/to/site/root
```

If no arguments are provided, usage is shown.

Note: This script now enables strict mode (set -euo pipefail) and includes additional runtime checks. Some optional features require external tools (jq, zip, gzip, wp, lsattr); the script will warn if they're unavailable and skip related checks.

The top-level wp-scan.sh now delegates to a modular implementation (wp-scan-mod.sh + lib/) to consolidate helper functions and make the codebase easier to extend and test.

New features added:
- More robust uploads directory scanning (avoids subshell variable scoping issues)
- Improved JSON output with per-module file lists
- Helpers to convert lists into JSON arrays for machine consumption
- Remote HTTP scan mode: use --url <site-url> to perform lightweight remote checks (meta generator, common endpoints)
- Dry-run mode: --dry-run to show what would be done without making changes
- Verbosity: -v/--verbose to increase verbosity


### Options

- `--email <addr>`: send report to this address if warnings were found
- `--email-always`: always send email even when there are no warnings
- `--email-from <addr>`: sender address when using sendmail/msmtp
- `--email-subject <text>`: base subject; status appended
- `--menu`: interactive module selection (no extra flags needed)
- `--only <modules>`: run only these modules (CSV or space‑separated)
- `--skip <modules>`: skip these modules (CSV or space‑separated)
- `--no-wordpress`: generic site mode; WP‑specific modules disabled by default
- `--sc`: show matched lines with line numbers for signature hits (concise triage)
- `--json`: output a minimal JSON summary of counts by module and overall status
- `--exit-code <binary|count>`: exit 0/1 in binary mode or return the warning count (capped to 254)
- `--with-cache`: include `wp-content/cache` in the recent files scan (excluded by default)
- `--zip <filename.zip>`: create a zip archive containing flagged files (recent changes, PHP shells, backdoor/obfuscation matches, hidden dotfiles, superglobal patterns, verification files, uploads PHP, world‑writable, filtered cURL, dynamic execution, one-liner shells, immutable files). Entries use absolute paths, and a `wp-scan-manifest.txt` is included listing all full paths for easy reference.
- `--dry-run`: show actions that would be taken (archives, signature updates) without modifying files or creating archives
- `--sarif <file>`: write a minimal SARIF v2.1.0 report containing flagged file locations
- `--csv <file>`: write a simple CSV report (file,module,message) for consumption by triage tools
- `--exclude-ips-file <file>`: file containing IPs to exclude from access-log *results* (one IP per line; `#` comments allowed)
- `--scan-all`: force-enable all modules for this run (overrides default non‑WP exclusions)

Environment variables for email:

- `WP_SCAN_EMAIL_TO`, `WP_SCAN_EMAIL_FROM`, `WP_SCAN_EMAIL_SUBJECT`, `WP_SCAN_EMAIL_ALWAYS`

Environment variables:

- `WP_SCAN_EXCLUDED_IPS_FILE`: same as `--exclude-ips-file` (optional)
- `NO_COLOR`: set to disable ANSI color in the Summary output

### Module triggers

- `--recent` / `--no-recent`
- `--suspicious` / `--no-suspicious`
- `--uploads` / `--no-uploads`
- `--uploads-php` / `--no-uploads-php`
- `--backdoor` / `--no-backdoor`
- `--obfuscation` / `--no-obfuscation`
- `--phpshell` / `--no-phpshell`
- `--dyn-exec` / `--no-dyn-exec`
- `--oneliner` / `--no-oneliner`
- `--wp-cli` / `--no-wp-cli`
- `--immutable` / `--no-immutable`
- `--hidden` / `--no-hidden`
- `--superglobal` / `--no-superglobal`
- `--curl` / `--no-curl`
- `--wpver` / `--no-wpver`
- `--perms` / `--no-perms`
- `--verification` / `--no-verification`
- `--access-logs` / `--no-access-logs`
- `--modsec-logs` / `--no-modsec-logs`

Modules: `recent`, `suspicious`, `uploads`, `uploads-php`, `backdoor`, `obfuscation`, `phpshell`, `dyn-exec`, `oneliner`, `wp-cli`, `immutable`, `hidden`, `superglobal`, `curl`, `wpver`, `perms`, `verification`, `access-logs`, `modsec-logs`, `all`

Note on module triggers:

- If you pass one or more **enable** triggers (example: `--modsec-logs`), the script will run **only** those enabled modules for that run.
- Use `--scan-all` if you want the full scan.
- `--no-...` triggers simply disable modules from the default full scan.

### Interactive menu

Run with `--menu` and enter selections like `1,3,8`:

1) Recent files (`--recent`)
2) Suspicious names (`--suspicious`)
3) Uploads sanity (non‑month dirs) (`--uploads`)
4) Backdoor signatures (`--backdoor`)
5) Obfuscation (`--obfuscation`)
6) cURL calls (`--curl`)
7) WordPress version (`--wpver`)
8) Permissions (`--perms`)
9) Uploads PHP (`--uploads-php`)
10) Hidden dotfiles (`--hidden`)
11) Superglobal backdoors (`--superglobal`)
12) Verification files (.well-known & top-level) (`--verification`)
13) Access logs scan (`--access-logs`)
14) ModSecurity logs scan (`--modsec-logs`)
15) Dynamic execution patterns (`--dyn-exec`)
16) Potential one-liner shells (`--oneliner`)
17) WP-CLI deep checks (`--wp-cli`)
18) Immutable files (+i attribute) (`--immutable`)

### JSON output

When `--json` is set, a compact JSON summary like below is printed:

```json
{
  "site": "/var/www/html/site",
  "status": "WARNINGS",
  "warnings": 3,
  "modules": {
    "recent": 2,
    "uploads_non_month": 1,
    "uploads_php": 0,
    "backdoor": 1,
    "obfuscation": 0,
    "phpshell": 0,
    "dyn_exec": 1,
    "oneliner": 0,
    "wp_cli": 1,
    "immutable": 1,
    "hidden": 0,
    "superglobal": 0,
    "curl": 0,
    "perms_world_writable": 0,
    "verification_files": 1,
    "access_logs": 2,
    "modsec_logs": 1
  }
}
```

### Exit codes

- `binary`: exits 0 if no warnings, 1 if any warnings
- `count`: exits with the number of warnings (max 254)

### Examples

```bash
# Full scan with context, JSON summary, and warning count exit mode
bash wp-scan.sh --sc --json --exit-code count /var/www/html/site

# Generic site scan (non‑WordPress), JSON summary
bash wp-scan.sh --no-wordpress --json /var/www/html/site

# Run only uploads sanity and backdoor signatures
bash wp-scan.sh --only uploads,backdoor /var/www/html/site

# Interactive selection
bash wp-scan.sh --menu /var/www/html/wordpress

# Email when warnings are found
bash wp-scan.sh --email security@example.com /var/www/html/site

# Include cache changes in recent file scan (default excludes cache)
bash wp-scan.sh --with-cache /var/www/html/site

# Zip flagged files for triage
bash wp-scan.sh --zip /var/www/html/scan-flags.zip /var/www/html/site
```

## Notes

- `.well-known` and top‑level verification HTML files are detected to help spot unauthorized ownership claims.
- Excluding IPs from results:
  - If `excluded-ips.txt` exists next to `wp-scan.sh`, it is used automatically.
  - You can override with `--exclude-ips-file /path/to/file` or `WP_SCAN_EXCLUDED_IPS_FILE=/path/to/file`.
  - This only filters what gets printed; it does not skip scanning the log files.
- Access logs scan:
  - If the scanned site path looks like `/home/<user>/public_html/...`, the script will prefer `/home/<user>/access-logs` and `/home/<user>/logs`.
  - Otherwise it falls back to scanning `/home/*/access-logs` and `/home/*/logs`.
- PHP files inside `wp-content/uploads` are commonly malicious; legitimate sites should store media only.
- Context preview (`--sc`) prints matched lines with their line numbers (no surrounding context).
- cURL matches are filtered to ignore standard WP core/theme/plugin paths.
- This scanner can produce false positives; always verify manually.
- The Summary may show a red `Files to review (high-signal matches; not proof)` section listing paths worth checking first.
- The WP-CLI module requires the `wp` command to be installed and accessible.
- The immutable file check requires the `lsattr` command and only works on filesystems that support extended attributes (like ext4).

## Changelog

- **2026‑01‑09**: Added ModSecurity log scanning (`--modsec-logs`) and included results in Summary/JSON output.
- **2026‑01‑09**: Added excluded IP filtering for access-log results (`excluded-ips.txt`, `--exclude-ips-file`, `WP_SCAN_EXCLUDED_IPS_FILE`), added a high-signal “files to review” summary section, and fixed numeric warning-count parsing that could trigger `integer expression expected`.
- **2026‑01‑02**: Added `--wp-cli` module for deep WordPress-specific checks (core integrity, vulnerabilities, users) and `--immutable` module to detect files with the `+i` attribute. Updated requirements and all documentation.
- **2026‑01‑01**: Added `dyn-exec` and `oneliner` modules to detect more advanced and unknown PHP shells. Fixed output issues where file lists were not being displayed for several modules. Tagged: `features/advanced-shell-detection-2026-01-01`.
- **2025‑12‑31**: Added uploads‑PHP, hidden dotfiles, superglobal backdoor scan, JSON summary output, exit‑code control, and fixed verification files search. Tagged: `features/all-suggested-2025-12-31`.

## License

GPLv3 (see `LICENSE`).

## Docker
A Dockerfile has been added to allow running wp-scan in a lightweight container.
Build: docker build -t wp-scan .
Run:  docker run --rm wp-scan --help

## CI
A GitHub Actions workflow (./github/workflows/ci.yml) has been added to run ShellCheck and basic checks on push and pull requests.
