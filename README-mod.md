# wp-scan (modular)

This folder contains a modular Bash scanner for WordPress sites.

## What it does

The scanner is designed to help you quickly spot common compromise indicators:

- Recently modified files
- Suspicious filenames (webshell patterns)
- PHP in `wp-content/uploads/`
- Verification files (google/bing/yandex + `.well-known`)
- Suspicious access log requests (if logs are under `/home/*`)
- Malicious PHP indicators (eval/base64_decode/obfuscation/dynamic exec/one-liners)
- Hidden dotfiles
- Superglobal-driven backdoor patterns
- cURL calls in non-standard folders
- WordPress version readout
- World-writable permissions
- Immutable files (`chattr +i`)
- Optional WP-CLI deep checks

## Usage

Run it from Linux (or WSL) like:

```bash
./wp-scan.sh /path/to/wordpress
```

> Note: the script expects a WordPress root (it checks for `wp-config.php`) unless you use `--no-wordpress`.

## Menu mode

Interactive selection menu:

```bash
./wp-scan.sh --menu /path/to/wordpress
```

- You can type multiple triggers on one line (space or comma separated)
- `r` runs scans using only the currently-toggled modules
- `c` exits back to console without scanning

## CLI “only run what I asked for”

If you pass any module trigger flags (like `--recent`), the scanner switches to **explicit selection mode**:

```bash
./wp-scan.sh --recent --uploads-php /path/to/wordpress
```

That means **only** those selected modules run.

If you want everything regardless, use:

```bash
./wp-scan.sh --scan-all /path/to/wordpress
```

## WP‑CLI checks

The `--wp-cli` module runs deeper checks via WP‑CLI when available.

If the scanner runs as root, it automatically adds `--allow-root` when calling `wp`.

## Files

- `wp-scan.sh`: entry script
- `lib/`: shared code (CLI parsing, menu, dispatcher)
- `modules/`: one file per scan module
