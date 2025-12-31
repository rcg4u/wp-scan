#!/bin/bash

# ====================================================================
# Generic WordPress Security Scanner
#
# Usage: ./generic_wp_scan.sh [options] /path/to/site/root
#
# Options:
#   --email <addr>           Send report to this address when warnings found
#   --email-always           Always send email even when no warnings
#   --email-from <addr>      Sender address (sendmail/msmtp)
#   --email-subject <text>   Base subject; status appended
#   --menu                   Interactive menu to select scan modules
#   --only <modules>         Run only these modules (csv or space-separated)
#   --skip <modules>         Skip these modules (csv or space-separated)
#   --no-wordpress           Scan generic site; skip WordPress-specific checks
#   --sc                     Show 2 lines of code context around matched signatures
#   --json                   Output a minimal JSON summary at the end
#   --exit-code <mode>       Exit code mode: 'binary' (0/1) or 'count' (0-254)
#   --zip <filename.zip>     Zip up flagged files into the specified archive
#   --scan-all               Force-enable all modules for this run
#
# Module Triggers (enable/disable individually):
#   --recent / --no-recent
#   --suspicious / --no-suspicious
#   --uploads / --no-uploads
#   --backdoor / --no-backdoor
#   --obfuscation / --no-obfuscation
#   --phpshell / --no-phpshell
#   --uploads-php / --no-uploads-php
#   --hidden / --no-hidden
#   --superglobal / --no-superglobal
#   --curl / --no-curl
#   --wpver / --no-wpver
#   --perms / --no-perms
#   --help                   Show usage
#
# Modules: recent, suspicious, uploads, backdoor, obfuscation, phpshell, curl, wpver, perms, all
# Example: ./generic_wp_scan.sh --only recent,uploads --email admin@example.com /var/www/html/site
# ====================================================================

# --- Script Logic ---

# --- Argument Parsing (email support) ---
# Allow configuration through CLI flags or environment variables
# Env vars: WP_SCAN_EMAIL_TO, WP_SCAN_EMAIL_FROM, WP_SCAN_EMAIL_SUBJECT, WP_SCAN_EMAIL_ALWAYS
EMAIL_TO="${WP_SCAN_EMAIL_TO:-}"
EMAIL_FROM="${WP_SCAN_EMAIL_FROM:-}"
EMAIL_SUBJECT="${WP_SCAN_EMAIL_SUBJECT:-}"
EMAIL_ALWAYS="${WP_SCAN_EMAIL_ALWAYS:-0}"

ARG_SITE=""

# WordPress mode (default on). Disable with --no-wordpress
WP_MODE=1

# Show context toggle (2 lines before/after around matched signatures)
SHOW_CONTEXT=0
JSON_OUTPUT=0
EXIT_CODE_MODE="binary"
EXCLUDE_CACHE=1
ZIP_ENABLED=0
ZIP_TARGET_ZIP=""
ZIP_CANDIDATES=""
SCAN_ALL=0

# Module toggles (default: run all)
DO_RECENT=1
DO_SUSPICIOUS=1
DO_UPLOADS=1
DO_UPLOADS_PHP=1
DO_BACKDOOR=1
DO_OBFUSCATED=1
DO_PHPSHELL=1
DO_HIDDEN=1
DO_SUPERGLOBAL=1
DO_CURL=1
DO_WPVER=1
DO_PERMS=1

MENU_MODE=0

enable_only_defaults() {
    DO_RECENT=0; DO_SUSPICIOUS=0; DO_UPLOADS=0; DO_BACKDOOR=0; DO_OBFUSCATED=0; DO_CURL=0; DO_WPVER=0; DO_PERMS=0
}

set_module_flag() {
    case "$1" in
        recent) DO_RECENT=1 ;;
        suspicious) DO_SUSPICIOUS=1 ;;
        uploads) DO_UPLOADS=1 ;;
        backdoor) DO_BACKDOOR=1 ;;
        obfuscation) DO_OBFUSCATED=1 ;;
        curl) DO_CURL=1 ;;
        wpver) DO_WPVER=1 ;;
        perms) DO_PERMS=1 ;;
        all) DO_RECENT=1; DO_SUSPICIOUS=1; DO_UPLOADS=1; DO_UPLOADS_PHP=1; DO_BACKDOOR=1; DO_OBFUSCATED=1; DO_PHPSHELL=1; DO_HIDDEN=1; DO_SUPERGLOBAL=1; DO_CURL=1; DO_WPVER=1; DO_PERMS=1 ;;
    esac
}

clear_module_flag() {
    case "$1" in
        recent) DO_RECENT=0 ;;
        suspicious) DO_SUSPICIOUS=0 ;;
        uploads) DO_UPLOADS=0 ;;
        backdoor) DO_BACKDOOR=0 ;;
        obfuscation) DO_OBFUSCATED=0 ;;
        curl) DO_CURL=0 ;;
        wpver) DO_WPVER=0 ;;
        perms) DO_PERMS=0 ;;
        all) DO_RECENT=0; DO_SUSPICIOUS=0; DO_UPLOADS=0; DO_UPLOADS_PHP=0; DO_BACKDOOR=0; DO_OBFUSCATED=0; DO_PHPSHELL=0; DO_HIDDEN=0; DO_SUPERGLOBAL=0; DO_CURL=0; DO_WPVER=0; DO_PERMS=0 ;;
    esac
}

while [ $# -gt 0 ]; do
    case "$1" in
        -e|--email)
            EMAIL_TO="$2"; shift 2 ;;
        --email-from)
            EMAIL_FROM="$2"; shift 2 ;;
        --email-subject)
            EMAIL_SUBJECT="$2"; shift 2 ;;
        --email-always)
            EMAIL_ALWAYS=1; shift ;;
        --menu)
            MENU_MODE=1; shift ;;
        --only)
            enable_only_defaults
            LIST=$(echo "$2" | tr ',' ' ')
            for m in $LIST; do set_module_flag "$m"; done
            shift 2 ;;
        --skip)
            LIST=$(echo "$2" | tr ',' ' ')
            for m in $LIST; do clear_module_flag "$m"; done
            shift 2 ;;
        --no-wordpress)
            WP_MODE=0; shift ;;
        --sc)
            SHOW_CONTEXT=1; shift ;;
        --json)
            JSON_OUTPUT=1; shift ;;
        --exit-code)
            EXIT_CODE_MODE="$2"; shift 2 ;;
        --zip)
            ZIP_ENABLED=1; ZIP_TARGET_ZIP="$2"; shift 2 ;;
        --with-cache)
            EXCLUDE_CACHE=0; shift ;;
        --scan-all)
            SCAN_ALL=1; set_module_flag all; shift ;;
        --recent)
            set_module_flag recent; shift ;;
        --no-recent)
            clear_module_flag recent; shift ;;
        --suspicious)
            set_module_flag suspicious; shift ;;
        --no-suspicious)
            clear_module_flag suspicious; shift ;;
        --uploads)
            set_module_flag uploads; shift ;;
        --no-uploads)
            clear_module_flag uploads; shift ;;
        --backdoor)
            set_module_flag backdoor; shift ;;
        --no-backdoor)
            clear_module_flag backdoor; shift ;;
        --obfuscation)
            set_module_flag obfuscation; shift ;;
        --no-obfuscation)
            clear_module_flag obfuscation; shift ;;
        --phpshell)
            DO_PHPSHELL=1; shift ;;
        --no-phpshell)
            DO_PHPSHELL=0; shift ;;
        --uploads-php)
            DO_UPLOADS_PHP=1; shift ;;
        --no-uploads-php)
            DO_UPLOADS_PHP=0; shift ;;
        --hidden)
            DO_HIDDEN=1; shift ;;
        --no-hidden)
            DO_HIDDEN=0; shift ;;
        --superglobal)
            DO_SUPERGLOBAL=1; shift ;;
        --no-superglobal)
            DO_SUPERGLOBAL=0; shift ;;
        --curl)
            set_module_flag curl; shift ;;
        --no-curl)
            clear_module_flag curl; shift ;;
        --wpver)
            set_module_flag wpver; shift ;;
        --no-wpver)
            clear_module_flag wpver; shift ;;
        --perms)
            set_module_flag perms; shift ;;
        --no-perms)
            clear_module_flag perms; shift ;;
        -h|--help)
            echo "Usage: $0 [options] /path/to/site/root"
            echo
            echo "Options: --email <addr> --email-always --email-from <addr> --email-subject <text> --menu --only <modules> --skip <modules> --no-wordpress --sc --json --exit-code <binary|count> --zip <filename.zip> --with-cache --scan-all"
            echo "Module Triggers: --recent/--no-recent --suspicious/--no-suspicious --uploads/--no-uploads --uploads-php/--no-uploads-php --backdoor/--no-backdoor --obfuscation/--no-obfuscation --phpshell/--no-phpshell --hidden/--no-hidden --superglobal/--no-superglobal --curl/--no-curl --wpver/--no-wpver --perms/--no-perms"
            echo "Modules: recent, suspicious, uploads, uploads-php, backdoor, obfuscation, phpshell, hidden, superglobal, curl, wpver, perms, all"
            echo
            echo "Examples:"
            echo "  $0 --only recent,uploads --email admin@example.com /var/www/html/site"
            echo "  $0 --no-wordpress --phpshell --sc /var/www/html/site"
            echo "  $0 --menu /var/www/html/wordpress"
            exit 0 ;;
        *)
            if [ -z "$ARG_SITE" ]; then
                ARG_SITE="$1"; shift
            else
                echo "Warning: Unrecognized extra argument '$1' will be ignored." ; shift
            fi ;;
    esac
done

if [ -z "$ARG_SITE" ]; then
    # No arguments provided: show help and exit
    echo "Usage: $0 [options] /path/to/site/root"
    echo "Run with --help to see all options."
    exit 0
fi

# Assign the site argument to a variable and sanitize it.
SITE_PATH=$(realpath "$ARG_SITE")

# Check if the provided path actually exists and is a directory.
if [ ! -d "$SITE_PATH" ]; then
    echo "Error: Directory '$SITE_PATH' not found."
    exit 1
fi

# Check if it looks like a WordPress installation.
if [ "$WP_MODE" -eq 1 ]; then
    if [ ! -f "$SITE_PATH/wp-config.php" ]; then
        echo "Error: wp-config.php not found in '$SITE_PATH'. Is this a WordPress root?"
        exit 1
    fi
else
    echo "[Info] Non-WordPress mode: skipping wp-config.php check."
fi

echo "=========================================================================="
echo "Starting Generic WordPress Security Scan for: $SITE_PATH"
echo "=========================================================================="

# Optional interactive module selection
if [ "$MENU_MODE" -eq 1 ]; then
    echo "Interactive Module Selection"
    echo "  1) Recently modified files"
    echo "  2) Suspicious file/directory names"
    echo "  3) Non-month directories in uploads"
    echo "  4) High-risk backdoor functions (PHP)"
    echo "  5) Obfuscated code (PHP)"
    echo "  6) cURL calls (PHP)"
    echo "  7) WordPress version"
    echo "  8) File permissions"
    echo "  9) PHP files inside uploads"
    echo " 10) Hidden dotfiles"
    echo " 11) Superglobal backdoor patterns"
    echo "Select modules to run (e.g., 1,3,8) or press Enter for default (all):"
    read -r USER_SEL
    if [ -n "$USER_SEL" ]; then
        enable_only_defaults
        for n in $(echo "$USER_SEL" | tr ',' ' '); do
            case "$n" in
                1) DO_RECENT=1 ;;
                2) DO_SUSPICIOUS=1 ;;
                3) DO_UPLOADS=1 ;;
                4) DO_BACKDOOR=1 ;;
                5) DO_OBFUSCATED=1 ;;
                6) DO_CURL=1 ;;
                7) DO_WPVER=1 ;;
                8) DO_PERMS=1 ;;
                9) DO_UPLOADS_PHP=1 ;;
               10) DO_HIDDEN=1 ;;
               11) DO_SUPERGLOBAL=1 ;;
            esac
        done
    fi
fi

# --- Prepare log capture so we can email the full report later ---
if command -v mktemp >/dev/null 2>&1; then
    LOG_FILE=$(mktemp -t wp-scan-XXXXXX.log)
else
    LOG_FILE="$SITE_PATH/wp-scan-$(date +%Y%m%d%H%M%S).log"
fi

VERBOSE_TO_STDOUT=1
if command -v tee >/dev/null 2>&1; then
    # Mirror output to both stdout and the log file
    exec > >(tee -a "$LOG_FILE") 2>&1
else
    # Fallback: only log file (we'll print it back at the end)
    exec >>"$LOG_FILE" 2>&1
    VERBOSE_TO_STDOUT=0
fi

# In non-WordPress mode, disable WP-specific modules by default unless --scan-all was requested
if [ "$WP_MODE" -eq 0 ] && [ "$SCAN_ALL" -eq 0 ]; then
    DO_WPVER=0
    DO_UPLOADS=0
    DO_UPLOADS_PHP=0
fi

# --- 1. Check for Recently Modified Files ---
if [ "$DO_RECENT" -eq 1 ]; then
    echo -e "\n[+] Checking for recently modified files (any type) in the last 60 minutes..."
    if [ "$EXCLUDE_CACHE" -eq 1 ]; then
        RECENT_FILES=$(find "$SITE_PATH" -type f -mmin -60 -not -path "*/wp-content/cache/*" 2>/dev/null)
    else
        RECENT_FILES=$(find "$SITE_PATH" -type f -mmin -60 2>/dev/null)
    fi
    if [ -n "$RECENT_FILES" ]; then
        echo "!!! WARNING: Recently modified files found. Please review them:"
        echo "$RECENT_FILES"
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$RECENT_FILES")
    else
        echo "OK: No recently modified files found."
    fi
fi

# --- 2. Check for Suspicious File/Directory Names ---
if [ "$DO_SUSPICIOUS" -eq 1 ]; then
    echo -e "\n[+] Checking for suspicious file/directory names..."

    # Common backdoor file/directory names
    SUSPICIOUS_NAMES=("cg-bin" "phpshell" "c99" "r57" "webshell" "wso" "adminer.php" "phpmyadmin" "xmlrpc.php")
    for name in "${SUSPICIOUS_NAMES[@]}"; do
        if [ -f "$SITE_PATH/$name" ] || [ -d "$SITE_PATH/$name" ]; then
            echo "!!! WARNING: Suspicious file/directory found: '/$name'"
            if [ -f "$SITE_PATH/$name" ]; then
                ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$SITE_PATH/$name")
            fi
        fi
    done
fi

# Check for non-standard directories in uploads (e.g., month > 12)
if [ "$DO_UPLOADS" -eq 1 ]; then
    UPLOADS_DIR="$SITE_PATH/wp-content/uploads"
    if [ -d "$UPLOADS_DIR" ]; then
        # Find directories in uploads with a numeric basename that is not a valid month (01-12)
        FAKE_MONTH_DIRS=$(find "$UPLOADS_DIR" -maxdepth 2 -type d -name "[0-9]*" -print 2>/dev/null | while read -r DIR; do
            BASENAME=$(basename "$DIR")
            if [[ "$BASENAME" =~ ^[0-9]+$ ]] && ! [[ "$BASENAME" =~ ^0[1-9]$|^1[0-2]$ ]]; then
                echo "$DIR"
            fi
        done)
        if [ -n "$FAKE_MONTH_DIRS" ]; then
            echo "!!! WARNING: Found non-month directories in uploads (possible backdoors):"
            echo "$FAKE_MONTH_DIRS"
        fi
        # New: Flag any PHP files within uploads (often malicious)
        if [ "$DO_UPLOADS_PHP" -eq 1 ]; then
            UPLOADS_PHP_FILES=$(find "$UPLOADS_DIR" -type f -name "*.php" 2>/dev/null)
            if [ -n "$UPLOADS_PHP_FILES" ]; then
                echo "!!! WARNING: Found PHP files inside uploads (should be media only):"
                echo "$UPLOADS_PHP_FILES"
                ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$UPLOADS_PHP_FILES")
            else
                echo "OK: No PHP files found inside uploads."
            fi
        fi
    fi
fi

# Check for any verification files (Google, Bing, Yandex, etc.)
# Fixed logic: search top-level verification HTML files and any files under .well-known
VERIFICATION_FILES=$( { find "$SITE_PATH" -maxdepth 1 -type f \( -name "google*.html" -o -name "bing*.html" -o -name "yandex*.html" \) 2>/dev/null ; find "$SITE_PATH/.well-known" -type f 2>/dev/null ; } 2>/dev/null )
if [ -n "$VERIFICATION_FILES" ]; then
    echo "!!! WARNING: Found verification files. These could be for unauthorized ownership claims:"
    echo "$VERIFICATION_FILES"
    ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$VERIFICATION_FILES")
fi


# --- 3. Search for Malicious Code Patterns ---
if [ "$DO_BACKDOOR" -eq 1 ] || [ "$DO_OBFUSCATED" -eq 1 ] || [ "$DO_PHPSHELL" -eq 1 ]; then
    echo -e "\n[+] Searching for malicious code patterns in PHP files..."
fi

# Search for common backdoor functions
if [ "$DO_BACKDOOR" -eq 1 ]; then
    echo "  -> Searching for high-risk backdoor functions..."
    BACKDOOR_PATTERN="eval\\s*\(|base64_decode\\s*\(|shell_exec\\s*\(|passthru\\s*\(|system\\s*\(|exec\\s*\("
    BACKDOOR_MATCH=$(grep -R -l -i --include="*.php" -E "$BACKDOOR_PATTERN" "$SITE_PATH" 2>/dev/null)
    if [ -n "$BACKDOOR_MATCH" ]; then
        echo "!!! WARNING: Found high-risk functions. Review these files:"
        FILTERED_BACKDOOR=$(echo "$BACKDOOR_MATCH" | grep -v -E "wp-includes/|wp-admin/|wp-content/plugins/|wp-content/themes/" | head -10)
        echo "$FILTERED_BACKDOOR"
    ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$FILTERED_BACKDOOR")
        if [ "$SHOW_CONTEXT" -eq 1 ]; then
            echo "  -> Showing matched lines with line numbers (first 3 matches per file):"
            printf "%s\n" "$FILTERED_BACKDOOR" | while IFS= read -r f; do
                [ -z "$f" ] && continue
                echo "----- $f -----"
                grep -n -I -E "$BACKDOOR_PATTERN" -m 3 "$f" 2>/dev/null || echo "(no signature lines found)"
            done
        fi
    else
        echo "OK: No high-risk functions found in non-standard locations."
    fi
fi

# Search for obfuscated code patterns
if [ "$DO_OBFUSCATED" -eq 1 ]; then
    echo "  -> Searching for obfuscated code (base64, gzinflate, str_rot13)..."
    OBFUSCATED_PATTERN="base64_decode|gzinflate\(|str_rot13\(|strrev\("
    OBFUSCATED_MATCH=$(grep -R -l -i --include="*.php" -E "$OBFUSCATED_PATTERN" "$SITE_PATH" 2>/dev/null)
    if [ -n "$OBFUSCATED_MATCH" ]; then
        echo "!!! WARNING: Found potentially obfuscated code. Review these files:"
        FILTERED_OBFUSCATED=$(echo "$OBFUSCATED_MATCH" | grep -v -E "wp-includes/|wp-admin/" | head -10)
        echo "$FILTERED_OBFUSCATED"
    ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$FILTERED_OBFUSCATED")
        if [ "$SHOW_CONTEXT" -eq 1 ]; then
            echo "  -> Showing matched lines with line numbers (first 3 matches per file):"
            printf "%s\n" "$FILTERED_OBFUSCATED" | while IFS= read -r f; do
                [ -z "$f" ] && continue
                echo "----- $f -----"
                grep -n -I -E "$OBFUSCATED_PATTERN" -m 3 "$f" 2>/dev/null || echo "(no signature lines found)"
            done
        fi
    else
        echo "OK: No obvious obfuscated code found."
    fi
fi

if [ "$DO_PHPSHELL" -eq 1 ]; then
    # Search for known PHP web shell signatures and names
    echo "  -> Searching for PHP shell signatures (C99, R57, WSO, B374K, FilesMan, etc.)..."
    PHPSHELL_SIG_PATTERN="C99Shell|c99|R57|r57|WSO|B374K|FilesMan|IndoXploit|WebShell|FilesManager|Symlink"
    PHPSHELL_MATCH=$(grep -R -l -I --include="*.php" -E "$PHPSHELL_SIG_PATTERN" "$SITE_PATH" 2>/dev/null)
    # Also check common shell filenames
    PHPSHELL_NAMES=$(find "$SITE_PATH" -type f \( -iname "*wso*.php" -o -iname "*c99*.php" -o -iname "*r57*.php" -o -iname "*b374k*.php" -o -iname "*filesman*.php" -o -iname "webshell.php" -o -iname "shell.php" \) 2>/dev/null)

    if [ -n "$PHPSHELL_MATCH" ] || [ -n "$PHPSHELL_NAMES" ]; then
        echo "!!! WARNING: Potential PHP shell indicators found. Review these files:"
        PHPSHELL_UNIQUE=$( { echo "$PHPSHELL_MATCH"; echo "$PHPSHELL_NAMES"; } | grep -v -E "wp-includes/|wp-admin/" | sort -u )
        echo "$PHPSHELL_UNIQUE" | head -20
    ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$PHPSHELL_UNIQUE")

        if [ "$SHOW_CONTEXT" -eq 1 ]; then
            echo "  -> Showing matched lines with line numbers (first 3 matches per file):"
            printf "%s\n" "$PHPSHELL_UNIQUE" | head -20 | while IFS= read -r f; do
                [ -z "$f" ] && continue
                echo "----- $f -----"
                if grep -q -I -E "$PHPSHELL_SIG_PATTERN" "$f" 2>/dev/null; then
                    grep -n -I -E "$PHPSHELL_SIG_PATTERN" -m 3 "$f" 2>/dev/null
                else
                    echo "(flagged by filename; no signature lines found)"
                fi
            done
        fi
    else
        echo "OK: No explicit PHP shell signatures found."
    fi
fi

# New: Hidden dotfiles scan
if [ "$DO_HIDDEN" -eq 1 ]; then
    echo -e "\n[+] Checking for hidden dotfiles (.*) in web root..."
    HIDDEN_FILES=$(find "$SITE_PATH" -type f -name ".*" \
        -not -path "*/.git/*" -not -path "*/.svn/*" -not -path "*/.hg/*" -not -path "*/.well-known/*" 2>/dev/null)
    if [ -n "$HIDDEN_FILES" ]; then
        echo "!!! WARNING: Hidden files found (could expose secrets or be used for persistence):"
        echo "$HIDDEN_FILES" | head -20
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$HIDDEN_FILES")
    else
        echo "OK: No hidden dotfiles found (excluding VCS and .well-known)."
    fi
fi

# New: Superglobal backdoor pattern scan
if [ "$DO_SUPERGLOBAL" -eq 1 ]; then
    echo -e "\n[+] Scanning for superglobal-driven backdoor patterns..."
    SUPER_PATTERN="(\$_(GET|POST|REQUEST|COOKIE)).*(eval\s*\(|system\s*\(|shell_exec\s*\(|passthru\s*\(|popen\s*\(|proc_open\s*\()"
    SUPER_MATCH=$(grep -R -l -I --include="*.php" -E "$SUPER_PATTERN" "$SITE_PATH" 2>/dev/null)
    if [ -n "$SUPER_MATCH" ]; then
        echo "!!! WARNING: Superglobal-driven exec/eval patterns found:"
        echo "$SUPER_MATCH" | grep -v -E "wp-includes/|wp-admin/" | head -20
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$SUPER_MATCH")
        if [ "$SHOW_CONTEXT" -eq 1 ]; then
            echo "  -> Showing matched lines with line numbers (first 3 matches per file):"
            printf "%s\n" "$SUPER_MATCH" | head -20 | while IFS= read -r f; do
                [ -z "$f" ] && continue
                echo "----- $f -----"
                grep -n -I -E "$SUPER_PATTERN" -m 3 "$f" 2>/dev/null || echo "(no signature lines found)"
            done
        fi
    else
        echo "OK: No obvious superglobal backdoor patterns found."
    fi
fi

# Search for hidden cURL calls
if [ "$DO_CURL" -eq 1 ]; then
    echo "  -> Searching for cURL calls to external domains..."
    CURL_MATCH=$(grep -R -l --include="*.php" -e "curl_init" "$SITE_PATH" 2>/dev/null)
    if [ -n "$CURL_MATCH" ]; then
        echo "!!! WARNING: Found cURL calls. These are common in backdoors. Review these files:"
        FILTERED_CURL=$(echo "$CURL_MATCH" | grep -v -E "wp-includes/|wp-content/themes/|wp-content/plugins/")
        echo "$FILTERED_CURL" | head -10
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$FILTERED_CURL")
    else
        echo "OK: No cURL calls found in non-standard locations."
    fi
fi


# --- 4. Check for WordPress Version Vulnerabilities ---
if [ "$DO_WPVER" -eq 1 ]; then
    echo -e "\n[+] Checking WordPress version..."
    if [ -f "$SITE_PATH/wp-includes/version.php" ]; then
        WP_VERSION=$(grep -o "wp_version = '[^^']*'" "$SITE_PATH/wp-includes/version.php" | sed "s/wp_version = '//" | sed "s/'//")
        echo "  -> Detected WordPress version: $WP_VERSION"
        echo "  -> Manual check required: Please compare this version against the WordPress.org security advisories to see if it's outdated."
    else
        echo "Could not determine WordPress version."
    fi
fi


# --- 5. Check File Permissions ---
if [ "$DO_PERMS" -eq 1 ]; then
    echo -e "\n[+] Checking for insecure file permissions..."
    echo "  -> Checking for world-writable files..."
    WRITABLE_FILES=$(find "$SITE_PATH" -type f -perm /002 -not -path "*/wp-content/cache/*" -not -path "*/wp-content/uploads/*" 2>/dev/null | head -5)
    if [ -n "$WRITABLE_FILES" ]; then
        echo "!!! WARNING: Found world-writable files (showing first 5):"
        echo "$WRITABLE_FILES"
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$WRITABLE_FILES")
    else
        echo "OK: No obvious world-writable files found outside uploads/cache."
    fi
fi

echo -e "\n=========================================================================="
echo "Scan Complete."
echo "=========================================================================="
echo "Disclaimer: This script is a powerful scanning aid. It may produce false"
echo "positives. All findings should be manually investigated and verified."
echo "=========================================================================="

# --- Email Notification (optional) ---
if [ -n "$EMAIL_TO" ]; then
    WARN_COUNT=$(grep -c "!!! WARNING" "$LOG_FILE" 2>/dev/null || echo 0)
    if [ "$EMAIL_ALWAYS" = "1" ] || [ "${WARN_COUNT}" -gt 0 ]; then
        STATUS="OK"
        [ "${WARN_COUNT}" -gt 0 ] && STATUS="WARNINGS"
        SUBJECT="${EMAIL_SUBJECT:-Generic WP Scan: $SITE_PATH} [$STATUS]"

        if command -v mail >/dev/null 2>&1 && [ -z "$EMAIL_FROM" ]; then
            mail -s "$SUBJECT" "$EMAIL_TO" < "$LOG_FILE"
            echo "Notification email sent via 'mail' to $EMAIL_TO."
        elif command -v sendmail >/dev/null 2>&1; then
            {
                echo "To: $EMAIL_TO"
                echo "From: ${EMAIL_FROM:-no-reply@localhost}"
                echo "Subject: $SUBJECT"
                echo "Content-Type: text/plain; charset=UTF-8"
                echo
                cat "$LOG_FILE"
            } | sendmail -t
            echo "Notification email sent via 'sendmail' to $EMAIL_TO."
        elif command -v msmtp >/dev/null 2>&1; then
            {
                echo "To: $EMAIL_TO"
                echo "From: ${EMAIL_FROM:-no-reply@localhost}"
                echo "Subject: $SUBJECT"
                echo "Content-Type: text/plain; charset=UTF-8"
                echo
                cat "$LOG_FILE"
            } | msmtp -t
            echo "Notification email sent via 'msmtp' to $EMAIL_TO."
        else
            echo "Email not sent: no mail/sendmail/msmtp found."
        fi
    else
        echo "Email not sent: no warnings found and --email-always not specified."
    fi
fi

# If we couldn't tee to stdout earlier, show the captured log now
if [ "$VERBOSE_TO_STDOUT" -eq 0 ]; then
    echo "---- Scan Output ----"
    cat "$LOG_FILE"
fi

# --- JSON Summary Output (optional) ---
if [ "$JSON_OUTPUT" -eq 1 ]; then
    # derive counts based on variables populated above (fallback to grepping the log)
    count_lines() { echo "$1" | sed '/^\s*$/d' | wc -l | awk '{print $1}'; }
    WARN_COUNT=$(grep -c "!!! WARNING" "$LOG_FILE" 2>/dev/null || echo 0)
    STATUS="OK"; [ "$WARN_COUNT" -gt 0 ] && STATUS="WARNINGS"
    RECENT_COUNT=$(count_lines "$RECENT_FILES")
    UPLOADS_NON_MONTH_COUNT=$(count_lines "$FAKE_MONTH_DIRS")
    UPLOADS_PHP_COUNT=$(count_lines "$UPLOADS_PHP_FILES")
    BACKDOOR_COUNT=$(count_lines "$FILTERED_BACKDOOR")
    OBFUSCATION_COUNT=$(count_lines "$FILTERED_OBFUSCATED")
    PHPSHELL_COUNT=$(count_lines "$PHPSHELL_UNIQUE")
    HIDDEN_COUNT=$(count_lines "$HIDDEN_FILES")
    SUPERGLOBAL_COUNT=$(count_lines "$SUPER_MATCH")
    CURL_COUNT=$(count_lines "$CURL_MATCH")
    PERMS_COUNT=$(count_lines "$WRITABLE_FILES")
    VERIF_COUNT=$(count_lines "$VERIFICATION_FILES")
    echo "{"
    echo "  \"site\": \"$SITE_PATH\","
    echo "  \"status\": \"$STATUS\","
    echo "  \"warnings\": $WARN_COUNT,"
    echo "  \"modules\": {"
    echo "    \"recent\": $RECENT_COUNT,"
    echo "    \"uploads_non_month\": $UPLOADS_NON_MONTH_COUNT,"
    echo "    \"uploads_php\": $UPLOADS_PHP_COUNT,"
    echo "    \"backdoor\": $BACKDOOR_COUNT,"
    echo "    \"obfuscation\": $OBFUSCATION_COUNT,"
    echo "    \"phpshell\": $PHPSHELL_COUNT,"
    echo "    \"hidden\": $HIDDEN_COUNT,"
    echo "    \"superglobal\": $SUPERGLOBAL_COUNT,"
    echo "    \"curl\": $CURL_COUNT,"
    echo "    \"perms_world_writable\": $PERMS_COUNT,"
    echo "    \"verification_files\": $VERIF_COUNT"
    echo "  }"
    echo "}"
fi

# --- Zip flagged files (optional) ---
if [ "$ZIP_ENABLED" -eq 1 ]; then
    if ! command -v zip >/dev/null 2>&1; then
        echo "Zip requested but 'zip' command not found. Skipping archive creation."
    else
        echo "Creating zip archive of flagged files: $ZIP_TARGET_ZIP"
        FILE_LIST=$(mktemp -t wp-scan-ziplist-XXXXXX.txt)
        # Collect only existing files, unique (absolute paths)
        printf "%s\n" "$ZIP_CANDIDATES" | sed '/^\s*$/d' | while IFS= read -r p; do
            [ -f "$p" ] && echo "$p"
        done | sort -u > "$FILE_LIST"
        COUNT=$(wc -l < "$FILE_LIST" | awk '{print $1}')
        if [ "$COUNT" -gt 0 ]; then
            # Create zip from list; entries will use the absolute path as listed
            zip -@ "$ZIP_TARGET_ZIP" < "$FILE_LIST"
            # Add a manifest with the full absolute paths for easy reference
            MANIFEST_TMP=$(mktemp -t wp-scan-manifest-XXXXXX.txt)
            {
                echo "wp-scan manifest"
                echo "site: $SITE_PATH"
                echo "created: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
                echo "files:"
                cat "$FILE_LIST"
            } > "$MANIFEST_TMP"
            MANIFEST_NAME="wp-scan-manifest.txt"
            cp "$MANIFEST_TMP" "$MANIFEST_NAME"
            zip "$ZIP_TARGET_ZIP" "$MANIFEST_NAME" >/dev/null 2>&1
            rm -f "$MANIFEST_NAME" "$MANIFEST_TMP"
            echo "Zip created ($COUNT files): $ZIP_TARGET_ZIP (includes $MANIFEST_NAME)"
        else
            echo "No files to zip. Archive not created."
        fi
        rm -f "$FILE_LIST"
    fi
fi

# --- Exit code control ---
WARN_COUNT=$(grep -c "!!! WARNING" "$LOG_FILE" 2>/dev/null || echo 0)
if [ "$EXIT_CODE_MODE" = "count" ]; then
    EC=$WARN_COUNT
    [ "$EC" -gt 254 ] && EC=254
    exit "$EC"
else
    [ "$WARN_COUNT" -gt 0 ] && exit 1 || exit 0
fi
