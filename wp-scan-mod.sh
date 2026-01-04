#!/bin/bash
# ====================================================================
# Generic WordPress Security Scanner (Modular Version)
#
# Usage: ./wp-scan.sh [options] /path/to/site/root
#
# Options:
#   --email <addr>         Send report to this address when warnings found
#   --email-always         Always send email even when no warnings
#   --email-from <addr>    Sender address (sendmail/msmtp)
#   --email-subject <text> Base subject; status appended
#   --menu                 Interactive menu to select scan modules
#   --only <modules>       Run only these modules (csv or space-separated)
#   --skip <modules>       Skip these modules (csv or space-separated)
#   --no-wordpress         Scan generic site; skip WordPress-specific checks
#   --sc                   Show 2 lines of code context around matched signatures
#   --json                 Output a minimal JSON summary at the end
#   --exit-code <mode>     Exit code mode: 'binary' (0/1) or 'count' (0-254)
#   --zip <filename.zip>   Zip up flagged files into the specified archive
#   --scan-all             Force-enable all modules for this run
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
#   --immutable / --no-immutable
#   --verification / --no-verification
#   --access-logs / --no-access-logs
#   --dyn-exec / --no-dyn-exec
#   --oneliner / --no-oneliner
#   --wp-cli / --no-wp-cli
#   --help                 Show usage
#
# Modules: recent, suspicious, uploads, backdoor, obfuscation, phpshell, curl, wpver, perms, immutable, verification, dyn-exec, oneliner, wp-cli, access_logs, all
# Example: ./wp-scan.sh --only recent,uploads --email admin@example.com /var/www/html/site
# ====================================================================

# --- GLOBAL VARIABLES & CONFIGURATION ---
# Allow configuration through CLI flags or environment variables
EMAIL_TO="${WP_SCAN_EMAIL_TO:-}"
EMAIL_FROM="${WP_SCAN_EMAIL_FROM:-}"
EMAIL_SUBJECT="${WP_SCAN_EMAIL_SUBJECT:-}"
EMAIL_ALWAYS="${WP_SCAN_EMAIL_ALWAYS:-0}"

ARG_SITE=""
SITE_PATH=""
SITE_OWNER=""
LOG_FILE=""
ZIP_CANDIDATES=""

# WordPress mode (default on). Disable with --no-wordpress
WP_MODE=1
# Show context toggle (2 lines before/after around matched signatures)
SHOW_CONTEXT=0
# Exclude cache from recent file scans
EXCLUDE_CACHE=1
# JSON output toggle
JSON_OUTPUT=0
# Exit code mode: 'binary' (0/1) or 'count' (0-254)
EXIT_CODE_MODE="binary"
# Zip archive toggle
ZIP_ENABLED=0
ZIP_TARGET_ZIP=""
# Force-enable all modules
SCAN_ALL=0

# Interactive menu toggle
MENU_MODE=0

# Module toggles (default: run all)
DO_RECENT=1; DO_SUSPICIOUS=1; DO_UPLOADS=1; DO_UPLOADS_PHP=1; DO_BACKDOOR=1
DO_OBFUSCATED=1; DO_PHPSHELL=1; DO_HIDDEN=1; DO_SUPERGLOBAL=1; DO_CURL=1
DO_WPVER=1; DO_PERMS=1; DO_IMMUTABLE=1; DO_VERIFICATION=1; DO_ACCESS_LOGS=1
DO_DYN_EXEC=1; DO_ONELINER=1; DO_WP_CLI=1

# --- HELPER FUNCTIONS ---

enable_only_defaults() {
    DO_RECENT=0; DO_SUSPICIOUS=0; DO_UPLOADS=0; DO_UPLOADS_PHP=0; DO_BACKDOOR=0
    DO_OBFUSCATED=0; DO_PHPSHELL=0; DO_HIDDEN=0; DO_SUPERGLOBAL=0; DO_CURL=0
    DO_WPVER=0; DO_PERMS=0; DO_IMMUTABLE=0; DO_VERIFICATION=0; DO_ACCESS_LOGS=0
    DO_DYN_EXEC=0; DO_ONELINER=0; DO_WP_CLI=0
}

set_module_flag() {
    case "$1" in
        recent|suspicious|uploads|backdoor|obfuscation|curl|wpver|perms|immutable|verification|access_logs|dyn-exec|oneliner|wp-cli)
            declare -i "DO_${1//-/_}=1" ;;
        phpshell) DO_PHPSHELL=1 ;;
        uploads-php) DO_UPLOADS_PHP=1 ;;
        all)
            DO_RECENT=1; DO_SUSPICIOUS=1; DO_UPLOADS=1; DO_UPLOADS_PHP=1; DO_BACKDOOR=1
            DO_OBFUSCATED=1; DO_PHPSHELL=1; DO_HIDDEN=1; DO_SUPERGLOBAL=1; DO_CURL=1
            DO_WPVER=1; DO_PERMS=1; DO_IMMUTABLE=1; DO_VERIFICATION=1; DO_ACCESS_LOGS=1
            DO_DYN_EXEC=1; DO_ONELINER=1; DO_WP_CLI=1 ;;
    esac
}

clear_module_flag() {
    case "$1" in
        recent|suspicious|uploads|backdoor|obfuscation|curl|wpver|perms|immutable|verification|access_logs|dyn-exec|oneliner|wp-cli)
            declare -i "DO_${1//-/_}=0" ;;
        phpshell) DO_PHPSHELL=0 ;;
        uploads-php) DO_UPLOADS_PHP=0 ;;
        all)
            enable_only_defaults ;;
    esac
}

print_module_status() {
    local key="$1"
    local var="$2"
    local val="${!var}"
    if [ "$val" -eq 1 ]; then
        printf "[x] %s\n" "$key"
    else
        printf "[ ] %s\n" "$key"
    fi
}

interactive_menu() {
    echo ""
    echo "Interactive Module Menu"
    echo "========================"
    echo "Type one or more triggers (space/comma separated)."
    echo "Commands: a=all, n=none, r=run, c=console, q=quit"

    while true; do
        echo ""
        echo "Current selection:"
    echo "  1) $(print_module_status "recent" DO_RECENT | tr -d '\n')        (triggers: 1, recent)"
    echo "  2) $(print_module_status "suspicious" DO_SUSPICIOUS | tr -d '\n')    (triggers: 2, suspicious)"
    echo "  3) $(print_module_status "uploads" DO_UPLOADS | tr -d '\n')       (triggers: 3, uploads)"
    echo "  4) $(print_module_status "uploads-php" DO_UPLOADS_PHP | tr -d '\n')   (triggers: 4, uploads-php)"
    echo "  5) $(print_module_status "backdoor" DO_BACKDOOR | tr -d '\n')      (triggers: 5, backdoor)"
    echo "  6) $(print_module_status "obfuscation" DO_OBFUSCATED | tr -d '\n')   (triggers: 6, obfuscation)"
    echo "  7) $(print_module_status "phpshell" DO_PHPSHELL | tr -d '\n')      (triggers: 7, phpshell)"
    echo "  8) $(print_module_status "hidden" DO_HIDDEN | tr -d '\n')        (triggers: 8, hidden)"
    echo "  9) $(print_module_status "superglobal" DO_SUPERGLOBAL | tr -d '\n')   (triggers: 9, superglobal)"
    echo " 10) $(print_module_status "curl" DO_CURL | tr -d '\n')          (triggers: 10, curl)"
    echo " 11) $(print_module_status "wpver" DO_WPVER | tr -d '\n')         (triggers: 11, wpver)"
    echo " 12) $(print_module_status "perms" DO_PERMS | tr -d '\n')         (triggers: 12, perms)"
    echo " 13) $(print_module_status "immutable" DO_IMMUTABLE | tr -d '\n')      (triggers: 13, immutable)"
    echo " 14) $(print_module_status "verification" DO_VERIFICATION | tr -d '\n')  (triggers: 14, verification)"
    echo " 15) $(print_module_status "access-logs" DO_ACCESS_LOGS | tr -d '\n')    (triggers: 15, access-logs)"
    echo " 16) $(print_module_status "dyn-exec" DO_DYN_EXEC | tr -d '\n')      (triggers: 16, dyn-exec)"
    echo " 17) $(print_module_status "oneliner" DO_ONELINER | tr -d '\n')      (triggers: 17, oneliner)"
    echo " 18) $(print_module_status "wp-cli" DO_WP_CLI | tr -d '\n')        (triggers: 18, wp-cli)"

        printf "\nSelect> "
        read -r line

        # Allow multiple triggers per line: split on commas and whitespace.
        line=$(printf "%s" "$line" | tr ',' ' ')

        # shellcheck disable=SC2086
        set -- $line
        if [ $# -eq 0 ]; then
            continue
        fi

        local token
        for token in "$@"; do
            case "$token" in
                1|recent) DO_RECENT=$((1-DO_RECENT)) ;;
                2|suspicious) DO_SUSPICIOUS=$((1-DO_SUSPICIOUS)) ;;
                3|uploads) DO_UPLOADS=$((1-DO_UPLOADS)) ;;
                4|uploads-php) DO_UPLOADS_PHP=$((1-DO_UPLOADS_PHP)) ;;
                5|backdoor) DO_BACKDOOR=$((1-DO_BACKDOOR)) ;;
                6|obfuscation) DO_OBFUSCATED=$((1-DO_OBFUSCATED)) ;;
                7|phpshell) DO_PHPSHELL=$((1-DO_PHPSHELL)) ;;
                8|hidden) DO_HIDDEN=$((1-DO_HIDDEN)) ;;
                9|superglobal) DO_SUPERGLOBAL=$((1-DO_SUPERGLOBAL)) ;;
                10|curl) DO_CURL=$((1-DO_CURL)) ;;
                11|wpver) DO_WPVER=$((1-DO_WPVER)) ;;
                12|perms) DO_PERMS=$((1-DO_PERMS)) ;;
                13|immutable) DO_IMMUTABLE=$((1-DO_IMMUTABLE)) ;;
                14|verification) DO_VERIFICATION=$((1-DO_VERIFICATION)) ;;
                15|access-logs|access_logs) DO_ACCESS_LOGS=$((1-DO_ACCESS_LOGS)) ;;
                16|dyn-exec|dyn_exec) DO_DYN_EXEC=$((1-DO_DYN_EXEC)) ;;
                17|oneliner) DO_ONELINER=$((1-DO_ONELINER)) ;;
                18|wp-cli|wp_cli) DO_WP_CLI=$((1-DO_WP_CLI)) ;;
                a|A|all) set_module_flag all ;;
                n|N|none) enable_only_defaults ;;
                r|R|run) return 0 ;;
                c|C|console) echo "Exiting menu."; exit 0 ;;
                q|Q|quit) echo "Aborted by user."; exit 0 ;;
                *) echo "Unknown selection: '$token'" ;;
            esac
        done
    done
}

# --- MODULAR SCAN FUNCTIONS ---

scan_recent_files() {
    [ "$DO_RECENT" -eq 1 ] || return 0
    echo -e "\n[+] Checking for recently modified files (any type) in the last 60 minutes..."
    local find_cmd="find \"$SITE_PATH\" -type f -mmin -60"
    [ "$EXCLUDE_CACHE" -eq 1 ] && find_cmd+=" -not -path \"*/wp-content/cache/*\""
    local recent_files=$(eval "$find_cmd" 2>/dev/null)
    if [ -n "$recent_files" ]; then
        echo "!!! WARNING: Recently modified files found. Please review them:"
        echo "$recent_files"
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$recent_files")
    else
        echo "OK: No recently modified files found."
    fi
}

scan_suspicious_names() {
    [ "$DO_SUSPICIOUS" -eq 1 ] || return 0
    echo -e "\n[+] Checking for suspicious file/directory names..."
    local suspicious_names=("cg-bin" "phpshell" "c99" "r57" "webshell" "wso" "adminer.php" "phpmyadmin" "xmlrpc.php")
    for name in "${suspicious_names[@]}"; do
        if [ -f "$SITE_PATH/$name" ] || [ -d "$SITE_PATH/$name" ]; then
            echo "!!! WARNING: Suspicious file/directory found: '/$name'"
            [ -f "$SITE_PATH/$name" ] && ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$SITE_PATH/$name")
        fi
    done
}

scan_uploads() {
    [ "$DO_UPLOADS" -eq 1 ] || return 0
    local uploads_dir="$SITE_PATH/wp-content/uploads"
    [ -d "$uploads_dir" ] || return 0

    echo -e "\n[+] Checking for non-month directories in uploads..."
    local fake_month_dirs_file=$(mktemp)
    find "$uploads_dir" -maxdepth 2 -type d -name "[0-9]*" -print 2>/dev/null | while IFS= read -r dir; do
        local basename=$(basename "$dir")
        if [[ "$basename" =~ ^^[0-9]+$ ]] && ! [[ "$basename" =~ ^^(0[1-9]|1[0-2])$ ]]; then
            echo "$dir"
        fi
    done | sort > "$fake_month_dirs_file"
    
    local fake_month_dirs=$(cat "$fake_month_dirs_file")
    if [ -n "$fake_month_dirs" ]; then
        echo "!!! WARNING: Found non-month directories in uploads (possible backdoors):"
        echo "$fake_month_dirs"
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$fake_month_dirs")
    else
        echo "OK: No non-month directories found in uploads."
    fi
    rm -f "$fake_month_dirs_file"
}

scan_uploads_php() {
    [ "$DO_UPLOADS_PHP" -eq 1 ] || return 0
    local uploads_dir="$SITE_PATH/wp-content/uploads"
    [ -d "$uploads_dir" ] || return 0

    echo -e "\n[+] Checking for PHP files inside uploads..."
    local uploads_php_files=$(find "$uploads_dir" -type f -name "*.php" 2>/dev/null)
    if [ -n "$uploads_php_files" ]; then
        echo "!!! WARNING: Found PHP files inside uploads (should be media only):"
        echo "$uploads_php_files"
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$uploads_php_files")
    else
        echo "OK: No PHP files found inside uploads."
    fi
}

scan_verification_files() {
    [ "$DO_VERIFICATION" -eq 1 ] || return 0
    echo -e "\n[+] Checking for verification files..."
    local verification_files=$( { find "$SITE_PATH" -maxdepth 1 -type f $$ -name "google*.html" -o -name "bing*.html" -o -name "yandex*.html" $$ 2>/dev/null ; find "$SITE_PATH/.well-known" -type f 2>/dev/null ; } 2>/dev/null )
    if [ -n "$verification_files" ]; then
        echo "!!! WARNING: Found verification files. These could be for unauthorized ownership claims:"
        echo "$verification_files"
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$verification_files")
    else
        echo "OK: No verification files found."
    fi
}

scan_access_logs() {
    [ "$DO_ACCESS_LOGS" -eq 1 ] || return 0
    echo -e "\n[+] Scanning access logs under /home/* (access-logs + logs) for suspicious requests..."
    local findings=""
    local files_found=""

    if [[ "$SITE_PATH" =~ ^^/home/([^^/]+)/public_html(/|$) ]]; then
        SITE_OWNER="${BASH_REMATCH[1]}"
    fi

    local scan_pattern="(\?[^^ ]*(cmd=|exec=|system=|shell=|base64|eval|assert|GLOBALS|_POST$$|_GET$$))|(/(wp-admin|wp-login\.php)\.php)|(/\.env)|(/wp-config\.php)|(/xmlrpc\.php)|(/\.git/)|(/cgi-bin/)|((/|%2f)(c99|r57|wso|b374k)[^^ ]*\.php)|((/|%2f)shell[^^ ]*\.php)|((/|%2f)webshell[^^ ]*\.php)|((union[+%20]+select|information_schema|sleep$$|benchmark$$)|((/|%2f)etc(/|%2f)passwd)|\b(base64_decode|gzinflate|str_rot13|php://input)\b)"

    scan_plain_log() {
        local f="$1"; [ -f "$f" ] || return 0
        if grep -Iq . "$f" 2>/dev/null; then
            local hits=$(grep -n -E -i "$scan_pattern" "$f" 2>/dev/null | head -50)
            if [ -n "$hits" ]; then
                files_found=$(printf "%s\n%s\n" "$files_found" "$f")
                findings=$(printf "%s\n=== %s ===\n%s\n" "$findings" "$f" "$hits")
            fi
        fi
    }
    
    scan_gz_log() {
        local f="$1"; [ -f "$f" ] || return 0
        command -v gzip >/dev/null 2>&1 || return 0
        local hits=$(gzip -cd -- "$f" 2>/dev/null | grep -n -E -i "$scan_pattern" | head -50)
        if [ -n "$hits" ]; then
            files_found=$(printf "%s\n%s\n" "$files_found" "$f")
            findings=$(printf "%s\n=== %s ===\n%s\n" "$findings" "$f" "$hits")
        fi
    }

    if [ -d "/home" ]; then
        local log_base="/home/${SITE_OWNER:-*}"
        while IFS= read -r lf; do [ -z "$lf" ] && continue; scan_plain_log "$lf"; done < <(find "$log_base" -maxdepth 2 -type f -path "*/access-logs/*" 2>/dev/null | head -500)
        while IFS= read -r lf; do [ -z "$lf" ] && continue; case "$lf" in *.gz) scan_gz_log "$lf" ;; *) scan_plain_log "$lf" ;; esac; done < <(find "$log_base" -maxdepth 2 -type f -path "*/logs/*" 2>/dev/null | head -500)
    fi

    files_found=$(printf "%s\n" "$files_found" | sed '/^^\s*$/d' | sort -u)
    if [ -n "$findings" ]; then
        echo "!!! WARNING: Suspicious access log requests found (showing first hits per file):"
        echo "$findings" | head -200
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$files_found")
    else
        echo "OK: No suspicious access log patterns found in /home/* access logs."
    fi
}

scan_malicious_code() {
    local should_run=0
    [ "$DO_BACKDOOR" -eq 1 ] || [ "$DO_OBFUSCATED" -eq 1 ] || [ "$DO_PHPSHELL" -eq 1 ] || [ "$DO_DYN_EXEC" -eq 1 ] || [ "$DO_ONELINER" -eq 1 ] && should_run=1
    [ "$should_run" -eq 1 ] || return 0

    echo -e "\n[+] Searching for malicious code patterns in PHP files..."
    local grep_base="grep -R -l -I --include=\"*.php\""

    if [ "$DO_BACKDOOR" -eq 1 ]; then
        echo " -> Searching for high-risk backdoor functions..."
        local pattern="eval\\s*$$|base64_decode\\s*$$|shell_exec\\s*$$|passthru\\s*$$|system\\s*$$|exec\\s*$$"
        local matches=$(eval "$grep_base -E \"$pattern\" \"$SITE_PATH\"" 2>/dev/null | grep -v -E "wp-includes/|wp-admin/|wp-content/plugins/|wp-content/themes/" | head -10)
        if [ -n "$matches" ]; then echo "!!! WARNING: Found high-risk functions. Review these files:"; echo "$matches"; ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$matches"); else echo "OK: No high-risk functions found in non-standard locations."; fi
    fi

    if [ "$DO_OBFUSCATED" -eq 1 ]; then
        echo " -> Searching for obfuscated code..."
        local pattern="base64_decode|gzinflate$$|str_rot13$$|strrev$$|str_replace$$|preg_replace.*\/e|assert$$|create_function$$"
        local matches=$(eval "$grep_base -E \"$pattern\" \"$SITE_PATH\"" 2>/dev/null | grep -v -E "wp-includes/|wp-admin/" | head -10)
        if [ -n "$matches" ]; then echo "!!! WARNING: Found potentially obfuscated code. Review these files:"; echo "$matches"; ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$matches"); else echo "OK: No obvious obfuscated code found."; fi
    fi

    if [ "$DO_PHPSHELL" -eq 1 ]; then
        echo " -> Searching for PHP shell signatures..."
        local sig_pattern="C99Shell|c99|R57|r57|WSO|B374K|FilesMan|IndoXploit|WebShell|FilesManager|Symlink|bypass|shell|cmd|backdoor|encoded by|gaza|hacker|priv8"
        local sig_matches=$(eval "$grep_base -E \"$sig_pattern\" \"$SITE_PATH\"" 2>/dev/null)
        local name_matches=$(find "$SITE_PATH" -type f $$ -iname "*wso*.php" -o -iname "*c99*.php" -o -iname "*r57*.php" -o -iname "*b374k*.php" -o -iname "*filesman*.php" -o -iname "webshell.php" -o -iname "shell.php" $$ 2>/dev/null)
        local unique=$( { printf "%s\n" "$sig_matches"; printf "%s\n" "$name_matches"; } | grep -v -E "wp-includes/|wp-admin/" | sort -u )
        if [ -n "$unique" ]; then echo "!!! WARNING: Potential PHP shell indicators found. Review these files:"; echo "$unique" | head -20; ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$unique"); else echo "OK: No explicit PHP shell signatures found."; fi
    fi

    if [ "$DO_DYN_EXEC" -eq 1 ]; then
        echo " -> Searching for dynamic function execution patterns..."
        local pattern="(\$\w+\s*).*['\"](eval|system|shell_exec|passthru|exec|assert|create_function)['\"]"
        local matches=$(eval "$grep_base -E \"$pattern\" \"$SITE_PATH\"" 2>/dev/null | grep -v -E "wp-includes/|wp-admin/" | head -10)
        if [ -n "$matches" ]; then echo "!!! WARNING: Found patterns suggesting dynamic function execution. Review these files:"; echo "$matches"; ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$matches"); else echo "OK: No obvious dynamic execution patterns found."; fi
    fi

    if [ "$DO_ONELINER" -eq 1 ]; then
        echo " -> Searching for potential one-liner shells..."
        local oneliner_files=$(find "$SITE_PATH" -type f -name "*.php" -exec sh -c 'line_count=$(wc -l < "$1"); [ "$line_count" -lt 5 ] && grep -q -i -E "(eval|system|shell_exec|passthru|exec)" "$1" && echo "$1"' sh {} \; 2>/dev/null)
        if [ -n "$oneliner_files" ]; then
            echo "!!! WARNING: Found very small PHP files with dangerous functions (potential one-liner shells):"
            local filtered=$(printf "%s\n" "$oneliner_files" | grep -v -E "wp-includes/|wp-admin/" | head -10)
            [ -n "$filtered" ] && echo "$filtered" || echo " (Found files were in standard directories, but still worth checking)"
            ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$oneliner_files")
        else
            echo "OK: No suspicious one-liner PHP files found."
        fi
    fi
}

scan_hidden_files() {
    [ "$DO_HIDDEN" -eq 1 ] || return 0
    echo -e "\n[+] Checking for hidden dotfiles..."
    local hidden_files=$(find "$SITE_PATH" -type f -name ".*" -not -path "*/.git/*" -not -path "*/.svn/*" -not -path "*/.hg/*" -not -path "*/.well-known/*" 2>/dev/null)
    if [ -n "$hidden_files" ]; then
        echo "!!! WARNING: Hidden files found (could expose secrets or be used for persistence):"
        echo "$hidden_files" | head -20
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$hidden_files")
    else
        echo "OK: No hidden dotfiles found (excluding VCS and .well-known)."
    fi
}

scan_superglobal() {
    [ "$DO_SUPERGLOBAL" -eq 1 ] || return 0
    echo -e "\n[+] Scanning for superglobal-driven backdoor patterns..."
    local pattern="(\$_(GET|POST|REQUEST|COOKIE)).*\s*(eval\s*$$|system\s*$$|shell_exec\s*$$|passthru\s*$$|popen\s*$$|proc_open\s*$$|assert\s*$$|create_function\s*$$|preg_replace.*\/e)"
    local matches=$(grep -R -l -I --include="*.php" -E "$pattern" "$SITE_PATH" 2>/dev/null | grep -v -E "wp-includes/|wp-admin/" | head -20)
    if [ -n "$matches" ]; then
        echo "!!! WARNING: Superglobal-driven exec/eval patterns found:"; echo "$matches"; ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$matches")
    else
        echo "OK: No obvious superglobal backdoor patterns found."
    fi
}

scan_curl() {
    [ "$DO_CURL" -eq 1 ] || return 0
    echo " -> Searching for cURL calls to external domains..."
    local matches=$(grep -R -l --include="*.php" -e "curl_init" "$SITE_PATH" 2>/dev/null | grep -v -E "wp-includes/|wp-content/themes/|wp-content/plugins/" | head -10)
    if [ -n "$matches" ]; then
        echo "!!! WARNING: Found cURL calls. These are common in backdoors. Review these files:"; echo "$matches"; ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$matches")
    else
        echo "OK: No cURL calls found in non-standard locations."
    fi
}

scan_wp_version() {
    [ "$DO_WPVER" -eq 1 ] || return 0
    echo -e "\n[+] Checking WordPress version..."
    local version_file="$SITE_PATH/wp-includes/version.php"
    if [ -f "$version_file" ]; then
        local wp_version=$(grep -o "wp_version = '[^^']*'" "$version_file" | sed "s/wp_version = '//" | sed "s/'//")
        echo " -> Detected WordPress version: $wp_version"
        echo " -> Manual check required: Please compare this version against the WordPress.org security advisories to see if it's outdated."
    else
        echo "Could not determine WordPress version."
    fi
}

scan_permissions() {
    [ "$DO_PERMS" -eq 1 ] || return 0
    echo -e "\n[+] Checking for insecure file permissions..."
    echo " -> Checking for world-writable files..."
    local writable_files=$(find "$SITE_PATH" -type f -perm /002 -not -path "*/wp-content/cache/*" -not -path "*/wp-content/uploads/*" 2>/dev/null | head -5)
    if [ -n "$writable_files" ]; then
        echo "!!! WARNING: Found world-writable files (showing first 5):"; echo "$writable_files"; ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$writable_files")
    else
        echo "OK: No obvious world-writable files found outside uploads/cache."
    fi
}

scan_immutable() {
    [ "$DO_IMMUTABLE" -eq 1 ] || return 0
    echo -e "\n[+] Checking for immutable files (+i attribute)..."
    if ! command -v lsattr >/dev/null 2>&1; then
        echo "INFO: 'lsattr' command not found. Skipping immutable file check (requires e2fsprogs)."
    else
        local immutable_files=$(find "$SITE_PATH" -type f -exec lsattr -d {} \; 2>/dev/null | grep '^^..i' | awk '{print $2}')
        if [ -n "$immutable_files" ]; then
            echo "!!! WARNING: Found immutable files. This is highly suspicious and may indicate a rootkit or backdoor."; echo "$immutable_files"; ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$immutable_files")
        else
            echo "OK: No immutable files found."
        fi
    fi
}

scan_wp_cli() {
    [ "$DO_WP_CLI" -eq 1 ] || return 0
    if ! command -v wp >/dev/null 2>&1; then
        echo -e "\n[+] WP-CLI checks skipped: 'wp' command not found."
        return
    fi
    echo -e "\n[+] Running WP-CLI deep checks..."
    cd "$SITE_PATH" || { echo "Error: Could not change directory to $SITE_PATH"; exit 1; }

    local WP_ALLOW_ROOT=""
    if [ "${EUID:-$(id -u)}" -eq 0 ]; then
        WP_ALLOW_ROOT="--allow-root"
    fi

    if ! wp $WP_ALLOW_ROOT core is-installed --quiet 2>/dev/null; then
        echo "!!! WARNING: WP-CLI found but not functional for this installation. Skipping WP-CLI checks."
        return
    fi

    echo " -> Checking core file integrity..."
    local core_status=$(wp $WP_ALLOW_ROOT core verify-checksums --format=json 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "!!! WARNING: WordPress core files have been modified or checksums are missing."; echo "$core_status" | jq -r '.[] | "File: $$.file), Status: $$.status)"' 2>/dev/null || echo "$core_status"
    else
        echo "OK: Core file integrity verified."
    fi

    echo " -> Checking plugin and theme status..."
    local plugin_status=$(wp $WP_ALLOW_ROOT plugin list --status=inactive --format=json 2>/dev/null)
    if [ -n "$plugin_status" ] && [ "$plugin_status" != "[]" ]; then
        echo "!!! WARNING: Inactive plugins found (can be a security risk):"; echo "$plugin_status" | jq -r '.[] | " - $$.name) (v$$.version))"' 2>/dev/null || echo "$plugin_status"
    fi
    local theme_status=$(wp $WP_ALLOW_ROOT theme list --status=inactive --format=json 2>/dev/null)
    if [ -n "$theme_status" ] && [ "$theme_status" != "[]" ]; then
        echo "!!! WARNING: Inactive themes found (should be removed):"; echo "$theme_status" | jq -r '.[] | " - $$.name) (v$$.version))"' 2>/dev/null || echo "$theme_status"
    fi
    
    if wp $WP_ALLOW_ROOT cli has-command "plugin vulnerability" 2>/dev/null; then
        echo " -> Checking for plugin vulnerabilities..."
        local vuln_report=$(wp $WP_ALLOW_ROOT plugin vulnerability list --format=json 2>/dev/null)
        local vuln_count=$(echo "$vuln_report" | jq length 2>/dev/null || echo 0)
        if [ "$vuln_count" -gt 0 ]; then
            echo "!!! WARNING: Found $vuln_count plugin vulnerabilities:"; echo "$vuln_report" | jq -r '.[] | " - $$.title) in $$.plugin) ($$.fixed_in // "no fix"))"' 2>/dev/null || echo "$vuln_report"
        fi
    fi
    
    echo " -> Checking user security..."
    local admin_users=$(wp $WP_ALLOW_ROOT user list --role=administrator --format=json 2>/dev/null)
    if [ -n "$admin_users" ]; then
        echo "INFO: Administrator users found:"; echo "$admin_users" | jq -r '.[] | " - $$.user_login) ($$.user_email))"' 2>/dev/null || echo "$admin_users"
    fi
    local no_role_users=$(wp $WP_ALLOW_ROOT user list --role= --format=json 2>/dev/null)
    if [ -n "$no_role_users" ] && [ "$no_role_users" != "[]" ]; then
        echo "!!! WARNING: Users with no assigned role found:"; echo "$no_role_users" | jq -r '.[] | " - $$.user_login) ($$.user_email))"' 2>/dev/null || echo "$no_role_users"
    fi

    echo " -> Checking for suspicious options..."
    local upload_path=$(wp $WP_ALLOW_ROOT option get upload_path --format=json 2>/dev/null)
    if [ -n "$upload_path" ] && [ "$upload_path" != "null" ] && [ "$upload_path" != "wp-content/uploads" ]; then
        echo "!!! WARNING: Custom upload_path detected: $upload_path"
    fi
}


# --- MAIN EXECUTION LOGIC ---

# Argument Parsing
while [ $# -gt 0 ]; do
    case "$1" in
        -e|--email) EMAIL_TO="$2"; shift 2 ;;
        --email-from) EMAIL_FROM="$2"; shift 2 ;;
        --email-subject) EMAIL_SUBJECT="$2"; shift 2 ;;
        --email-always) EMAIL_ALWAYS=1; shift ;;
        --menu) MENU_MODE=1; shift ;;
        --only) enable_only_defaults; LIST=$(echo "$2" | tr ',' ' '); for m in $LIST; do set_module_flag "$m"; done; shift 2 ;;
        --skip) LIST=$(echo "$2" | tr ',' ' '); for m in $LIST; do clear_module_flag "$m"; done; shift 2 ;;
        --no-wordpress) WP_MODE=0; shift ;;
        --sc) SHOW_CONTEXT=1; shift ;;
        --json) JSON_OUTPUT=1; shift ;;
        --exit-code) EXIT_CODE_MODE="$2"; shift 2 ;;
        --zip) ZIP_ENABLED=1; ZIP_TARGET_ZIP="$2"; shift 2 ;;
        --with-cache) EXCLUDE_CACHE=0; shift ;;
        --scan-all) SCAN_ALL=1; set_module_flag all; shift ;;
        --recent) set_module_flag recent; shift ;;
        --no-recent) clear_module_flag recent; shift ;;
        --suspicious) set_module_flag suspicious; shift ;;
        --no-suspicious) clear_module_flag suspicious; shift ;;
        --uploads) set_module_flag uploads; shift ;;
        --no-uploads) clear_module_flag uploads; shift ;;
        --backdoor) set_module_flag backdoor; shift ;;
        --no-backdoor) clear_module_flag backdoor; shift ;;
        --obfuscation) set_module_flag obfuscation; shift ;;
        --no-obfuscation) clear_module_flag obfuscation; shift ;;
        --phpshell) DO_PHPSHELL=1; shift ;;
        --no-phpshell) DO_PHPSHELL=0; shift ;;
        --uploads-php) DO_UPLOADS_PHP=1; shift ;;
        --no-uploads-php) DO_UPLOADS_PHP=0; shift ;;
        --hidden) set_module_flag hidden; shift ;;
        --no-hidden) clear_module_flag hidden; shift ;;
        --superglobal) set_module_flag superglobal; shift ;;
        --no-superglobal) clear_module_flag superglobal; shift ;;
        --curl) set_module_flag curl; shift ;;
        --no-curl) clear_module_flag curl; shift ;;
        --wpver) set_module_flag wpver; shift ;;
        --no-wpver) clear_module_flag wpver; shift ;;
        --perms) set_module_flag perms; shift ;;
        --no-perms) clear_module_flag perms; shift ;;
        --immutable) set_module_flag immutable; shift ;;
        --no-immutable) clear_module_flag immutable; shift ;;
        --verification) set_module_flag verification; shift ;;
        --no-verification) clear_module_flag verification; shift ;;
        --access-logs) set_module_flag access_logs; shift ;;
        --no-access-logs) clear_module_flag access_logs; shift ;;
        --dyn-exec) set_module_flag dyn-exec; shift ;;
        --no-dyn-exec) clear_module_flag dyn-exec; shift ;;
        --oneliner) set_module_flag oneliner; shift ;;
        --no-oneliner) clear_module_flag oneliner; shift ;;
        --wp-cli) set_module_flag wp-cli; shift ;;
        --no-wp-cli) clear_module_flag wp-cli; shift ;;
        -h|--help) echo "Usage: $0 [options] /path/to/site/root"; echo; echo "Run with --help to see all options."; exit 0 ;;
        *) if [ -z "$ARG_SITE" ]; then ARG_SITE="$1"; shift; else echo "Warning: Unrecognized extra argument '$1' will be ignored." ; shift; fi ;;
    esac
done

# Site Validation
if [ -z "$ARG_SITE" ]; then echo "Usage: $0 [options] /path/to/site/root"; echo "Run with --help to see all options."; exit 0; fi
SITE_PATH=$(realpath "$ARG_SITE")
if [ ! -d "$SITE_PATH" ]; then echo "Error: Directory '$SITE_PATH' not found."; exit 1; fi
if [ "$WP_MODE" -eq 1 ] && [ ! -f "$SITE_PATH/wp-config.php" ]; then echo "Error: wp-config.php not found in '$SITE_PATH'. Is this a WordPress root?"; exit 1; fi

# Log Setup
if command -v mktemp >/dev/null 2>&1; then LOG_FILE=$(mktemp -t wp-scan-XXXXXX.log); else LOG_FILE="$SITE_PATH/wp-scan-$(date +%Y%m%d%H%M%S).log"; fi
if command -v tee >/dev/null 2>&1; then exec > >(tee -a "$LOG_FILE") 2>&1; else exec >>"$LOG_FILE" 2>&1; fi

# Non-WordPress mode adjustments
if [ "$WP_MODE" -eq 0 ] && [ "$SCAN_ALL" -eq 0 ]; then DO_WPVER=0; DO_UPLOADS=0; DO_UPLOADS_PHP=0; DO_WP_CLI=0; fi

# --- Module Dispatcher ---
run_modules() {
    scan_recent_files
    scan_suspicious_names
    scan_uploads
    scan_uploads_php
    scan_verification_files
    scan_access_logs
    scan_malicious_code
    scan_hidden_files
    scan_superglobal
    scan_curl
    scan_wp_version
    scan_permissions
    scan_immutable
    scan_wp_cli
}

# Run only the modules currently toggled on (used by --menu)
run_selected_modules() {
    [ "$DO_RECENT" -eq 1 ] && scan_recent_files
    [ "$DO_SUSPICIOUS" -eq 1 ] && scan_suspicious_names
    [ "$DO_UPLOADS" -eq 1 ] && scan_uploads
    [ "$DO_UPLOADS_PHP" -eq 1 ] && scan_uploads_php
    [ "$DO_VERIFICATION" -eq 1 ] && scan_verification_files
    [ "$DO_ACCESS_LOGS" -eq 1 ] && scan_access_logs

    # Pattern scans: scan_malicious_code internally checks its own sub-flags,
    # but we only invoke it if at least one related toggle is enabled.
    if [ "$DO_BACKDOOR" -eq 1 ] || [ "$DO_OBFUSCATED" -eq 1 ] || [ "$DO_PHPSHELL" -eq 1 ] || [ "$DO_DYN_EXEC" -eq 1 ] || [ "$DO_ONELINER" -eq 1 ]; then
        scan_malicious_code
    fi

    [ "$DO_HIDDEN" -eq 1 ] && scan_hidden_files
    [ "$DO_SUPERGLOBAL" -eq 1 ] && scan_superglobal
    [ "$DO_CURL" -eq 1 ] && scan_curl
    [ "$DO_WPVER" -eq 1 ] && scan_wp_version
    [ "$DO_PERMS" -eq 1 ] && scan_permissions
    [ "$DO_IMMUTABLE" -eq 1 ] && scan_immutable
    [ "$DO_WP_CLI" -eq 1 ] && scan_wp_cli
}

# --- SCRIPT ENTRY POINT ---
echo "=========================================================================="
echo "Starting Generic WordPress Security Scan for: $SITE_PATH"
echo "=========================================================================="

if [ "${MENU_MODE:-0}" -eq 1 ]; then
    interactive_menu
fi

if [ "${MENU_MODE:-0}" -eq 1 ]; then
    run_selected_modules
else
    run_modules
fi
echo -e "\n=========================================================================="
echo "Scan Complete."
echo "=========================================================================="
echo "Disclaimer: This script is a powerful scanning aid. It may produce false"
echo "positives. All findings should be manually investigated and verified."
echo "=========================================================================="


# --- Email Notification ---
if [ -n "$EMAIL_TO" ]; then
    WARN_COUNT=$(grep -c "!!! WARNING" "$LOG_FILE" 2>/dev/null || echo 0)
    if [ "$EMAIL_ALWAYS" = "1" ] || [ "${WARN_COUNT}" -gt 0 ]; then
        STATUS="OK"; [ "${WARN_COUNT}" -gt 0 ] && STATUS="WARNINGS"
        SUBJECT="${EMAIL_SUBJECT:-Generic WP Scan: $SITE_PATH} [$STATUS]"
        if command -v mail >/dev/null 2>&1 && [ -z "$EMAIL_FROM" ]; then mail -s "$SUBJECT" "$EMAIL_TO" < "$LOG_FILE"; echo "Notification email sent via 'mail' to $EMAIL_TO."
        elif command -v sendmail >/dev/null 2>&1; then { echo "To: $EMAIL_TO"; echo "From: ${EMAIL_FROM:-no-reply@localhost}"; echo "Subject: $SUBJECT"; echo "Content-Type: text/plain; charset=UTF-8"; echo; cat "$LOG_FILE"; } | sendmail -t; echo "Notification email sent via 'sendmail' to $EMAIL_TO."
        elif command -v msmtp >/dev/null 2>&1; then { echo "To: $EMAIL_TO"; echo "From: ${EMAIL_FROM:-no-reply@localhost}"; echo "Subject: $SUBJECT"; echo "Content-Type: text/plain; charset=UTF-8"; echo; cat "$LOG_FILE"; } | msmtp -t; echo "Notification email sent via 'msmtp' to $EMAIL_TO."
        else echo "Email not sent: no mail/sendmail/msmtp found."
        fi
    else echo "Email not sent: no warnings found and --email-always not specified."
    fi
fi

# --- JSON Summary Output ---
if [ "$JSON_OUTPUT" -eq 1 ]; then
    count_lines() { echo "$1" | sed '/^^\s*$/d' | wc -l | awk '{print $1}'; }
    WARN_COUNT=$(grep -c "!!! WARNING" "$LOG_FILE" 2>/dev/null || echo 0)
    STATUS="OK"; [ "$WARN_COUNT" -gt 0 ] && STATUS="WARNINGS"
    # Note: In a modular script, you'd need to capture module outputs into variables to count them here.
    # For simplicity, this example greps the log file for counts.
    ACCESS_LOG_COUNT=$(grep -c "Suspicious access log requests found" "$LOG_FILE" 2>/dev/null || echo 0)
    # ... other counts would be gathered similarly ...
    echo "{"
    echo " \"site\": \"$SITE_PATH\","
    echo " \"status\": \"$STATUS\","
    echo " \"warnings\": $WARN_COUNT,"
    echo " \"modules\": {"
    echo " \"access_logs\": $ACCESS_LOG_COUNT"
    # ... other module counts ...
    echo " }"
    echo "}"
fi

# --- Zip flagged files ---
if [ "$ZIP_ENABLED" -eq 1 ]; then
    if ! command -v zip >/dev/null 2>&1; then
        echo "Zip requested but 'zip' command not found. Skipping archive creation."
    else
        echo "Creating zip archive of flagged files: $ZIP_TARGET_ZIP"
        FILE_LIST=$(mktemp -t wp-scan-ziplist-XXXXXX.txt)
        printf "%s\n" "$ZIP_CANDIDATES" | sed '/^^\s*$/d' | while IFS= read -r p; do [ -f "$p" ] && echo "$p"; done | sort -u > "$FILE_LIST"
        COUNT=$(wc -l < "$FILE_LIST" | awk '{print $1}')
        if [ "$COUNT" -gt 0 ]; then
            zip -@ "$ZIP_TARGET_ZIP" < "$FILE_LIST"
            MANIFEST_TMP=$(mktemp -t wp-scan-manifest-XXXXXX.txt)
            { echo "wp-scan manifest"; echo "site: $SITE_PATH"; echo "created: $(date -u +%Y-%m-%dT%H:%M:%SZ)"; echo "files:"; cat "$FILE_LIST"; } > "$MANIFEST_TMP"
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
if [ "$EXIT_CODE_MODE" = "count" ]; then EC=$WARN_COUNT; [ "$EC" -gt 254 ] && EC=254; exit "$EC"; else [ "$WARN_COUNT" -gt 0 ] && exit 1 || exit 0; fi