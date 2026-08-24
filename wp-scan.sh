#!/bin/bash
# ====================================================================
# Generic WordPress Security Scanner
#
# Usage: ./wp-scan.sh [options] /path/to/site/root
#
# Options:
#   --email <addr>          Send report to this address when warnings found
#   --email-always          Always send email even when no warnings
#   --email-from <addr>     Sender address (sendmail/msmtp)
#   --email-subject <text>  Base subject; status appended
#   --menu                  Interactive menu to select scan modules
#   --plugin-scan            Scan wp-content/plugins for suspicious/malicious/fake plugins
#   --only <modules>        Run only these modules (csv or space-separated)
#   --skip <modules>        Skip these modules (csv or space-separated)
#   --no-wordpress          Scan generic site; skip WordPress-specific checks
#   --sc                    Show 2 lines of code context around matched signatures
#   --json                  Output a minimal JSON summary at the end
#   --exit-code <mode>      Exit code mode: 'binary' (0/1) or 'count' (0-254)
#   --zip <filename.zip>    Zip up flagged files into the specified archive
#   --scan-all              Force-enable all modules for this run
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
#   --modsec-logs / --no-modsec-logs
#   --dyn-exec / --no-dyn-exec
#   --oneliner / --no-oneliner
#   --wp-cli / --no-wp-cli
#   --image-headers / --no-image-headers
#   --help                  Show usage
#
# Modules: recent, suspicious, uploads, uploads-php, backdoor, obfuscation, phpshell, hidden, superglobal, curl, wpver, perms, verification, access-logs, modsec-logs, dyn-exec, oneliner, wp-cli, plugin-scan, immutable, image-headers, all
# Example: ./wp-scan.sh --only recent,uploads --email admin@example.com /var/www/html/site
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

# Optional: file containing IPs to exclude from scan *results* (one per line).
# Env var: WP_SCAN_EXCLUDED_IPS_FILE
EXCLUDED_IPS_FILE="${WP_SCAN_EXCLUDED_IPS_FILE:-}"
EXCLUDED_IPS_PATTERNS_FILE=""

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

# Suspicious IPs collection
SUSPICIOUS_IPS=""

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
DO_IMMUTABLE=1
DO_VERIFICATION=1
DO_ACCESS_LOGS=1
DO_MODSEC_LOGS=1
DO_DYN_EXEC=1
DO_ONELINER=1
DO_WP_CLI=1
DO_IMAGE_HEADERS=1
DO_PLUGIN_SCAN=1
DO_SEO_SPAM=0
DO_SEO_SPAM_MASS=0
DO_SHADOW_ADMIN=0

# Optional WP core verification/restore actions
DO_VERIFY_CORE=0
DO_RESTORE_CORE=0
MENU_MODE=0

# If the user passes one or more *enable* module triggers (e.g. --modsec-logs),
# automatically switch to "only these modules" mode (like --only) unless --scan-all was used.
DEFAULTS_CLEARED=0

enable_only_defaults() {
  DO_RECENT=0; DO_SUSPICIOUS=0; DO_UPLOADS=0; DO_UPLOADS_PHP=0; DO_BACKDOOR=0; DO_OBFUSCATED=0; DO_PHPSHELL=0; DO_HIDDEN=0; DO_SUPERGLOBAL=0; DO_CURL=0; DO_WPVER=0; DO_PERMS=0; DO_IMMUTABLE=0; DO_VERIFICATION=0; DO_ACCESS_LOGS=0; DO_MODSEC_LOGS=0; DO_DYN_EXEC=0; DO_ONELINER=0; DO_WP_CLI=0; DO_IMAGE_HEADERS=0; DO_PLUGIN_SCAN=0
  DEFAULTS_CLEARED=1
}

enter_only_mode_if_needed() {
  # Only enter "only these modules" mode when user explicitly enabled a module,
  # and they didn't request --scan-all.
  if [ "$SCAN_ALL" -eq 0 ] && [ "$DEFAULTS_CLEARED" -eq 0 ]; then
    enable_only_defaults
  fi
}

set_module_flag() {
  case "$1" in
    recent) DO_RECENT=1 ;;
    suspicious) DO_SUSPICIOUS=1 ;;
    uploads) DO_UPLOADS=1 ;;
	    seo-spam) DO_SEO_SPAM=1 ;;
    shadow-admin) DO_SHADOW_ADMIN=1 ;;

    backdoor) DO_BACKDOOR=1 ;;
    obfuscation) DO_OBFUSCATED=1 ;;
    curl) DO_CURL=1 ;;
    wpver) DO_WPVER=1 ;;
    perms) DO_PERMS=1 ;;
    immutable) DO_IMMUTABLE=1 ;;
    verification) DO_VERIFICATION=1 ;;
    access-logs) DO_ACCESS_LOGS=1 ;;
    modsec-logs) DO_MODSEC_LOGS=1 ;;
    dyn-exec) DO_DYN_EXEC=1 ;;
    oneliner) DO_ONELINER=1 ;;
    wp-cli) DO_WP_CLI=1 ;;
    image-headers) DO_IMAGE_HEADERS=1 ;;
    all)
      DO_RECENT=1; DO_SUSPICIOUS=1; DO_UPLOADS=1; DO_UPLOADS_PHP=1; DO_BACKDOOR=1; DO_OBFUSCATED=1; DO_PHPSHELL=1; DO_HIDDEN=1; DO_SUPERGLOBAL=1; DO_CURL=1; DO_WPVER=1; DO_PERMS=1; DO_IMMUTABLE=1; DO_VERIFICATION=1; DO_ACCESS_LOGS=1; DO_MODSEC_LOGS=1; DO_DYN_EXEC=1; DO_ONELINER=1; DO_WP_CLI=1; DO_IMAGE_HEADERS=1
      ;;
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
    immutable) DO_IMMUTABLE=0 ;;
    verification) DO_VERIFICATION=0 ;;
    access-logs) DO_ACCESS_LOGS=0 ;;
    modsec-logs) DO_MODSEC_LOGS=0 ;;
    dyn-exec) DO_DYN_EXEC=0 ;;
    oneliner) DO_ONELINER=0 ;;
    wp-cli) DO_WP_CLI=0 ;;
    image-headers) DO_IMAGE_HEADERS=0 ;;
    plugin-scan) DO_PLUGIN_SCAN=0 ;;
    all)
      DO_RECENT=0; DO_SUSPICIOUS=0; DO_UPLOADS=0; DO_UPLOADS_PHP=0; DO_BACKDOOR=0; DO_OBFUSCATED=0; DO_PHPSHELL=0; DO_HIDDEN=0; DO_SUPERGLOBAL=0; DO_CURL=0; DO_WPVER=0; DO_PERMS=0; DO_IMMUTABLE=0; DO_VERIFICATION=0; DO_ACCESS_LOGS=0; DO_MODSEC_LOGS=0; DO_DYN_EXEC=0; DO_ONELINER=0; DO_WP_CLI=0; DO_IMAGE_HEADERS=0; DO_PLUGIN_SCAN=0
      ;;
  esac
}

while [ $# -gt 0 ]; do
  case "$1" in
    -e|--email) EMAIL_TO="$2"; shift 2 ;;
    --email-from) EMAIL_FROM="$2"; shift 2 ;;
    --email-subject) EMAIL_SUBJECT="$2"; shift 2 ;;
    --email-always) EMAIL_ALWAYS=1; shift ;;
    --menu) MENU_MODE=1; shift ;;
    --only)
      enable_only_defaults
      LIST=$(echo "$2" | tr ',' ' ')
      for m in $LIST; do
        set_module_flag "$m"
      done
      shift 2
      ;;
    --skip)
      LIST=$(echo "$2" | tr ',' ' ')
      for m in $LIST; do
        clear_module_flag "$m"
      done
      shift 2
      ;;
    --no-wordpress) WP_MODE=0; shift ;;
    --sc) SHOW_CONTEXT=1; shift ;;
    --json) JSON_OUTPUT=1; shift ;;
    --exit-code) EXIT_CODE_MODE="$2"; shift 2 ;;
    --zip) ZIP_ENABLED=1; ZIP_TARGET_ZIP="$2"; shift 2 ;;
    --exclude-ips-file) EXCLUDED_IPS_FILE="$2"; shift 2 ;;
    --with-cache) EXCLUDE_CACHE=0; shift ;;
    --scan-all) SCAN_ALL=1; set_module_flag all; shift ;;
    --recent) enter_only_mode_if_needed; set_module_flag recent; shift ;;
    --no-recent) clear_module_flag recent; shift ;;
    --suspicious) enter_only_mode_if_needed; set_module_flag suspicious; shift ;;
    --no-suspicious) clear_module_flag suspicious; shift ;;
    --uploads) enter_only_mode_if_needed; set_module_flag uploads; shift ;;
    --no-uploads) clear_module_flag uploads; shift ;;
    --backdoor) enter_only_mode_if_needed; set_module_flag backdoor; shift ;;
    --no-backdoor) clear_module_flag backdoor; shift ;;
    --obfuscation) enter_only_mode_if_needed; set_module_flag obfuscation; shift ;;
    --no-obfuscation) clear_module_flag obfuscation; shift ;;
    --phpshell) enter_only_mode_if_needed; DO_PHPSHELL=1; shift ;;
    --no-phpshell) DO_PHPSHELL=0; shift ;;
    --uploads-php) enter_only_mode_if_needed; DO_UPLOADS_PHP=1; shift ;;
    --no-uploads-php) DO_UPLOADS_PHP=0; shift ;;
    --hidden) enter_only_mode_if_needed; DO_HIDDEN=1; shift ;;
    --no-hidden) DO_HIDDEN=0; shift ;;
    --superglobal) enter_only_mode_if_needed; set_module_flag superglobal; shift ;;
    --no-superglobal) clear_module_flag superglobal; shift ;;
    --curl) enter_only_mode_if_needed; set_module_flag curl; shift ;;
    --no-curl) clear_module_flag curl; shift ;;
    --wpver) enter_only_mode_if_needed; set_module_flag wpver; shift ;;
    --no-wpver) clear_module_flag wpver; shift ;;
    --perms) enter_only_mode_if_needed; set_module_flag perms; shift ;;
    --no-perms) clear_module_flag perms; shift ;;
    --immutable) enter_only_mode_if_needed; set_module_flag immutable; shift ;;
    --no-immutable) clear_module_flag immutable; shift ;;
    --verification) enter_only_mode_if_needed; set_module_flag verification; shift ;;
    --no-verification) clear_module_flag verification; shift ;;
  --access-logs) enter_only_mode_if_needed; set_module_flag access-logs; shift ;;
  --no-access-logs) clear_module_flag access-logs; shift ;;
    --modsec-logs) enter_only_mode_if_needed; set_module_flag modsec-logs; shift ;;
    --no-modsec-logs) clear_module_flag modsec-logs; shift ;;
    --dyn-exec) enter_only_mode_if_needed; set_module_flag dyn-exec; shift ;;
    --no-dyn-exec) clear_module_flag dyn-exec; shift ;;
    --oneliner) enter_only_mode_if_needed; set_module_flag oneliner; shift ;;
    --no-oneliner) clear_module_flag oneliner; shift ;;
    --wp-cli) enter_only_mode_if_needed; set_module_flag wp-cli; shift ;;
    --no-wp-cli) clear_module_flag wp-cli; shift ;;
    --plugin-scan) enter_only_mode_if_needed; set_module_flag plugin-scan; shift ;;
    --no-plugin-scan) clear_module_flag plugin-scan; shift ;;
    --image-headers) enter_only_mode_if_needed; set_module_flag image-headers; shift ;;
    --no-image-headers) clear_module_flag image-headers; shift ;;
    --verify-core) DO_VERIFY_CORE=1; shift ;;
    --restore-core) DO_RESTORE_CORE=1; shift ;;
    --seo-spam-mass) DO_SEO_SPAM_MASS=1; shift ;;
	
    -h|--help)
      echo "Usage: $0 [options] /path/to/site/root"
      echo
      echo "Options: --email <addr> --email-always --email-from <addr> --email-subject <text> --menu --plugin-scan --only <modules> --skip <modules> --no-wordpress --sc --json --exit-code <binary|count> --zip <filename.zip> --exclude-ips-file <file> --with-cache --scan-all --verify-core --restore-core"
      echo "Module Triggers: --recent/--no-recent --suspicious/--no-suspicious --uploads/--no-uploads --uploads-php/--no-uploads-php --backdoor/--no-backdoor --obfuscation/--no-obfuscation --phpshell/--no-phpshell --hidden/--no-hidden --superglobal/--no-superglobal --curl/--no-curl --wpver/--no-wpver --perms/--no-perms --immutable/--no-immutable --verification/--no-verification --access-logs/--no-access-logs --modsec-logs/--no-modsec-logs --dyn-exec/--no-dyn-exec --oneliner/--no-oneliner --wp-cli/--no-wp-cli --image-headers/--no-image-headers"
      echo "Modules: recent, suspicious, uploads, uploads-php, backdoor, obfuscation, phpshell, dyn-exec, oneliner, wp-cli, hidden, superglobal, curl, wpver, perms, immutable, verification, access-logs, modsec-logs, image-headers, all"
      echo
      echo "Examples:"
      echo " $0 --only recent,uploads --email admin@example.com /var/www/html/site"
      echo " $0 --no-wordpress --phpshell --sc /var/www/html/site"
      echo " $0 --exclude-ips-file ./excluded-ips.txt --access-logs /var/www/html/site"
      echo " $0 --menu /var/www/html/wordpress"
      exit 0
      ;;
    *)
      if [ -z "$ARG_SITE" ]; then
        ARG_SITE="$1"; shift
      else
        echo "Warning: Unrecognized extra argument '$1' will be ignored." ; shift
      fi
      ;;
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


# --- Excluded IPs support (filters results output, not the scanning itself) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

# Default excluded IPs file is alongside this script if present.
if [ -z "$EXCLUDED_IPS_FILE" ] && [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/excluded-ips.txt" ]; then
  EXCLUDED_IPS_FILE="$SCRIPT_DIR/excluded-ips.txt"
fi

prepare_excluded_ip_patterns() {
  # Build a sanitized, newline-delimited pattern file for grep -F -f.
  # Supports comments (# ...) and blank lines.
  if [ -z "$EXCLUDED_IPS_FILE" ] || [ ! -f "$EXCLUDED_IPS_FILE" ]; then
    EXCLUDED_IPS_PATTERNS_FILE=""
    return 0
  fi

  if ! command -v mktemp >/dev/null 2>&1; then
    # No mktemp available; use file directly (best-effort, less safe).
    EXCLUDED_IPS_PATTERNS_FILE="$EXCLUDED_IPS_FILE"
    return 0
  fi

  EXCLUDED_IPS_PATTERNS_FILE=$(mktemp -t wp-scan-excluded-ips-XXXXXX.txt)
  # Remove comments, trim whitespace, drop empty lines.
  sed -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e '/^$/d' "$EXCLUDED_IPS_FILE" > "$EXCLUDED_IPS_PATTERNS_FILE" 2>/dev/null || true

  # If the sanitized file is empty, treat as disabled.
  if [ ! -s "$EXCLUDED_IPS_PATTERNS_FILE" ]; then
    rm -f "$EXCLUDED_IPS_PATTERNS_FILE" 2>/dev/null || true
    EXCLUDED_IPS_PATTERNS_FILE=""
  fi
}

cleanup_excluded_ip_patterns() {
  if [ -n "$EXCLUDED_IPS_PATTERNS_FILE" ] \
    && [ -n "$EXCLUDED_IPS_FILE" ] \
    && [ "$EXCLUDED_IPS_PATTERNS_FILE" != "$EXCLUDED_IPS_FILE" ]; then
    rm -f "$EXCLUDED_IPS_PATTERNS_FILE" 2>/dev/null || true
  fi
}

filter_excluded_ips() {
  # Reads from stdin; writes to stdout.
  # If an exclude list is configured, remove lines containing any excluded IP.
  if [ -n "$EXCLUDED_IPS_PATTERNS_FILE" ] && [ -f "$EXCLUDED_IPS_PATTERNS_FILE" ]; then
    grep -v -F -f "$EXCLUDED_IPS_PATTERNS_FILE" 2>/dev/null || true
  else
    cat
  fi
}

prepare_excluded_ip_patterns
trap cleanup_excluded_ip_patterns EXIT


# Optional interactive module selection
if [ "$MENU_MODE" -eq 1 ]; then
  echo "Interactive Module Selection"
  echo " 1) Recently modified files                      (--recent)"
  echo " 2) Suspicious file/directory names               (--suspicious)"
  echo " 3) Non-month directories in uploads              (--uploads)"
  echo " 4) High-risk backdoor functions (PHP)            (--backdoor)"
  echo " 5) Obfuscated code (PHP)                         (--obfuscation)"
  echo " 6) cURL calls (PHP)                              (--curl)"
  echo " 7) WordPress version                             (--wpver)"
  echo " 8) File permissions                              (--perms)"
  echo " 9) PHP files inside uploads                      (--uploads-php)"
  echo "10) Hidden dotfiles                               (--hidden)"
  echo "11) Superglobal backdoor patterns                 (--superglobal)"
  echo "12) Verification files (.well-known & top-level)  (--verification)"
  echo "13) Access logs scan (/home/<user>/logs, etc.)    (--access-logs)"
  echo "14) ModSecurity logs scan (/var/log/*modsec*)     (--modsec-logs)"
  echo "15) Dynamic execution patterns                    (--dyn-exec)"
  echo "16) Potential one-liner shells                    (--oneliner)"
    echo "20) SEO Spam 'Link Factory' (German Hijack)       (--seo-spam)"
  echo "21) Database Shadow Admin Audit                  (--shadow-admin)"
  echo "22) Plugin deep scan (plugins directory)          (--plugin-scan)"
  echo "40) Mass-scan /home/* for SEO Spam (de_DE.l10n.php)  (--seo-spam-mass)"

  echo "17) WP-CLI deep checks                            (--wp-cli)"
  echo "18) Immutable files (+i attribute)                (--immutable)"
  echo "19) Image header malware scan                     (--image-headers)"
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
		        20) DO_SEO_SPAM=1 ;;
        21) DO_SHADOW_ADMIN=1 ;;
        22) DO_PLUGIN_SCAN=1 ;;
        40) DO_SEO_SPAM_MASS=1 ;;

        9) DO_UPLOADS_PHP=1 ;;
        10) DO_HIDDEN=1 ;;
        11) DO_SUPERGLOBAL=1 ;;
        12) DO_VERIFICATION=1 ;;
        13) DO_ACCESS_LOGS=1 ;;
        14) DO_MODSEC_LOGS=1 ;;
        15) DO_DYN_EXEC=1 ;;
        16) DO_ONELINER=1 ;;
        17) DO_WP_CLI=1 ;;
        18) DO_IMMUTABLE=1 ;;
        19) DO_IMAGE_HEADERS=1 ;;
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
  DO_WP_CLI=0
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
  SUSPICIOUS_NAMES=("cg-bin" "phpshell" "c99" "r57" "webshell" "wso" "adminer.php" "phpmyadmin" "xmlrpc.php" "enmnnu.php")
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
    # FIX: Use a while loop with process redirection to avoid subshell issues.
    echo " -> Checking for non-month directories in uploads..."
    FAKE_MONTH_DIRS=""
    find "$UPLOADS_DIR" -maxdepth 2 -type d -name "[0-9]*" -print 2>/dev/null | while IFS= read -r DIR; do
      BASENAME=$(basename "$DIR")
      # months are typically 01-12
      if [[ "$BASENAME" =~ ^[0-9]+$ ]] && ! [[ "$BASENAME" =~ ^(0[1-9]|1[0-2])$ ]]; then
        echo "$DIR"
      fi
    done | sort > "${FAKE_MONTH_DIRS_FILE:=$(mktemp)}"
    FAKE_MONTH_DIRS=$(cat "${FAKE_MONTH_DIRS_FILE}")

    if [ -n "$FAKE_MONTH_DIRS" ]; then
      echo "!!! WARNING: Found non-month directories in uploads (possible backdoors):"
      echo "$FAKE_MONTH_DIRS"
      ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$FAKE_MONTH_DIRS")
    else
      echo "OK: No non-month directories found in uploads."
    fi
    rm -f "${FAKE_MONTH_DIRS_FILE}"

    # New: Flag any PHP files within uploads (often malicious)
    if [ "$DO_UPLOADS_PHP" -eq 1 ]; then
      # Catch common executable PHP-like extensions used for bypasses.
      UPLOADS_PHP_FILES=$(find "$UPLOADS_DIR" -type f \( -iname "*.php" -o -iname "*.phtml" -o -iname "*.php5" -o -iname "*.php7" -o -iname "*.phar" -o -iname "*.inc" \) 2>/dev/null)
      if [ -n "$UPLOADS_PHP_FILES" ]; then
        echo "!!! WARNING: Found executable PHP-like files inside uploads (should be media only):"
        echo "$UPLOADS_PHP_FILES"
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$UPLOADS_PHP_FILES")
      else
        echo "OK: No PHP files found inside uploads."
      fi

      # Also flag common double-extension tricks like image.jpg.php
      UPLOADS_DOUBLE_EXT=$(find "$UPLOADS_DIR" -type f \( -iname "*.jpg.php" -o -iname "*.jpeg.php" -o -iname "*.png.php" -o -iname "*.gif.php" -o -iname "*.webp.php" -o -iname "*.pdf.php" -o -iname "*.txt.php" \) 2>/dev/null)
      if [ -n "$UPLOADS_DOUBLE_EXT" ]; then
        echo "!!! WARNING: Found double-extension files in uploads (e.g. image.jpg.php):"
        echo "$UPLOADS_DOUBLE_EXT" | head -50
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$UPLOADS_DOUBLE_EXT")
      fi
    fi
  fi
fi

# Check for any verification files (Google, Bing, Yandex, etc.)
if [ "$DO_VERIFICATION" -eq 1 ]; then
  VERIFICATION_FILES=$( { find "$SITE_PATH" -maxdepth 1 -type f \( -name "google*.html" -o -name "bing*.html" -o -name "yandex*.html" \) 2>/dev/null ; find "$SITE_PATH/.well-known" -type f 2>/dev/null ; } 2>/dev/null )
  # Known trusted verification files can be listed here to avoid false positives.
  # Example: google0ebb363c25f399c9.html belongs to Forrest and should not trigger a warning.
  if [ -n "$VERIFICATION_FILES" ]; then
    # Detect and remove the trusted Forrest file from the warning list.
    TRUSTED_ENTRY="${SITE_PATH}/google0ebb363c25f399c9.html"
    if printf "%s\n" "$VERIFICATION_FILES" | grep -x -F -q "$TRUSTED_ENTRY" 2>/dev/null; then
      echo "Info: Found verification file 'google0ebb363c25f399c9.html' (owned by Forrest); skipping warning for that file."
      VERIFICATION_FILES=$(printf "%s\n" "$VERIFICATION_FILES" | grep -v -x -F "$TRUSTED_ENTRY" 2>/dev/null || true)
    fi
  fi
  if [ -n "$VERIFICATION_FILES" ]; then
    echo "!!! WARNING: Found verification files. These could be for unauthorized ownership claims:"
    echo "$VERIFICATION_FILES"
    ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$VERIFICATION_FILES")
  else
    echo "OK: No verification files found."
  fi
fi


# --- Access logs scan (home directory access-logs + compressed logs) ---
if [ "$DO_ACCESS_LOGS" -eq 1 ]; then
  echo -e "\n[+] Scanning access logs under /home/* (access-logs + logs) for suspicious requests..."

  ACCESS_LOG_FINDINGS=""
  ACCESS_LOG_FILES=""
  ACCESS_LOG_MATCHED_LINES=""
  ACCESS_LOG_STATUS_2XX=0
  ACCESS_LOG_STATUS_3XX=0
  ACCESS_LOG_STATUS_4XX=0
  ACCESS_LOG_STATUS_5XX=0
  ACCESS_LOG_STATUS_0=0
  ACCESS_LOG_LIKELY_OUTCOME=""

  # Try to extract HTTP status code from common log formats.
  # Common/combined log format ends with: "<METHOD> <PATH> HTTP/x.y" <status> <bytes>
  # Some variants have: <status> right after the closing quote.
  extract_http_status() {
    # Input: full log line
    # Output: status code (e.g., 200) or empty
    # Prefer: after request "..." <status>
    printf "%s" "$1" | sed -n -E 's/.*"[A-Z]+ [^"]+ HTTP\/[0-9.]+"[[:space:]]+([0-9]{3}).*/\1/p'
  }

  bump_status_bucket() {
    local st="$1"
    case "$st" in
      2??) ACCESS_LOG_STATUS_2XX=$((ACCESS_LOG_STATUS_2XX + 1)) ;;
      3??) ACCESS_LOG_STATUS_3XX=$((ACCESS_LOG_STATUS_3XX + 1)) ;;
      4??) ACCESS_LOG_STATUS_4XX=$((ACCESS_LOG_STATUS_4XX + 1)) ;;
      5??) ACCESS_LOG_STATUS_5XX=$((ACCESS_LOG_STATUS_5XX + 1)) ;;
      *) ACCESS_LOG_STATUS_0=$((ACCESS_LOG_STATUS_0 + 1)) ;;
    esac
  }

  # Extract IP address from log line and add to suspicious IPs collection
  collect_suspicious_ip() {
    local line="$1"
    # Extract IP from common log formats (IP is typically first field)
    local ip=$(printf "%s" "$line" | grep -oE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    if [ -n "$ip" ]; then
      SUSPICIOUS_IPS=$(printf "%s\n%s" "$SUSPICIOUS_IPS" "$ip")
    fi
  }

  # If the scanned site is under /home/<user>/public_html, prefer that user's log folders.
  ACCESS_LOG_USER=""
  if [[ "$SITE_PATH" =~ ^/home/([^/]+)/public_html(/|$) ]]; then
    ACCESS_LOG_USER="${BASH_REMATCH[1]}"
  fi

  # Helper: scan a plain text log file
  scan_plain_access_log() {
    local f="$1"
    [ -f "$f" ] || return 0
    # Only text-ish files; if grep thinks it's binary, skip.
    if grep -Iq . "$f" 2>/dev/null; then
      # A small but useful set of high-signal patterns.
      local pat
  pat="(/\.env(\b|$))|(/wp-config\.php(\b|$))|(/xmlrpc\.php(\b|$))|(/wp-admin/?(\b|$))|(/wp-login\.php(\b|$))|(/wp-content/(uploads|mu-plugins)/[^ ]*\.(php|phtml|php[0-9]|phar)(\b|$))|(/\.git/)|(/\.svn/)|(/\.hg/)|(/cgi-bin/)|(/(wp-includes|wp-admin)/[^ ]*\.(php|phtml)(\b|$))|(/phpmyadmin/?|/pma/?|/adminer\.php(\b|$))|(/\.well-known/)|\b(Go-http-client|python-requests|curl/|Wget/|libwww-perl|masscan|zgrab|sqlmap|nikto|acunetix|nessus|openvas|wpscan|nmap|gobuster|dirb|dirbuster)\b|\.(bak|old|orig|save|swp|swo|~)(\b|$)|\b(select\b.*\bfrom\b|union([+%20]|%2b)+select|information_schema|sleep\(|benchmark\(|load_file\(|outfile|into([+%20]|%2b)+dumpfile)\b|\bxp_cmdshell\b)\b|\b(or|and)([+%20]|%2b)+1=1\b|\b(wp_)?users\b.*\b(user_login|user_pass)\b|\bpasswd\b|\bshadow\b|((/|%2f)(etc|proc)(/|%2f)(passwd|shadow|self/environ|version))|\b(\.{2}(/|\\\\|%2f|%5c)){2,}\b|\b(%2e%2e%2f|%2e%2e%5c){2,}\b|\bphp://(input|filter)\b|\bdata://\b|\bphar://\b|\bexpect://\b|\b(\$\{|\$\(|\x60|;|\|\||&&)\b|\b(cmd=|exec=|system=|shell=|powershell=|bash=|sh=|wget=|curl=|python=|perl=|php=)\b|\b(base64|base64_decode|gzinflate|str_rot13|eval\(|assert\(|passthru\(|shell_exec\(|proc_open\(|popen\(|\bwhoami\b|\bid\b|\buname\b)"
      local hits
      hits=$(grep -n -E -i "$pat" "$f" 2>/dev/null | filter_excluded_ips | head -50)
      if [ -n "$hits" ]; then
        ACCESS_LOG_FILES=$(printf "%s\n%s\n" "$ACCESS_LOG_FILES" "$f")
        ACCESS_LOG_FINDINGS=$(printf "%s\n=== %s ===\n%s\n" "$ACCESS_LOG_FINDINGS" "$f" "$hits")

        # Capture matched lines for status parsing (strip the grep-added line number prefix)
        ACCESS_LOG_MATCHED_LINES=$(printf "%s\n%s\n" "$ACCESS_LOG_MATCHED_LINES" "$(printf "%s\n" "$hits" | sed -E 's/^[0-9]+://')")
        
        # Extract and collect suspicious IPs from matched lines
        while IFS= read -r ln; do
          [ -z "$ln" ] && continue
          collect_suspicious_ip "$(printf "%s" "$ln" | sed -E 's/^[0-9]+://')"
        done < <(printf "%s\n" "$hits")
      fi
    fi
  }

  # Helper: scan a gzipped log (gunzip -c)
  scan_gz_access_log() {
    local f="$1"
    [ -f "$f" ] || return 0
    command -v gzip >/dev/null 2>&1 || return 0
    local pat
  pat="(/\.env(\b|$))|(/wp-config\.php(\b|$))|(/xmlrpc\.php(\b|$))|(/wp-admin/?(\b|$))|(/wp-login\.php(\b|$))|(/wp-content/(uploads|mu-plugins)/[^ ]*\.(php|phtml|php[0-9]|phar)(\b|$))|(/\.git/)|(/\.svn/)|(/\.hg/)|(/cgi-bin/)|(/(wp-includes|wp-admin)/[^ ]*\.(php|phtml)(\b|$))|(/phpmyadmin/?|/pma/?|/adminer\.php(\b|$))|(/\.well-known/)|\b(Go-http-client|python-requests|curl/|Wget/|libwww-perl|masscan|zgrab|sqlmap|nikto|acunetix|nessus|openvas|wpscan|nmap|gobuster|dirb|dirbuster)\b|\.(bak|old|orig|save|swp|swo|~)(\b|$)|\b(select\b.*\bfrom\b|union([+%20]|%2b)+select|information_schema|sleep\(|benchmark\(|load_file\(|outfile|into([+%20]|%2b)+dumpfile)\b|\bxp_cmdshell\b)\b|\b(or|and)([+%20]|%2b)+1=1\b|\b(wp_)?users\b.*\b(user_login|user_pass)\b|\bpasswd\b|\bshadow\b|((/|%2f)(etc|proc)(/|%2f)(passwd|shadow|self/environ|version))|\b(\.{2}(/|\\\\|%2f|%5c)){2,}\b|\b(%2e%2e%2f|%2e%2e%5c){2,}\b|\bphp://(input|filter)\b|\bdata://\b|\bphar://\b|\bexpect://\b|\b(\$\{|\$\(|\x60|;|\|\||&&)\b|\b(cmd=|exec=|system=|shell=|powershell=|bash=|sh=|wget=|curl=|python=|perl=|php=)\b|\b(base64|base64_decode|gzinflate|str_rot13|eval\(|assert\(|passthru\(|shell_exec\(|proc_open\(|popen\(|\bwhoami\b|\bid\b|\buname\b)"
    local hits
    hits=$(gzip -cd -- "$f" 2>/dev/null | grep -n -E -i "$pat" | filter_excluded_ips | head -50)
    if [ -n "$hits" ]; then
      ACCESS_LOG_FILES=$(printf "%s\n%s\n" "$ACCESS_LOG_FILES" "$f")
      ACCESS_LOG_FINDINGS=$(printf "%s\n=== %s ===\n%s\n" "$ACCESS_LOG_FINDINGS" "$f" "$hits")

      # Capture matched lines for status parsing (strip the grep-added line number prefix)
      ACCESS_LOG_MATCHED_LINES=$(printf "%s\n%s\n" "$ACCESS_LOG_MATCHED_LINES" "$(printf "%s\n" "$hits" | sed -E 's/^[0-9]+://')")
      
      # Extract and collect suspicious IPs from matched lines
      while IFS= read -r ln; do
        [ -z "$ln" ] && continue
        collect_suspicious_ip "$(printf "%s" "$ln" | sed -E 's/^[0-9]+://')"
      done < <(printf "%s\n" "$hits")
    fi
  }

  if [ -d "/home" ]; then
    if [ -n "$ACCESS_LOG_USER" ]; then
      ACCESS_LOG_BASE="/home/$ACCESS_LOG_USER"
      # 1) /home/<user>/access-logs (typically uncompressed)
      if [ -d "$ACCESS_LOG_BASE/access-logs" ]; then
        while IFS= read -r lf; do
          [ -z "$lf" ] && continue
          scan_plain_access_log "$lf"
        done < <(find "$ACCESS_LOG_BASE/access-logs" -maxdepth 1 -type f 2>/dev/null | head -500)
      fi

      # 2) /home/<user>/logs (often compressed)
      if [ -d "$ACCESS_LOG_BASE/logs" ]; then
        while IFS= read -r lf; do
          [ -z "$lf" ] && continue
          case "$lf" in
            *.gz) scan_gz_access_log "$lf" ;;
            *) scan_plain_access_log "$lf" ;;
          esac
        done < <(find "$ACCESS_LOG_BASE/logs" -maxdepth 1 -type f 2>/dev/null | head -500)
      fi
    else
      # Fallback: scan all /home/* trees
      while IFS= read -r lf; do
        [ -z "$lf" ] && continue
        scan_plain_access_log "$lf"
      done < <(find /home -maxdepth 3 -type f -path "*/access-logs/*" 2>/dev/null | head -500)

      while IFS= read -r lf; do
        [ -z "$lf" ] && continue
        case "$lf" in
          *.gz) scan_gz_access_log "$lf" ;;
          *) scan_plain_access_log "$lf" ;;
        esac
      done < <(find /home -maxdepth 3 -type f -path "*/logs/*" 2>/dev/null | head -500)
    fi
  fi

  ACCESS_LOG_FILES=$(printf "%s\n" "$ACCESS_LOG_FILES" | sed '/^\s*$/d' | sort -u)

  # Also look for application error_log files inside the site and show the last 100 lines for quick debugging.
  ERR_LOG_FILES=$(find "$SITE_PATH" -type f -name "error_log" 2>/dev/null | head -50)
  if [ -n "$ERR_LOG_FILES" ]; then
    echo " -> Found error_log files under site; showing last 100 lines for each (use --zip to collect):"
    while IFS= read -r ef; do
      [ -z "$ef" ] && continue
      echo "----- $ef (last 100 lines) -----"
      if tail -n 100 "$ef" 2>/dev/null; then :; else echo "(couldn't read or tail $ef)"; fi
      ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$ef")
    done < <(printf "%s\n" "$ERR_LOG_FILES")
  fi

  if [ -n "$ACCESS_LOG_FINDINGS" ]; then
    echo "!!! WARNING: Suspicious access log requests found (showing first hits per file):"
    echo "$ACCESS_LOG_FINDINGS" | head -200

    # Quick summary: surface the most frequent indicators across all hits
    echo " -> Access log quick summary (top indicators):"
    echo "    Flagged log files: $(printf "%s\n" "$ACCESS_LOG_FILES" | sed '/^\s*$/d' | wc -l | awk '{print $1}')"

    # Derive a *non-conclusive* heuristic from HTTP status codes in the matched lines.
    # Interpretation:
    #  - 2xx/3xx on suspicious requests = endpoint returned a response (does not prove compromise)
    #  - 4xx = more likely blocked/missing (not conclusive)
    #  - 5xx = server error (investigate; not conclusive)
    #  - unknown = can't parse
    ACCESS_LOG_STATUS_2XX=0
    ACCESS_LOG_STATUS_3XX=0
    ACCESS_LOG_STATUS_4XX=0
    ACCESS_LOG_STATUS_5XX=0
    ACCESS_LOG_STATUS_0=0
    if [ -n "$ACCESS_LOG_MATCHED_LINES" ]; then
      while IFS= read -r ln; do
        [ -z "$ln" ] && continue
        st=$(extract_http_status "$ln")
        if [ -n "$st" ]; then
          bump_status_bucket "$st"
        else
          ACCESS_LOG_STATUS_0=$((ACCESS_LOG_STATUS_0 + 1))
        fi
      done < <(printf "%s\n" "$ACCESS_LOG_MATCHED_LINES")
    fi
    echo "    Status buckets (matched lines): 2xx=$ACCESS_LOG_STATUS_2XX  3xx=$ACCESS_LOG_STATUS_3XX  4xx=$ACCESS_LOG_STATUS_4XX  5xx=$ACCESS_LOG_STATUS_5XX  unknown=$ACCESS_LOG_STATUS_0"
    POSS_SUCCESS=$((ACCESS_LOG_STATUS_2XX + ACCESS_LOG_STATUS_3XX))
    POSS_BLOCKED=$((ACCESS_LOG_STATUS_4XX))
    if [ "$POSS_SUCCESS" -gt 0 ]; then
      ACCESS_LOG_LIKELY_OUTCOME="2xx/3xx observed"
      echo "    Heuristic: suspicious requests returned 2xx/3xx (not proof of compromise)"
    elif [ "$POSS_BLOCKED" -gt 0 ] && [ "$ACCESS_LOG_STATUS_5XX" -eq 0 ]; then
      ACCESS_LOG_LIKELY_OUTCOME="only 4xx observed"
      echo "    Heuristic: only 4xx observed on suspicious requests (not conclusive)"
    elif [ "$ACCESS_LOG_STATUS_5XX" -gt 0 ]; then
      ACCESS_LOG_LIKELY_OUTCOME="5xx observed"
      echo "    Heuristic: 5xx errors observed on suspicious requests (investigate; not conclusive)"
    else
      ACCESS_LOG_LIKELY_OUTCOME="unknown"
      echo "    Heuristic: could not parse status codes from log lines"
    fi

    # Extract hit lines, normalize to lower, and count common indicators
    printf "%s\n" "$ACCESS_LOG_FINDINGS" \
      | grep -E -i "(^[0-9]+:|\b(Go-http-client|python-requests|curl/|Wget/|libwww-perl|masscan|zgrab|sqlmap|nikto|acunetix|nessus|openvas|wpscan|nmap|gobuster|dirb|dirbuster)\b|/\.env\b|/wp-config\.php\b|/xmlrpc\.php\b|/wp-login\.php\b|/wp-admin\b|/phpmyadmin\b|/adminer\.php\b|/\.git/|\.{2}/|%2e%2e%2f|php://|data://|phar://|expect://|union[+%20]%?select|information_schema|sleep\(|benchmark\()" \
      | tr 'A-Z' 'a-z' \
      | grep -o -E "go-http-client|python-requests|curl/|wget/|libwww-perl|masscan|zgrab|sqlmap|nikto|acunetix|nessus|openvas|wpscan|nmap|gobuster|dirb|dirbuster|/\.env|/wp-config\.php|/xmlrpc\.php|/wp-login\.php|/wp-admin|/phpmyadmin|/adminer\.php|/\.git/|\.\./|%2e%2e%2f|php://|data://|phar://|expect://|information_schema|union|sleep\(|benchmark\(" \
      | sort \
      | uniq -c \
      | sort -nr \
      | head -15 \
      | sed 's/^/    /'

    ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$ACCESS_LOG_FILES")
  else
    echo "OK: No suspicious access log patterns found in /home/* access logs."
  fi
fi


# --- ModSecurity logs scan (audit/debug logs) ---
if [ "$DO_MODSEC_LOGS" -eq 1 ]; then
  echo -e "\n[+] Scanning ModSecurity logs (audit/debug) for blocked/suspicious requests..."

  MODSEC_LOG_FINDINGS=""
  MODSEC_LOG_FILES=""
  MODSEC_MATCHED_LINES=""

  # High-signal patterns commonly present in audit/debug logs.
  # Example: ModSecurity: Access denied with code 403 (phase 2). ... [id "12345"] [msg "..."] [uri "/wp-login.php"] [client 1.2.3.4]
  MODSEC_PAT="ModSecurity:|Access denied with code|\[id \"[0-9]+\"\]|\[msg \"|\[uri \"|\[client |\[hostname \"|\[tag \""

  # Extract IP from ModSecurity log line (format: [client IP])
  collect_modsec_ip() {
    local line="$1"
    local ip=$(printf "%s" "$line" | sed -n -E 's/.*\[client ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\].*/\1/p')
    if [ -n "$ip" ]; then
      SUSPICIOUS_IPS=$(printf "%s\n%s" "$SUSPICIOUS_IPS" "$ip")
    fi
  }

  scan_plain_modsec_log() {
    local f="$1"
    [ -f "$f" ] || return 0
    if grep -Iq . "$f" 2>/dev/null; then
      local hits
      hits=$(grep -n -E -i "$MODSEC_PAT" "$f" 2>/dev/null | head -80)
      if [ -n "$hits" ]; then
        MODSEC_LOG_FILES=$(printf "%s\n%s\n" "$MODSEC_LOG_FILES" "$f")
        MODSEC_LOG_FINDINGS=$(printf "%s\n=== %s ===\n%s\n" "$MODSEC_LOG_FINDINGS" "$f" "$hits")
        MODSEC_MATCHED_LINES=$(printf "%s\n%s\n" "$MODSEC_MATCHED_LINES" "$(printf "%s\n" "$hits" | sed -E 's/^[0-9]+://')")
        
        # Extract and collect suspicious IPs from matched lines
        while IFS= read -r ln; do
          [ -z "$ln" ] && continue
          collect_modsec_ip "$(printf "%s" "$ln" | sed -E 's/^[0-9]+://')"
        done < <(printf "%s\n" "$hits")
      fi
    fi
  }

  scan_gz_modsec_log() {
    local f="$1"
    [ -f "$f" ] || return 0
    command -v gzip >/dev/null 2>&1 || return 0
    local hits
    hits=$(gzip -cd -- "$f" 2>/dev/null | grep -n -E -i "$MODSEC_PAT" | head -80)
    if [ -n "$hits" ]; then
      MODSEC_LOG_FILES=$(printf "%s\n%s\n" "$MODSEC_LOG_FILES" "$f")
      MODSEC_LOG_FINDINGS=$(printf "%s\n=== %s ===\n%s\n" "$MODSEC_LOG_FINDINGS" "$f" "$hits")
      MODSEC_MATCHED_LINES=$(printf "%s\n%s\n" "$MODSEC_MATCHED_LINES" "$(printf "%s\n" "$hits" | sed -E 's/^[0-9]+://')")
      
      # Extract and collect suspicious IPs from matched lines
      while IFS= read -r ln; do
        [ -z "$ln" ] && continue
        collect_modsec_ip "$(printf "%s" "$ln" | sed -E 's/^[0-9]+://')"
      done < <(printf "%s\n" "$hits")
    fi
  }

  # Candidate locations (kept conservative to avoid huge scans)
  for d in /var/log/apache2 /var/log/httpd /var/log/nginx /var/log/modsecurity /usr/local/apache/logs /var/log; do
    [ -d "$d" ] || continue
    while IFS= read -r lf; do
      [ -z "$lf" ] && continue
      case "$lf" in
        *.gz) scan_gz_modsec_log "$lf" ;;
        *) scan_plain_modsec_log "$lf" ;;
      esac
    done < <(
      find "$d" -maxdepth 2 -type f \
        \( -iname "*modsec*" -o -iname "*modsecurity*" -o -iname "modsec_audit.log*" -o -iname "modsecurity_audit.log*" \) \
        2>/dev/null | head -200
    )
  done

  MODSEC_LOG_FILES=$(printf "%s\n" "$MODSEC_LOG_FILES" | sed '/^\s*$/d' | sort -u)

  if [ -n "$MODSEC_LOG_FINDINGS" ]; then
    echo "!!! WARNING: ModSecurity log entries found (showing first hits per file):"
    echo "$MODSEC_LOG_FINDINGS" | head -200

    echo " -> ModSecurity quick summary:"
    echo "    Flagged log files: $(printf "%s\n" "$MODSEC_LOG_FILES" | sed '/^\s*$/d' | wc -l | awk '{print $1}')"

    # Top rule IDs (best-effort)
    if [ -n "$MODSEC_MATCHED_LINES" ]; then
      echo "    Top rule IDs (if present):"
      printf "%s\n" "$MODSEC_MATCHED_LINES" \
        | sed -n -E 's/.*\[id "([0-9]+)"\].*/\1/p' \
        | sed '/^\s*$/d' \
        | sort | uniq -c | sort -nr | head -10 \
        | sed 's/^/      /'
    fi

    ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$MODSEC_LOG_FILES")
  else
    echo "OK: No ModSecurity log entries found in common log locations."
  fi
fi


# --- 3. Search for Malicious Code Patterns ---
if [ "$DO_BACKDOOR" -eq 1 ] || [ "$DO_OBFUSCATED" -eq 1 ] || [ "$DO_PHPSHELL" -eq 1 ] || [ "$DO_DYN_EXEC" -eq 1 ] || [ "$DO_ONELINER" -eq 1 ]; then
  echo -e "\n[+] Searching for malicious code patterns in PHP files..."
fi

# Search for common backdoor functions
if [ "$DO_BACKDOOR" -eq 1 ]; then
  echo " -> Searching for high-risk backdoor functions..."
  # Match actual function calls like eval( ... ). Word boundaries reduce noise.
  BACKDOOR_PATTERN="\\b(eval|base64_decode|shell_exec|passthru|system|exec|popen|proc_open|assert)\\b\\s*\\("
  BACKDOOR_MATCH=$(grep -R -l -i --include="*.php" -E "$BACKDOOR_PATTERN" "$SITE_PATH" 2>/dev/null)
  if [ -n "$BACKDOOR_MATCH" ]; then
    echo "!!! WARNING: Found high-risk functions. Review these files:"
    # FIX: Use command substitution to properly capture the filtered list
    FILTERED_BACKDOOR=$(printf "%s\n" "$BACKDOOR_MATCH" | grep -v -E "wp-includes/|wp-admin/|wp-content/plugins/|wp-content/themes/" | head -10)
    echo "$FILTERED_BACKDOOR"
    ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$FILTERED_BACKDOOR")
    if [ "$SHOW_CONTEXT" -eq 1 ]; then
      echo " -> Showing matched lines with line numbers (first 3 matches per file):"
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
  echo " -> Searching for obfuscated code (base64, gzinflate, str_rot13, etc.)..."
  OBFUSCATED_PATTERN="\\b(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|str_replace|rawurldecode|urldecode|pack\\s*\\(\\s*['\"]H\\*['\"]|openssl_decrypt|preg_replace.*\\/e|assert|create_function)\\b"
  OBFUSCATED_MATCH=$(grep -R -l -i --include="*.php" -E "$OBFUSCATED_PATTERN" "$SITE_PATH" 2>/dev/null)
  if [ -n "$OBFUSCATED_MATCH" ]; then
    echo "!!! WARNING: Found potentially obfuscated code. Review these files:"
    # FIX: Use command substitution to properly capture the filtered list
    FILTERED_OBFUSCATED=$(printf "%s\n" "$OBFUSCATED_MATCH" | grep -v -E "wp-includes/|wp-admin/" | head -10)
    echo "$FILTERED_OBFUSCATED"
    ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$FILTERED_OBFUSCATED")
    if [ "$SHOW_CONTEXT" -eq 1 ]; then
      echo " -> Showing matched lines with line numbers (first 3 matches per file):"
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
  echo " -> Searching for PHP shell signatures (C99, R57, WSO, B374K, FilesMan, etc.)..."
  # Classic signatures + common shell UI/feature strings.
  PHPSHELL_SIG_PATTERN="C99Shell|\\bc99\\b|R57|\\br57\\b|WSO|B374K|FilesMan|IndoXploit|WebShell|FilesManager|File\\s*manager|Upload\\s*file|Download\\s*file|Symlink|php_uname|posix_geteuid|posix_getpwuid|\\bwhoami\\b|\\buname\\b|\\bid\\b|\\bpriv8\\b|cmd\\s*="
  PHPSHELL_MATCH=$(grep -R -l -I --include="*.php" -E "$PHPSHELL_SIG_PATTERN" "$SITE_PATH" 2>/dev/null)
  # Also check common shell filenames
  PHPSHELL_NAMES=$(find "$SITE_PATH" -type f $$ -iname "*wso*.php" -o -iname "*c99*.php" -o -iname "*r57*.php" -o -iname "*b374k*.php" -o -iname "*filesman*.php" -o -iname "webshell.php" -o -iname "shell.php" -o -iname "*enmnnu*.php" $$ 2>/dev/null)
  if [ -n "$PHPSHELL_MATCH" ] || [ -n "$PHPSHELL_NAMES" ]; then
    echo "!!! WARNING: Potential PHP shell indicators found. Review these files:"
    # FIX: Use command substitution to properly capture the filtered list
    PHPSHELL_UNIQUE=$( { printf "%s\n" "$PHPSHELL_MATCH"; printf "%s\n" "$PHPSHELL_NAMES"; } | grep -v -E "wp-includes/|wp-admin/" | sort -u )
    echo "$PHPSHELL_UNIQUE" | head -20
    ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$PHPSHELL_UNIQUE")
    if [ "$SHOW_CONTEXT" -eq 1 ]; then
      echo " -> Showing matched lines with line numbers (first 3 matches per file):"
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

  # ---- Additional PHP shell heuristics (higher confidence, lower false positives) ----

  echo " -> Searching for decode→exec chains (decoder + exec primitive in same file)..."
  DECODER_PATTERN="\\b(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|urldecode|pack\\s*\\(\\s*['\"]H\\*['\"]|openssl_decrypt)\\b"
  EXEC_PATTERN="\\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|preg_replace)\\b"
  DECODE_HITS=$(grep -R -l -I --include="*.php" -E "$DECODER_PATTERN" "$SITE_PATH" 2>/dev/null)
  if [ -n "$DECODE_HITS" ]; then
    DECODE_EXEC_FILES=$(printf "%s\n" "$DECODE_HITS" | while IFS= read -r f; do
      [ -z "$f" ] && continue
      if grep -q -I -E "$EXEC_PATTERN" "$f" 2>/dev/null; then
        echo "$f"
      fi
    done | sort -u)
  else
    DECODE_EXEC_FILES=""
  fi
  if [ -n "$DECODE_EXEC_FILES" ]; then
    echo "!!! WARNING: Found decoder + exec primitive in the same file (common webshell pattern):"
    FILTERED_DECODE_EXEC=$(printf "%s\n" "$DECODE_EXEC_FILES" | grep -v -E "wp-includes/|wp-admin/" | head -20)
    echo "$FILTERED_DECODE_EXEC"
    ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$FILTERED_DECODE_EXEC")
    if [ "$SHOW_CONTEXT" -eq 1 ]; then
      echo " -> Showing matched lines (decoder/exec), first 3 per file:"
      printf "%s\n" "$FILTERED_DECODE_EXEC" | while IFS= read -r f; do
        [ -z "$f" ] && continue
        echo "----- $f -----"
        grep -n -I -E "($DECODER_PATTERN|$EXEC_PATTERN)" -m 3 "$f" 2>/dev/null || echo "(no signature lines found)"
      done
    fi
  else
    echo "OK: No decoder+exec chain hits."
  fi

  echo " -> Searching for dangerous wrappers (php://input, data://, phar://, expect://)..."
  WRAPPER_PATTERN="php:\\/\\/input|data:\\/\\/text|phar:\\/\\/|expect:\\/\\/"
  WRAPPER_MATCH=$(grep -R -l -I --include="*.php" -E "$WRAPPER_PATTERN" "$SITE_PATH" 2>/dev/null)
  if [ -n "$WRAPPER_MATCH" ]; then
    echo "!!! WARNING: Found suspicious stream wrapper usage (often used by loaders/stagers):"
    FILTERED_WRAPPER=$(printf "%s\n" "$WRAPPER_MATCH" | grep -v -E "wp-includes/|wp-admin/" | head -20)
    echo "$FILTERED_WRAPPER"
    ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$FILTERED_WRAPPER")
    if [ "$SHOW_CONTEXT" -eq 1 ]; then
      echo " -> Showing matched lines with line numbers (first 3 matches per file):"
      printf "%s\n" "$FILTERED_WRAPPER" | while IFS= read -r f; do
        [ -z "$f" ] && continue
        echo "----- $f -----"
        grep -n -I -E "$WRAPPER_PATTERN" -m 3 "$f" 2>/dev/null || echo "(no signature lines found)"
      done
    fi
  else
    echo "OK: No suspicious wrapper usage found."
  fi

  echo " -> Searching for stealth toggles (error_reporting(0), set_time_limit(0), @eval, etc.)..."
  STEALTH_PATTERN="error_reporting\\s*\\(\\s*0\\s*\\)|set_time_limit\\s*\\(\\s*0\\s*\\)|ini_set\\s*\\(\\s*['\"]display_errors['\"]\\s*,\\s*0\\s*\\)|@\\s*(eval|assert|system|exec|shell_exec|passthru)\\b"
  STEALTH_MATCH=$(grep -R -l -I --include="*.php" -E "$STEALTH_PATTERN" "$SITE_PATH" 2>/dev/null)
  if [ -n "$STEALTH_MATCH" ]; then
    echo "!!! WARNING: Found stealth/anti-debug toggles (often used by shells):"
    FILTERED_STEALTH=$(printf "%s\n" "$STEALTH_MATCH" | grep -v -E "wp-includes/|wp-admin/" | head -20)
    echo "$FILTERED_STEALTH"
    ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$FILTERED_STEALTH")
    if [ "$SHOW_CONTEXT" -eq 1 ]; then
      echo " -> Showing matched lines with line numbers (first 3 matches per file):"
      printf "%s\n" "$FILTERED_STEALTH" | while IFS= read -r f; do
        [ -z "$f" ] && continue
        echo "----- $f -----"
        grep -n -I -E "$STEALTH_PATTERN" -m 3 "$f" 2>/dev/null || echo "(no signature lines found)"
      done
    fi
  else
    echo "OK: No stealth toggle patterns found."
  fi

  echo " -> Searching for variable-function calls (\$f(...)) combined with superglobals..."
  VARFUNC_PATTERN="\\$[A-Za-z_][A-Za-z0-9_]*\\s*\\("
  SUPERGLOBAL_ANY="\\$_(GET|POST|REQUEST|COOKIE)"
  VARFUNC_HITS=$(grep -R -l -I --include="*.php" -E "$VARFUNC_PATTERN" "$SITE_PATH" 2>/dev/null)
  if [ -n "$VARFUNC_HITS" ]; then
    VARFUNC_SUSP=$(printf "%s\n" "$VARFUNC_HITS" | while IFS= read -r f; do
      [ -z "$f" ] && continue
      if grep -q -I -E "$SUPERGLOBAL_ANY" "$f" 2>/dev/null; then
        echo "$f"
      fi
    done | sort -u)
  else
    VARFUNC_SUSP=""
  fi
  if [ -n "$VARFUNC_SUSP" ]; then
    echo "!!! WARNING: Found variable function calls in files that also reference superglobals (common backdoor technique):"
    FILTERED_VARFUNC=$(printf "%s\n" "$VARFUNC_SUSP" | grep -v -E "wp-includes/|wp-admin/" | head -20)
    echo "$FILTERED_VARFUNC"
    ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$FILTERED_VARFUNC")
    if [ "$SHOW_CONTEXT" -eq 1 ]; then
      echo " -> Showing matched lines with line numbers (first 3 matches per file):"
      printf "%s\n" "$FILTERED_VARFUNC" | while IFS= read -r f; do
        [ -z "$f" ] && continue
        echo "----- $f -----"
        grep -n -I -E "($VARFUNC_PATTERN|$SUPERGLOBAL_ANY)" -m 3 "$f" 2>/dev/null || echo "(no signature lines found)"
      done
    fi
  else
    echo "OK: No variable-function + superglobal combo hits."
  fi

  echo " -> Searching for high-entropy blobs in tiny PHP files..."
  ENTROPY_PATTERN="[A-Za-z0-9+/]{200,}={0,2}"
  ENTROPY_FILES=$(find "$SITE_PATH" -type f -name "*.php" -exec sh -c '
    f="$1"
    pat="$2"
    if ! grep -Iq . "$f" 2>/dev/null; then
      exit 0
    fi
    lc=$(wc -l < "$f" 2>/dev/null)
    if [ -n "$lc" ] && [ "$lc" -lt 20 ] && grep -q -E "$pat" "$f" 2>/dev/null; then
      echo "$f"
    fi
  ' sh {} "$ENTROPY_PATTERN" \; 2>/dev/null)
  if [ -n "$ENTROPY_FILES" ]; then
    echo "!!! WARNING: Found small PHP files containing large base64-ish blobs (common loader/stager pattern):"
    FILTERED_ENTROPY=$(printf "%s\n" "$ENTROPY_FILES" | grep -v -E "wp-includes/|wp-admin/" | head -20)
    echo "$FILTERED_ENTROPY"
    ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$FILTERED_ENTROPY")
    if [ "$SHOW_CONTEXT" -eq 1 ]; then
      echo " -> Showing matched lines with line numbers (first 3 matches per file):"
      printf "%s\n" "$FILTERED_ENTROPY" | while IFS= read -r f; do
        [ -z "$f" ] && continue
        echo "----- $f -----"
        grep -n -I -E "$ENTROPY_PATTERN" -m 3 "$f" 2>/dev/null || echo "(no signature lines found)"
      done
    fi
  else
    echo "OK: No high-entropy blob hits in small PHP files."
  fi
fi

# New: Dynamic Variable Execution Scan
if [ "$DO_DYN_EXEC" -eq 1 ]; then
  echo " -> Searching for dynamic function execution patterns..."
  DYN_EXEC_PATTERN="(\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*).*['\"](eval|system|shell_exec|passthru|exec|assert|create_function)['\"]"
  DYN_EXEC_MATCH=$(grep -R -l -I --include="*.php" -E "$DYN_EXEC_PATTERN" "$SITE_PATH" 2>/dev/null)
  if [ -n "$DYN_EXEC_MATCH" ]; then
    echo "!!! WARNING: Found patterns suggesting dynamic function execution. Review these files:"
    # FIX: Use command substitution to properly capture the filtered list
    FILTERED_DYN_EXEC=$(printf "%s\n" "$DYN_EXEC_MATCH" | grep -v -E "wp-includes/|wp-admin/" | head -10)
    echo "$FILTERED_DYN_EXEC"
    ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$FILTERED_DYN_EXEC")
    if [ "$SHOW_CONTEXT" -eq 1 ]; then
      echo " -> Showing matched lines with line numbers (first 3 matches per file):"
      printf "%s\n" "$FILTERED_DYN_EXEC" | while IFS= read -r f; do
        [ -z "$f" ] && continue
        echo "----- $f -----"
        grep -n -I -E "$DYN_EXEC_PATTERN" -m 3 "$f" 2>/dev/null || echo "(no signature lines found)"
      done
    fi
  else
    echo "OK: No obvious dynamic execution patterns found."
  fi
fi

# New: One-Liner Shell Scan
if [ "$DO_ONELINER" -eq 1 ]; then
  echo " -> Searching for potential one-liner shells (short PHP files with dangerous functions)..."
  ONELINER_FILES=$(find "$SITE_PATH" -type f -name "*.php" -exec sh -c '
    line_count=$(wc -l < "$1")
    if [ "$line_count" -lt 5 ] && grep -q -i -E "(eval|system|shell_exec|passthru|exec)" "$1"; then
      echo "$1"
    fi
  ' sh {} \; 2>/dev/null)
  if [ -n "$ONELINER_FILES" ]; then
    echo "!!! WARNING: Found very small PHP files with dangerous functions (potential one-liner shells):"
    # FIX: Use command substitution to properly capture the filtered list
    FILTERED_ONELINER=$(printf "%s\n" "$ONELINER_FILES" | grep -v -E "wp-includes/|wp-admin/" | head -10)
    if [ -n "$FILTERED_ONELINER" ]; then
        echo "$FILTERED_ONELINER"
    else
        echo " (Found files were in standard directories, but still worth checking)"
    fi
    ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$ONELINER_FILES")
  else
    echo "OK: No suspicious one-liner PHP files found."
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
  SUPER_PATTERN="(\$_(GET|POST|REQUEST|COOKIE)).*(\\b(eval|system|shell_exec|passthru|popen|proc_open|assert|create_function)\\b\\s*\\(|preg_replace.*\\/e)"
  SUPER_MATCH=$(grep -R -l -I --include="*.php" -E "$SUPER_PATTERN" "$SITE_PATH" 2>/dev/null)
  if [ -n "$SUPER_MATCH" ]; then
    echo "!!! WARNING: Superglobal-driven exec/eval patterns found:"
    # FIX: Use command substitution to properly capture the filtered list
    FILTERED_SUPER=$(printf "%s\n" "$SUPER_MATCH" | grep -v -E "wp-includes/|wp-admin/" | head -20)
    echo "$FILTERED_SUPER"
    ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$FILTERED_SUPER")
    if [ "$SHOW_CONTEXT" -eq 1 ]; then
      echo " -> Showing matched lines with line numbers (first 3 matches per file):"
      printf "%s\n" "$FILTERED_SUPER" | while IFS= read -r f; do
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
  echo " -> Searching for cURL calls to external domains..."
  CURL_MATCH=$(grep -R -l --include="*.php" -e "curl_init" "$SITE_PATH" 2>/dev/null)
  if [ -n "$CURL_MATCH" ]; then
    echo "!!! WARNING: Found cURL calls. These are common in backdoors. Review these files:"
    # FIX: Use command substitution to properly capture the filtered list
    FILTERED_CURL=$(printf "%s\n" "$CURL_MATCH" | grep -v -E "wp-includes/|wp-content/themes/|wp-content/plugins/" | head -10)
    echo "$FILTERED_CURL"
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
    echo " -> Detected WordPress version: $WP_VERSION"
    echo " -> Manual check required: Please compare this version against the WordPress.org security advisories to see if it's outdated."
  else
    echo "Could not determine WordPress version."
  fi
fi


# --- 5. Check File Permissions ---
if [ "$DO_PERMS" -eq 1 ]; then
  echo -e "\n[+] Checking for insecure file permissions..."
  echo " -> Checking for world-writable files..."
  WRITABLE_FILES=$(find "$SITE_PATH" -type f -perm /002 -not -path "*/wp-content/cache/*" -not -path "*/wp-content/uploads/*" 2>/dev/null | head -5)
  if [ -n "$WRITABLE_FILES" ]; then
    echo "!!! WARNING: Found world-writable files (showing first 5):"
    echo "$WRITABLE_FILES"
    ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$WRITABLE_FILES")
  else
    echo "OK: No obvious world-writable files found outside uploads/cache."
  fi
fi

# --- 6. Check for Immutable Files ---
if [ "$DO_IMMUTABLE" -eq 1 ]; then
  echo -e "\n[+] Checking for immutable files (+i attribute)..."
  # Check if lsattr command is available
  if ! command -v lsattr >/dev/null 2>&1; then
    echo "INFO: 'lsattr' command not found. Skipping immutable file check (requires e2fsprogs)."
  else
    # Use find to execute lsattr on all files and grep to filter for the immutable flag.
    # We only care about regular files, not directories.
    IMMUTABLE_FILES=$(find "$SITE_PATH" -type f -exec lsattr -d {} \; 2>/dev/null | grep '^^.i' | awk '{print $2}')
    if [ -n "$IMMUTABLE_FILES" ]; then
      echo "!!! WARNING: Found immutable files. This is highly suspicious and may indicate a rootkit or backdoor."
      echo "$IMMUTABLE_FILES"
      ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$IMMUTABLE_FILES")
    else
      echo "OK: No immutable files found."
    fi
  fi
fi


# --- 6.5. Check Image Headers for Malicious Code ---
if [ "$DO_IMAGE_HEADERS" -eq 1 ]; then
  echo -e "\n[+] Scanning image headers for malicious code..."
  
  IMAGE_EXTS="jpg|jpeg|png|gif|webp|ico|svg|bmp"
  HACKED_IMAGES=""
  SUSPECT_COUNT=0
  
  # Patterns that indicate malicious code in image headers
  PHP_PATTERN="<\?php|<\?=|<script[^>]*php"
  EVAL_PATTERN="eval\(|base64_decode\(|gzinflate\(|assert\(|system\(|exec\(|shell_exec\(|passthru\("
  STEALTH_PATTERN="@eval|error_reporting\(0\)|ini_set.*display_errors"
  
  echo " -> Scanning for PHP code in image file headers (first 1KB)..."
  
  # Find all image files
  while IFS= read -r img; do
    [ -z "$img" ] && continue
    [ ! -f "$img" ] && continue
    
    # Read first 1024 bytes of the file, stripping NUL bytes to avoid command-substitution warnings
    header=$(head -c 1024 "$img" 2>/dev/null | tr -d '\000')
    [ -z "$header" ] && continue
    
    # Check for PHP tags in header
    if echo "$header" | grep -q -E "$PHP_PATTERN" 2>/dev/null; then
      echo "!!! WARNING: PHP code found in image header: $img"
      HACKED_IMAGES=$(printf "%s\n%s\n" "$HACKED_IMAGES" "$img")
      SUSPECT_COUNT=$((SUSPECT_COUNT + 1))
      
      if [ "$SHOW_CONTEXT" -eq 1 ]; then
        echo " -> First 200 chars of suspicious content:"
        echo "$header" | head -c 200 | od -c | head -10
      fi
      continue
    fi
    
    # Check for eval/exec patterns in header
    if echo "$header" | grep -q -E "$EVAL_PATTERN" 2>/dev/null; then
      echo "!!! WARNING: Suspicious eval/exec pattern in image header: $img"
      HACKED_IMAGES=$(printf "%s\n%s\n" "$HACKED_IMAGES" "$img")
      SUSPECT_COUNT=$((SUSPECT_COUNT + 1))
      
      if [ "$SHOW_CONTEXT" -eq 1 ]; then
        echo " -> Matched pattern:"
        echo "$header" | grep -o -E ".{0,50}($EVAL_PATTERN).{0,50}" | head -3
      fi
      continue
    fi
    
    # Check for stealth/obfuscation patterns
    if echo "$header" | grep -q -E "$STEALTH_PATTERN" 2>/dev/null; then
      echo "!!! WARNING: Stealth/obfuscation pattern in image header: $img"
      HACKED_IMAGES=$(printf "%s\n%s\n" "$HACKED_IMAGES" "$img")
      SUSPECT_COUNT=$((SUSPECT_COUNT + 1))
      continue
    fi
    
  done < <(find "$SITE_PATH" -type f -regextype posix-extended -iregex ".*\.($IMAGE_EXTS)$" 2>/dev/null | head -10000)
  
  if [ "$SUSPECT_COUNT" -gt 0 ]; then
    echo "!!! WARNING: Found $SUSPECT_COUNT image(s) with suspicious headers"
    HACKED_IMAGES=$(printf "%s\n" "$HACKED_IMAGES" | sed '/^\s*$/d' | sort -u)
    ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$HACKED_IMAGES")
    
    echo " -> Quick analysis tips:"
    echo "    - Use 'head -c 2048 <file> | strings' to view header content"
    echo "    - Use 'exiftool <file>' to check metadata"
    echo "    - Use 'file <file>' to verify actual file type"
    echo "    - Check file size - hacked images are often larger than normal"
  else
    echo "OK: No suspicious code found in image headers (scanned up to 10000 images)"
  fi
  
  # Store results for summary
  IMAGE_HEADER_FINDINGS="$HACKED_IMAGES"
  IMAGE_HEADER_COUNT="$SUSPECT_COUNT"
fi


# --- 7. WP-CLI Deep Checks ---
if [ "$DO_WP_CLI" -eq 1 ]; then
  # Determine how to invoke WP-CLI. Prefer env override, then `wp` on PATH.
  WP_CLI_BIN="${WP_CLI_BIN:-${WP_CLI:-}}"
  WP_CLI=()
  if [ -n "$WP_CLI_BIN" ]; then
    WP_CLI=("$WP_CLI_BIN")
  elif command -v wp >/dev/null 2>&1; then
    WP_CLI=(wp)
  elif command -v wp-cli >/dev/null 2>&1; then
    WP_CLI=(wp-cli)
  elif [ -f "$SITE_PATH/wp-cli.phar" ] && command -v php >/dev/null 2>&1; then
    WP_CLI=(php "$SITE_PATH/wp-cli.phar")
  fi

  if [ "${#WP_CLI[@]}" -eq 0 ]; then
    echo -e "\n[+] WP-CLI checks skipped: 'wp' command not found."
  else
    echo -e "\n[+] Running WP-CLI deep checks..."
    cd "$SITE_PATH" || { echo "Error: Could not change directory to $SITE_PATH"; exit 1; }

    WP_CLI_ARGS=()
    if command -v id >/dev/null 2>&1 && [ "$(id -u 2>/dev/null)" = "0" ]; then
      WP_CLI_ARGS+=(--allow-root)
    fi

    # Check if WP-CLI can talk to this WP install
    if ! "${WP_CLI[@]}" "${WP_CLI_ARGS[@]}" core is-installed --quiet 2>/dev/null; then
      echo "!!! WARNING: WP-CLI found but not functional for this installation. Skipping WP-CLI checks."
    else
      # 7.1 Core Integrity Check (optional via --verify-core)
      if [ "$DO_VERIFY_CORE" -eq 1 ]; then
        echo " -> Verifying core file integrity..."
        CORE_STATUS=$("${WP_CLI[@]}" "${WP_CLI_ARGS[@]}" core verify-checksums --format=json 2>/dev/null)
        CORE_RC=$?
        if [ $CORE_RC -ne 0 ]; then
          echo "!!! WARNING: WordPress core files have been modified or checksums are missing."
          echo "$CORE_STATUS" | jq -r '.[] | "File: \(.file), Status: \(.status)"' 2>/dev/null || echo "$CORE_STATUS"
          # Add changed files to zip candidates (prepend site path)
          if command -v jq >/dev/null 2>&1; then
            BADFILES=$(printf "%s\n" "$CORE_STATUS" | jq -r '.[] | select(.status != "verified") | .file' 2>/dev/null)
            if [ -n "$BADFILES" ]; then
              while IFS= read -r bf; do
                [ -z "$bf" ] && continue
                ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$SITE_PATH/$bf")
              done <<< "$BADFILES"
            fi
          fi
        else
          echo "OK: Core file integrity verified."
        fi
      fi

      # 7.2 Plugin/Theme Status and Vulnerabilities
      echo " -> Checking plugin and theme status..."
      PLUGIN_STATUS=$("${WP_CLI[@]}" "${WP_CLI_ARGS[@]}" plugin list --status=inactive --format=json 2>/dev/null)
      if [ -n "$PLUGIN_STATUS" ] && [ "$PLUGIN_STATUS" != "[]" ]; then
        echo "!!! WARNING: Inactive plugins found (can be a security risk):"
        echo "$PLUGIN_STATUS" | jq -r '.[] | " - \(.name) (v\(.version))"' 2>/dev/null || echo "$PLUGIN_STATUS"
      fi
      THEME_STATUS=$("${WP_CLI[@]}" "${WP_CLI_ARGS[@]}" theme list --status=inactive --format=json 2>/dev/null)
      if [ -n "$THEME_STATUS" ] && [ "$THEME_STATUS" != "[]" ]; then
        echo "!!! WARNING: Inactive themes found (should be removed):"
        echo "$THEME_STATUS" | jq -r '.[] | " - \(.name) (v\(.version))"' 2>/dev/null || echo "$THEME_STATUS"
      fi
      if "${WP_CLI[@]}" "${WP_CLI_ARGS[@]}" cli has-command "plugin vulnerability" 2>/dev/null; then
        echo " -> Checking for plugin vulnerabilities..."
        VULN_REPORT=$("${WP_CLI[@]}" "${WP_CLI_ARGS[@]}" plugin vulnerability list --format=json 2>/dev/null)
        VULN_COUNT=$(echo "$VULN_REPORT" | jq length 2>/dev/null || echo 0)
        if [ "$VULN_COUNT" -gt 0 ]; then
          echo "!!! WARNING: Found $VULN_COUNT plugin vulnerabilities:"
          echo "$VULN_REPORT" | jq -r '.[] | " - \(.title) in \(.plugin) (\(.fixed_in // \"no fix\"))"' 2>/dev/null || echo "$VULN_REPORT"
        fi
      fi

      # 7.3 User Security Check
      # Verify plugin checksums for all installed plugins via WP-CLI
      echo " -> Verifying plugin checksums via WP-CLI..."
      PLUGIN_LIST=$("${WP_CLI[@]}" "${WP_CLI_ARGS[@]}" plugin list --format=csv --fields=name 2>/dev/null | sed -n '2,$p')
      if [ -n "$PLUGIN_LIST" ]; then
        printf "%s\n" "$PLUGIN_LIST" | while IFS= read -r p; do
          [ -z "$p" ] && continue
          if ! "${WP_CLI[@]}" "${WP_CLI_ARGS[@]}" plugin verify-checksums "$p" --allow-root >/dev/null 2>&1; then
            echo "!!! WARNING: Plugin '$p' failed checksum verification (modified or missing)."
            ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$SITE_PATH/wp-content/plugins/$p")
          fi
        done
      fi
      echo " -> Checking user security..."
      ADMIN_USERS=$("${WP_CLI[@]}" "${WP_CLI_ARGS[@]}" user list --role=administrator --format=json 2>/dev/null)
      if [ -n "$ADMIN_USERS" ] && [ "$ADMIN_USERS" != "[]" ]; then
        echo "INFO: Administrator users found:"
        echo "$ADMIN_USERS" | jq -r '.[] | " - \(.user_login) (\(.user_email))"' 2>/dev/null || echo "$ADMIN_USERS"
      fi
      NO_ROLE_USERS=$("${WP_CLI[@]}" "${WP_CLI_ARGS[@]}" user list --role= --format=json 2>/dev/null)
      if [ -n "$NO_ROLE_USERS" ] && [ "$NO_ROLE_USERS" != "[]" ]; then
        echo "!!! WARNING: Users with no assigned role found:"
        echo "$NO_ROLE_USERS" | jq -r '.[] | " - \(.user_login) (\(.user_email))"' 2>/dev/null || echo "$NO_ROLE_USERS"
      fi

      # 7.4 Database Status
      echo " -> Checking database status..."
      DB_SIZE=$("${WP_CLI[@]}" "${WP_CLI_ARGS[@]}" db size --format=json 2>/dev/null)
      if [ -n "$DB_SIZE" ]; then
        echo "INFO: Database size: $(echo "$DB_SIZE" | jq -r '.size_human' 2>/dev/null || echo "$DB_SIZE")"
      fi

      # 7.5 Suspicious Options
      echo " -> Checking for suspicious options..."
      UPLOAD_PATH=$("${WP_CLI[@]}" "${WP_CLI_ARGS[@]}" option get upload_path --format=plaintext 2>/dev/null)
      if [ -n "$UPLOAD_PATH" ] && [ "$UPLOAD_PATH" != "wp-content/uploads" ]; then
        echo "!!! WARNING: Custom upload_path detected: $UPLOAD_PATH"
      fi

      # Optional: restore core files via WP-CLI when requested
      if [ "$DO_RESTORE_CORE" -eq 1 ]; then
        echo " -> Restoring WordPress core files via WP-CLI (this will overwrite core files)..."
        if "${WP_CLI[@]}" "${WP_CLI_ARGS[@]}" core download --force 2>/dev/null; then
          echo " -> Core files restored (wp core download --force succeeded)."
        else
          echo "!!! WARNING: Failed to restore core files via WP-CLI."
        fi
      fi
    fi
  fi
fi
# --- Plugin scan: scan wp-content/plugins for suspicious/fake plugins ---
if [ "$DO_PLUGIN_SCAN" -eq 1 ]; then
  echo -e "\n[+] Scanning wp-content/plugins for suspicious or fake plugins..."
  PLUG_DIR="$SITE_PATH/wp-content/plugins"
  if [ -d "$PLUG_DIR" ]; then
    PLUGIN_PAT="(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|eval\\(|assert\\(|shell_exec|passthru|system|exec|popen|proc_open|preg_replace.*\\/e|php_uname|posix_geteuid)"
    PLUGIN_HITS=$(grep -R -l -I --include="*.php" -E "$PLUGIN_PAT" "$PLUG_DIR" 2>/dev/null)
    if [ -n "$PLUGIN_HITS" ]; then
      echo "!!! WARNING: Suspicious code found inside plugin files (showing first hits):"
      echo "$PLUGIN_HITS" | head -50
      ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$PLUGIN_HITS")
    fi

    SUSPECT_PLUGINS=$(find "$PLUG_DIR" -mindepth 1 -maxdepth 2 -type d 2>/dev/null | while IFS= read -r d; do
      if ! grep -R -I -m1 -E "^[[:space:]]*Plugin Name:" "$d"/* 2>/dev/null >/dev/null; then
        echo "$d"
      fi
    done)
    if [ -n "$SUSPECT_PLUGINS" ]; then
      echo "!!! WARNING: Plugin directories without a plugin header (possible fake plugins):"
      echo "$SUSPECT_PLUGINS" | head -50
      ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$SUSPECT_PLUGINS")
    fi

    RECENT_PLUGIN_MODS=$(find "$PLUG_DIR" -type f -name "*.php" -mmin -120 2>/dev/null)
    if [ -n "$RECENT_PLUGIN_MODS" ]; then
      echo " -> Recent plugin file modifications (last 120 minutes):"
      echo "$RECENT_PLUGIN_MODS" | head -50
      ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$RECENT_PLUGIN_MODS")
    fi
  else
    echo " -> No plugins directory found at $PLUG_DIR"
  fi

  # New: Verify plugin checksums via WP-CLI (if available and functional)
  if command -v wp >/dev/null 2>&1; then
    if (cd "$SITE_PATH" && wp core is-installed --quiet 2>/dev/null); then
      echo " -> Verifying installed plugins checksums via WP-CLI..."
      PLUGIN_NAMES=$(cd "$SITE_PATH" && wp plugin list --format=csv --fields=name 2>/dev/null | sed -n '2,$p')
      if [ -n "$PLUGIN_NAMES" ]; then
        printf "%s\n" "$PLUGIN_NAMES" | while IFS= read -r p; do
          [ -z "$p" ] && continue
          # Run checksum verification for each plugin; non-zero indicates modified or missing files.
          if ! (cd "$SITE_PATH" && wp plugin verify-checksums "$p" --allow-root >/dev/null 2>&1); then
            echo "!!! WARNING: Plugin '$p' failed checksum verification (modified or missing)."
            ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$SITE_PATH/wp-content/plugins/$p")
          fi
        done
      fi
    else
      echo " -> WP-CLI present but not functional for this install; skipping plugin checksum verification."
    fi
  else
    echo " -> WP-CLI not found; skipping plugin checksum verification."
  fi
fi

# --- 6.7. Check for SEO Spam "Link Factory" Files ---
if [ "$DO_SEO_SPAM" -eq 1 ]; then
  echo -e "\n[+] Scanning for SEO Spam 'Link Factory' files..."
  # Specifically targeting the .l10n.php pattern found on dedicated218
  SEO_SPAM_FILES=$(find "$SITE_PATH/wp-content/languages" -name "*de_DE.l10n.php" -mtime -60 2>/dev/null)
  if [ -n "$SEO_SPAM_FILES" ]; then
    echo "!!! WARNING: Confirmed SEO Spam Factory files found (German Language Hijack):"
    echo "$SEO_SPAM_FILES"
    ZIP_CANDIDATES=$(printf "%s\n%s" "$ZIP_CANDIDATES" "$SEO_SPAM_FILES")

    # Cleanup instructions printed for the operator. These are manual steps to safely remove
    # malicious language files and restore legitimate translations using WP-CLI.
    echo ""
    echo "Cleanup guidance:"
    echo " 1) Carefully review the listed files. If they are malicious, remove them, e.g.:"
    echo "      sudo rm -f \"$SITE_PATH/wp-content/languages/<malicious-file>.php\""
    echo " 2) Update or reinstall official translations via WP-CLI (recommended where available):"
    echo "      cd \"$SITE_PATH\" && wp language core update --all --allow-root || true"
    echo "      cd \"$SITE_PATH\" && wp language plugin update --all --allow-root || true"
    echo "      cd \"$SITE_PATH\" && wp language theme update --all --allow-root || true"
    echo " 3) To force reinstall a specific locale (example: de_DE) from wordpress.org:"
    echo "      cd \"$SITE_PATH\" && wp language core install --force de_DE --allow-root || true"
    echo " 4) Clear caches and search for injected links to verify cleanup (examples):"
    echo "      cd \"$SITE_PATH\" && wp cache flush --allow-root || true"
    echo "      grep -R --line-number --exclude-dir=wp-content/languages 'http[s]\?://[a-z0-9.-]*' . | head -50"
    echo ""
    echo "Notes:"
    echo " - Do not blindly delete legitimate language files for other locales. Only remove files confirmed malicious."
    echo " - If the site shows other compromises (backdoors, modified core/plugins/themes), prefer restore from a clean backup and rotate all credentials."
  else
    echo "OK: No German SEO Spam files found."
  fi
fi

# --- 6.7b. Mass-scan all /home/* accounts for SEO Spam files ---
if [ "$DO_SEO_SPAM_MASS" -eq 1 ]; then
  echo -e "\n[+] Mass-scanning /home/* for SEO Spam 'Link Factory' files (de_DE.l10n.php) (backgrounded)..."
  # Run long scan in background and save detailed report with remediation steps
  (
    echo "SEO Spam mass scan started: $(date -u)"
    echo ""
    find /home -type f -path "*/public_html/wp-content/languages/*de_DE.l10n.php" -mtime -60 2>/dev/null | while IFS= read -r f; do
      [ -z "$f" ] && continue
      site_root=$(printf "%s" "$f" | sed -E 's|(.*)/public_html/wp-content/languages/.*$|\1/public_html|')
      user=$(basename "$(dirname "$site_root")")
      echo "ACCOUNT: $user"
      echo "SITE_ROOT: $site_root"
      echo "FILE: $f"
      echo "Suggested fix:"
      echo " 1) Inspect the file: sudo less \"$f\""
      echo " 2) If malicious, remove the file: sudo rm -f \"$f\""
      echo " 3) Reinstall translations and clear caches (example):"
      echo "      cd \"$site_root\" && wp language core install --force de_DE --allow-root || true"
      echo "      cd \"$site_root\" && wp cache flush --allow-root || true"
      echo " 4) Search site for injected links or other backdoors:"
      echo "      cd \"$site_root\" && grep -R --line-number --exclude-dir=wp-content/languages 'http[s]\\?:\\/\\/[a-z0-9.-]*' . | head -50"
      echo " 5) If other compromises found, restore from clean backup and rotate creds."
      echo "-----"
    done
    echo ""
    echo "Scan completed: $(date -u)"
  ) > /root/seospamscan.txt 2>&1 &
  echo "Mass SEO spam scan started in background; results will be saved to /root/seospamscan.txt"
fi

# --- 6.8. Database Audit for Shadow Administrators ---
if [ "$DO_SHADOW_ADMIN" -eq 1 ] && [ "$WP_MODE" -eq 1 ]; then
  echo -e "\n[+] Auditing MariaDB for Shadow Administrators..."
  DB_NAME=$(grep "DB_NAME" "$SITE_PATH/wp-config.php" | cut -d"'" -f4 2>/dev/null)
  if [ -n "$DB_NAME" ]; then
    PREFIX=$(mysql "$DB_NAME" -N -s -e "SHOW TABLES LIKE '%_users';" 2>/dev/null | sed 's/users//')
    if [ -n "$PREFIX" ]; then
      SHADOW_USERS=$(mysql "$DB_NAME" -N -s -e "SELECT user_login FROM ${PREFIX}users WHERE user_login LIKE '%admin_%' OR user_login LIKE '%bckup%' OR user_login LIKE '%support%';" 2>/dev/null)
      if [ -n "$SHADOW_USERS" ]; then
        echo "!!! WARNING: Potential Shadow Administrators found in database '$DB_NAME':"
        echo "$SHADOW_USERS"
      else
        echo "OK: No suspicious admin users found in database."
      fi
    fi
  fi
fi


echo -e "\n=========================================================================="
echo "Scan Complete."
echo "=========================================================================="
echo "Disclaimer: This script is a powerful scanning aid. It may produce false"
echo "positives. All findings should be manually investigated and verified."
echo "=========================================================================="

# --- Color helpers (for summary only) ---
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RED=$'\033[31m'
  C_YELLOW=$'\033[33m'
  C_RESET=$'\033[0m'
else
  C_RED=""; C_YELLOW=""; C_RESET=""
fi

# --- Human-friendly summary (always shown) ---
summary_count_lines() { printf "%s\n" "$1" | sed '/^\s*$/d' | wc -l | awk '{print $1}'; }
SUMMARY_WARN=$(grep -c "!!! WARNING" "$LOG_FILE" 2>/dev/null || true)
SUMMARY_WARN=${SUMMARY_WARN:-0}
SUMMARY_STATUS="OK"; [ "$SUMMARY_WARN" -gt 0 ] && SUMMARY_STATUS="WARNINGS"

# --- High-signal file list (for review) ---
# These are high-signal matches worth reviewing; they do NOT prove compromise.
POSSIBLE_HACK_FILES=$( {
  printf "%s\n" "${PHPSHELL_UNIQUE:-}"
  printf "%s\n" "${FILTERED_DECODE_EXEC:-}"
  printf "%s\n" "${FILTERED_SUPER:-}"
  printf "%s\n" "${FILTERED_ONELINER:-}"
  printf "%s\n" "${FILTERED_DYN_EXEC:-}"
  printf "%s\n" "${FILTERED_BACKDOOR:-}"
  printf "%s\n" "${UPLOADS_PHP_FILES:-}"
  printf "%s\n" "${IMMUTABLE_FILES:-}"
} | sed '/^\s*$/d')

echo -e "\n[+] Summary"
echo " -> Status: $SUMMARY_STATUS ($SUMMARY_WARN warnings)"
echo " -> Recently modified files: $(summary_count_lines "$RECENT_FILES")"
echo " -> Uploads non-month dirs:  $(summary_count_lines "$FAKE_MONTH_DIRS")"
echo " -> Uploads PHP files:       $(summary_count_lines "$UPLOADS_PHP_FILES")"
echo " -> Backdoor hits (filtered):$(summary_count_lines "$FILTERED_BACKDOOR")"
echo " -> Obfuscation hits (filt): $(summary_count_lines "$FILTERED_OBFUSCATED")"
echo " -> PHP shell indicators:    $(summary_count_lines "$PHPSHELL_UNIQUE")"
echo " -> Hidden dotfiles:         $(summary_count_lines "$HIDDEN_FILES")"
echo " -> Superglobal exec hits:   $(summary_count_lines "$FILTERED_SUPER")"
echo " -> cURL hits (filtered):    $(summary_count_lines "$FILTERED_CURL")"
echo " -> World-writable files:    $(summary_count_lines "$WRITABLE_FILES")"
echo " -> Verification files:      $(summary_count_lines "$VERIFICATION_FILES")"
echo " -> Access-log files flagged:$(summary_count_lines "$ACCESS_LOG_FILES")"
echo " -> ModSecurity log files:   $(summary_count_lines "$MODSEC_LOG_FILES")"
echo " -> Dyn-exec hits (filtered):$(summary_count_lines "$FILTERED_DYN_EXEC")"
echo " -> One-liner hits (filt):   $(summary_count_lines "$FILTERED_ONELINER")"
echo " -> Immutable files:         $(summary_count_lines "$IMMUTABLE_FILES")"
echo " -> Image headers flagged:   $(summary_count_lines "$IMAGE_HEADER_FINDINGS")"

if [ -n "$POSSIBLE_HACK_FILES" ]; then
  if command -v sort >/dev/null 2>&1; then
    POSSIBLE_HACK_FILES=$(printf "%s\n" "$POSSIBLE_HACK_FILES" | sort -u)
  fi
  echo -e " -> ${C_RED}Files to review (high-signal matches; not proof):${C_RESET}"
  printf "%s\n" "$POSSIBLE_HACK_FILES" | head -50 | while IFS= read -r f; do
    [ -z "$f" ] && continue
    echo -e "    ${C_RED}$f${C_RESET}"
  done
fi

if [ -n "$ACCESS_LOG_FINDINGS" ]; then
  echo " -> Access log highlights (first ~20 lines across files):"
  echo "$ACCESS_LOG_FINDINGS" | head -20
fi

if [ -n "$MODSEC_LOG_FINDINGS" ]; then
  echo " -> ModSecurity highlights (first ~20 lines across files):"
  echo "$MODSEC_LOG_FINDINGS" | head -20
fi


# --- Suspicious IPs Summary ---
if [ -n "$SUSPICIOUS_IPS" ]; then
  echo ""
  echo "=============================================="
  echo "SUSPICIOUS IPs DETECTED"
  echo "=============================================="
  echo "The following IP addresses were found making suspicious/malicious requests:"
  echo ""
  
  # Remove empty lines, sort, unique, and count occurrences
  UNIQUE_IPS=$(printf "%s\n" "$SUSPICIOUS_IPS" | sed '/^$/d' | sort | uniq -c | sort -rn)
  TOTAL_UNIQUE=$(printf "%s\n" "$SUSPICIOUS_IPS" | sed '/^$/d' | sort -u | wc -l | awk '{print $1}')
  
  echo "Total unique suspicious IPs: $TOTAL_UNIQUE"
  echo ""
  echo "IP Address           | Request Count"
  echo "---------------------|--------------"
  printf "%s\n" "$UNIQUE_IPS" | while IFS= read -r line; do
    [ -z "$line" ] && continue
    count=$(echo "$line" | awk '{print $1}')
    ip=$(echo "$line" | awk '{print $2}')
    printf "%-20s | %s\n" "$ip" "$count"
  done
  
  echo ""
  echo "Consider blocking these IPs via firewall, .htaccess, or server configuration."
  echo "=============================================="
  echo ""
  
  # Save to file for easy reference
  SUSPICIOUS_IPS_FILE="${SITE_PATH}/suspicious-ips.txt"
  if printf "%s\n" "$SUSPICIOUS_IPS" | sed '/^$/d' | sort -u > "$SUSPICIOUS_IPS_FILE" 2>/dev/null; then
    echo "Suspicious IPs have been saved to: $SUSPICIOUS_IPS_FILE"
    echo ""
  fi
fi


# --- Email Notification (optional) ---
if [ -n "$EMAIL_TO" ]; then
  WARN_COUNT=$(grep -c "!!! WARNING" "$LOG_FILE" 2>/dev/null || true)
  WARN_COUNT=${WARN_COUNT:-0}
  if [ "$EMAIL_ALWAYS" = "1" ] || [ "${WARN_COUNT}" -gt 0 ]; then
    STATUS="OK"
    [ "${WARN_COUNT}" -gt 0 ] && STATUS="WARNINGS"
    SUBJECT="${EMAIL_SUBJECT:-Generic WP Scan: $SITE_PATH} [$STATUS]"
    if command -v mail >/dev/null 2>&1 && [ -z "$EMAIL_FROM" ]; then
      mail -s "$SUBJECT" "$EMAIL_TO" < "$LOG_FILE"
      echo "Notification email sent via 'mail' to $EMAIL_TO."
    elif command -v sendmail >/dev/null 2>&1; then
      { echo "To: $EMAIL_TO"; echo "From: ${EMAIL_FROM:-no-reply@localhost}"; echo "Subject: $SUBJECT"; echo "Content-Type: text/plain; charset=UTF-8"; echo; cat "$LOG_FILE"; } | sendmail -t
      echo "Notification email sent via 'sendmail' to $EMAIL_TO."
    elif command -v msmtp >/dev/null 2>&1; then
      { echo "To: $EMAIL_TO"; echo "From: ${EMAIL_FROM:-no-reply@localhost}"; echo "Subject: $SUBJECT"; echo "Content-Type: text/plain; charset=UTF-8"; echo; cat "$LOG_FILE"; } | msmtp -t
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
  count_lines() { echo "$1" | sed '/^^\s*$/d' | wc -l | awk '{print $1}'; }
  WARN_COUNT=$(grep -c "!!! WARNING" "$LOG_FILE" 2>/dev/null || true)
  WARN_COUNT=${WARN_COUNT:-0}
  STATUS="OK"; [ "$WARN_COUNT" -gt 0 ] && STATUS="WARNINGS"
  RECENT_COUNT=$(count_lines "$RECENT_FILES")
  UPLOADS_NON_MONTH_COUNT=$(count_lines "$FAKE_MONTH_DIRS")
  UPLOADS_PHP_COUNT=$(count_lines "$UPLOADS_PHP_FILES")
  BACKDOOR_COUNT=$(count_lines "$FILTERED_BACKDOOR")
  OBFUSCATION_COUNT=$(count_lines "$FILTERED_OBFUSCATED")
  PHPSHELL_COUNT=$(count_lines "$PHPSHELL_UNIQUE")
  HIDDEN_COUNT=$(count_lines "$HIDDEN_FILES")
  SUPERGLOBAL_COUNT=$(count_lines "$FILTERED_SUPER")
  CURL_COUNT=$(count_lines "$FILTERED_CURL")
  PERMS_COUNT=$(count_lines "$WRITABLE_FILES")
  VERIF_COUNT=$(count_lines "$VERIFICATION_FILES")
  ACCESS_LOG_COUNT=$(count_lines "$ACCESS_LOG_FILES")
  MODSEC_LOG_COUNT=$(count_lines "$MODSEC_LOG_FILES")
  DYN_EXEC_COUNT=$(count_lines "$FILTERED_DYN_EXEC")
  ONELINER_COUNT=$(count_lines "$FILTERED_ONELINER")
  IMMUTABLE_COUNT=$(count_lines "$IMMUTABLE_FILES")
  WP_CLI_COUNT=$(grep -c "!!! WARNING.*WP-CLI" "$LOG_FILE" 2>/dev/null || true)
  WP_CLI_COUNT=${WP_CLI_COUNT:-0}

  echo "{"
  echo " \"site\": \"$SITE_PATH\","
  echo " \"status\": \"$STATUS\","
  echo " \"warnings\": $WARN_COUNT,"
  echo " \"modules\": {"
  echo "  \"recent\": $RECENT_COUNT,"
  echo "  \"uploads_non_month\": $UPLOADS_NON_MONTH_COUNT,"
  echo "  \"uploads_php\": $UPLOADS_PHP_COUNT,"
  echo "  \"backdoor\": $BACKDOOR_COUNT,"
  echo "  \"obfuscation\": $OBFUSCATION_COUNT,"
  echo "  \"phpshell\": $PHPSHELL_COUNT,"
  echo "  \"hidden\": $HIDDEN_COUNT,"
  echo "  \"superglobal\": $SUPERGLOBAL_COUNT,"
  echo "  \"curl\": $CURL_COUNT,"
  echo "  \"perms_world_writable\": $PERMS_COUNT,"
  echo "  \"verification_files\": $VERIF_COUNT,"
  echo "  \"access_logs\": $ACCESS_LOG_COUNT,"
  echo "  \"modsec_logs\": $MODSEC_LOG_COUNT,"
  echo "  \"dyn_exec\": $DYN_EXEC_COUNT,"
  echo "  \"oneliner\": $ONELINER_COUNT,"
  echo "  \"immutable\": $IMMUTABLE_COUNT,"
  echo "  \"wp_cli\": $WP_CLI_COUNT"
  echo " }"
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
    printf "%s\n" "$ZIP_CANDIDATES" | sed '/^^\s*$/d' | while IFS= read -r p; do
      [ -f "$p" ] && echo "$p"
    done | sort -u > "$FILE_LIST"
    COUNT=$(wc -l < "$FILE_LIST" | awk '{print $1}')
    if [ "$COUNT" -gt 0 ]; then
      # Create zip from list; entries will use the absolute path as listed
      zip -@ "$ZIP_TARGET_ZIP" < "$FILE_LIST"
      # Add a manifest with the full absolute paths for easy reference
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
WARN_COUNT=$(grep -c "!!! WARNING" "$LOG_FILE" 2>/dev/null || true)
WARN_COUNT=${WARN_COUNT:-0}
if [ "$EXIT_CODE_MODE" = "count" ]; then
  EC=$WARN_COUNT
  [ "$EC" -gt 254 ] && EC=254
  exit "$EC"
else
  [ "$WARN_COUNT" -gt 0 ] && exit 1 || exit 0
fi