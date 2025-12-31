#!/bin/bash

# ====================================================================
# Generic WordPress Security Scanner
#
# Usage: ./generic_wp_scan.sh /path/to/wordpress/root
# Example: ./generic_wp_scan.sh /var/www/html/wordpress
# ====================================================================

# --- Script Logic ---

# Check if a directory was provided as an argument.
if [ -z "$1" ]; then
    echo "Error: Please provide the path to the WordPress root directory."
    echo "Usage: $0 /path/to/wordpress/root"
    exit 1
fi

# Assign the first argument to a variable and sanitize it.
SITE_PATH=$(realpath "$1")

# Check if the provided path actually exists and is a directory.
if [ ! -d "$SITE_PATH" ]; then
    echo "Error: Directory '$SITE_PATH' not found."
    exit 1
fi

# Check if it looks like a WordPress installation.
if [ ! -f "$SITE_PATH/wp-config.php" ]; then
    echo "Error: wp-config.php not found in '$SITE_PATH'. Is this a WordPress root?"
    exit 1
fi

echo "=========================================================================="
echo "Starting Generic WordPress Security Scan for: $SITE_PATH"
echo "=========================================================================="

# --- 1. Check for Recently Modified Files ---
echo -e "\n[+] Checking for recently modified files (any type) in the last 60 minutes..."
RECENT_FILES=$(find "$SITE_PATH" -type f -mmin -60 2>/dev/null)
if [ -n "$RECENT_FILES" ]; then
    echo "!!! WARNING: Recently modified files found. Please review them:"
    echo "$RECENT_FILES"
else
    echo "OK: No recently modified files found."
fi

# --- 2. Check for Suspicious File/Directory Names ---
echo -e "\n[+] Checking for suspicious file/directory names..."

# Common backdoor file/directory names
SUSPICIOUS_NAMES=("cg-bin" "phpshell" "c99" "r57" "webshell" "wso" "adminer.php" "phpmyadmin" "xmlrpc.php")
for name in "${SUSPICIOUS_NAMES[@]}"; do
    if [ -f "$SITE_PATH/$name" ] || [ -d "$SITE_PATH/$name" ]; then
        echo "!!! WARNING: Suspicious file/directory found: '/$name'"
    fi
done

# Check for non-standard directories in uploads (e.g., month > 12)
UPLOADS_DIR="$SITE_PATH/wp-content/uploads"
if [ -d "$UPLOADS_DIR" ]; then
    # Find directories in uploads with a numeric name that is not 01-12
    FAKE_MONTHS=$(find "$UPLOADS_DIR" -maxdepth 2 -type d -name "[0-9]*" | awk -F'/' '{print $NF}' | grep -vxE '^^[0-9]{1,2}$' | grep -vxE '0[1-9]|1[0-2]')
    if [ -n "$FAKE_MONTHS" ]; then
        echo "!!! WARNING: Found non-month directories in uploads (possible backdoors):"
        echo "$FAKE_MONTHS"
    fi
fi

# Check for any verification files (Google, Bing, Yandex, etc.)
VERIFICATION_FILES=$(find "$SITE_PATH" -maxdepth 1 -type f $$ -name "google*.html" -o -name "bing*.html" -o -name "yandex*.html" -o -name "*.well-known/*" $$ 2>/dev/null)
if [ -n "$VERIFICATION_FILES" ]; then
    echo "!!! WARNING: Found verification files. These could be for unauthorized ownership claims:"
    echo "$VERIFICATION_FILES"
fi


# --- 3. Search for Malicious Code Patterns ---
echo -e "\n[+] Searching for malicious code patterns in PHP files..."

# Search for common backdoor functions
echo "  -> Searching for high-risk backdoor functions..."
BACKDOOR_MATCH=$(grep -R -l -i --include="*.php" -e "eval\s*(" -e "base64_decode\s*(" -e "shell_exec\s*(" -e "passthru\s*(" -e "system\s*(" -e "exec\s*(" "$SITE_PATH" 2>/dev/null)
if [ -n "$BACKDOOR_MATCH" ]; then
    echo "!!! WARNING: Found high-risk functions. Review these files:"
    # Filter out known WordPress core files to reduce noise
    echo "$BACKDOOR_MATCH" | grep -v -E "wp-includes/|wp-admin/|wp-content/plugins/|wp-content/themes/" | head -10
else
    echo "OK: No high-risk functions found in non-standard locations."
fi

# Search for obfuscated code patterns
echo "  -> Searching for obfuscated code (base64, gzinflate, str_rot13)..."
OBFUSCATED_MATCH=$(grep -R -l -i --include="*.php" -e "base64_decode" -e "gzinflate(" -e "str_rot13(" -e "strrev(" "$SITE_PATH" 2>/dev/null)
if [ -n "$OBFUSCATED_MATCH" ]; then
    echo "!!! WARNING: Found potentially obfuscated code. Review these files:"
    echo "$OBFUSCATED_MATCH" | grep -v -E "wp-includes/|wp-admin/" | head -10
else
    echo "OK: No obvious obfuscated code found."
fi

# Search for hidden cURL calls
echo "  -> Searching for cURL calls to external domains..."
CURL_MATCH=$(grep -R -l --include="*.php" -e "curl_init" "$SITE_PATH" 2>/dev/null)
if [ -n "$CURL_MATCH" ]; then
    echo "!!! WARNING: Found cURL calls. These are common in backdoors. Review these files:"
    echo "$CURL_MATCH" | grep -v -E "wp-includes/|wp-content/themes/|wp-content/plugins/" | head -10
else
    echo "OK: No cURL calls found in non-standard locations."
fi


# --- 4. Check for WordPress Version Vulnerabilities ---
echo -e "\n[+] Checking WordPress version..."
if [ -f "$SITE_PATH/wp-includes/version.php" ]; then
    WP_VERSION=$(grep -o "wp_version = '[^^']*'" "$SITE_PATH/wp-includes/version.php" | sed "s/wp_version = '//" | sed "s/'//")
    echo "  -> Detected WordPress version: $WP_VERSION"
    echo "  -> Manual check required: Please compare this version against the WordPress.org security advisories to see if it's outdated."
else
    echo "Could not determine WordPress version."
fi


# --- 5. Check File Permissions ---
echo -e "\n[+] Checking for insecure file permissions..."
echo "  -> Checking for world-writable files..."
WRITABLE_FILES=$(find "$SITE_PATH" -type f -perm /002 -not -path "*/wp-content/cache/*" -not -path "*/wp-content/uploads/*" 2>/dev/null | head -5)
if [ -n "$WRITABLE_FILES" ]; then
    echo "!!! WARNING: Found world-writable files (showing first 5):"
    echo "$WRITABLE_FILES"
else
    echo "OK: No obvious world-writable files found outside uploads/cache."
fi

echo -e "\n=========================================================================="
echo "Scan Complete."
echo "=========================================================================="
echo "Disclaimer: This script is a powerful scanning aid. It may produce false"
echo "positives. All findings should be manually investigated and verified."
echo "=========================================================================="
