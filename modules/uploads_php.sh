#!/usr/bin/env bash

scan_uploads_php() {
    [ "$DO_UPLOADS_PHP" -eq 1 ] || return 0

    local uploads_dir="$SITE_PATH/wp-content/uploads"
    [ -d "$uploads_dir" ] || return 0

    echo -e "\n[+] Checking for PHP files inside uploads..."
    local uploads_php_files
    uploads_php_files=$(find "$uploads_dir" -type f -name "*.php" 2>/dev/null)

    if [ -n "$uploads_php_files" ]; then
        echo "!!! WARNING: Found PHP files inside uploads (should be media only):"
        echo "$uploads_php_files"
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$uploads_php_files")
    else
        echo "OK: No PHP files found inside uploads."
    fi
}
