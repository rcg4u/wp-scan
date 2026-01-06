#!/usr/bin/env bash

scan_permissions() {
    [ "$DO_PERMS" -eq 1 ] || return 0

    echo -e "\n[+] Checking for insecure file permissions..."
    echo " -> Checking for world-writable files..."

    local writable_files
    writable_files=$(find "$SITE_PATH" -type f -perm /002 \
        -not -path "*/wp-content/cache/*" \
        -not -path "*/wp-content/uploads/*" \
        2>/dev/null | head -5)

    if [ -n "$writable_files" ]; then
        echo "!!! WARNING: Found world-writable files (showing first 5):"
        echo "$writable_files"
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$writable_files")
    else
        echo "OK: No obvious world-writable files found outside uploads/cache."
    fi
}
