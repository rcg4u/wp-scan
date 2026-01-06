#!/usr/bin/env bash

scan_verification_files() {
    [ "$DO_VERIFICATION" -eq 1 ] || return 0

    echo -e "\n[+] Checking for verification files..."

    local verification_files
    verification_files=$( {
        find "$SITE_PATH" -maxdepth 1 -type f \( -name "google*.html" -o -name "bing*.html" -o -name "yandex*.html" \) 2>/dev/null
        find "$SITE_PATH/.well-known" -type f 2>/dev/null
    } 2>/dev/null )

    if [ -n "$verification_files" ]; then
        echo "!!! WARNING: Found verification files. These could be for unauthorized ownership claims:"
        echo "$verification_files"
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$verification_files")
    else
        echo "OK: No verification files found."
    fi
}
