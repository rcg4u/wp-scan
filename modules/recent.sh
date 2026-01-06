#!/usr/bin/env bash

scan_recent_files() {
    [ "$DO_RECENT" -eq 1 ] || return 0

    echo -e "\n[+] Checking for recently modified files (any type) in the last 60 minutes..."
    local find_cmd="find \"$SITE_PATH\" -type f -mmin -60"
    [ "$EXCLUDE_CACHE" -eq 1 ] && find_cmd+=" -not -path \"*/wp-content/cache/*\""

    local recent_files
    recent_files=$(eval "$find_cmd" 2>/dev/null)

    if [ -n "$recent_files" ]; then
        echo "!!! WARNING: Recently modified files found. Please review them:"
        echo "$recent_files"
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$recent_files")
    else
        echo "OK: No recently modified files found."
    fi
}
