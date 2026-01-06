#!/usr/bin/env bash

scan_immutable() {
    [ "$DO_IMMUTABLE" -eq 1 ] || return 0

    echo -e "\n[+] Checking for immutable files (+i attribute)..."

    if ! command -v lsattr >/dev/null 2>&1; then
        echo "INFO: 'lsattr' command not found. Skipping immutable file check (requires e2fsprogs)."
    else
        local immutable_files
        immutable_files=$(find "$SITE_PATH" -type f -exec lsattr -d {} \; 2>/dev/null | grep '^..i' | awk '{print $2}')

        if [ -n "$immutable_files" ]; then
            echo "!!! WARNING: Found immutable files. This is highly suspicious and may indicate a rootkit or backdoor."
            echo "$immutable_files"
            ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$immutable_files")
        else
            echo "OK: No immutable files found."
        fi
    fi
}
