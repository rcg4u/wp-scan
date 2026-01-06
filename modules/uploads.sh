#!/usr/bin/env bash

scan_uploads() {
    [ "$DO_UPLOADS" -eq 1 ] || return 0

    local uploads_dir="$SITE_PATH/wp-content/uploads"
    [ -d "$uploads_dir" ] || return 0

    echo -e "\n[+] Checking for non-month directories in uploads..."

    local fake_month_dirs_file
    fake_month_dirs_file=$(mktemp)

    find "$uploads_dir" -maxdepth 2 -type d -name "[0-9]*" -print 2>/dev/null | while IFS= read -r dir; do
        local basename
        basename=$(basename "$dir")
        if [[ "$basename" =~ ^[0-9]+$ ]] && ! [[ "$basename" =~ ^(0[1-9]|1[0-2])$ ]]; then
            echo "$dir"
        fi
    done | sort > "$fake_month_dirs_file"

    local fake_month_dirs
    fake_month_dirs=$(cat "$fake_month_dirs_file")

    if [ -n "$fake_month_dirs" ]; then
        echo "!!! WARNING: Found non-month directories in uploads (possible backdoors):"
        echo "$fake_month_dirs"
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$fake_month_dirs")
    else
        echo "OK: No non-month directories found in uploads."
    fi

    rm -f "$fake_month_dirs_file"
}
