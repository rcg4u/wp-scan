#!/usr/bin/env bash

scan_hidden_files() {
    [ "$DO_HIDDEN" -eq 1 ] || return 0

    echo -e "\n[+] Checking for hidden dotfiles..."
    local hidden_files
    hidden_files=$(find "$SITE_PATH" -type f -name ".*" \
        -not -path "*/.git/*" \
        -not -path "*/.svn/*" \
        -not -path "*/.hg/*" \
        -not -path "*/.well-known/*" \
        2>/dev/null)

    if [ -n "$hidden_files" ]; then
        echo "!!! WARNING: Hidden files found (could expose secrets or be used for persistence):"
        highlight_caution "Hidden dotfiles can contain credentials, API keys, or persistence mechanisms; review contents before taking action."
        # Show filenames and the first 20 lines of each (up to 20 files)
        printf "%s\n" "$hidden_files" | head -20 | while IFS= read -r f; do
            [ -z "$f" ] && continue
            echo "----- $f -----"
            sed -n '1,20p' "$f" 2>/dev/null || echo "(could not read file or permission denied)"
        done
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$hidden_files")
    else
        echo "OK: No hidden dotfiles found (excluding VCS and .well-known)."
    fi
}
