#!/usr/bin/env bash

scan_suspicious_names() {
    [ "$DO_SUSPICIOUS" -eq 1 ] || return 0

    echo -e "\n[+] Checking for suspicious file/directory names..."
    local suspicious_names=("cg-bin" "phpshell" "c99" "r57" "webshell" "wso" "adminer.php" "phpmyadmin" "xmlrpc.php")

    local name
    for name in "${suspicious_names[@]}"; do
        if [ -f "$SITE_PATH/$name" ] || [ -d "$SITE_PATH/$name" ]; then
            echo "!!! WARNING: Suspicious file/directory found: '/$name'"
            [ -f "$SITE_PATH/$name" ] && ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$SITE_PATH/$name")
        fi
    done
}
