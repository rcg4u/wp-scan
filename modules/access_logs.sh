#!/usr/bin/env bash

scan_access_logs() {
    [ "$DO_ACCESS_LOGS" -eq 1 ] || return 0

    echo -e "\n[+] Scanning access logs under /home/* (access-logs + logs) for suspicious requests..."

    local findings=""
    local files_found=""

    if [[ "$SITE_PATH" =~ ^/home/([^/]+)/public_html(/|$) ]]; then
        SITE_OWNER="${BASH_REMATCH[1]}"
    fi

    local scan_pattern="(\?[^ ]*(cmd=|exec=|system=|shell=|base64|eval|assert|GLOBALS|_POST\$|_GET\$))|(/(wp-admin|wp-login\.php)\.php)|(/\.env)|(/wp-config\.php)|(/xmlrpc\.php)|(/\.git/)|(/cgi-bin/)|((/|%2f)(c99|r57|wso|b374k)[^ ]*\.php)|((/|%2f)shell[^ ]*\.php)|((/|%2f)webshell[^ ]*\.php)|((union[+%20]+select|information_schema|sleep\$|benchmark\$)|((/|%2f)etc(/|%2f)passwd)|\b(base64_decode|gzinflate|str_rot13|php://input)\b)"

    scan_plain_log() {
        local f="$1"; [ -f "$f" ] || return 0
        if grep -Iq . "$f" 2>/dev/null; then
            local hits
            hits=$(grep -n -E -i "$scan_pattern" "$f" 2>/dev/null | head -50)
            if [ -n "$hits" ]; then
                files_found=$(printf "%s\n%s\n" "$files_found" "$f")
                findings=$(printf "%s\n=== %s ===\n%s\n" "$findings" "$f" "$hits")
            fi
        fi
    }

    scan_gz_log() {
        local f="$1"; [ -f "$f" ] || return 0
        command -v gzip >/dev/null 2>&1 || return 0
        local hits
        hits=$(gzip -cd -- "$f" 2>/dev/null | grep -n -E -i "$scan_pattern" | head -50)
        if [ -n "$hits" ]; then
            files_found=$(printf "%s\n%s\n" "$files_found" "$f")
            findings=$(printf "%s\n=== %s ===\n%s\n" "$findings" "$f" "$hits")
        fi
    }

    if [ -d "/home" ]; then
        local log_base="/home/${SITE_OWNER:-*}"

        while IFS= read -r lf; do
            [ -z "$lf" ] && continue
            scan_plain_log "$lf"
        done < <(find "$log_base" -maxdepth 2 -type f -path "*/access-logs/*" 2>/dev/null | head -500)

        while IFS= read -r lf; do
            [ -z "$lf" ] && continue
            case "$lf" in
                *.gz) scan_gz_log "$lf" ;;
                *) scan_plain_log "$lf" ;;
            esac
        done < <(find "$log_base" -maxdepth 2 -type f -path "*/logs/*" 2>/dev/null | head -500)
    fi

    files_found=$(printf "%s\n" "$files_found" | sed '/^\s*$/d' | sort -u)

    if [ -n "$findings" ]; then
        echo "!!! WARNING: Suspicious access log requests found (showing first hits per file):"
        echo "$findings" | head -200
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$files_found")
    else
        echo "OK: No suspicious access log patterns found in /home/* access logs."
    fi
}
