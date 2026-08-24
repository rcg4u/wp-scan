#!/usr/bin/env bash

scan_superglobal() {
    [ "$DO_SUPERGLOBAL" -eq 1 ] || return 0

    echo -e "\n[+] Scanning for superglobal-driven backdoor patterns..."
    local pattern="(\$_(GET|POST|REQUEST|COOKIE)).*\s*(eval\s*\(|system\s*\(|shell_exec\s*\(|passthru\s*\(|popen\s*\(|proc_open\s*\(|assert\s*\(|create_function\s*\(|preg_replace.*\/e)"

    local matches
    matches=$(grep -R -l -I --include="*.php" -E "$pattern" "$SITE_PATH" 2>/dev/null | grep -v -E "wp-includes/|wp-admin/" | head -20)

    if [ -n "$matches" ]; then
        echo "!!! WARNING: Superglobal-driven exec/eval patterns found:"
        highlight_high "Patterns that execute data from \\$_GET/POST/REQUEST/COOKIE were found; this allows attackers to send payloads that the site will execute directly."
        echo "$matches"
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$matches")
    else
        echo "OK: No obvious superglobal backdoor patterns found."
    fi
}
