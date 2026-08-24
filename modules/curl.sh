#!/usr/bin/env bash

scan_curl() {
    [ "$DO_CURL" -eq 1 ] || return 0

    echo " -> Searching for cURL calls to external domains..."
    local matches
    matches=$(grep -R -l --include="*.php" -e "curl_init" "$SITE_PATH" 2>/dev/null | grep -v -E "wp-includes/|wp-content/themes/|wp-content/plugins/" | head -10)

    if [ -n "$matches" ]; then
        echo "!!! WARNING: Found cURL calls. These are common in backdoors. Review these files:"
        highlight_caution "Outbound cURL requests can exfiltrate data or fetch malicious payloads; inspect the remote endpoints and context of usage."
        echo "$matches"
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$matches")
    else
        echo "OK: No cURL calls found in non-standard locations."
    fi
}
