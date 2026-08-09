#!/usr/bin/env bash

scan_wp_cli() {
    [ "$DO_WP_CLI" -eq 1 ] || return 0

    if ! command -v wp >/dev/null 2>&1; then
        echo -e "\n[+] WP-CLI checks skipped: 'wp' command not found."
        return 0
    fi

    echo -e "\n[+] Running WP-CLI deep checks..."

    cd "$SITE_PATH" || { echo "Error: Could not change directory to $SITE_PATH"; exit 1; }

    local WP_ALLOW_ROOT=""
    if [ "${EUID:-$(id -u)}" -eq 0 ]; then
        WP_ALLOW_ROOT="--allow-root"
    fi

    if ! wp $WP_ALLOW_ROOT core is-installed --quiet 2>/dev/null; then
        echo "!!! WARNING: WP-CLI found but not functional for this installation. Skipping WP-CLI checks."
        return 0
    fi

    echo " -> Checking core file integrity..."
    local core_status
    core_status=$(wp $WP_ALLOW_ROOT core verify-checksums --format=json 2>/dev/null)

    if [ $? -ne 0 ]; then
        echo "!!! WARNING: WordPress core files have been modified or checksums are missing."
        echo "$core_status" | jq -r '.[] | "File: \(.file), Status: \(.status)"' 2>/dev/null || echo "$core_status"
    else
        echo "OK: Core file integrity verified."
    fi

    echo " -> Verifying plugin checksums..."
    local plugin_checks
    plugin_checks=$(wp $WP_ALLOW_ROOT plugin verify-checksums --format=json 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "!!! WARNING: Plugin checksums verification failed or modifications detected."
        echo "$plugin_checks" | jq -r '.[] | " - \(.file // .) (Status: \(.status // .))"' 2>/dev/null || echo "$plugin_checks"
    else
        echo "OK: Plugin checksums verified."
    fi

    echo " -> Checking plugin and theme status..."

    local plugin_status
    plugin_status=$(wp $WP_ALLOW_ROOT plugin list --status=inactive --format=json 2>/dev/null)
    if [ -n "$plugin_status" ] && [ "$plugin_status" != "[]" ]; then
        echo "!!! WARNING: Inactive plugins found (can be a security risk):"
        echo "$plugin_status" | jq -r '.[] | " - \(.name) (v\(.version))"' 2>/dev/null || echo "$plugin_status"
    fi

    local theme_status
    theme_status=$(wp $WP_ALLOW_ROOT theme list --status=inactive --format=json 2>/dev/null)
    if [ -n "$theme_status" ] && [ "$theme_status" != "[]" ]; then
        echo "!!! WARNING: Inactive themes found (should be removed):"
        echo "$theme_status" | jq -r '.[] | " - \(.name) (v\(.version))"' 2>/dev/null || echo "$theme_status"
    fi

    if wp $WP_ALLOW_ROOT cli has-command "plugin vulnerability" 2>/dev/null; then
        echo " -> Checking for plugin vulnerabilities..."
        local vuln_report
        vuln_report=$(wp $WP_ALLOW_ROOT plugin vulnerability list --format=json 2>/dev/null)
        local vuln_count
        vuln_count=$(echo "$vuln_report" | jq length 2>/dev/null || echo 0)
        if [ "$vuln_count" -gt 0 ]; then
            echo "!!! WARNING: Found $vuln_count plugin vulnerabilities:"
            echo "$vuln_report" | jq -r '.[] | " - \(.title) in \(.plugin) (\(.fixed_in // "no fix"))"' 2>/dev/null || echo "$vuln_report"
        fi
    fi

    echo " -> Checking user security..."
    local admin_users
    admin_users=$(wp $WP_ALLOW_ROOT user list --role=administrator --format=json 2>/dev/null)
    if [ -n "$admin_users" ]; then
        echo "INFO: Administrator users found:"
        echo "$admin_users" | jq -r '.[] | " - \(.user_login) (\(.user_email))"' 2>/dev/null || echo "$admin_users"
    fi

    local no_role_users
    no_role_users=$(wp $WP_ALLOW_ROOT user list --role= --format=json 2>/dev/null)
    if [ -n "$no_role_users" ] && [ "$no_role_users" != "[]" ]; then
        echo "!!! WARNING: Users with no assigned role found:"
        echo "$no_role_users" | jq -r '.[] | " - \(.user_login) (\(.user_email))"' 2>/dev/null || echo "$no_role_users"
    fi

    echo " -> Checking for suspicious options..."
    local upload_path
    upload_path=$(wp $WP_ALLOW_ROOT option get upload_path --format=json 2>/dev/null)
    if [ -n "$upload_path" ] && [ "$upload_path" != "null" ] && [ "$upload_path" != "wp-content/uploads" ]; then
        echo "!!! WARNING: Custom upload_path detected: $upload_path"
    fi
}
