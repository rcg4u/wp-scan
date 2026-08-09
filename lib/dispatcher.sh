#!/usr/bin/env bash

run_modules() {
    scan_recent_files
    scan_suspicious_names
    scan_uploads
    scan_uploads_php
    scan_verification_files
    scan_access_logs
    scan_malicious_code
    scan_hidden_files
    scan_superglobal
    scan_curl
    scan_wp_version
    scan_permissions
    scan_immutable
    scan_image_headers
    scan_wp_cli
}

run_selected_modules() {
    [ "$DO_RECENT" -eq 1 ] && scan_recent_files
    [ "$DO_SUSPICIOUS" -eq 1 ] && scan_suspicious_names
    [ "$DO_UPLOADS" -eq 1 ] && scan_uploads
    [ "$DO_UPLOADS_PHP" -eq 1 ] && scan_uploads_php
    [ "$DO_VERIFICATION" -eq 1 ] && scan_verification_files
    [ "$DO_ACCESS_LOGS" -eq 1 ] && scan_access_logs

    if [ "$DO_BACKDOOR" -eq 1 ] || [ "$DO_OBFUSCATED" -eq 1 ] || [ "$DO_PHPSHELL" -eq 1 ] || [ "$DO_DYN_EXEC" -eq 1 ] || [ "$DO_ONELINER" -eq 1 ]; then
        scan_malicious_code
    fi

    [ "$DO_HIDDEN" -eq 1 ] && scan_hidden_files
    [ "$DO_SUPERGLOBAL" -eq 1 ] && scan_superglobal
    [ "$DO_CURL" -eq 1 ] && scan_curl
    [ "$DO_WPVER" -eq 1 ] && scan_wp_version
    [ "$DO_PERMS" -eq 1 ] && scan_permissions
    [ "$DO_IMMUTABLE" -eq 1 ] && scan_immutable
    [ "$DO_IMAGE_HEADERS" -eq 1 ] && scan_image_headers
    [ "$DO_WP_CLI" -eq 1 ] && scan_wp_cli
}

run_dispatch() {
    if [ "${MENU_MODE:-0}" -eq 1 ]; then
        run_selected_modules
        return 0
    fi

    if [ "${EXPLICIT_MODULE_SELECTION:-0}" -eq 1 ] && [ "${SCAN_ALL:-0}" -eq 0 ]; then
        run_selected_modules
    else
        run_modules
    fi
}
