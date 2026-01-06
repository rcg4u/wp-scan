#!/usr/bin/env bash

scan_wp_version() {
    [ "$DO_WPVER" -eq 1 ] || return 0

    echo -e "\n[+] Checking WordPress version..."
    local version_file="$SITE_PATH/wp-includes/version.php"

    if [ -f "$version_file" ]; then
        local wp_version
        wp_version=$(grep -o "wp_version = '[^']*'" "$version_file" | sed "s/wp_version = '//" | sed "s/'//")
        echo " -> Detected WordPress version: $wp_version"
        echo " -> Manual check required: Please compare this version against the WordPress.org security advisories to see if it's outdated."
    else
        echo "Could not determine WordPress version."
    fi
}
