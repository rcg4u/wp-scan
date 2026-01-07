#!/usr/bin/env bash

scan_uploads_php() {
    [ "$DO_UPLOADS_PHP" -eq 1 ] || return 0

    local uploads_dir="$SITE_PATH/wp-content/uploads"
    [ -d "$uploads_dir" ] || return 0

    echo -e "\n[+] Checking for PHP files inside uploads..."
    local uploads_php_files
    uploads_php_files=$(find "$uploads_dir" -type f \( -iname "*.php" -o -iname "*.phtml" -o -iname "*.php5" -o -iname "*.php7" -o -iname "*.phar" -o -iname "*.inc" \) 2>/dev/null)

    if [ -n "$uploads_php_files" ]; then
        echo "!!! WARNING: Found executable PHP-like files inside uploads (should be media only):"
        echo "$uploads_php_files"
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$uploads_php_files")
    else
        echo "OK: No PHP files found inside uploads."
    fi

    # Also flag common double-extension tricks like image.jpg.php
    local double_ext
    double_ext=$(find "$uploads_dir" -type f \( -iname "*.jpg.php" -o -iname "*.jpeg.php" -o -iname "*.png.php" -o -iname "*.gif.php" -o -iname "*.webp.php" -o -iname "*.pdf.php" -o -iname "*.txt.php" \) 2>/dev/null)
    if [ -n "$double_ext" ]; then
        echo "!!! WARNING: Found double-extension files in uploads (e.g. image.jpg.php):"
        echo "$double_ext" | head -50
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$double_ext")
    fi
}
