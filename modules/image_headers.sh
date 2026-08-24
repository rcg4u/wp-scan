#!/usr/bin/env bash

scan_image_headers() {
    [ "$DO_IMAGE_HEADERS" -eq 1 ] || return 0
    
    echo -e "\n[+] Scanning image headers for malicious code..."
    
    local IMAGE_EXTS="jpg|jpeg|png|gif|webp|ico|svg|bmp"
    local HACKED_IMAGES=""
    local SUSPECT_COUNT=0
    
    # Patterns that indicate malicious code in image headers
    local PHP_PATTERN="<\?php|<\?=|<script[^>]*php"
    local EVAL_PATTERN="eval\(|base64_decode\(|gzinflate\(|assert\(|system\(|exec\(|shell_exec\(|passthru\("
    local STEALTH_PATTERN="@eval|error_reporting\(0\)|ini_set.*display_errors"
    
    echo " -> Scanning for PHP code in image file headers (first 1KB)..."
    
    # Find all image files
    while IFS= read -r img; do
        [ -z "$img" ] && continue
        [ ! -f "$img" ] && continue
        
        # Read first 1024 bytes of the file, stripping NUL bytes to avoid command-substitution warnings
        local header
        header=$(head -c 1024 "$img" 2>/dev/null | tr -d '\000')
        [ -z "$header" ] && continue
        
        # Check for PHP tags in header
        if echo "$header" | grep -q -E "$PHP_PATTERN" 2>/dev/null; then
            echo "!!! WARNING: PHP code found in image header: $img"
            highlight_high "PHP code embedded inside image headers allows execution when the file is served; this is commonly used to hide backdoors in media uploads."
            HACKED_IMAGES=$(printf "%s\n%s\n" "$HACKED_IMAGES" "$img")
            SUSPECT_COUNT=$((SUSPECT_COUNT + 1))
            
            if [ "$SHOW_CONTEXT" -eq 1 ] || [ "$DO_BACKDOOR" -eq 1 ] || [ "$DO_OBFUSCATED" -eq 1 ] || [ "$DO_CURL" -eq 1 ] || [ "$DO_UPLOADS_PHP" -eq 1 ] || [ "$DO_HIDDEN" -eq 1 ] || [ "$DO_SUPERGLOBAL" -eq 1 ] || [ "$DO_VERIFICATION" -eq 1 ] || [ "$DO_DYN_EXEC" -eq 1 ] || [ "$DO_ONELINER" -eq 1 ] || [ "$DO_SEO_SPAM" -eq 1 ] || [ "$DO_WP_CLI" -eq 1 ] || [ "$DO_IMAGE_HEADERS" -eq 1 ]; then
                echo " -> First 200 chars of suspicious content:"
                echo "$header" | head -c 200 | od -c | head -10
            fi
            continue
        fi
        
        # Check for eval/exec patterns in header
        if echo "$header" | grep -q -E "$EVAL_PATTERN" 2>/dev/null; then
            echo "!!! WARNING: Suspicious eval/exec pattern in image header: $img"
            highlight_high "Eval/exec-like constructs in an image header are a strong sign of a malicious payload; these files should be quarantined and analyzed."
            HACKED_IMAGES=$(printf "%s\n%s\n" "$HACKED_IMAGES" "$img")
            SUSPECT_COUNT=$((SUSPECT_COUNT + 1))
            
            if [ "$SHOW_CONTEXT" -eq 1 ] || [ "$DO_BACKDOOR" -eq 1 ] || [ "$DO_OBFUSCATED" -eq 1 ] || [ "$DO_CURL" -eq 1 ] || [ "$DO_UPLOADS_PHP" -eq 1 ] || [ "$DO_HIDDEN" -eq 1 ] || [ "$DO_SUPERGLOBAL" -eq 1 ] || [ "$DO_VERIFICATION" -eq 1 ] || [ "$DO_DYN_EXEC" -eq 1 ] || [ "$DO_ONELINER" -eq 1 ] || [ "$DO_SEO_SPAM" -eq 1 ] || [ "$DO_WP_CLI" -eq 1 ] || [ "$DO_IMAGE_HEADERS" -eq 1 ]; then
                echo " -> Matched pattern:"
                echo "$header" | grep -o -E ".{0,50}($EVAL_PATTERN).{0,50}" | head -3
            fi
            continue
        fi
        
        # Check for stealth/obfuscation patterns
        if echo "$header" | grep -q -E "$STEALTH_PATTERN" 2>/dev/null; then
            echo "!!! WARNING: Stealth/obfuscation pattern in image header: $img"
            highlight_caution "Stealth or obfuscation markers may indicate a payload is hidden or attempts to avoid detection; review the file closely."
            HACKED_IMAGES=$(printf "%s\n%s\n" "$HACKED_IMAGES" "$img")
            SUSPECT_COUNT=$((SUSPECT_COUNT + 1))
            continue
        fi
        
    done < <(find "$SITE_PATH" -type f -regextype posix-extended -iregex ".*\.($IMAGE_EXTS)$" 2>/dev/null | head -10000)
    
    if [ "$SUSPECT_COUNT" -gt 0 ]; then
        echo "!!! WARNING: Found $SUSPECT_COUNT image(s) with suspicious headers"
        HACKED_IMAGES=$(printf "%s\n" "$HACKED_IMAGES" | sed '/^\s*$/d' | sort -u)
        ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$HACKED_IMAGES")
        
        echo " -> Quick analysis tips:"
        echo "    - Use 'head -c 2048 <file> | strings' to view header content"
        echo "    - Use 'exiftool <file>' to check metadata"
        echo "    - Use 'file <file>' to verify actual file type"
        echo "    - Check file size - hacked images are often larger than normal"
    else
        echo "OK: No suspicious code found in image headers (scanned up to 10000 images)"
    fi
    
    # Store results for summary
    IMAGE_HEADER_FINDINGS="$HACKED_IMAGES"
    IMAGE_HEADER_COUNT="$SUSPECT_COUNT"
}
