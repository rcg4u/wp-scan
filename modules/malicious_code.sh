#!/usr/bin/env bash

scan_malicious_code() {
    local should_run=0
    if [ "$DO_BACKDOOR" -eq 1 ] || [ "$DO_OBFUSCATED" -eq 1 ] || [ "$DO_PHPSHELL" -eq 1 ] || [ "$DO_DYN_EXEC" -eq 1 ] || [ "$DO_ONELINER" -eq 1 ]; then
        should_run=1
    fi
    [ "$should_run" -eq 1 ] || return 0

    echo -e "\n[+] Searching for malicious code patterns in PHP files..."
    local grep_base="grep -R -l -I --include=\"*.php\""

    if [ "$DO_BACKDOOR" -eq 1 ]; then
        echo " -> Searching for high-risk backdoor functions..."
        # Match real function calls like eval( ... ); word boundaries reduce noise
        local pattern="\\b(eval|base64_decode|shell_exec|passthru|system|exec|popen|proc_open|assert)\\b\\s*\\("
        local matches
        matches=$(eval "$grep_base -E \"$pattern\" \"$SITE_PATH\"" 2>/dev/null | grep -v -E "wp-includes/|wp-admin/|wp-content/plugins/|wp-content/themes/" | head -10)
        if [ -n "$matches" ]; then
            echo "!!! WARNING: Found high-risk functions. Review these files:"
            echo "$matches"
            ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$matches")
        else
            echo "OK: No high-risk functions found in non-standard locations."
        fi
    fi

    if [ "$DO_OBFUSCATED" -eq 1 ]; then
        echo " -> Searching for obfuscated code..."
        local pattern="\\b(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|str_replace|rawurldecode|urldecode|pack\\s*\\(\\s*['\"]H\\*['\"]|openssl_decrypt|preg_replace.*\\/e|assert|create_function)\\b"
        local matches
        matches=$(eval "$grep_base -E \"$pattern\" \"$SITE_PATH\"" 2>/dev/null | grep -v -E "wp-includes/|wp-admin/" | head -10)
        if [ -n "$matches" ]; then
            echo "!!! WARNING: Found potentially obfuscated code. Review these files:"
            echo "$matches"
            ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$matches")
        else
            echo "OK: No obvious obfuscated code found."
        fi
    fi

    if [ "$DO_PHPSHELL" -eq 1 ]; then
        echo " -> Searching for PHP shell signatures..."
        # Classic signatures + common shell UI/feature strings.
        local sig_pattern="C99Shell|\\bc99\\b|R57|\\br57\\b|WSO|B374K|FilesMan|IndoXploit|WebShell|FilesManager|File\\s*manager|Upload\\s*file|Download\\s*file|Symlink|php_uname|posix_geteuid|posix_getpwuid|\\bwhoami\\b|\\buname\\b|\\bid\\b|\\bpriv8\\b|cmd\\s*="
        local sig_matches
        sig_matches=$(eval "$grep_base -E \"$sig_pattern\" \"$SITE_PATH\"" 2>/dev/null)

        local name_matches
        name_matches=$(find "$SITE_PATH" -type f \( -iname "*wso*.php" -o -iname "*c99*.php" -o -iname "*r57*.php" -o -iname "*b374k*.php" -o -iname "*filesman*.php" -o -iname "webshell.php" -o -iname "shell.php" \) 2>/dev/null)

        local unique
        unique=$( { printf "%s\n" "$sig_matches"; printf "%s\n" "$name_matches"; } | grep -v -E "wp-includes/|wp-admin/" | sort -u )

        if [ -n "$unique" ]; then
            echo "!!! WARNING: Potential PHP shell indicators found. Review these files:"
            echo "$unique" | head -20
            ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$unique")
        else
            echo "OK: No explicit PHP shell signatures found."
        fi

        # --- Additional high-signal detectors ---

        echo " -> Searching for decode→exec chains (decoder + exec primitive in same file)..."
        local decoder_pattern="\\b(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|urldecode|pack\\s*\\(\\s*['\"]H\\*['\"]|openssl_decrypt)\\b"
        local exec_pattern="\\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|preg_replace)\\b"
        local decode_hits decode_exec_files
        decode_hits=$(eval "$grep_base -E \"$decoder_pattern\" \"$SITE_PATH\"" 2>/dev/null)
        if [ -n "$decode_hits" ]; then
            decode_exec_files=$(printf "%s\n" "$decode_hits" | while IFS= read -r f; do
                [ -z "$f" ] && continue
                if grep -q -I -E "$exec_pattern" "$f" 2>/dev/null; then
                    echo "$f"
                fi
            done | grep -v -E "wp-includes/|wp-admin/" | sort -u | head -20)
        else
            decode_exec_files=""
        fi
        if [ -n "$decode_exec_files" ]; then
            echo "!!! WARNING: Found decoder + exec primitive in the same file:"
            echo "$decode_exec_files"
            ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$decode_exec_files")
            if [ "$SHOW_CONTEXT" -eq 1 ]; then
                echo " -> Showing matched lines with line numbers (first 3 matches per file):"
                printf "%s\n" "$decode_exec_files" | while IFS= read -r f; do
                    [ -z "$f" ] && continue
                    echo "----- $f -----"
                    grep -n -I -E "($decoder_pattern|$exec_pattern)" -m 3 "$f" 2>/dev/null || echo "(no signature lines found)"
                done
            fi
        else
            echo "OK: No decoder+exec chain hits."
        fi

        echo " -> Searching for dangerous wrappers (php://input, data://, phar://, expect://)..."
        local wrapper_pattern="php:\\/\\/input|data:\\/\\/text|phar:\\/\\/|expect:\\/\\/"
        local wrapper_matches
        wrapper_matches=$(eval "$grep_base -E \"$wrapper_pattern\" \"$SITE_PATH\"" 2>/dev/null | grep -v -E "wp-includes/|wp-admin/" | head -20)
        if [ -n "$wrapper_matches" ]; then
            echo "!!! WARNING: Found suspicious stream wrapper usage:"
            echo "$wrapper_matches"
            ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$wrapper_matches")
            if [ "$SHOW_CONTEXT" -eq 1 ]; then
                echo " -> Showing matched lines with line numbers (first 3 matches per file):"
                printf "%s\n" "$wrapper_matches" | while IFS= read -r f; do
                    [ -z "$f" ] && continue
                    echo "----- $f -----"
                    grep -n -I -E "$wrapper_pattern" -m 3 "$f" 2>/dev/null || echo "(no signature lines found)"
                done
            fi
        else
            echo "OK: No suspicious wrapper usage found."
        fi

        echo " -> Searching for stealth toggles (error_reporting(0), set_time_limit(0), @eval, etc.)..."
        local stealth_pattern="error_reporting\\s*\\(\\s*0\\s*\\)|set_time_limit\\s*\\(\\s*0\\s*\\)|ini_set\\s*\\(\\s*['\"]display_errors['\"]\\s*,\\s*0\\s*\\)|@\\s*(eval|assert|system|exec|shell_exec|passthru)\\b"
        local stealth_matches
        stealth_matches=$(eval "$grep_base -E \"$stealth_pattern\" \"$SITE_PATH\"" 2>/dev/null | grep -v -E "wp-includes/|wp-admin/" | head -20)
        if [ -n "$stealth_matches" ]; then
            echo "!!! WARNING: Found stealth/anti-debug toggles:"
            echo "$stealth_matches"
            ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$stealth_matches")
            if [ "$SHOW_CONTEXT" -eq 1 ]; then
                echo " -> Showing matched lines with line numbers (first 3 matches per file):"
                printf "%s\n" "$stealth_matches" | while IFS= read -r f; do
                    [ -z "$f" ] && continue
                    echo "----- $f -----"
                    grep -n -I -E "$stealth_pattern" -m 3 "$f" 2>/dev/null || echo "(no signature lines found)"
                done
            fi
        else
            echo "OK: No stealth toggle patterns found."
        fi

        echo " -> Searching for variable-function calls combined with superglobals..."
        local varfunc_pattern="\\$[A-Za-z_][A-Za-z0-9_]*\\s*\\("
        local superglobal_any="\\$_(GET|POST|REQUEST|COOKIE)"
        local varfunc_hits varfunc_susp
        varfunc_hits=$(eval "$grep_base -E \"$varfunc_pattern\" \"$SITE_PATH\"" 2>/dev/null)
        if [ -n "$varfunc_hits" ]; then
            varfunc_susp=$(printf "%s\n" "$varfunc_hits" | while IFS= read -r f; do
                [ -z "$f" ] && continue
                if grep -q -I -E "$superglobal_any" "$f" 2>/dev/null; then
                    echo "$f"
                fi
            done | grep -v -E "wp-includes/|wp-admin/" | sort -u | head -20)
        else
            varfunc_susp=""
        fi
        if [ -n "$varfunc_susp" ]; then
            echo "!!! WARNING: Found variable-function calls in files that also reference superglobals:"
            echo "$varfunc_susp"
            ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$varfunc_susp")
            if [ "$SHOW_CONTEXT" -eq 1 ]; then
                echo " -> Showing matched lines with line numbers (first 3 matches per file):"
                printf "%s\n" "$varfunc_susp" | while IFS= read -r f; do
                    [ -z "$f" ] && continue
                    echo "----- $f -----"
                    grep -n -I -E "($varfunc_pattern|$superglobal_any)" -m 3 "$f" 2>/dev/null || echo "(no signature lines found)"
                done
            fi
        else
            echo "OK: No variable-function + superglobal combo hits."
        fi

        echo " -> Searching for high-entropy blobs in tiny PHP files..."
        local entropy_pattern="[A-Za-z0-9+/]{200,}={0,2}"
        local entropy_files
        entropy_files=$(find "$SITE_PATH" -type f -name "*.php" -exec sh -c '
            f="$1"; pat="$2"
            if ! grep -Iq . "$f" 2>/dev/null; then exit 0; fi
            lc=$(wc -l < "$f" 2>/dev/null)
            if [ -n "$lc" ] && [ "$lc" -lt 20 ] && grep -q -E "$pat" "$f" 2>/dev/null; then
                echo "$f"
            fi
        ' sh {} "$entropy_pattern" \; 2>/dev/null | grep -v -E "wp-includes/|wp-admin/" | head -20)
        if [ -n "$entropy_files" ]; then
            echo "!!! WARNING: Found small PHP files containing large base64-ish blobs:"
            echo "$entropy_files"
            ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$entropy_files")
            if [ "$SHOW_CONTEXT" -eq 1 ]; then
                echo " -> Showing matched lines with line numbers (first 3 matches per file):"
                printf "%s\n" "$entropy_files" | while IFS= read -r f; do
                    [ -z "$f" ] && continue
                    echo "----- $f -----"
                    grep -n -I -E "$entropy_pattern" -m 3 "$f" 2>/dev/null || echo "(no signature lines found)"
                done
            fi
        else
            echo "OK: No high-entropy blob hits in small PHP files."
        fi
    fi

    if [ "$DO_DYN_EXEC" -eq 1 ]; then
        echo " -> Searching for dynamic function execution patterns..."
        local pattern="(\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*).*['\"](eval|system|shell_exec|passthru|exec|assert|create_function)['\"]"
        local matches
        matches=$(eval "$grep_base -E \"$pattern\" \"$SITE_PATH\"" 2>/dev/null | grep -v -E "wp-includes/|wp-admin/" | head -10)
        if [ -n "$matches" ]; then
            echo "!!! WARNING: Found patterns suggesting dynamic function execution. Review these files:"
            echo "$matches"
            ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$matches")
        else
            echo "OK: No obvious dynamic execution patterns found."
        fi
    fi

    if [ "$DO_ONELINER" -eq 1 ]; then
        echo " -> Searching for potential one-liner shells..."
        local oneliner_files
        oneliner_files=$(find "$SITE_PATH" -type f -name "*.php" -exec sh -c 'line_count=$(wc -l < "$1"); [ "$line_count" -lt 5 ] && grep -q -i -E "(eval|system|shell_exec|passthru|exec)" "$1" && echo "$1"' sh {} \; 2>/dev/null)

        if [ -n "$oneliner_files" ]; then
            echo "!!! WARNING: Found very small PHP files with dangerous functions (potential one-liner shells):"
            local filtered
            filtered=$(printf "%s\n" "$oneliner_files" | grep -v -E "wp-includes/|wp-admin/" | head -10)
            [ -n "$filtered" ] && echo "$filtered" || echo " (Found files were in standard directories, but still worth checking)"
            ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$oneliner_files")
        else
            echo "OK: No suspicious one-liner PHP files found."
        fi
    fi
}
