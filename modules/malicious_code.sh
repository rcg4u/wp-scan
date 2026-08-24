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
        local pattern="eval\\s*\(|base64_decode\\s*\(|shell_exec\\s*\(|passthru\\s*\(|system\\s*\(|exec\\s*\("
        local matches
        matches=$(eval "$grep_base -E \"$pattern\" \"$SITE_PATH\"" 2>/dev/null | grep -v -E "wp-includes/|wp-admin/|wp-content/plugins/|wp-content/themes/" | head -10)
        if [ -n "$matches" ]; then
            echo "!!! WARNING: Found high-risk functions. Review these files:"
            highlight_high "These files contain high-risk function calls (eval/system/exec/etc.) that may allow remote code execution or shell access. Review immediately."
            echo "$matches"
            ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$matches")
        else
            echo "OK: No high-risk functions found in non-standard locations."
        fi
    fi

    if [ "$DO_OBFUSCATED" -eq 1 ]; then
        echo " -> Searching for obfuscated code..."
        local pattern="base64_decode|gzinflate\(|str_rot13\(|strrev\(|str_replace\(|preg_replace.*\/e|assert\(|create_function\("
        local matches
        matches=$(eval "$grep_base -E \"$pattern\" \"$SITE_PATH\"" 2>/dev/null | grep -v -E "wp-includes/|wp-admin/" | head -10)
        if [ -n "$matches" ]; then
            echo "!!! WARNING: Found potentially obfuscated code. Review these files:"
            highlight_caution "Obfuscated code (base64/gzinflate/etc.) often hides malicious payloads; inspect decoded content before restoring or deleting."
            echo "$matches"
            ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$matches")
        else
            echo "OK: No obvious obfuscated code found."
        fi
    fi

    if [ "$DO_PHPSHELL" -eq 1 ]; then
        echo " -> Searching for PHP shell signatures..."
        local sig_pattern="C99Shell|c99|R57|r57|WSO|B374K|FilesMan|IndoXploit|WebShell|FilesManager|Symlink|bypass|shell|cmd|backdoor|encoded by|gaza|hacker|priv8"
        local sig_matches
        sig_matches=$(eval "$grep_base -E \"$sig_pattern\" \"$SITE_PATH\"" 2>/dev/null)

        local name_matches
        name_matches=$(find "$SITE_PATH" -type f \( -iname "*wso*.php" -o -iname "*c99*.php" -o -iname "*r57*.php" -o -iname "*b374k*.php" -o -iname "*filesman*.php" -o -iname "webshell.php" -o -iname "shell.php" \) 2>/dev/null)

        local unique
        unique=$( { printf "%s\n" "$sig_matches"; printf "%s\n" "$name_matches"; } | grep -v -E "wp-includes/|wp-admin/" | sort -u )

        if [ -n "$unique" ]; then
            echo "!!! WARNING: Potential PHP shell indicators found. Review these files:"
            highlight_high "Known web shell signatures detected; these typically allow remote command execution and full site compromise."
            echo "$unique" | head -20
            ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$unique")
        else
            echo "OK: No explicit PHP shell signatures found."
        fi
    fi

    if [ "$DO_DYN_EXEC" -eq 1 ]; then
        echo " -> Searching for dynamic function execution patterns..."
        local pattern="(\$\\w+\\s*).*['\"](eval|system|shell_exec|passthru|exec|assert|create_function)['\"]"
        local matches
        matches=$(eval "$grep_base -E \"$pattern\" \"$SITE_PATH\"" 2>/dev/null | grep -v -E "wp-includes/|wp-admin/" | head -10)
        if [ -n "$matches" ]; then
            echo "!!! WARNING: Found patterns suggesting dynamic function execution. Review these files:"
            highlight_high "Dynamic function execution enables attackers to build and invoke functions at runtime, often bypassing static detection; treat as high risk."
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
            highlight_high "One-line or very small PHP files with exec/eval are commonly tiny webshells that provide immediate remote command execution; investigate immediately."
            local filtered
            filtered=$(printf "%s\n" "$oneliner_files" | grep -v -E "wp-includes/|wp-admin/" | head -10)
            [ -n "$filtered" ] && echo "$filtered" || echo " (Found files were in standard directories, but still worth checking)"
            ZIP_CANDIDATES=$(printf "%s\n%s\n" "$ZIP_CANDIDATES" "$oneliner_files")
        else
            echo "OK: No suspicious one-liner PHP files found."
        fi
    fi
}
