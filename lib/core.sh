#!/usr/bin/env bash

# Shared globals + CLI parsing + entry orchestration.

# --- GLOBAL VARIABLES & CONFIGURATION ---
# Allow configuration through CLI flags or environment variables
EMAIL_TO="${WP_SCAN_EMAIL_TO:-}"
EMAIL_FROM="${WP_SCAN_EMAIL_FROM:-}"
EMAIL_SUBJECT="${WP_SCAN_EMAIL_SUBJECT:-}"
EMAIL_ALWAYS="${WP_SCAN_EMAIL_ALWAYS:-0}"

ARG_SITE=""
SITE_PATH=""
SITE_OWNER=""
LOG_FILE=""
ZIP_CANDIDATES=""
# Remote / runtime flags
DRY_RUN=0
SARIF_FILE=""
CSV_FILE=""
SIGNATURES_FILE="${SIGNATURES_DIR:-$(dirname "$0")/../signatures}/latest-signatures.txt"

# WordPress mode (default on). Disable with --no-wordpress
WP_MODE=1
# Show context toggle (2 lines before/after around matched signatures)
SHOW_CONTEXT=0
# Exclude cache from recent file scans
EXCLUDE_CACHE=1
# JSON output toggle
JSON_OUTPUT=0
# Exit code mode: 'binary' (0/1) or 'count' (0-254)
EXIT_CODE_MODE="binary"
# Zip archive toggle
ZIP_ENABLED=0
ZIP_TARGET_ZIP=""
# Force-enable all modules
SCAN_ALL=0

# Interactive menu toggle
MENU_MODE=0

# If any module trigger is passed on CLI, run only selected modules.
EXPLICIT_MODULE_SELECTION=0

# Module toggles (default: run all)
DO_RECENT=1; DO_SUSPICIOUS=1; DO_UPLOADS=1; DO_UPLOADS_PHP=1; DO_BACKDOOR=1
DO_OBFUSCATED=1; DO_PHPSHELL=1; DO_HIDDEN=1; DO_SUPERGLOBAL=1; DO_CURL=1
DO_WPVER=1; DO_PERMS=1; DO_IMMUTABLE=1; DO_VERIFICATION=1; DO_ACCESS_LOGS=1
DO_DYN_EXEC=1; DO_ONELINER=1; DO_WP_CLI=1

# --- Helper functions shared across modules ---

enable_only_defaults() {
    DO_RECENT=0; DO_SUSPICIOUS=0; DO_UPLOADS=0; DO_UPLOADS_PHP=0; DO_BACKDOOR=0
    DO_OBFUSCATED=0; DO_PHPSHELL=0; DO_HIDDEN=0; DO_SUPERGLOBAL=0; DO_CURL=0
    DO_WPVER=0; DO_PERMS=0; DO_IMMUTABLE=0; DO_VERIFICATION=0; DO_ACCESS_LOGS=0
    DO_DYN_EXEC=0; DO_ONELINER=0; DO_WP_CLI=0
}

set_module_flag() {
    case "$1" in
        recent|suspicious|uploads|backdoor|obfuscation|curl|wpver|perms|immutable|verification|access_logs|dyn-exec|oneliner|wp-cli)
            # Map name -> DO_<NAME> toggle. bash supports indirect via printf+eval.
            local var="DO_${1//-/_}"
            eval "$var=1"
            ;;
        phpshell) DO_PHPSHELL=1 ;;
        uploads-php) DO_UPLOADS_PHP=1 ;;
        all)
            DO_RECENT=1; DO_SUSPICIOUS=1; DO_UPLOADS=1; DO_UPLOADS_PHP=1; DO_BACKDOOR=1
            DO_OBFUSCATED=1; DO_PHPSHELL=1; DO_HIDDEN=1; DO_SUPERGLOBAL=1; DO_CURL=1
            DO_WPVER=1; DO_PERMS=1; DO_IMMUTABLE=1; DO_VERIFICATION=1; DO_ACCESS_LOGS=1
            DO_DYN_EXEC=1; DO_ONELINER=1; DO_WP_CLI=1
            ;;
    esac
}

clear_module_flag() {
    case "$1" in
        recent|suspicious|uploads|backdoor|obfuscation|curl|wpver|perms|immutable|verification|access_logs|dyn-exec|oneliner|wp-cli)
            local var="DO_${1//-/_}"
            eval "$var=0"
            ;;
        phpshell) DO_PHPSHELL=0 ;;
        uploads-php) DO_UPLOADS_PHP=0 ;;
        all)
            enable_only_defaults
            ;;
    esac
}

# Stubs: the implementation is provided by modules/*.sh
scan_recent_files() { :; }
scan_suspicious_names() { :; }
scan_uploads() { :; }
scan_uploads_php() { :; }
scan_verification_files() { :; }
scan_access_logs() { :; }
scan_malicious_code() { :; }
scan_hidden_files() { :; }
scan_superglobal() { :; }
scan_curl() { :; }
scan_wp_version() { :; }
scan_permissions() { :; }
scan_immutable() { :; }
scan_wp_cli() { :; }

usage() {
    cat <<'USAGE'
Usage: ./wp-scan.sh [options] /path/to/site/root

Options:
  --email <addr>         Send report to this address when warnings found
  --email-always         Always send email even when no warnings
  --email-from <addr>    Sender address (sendmail/msmtp)
  --email-subject <text> Base subject; status appended
  --menu                 Interactive menu to select scan modules
  --only <modules>       Run only these modules (csv or space-separated)
  --skip <modules>       Skip these modules (csv or space-separated)
  --no-wordpress         Scan generic site; skip WordPress-specific checks
  --sc                   Show 2 lines of code context around matched signatures
  --json                 Output a minimal JSON summary at the end
  --exit-code <mode>     Exit code mode: 'binary' (0/1) or 'count' (0-254)
  --zip <filename.zip>   Zip up flagged files into the specified archive
  --scan-all             Force-enable all modules for this run

Module Triggers (enable/disable individually):
  --recent / --no-recent
  --suspicious / --no-suspicious
  --uploads / --no-uploads
  --backdoor / --no-backdoor
  --obfuscation / --no-obfuscation
  --phpshell / --no-phpshell
  --uploads-php / --no-uploads-php
  --hidden / --no-hidden
  --superglobal / --no-superglobal
  --curl / --no-curl
  --wpver / --no-wpver
  --perms / --no-perms
  --immutable / --no-immutable
  --verification / --no-verification
  --access-logs / --no-access-logs
  --dyn-exec / --no-dyn-exec
  --oneliner / --no-oneliner
  --wp-cli / --no-wp-cli
  --help                 Show usage

Example:
  ./wp-scan.sh --only recent,uploads --email admin@example.com /var/www/html/site
USAGE
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -e|--email) EMAIL_TO="$2"; shift 2 ;;
            --email-from) EMAIL_FROM="$2"; shift 2 ;;
            --email-subject) EMAIL_SUBJECT="$2"; shift 2 ;;
            --email-always) EMAIL_ALWAYS=1; shift ;;
            --menu) MENU_MODE=1; shift ;;
            --only)
                enable_only_defaults
                local LIST
                LIST=$(echo "$2" | tr ',' ' ')
                for m in $LIST; do set_module_flag "$m"; done
                shift 2
                ;;
            --skip)
                local LIST
                LIST=$(echo "$2" | tr ',' ' ')
                for m in $LIST; do clear_module_flag "$m"; done
                shift 2
                ;;
            --no-wordpress) WP_MODE=0; shift ;;
            --sc) SHOW_CONTEXT=1; shift ;;
            --json) JSON_OUTPUT=1; shift ;;
            --exit-code) EXIT_CODE_MODE="$2"; shift 2 ;;
            --zip) ZIP_ENABLED=1; ZIP_TARGET_ZIP="$2"; shift 2 ;;
            --with-cache) EXCLUDE_CACHE=0; shift ;;
            --scan-all) SCAN_ALL=1; set_module_flag all; shift ;;

            # Module triggers. If the user specifies any of these, we switch to
            # explicit selection mode and run only modules they enable.
            --recent) EXPLICIT_MODULE_SELECTION=1; set_module_flag recent; shift ;;
            --no-recent) EXPLICIT_MODULE_SELECTION=1; clear_module_flag recent; shift ;;
            --suspicious) EXPLICIT_MODULE_SELECTION=1; set_module_flag suspicious; shift ;;
            --no-suspicious) EXPLICIT_MODULE_SELECTION=1; clear_module_flag suspicious; shift ;;
            --uploads) EXPLICIT_MODULE_SELECTION=1; set_module_flag uploads; shift ;;
            --no-uploads) EXPLICIT_MODULE_SELECTION=1; clear_module_flag uploads; shift ;;
            --backdoor) EXPLICIT_MODULE_SELECTION=1; set_module_flag backdoor; shift ;;
            --no-backdoor) EXPLICIT_MODULE_SELECTION=1; clear_module_flag backdoor; shift ;;
            --obfuscation) EXPLICIT_MODULE_SELECTION=1; set_module_flag obfuscation; shift ;;
            --no-obfuscation) EXPLICIT_MODULE_SELECTION=1; clear_module_flag obfuscation; shift ;;
            --phpshell) EXPLICIT_MODULE_SELECTION=1; DO_PHPSHELL=1; shift ;;
            --no-phpshell) EXPLICIT_MODULE_SELECTION=1; DO_PHPSHELL=0; shift ;;
            --uploads-php) EXPLICIT_MODULE_SELECTION=1; DO_UPLOADS_PHP=1; shift ;;
            --no-uploads-php) EXPLICIT_MODULE_SELECTION=1; DO_UPLOADS_PHP=0; shift ;;
            --hidden) EXPLICIT_MODULE_SELECTION=1; set_module_flag hidden; shift ;;
            --no-hidden) EXPLICIT_MODULE_SELECTION=1; clear_module_flag hidden; shift ;;
            --superglobal) EXPLICIT_MODULE_SELECTION=1; set_module_flag superglobal; shift ;;
            --no-superglobal) EXPLICIT_MODULE_SELECTION=1; clear_module_flag superglobal; shift ;;
            --curl) EXPLICIT_MODULE_SELECTION=1; set_module_flag curl; shift ;;
            --no-curl) EXPLICIT_MODULE_SELECTION=1; clear_module_flag curl; shift ;;
            --wpver) EXPLICIT_MODULE_SELECTION=1; set_module_flag wpver; shift ;;
            --no-wpver) EXPLICIT_MODULE_SELECTION=1; clear_module_flag wpver; shift ;;
            --perms) EXPLICIT_MODULE_SELECTION=1; set_module_flag perms; shift ;;
            --no-perms) EXPLICIT_MODULE_SELECTION=1; clear_module_flag perms; shift ;;
            --immutable) EXPLICIT_MODULE_SELECTION=1; set_module_flag immutable; shift ;;
            --no-immutable) EXPLICIT_MODULE_SELECTION=1; clear_module_flag immutable; shift ;;
            --verification) EXPLICIT_MODULE_SELECTION=1; set_module_flag verification; shift ;;
            --no-verification) EXPLICIT_MODULE_SELECTION=1; clear_module_flag verification; shift ;;
            --access-logs) EXPLICIT_MODULE_SELECTION=1; set_module_flag access_logs; shift ;;
            --no-access-logs) EXPLICIT_MODULE_SELECTION=1; clear_module_flag access_logs; shift ;;
            --dyn-exec) EXPLICIT_MODULE_SELECTION=1; set_module_flag dyn-exec; shift ;;
            --no-dyn-exec) EXPLICIT_MODULE_SELECTION=1; clear_module_flag dyn-exec; shift ;;
            --oneliner) EXPLICIT_MODULE_SELECTION=1; set_module_flag oneliner; shift ;;
            --no-oneliner) EXPLICIT_MODULE_SELECTION=1; clear_module_flag oneliner; shift ;;
            --wp-cli) EXPLICIT_MODULE_SELECTION=1; DO_WP_CLI=1; shift ;;
            --no-wp-cli) EXPLICIT_MODULE_SELECTION=1; DO_WP_CLI=0; shift ;;
            --dry-run) DRY_RUN=1; shift ;;
            --sarif) SARIF_FILE="$2"; shift 2 ;;
            --csv) CSV_FILE="$2"; shift 2 ;;

            -h|--help)
                usage
                exit 0
                ;;
            *)
                if [ -z "$ARG_SITE" ]; then
                    ARG_SITE="$1"
                    shift
                else
                    echo "Warning: Unrecognized extra argument '$1' will be ignored."
                    shift
                fi
                ;;
        esac
    done

    # If any module toggles were used directly, default to 'only those toggles'.
    if [ "${EXPLICIT_MODULE_SELECTION:-0}" -eq 1 ] && [ "${SCAN_ALL:-0}" -eq 0 ]; then
        local _r=$DO_RECENT _s=$DO_SUSPICIOUS _u=$DO_UPLOADS _up=$DO_UPLOADS_PHP _b=$DO_BACKDOOR
        local _o=$DO_OBFUSCATED _ps=$DO_PHPSHELL _h=$DO_HIDDEN _sg=$DO_SUPERGLOBAL _c=$DO_CURL
        local _wv=$DO_WPVER _p=$DO_PERMS _im=$DO_IMMUTABLE _vf=$DO_VERIFICATION _al=$DO_ACCESS_LOGS
        local _de=$DO_DYN_EXEC _ol=$DO_ONELINER _wpc=$DO_WP_CLI

        enable_only_defaults

        DO_RECENT=$_r; DO_SUSPICIOUS=$_s; DO_UPLOADS=$_u; DO_UPLOADS_PHP=$_up; DO_BACKDOOR=$_b
        DO_OBFUSCATED=$_o; DO_PHPSHELL=$_ps; DO_HIDDEN=$_h; DO_SUPERGLOBAL=$_sg; DO_CURL=$_c
        DO_WPVER=$_wv; DO_PERMS=$_p; DO_IMMUTABLE=$_im; DO_VERIFICATION=$_vf; DO_ACCESS_LOGS=$_al
        DO_DYN_EXEC=$_de; DO_ONELINER=$_ol; DO_WP_CLI=$_wpc
    fi
}

validate_site() {
    if [ -z "${ARG_SITE:-}" ]; then
        usage
        exit 0
    fi

    SITE_PATH=$(realpath "$ARG_SITE")

    if [ ! -d "$SITE_PATH" ]; then
        echo "Error: Directory '$SITE_PATH' not found."
        exit 1
    fi

    if [ "$WP_MODE" -eq 1 ] && [ ! -f "$SITE_PATH/wp-config.php" ]; then
        echo "Error: wp-config.php not found in '$SITE_PATH'. Is this a WordPress root?"
        exit 1
    fi
}

setup_logging() {
    if command -v mktemp >/dev/null 2>&1; then
        LOG_FILE=$(mktemp -t wp-scan-XXXXXX.log)
    else
        LOG_FILE="$SITE_PATH/wp-scan-$(date +%Y%m%d%H%M%S).log"
    fi

    if command -v tee >/dev/null 2>&1; then
        exec > >(tee -a "$LOG_FILE") 2>&1
    else
        exec >>"$LOG_FILE" 2>&1
    fi
}

apply_non_wp_mode_adjustments() {
    if [ "$WP_MODE" -eq 0 ] && [ "$SCAN_ALL" -eq 0 ]; then
        DO_WPVER=0; DO_UPLOADS=0; DO_UPLOADS_PHP=0; DO_WP_CLI=0
    fi
}

send_email_if_needed() {
    [ -n "$EMAIL_TO" ] || return 0

    local WARN_COUNT
    WARN_COUNT=$(grep -c "!!! WARNING" "$LOG_FILE" 2>/dev/null || echo 0)

    if [ "$EMAIL_ALWAYS" = "1" ] || [ "${WARN_COUNT}" -gt 0 ]; then
        local STATUS="OK"
        [ "${WARN_COUNT}" -gt 0 ] && STATUS="WARNINGS"
        local SUBJECT
        SUBJECT="${EMAIL_SUBJECT:-Generic WP Scan: $SITE_PATH} [$STATUS]"

        if command -v mail >/dev/null 2>&1 && [ -z "$EMAIL_FROM" ]; then
            mail -s "$SUBJECT" "$EMAIL_TO" < "$LOG_FILE"
            echo "Notification email sent via 'mail' to $EMAIL_TO."
        elif command -v sendmail >/dev/null 2>&1; then
            {
                echo "To: $EMAIL_TO"
                echo "From: ${EMAIL_FROM:-no-reply@localhost}"
                echo "Subject: $SUBJECT"
                echo "Content-Type: text/plain; charset=UTF-8"
                echo
                cat "$LOG_FILE"
            } | sendmail -t
            echo "Notification email sent via 'sendmail' to $EMAIL_TO."
        elif command -v msmtp >/dev/null 2>&1; then
            {
                echo "To: $EMAIL_TO"
                echo "From: ${EMAIL_FROM:-no-reply@localhost}"
                echo "Subject: $SUBJECT"
                echo "Content-Type: text/plain; charset=UTF-8"
                echo
                cat "$LOG_FILE"
            } | msmtp -t
            echo "Notification email sent via 'msmtp' to $EMAIL_TO."
        else
            echo "Email not sent: no mail/sendmail/msmtp found."
        fi
    else
        echo "Email not sent: no warnings found and --email-always not specified."
    fi
}

output_json_if_requested() {
    [ "$JSON_OUTPUT" -eq 1 ] || return 0

    local WARN_COUNT
    WARN_COUNT=$(grep -c "!!! WARNING" "$LOG_FILE" 2>/dev/null || echo 0)

    local STATUS="OK"
    [ "$WARN_COUNT" -gt 0 ] && STATUS="WARNINGS"

    # Minimal summary (kept intentionally small and similar to previous behaviour)
    local ACCESS_LOG_COUNT
    ACCESS_LOG_COUNT=$(grep -c "Suspicious access log requests found" "$LOG_FILE" 2>/dev/null || echo 0)

    echo "{"
    echo " \"site\": \"$SITE_PATH\","
    echo " \"status\": \"$STATUS\","
    echo " \"warnings\": $WARN_COUNT,"
    echo " \"modules\": {"
    echo " \"access_logs\": $ACCESS_LOG_COUNT"
    echo " }"
    echo "}"
}

emit_csv() {
    # emit_csv <csv_file> <file_list>
    local csv_file="$1"; shift || true
    local file_list="$1"; shift || true
    [ -n "$csv_file" ] || return 0
    if [ ! -f "$file_list" ]; then
        echo "CSV emission skipped: file list not found: $file_list"
        return 0
    fi

    {
        echo "file,module,message"
        while IFS= read -r f; do
            printf '%s,%s,%s\n' "$f" "wp-scan" "flagged" 
        done < "$file_list"
    } > "$csv_file"
    echo "CSV report written: $csv_file"
}

emit_sarif() {
    # emit_sarif <sarif_file> <file_list>
    local sarif_file="$1"; shift || true
    local file_list="$1"; shift || true
    [ -n "$sarif_file" ] || return 0
    if [ ! -f "$file_list" ]; then
        echo "SARIF emission skipped: file list not found: $file_list"
        return 0
    fi

    # Minimal SARIF v2.1.0 skeleton with one run and results for each file
    local results
    results="[]"
    while IFS= read -r f; do
        # create a simple result object
        # escape backslashes and quotes in filename
        esc=$(printf '%s' "$f" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g')
        results=$(printf '%s' "$results" | jq -c --arg file "$esc" '. += [{"ruleId":"wp-scan","level":"warning","message":{"text":"flagged by wp-scan"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":$file}}]} }]')
    done < "$file_list"

    # If jq is not available, fallback to a very small handcrafted JSON (best-effort)
    if command -v jq >/dev/null 2>&1; then
        jq -n --argjson results "$results" '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"wp-scan"}},"results":$results}]}' > "$sarif_file"
    else
        # naive JSON assembly
        echo '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"wp-scan"}},"results":[' > "$sarif_file"
        first=1
        while IFS= read -r f; do
            esc=$(printf '%s' "$f" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g')
            if [ "$first" -eq 1 ]; then
                first=0
            else
                echo ',' >> "$sarif_file"
            fi
            echo "{\"ruleId\":\"wp-scan\",\"level\":\"warning\",\"message\":{\"text\":\"flagged by wp-scan\"},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"${esc}\"}}}] }" >> "$sarif_file"
        done < "$file_list"
        echo ']}}]}' >> "$sarif_file"
    fi
    echo "SARIF report written: $sarif_file"
}

zip_flagged_files_if_requested() {
    [ "$ZIP_ENABLED" -eq 1 ] || return 0

    if ! command -v zip >/dev/null 2>&1; then
        echo "Zip requested but 'zip' command not found. Skipping archive creation."
        return 0
    fi

    echo "Preparing zip archive of flagged files: $ZIP_TARGET_ZIP"
    local FILE_LIST
    FILE_LIST=$(mktemp -t wp-scan-ziplist-XXXXXX.txt)

    # Normalize input and collect existing files
    printf "%s\n" "$ZIP_CANDIDATES" | sed '/^\s*$/d' | while IFS= read -r p; do
        [ -f "$p" ] && echo "$p"
    done | sort -u > "$FILE_LIST"

    local COUNT
    COUNT=$(wc -l < "$FILE_LIST" | awk '{print $1}')

    if [ "$COUNT" -gt 0 ]; then
        if [ "$DRY_RUN" -eq 1 ]; then
            echo "DRY-RUN: would create zip: $ZIP_TARGET_ZIP with $COUNT files (showing first 20):"
            head -n 20 "$FILE_LIST" || true
        else
            zip -@ "$ZIP_TARGET_ZIP" < "$FILE_LIST"

            local MANIFEST_TMP
            MANIFEST_TMP=$(mktemp -t wp-scan-manifest-XXXXXX.txt)
            {
                echo "wp-scan manifest"
                echo "site: $SITE_PATH"
                echo "created: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
                echo "files:"
                cat "$FILE_LIST"
            } > "$MANIFEST_TMP"

            local MANIFEST_NAME="wp-scan-manifest.txt"
            cp "$MANIFEST_TMP" "$MANIFEST_NAME"
            zip "$ZIP_TARGET_ZIP" "$MANIFEST_NAME" >/dev/null 2>&1
            rm -f "$MANIFEST_NAME" "$MANIFEST_TMP"

            echo "Zip created ($COUNT files): $ZIP_TARGET_ZIP (includes $MANIFEST_NAME)"
        fi

        # Emit SARIF/CSV if requested
        if [ -n "$SARIF_FILE" ]; then
            emit_sarif "$SARIF_FILE" "$FILE_LIST"
        fi
        if [ -n "$CSV_FILE" ]; then
            emit_csv "$CSV_FILE" "$FILE_LIST"
        fi
    else
        echo "No files to zip. Archive not created."
    fi

    rm -f "$FILE_LIST"
}

exit_with_mode() {
    local WARN_COUNT
    WARN_COUNT=$(grep -c "!!! WARNING" "$LOG_FILE" 2>/dev/null || echo 0)

    if [ "$EXIT_CODE_MODE" = "count" ]; then
        local EC=$WARN_COUNT
        [ "$EC" -gt 254 ] && EC=254
        exit "$EC"
    else
        [ "$WARN_COUNT" -gt 0 ] && exit 1 || exit 0
    fi
}

main() {
    parse_args "$@"
    validate_site
    apply_non_wp_mode_adjustments
    setup_logging

    echo "=========================================================================="
    echo "Starting Generic WordPress Security Scan for: $SITE_PATH"
    echo "=========================================================================="

    if [ "${MENU_MODE:-0}" -eq 1 ]; then
        interactive_menu
    fi

    run_dispatch

    echo -e "\n=========================================================================="
    echo "Scan Complete."
    echo "=========================================================================="
    echo "Disclaimer: This script is a powerful scanning aid. It may produce false"
    echo "positives. All findings should be manually investigated and verified."
    echo "=========================================================================="

    send_email_if_needed
    output_json_if_requested
    zip_flagged_files_if_requested
    exit_with_mode
}
