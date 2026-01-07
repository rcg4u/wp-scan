#!/usr/bin/env bash

print_module_status() {
    local key="$1"
    local var="$2"
    local val="${!var}"
    if [ "$val" -eq 1 ]; then
        printf "[x] %s\n" "$key"
    else
        printf "[ ] %s\n" "$key"
    fi
}

interactive_menu() {
    echo ""
    echo "Interactive Module Menu"
    echo "========================"
    echo "Type one or more triggers (space/comma separated)."
    echo "Commands: a=all, n=none, r=run, c=console, q=quit"

    while true; do
        echo ""
        echo "Current selection:"
        echo "  1) $(print_module_status "recent" DO_RECENT | tr -d '\n')        (triggers: 1, recent)"
        echo "  2) $(print_module_status "suspicious" DO_SUSPICIOUS | tr -d '\n')    (triggers: 2, suspicious)"
        echo "  3) $(print_module_status "uploads" DO_UPLOADS | tr -d '\n')       (triggers: 3, uploads)"
        echo "  4) $(print_module_status "uploads-php" DO_UPLOADS_PHP | tr -d '\n')   (triggers: 4, uploads-php)"
        echo "  5) $(print_module_status "backdoor" DO_BACKDOOR | tr -d '\n')      (triggers: 5, backdoor)"
        echo "  6) $(print_module_status "obfuscation" DO_OBFUSCATED | tr -d '\n')   (triggers: 6, obfuscation)"
        echo "  7) $(print_module_status "phpshell" DO_PHPSHELL | tr -d '\n')      (triggers: 7, phpshell)"
        echo "  8) $(print_module_status "hidden" DO_HIDDEN | tr -d '\n')        (triggers: 8, hidden)"
        echo "  9) $(print_module_status "superglobal" DO_SUPERGLOBAL | tr -d '\n')   (triggers: 9, superglobal)"
        echo " 10) $(print_module_status "curl" DO_CURL | tr -d '\n')          (triggers: 10, curl)"
        echo " 11) $(print_module_status "wpver" DO_WPVER | tr -d '\n')         (triggers: 11, wpver)"
        echo " 12) $(print_module_status "perms" DO_PERMS | tr -d '\n')         (triggers: 12, perms)"
        echo " 13) $(print_module_status "immutable" DO_IMMUTABLE | tr -d '\n')      (triggers: 13, immutable)"
        echo " 14) $(print_module_status "verification" DO_VERIFICATION | tr -d '\n')  (triggers: 14, verification)"
        echo " 15) $(print_module_status "access-logs" DO_ACCESS_LOGS | tr -d '\n')    (triggers: 15, access-logs)"
        echo " 16) $(print_module_status "dyn-exec" DO_DYN_EXEC | tr -d '\n')      (triggers: 16, dyn-exec)"
        echo " 17) $(print_module_status "oneliner" DO_ONELINER | tr -d '\n')      (triggers: 17, oneliner)"
        echo " 18) $(print_module_status "wp-cli" DO_WP_CLI | tr -d '\n')        (triggers: 18, wp-cli)"

        printf "\nSelect> "
        read -r line

        # Allow multiple triggers per line: split on commas and whitespace.
        line=$(printf "%s" "$line" | tr ',' ' ')

        # shellcheck disable=SC2086
        set -- $line
        if [ $# -eq 0 ]; then
            continue
        fi

        local token
        for token in "$@"; do
            case "$token" in
                1|recent) DO_RECENT=$((1-DO_RECENT)) ;;
                2|suspicious) DO_SUSPICIOUS=$((1-DO_SUSPICIOUS)) ;;
                3|uploads) DO_UPLOADS=$((1-DO_UPLOADS)) ;;
                4|uploads-php) DO_UPLOADS_PHP=$((1-DO_UPLOADS_PHP)) ;;
                5|backdoor) DO_BACKDOOR=$((1-DO_BACKDOOR)) ;;
                6|obfuscation) DO_OBFUSCATED=$((1-DO_OBFUSCATED)) ;;
                7|phpshell) DO_PHPSHELL=$((1-DO_PHPSHELL)) ;;
                8|hidden) DO_HIDDEN=$((1-DO_HIDDEN)) ;;
                9|superglobal) DO_SUPERGLOBAL=$((1-DO_SUPERGLOBAL)) ;;
                10|curl) DO_CURL=$((1-DO_CURL)) ;;
                11|wpver) DO_WPVER=$((1-DO_WPVER)) ;;
                12|perms) DO_PERMS=$((1-DO_PERMS)) ;;
                13|immutable) DO_IMMUTABLE=$((1-DO_IMMUTABLE)) ;;
                14|verification) DO_VERIFICATION=$((1-DO_VERIFICATION)) ;;
                15|access-logs|access_logs) DO_ACCESS_LOGS=$((1-DO_ACCESS_LOGS)) ;;
                16|dyn-exec|dyn_exec) DO_DYN_EXEC=$((1-DO_DYN_EXEC)) ;;
                17|oneliner) DO_ONELINER=$((1-DO_ONELINER)) ;;
                18|wp-cli|wp_cli) DO_WP_CLI=$((1-DO_WP_CLI)) ;;
                a|A|all) set_module_flag all ;;
                n|N|none) enable_only_defaults ;;
                r|R|run) return 0 ;;
                c|C|console) echo "Exiting menu."; exit 0 ;;
                q|Q|quit) echo "Aborted by user."; exit 0 ;;
                *) echo "Unknown selection: '$token'" ;;
            esac
        done
    done
}
