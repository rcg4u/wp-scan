#!/usr/bin/env bash
# ====================================================================
# Generic WordPress Security Scanner (Modular)
# 
# Entry point that wires CLI parsing + module loading + dispatcher.
# Keep this file small; implementation lives in lib/ and modules/.
# ====================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/core.sh
. "$SCRIPT_DIR/lib/core.sh"
# shellcheck source=lib/menu.sh
. "$SCRIPT_DIR/lib/menu.sh"
# shellcheck source=lib/dispatcher.sh
. "$SCRIPT_DIR/lib/dispatcher.sh"

# Modules
# shellcheck source=modules/recent.sh
. "$SCRIPT_DIR/modules/recent.sh"
# shellcheck source=modules/suspicious.sh
. "$SCRIPT_DIR/modules/suspicious.sh"
# shellcheck source=modules/uploads.sh
. "$SCRIPT_DIR/modules/uploads.sh"
# shellcheck source=modules/uploads_php.sh
. "$SCRIPT_DIR/modules/uploads_php.sh"
# shellcheck source=modules/verification.sh
. "$SCRIPT_DIR/modules/verification.sh"
# shellcheck source=modules/access_logs.sh
. "$SCRIPT_DIR/modules/access_logs.sh"
# shellcheck source=modules/malicious_code.sh
. "$SCRIPT_DIR/modules/malicious_code.sh"
# shellcheck source=modules/hidden_files.sh
. "$SCRIPT_DIR/modules/hidden_files.sh"
# shellcheck source=modules/superglobal.sh
. "$SCRIPT_DIR/modules/superglobal.sh"
# shellcheck source=modules/curl.sh
. "$SCRIPT_DIR/modules/curl.sh"
# shellcheck source=modules/wp_version.sh
. "$SCRIPT_DIR/modules/wp_version.sh"
# shellcheck source=modules/permissions.sh
. "$SCRIPT_DIR/modules/permissions.sh"
# shellcheck source=modules/immutable.sh
. "$SCRIPT_DIR/modules/immutable.sh"
# shellcheck source=modules/image_headers.sh
. "$SCRIPT_DIR/modules/image_headers.sh"
# shellcheck source=modules/wp_cli.sh
. "$SCRIPT_DIR/modules/wp_cli.sh"

main "$@"
