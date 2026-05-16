# Changelog

## Unreleased

- fix: enable strict mode (set -euo pipefail) and add error handler
- fix: correct several shell bugs (stray $$ in find, lsattr parsing, sed regex typos)
- chore: add dependency warnings for missing helper commands
- docs: update README with latest changes
- fix: avoid subshell variable loss when scanning uploads directories
- feat: improved JSON output with per-module file lists
- feat: add Dockerfile for containerized runs
