#!/usr/bin/env bash
# Validate a signatures file used by wp-scan.
# Usage: validate-signatures.sh /path/to/signatures.txt

set -euo pipefail

SIG_FILE="${1:-signatures/latest-signatures.txt}"

if [ ! -f "$SIG_FILE" ]; then
  echo "ERROR: Signatures file not found: $SIG_FILE" >&2
  exit 2
fi

err=0
lineno=0
while IFS= read -r line || [ -n "$line" ]; do
  lineno=$((lineno+1))
  # Trim
  sig=$(printf "%s" "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  [ -z "$sig" ] && continue
  case "$sig" in
    \#*) continue ;; # comment
  esac

  if echo "$sig" | grep -q "|"; then
    # Expect: ruleId|severity|pattern|description
    IFS='|' read -r ruleId severity pattern description <<< "$sig"
    ruleId=$(printf "%s" "$ruleId" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    severity=$(printf "%s" "$severity" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | tr '[:upper:]' '[:lower:]')
    pattern=$(printf "%s" "$pattern" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    description=$(printf "%s" "$description" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    if [ -z "$ruleId" ]; then
      echo "ERROR: $SIG_FILE:$lineno: empty ruleId" >&2
      err=1
      continue
    fi
    if [ -z "$pattern" ]; then
      echo "ERROR: $SIG_FILE:$lineno: empty pattern" >&2
      err=1
      continue
    fi
    # Validate severity value
    case "$severity" in
      info|low|medium|high|critical|warning|error) ;;
      *) echo "ERROR: $SIG_FILE:$lineno: unknown severity '$severity'" >&2; err=1; continue ;;
    esac

    # Validate regex sanity by running grep -E against empty input
    if ! printf "" | grep -E -n -- "$pattern" >/dev/null 2>&1; then
      rc=$?
      # grep returns 2 on bad regex; 1 means no match which is fine
      if [ "$rc" -eq 2 ]; then
        echo "ERROR: $SIG_FILE:$lineno: invalid regex pattern: $pattern" >&2
        err=1
        continue
      fi
    fi
  else
    # Legacy line: treat entire line as an ERE pattern
    pattern="$sig"
    if [ -z "$pattern" ]; then
      echo "ERROR: $SIG_FILE:$lineno: empty legacy pattern" >&2
      err=1
      continue
    fi
    if ! printf "" | grep -E -n -- "$pattern" >/dev/null 2>&1; then
      rc=$?
      if [ "$rc" -eq 2 ]; then
        echo "ERROR: $SIG_FILE:$lineno: invalid legacy regex pattern: $pattern" >&2
        err=1
        continue
      fi
    fi
  fi

done < "$SIG_FILE"

if [ "$err" -ne 0 ]; then
  echo "Signature validation failed: $SIG_FILE" >&2
  exit 2
fi

echo "Signatures OK: $SIG_FILE"
exit 0
