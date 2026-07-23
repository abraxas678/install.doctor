#!/usr/bin/env bash
# scripts/audit-deprecated.sh — Audit deprecated software.yml entries.
# Reports counts, categories, and entries-by-reason for migration planning.
# Usage: bash scripts/audit-deprecated.sh [--json]
set -euo pipefail

JSON_MODE=false
[ "${1:-}" = "--json" ] && JSON_MODE=true

SOFTWARE_YML="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/software.yml"
TOTAL=$(/usr/bin/grep -c '_deprecated:' "$SOFTWARE_YML" 2>/dev/null || echo "0")
HAS_REPLACEMENT=$(/usr/bin/grep -ic 'Replaced by\|replaced by\|superseded\|in favor of\|instead' "$SOFTWARE_YML" 2>/dev/null || echo "0")
UNNECESSARY=$(/usr/bin/grep -ic 'Unnecessary\|Unneeded\|no longer needed' "$SOFTWARE_YML" 2>/dev/null || echo "0")
EOL=$(/usr/bin/grep -ic 'EOL\|broken\|no longer maintained\|alpha stage\|deprecated upstream' "$SOFTWARE_YML" 2>/dev/null || echo "0")

TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if $JSON_MODE; then
  printf '{"timestamp":"%s","total_deprecated":%s,"has_replacement":%s,"unnecessary":%s,"eol_broken":%s,"other":%s}\n' \
    "$TIMESTAMP" "$TOTAL" "$HAS_REPLACEMENT" "$UNNECESSARY" "$EOL" \
    "$((TOTAL - HAS_REPLACEMENT - UNNECESSARY - EOL))"
else
  echo "=== Deprecated Software Audit ==="
  echo "Total deprecated entries: $TOTAL"
  echo "  Has clear replacement:  $HAS_REPLACEMENT"
  echo "  Unnecessary/unneeded:   $UNNECESSARY"
  echo "  EOL/broken upstream:    $EOL"
  echo "  Other (quality/pref):   $((TOTAL - HAS_REPLACEMENT - UNNECESSARY - EOL))"
  echo ""
  echo "Entries with clear replacements:"
  /usr/bin/grep -B1 '_deprecated:' "$SOFTWARE_YML" | /usr/bin/grep "^    _deprecated:" | \
    /usr/bin/grep -i "Replaced by\|in favor of\|superseded\|instead" | \
    sed 's/    _deprecated: /  → /' | sort
fi
