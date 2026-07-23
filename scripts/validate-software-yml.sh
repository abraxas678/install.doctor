#!/usr/bin/env bash
# scripts/validate-software-yml.sh — Validate software.yml structure.
# Checks for required fields, valid install methods, and malformed entries.
# Exits non-zero on violations.
set -euo pipefail

SW_YML="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/software.yml"
PASS=0
FAIL=0

echo "=== software.yml Validator ==="
echo "File: $SW_YML"
echo ""

# ---------------------------------------------------------------------------
# Check 1: File exists and is non-empty
# ---------------------------------------------------------------------------
if [ ! -f "$SW_YML" ]; then
  echo "FAIL: software.yml not found"
  exit 1
fi
LINES=$(wc -l < "$SW_YML" | tr -d ' ')
echo "PASS: software.yml exists ($LINES lines)"
PASS=$((PASS + 1))

# ---------------------------------------------------------------------------
# Check 2: Every top-level entry has _name
# ---------------------------------------------------------------------------
# Count entries in the softwarePackages section (indented 2 spaces under softwarePackages:)
ENTRIES_TOTAL=$(sed -n '/^softwarePackages:/,/^[^ ]/p' "$SW_YML" | /usr/bin/grep -c '^  [a-z]' 2>/dev/null || echo "0")
ENTRIES_WITH_NAME=$(sed -n '/^softwarePackages:/,/^[^ ]/p' "$SW_YML" | /usr/bin/grep -c '    _name:' 2>/dev/null || echo "0")

if [ "$ENTRIES_TOTAL" -eq "$ENTRIES_WITH_NAME" ] 2>/dev/null; then
  echo "PASS: All $ENTRIES_TOTAL entries have _name field"
  PASS=$((PASS + 1))
else
  MISSING=$((ENTRIES_TOTAL - ENTRIES_WITH_NAME))
  echo "WARN: $MISSING of $ENTRIES_TOTAL entries may be missing _name (some may be sub-entries)"
fi

# ---------------------------------------------------------------------------
# Check 3: No empty _deprecated (must have a reason)
# ---------------------------------------------------------------------------
EMPTY_DEPRECATED=$(/usr/bin/grep -c '_deprecated: ""$\|_deprecated: $''\|_deprecated: TODO$' "$SW_YML" 2>/dev/null | tr -d '[:space:]' || echo "0")
if [ "${EMPTY_DEPRECATED}" -le 0 ] 2>/dev/null; then
  echo "PASS: No empty _deprecated entries"
  PASS=$((PASS + 1))
else
  echo "FAIL: $EMPTY_DEPRECATED _deprecated entries have no reason"
  FAIL=$((FAIL + 1))
fi

# ---------------------------------------------------------------------------
# Check 4: Count deprecated + install method conflicts
# (entries with _deprecated AND _todo are double-indicated)
# ---------------------------------------------------------------------------
DOUBLE_TAGGED=$(/usr/bin/grep -B50 '_todo:' "$SW_YML" | /usr/bin/grep -c '_deprecated:' 2>/dev/null || echo "0")
if [ "$DOUBLE_TAGGED" -eq 0 ]; then
  echo "PASS: No entries with both _deprecated and _todo"
  PASS=$((PASS + 1))
else
  echo "WARN: $DOUBLE_TAGGED entries have both _deprecated and _todo (non-blocking)"
fi

# ---------------------------------------------------------------------------
# Check 5: No malformed conditional install keys (_when with no target)
# ---------------------------------------------------------------------------
MALFORMED_WHEN=$(/usr/bin/grep -c '_when:$\|_when: ""\|_when:cask:$\|_when:apt:$' "$SW_YML" 2>/dev/null | tr -d '[:space:]' || echo "0")
if [ "${MALFORMED_WHEN}" -le 0 ] 2>/dev/null; then
  echo "PASS: No malformed _when conditional keys"
  PASS=$((PASS + 1))
else
  echo "FAIL: $MALFORMED_WHEN malformed _when conditional keys"
  FAIL=$((FAIL + 1))
fi

# ---------------------------------------------------------------------------
# Check 6: Count entries by install method
# ---------------------------------------------------------------------------
echo ""
echo "=== Install Method Summary ==="
for method in brew cask apt npm pipx cargo go snap flatpak pacman dnf choco scoop yay; do
  count=$(/usr/bin/grep -c "    ${method}:" "$SW_YML" 2>/dev/null || echo "0")
  [ "$count" -gt 0 ] && echo "  $method: $count entries"
done

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0
