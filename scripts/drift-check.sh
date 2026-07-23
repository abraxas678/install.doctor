#!/usr/bin/env bash
# scripts/drift-check.sh — Detect unmanaged changes (drift) between the
# live system and the chezmoi source of truth.
#
# Usage:
#   bash scripts/drift-check.sh              # Human-readable report
#   bash scripts/drift-check.sh --json       # Machine-readable JSON (stdout)
#   bash scripts/drift-check.sh --fix        # Auto-apply chezmoi to resolve drift
#   bash scripts/drift-check.sh --ci         # CI mode: HEADLESS, exit 1 on drift
#
# Exit codes:
#   0 — No drift detected (clean)
#   1 — Drift detected (files differ from source of truth)
#   2 — Error (chezmoi not installed, cannot run)
set -euo pipefail

# ---------------------------------------------------------------------------
# Parse flags
# ---------------------------------------------------------------------------
JSON_MODE=false
FIX_MODE=false
CI_MODE=false

for arg in "$@"; do
  case "$arg" in
    --json) JSON_MODE=true ;;
    --fix)  FIX_MODE=true ;;
    --ci)   CI_MODE=true ;;
    --help|-h)
      echo "Usage: bash scripts/drift-check.sh [--json] [--fix] [--ci]"
      exit 0
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
if ! command -v chezmoi &>/dev/null; then
  if $JSON_MODE; then
    printf '{"error":"chezmoi not installed","drift":"unknown"}\n'
  else
    echo "DRIFT: SKIP — chezmoi not installed"
  fi
  exit 2
fi

DRIFT_COUNT=0
DRIFT_FILES=""
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GIT_SHA="$(git -C "$(chezmoi source-path 2>/dev/null || echo "$HOME/.local/share/chezmoi")" rev-parse --short HEAD 2>/dev/null || echo "unknown")"
HOSTNAME="$(hostname -s 2>/dev/null || echo "unknown")"

# ---------------------------------------------------------------------------
# Check for uncommitted chezmoi source changes (source drift)
# ---------------------------------------------------------------------------
SOURCE_DIR="$(chezmoi source-path 2>/dev/null || echo "")"
SOURCE_DRIFT=false
if [ -n "$SOURCE_DIR" ] && [ -d "$SOURCE_DIR/.git" ]; then
  if ! git -C "$SOURCE_DIR" diff --quiet 2>/dev/null; then
    SOURCE_DRIFT=true
  fi
  if ! git -C "$SOURCE_DIR" diff --cached --quiet 2>/dev/null; then
    SOURCE_DRIFT=true
  fi
fi

# ---------------------------------------------------------------------------
# Check for target state drift (live files differ from chezmoi source)
# ---------------------------------------------------------------------------
# chezmoi diff exits 0 when clean, 1 when differences exist
DIFF_OUTPUT=""
if DIFF_OUTPUT=$(chezmoi diff 2>&1); then
  DRIFT_COUNT=0
else
  # Count drifted files (each diff starts with "diff --git")
  DRIFT_COUNT=$(echo "$DIFF_OUTPUT" | /usr/bin/grep -c "^diff --git" 2>/dev/null || echo "0")
  DRIFT_FILES=$(echo "$DIFF_OUTPUT" | /usr/bin/grep "^diff --git" | sed 's/.*a\///' | sed 's/ b\/.*//' | sort -u | tr '\n' ' ' 2>/dev/null || echo "")
fi

# ---------------------------------------------------------------------------
# Auto-fix mode
# ---------------------------------------------------------------------------
if $FIX_MODE && [ "$DRIFT_COUNT" -gt 0 ]; then
  if $JSON_MODE || $CI_MODE; then
    chezmoi apply --force 2>&1 || true
  else
    echo "Applying chezmoi to resolve $DRIFT_COUNT drifted file(s)..."
    chezmoi apply --force 2>&1 || echo "WARN: chezmoi apply had errors"
  fi
  # Re-check after fix
  if chezmoi diff > /dev/null 2>&1; then
    DRIFT_COUNT=0
    DRIFT_FILES=""
  fi
fi

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
if $JSON_MODE; then
  # Machine-readable envelope
  printf '{"hostname":"%s","timestamp":"%s","git_sha":"%s","drifted_files":%d,"source_drift":%s,"files":"%s"}\n' \
    "$HOSTNAME" "$TIMESTAMP" "$GIT_SHA" "$DRIFT_COUNT" \
    "$($SOURCE_DRIFT && echo "true" || echo "false")" \
    "$DRIFT_FILES"
else
  # Human-readable report
  echo "=== Drift Check ==="
  echo "Host:     $HOSTNAME"
  echo "Source:   $SOURCE_DIR ($GIT_SHA)"
  echo "Time:     $TIMESTAMP"
  echo ""
  if [ "$DRIFT_COUNT" -eq 0 ] && ! $SOURCE_DRIFT; then
    echo "DRIFT: CLEAN — no unmanaged changes detected"
  else
    if $SOURCE_DRIFT; then
      echo "DRIFT: SOURCE — chezmoi source has uncommitted changes"
    fi
    if [ "$DRIFT_COUNT" -gt 0 ]; then
      echo "DRIFT: $DRIFT_COUNT file(s) differ from source of truth:"
      echo "$DRIFT_FILES" | tr ' ' '\n' | sed 's/^/  - /'
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Exit
# ---------------------------------------------------------------------------
HAS_DRIFT=false
[ "$DRIFT_COUNT" -gt 0 ] && HAS_DRIFT=true
$SOURCE_DRIFT && HAS_DRIFT=true

if $HAS_DRIFT; then
  exit 1
fi
exit 0
