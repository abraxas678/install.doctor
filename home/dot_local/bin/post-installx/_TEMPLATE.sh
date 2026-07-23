#!/usr/bin/env bash
# @file post-installx/_TEMPLATE.sh
# @brief Template for post-installx hooks. Copy and customize.
#
# Every post-install hook MUST:
#   1. set -euo pipefail (fail fast, fail loud)
#   2. Early-exit on wrong OS (use detect_os or ad-hoc check)
#   3. Use structured logging (logg/gum if available, echo as fallback)
#   4. Be idempotent (check before applying)
#   5. Clean up temp files on exit (trap)
#
# Source: CONVERGENCE.md §C14
set -euo pipefail

# ---------------------------------------------------------------------------
# OS gate — skip if this hook doesn't apply to the current platform
# ---------------------------------------------------------------------------
# Option A: source the centralized library (preferred when repo is available)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/../../../scripts/lib/detect_os.sh" ]; then
  # shellcheck disable=SC1090
  source "$SCRIPT_DIR/../../../scripts/lib/detect_os.sh"
  OS="$(detect_os)"
else
  # Fallback: ad-hoc detection
  if [[ "$OSTYPE" == 'darwin'* ]]; then OS="macos"
  elif [ -f /etc/debian_version ]; then OS="debian"
  elif [ -f /etc/redhat-release ]; then OS="fedora"
  else OS="unknown"
  fi
fi

# Gate: change this to the OS this hook targets
# EXPECTED_OS="macos"
# if [ "$OS" != "$EXPECTED_OS" ]; then
#   echo "Skipping $0: expected $EXPECTED_OS, detected $OS" >&2
#   exit 0
# fi
# EXPAND_ME: Replace EXPECTED_OS with the actual OS this hook targets,
# or remove the gate for universal hooks.

# ---------------------------------------------------------------------------
# Logging — prefer gum if available, fall back to echo
# ---------------------------------------------------------------------------
if command -v gum &>/dev/null; then
  log() { gum log -sl info "$1"; }
  warn() { gum log -sl warn "$1"; }
else
  log() { echo "[INFO] $1"; }
  warn() { echo "[WARN] $1"; }
fi

# ---------------------------------------------------------------------------
# Idempotency — check if already configured
# ---------------------------------------------------------------------------
# MARKER_FILE="${XDG_STATE_HOME:-$HOME/.local/state}/install.doctor/post-<TOOL>.done"
# if [ -f "$MARKER_FILE" ]; then
#   log "<TOOL> already configured — skipping"
#   exit 0
# fi
# EXPAND_ME: Replace <TOOL> with the tool name.

# ---------------------------------------------------------------------------
# Cleanup on exit
# ---------------------------------------------------------------------------
cleanup() {
  rm -f /tmp/post-<TOOL>-* 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Main — your provisioning logic here
# ---------------------------------------------------------------------------
log "Configuring <TOOL>..."

# EXPAND_ME: Add your provisioning logic below.
# Remember: idempotent (check state before mutating), headless-safe,
# and SKIP gracefully (exit 0, not error) when the tool isn't installed.

# Example:
# if ! command -v <TOOL> &>/dev/null; then
#   warn "<TOOL> not installed — skipping post-install"
#   exit 0
# fi

# ... your logic here ...

# mkdir -p "$(dirname "$MARKER_FILE")"
# touch "$MARKER_FILE"
# log "<TOOL> configuration complete"
