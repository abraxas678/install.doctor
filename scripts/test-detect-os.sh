#!/usr/bin/env bash
# scripts/test-detect-os.sh — Test harness for detect_os.sh library.
# Runs on ANY OS; validates the functions work correctly on the host.
# CI runs this per-OS via the container matrix, so every OS type
# gets tested on its native host.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
if [ ! -f "$LIB_DIR/detect_os.sh" ]; then
  echo "FAIL: $LIB_DIR/detect_os.sh not found"
  exit 1
fi

# shellcheck disable=SC1090
source "$LIB_DIR/detect_os.sh"

PASS=0
FAIL=0

assert_eq() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "  PASS: $desc"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $desc — expected '$expected', got '$actual'"
    FAIL=$((FAIL + 1))
  fi
}

assert_ok() {
  local desc="$1" result="$2"
  if [ "$result" -eq 0 ]; then
    echo "  PASS: $desc (exit 0)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $desc — exit code $result"
    FAIL=$((FAIL + 1))
  fi
}

assert_defined() {
  local desc="$1" value="$2"
  if [ -n "$value" ] && [ "$value" != "unknown" ]; then
    echo "  PASS: $desc ($value)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $desc — undefined or unknown"
    FAIL=$((FAIL + 1))
  fi
}

# ---------------------------------------------------------------------------
# Test 1: detect_os returns a known value on this host
# ---------------------------------------------------------------------------
echo "=== Test: detect_os ==="
OS="$(detect_os)"
KNOWN_OS="macos ubuntu debian fedora silverblue alpine arch qubes-dom0 qubes-appvm proxmox wsl container linux"
if echo "$KNOWN_OS" | /usr/bin/grep -qw "$OS"; then
  echo "  PASS: detect_os returned '$OS' (valid value)"
  PASS=$((PASS + 1))
else
  echo "  FAIL: detect_os returned '$OS' (not in known list)"
  FAIL=$((FAIL + 1))
fi

# Check exit code
detect_os > /dev/null
assert_ok "detect_os exit code" $?

# ---------------------------------------------------------------------------
# Test 2: detect_role returns a known value
# ---------------------------------------------------------------------------
echo "=== Test: detect_role ==="
ROLE="$(detect_role)"
KNOWN_ROLES="workstation server proxmox coolify qubes-dom0 qubes-appvm wsl container"
if echo "$KNOWN_ROLES" | /usr/bin/grep -qw "$ROLE"; then
  echo "  PASS: detect_role returned '$ROLE' (valid value)"
  PASS=$((PASS + 1))
else
  echo "  FAIL: detect_role returned '$ROLE' (not in known list)"
  FAIL=$((FAIL + 1))
fi

# Override test
INSTALL_DOCTOR_ROLE="test-role" detect_role > /dev/null
assert_eq "detect_role with INSTALL_DOCTOR_ROLE override" "test-role" "$(INSTALL_DOCTOR_ROLE="test-role" detect_role)"

# ---------------------------------------------------------------------------
# Test 3: detect_package_manager returns a known value
# ---------------------------------------------------------------------------
echo "=== Test: detect_package_manager ==="
PM="$(detect_package_manager)"
KNOWN_PM="brew apt dnf apk pacman"
if echo "$KNOWN_PM" | /usr/bin/grep -qw "$PM"; then
  echo "  PASS: detect_package_manager returned '$PM' (valid value)"
  PASS=$((PASS + 1))
else
  echo "  FAIL: detect_package_manager returned '$PM' for OS=$OS (not in known list)"
  FAIL=$((FAIL + 1))
fi

# Check cross-OS mapping
case "$OS" in
  macos) assert_eq "package manager for macOS" "brew" "$PM" ;;
  ubuntu|debian) assert_eq "package manager for $OS" "apt" "$PM" ;;
  fedora|silverblue) assert_eq "package manager for $OS" "dnf" "$PM" ;;
  alpine) assert_eq "package manager for alpine" "apk" "$PM" ;;
  arch) assert_eq "package manager for arch" "pacman" "$PM" ;;
esac

# ---------------------------------------------------------------------------
# Test 4: is_headless
# ---------------------------------------------------------------------------
echo "=== Test: is_headless ==="
# HEADLESS_INSTALL=true must return 0
if HEADLESS_INSTALL=true is_headless; then
  echo "  PASS: is_headless with HEADLESS_INSTALL=true (exit 0)"
  PASS=$((PASS + 1))
else
  echo "  FAIL: is_headless with HEADLESS_INSTALL=true returned non-zero"
  FAIL=$((FAIL + 1))
fi

# Without HEADLESS_INSTALL, macOS should return 1 (has GUI)
if [ "$OS" = "macos" ]; then
  if is_headless; then
    echo "  FAIL: is_headless on macOS without HEADLESS_INSTALL returned 0 (should be 1)"
    FAIL=$((FAIL + 1))
  else
    echo "  PASS: is_headless on macOS without HEADLESS_INSTALL (exit non-zero, has GUI)"
    PASS=$((PASS + 1))
  fi
fi

# ---------------------------------------------------------------------------
# Test 5: All functions are defined
# ---------------------------------------------------------------------------
echo "=== Test: function definitions ==="
for fn in detect_os detect_role detect_package_manager is_headless; do
  if declare -f "$fn" > /dev/null 2>&1; then
    echo "  PASS: $fn is defined"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $fn is not defined"
    FAIL=$((FAIL + 1))
  fi
done

# ---------------------------------------------------------------------------
# Test 6: Idempotency — multiple calls return same result
# ---------------------------------------------------------------------------
echo "=== Test: idempotency ==="
FIRST="$(detect_os)"
SECOND="$(detect_os)"
assert_eq "detect_os idempotent" "$FIRST" "$SECOND"

# ---------------------------------------------------------------------------
# Test 7: start.sh embedded detect_os matches the library
# ---------------------------------------------------------------------------
echo "=== Test: start.sh embedded detect_os consistency ==="
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
if [ -f "$REPO_ROOT/start.sh" ]; then
  # Source the embedded function from start.sh (it defines detect_os inline)
  EMBEDDED_OS="$(bash -c "
    $(sed -n '/^detect_os() {/,/^}/p' "$REPO_ROOT/start.sh")
    detect_os
  " 2>/dev/null || echo "error")"
  if [ "$EMBEDDED_OS" = "error" ]; then
    echo "  WARN: Could not extract embedded detect_os from start.sh"
  elif [ "$EMBEDDED_OS" = "$OS" ]; then
    echo "  PASS: start.sh embedded detect_os matches library ($EMBEDDED_OS == $OS)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: start.sh embedded detect_os ($EMBEDDED_OS) differs from library ($OS)"
    FAIL=$((FAIL + 1))
  fi
fi

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------
echo ""
echo "=============================="
echo "Results: $PASS passed, $FAIL failed"
echo "=============================="

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0
