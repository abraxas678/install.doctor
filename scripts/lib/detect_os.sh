#!/usr/bin/env bash
# scripts/lib/detect_os.sh — Single source of truth for OS/role detection.
# Source this file, then call detect_os or detect_role.
# Replaces 25+ ad-hoc OS checks across start.sh, provision.sh, installx, and
# chezmoi scripts.

# shellcheck disable=SC2034  # Functions are sourced, not executed directly

# ---------------------------------------------------------------------------
# detect_os — returns the base operating system
#
# Output: macos | ubuntu | debian | fedora | silverblue | alpine | arch |
#         qubes-dom0 | qubes-appvm | proxmox | wsl | container | unknown
#
# Detection order (most-specific first):
#   1. Qubes (dom0 or AppVM — checked before generic Linux)
#   2. WSL (checked before generic Linux)
#   3. Container (checked before generic Linux)
#   4. macOS (darwin OSTYPE)
#   5. Linux distros via release files
# ---------------------------------------------------------------------------
detect_os() {
  # Qubes dom0 — Xen hypervisor host with Salt control
  if [ -f /usr/bin/qubes-session ] && [ -f /etc/qubes/dom0 ]; then
    echo "qubes-dom0"
    return 0
  fi

  # Qubes AppVM — runs inside a Qubes VM
  if [ -f /usr/bin/qubes-session ] || [ -d /usr/share/qubes ]; then
    echo "qubes-appvm"
    return 0
  fi

  # WSL — Windows Subsystem for Linux
  if [ -f /proc/sys/fs/binfmt_misc/WSLInterop ] || grep -qi microsoft /proc/version 2>/dev/null; then
    echo "wsl"
    return 0
  fi

  # Container — Docker/Podman/LXC
  if [ -f /.dockerenv ] || grep -qE 'docker|lxc|containerd' /proc/1/cgroup 2>/dev/null; then
    echo "container"
    return 0
  fi

  # macOS
  if [[ "$OSTYPE" == 'darwin'* ]]; then
    echo "macos"
    return 0
  fi

  # Proxmox VE — Debian-based hypervisor
  if [ -f /etc/pve/pve.cfg ] || [ -x /usr/bin/pvesh ]; then
    echo "proxmox"
    return 0
  fi

  # Linux distro detection via release files
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    local id
    id="$(. /etc/os-release && echo "${ID:-unknown}")"

    case "$id" in
      ubuntu)       echo "ubuntu";   return 0 ;;
      debian)       echo "debian";   return 0 ;;
      fedora)
        # Silverblue / immutable Fedora variants
        if [ -f /run/ostree-booted ]; then
          echo "silverblue"
        else
          echo "fedora"
        fi
        return 0
        ;;
      rhel|centos|rocky|almalinux|ol)  echo "fedora"; return 0 ;;  # RHEL family ≈ fedora for install purposes
      arch|archlinux|manjaro)           echo "arch";    return 0 ;;
      alpine)                           echo "alpine";  return 0 ;;
      opensuse*|sles)                   echo "fedora";  return 0 ;;  # SUSE ≈ fedora (uses rpm)
      *)                                echo "$id";     return 0 ;;
    esac
  fi

  # Fallback detection via legacy release files (pre-systemd or minimal)
  if [ -f /etc/redhat-release ]; then
    echo "fedora"
    return 0
  elif [ -f /etc/debian_version ]; then
    echo "debian"
    return 0
  elif [ -f /etc/arch-release ]; then
    echo "arch"
    return 0
  elif [ -f /etc/alpine-release ]; then
    echo "alpine"
    return 0
  fi

  # Final fallback: check OSTYPE for generic Linux
  if [[ "$OSTYPE" == 'linux'* ]]; then
    echo "linux"
    return 0
  fi

  echo "unknown"
  return 1
}

# ---------------------------------------------------------------------------
# detect_role — returns the machine's role in the fleet
#
# Output: workstation | server | proxmox | coolify | qubes-dom0 |
#         qubes-appvm | wsl | container | unknown
#
# Can be overridden via INSTALL_DOCTOR_ROLE env var.
# Defaults to 'workstation' on macOS, 'server' on headless Linux.
# ---------------------------------------------------------------------------
detect_role() {
  # Explicit override
  if [ -n "${INSTALL_DOCTOR_ROLE:-}" ]; then
    echo "$INSTALL_DOCTOR_ROLE"
    return 0
  fi

  local os
  os="$(detect_os)"

  case "$os" in
    qubes-dom0)  echo "qubes-dom0";  return 0 ;;
    qubes-appvm) echo "qubes-appvm"; return 0 ;;
    proxmox)     echo "proxmox";     return 0 ;;
    wsl)         echo "wsl";         return 0 ;;
    container)   echo "container";   return 0 ;;
  esac

  # Coolify detection — check for Coolify-specific markers
  if [ -d /data/coolify ] || [ -f /etc/coolify/.installed ]; then
    echo "coolify"
    return 0
  fi

  # macOS defaults to workstation
  if [ "$os" = "macos" ]; then
    echo "workstation"
    return 0
  fi

  # Linux: check for desktop environment for workstation vs server
  if [ -n "${XDG_CURRENT_DESKTOP:-}" ] || [ -n "${DISPLAY:-}" ]; then
    echo "workstation"
  else
    echo "server"
  fi
}

# ---------------------------------------------------------------------------
# detect_package_manager — returns the native package manager for the OS
# ---------------------------------------------------------------------------
detect_package_manager() {
  local os
  os="$(detect_os)"

  case "$os" in
    macos)       echo "brew"  ;;
    ubuntu|debian) echo "apt" ;;
    fedora|silverblue) echo "dnf" ;;
    alpine)      echo "apk"   ;;
    arch)        echo "pacman";;
    *)           echo "unknown" ;;
  esac
}

# ---------------------------------------------------------------------------
# is_headless — returns 0 if the machine has no GUI
# ---------------------------------------------------------------------------
is_headless() {
  # Explicit override
  [ "${HEADLESS_INSTALL:-}" = "true" ] && return 0

  # macOS: always has GUI unless explicitly headless
  [ "$(detect_os)" = "macos" ] && return 1

  # Linux: check for display server
  [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ] && return 0

  return 1
}
