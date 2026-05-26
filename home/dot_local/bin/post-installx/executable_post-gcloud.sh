#!/usr/bin/env bash
# @file ~/.local/bin/post-installx/post-gcloud.sh
# @brief Fleet-aware Google Cloud SDK post-install: install essential components,
#        ensure CLOUDSDK_PYTHON is set, surface auth status.
# @description
#   Runs after `installx gcloud` lands the SDK. On macOS the cask is
#   `gcloud-cli` (recently renamed from `google-cloud-sdk`); on Ubuntu it's
#   `google-cloud-sdk` via apt; on Fedora it's `google-cloud-cli` via dnf;
#   on Coolify/Proxmox it's typically the tarball under
#   /usr/lib/google-cloud-sdk/. Either way `gcloud` ends up on PATH and
#   this script tunes the rest of the experience.
#
#   What it does:
#     1. Sanity-check `gcloud` is on PATH; bail otherwise
#     2. Install components everyone uses: gke-gcloud-auth-plugin, alpha, beta
#     3. Auto-update is disabled fleet-wide (`gcloud config set
#        component_manager/disable_update_check true`) — same rationale as
#        the macOS auto-update disable: background updates to running apps
#        corrupt in-flight sessions
#     4. Report auth status (active account + project) so the user knows
#        whether `gcloud auth login` is still needed

set -u

[ -f "${XDG_CONFIG_HOME:-$HOME/.config}/shell/exports.sh" ] && source "${XDG_CONFIG_HOME:-$HOME/.config}/shell/exports.sh"

### gum fallback for non-installed-gum bootstraps (rare; usually installx
### lands gum before this script). Keep parity with the other post-installx
### scripts that have the same pattern.
if ! command -v gum > /dev/null; then
  gum() {
    if [ "${1:-}" = "log" ]; then shift; while [ "$#" -gt 0 ] && [ "${1#-}" != "$1" ]; do shift; done; printf '%s %s\n' "${1:-INFO}" "${2:-}"; else "$@"; fi
  }
fi

if ! command -v gcloud > /dev/null 2>&1; then
  gum log -sl warn 'gcloud not on PATH; skipping post-gcloud setup (re-run after installx finishes)'
  exit 0
fi

GCLOUD_VERSION="$(gcloud version --format='value(\"Google Cloud SDK\")' 2>/dev/null | head -1)"
gum log -sl info "gcloud detected: ${GCLOUD_VERSION:-unknown version}"

### 1. Disable component-update auto-check. Same rationale as
### `disableAutoUpdateDarwin`: background mutation of running CLI tools
### corrupts in-flight sessions and surprises users mid-task. User runs
### `gcloud components update` manually when they want updates.
gcloud config set component_manager/disable_update_check true --installation 2>/dev/null \
  && gum log -sl info 'gcloud component auto-update-check disabled' \
  || gum log -sl warn 'Could not disable gcloud component auto-update-check (non-fatal)'

### 2. Disable usage-reporting telemetry (privacy + slight speedup).
gcloud config set core/disable_usage_reporting true --installation 2>/dev/null || true

### 3. Install essential components if not already present.
###    - gke-gcloud-auth-plugin: required for kubectl→GKE auth on modern
###      Kubernetes versions (deprecation took effect in 1.26+)
###    - alpha + beta: needed for any non-GA feature; tiny components
NEEDED_COMPONENTS=()
gcloud components list --filter='id:gke-gcloud-auth-plugin' --format='value(state.name)' 2>/dev/null | grep -q 'Installed' || NEEDED_COMPONENTS+=('gke-gcloud-auth-plugin')
gcloud components list --filter='id:alpha' --format='value(state.name)' 2>/dev/null | grep -q 'Installed' || NEEDED_COMPONENTS+=('alpha')
gcloud components list --filter='id:beta'  --format='value(state.name)' 2>/dev/null | grep -q 'Installed' || NEEDED_COMPONENTS+=('beta')

if [ "${#NEEDED_COMPONENTS[@]}" -gt 0 ]; then
  gum log -sl info "Installing gcloud components: ${NEEDED_COMPONENTS[*]}"
  ### `--quiet` skips the y/N prompt. Components install into the SDK
  ### root which on a brew-installed cask requires the user to own
  ### /opt/homebrew (which they normally do — chezmoi requirements step
  ### chowns it).
  gcloud components install --quiet "${NEEDED_COMPONENTS[@]}" 2>&1 | tail -5 || gum log -sl warn 'Component install returned non-zero; check `gcloud components list`'
else
  gum log -sl info 'All essential gcloud components already installed'
fi

### 4. Report auth status — useful in headless / first-provision context.
ACTIVE_ACCOUNT="$(gcloud auth list --filter='status:ACTIVE' --format='value(account)' 2>/dev/null | head -1)"
ACTIVE_PROJECT="$(gcloud config get-value project 2>/dev/null)"
if [ -n "$ACTIVE_ACCOUNT" ]; then
  gum log -sl info "gcloud auth: ✓ ${ACTIVE_ACCOUNT}${ACTIVE_PROJECT:+ (project: $ACTIVE_PROJECT)}"
else
  gum log -sl warn 'gcloud is not authed. Run `gcloud auth login` (and `gcloud auth application-default login` if SDK clients also need creds).'
fi
