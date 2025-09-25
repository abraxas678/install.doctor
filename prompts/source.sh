#!/usr/bin/env bash
# ==============================================================================
#  source.sh — Shared Bash utilities for "Shell Expert" scripts
# ------------------------------------------------------------------------------
#  Purpose:
#    One import for all shared functionality so individual scripts stay tiny.
#    Covers:
#      • Context init (slug, XDG; root → /etc,/var/lib,/var/cache), TZ=America/New_York
#      • TTY-aware styled logging + optional JSON logs + journald
#      • Secret masking in logs, plain log file with rotation (10MB, keep 5)
#      • Command runner with confirm / dry-run
#      • NDJSON run summary (OK/FAIL per step)
#      • Healthchecks start/success/fail with log streaming (1MB guard)
#      • Self-update from URL → stage /usr/local/lib/<slug>/<ts>-<sha8> → atomic symlink
#      • Update URL persistence in XDG
#      • Dependency bootstrap (apt/dnf/apk/pacman/brew) with --no-sudo support
#      • Config encrypt/decrypt (OpenSSL AES-256-GCM PBKDF2; fallback CBC)
#      • Interactive recovery shell (vim, 15-min inactivity timeout)
#      • Helpers for ordered step execution and START_FROM gating
#
#  Notes:
#    - Bash 5+ assumed. 2-space indent. Prefer printf over echo. Defensive checks.
#    - No global `set -e`/`-u`; functions return codes, caller decides.
#    - This file is meant to be *sourced*, not executed.
# ==============================================================================

# ------------------------------- Defaults -------------------------------------

: "${SE_TZ:=America/New_York}"         # Human-facing timestamps timezone
: "${SE_COLOR_MODE:=auto}"             # auto|always|never
: "${DEBUG:=0}"                        # 0|1
: "${CONFIRM_COMMAND:=0}"              # 0|1 (prompt before commands)
: "${DRY_RUN:=0}"                      # 0|1 (skip execution)
: "${ENCRYPT_CONFIG:=1}"               # 0|1 (config encryption on/off)
: "${SE_JSON_LOGS:=0}"                 # 0|1 (also emit JSON logs to stdout)
: "${NO_SUDO:=0}"                      # 0|1 (disallow sudo)

: "${HEALTHCHECKS_BASE:=https://healthchecks.megabyte.space}"  # default base
: "${HEALTHCHECKS_URL:=}"             # full URL (preferred) or base; config.json fallback supported
: "${HEALTHCHECKS_PING_KEY:=}"        # used only if base+key building is needed

: "${SE_LOG_MAX_BYTES:=10485760}"     # 10MB rotation threshold
: "${SE_LOG_KEEP:=5}"                  # keep 5 rotated logs
: "${SE_HC_TAIL_LINES:=3000}"         # lines to POST on success
: "${SE_HC_TAIL_LINES_FAIL:=300}"     # lines to POST on failure

# Pre-shared key for encryption (security-through-obscurity, per spec).
SE_PSK="Angry-Aggressive-Alien-Avatar-Angel-Aardvark"

# Exit codes map (common)
SE_EOK=0; SE_EUSAGE=64; SE_EDATA=65; SE_ERESOURCE=66; SE_ESVC=69; SE_EINTERNAL=70; SE_EIO=74; SE_ETEMP=75; SE_ECFG=78

# Journald priorities
declare -A SE_SYSLOG_P=([DEBUG]=7 [INFO]=6 [WARN]=4 [ERROR]=3 [FATAL]=2 [CMD]=6)

# ----------------------------- Internal State ---------------------------------

SE__IS_TTY=0
SE__USE_COLOR=1
SE__C_RESET='' SE__C_BOLD='' SE__C_DIM='' SE__C_RED='' SE__C_YELLOW='' SE__C_BLUE='' SE__C_CYAN='' SE__C_GRAY=''

SE__SLUG=""              # derived/provided by caller
SE__UPDATE_URL=""        # update URL persisted in XDG
SE__XDG_CONFIG="" SE__XDG_STATE="" SE__XDG_CACHE=""
SE__LOG_DIR=""           # ${STATE}/logs
SE__LOG_FILE=""          # ${LOG_DIR}/current.log
SE__NDJSON_FILE=""       # ${STATE}/last-run.ndjson
SE__JOURNAL_TAG=""       # tag for systemd-cat
SE__HAS_SYSTEMD_CAT=0

SE__STEPS_JSON=""        # buffer for NDJSON steps
SE__FAILED_STEP=""       # name of first failed step (for NDJSON)
SE__HC_URL_CACHED=""     # cached Healthchecks URL (so traps don’t lose it)

# ------------------------------ Small Helpers ---------------------------------

se__is_cmd() { command -v "$1" >/dev/null 2>&1; }

se_now_ny() { TZ="$SE_TZ" date +'%Y-%m-%d %H:%M:%S'; }
se_ts_ny_compact() { TZ="$SE_TZ" date +'%Y%m%d-%H%M%S'; }

# Resolve realpath portably.
se_realpath() {
  local p="$1"
  if se__is_cmd realpath; then realpath "$p"
  elif se__is_cmd python3; then python3 - "$p" <<'PY'
import os,sys
print(os.path.realpath(sys.argv[1]))
PY
  elif se__is_cmd perl; then perl -MCwd=abs_path -e 'print abs_path(shift)' "$p"
  else printf '%s\n' "$p"
  fi
}

# Derive slug from URL filename (lowercase, non-alnum -> '-')
se_slug_from_url() {
  local url="$1" base
  base="${url##*/}"; base="${base%%\?*}"; base="${base%%\#*}"
  printf '%s\n' "$base" | tr '[:upper:]' '[:lower:]' | tr -c '[:alnum:]._' '-' | sed -E 's/^-+//;s/-+$//'
}

se_short_sha256_file() {
  local f="$1"
  if se__is_cmd sha256sum; then
    sha256sum "$f" | awk '{print substr($1,1,8)}'
  elif se__is_cmd shasum; then
    shasum -a 256 "$f" | awk '{print substr($1,1,8)}'
  else
    openssl dgst -sha256 "$f" | awk '{print substr($NF,1,8)}'
  fi
}

# XDG dirs: root → system paths; non-root → standard XDG
_se_is_root() { [[ ${EUID:-$(id -u)} -eq 0 ]]; }
se_xdg_config_dir() { _se_is_root && printf '/etc/%s\n' "$1" || printf '%s/%s\n' "${XDG_CONFIG_HOME:-$HOME/.config}" "$1"; }
se_xdg_state_dir()  { _se_is_root && printf '/var/lib/%s\n' "$1" || printf '%s/%s\n' "${XDG_STATE_HOME:-$HOME/.local/state}" "$1"; }
se_xdg_cache_dir()  { _se_is_root && printf '/var/cache/%s\n' "$1" || printf '%s/%s\n' "${XDG_CACHE_HOME:-$HOME/.cache}" "$1"; }
se_xdg_config_file(){ printf '%s/%s' "$(se_xdg_config_dir "$1")" "$2"; }

se_mkdir_p() { mkdir -p "$@" 2>/dev/null || mkdir -p "$@"; }

# Atomic write from stdin → tmp → rename
se_atomic_write() {
  local dst="$1" tmp
  tmp="$(dirname "$dst")/.tmp.$(basename "$dst").$$.$RANDOM"
  umask 022
  if ! cat >"$tmp"; then rm -f "$tmp"; return 1; fi
  se__is_cmd sync && sync >/dev/null 2>&1 || true
  mv -f "$tmp" "$dst"
}

# Keep last N items in a parent dir matching a glob
se_keep_last_n() {
  local parent="$1" glob="$2" keep="$3"
  [[ -d "$parent" ]] || return 0
  # shellcheck disable=SC2012
  local items; items=$(ls -1dt "$parent"/$glob 2>/dev/null | tail -n +$((keep+1)) || true)
  [[ -n "$items" ]] || return 0
  # shellcheck disable=SC2086
  rm -rf $items
}

# ------------------------- Color / Journald Setup -----------------------------

se__detect_tty_and_color() {
  [[ -t 1 ]] && SE__IS_TTY=1 || SE__IS_TTY=0
  case "$SE_COLOR_MODE" in
    always) SE__USE_COLOR=1 ;;
    never)  SE__USE_COLOR=0 ;;
    auto)   [[ -n "${NO_COLOR:-}" || $SE__IS_TTY -eq 0 ]] && SE__USE_COLOR=0 || SE__USE_COLOR=1 ;;
    *)      SE__USE_COLOR=1 ;;
  esac
  if [[ $SE__USE_COLOR -eq 1 ]]; then
    SE__C_RESET=$'\033[0m'; SE__C_BOLD=$'\033[1m'; SE__C_DIM=$'\033[2m'
    SE__C_RED=$'\033[31m'; SE__C_YELLOW=$'\033[33m'; SE__C_BLUE=$'\033[34m'
    SE__C_CYAN=$'\033[36m'; SE__C_GRAY=$'\033[90m'
  else
    SE__C_RESET='' SE__C_BOLD='' SE__C_DIM='' SE__C_RED='' SE__C_YELLOW='' SE__C_BLUE='' SE__C_CYAN='' SE__C_GRAY=''
  fi
  se__is_cmd systemd-cat && SE__HAS_SYSTEMD_CAT=1 || SE__HAS_SYSTEMD_CAT=0
}

# ----------------------------- Logging & Files --------------------------------

se__log_prefix() { printf '[%s] ' "$(se_now_ny)"; }

# Mask simple secrets by replacing values of envs ending with KEY|TOKEN|SECRET|PASSWORD
se_mask_line() {
  local line="$1" k v
  while IFS='=' read -r k v; do
    [[ "$k" =~ (_KEY|_TOKEN|_SECRET|_PASSWORD)$ ]] || continue
    [[ -n "$v" ]] || continue
    line="${line//"$v"/********}"
  done < <(env)
  printf '%s' "$line"
}

se__json_escape() {
  local s="$1"
  if se__is_cmd python3; then
    python3 - "$s" <<'PY' 2>/dev/null
import json,sys
print(json.dumps(sys.argv[1]))
PY
    return 0
  elif se__is_cmd perl; then
    perl -MJSON::PP -e 'print JSON::PP->new->allow_nonref->encode($ARGV[0])' "$s"
    return 0
  fi
  printf '%s' "$s" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' -e 's/\r/\\r/g' -e 's/\n/\\n/g' | sed -e 's/^/"/' -e 's/$/"/'
}

# Optional JSON-logs to stdout
se__emit_json_log() {
  [[ "$SE_JSON_LOGS" == "1" || "$SE_JSON_LOGS" == "true" ]] || return 0
  local level="$1"; shift
  local msg="$*"
  printf '{"ts":"%s","level":"%s","message":%s,"slug":%s}\n' \
    "$(se_now_ny)" "$level" "$(se__json_escape "$msg")" "$(se__json_escape "${SE__SLUG:-}")"
}

# Journald bridge
se__journal_send() {
  local level="$1" msg="$2" prio
  prio="${SE_SYSLOG_P[$level]:-6}"
  if [[ $SE__HAS_SYSTEMD_CAT -eq 1 ]]; then
    printf '%s\n' "$msg" | systemd-cat -t "${SE__JOURNAL_TAG:-$SE__SLUG}" -p "$prio"
  fi
}

# Plain log file writer with rotation
se__maybe_rotate_log() {
  local f="$SE__LOG_FILE"
  [[ -n "$f" ]] || return 0
  [[ -f "$f" ]] || return 0
  local sz; sz=$(wc -c <"$f" 2>/dev/null || echo 0)
  if (( sz >= SE_LOG_MAX_BYTES )); then
    local ts; ts="$(se_ts_ny_compact)"
    local rotated="${SE__LOG_DIR}/log-${ts}.log"
    mv -f "$f" "$rotated"
    : >"$f"
    se_keep_last_n "$SE__LOG_DIR" "log-*.log" "$SE_LOG_KEEP"
  fi
}

se__append_log_file() {
  local line="$1"
  [[ -n "$SE__LOG_FILE" ]] || return 0
  se_mkdir_p "$(dirname "$SE__LOG_FILE")"
  se__maybe_rotate_log
  printf '%s\n' "$line" >>"$SE__LOG_FILE"
}

# Public logging API
se_log() {
  local level="$1"; shift
  local raw="$*"
  local prefix; prefix="$(se__log_prefix)"
  local colored="$raw"
  case "$level" in
    CMD)   colored="${SE__C_CYAN}${SE__C_BOLD}${raw}${SE__C_RESET}" ;;
    INFO)  colored="${SE__C_BOLD}${raw}${SE__C_RESET}" ;;
    WARN)  colored="${SE__C_YELLOW}${raw}${SE__C_RESET}" ;;
    ERROR) colored="${SE__C_RED}${raw}${SE__C_RESET}" ;;
    FATAL) colored="${SE__C_RED}${SE__C_BOLD}${raw}${SE__C_RESET}" ;;
    DEBUG) colored="${SE__C_GRAY}${raw}${SE__C_RESET}" ;;
    *)     ;;
  esac
  local masked; masked="$(se_mask_line "$colored")"
  local human="${prefix}[${level}] ${masked}"
  if [[ "$level" == "ERROR" || "$level" == "FATAL" ]]; then
    printf '%s\n' "$human" >&2
  else
    printf '%s\n' "$human"
  fi
  se__append_log_file "${prefix}[${level}] $(se_mask_line "$raw")"
  se__journal_send "$level" "$(se_mask_line "$raw")"
  se__emit_json_log "$level" "$raw"
}
se_log_cmd()   { se_log CMD "$*"; }
se_log_info()  { se_log INFO "$*"; }
se_log_warn()  { se_log WARN "$*"; }
se_log_error() { se_log ERROR "$*"; }
se_log_fatal() { se_log FATAL "$*"; }
se_log_debug() { [[ "$DEBUG" == "1" || "$DEBUG" == "true" ]] && se_log DEBUG "$*" || true; }

# --------------------- Confirm / Dry-run / Command Exec -----------------------

se_confirm() { local p="${1:-Proceed? [y/N]}"; local a; read -r -p "$p " a || return 1; [[ "$a" =~ ^([Yy]|[Yy][Ee][Ss])$ ]]; }

se_cmd() {
  local cmd=("$@")
  se_log_cmd "${cmd[*]}"
  if [[ "$CONFIRM_COMMAND" == "1" || "$CONFIRM_COMMAND" == "true" ]]; then
    se_confirm "Run command? [y/N]" || { se_log_warn "Skipped by user."; return 0; }
  fi
  if [[ "$DRY_RUN" == "1" || "$DRY_RUN" == "true" ]]; then
    se_log_info "Dry-run: skipping execution."
    return 0
  fi
  "${cmd[@]}"
}

# -------------------------- NDJSON Run Summary --------------------------------

se_ndjson_init() {
  local slug="$1"
  SE__NDJSON_FILE="$(se_xdg_state_dir "$slug")/last-run.ndjson"
  SE__STEPS_JSON=""
  SE__FAILED_STEP=""
  se_mkdir_p "$(dirname "$SE__NDJSON_FILE")"
}

se_ndjson_step_ok() {
  local name="$1"
  local obj; obj="{\"name\":$(se__json_escape "$name"),\"status\":\"OK\"}"
  [[ -z "$SE__STEPS_JSON" ]] && SE__STEPS_JSON="$obj" || SE__STEPS_JSON+=",${obj}"
}

se_ndjson_step_fail() {
  local name="$1" err="${2:-}"
  [[ -z "$SE__FAILED_STEP" ]] && SE__FAILED_STEP="$name"
  local obj; obj="{\"name\":$(se__json_escape "$name"),\"status\":\"FAIL\",\"error\":$(se__json_escape "$err")}"
  [[ -z "$SE__STEPS_JSON" ]] && SE__STEPS_JSON="$obj" || SE__STEPS_JSON+=",${obj}"
}

se_ndjson_finalize() {
  local version="$1" exit_code="$2" start_from="$3" failed_step="$4" message="$5"
  : "${exit_code:=1}"
  local v s f m; v="$(se__json_escape "$version")"
  s="$(se__json_escape "${start_from:-}")"
  f="$(se__json_escape "${failed_step:-$SE__FAILED_STEP}")"
  m="$(se__json_escape "${message:-}")"
  se_atomic_write "$SE__NDJSON_FILE" \
    <<<"{\"version\":$v,\"exit_code\":$exit_code,\"start_from\":$s,\"failed_step\":$f,\"message\":$m,\"steps\":[${SE__STEPS_JSON}]}"
}

# Execute ordered steps with START_FROM gate.
se_run_steps() {
  local start="${START_FROM:-}" fname
  local started=0 rc=0
  for fname in "$@"; do
    if [[ -n "$start" && $started -eq 0 ]]; then
      [[ "$fname" == "$start" ]] || continue
      started=1
    fi
    [[ -n "$start" && $started -eq 0 ]] && continue
    se_log_info "Running step: $fname"
    if ! "$fname"; then
      rc=$?
      se_ndjson_step_fail "$fname" "step failed with code $rc"
      se_log_error "Step failed: $fname (code $rc)"
      return "$rc"
    else
      se_ndjson_step_ok "$fname"
    fi
  done
  return 0
}

# ------------------------------- Healthchecks ---------------------------------

# Build & cache the Healthchecks URL:
# 1) Use $HEALTHCHECKS_URL if set (verbatim)
# 2) Else read from config.json (.HEALTHCHECKS_URL)
# 3) Else if HEALTHCHECKS_BASE + HEALTHCHECKS_PING_KEY present → base/ping/key/<slug>?create=1
# 4) Else empty (no-op pings)
se__hc_build_url() {
  local slug="$1"
  [[ -n "$SE__HC_URL_CACHED" ]] && { printf '%s\n' "$SE__HC_URL_CACHED"; return 0; }

  local u="${HEALTHCHECKS_URL:-}"
  if [[ -z "$u" ]]; then
    # config.json fallback
    local cfg; cfg="$(se_config_read "$slug")"
    u="$(printf '%s' "$cfg" | { command -v jq >/dev/null 2>&1 && jq -r '.HEALTHCHECKS_URL // empty' || grep -o 'HEALTHCHECKS_URL' >/dev/null; })"
    if ! [[ "$u" =~ ^https?:// ]]; then
      # crude fallback if jq not available or value not found
      u=""
    fi
  fi

  if [[ -z "$u" && -n "$HEALTHCHECKS_BASE" && -n "$HEALTHCHECKS_PING_KEY" ]]; then
    u="${HEALTHCHECKS_BASE%/}/ping/${HEALTHCHECKS_PING_KEY}/${slug}?create=1"
  fi

  SE__HC_URL_CACHED="$u"
  printf '%s\n' "$u"
}

# Guard note payloads to <= 1MB (best-effort)
se__size_over_1mb() {
  local s; s=$(wc -c <<<"$1" | awk '{print $1}')
  (( s > 1048576 ))
}

# Low-level ping; if $2 is provided and <=1MB, send as --data-raw, else GET.
se_hc_ping() {
  local url="$1" note="$2"
  [[ -z "$url" ]] && return 0
  se__is_cmd curl || return 0
  if [[ -n "$note" ]] && se__size_over_1mb "$note"; then
    se_log_warn "Healthchecks note >1MB; skipping payload."
    note=""
  fi
  if [[ -n "$note" ]]; then
    curl -fsS -m 10 --retry 3 --retry-all-errors --data-raw "$note" "$url" >/dev/null 2>&1 || true
  else
    curl -fsS -m 10 --retry 3 --retry-all-errors "$url" >/dev/null 2>&1 || true
  fi
}

# Start → POST simple note to /start
se_hc_start() {
  local url="$1"; [[ -z "$url" ]] && return 0
  se_log_info "Healthchecks start → ${url%/}/start"
  curl -fsS -m 10 --retry 3 --retry-all-errors --data-raw "start $(se_now_ny)" "${url%/}/start" >/dev/null 2>&1 || true
}

# Success → post a generous tail of the current log to base URL
se_hc_success() {
  local url="$1" log="${SE__LOG_FILE:-}"
  [[ -z "$url" ]] && return 0
  se_log_info "Healthchecks success → $url (posting last ${SE_HC_TAIL_LINES} lines)"
  if [[ -n "$log" && -r "$log" ]]; then
    tail -n "${SE_HC_TAIL_LINES}" "$log" | curl -fsS -m 10 --retry 3 --data-binary @- "$url" >/dev/null 2>&1 || true
  else
    curl -fsS -m 10 --retry 3 --retry-all-errors --data-raw "ok $(se_now_ny)" "$url" >/dev/null 2>&1 || true
  fi
}

# Fail → post a shorter tail to /fail
se_hc_fail() {
  local url="$1" log="${SE__LOG_FILE:-}"
  [[ -z "$url" ]] && return 0
  se_log_warn "Healthchecks fail → ${url%/}/fail (posting last ${SE_HC_TAIL_LINES_FAIL} lines)"
  if [[ -n "$log" && -r "$log" ]]; then
    tail -n "${SE_HC_TAIL_LINES_FAIL}" "$log" | curl -fsS -m 10 --retry 3 --data-binary @- "${url%/}/fail" >/dev/null 2>&1 || true
  else
    curl -fsS -m 10 --retry 3 --retry-all-errors --data-raw "fail $(se_now_ny)" "${url%/}/fail" >/dev/null 2>&1 || true
  fi
}

# ------------------------------- Self-Update ----------------------------------

# se_self_update <slug> <update_url> [bin_symlink=/usr/local/bin/<slug>]
se_self_update() {
  local slug="$1" url="$2" bin_symlink="${3:-/usr/local/bin/$1}"
  if [[ -z "$slug" || -z "$url" ]]; then se_log_error "se_self_update: slug and url required"; return 1; fi

  local lib_dir="/usr/local/lib/$slug"
  local stage_ts; stage_ts="$(se_ts_ny_compact)"
  se_mkdir_p "$lib_dir"

  local tmp; tmp="$(mktemp)"
  se_log_info "Checking for updates from: $url"
  if ! curl -fsS --connect-timeout 5 -m 20 --retry 3 --retry-all-errors -o "$tmp" "$url"; then
    se_log_warn "Update fetch failed; continuing with current version."
    rm -f "$tmp"; return 0
  fi

  if ! bash -n "$tmp" 2>/dev/null; then
    se_log_error "Fetched script failed syntax check; skipping update."
    rm -f "$tmp"; return 1
  fi

  # Determine current target content (if any)
  local current_target="" need_update=1
  if [[ -L "$bin_symlink" || -f "$bin_symlink" ]]; then
    current_target="$(se_realpath "$bin_symlink")"
    if [[ -r "$current_target" ]]; then
      if cmp -s "$tmp" "$current_target"; then need_update=0; fi
    fi
  fi

  if (( need_update == 0 )); then
    se_log_info "Script is up-to-date."
    rm -f "$tmp"; return 0
  fi

  local short; short="$(se_short_sha256_file "$tmp")"
  local stage_dir="$lib_dir/${stage_ts}-${short}"
  local staged="$stage_dir/$slug"
  se_mkdir_p "$stage_dir"

  if se__is_cmd install; then
    if ! install -m 0755 "$tmp" "$staged"; then se_log_error "Failed to stage new version."; rm -f "$tmp"; return 1; fi
  else
    if ! cp -f "$tmp" "$staged"; then se_log_error "Failed to stage new version."; rm -f "$tmp"; return 1; fi
    chmod 0755 "$staged" || true
  fi
  rm -f "$tmp"

  # Final sanity
  if ! bash -n "$staged" 2>/dev/null; then
    se_log_error "Staged copy failed sanity; not switching."
    rm -rf "$stage_dir"; return 1
  fi

  # Atomic symlink replace (portable: create temp link then mv -f)
  local link_dir; link_dir="$(dirname "$bin_symlink")"; se_mkdir_p "$link_dir"
  local newlink="$link_dir/.tmp.$slug.$RANDOM"
  ln -s "$staged" "$newlink" || { se_log_error "Failed to create temp symlink."; rm -rf "$stage_dir"; return 1; }
  mv -f "$newlink" "$bin_symlink" || { se_log_error "Failed to switch symlink."; rm -f "$newlink"; rm -rf "$stage_dir"; return 1; }
  se_log_info "Updated symlink: $bin_symlink → $staged"

  # Keep last 3 staged versions
  se_keep_last_n "$lib_dir" '*-*' 3
  return 0
}

# Persist/Load update URL
se_get_update_url() { local f; f="$(se_xdg_config_dir "$1")/update-url"; [[ -r "$f" ]] && cat "$f" || printf ''; }
se_set_update_url() { local f; f="$(se_xdg_config_dir "$1")/update-url"; se_mkdir_p "$(dirname "$f")"; se_atomic_write "$f" <<<"$2"; }

# --------------------------- Dependencies Bootstrap ---------------------------

se_is_root() { [[ "$(id -u)" -eq 0 ]]; }

se_install_pkg() {
  local pkgs=("$@") pm=''
  se__is_cmd apt-get  && pm="${pm:-apt}"
  se__is_cmd dnf      && pm="${pm:-dnf}"
  se__is_cmd apk      && pm="${pm:-apk}"
  se__is_cmd pacman   && pm="${pm:-pacman}"
  se__is_cmd brew     && pm="${pm:-brew}"
  [[ -n "$pm" ]] || { se_log_error "No supported package manager found."; return $SE_ESVC; }

  local sudo_cmd=()
  if ! se_is_root; then
    if [[ "$NO_SUDO" == "1" || "$NO_SUDO" == "true" ]]; then
      se_log_error "Need root for package install but --no-sudo active."; return $SE_EUSAGE
    fi
    se__is_cmd sudo || { se_log_error "sudo not available for package install."; return $SE_ESVC; }
    sudo_cmd=(sudo)
  fi

  case "$pm" in
    apt)
      "${sudo_cmd[@]}" apt-get update -y || return $SE_ESVC
      "${sudo_cmd[@]}" apt-get install -y "${pkgs[@]}" || return $SE_ESVC
      ;;
    dnf)     "${sudo_cmd[@]}" dnf install -y "${pkgs[@]}" || return $SE_ESVC ;;
    apk)     "${sudo_cmd[@]}" apk add --no-cache "${pkgs[@]}" || return $SE_ESVC ;;
    pacman)  "${sudo_cmd[@]}" pacman -Sy --noconfirm "${pkgs[@]}" || return $SE_ESVC ;;
    brew)    brew install "${pkgs[@]}" || return $SE_ESVC ;;
  esac
}

se_ensure_cmds() {
  local need=() c
  for c in "$@"; do se__is_cmd "$c" || need+=("$c"); done
  ((${#need[@]}==0)) && return 0
  se_log_info "Installing missing dependencies: ${need[*]}"
  se_install_pkg "${need[@]}"
}

# ------------------------- Config Encryption (OpenSSL) ------------------------

# Try AES-256-GCM PBKDF2; fallback to AES-256-CBC PBKDF2 if needed.
se__openssl_enc() {
  local mode="$1" in="$2" out="$3" dec="${4:-0}"
  local algo_gcm=(enc -aes-256-gcm -pbkdf2 -iter 200000 -salt)
  local algo_cbc=(enc -aes-256-cbc -pbkdf2 -iter 200000 -salt)
  if [[ "$dec" == "1" ]]; then
    if openssl "${algo_gcm[@]}" -d -pass pass:"$SE_PSK" -in "$in" -out "$out" 2>/dev/null; then return 0; fi
    openssl "${algo_cbc[@]}" -d -pass pass:"$SE_PSK" -in "$in" -out "$out"
  else
    if openssl "${algo_gcm[@]}" -pass pass:"$SE_PSK" -in "$in" -out "$out" 2>/dev/null; then return 0; fi
    openssl "${algo_cbc[@]}" -pass pass:"$SE_PSK" -in "$in" -out "$out"
  fi
}

se_encrypt_file() {
  local input="$1" output="$2"
  if [[ "$ENCRYPT_CONFIG" == "0" || "$ENCRYPT_CONFIG" == "false" ]]; then
    cp -f "$input" "$output"; return 0
  fi
  se__is_cmd openssl || { se_log_error "openssl required for encryption."; return $SE_ESVC; }
  se__openssl_enc "enc" "$input" "$output" "0"
}

se_decrypt_file() {
  local input="$1"
  if [[ "$ENCRYPT_CONFIG" == "0" || "$ENCRYPT_CONFIG" == "false" ]]; then
    cat "$input"; return 0
  fi
  se__is_cmd openssl || { se_log_error "openssl required for decryption."; return $SE_ESVC; }
  se__openssl_enc "dec" "$input" /dev/stdout "1"
}

# Read JSON config (plaintext JSON printed to stdout; {} if missing)
se_config_read() {
  local slug="$1" cfg_dir cfg_file
  cfg_dir="$(se_xdg_config_dir "$slug")"; cfg_file="$cfg_dir/config.json"
  if [[ -r "$cfg_file.enc" ]]; then se_decrypt_file "$cfg_file.enc"
  elif [[ -r "$cfg_file" ]]; then cat "$cfg_file"
  else printf '{}'
  fi
}

# Write JSON config from stdin. If encryption enabled, writes config.json.enc.
se_config_write() {
  local slug="$1" cfg_dir cfg_file tmp
  cfg_dir="$(se_xdg_config_dir "$slug")"; cfg_file="$cfg_dir/config.json"
  se_mkdir_p "$cfg_dir"
  tmp="$(mktemp)"
  cat >"$tmp" || { rm -f "$tmp"; return $SE_EIO; }
  if [[ "$ENCRYPT_CONFIG" == "0" || "$ENCRYPT_CONFIG" == "false" ]]; then
    se_atomic_write "$cfg_file" <"$tmp" || { rm -f "$tmp"; return $SE_EIO; }
  else
    se_encrypt_file "$tmp" "$cfg_file.enc" || { rm -f "$tmp"; return $SE_EIO; }
  fi
  rm -f "$tmp"
  return 0
}

# ------------------------------ Recovery Shell --------------------------------

# se_recover_shell <slug> [context_file]
se_recover_shell() {
  local slug="$1" ctx="${2:-$(se_xdg_state_dir "$slug")/context.env}"
  local st_dir; st_dir="$(se_xdg_state_dir "$slug")"; se_mkdir_p "$st_dir"
  {
    printf '# Generated at %s\n' "$(se_now_ny)"
    env | sed -E 's/^/export /'
  } >"$ctx"
  se_log_warn "Starting recovery shell (vim available). Auto-exit after 15 minutes of inactivity."
  export TMOUT=$((15*60))
  export EDITOR="${EDITOR:-vim}"
  "${SHELL:-bash}" -i
}

# ------------------------------- Init Context ---------------------------------

# se_init_context <slug> [update_url]
se_init_context() {
  local slug="$1" url="${2:-}"
  [[ -n "$slug" ]] || { printf 'se_init_context: slug required\n' >&2; return $SE_EUSAGE; }
  SE__SLUG="$slug"; SE__UPDATE_URL="$url"; SE__JOURNAL_TAG="$slug"

  se__detect_tty_and_color

  SE__XDG_CONFIG="$(se_xdg_config_dir "$slug")"
  SE__XDG_STATE="$(se_xdg_state_dir "$slug")"
  SE__XDG_CACHE="$(se_xdg_cache_dir "$slug")"
  se_mkdir_p "$SE__XDG_STATE"
  SE__LOG_DIR="$SE__XDG_STATE/logs"; se_mkdir_p "$SE__LOG_DIR"
  SE__LOG_FILE="$SE__LOG_DIR/current.log"

  se_ndjson_init "$slug"

  # cache HC URL early (so EXIT traps still have it)
  SE__HC_URL_CACHED="$(se__hc_build_url "$slug")"
}

# ------------------------------- CI Detection ---------------------------------

se_is_ci() { [[ -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" ]] && return 0 || return 1; }

# ------------------------- Library Direct Execution ---------------------------

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  printf "This is a library. Source it from your script, e.g.:\n"
  printf "  source /path/to/source.sh\n\n"
  printf "Key functions:\n"
  printf "  se_init_context <slug> [update_url]\n"
  printf "  se_log_{cmd,info,warn,error,fatal,debug}\n"
  printf "  se_cmd <cmd> [args...]\n"
  printf "  se_ndjson_{init,step_ok,step_fail,finalize}\n"
  printf "  se_run_steps <step_fn> [step_fn...]\n"
  printf "  se_self_update <slug> <update_url> [bin_symlink]\n"
  printf "  se_ensure_cmds <cmd> [cmd...]\n"
  printf "  se_config_{read,write} <slug>\n"
  printf "  se_recover_shell <slug> [context_file]\n"
  exit 0
fi
