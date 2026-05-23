#!/usr/bin/env bash
# @file ~/.local/bin/post-installx/post-zsh-bootstrap.sh
# @brief Pre-warm zinit plugin cache, zcompile .zshrc, configure Terminal.app font
# @description
#   1. Pre-warm zinit plugins by sourcing ~/.zshrc once headless so the
#      first interactive terminal launch is silent and instant. (Replaces
#      the old antigen pre-warm path; antigen has been retired in favor of
#      zinit turbo mode.)
#   2. zcompile ~/.zshrc into ~/.zshrc.zwc so the zsh parser skips the
#      ~30-50ms tokenize/parse cost on every shell launch.
#   3. Force Terminal.app's default profile to use the MesloLGS Nerd Font
#      Mono at 13pt — powerlevel10k's powerline glyphs render as tofu in
#      the stock SF Mono.

set -u

### Only run on macOS.
[ -d /Applications ] && [ -d /System ] || exit 0

### gum is the standard logger across install.doctor scripts. Fall back to
### plain echo if it isn't on PATH yet (e.g. when this runs very early in
### a chroot/CI shell).
if ! command -v gum > /dev/null; then
  gum() {
    if [ "${1:-}" = "log" ]; then shift; while [ "$#" -gt 0 ] && [ "${1#-}" != "$1" ]; do shift; done; printf '%s %s\n' "${1:-INFO}" "${2:-}"; else "$@"; fi
  }
fi

###########################################################################
# 1. Pre-warm zinit plugin cache + zcompile .zshrc
###########################################################################
preWarmZinit() {
  if ! command -v zsh > /dev/null; then
    gum log -sl warn 'zsh not found on PATH; skipping zsh pre-warm'
    return 0
  fi
  local ZINIT_HOME="${XDG_DATA_HOME:-$HOME/.local/share}/zinit/zinit.git"
  local P10K_BUNDLE="${XDG_DATA_HOME:-$HOME/.local/share}/zinit/plugins/romkatv---powerlevel10k"

  if [ -d "$ZINIT_HOME" ] && [ -d "$P10K_BUNDLE" ]; then
    gum log -sl info 'zinit + powerlevel10k already populated; skipping plugin pre-warm'
  else
    gum log -sl info 'Pre-warming zinit plugins by sourcing ~/.zshrc once headless'
    ### POWERLEVEL9K_INSTANT_PROMPT=quiet suppresses the p10k console-output
    ### warning during the first sourcing (zinit clone output triggers it).
    ### `< /dev/null` keeps zsh from blocking on a tty read; `wait` lets
    ### turbo-mode plugins finish loading before we exit.
    POWERLEVEL9K_INSTANT_PROMPT=quiet zsh -i -c 'zinit wait_for_complete 2>/dev/null; sleep 1; exit 0' < /dev/null > /dev/null 2>&1 || true
    if [ -d "$P10K_BUNDLE" ]; then
      gum log -sl info 'zinit plugin cache pre-warmed'
    else
      gum log -sl warn 'zinit pre-warm finished but powerlevel10k not present; first interactive zsh will clone it'
    fi
  fi

  ### zcompile ~/.zshrc → ~/.zshrc.zwc. zsh checks for the .zwc on every
  ### shell launch and skips re-parsing the .zshrc when present + newer
  ### than its source. Saves ~30-50ms per shell launch.
  if [ -f "$HOME/.zshrc" ]; then
    gum log -sl info 'Compiling ~/.zshrc → ~/.zshrc.zwc'
    zsh -fc "zcompile -R -- '$HOME/.zshrc.zwc' '$HOME/.zshrc'" 2>/dev/null || gum log -sl warn 'zcompile failed (non-fatal)'
  fi
}

###########################################################################
# 2. Import existing shell history into atuin (idempotent — atuin
#    dedupes on import). Only runs if atuin is installed and the local DB
#    doesn't already have rows.
###########################################################################
importAtuinHistory() {
  command -v atuin > /dev/null || { gum log -sl info 'atuin not installed; skipping history import'; return 0; }
  local DB="${XDG_DATA_HOME:-$HOME/.local/share}/atuin/history.db"
  if [ -f "$DB" ] && [ "$(stat -f %z "$DB" 2>/dev/null || echo 0)" -gt 16384 ]; then
    gum log -sl info 'atuin history DB already populated; skipping import'
    return 0
  fi
  ### atuin auto-detects the shell + history file. Falls back to explicit
  ### HISTFILE if auto-detection fails (zsh history at a non-default path).
  gum log -sl info 'Importing existing shell history into atuin'
  HISTFILE="${HISTFILE:-${XDG_STATE_HOME:-$HOME/.local/state}/zsh/history}" atuin import auto 2>&1 | tail -3 | sed 's/^/  /'
}

###########################################################################
# 2. Force Terminal.app default profile to use MesloLGS NF
###########################################################################
configureTerminalFont() {
  ### Detect which MesloLGS face is actually installed and use its real
  ### family name. font-meslo-lg-nerd-font ships `MesloLGSNerdFontMono-
  ### Regular.ttf` (family `MesloLGS Nerd Font Mono`); the p10k-official
  ### download ships `MesloLGS NF Regular.ttf` (family `MesloLGS NF`).
  ### Both render the same powerline glyphs — we just need to use the
  ### family name macOS actually knows about.
  local FONT_FAMILY=""
  if ls "$HOME/Library/Fonts/MesloLGSNerdFontMono-Regular.ttf" /Library/Fonts/MesloLGSNerdFontMono-Regular.ttf 2>/dev/null | grep -q .; then
    FONT_FAMILY="MesloLGS Nerd Font Mono"
  elif ls "$HOME/Library/Fonts/MesloLGSNerdFont-Regular.ttf" /Library/Fonts/MesloLGSNerdFont-Regular.ttf 2>/dev/null | grep -q .; then
    FONT_FAMILY="MesloLGS Nerd Font"
  elif ls "$HOME/Library/Fonts/MesloLGS NF Regular.ttf" "/Library/Fonts/MesloLGS NF Regular.ttf" 2>/dev/null | grep -q .; then
    FONT_FAMILY="MesloLGS NF"
  else
    gum log -sl warn 'No MesloLGS face found in ~/Library/Fonts or /Library/Fonts; skipping Terminal.app font config (cask font-meslo-lg-nerd-font may not have installed)'
    return 0
  fi
  gum log -sl info "Detected installed Meslo family: $FONT_FAMILY"

  ### Apple's font cache may not have picked up the new TTF yet —
  ### `atsutil databases -remove` forces a rebuild and is safe to run
  ### even when nothing changed. Without this, the AppleScript call
  ### below can return "font not registered" on a fresh machine.
  atsutil databases -remove > /dev/null 2>&1 || true

  ### AppleScript is the cleanest way to set the font on every existing
  ### Terminal.app profile + lock in the default. We pass the detected
  ### family name in via the env so the AppleScript stays static.
  gum log -sl info "Configuring every Terminal.app settings set to use $FONT_FAMILY 13pt"
  TERMINAL_FONT_FAMILY="$FONT_FAMILY" /usr/bin/osascript <<'APPLESCRIPT' > /dev/null 2>&1 || gum log -sl warn 'AppleScript Terminal.app font config returned non-zero; check Terminal > Preferences manually'
on getEnv(varName)
  return do shell script "printf %s \"$" & varName & "\""
end getEnv

set famName to my getEnv("TERMINAL_FONT_FAMILY")

tell application "Terminal"
  set allProfiles to name of every settings set
  repeat with p in allProfiles
    try
      set font name of settings set (p as string) to famName
      set font size of settings set (p as string) to 13
    end try
  end repeat
  try
    set font name of default settings to famName
    set font size of default settings to 13
  end try
  try
    set font name of startup settings to famName
    set font size of startup settings to 13
  end try
end tell
APPLESCRIPT

  gum log -sl info "Terminal.app font set to $FONT_FAMILY 13pt. Open a new window to see the change."
}

###########################################################################
# Main
###########################################################################
preWarmZinit
importAtuinHistory

### configureTerminalFont failure is purely cosmetic — zinit still
### works without it, but powerline glyphs render as tofu.
configureTerminalFont || gum log -sl warn 'Terminal.app font configuration failed; set Terminal > Preferences > Profiles > Text > Font manually to MesloLGS NF.'
