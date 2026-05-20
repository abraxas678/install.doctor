#!/usr/bin/env bash
# @file ~/.local/bin/post-installx/post-zsh-bootstrap.sh
# @brief Pre-warm antigen bundles + point Terminal.app at the Meslo Nerd Font
# @description
#   On the first interactive zsh launch antigen clones ~7 bundle repos
#   (oh-my-zsh, zsh-autosuggestions, syntax-highlighting, fzf-tab,
#   powerlevel10k, ...) into ~/.local/share/antigen/bundles and prints a
#   wall of "Installing repo/name!..." lines. That happens *every* new
#   machine the first time someone opens their terminal. We pre-run that
#   here so the next interactive shell starts up silent and instant.
#
#   We also force Terminal.app's default profile to use the MesloLGS NF
#   font and pin a 13pt size — powerlevel10k's prompt uses powerline
#   glyphs that render as tofu in the stock SF Mono font.

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
# 1. Pre-warm antigen bundle cache
###########################################################################
preWarmAntigen() {
  local ANTIGEN_BIN="$HOME/.local/scripts/antigen.zsh"
  local ANTIGEN_HOME="${XDG_DATA_HOME:-$HOME/.local/share}/antigen"
  if [ ! -f "$ANTIGEN_BIN" ]; then
    gum log -sl warn "$ANTIGEN_BIN missing; skipping antigen pre-warm"
    return 0
  fi
  if ! command -v zsh > /dev/null; then
    gum log -sl warn 'zsh not found on PATH; skipping antigen pre-warm'
    return 0
  fi
  if [ -d "$ANTIGEN_HOME/bundles/romkatv/powerlevel10k" ] \
     && [ -d "$ANTIGEN_HOME/bundles/zsh-users/zsh-syntax-highlighting" ]; then
    gum log -sl info 'antigen bundles already populated; skipping pre-warm'
    return 0
  fi

  gum log -sl info 'Pre-warming antigen bundle cache by sourcing ~/.zshrc once'
  ### POWERLEVEL9K_INSTANT_PROMPT=quiet suppresses the p10k instant-prompt
  ### console-output warning that fires when antigen prints during init.
  ### `< /dev/null` keeps zsh from blocking on a tty read.
  POWERLEVEL9K_INSTANT_PROMPT=quiet zsh -i -c 'antigen reset 2>/dev/null; antigen apply 2>/dev/null; exit 0' < /dev/null > /dev/null 2>&1 || true

  if [ -d "$ANTIGEN_HOME/bundles/romkatv/powerlevel10k" ]; then
    gum log -sl info 'antigen bundles installed'
  else
    gum log -sl warn 'antigen pre-warm completed but bundle dir is still empty; first interactive zsh will install them'
  fi
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
preWarmAntigen

### configureTerminalFont failure is purely cosmetic — antigen still
### works without it, but powerline glyphs render as tofu.
configureTerminalFont || gum log -sl warn 'Terminal.app font configuration failed; set Terminal > Preferences > Profiles > Text > Font manually to MesloLGS NF.'
