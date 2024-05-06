#!/usr/bin/env bash
# @file Atuin Initialization
# @brief Registers with atuin, logs in, imports command history, and synchronizes

if command -v atuin > /dev/null; then
    source "${XDG_CONFIG_HOME:-$HOME/.config}/shell/private.sh"
    atuin register -u "$ATUIN_USERNAME" -e "$ATUIN_EMAIL" -p "$ATUIN_PASSWORD"
    atuin login -u "$ATUIN_USERNAME" -p "$ATUIN_PASSWORD" -k "$ATUIN_KEY"
    atuin import auto
    atuin sync
else
    logg info 'atuin is not available in the PATH'
fi