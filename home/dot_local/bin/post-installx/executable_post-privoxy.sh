#!/usr/bin/env bash
# @file Privoxy Configuration
# @brief This script applies the Privoxy configuration stored at `${XDG_CONFIG_HOME:-HOME/.config}/privoxy/config` to the system and then restarts Privoxy
# @description
#     Privoxy is a web proxy that can be combined with Tor to provide an HTTPS / HTTP proxy that can funnel all traffic
#     through Tor. This script:
#
#     1. Determines the system configuration file location
#     2. Applies the configuration stored at `${XDG_CONFIG_HOME:-HOME/.config}/privoxy/config`
#     3. Enables and restarts the Privoxy service with the new configuration
#
#     ## Links
#
#     * [Privoxy configuration](https://github.com/megabyte-labs/install.doctor/tree/master/home/dot_config/privoxy/config)

### Configure variables
if [ -d /Applications ] && [ -d /System ]; then
  ### macOS
  if [ -d "/usr/local/etc/privoxy" ]; then
    PRIVOXY_CONFIG_DIR=/usr/local/etc/privoxy
  elif [ -d "${HOMEBREW_PREFIX:-/opt/homebrew}/etc/privoxy" ]; then
    PRIVOXY_CONFIG_DIR="${HOMEBREW_PREFIX:-/opt/homebrew}/etc/privoxy"
  else
    logg warn 'Unable to detect Privoxy configuration directory'
  fi
else
  ### Linux
  PRIVOXY_CONFIG_DIR=/etc/privoxy
fi
PRIVOXY_CONFIG="$PRIVOXY_CONFIG_DIR/config"

### Copy Privoxy configuration stored at `${XDG_CONFIG_HOME:-HOME/.config}/privoxy/config` to the system location
if command -v privoxy > /dev/null; then
  if [ -d  "$PRIVOXY_CONFIG_DIR" ]; then
    sudo cp -f "${XDG_CONFIG_HOME:-HOME/.config}/privoxy/config" "$PRIVOXY_CONFIG"
    sudo chmod 600 "$PRIVOXY_CONFIG"
    if command -v add-usergroup > /dev/null; then
      sudo add-usergroup "$USER" privoxy
    fi
    sudo chown privoxy:privoxy "$PRIVOXY_CONFIG" 2> /dev/null || sudo chown privoxy:$(id -g -n) "$PRIVOXY_CONFIG"

    ### Restart Privoxy after configuration is applied
    if [ -d /Applications ] && [ -d /System ]; then
      ### macOS
      brew services restart privoxy
    else
      if [[ ! "$(test -d /proc && grep Microsoft /proc/version > /dev/null)" ]]; then
        ### Linux
        sudo systemctl enable privoxy
        sudo systemctl restart privoxy
      else
        logg info 'The system is a WSL environment so the Privoxy systemd service will not be enabled / restarted'
      fi
    fi
  else
    logg warn 'The '"$PRIVOXY_CONFIG_DIR"' directory is missing'
  fi
else
  logg logg 'privoxy is missing from the PATH - skipping configuration'
fi