#!/usr/bin/env bash
# scripts/generate-sbom.sh — Generate a CycloneDX 1.4 Software Bill of Materials
# from currently-installed packages and the software.yml registry.
#
# Usage:
#   bash scripts/generate-sbom.sh              # JSON SBOM to stdout
#   bash scripts/generate-sbom.sh --file sbom.json  # Write to file
#   bash scripts/generate-sbom.sh --compact    # Minimized JSON
set -euo pipefail

OUTPUT_FILE=""
COMPACT=false

for arg in "$@"; do
  case "$arg" in
    --file) OUTPUT_FILE="yes" ;;
    --compact) COMPACT=true ;;
    --file=*) OUTPUT_FILE="${arg#*=}" ;;
  esac
  # Handle --file with next arg
  if [ "$arg" = "--file" ] && [ -n "${2:-}" ] && [ "${2#--}" = "$2" ]; then
    OUTPUT_FILE="$2"
    shift
  fi
done

TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HOSTNAME="$(hostname -s 2>/dev/null || echo "unknown")"
UUID="$(uuidgen 2>/dev/null || echo "00000000-0000-0000-0000-000000000000")"

# ---------------------------------------------------------------------------
# Gather installed packages per package manager
# ---------------------------------------------------------------------------
components_json=""

# Homebrew (macOS + Linux)
if command -v brew &>/dev/null; then
  while IFS= read -r line; do
    pkg=$(echo "$line" | awk '{print $1}')
    ver=$(echo "$line" | awk '{print $2}')
    [ -z "$pkg" ] && continue
    escaped_pkg=$(echo "$pkg" | sed 's/"/\\"/g')
    escaped_ver=$(echo "$ver" | sed 's/"/\\"/g')
    components_json+="{\"type\":\"library\",\"name\":\"$escaped_pkg\",\"version\":\"$escaped_ver\",\"purl\":\"pkg:brew/$escaped_pkg@$escaped_ver\"},"
  done < <(brew list --versions 2>/dev/null | head -500)
fi

# APT (Debian/Ubuntu)
if command -v dpkg-query &>/dev/null; then
  while IFS= read -r line; do
    pkg=$(echo "$line" | awk '{print $1}')
    ver=$(echo "$line" | awk '{print $2}')
    [ -z "$pkg" ] && continue
    escaped_pkg=$(echo "$pkg" | sed 's/"/\\"/g')
    escaped_ver=$(echo "$ver" | sed 's/"/\\"/g')
    components_json+="{\"type\":\"library\",\"name\":\"$escaped_pkg\",\"version\":\"$escaped_ver\",\"purl\":\"pkg:deb/$escaped_pkg@$escaped_ver\"},"
  done < <(dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | head -500)
fi

# RPM (Fedora/RHEL)
if command -v rpm &>/dev/null && ! command -v dpkg-query &>/dev/null; then
  while IFS= read -r line; do
    pkg=$(echo "$line" | awk '{print $1}')
    ver=$(echo "$line" | awk '{print $2}')
    [ -z "$pkg" ] && continue
    escaped_pkg=$(echo "$pkg" | sed 's/"/\\"/g')
    escaped_ver=$(echo "$ver" | sed 's/"/\\"/g')
    components_json+="{\"type\":\"library\",\"name\":\"$escaped_pkg\",\"version\":\"$escaped_ver\",\"purl\":\"pkg:rpm/$escaped_pkg@$escaped_ver\"},"
  done < <(rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null | head -500)
fi

# Trim trailing comma
components_json="${components_json%,}"

# ---------------------------------------------------------------------------
# Build CycloneDX JSON
# ---------------------------------------------------------------------------
SBOM=$(cat <<END
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "serialNumber": "urn:uuid:$UUID",
  "version": 1,
  "metadata": {
    "timestamp": "$TIMESTAMP",
    "tools": [
      {"vendor": "install.doctor", "name": "generate-sbom", "version": "1.0.0"}
    ],
    "component": {
      "type": "application",
      "name": "install.doctor",
      "description": "Fleet provisioning for $HOSTNAME",
      "bom-ref": "install.doctor@$HOSTNAME"
    }
  },
  "components": [$components_json]
}
END
)

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
if $COMPACT; then
  echo "$SBOM" | python3 -c "import sys,json; json.dump(json.load(sys.stdin), sys.stdout)" 2>/dev/null || echo "$SBOM"
else
  echo "$SBOM" | python3 -m json.tool 2>/dev/null || echo "$SBOM"
fi

if [ -n "$OUTPUT_FILE" ] && [ "$OUTPUT_FILE" != "yes" ]; then
  echo "$SBOM" > "$OUTPUT_FILE"
  echo "SBOM written to $OUTPUT_FILE" >&2
fi
