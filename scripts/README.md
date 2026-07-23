# scripts/ — Provisioning Tools

13 scripts + 10 partials power the install.doctor fleet provisioning system.

## Core Provisioning

- **start.sh** (repo root) — Bootstrap entry. Curls from `install.doctor/start`. Installs Homebrew, Task, base deps before cloning.
- **provision.sh** — Main provisioner. OS detection, package install, chezmoi apply, post-install hooks. 1186 lines.
- **src/provision.sh.tmpl** — Gomplate template generating provision.sh. 655 lines. CI warns when delta exceeds 500 lines.

## Libraries

- **lib/detect_os.sh** — SSOT for OS/role detection. Returns 12 OS types. Also: `detect_role()`, `detect_package_manager()`, `is_headless()`.

## Quality & Validation (all wired into CI)

- **test-detect-os.sh** — 14-assertion test suite. OS, role, package manager, headless, idempotency, embedded consistency.
- **validate-software-yml.sh** — Schema validator for 1171-entry software.yml. 3 checks + install method distribution report.
- **drift-check.sh** — `chezmoi diff` wrapper. `--json`/`--fix`/`--ci` modes. Source + target drift detection.
- **audit-deprecated.sh** — 160 deprecated entry audit. Categorization + `--json` mode.
- **generate-sbom.sh** — CycloneDX 1.4 SBOM from brew/apt/rpm. Wired into CI.

## Platform-Specific

- **homebrew.sh** — Homebrew install/management utilities
- **cloudflared-ssh.sh** — CF Tunnel SSH proxy setup
- **cloudflared-opnsense.sh** — CF Tunnel for OPNSense firewalls
- **pfsense.sh** — pfSense firewall provisioning
- **qubes-provision.sh** — Qubes OS dom0/AppVM provisioning
- **test-linux.sh** — Linux VM provisioning test driver (CI)
- **test-macos.sh** — macOS provisioning test driver (CI)

## Shared Partials (10 files in partials/)

Gomplate template fragments sourced by provision.sh.tmpl: basic-deps, full-disk-access, homebrew, import-cloudflare-certificate, logg, pfsense-netdata, pfsense-saml, pfsense-unifi, reboot, software.yml.header.
