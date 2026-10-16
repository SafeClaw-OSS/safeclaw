#!/bin/sh
# SafeClaw CLI installer: github.com/getsafeclaw/safeclaw (open source).
#
# What it does, in order (read it before you run it):
#   * Downloads the prebuilt `sc` binary for this platform from the project's
#     GitHub Releases (the latest release, or SAFECLAW_VERSION).
#   * Verifies it against the release's SHA256SUMS and refuses to install on any
#     mismatch or missing checksum.
#   * Installs it to ~/.local/bin (or SAFECLAW_BIN_DIR). No sudo, no shell
#     config changes, no telemetry.
#   * Installs the SafeClaw agent skill with `sc skill install` (skip with
#     --no-skill or SAFECLAW_NO_SKILL=1).
#   * When an AI agent runs it, continues with `sc setup`; skip this with
#     SAFECLAW_NO_SETUP=1. Otherwise, prints one next step.
set -eu

REPO="getsafeclaw/safeclaw"
if [ -n "${SAFECLAW_VERSION:-}" ]; then
  BASE="https://github.com/${REPO}/releases/download/${SAFECLAW_VERSION}"
  RELEASE="${SAFECLAW_VERSION}"
else
  BASE="https://github.com/${REPO}/releases/latest/download"
  RELEASE="latest release"
fi

NO_SKILL="${SAFECLAW_NO_SKILL:-0}"
for ARG in "$@"; do
  case "${ARG}" in
    --no-skill) NO_SKILL=1 ;;
    *) echo "Unknown argument: ${ARG}" >&2; exit 2 ;;
  esac
done

OS="$(uname -s)"
ARCH="$(uname -m)"
case "${OS}/${ARCH}" in
  Linux/x86_64)   ASSET="safeclaw-linux-x86_64" ;;
  Linux/aarch64)  ASSET="safeclaw-linux-aarch64" ;;
  Darwin/x86_64)  ASSET="safeclaw-macos-x86_64" ;;
  Darwin/arm64)   ASSET="safeclaw-macos-aarch64" ;;
  *) echo "Unsupported platform: ${OS}/${ARCH}" >&2; exit 1 ;;
esac

DEST="${SAFECLAW_BIN_DIR:-$HOME/.local/bin}"
mkdir -p "${DEST}"
DOWNLOAD="${DEST}/.sc-download.$$"
trap 'rm -f "${DOWNLOAD}"' EXIT HUP INT TERM

echo "Downloading ${ASSET} from ${REPO} (${RELEASE})..."
curl -fsSL "${BASE}/${ASSET}" -o "${DOWNLOAD}"

# Integrity check against the release's published checksums.
if ! SUMS="$(curl -fsSL "${BASE}/SHA256SUMS")"; then
  echo "Could not fetch SHA256SUMS; refusing to install." >&2
  exit 1
fi
EXPECTED="$(printf '%s\n' "${SUMS}" | awk -v asset="${ASSET}" '$2 == asset { print $1; exit }')"
if [ -z "${EXPECTED}" ]; then
  echo "SHA256SUMS has no checksum for ${ASSET}; refusing to install." >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "${DOWNLOAD}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL="$(shasum -a 256 "${DOWNLOAD}" | awk '{print $1}')"
else
  echo "No sha256sum or shasum command is available; refusing to install." >&2
  exit 1
fi
if [ "${EXPECTED}" != "${ACTUAL}" ]; then
  echo "Checksum mismatch; refusing to install." >&2
  echo "  expected ${EXPECTED}" >&2
  echo "  got      ${ACTUAL}" >&2
  exit 1
fi
echo "Checksum OK."

chmod +x "${DOWNLOAD}"
mv "${DOWNLOAD}" "${DEST}/sc"
trap - EXIT HUP INT TERM

if [ "${NO_SKILL}" != "1" ]; then
  if "${DEST}/sc" skill --help >/dev/null 2>&1; then
    if ! "${DEST}/sc" skill install; then
      echo "Warning: SafeClaw was installed, but the agent skill could not be installed." >&2
    fi
  fi
fi

echo "Installed: ${DEST}/sc"
case ":${PATH}:" in
  *":${DEST}:"*) ;;
  *) echo "Add it to PATH: export PATH=\"${DEST}:\$PATH\"" ;;
esac
if [ "${SAFECLAW_CHANNEL:-}" = "dev" ]; then
  PROFILE_ARG=" --profile dev"
else
  PROFILE_ARG=""
fi
if [ "${SAFECLAW_NO_SETUP:-0}" != "1" ] &&
  "${DEST}/sc" setup --detect-agent >/dev/null 2>&1; then
  echo "Setting up SafeClaw for this agent:"
  exec "${DEST}/sc" setup${PROFILE_ARG}
fi
echo "Next: sc setup --name <a name for this agent>${PROFILE_ARG}"
