#!/bin/sh
# SafeClaw CLI installer — github.com/SafeClaw-OSS/safeclaw (open source)
#
# Transparent by design — read it before you run it:
#   * Only downloads the prebuilt `sc` binary for your platform from the
#     project's LATEST GitHub Release, verifies its sha256, and installs it
#     to ~/.local/bin. No sudo. No system changes. No telemetry.
#   * The binaries are built by this repo's PUBLIC CI from the PUBLIC source
#     you can read here. Each release also carries a keyless sigstore
#     build-provenance attestation — verify it independently of the download:
#         gh attestation verify ~/.local/bin/sc --repo SafeClaw-OSS/safeclaw
set -eu

REPO="SafeClaw-OSS/safeclaw"
BASE="https://github.com/${REPO}/releases/latest/download"

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

echo "Downloading ${ASSET} from ${REPO} (latest release)..."
curl -fsSL "${BASE}/${ASSET}" -o "${DEST}/sc"
chmod +x "${DEST}/sc"

# Integrity check against the release's published checksums.
EXPECTED="$(curl -fsSL "${BASE}/SHA256SUMS" 2>/dev/null | grep " ${ASSET}\$" | awk '{print $1}' || true)"
if [ -n "${EXPECTED}" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL="$(sha256sum "${DEST}/sc" | awk '{print $1}')"
  else
    ACTUAL="$(shasum -a 256 "${DEST}/sc" | awk '{print $1}')"
  fi
  if [ "${EXPECTED}" != "${ACTUAL}" ]; then
    echo "Checksum mismatch — refusing to install." >&2
    echo "  expected ${EXPECTED}" >&2
    echo "  got      ${ACTUAL}" >&2
    rm -f "${DEST}/sc"
    exit 1
  fi
  echo "Checksum OK."
else
  echo "Warning: could not fetch SHA256SUMS; skipping checksum check." >&2
fi

echo "Installed: ${DEST}/sc"
echo "Verify provenance (optional):  gh attestation verify ${DEST}/sc --repo ${REPO}"
case ":${PATH}:" in
  *":${DEST}:"*) ;;
  *) echo "Add it to PATH:  export PATH=\"${DEST}:\$PATH\"" ;;
esac
echo "Next:  sc login --pair-token <token>"
