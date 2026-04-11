#!/bin/bash
# Build safeclaw release artifacts and create a GitHub release.
#
# Usage: ./scripts/release.sh [--draft]
#
# Creates:
#   - safeclaw-linux-x86_64.tar.gz  (binary)
#   - templates.tar.gz              (template files)
#
# Requires: cargo, strip, tar, gh (authenticated)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
TAG="v${VERSION}"
DRAFT=""
[[ "${1:-}" == "--draft" ]] && DRAFT="--draft"

echo "[release] Version: $TAG"
echo "[release] Building release binary..."

cargo build --release
strip target/release/safeclaw
BINARY_SIZE=$(ls -lh target/release/safeclaw | awk '{print $5}')
echo "[release] Binary: $BINARY_SIZE"

# Create temp dir for artifacts
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# 1. Binary tarball
echo "[release] Packaging binary..."
cp target/release/safeclaw "$TMPDIR/safeclaw"
tar -czf "$TMPDIR/safeclaw-linux-x86_64.tar.gz" -C "$TMPDIR" safeclaw
rm "$TMPDIR/safeclaw"

# 2. Templates tarball (only .md files at top level, skip archive/)
echo "[release] Packaging templates..."
tar -czf "$TMPDIR/templates.tar.gz" -C "$REPO_ROOT" \
    --exclude='templates/archive' \
    templates/

echo "[release] Artifacts:"
ls -lh "$TMPDIR"/*.tar.gz

# 3. Create GitHub release
echo "[release] Creating GitHub release $TAG..."
gh release create "$TAG" \
    "$TMPDIR/safeclaw-linux-x86_64.tar.gz" \
    "$TMPDIR/templates.tar.gz" \
    --title "SafeClaw $TAG" \
    --notes "$(cat <<EOF
## SafeClaw $TAG

### Assets
- \`safeclaw-linux-x86_64.tar.gz\` — Pre-built binary (Debian 12 / Ubuntu 22+)
- \`templates.tar.gz\` — Template files (skill.md, safeclaw.md, agents-snippet.md)

### Update
\`\`\`bash
./safeclaw update
\`\`\`
EOF
)" $DRAFT

echo ""
echo "[release] Done: https://github.com/SafeClaw-OSS/safeclaw/releases/tag/$TAG"
