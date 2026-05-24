#!/bin/sh
# SafeClaw daemon container entrypoint.
#
# Runs as root, makes sure $SAFECLAW_STATE_DIR exists and is owned by the
# `safeclaw` user, then drops privileges via gosu and exec's the daemon.
# This is the contract that lets the same image deploy unchanged to
# Railway / k8s / docker-compose / bare docker — each platform may mount
# a persistent volume at a different path and with root ownership, and
# this script normalises both cases.

set -e

STATE_DIR="${SAFECLAW_STATE_DIR:-/var/lib/safeclaw/state}"

mkdir -p "$STATE_DIR"
chown -R safeclaw:safeclaw "$STATE_DIR"

# Also ensure $HOME exists with the right owner — useful if the home
# happens to live on the same volume mount and got reset by the platform.
chown safeclaw:safeclaw /var/lib/safeclaw 2>/dev/null || true

exec gosu safeclaw "$@"
