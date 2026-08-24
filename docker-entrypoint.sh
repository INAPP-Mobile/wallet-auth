#!/bin/sh
set -e

# Railway volumes can arrive root-owned; fix ownership, then drop privileges.
DATA_DIR="${DATA_DIR:-/data}"
mkdir -p "$DATA_DIR"
chown -R wa:wa "$DATA_DIR" 2>/dev/null || true

exec su-exec wa:wa node src/server.js
