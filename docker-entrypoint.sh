#!/bin/sh
set -e

# Railway volumes mount at /data. Export DATA_DIR so src/server.js resolves
# the same directory this script creates/chowns — without it the server falls
# back to $PWD/data (/app/data), which is root-owned and unwritable for the
# unprivileged runtime user.
export DATA_DIR="${DATA_DIR:-/data}"
mkdir -p "$DATA_DIR"
chown -R wa:wa "$DATA_DIR" 2>/dev/null || true

exec su-exec wa:wa node src/server.js
