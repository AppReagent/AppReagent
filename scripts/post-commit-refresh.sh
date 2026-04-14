#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-/tmp/area-build}"

echo "[post-commit] rebuilding area"
cmake -B "$BUILD_DIR" "$ROOT" >/dev/null
cmake --build "$BUILD_DIR" -j"$(nproc)" --target area >/dev/null

if ! sudo -n true 2>/dev/null; then
    echo "[post-commit] sudo -n is required to refresh /bin/area and restart area.service" >&2
    exit 1
fi

echo "[post-commit] refreshing /bin/area"
sudo -n ln -sf "$ROOT/area" /bin/area

echo "[post-commit] restarting area.service"
sudo -n systemctl restart area.service
sudo -n systemctl is-active area.service >/dev/null

echo "[post-commit] area.service restarted"
