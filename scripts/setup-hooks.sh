#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

git -C "$ROOT" config core.hooksPath .githooks
mkdir -p "$ROOT/.git/hooks"
ln -sf ../../.githooks/post-commit "$ROOT/.git/hooks/post-commit"

echo "[hooks] core.hooksPath=.githooks"
echo "[hooks] linked .git/hooks/post-commit"
