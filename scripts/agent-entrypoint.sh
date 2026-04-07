#!/bin/bash
# Entrypoint for coding agent containers.
# Supports Claude Code, Codex, and OpenCode in interactive or headless mode.
# Source is COPIED into the image — changes are extracted as a patch.
set -e

AGENT="${AGENT:-claude}"
AGENT_MODE="${AGENT_MODE:-interactive}"
PATCH_DIR="/output"

# Write task to a file so the agent can reference it
if [ -n "$TASK" ]; then
    echo "$TASK" > /workspace/.task.md
fi

# Snapshot current state so we only capture the agent's changes
cd /workspace
git add -A && git commit -m "baseline" --allow-empty -q
BASELINE=$(git rev-parse HEAD)

# Pre-build area so the MCP tools work immediately
echo "[area] building..."
# Show a dot every 5s so it doesn't look frozen, while logging full output
make all -j14 > /tmp/area-build.log 2>&1 &
_BUILD_PID=$!
while kill -0 "$_BUILD_PID" 2>/dev/null; do
    sleep 5
    printf "."
done
wait "$_BUILD_PID"
_BUILD_RC=$?
echo ""
if [ $_BUILD_RC -eq 0 ]; then
    echo "[area] build ok"
else
    echo "[area] build failed — last 20 lines:"
    tail -20 /tmp/area-build.log
    echo "[area] use area_build MCP tool to retry"
fi

# Start the server in background (MCP area_chat needs it)
if [ -x ./area ]; then
    AREA_DATA_DIR="${AREA_DATA_DIR:-/opt/area}" ./area server &
    _AREA_SERVER_PID=$!
    for _i in $(seq 1 12); do
        [ -S "${AREA_DATA_DIR:-/opt/area}/area.sock" ] && break
        sleep 0.5
    done
    if [ -S "${AREA_DATA_DIR:-/opt/area}/area.sock" ]; then
        echo "[area] server ready (PID $_AREA_SERVER_PID)"
    else
        echo "[area] server failed to start — use area_server_start MCP tool"
    fi
fi

# Stop the area server if we started it
stop_area_server() {
    if [ -n "$_AREA_SERVER_PID" ] && kill -0 "$_AREA_SERVER_PID" 2>/dev/null; then
        ./area kill-server 2>/dev/null || kill "$_AREA_SERVER_PID" 2>/dev/null
        wait "$_AREA_SERVER_PID" 2>/dev/null
        echo "[area] server stopped"
    fi
}

# Emit a git patch covering everything the agent changed (committed or not)
emit_patch() {
    cd /workspace
    # Stage any uncommitted leftovers so they're included in the diff
    git add -A
    git commit -m "uncommitted changes" --allow-empty -q
    local patch
    # Exclude build artifacts — binaries can't be applied and should be recompiled
    patch=$(git diff "$BASELINE" HEAD -- . ':!area' ':!area_tests')
    if [ -n "$patch" ]; then
        echo "$patch" > "$PATCH_DIR/improve.patch"
        local count
        count=$(git diff --diff-filter=d --name-only "$BASELINE" HEAD -- . ':!area' ':!area_tests' | wc -l)
        echo "--- patch written to $PATCH_DIR/improve.patch ($count files) ---"
    else
        echo "--- no changes ---"
    fi
}

run_agent() {
    case "$AGENT" in
        claude)
            if [ "$AGENT_MODE" = "headless" ]; then
                claude -p "${TASK:-Read CLAUDE.md and follow the instructions.}" \
                    --dangerously-skip-permissions "$@"
            else
                claude --dangerously-skip-permissions "$@" || true
            fi
            ;;
        codex)
            if [ "$AGENT_MODE" = "headless" ]; then
                codex -q "${TASK:-Read CLAUDE.md}" --full-auto "$@"
            else
                exec codex --full-auto "$@"
            fi
            ;;
        opencode)
            if [ "$AGENT_MODE" = "interactive" ]; then
                exec opencode "$@"
            else
                echo "Error: opencode does not support headless mode" >&2
                exit 1
            fi
            ;;
        *)
            echo "Error: unknown agent '$AGENT'" >&2
            exit 1
            ;;
    esac
}

case "$AGENT_MODE" in
    headless)
        run_agent "$@"
        stop_area_server
        emit_patch
        ;;
    interactive)
        run_agent "$@"
        stop_area_server
        emit_patch
        ;;
    *)
        echo "Error: unknown AGENT_MODE '$AGENT_MODE' (use 'interactive' or 'headless')" >&2
        exit 1
        ;;
esac
