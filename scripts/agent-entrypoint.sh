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
        emit_patch
        ;;
    interactive)
        run_agent "$@"
        emit_patch
        ;;
    *)
        echo "Error: unknown AGENT_MODE '$AGENT_MODE' (use 'interactive' or 'headless')" >&2
        exit 1
        ;;
esac
