# AppReagent Improvement Task

You are improving AppReagent, a malware analysis platform that uses LLM-powered
node graphs to analyze Android apps. Your changes must be tested.

## MCP Tools

The area server is **already running** and MCP tools are pre-configured. Use them
instead of raw shell commands:

| Tool | Replaces |
|------|----------|
| `area_build` | `make` |
| `area_test_unit` | `make test` |
| `area_test_e2e` | `./scripts/test-use-case.sh all` |
| `area_evaluate` | `./autoresearch/evaluate.sh` |
| `area_chat` | `echo "..." \| ./area chat` |
| `area_server_restart` | (restart after code/prompt changes) |

After editing C++ code, call `area_build` then `area_server_restart`.
After editing prompts only, call `area_server_restart` (no rebuild needed).

## Step 1: Orient

Read these files:
- `CLAUDE.md` — architecture, tools, how testing works
- `autoresearch/program.md` — eval framework and research directions
- A few existing tests in `tests/use-cases/` to understand the e2e test pattern

## Step 2: Build & Baseline

Run `area_test_unit` to confirm unit tests pass.

Then run `area_evaluate` for a corpus evaluation. Study the per-file breakdown.
Which files score lowest? Which dimension (classification, calibration, evidence)
is weakest?

If evaluation can't run (no DB, no LLM endpoints), skip eval and focus on
code-level improvements in Step 3B instead.

## Step 3: Make ONE improvement

Pick the highest-impact option based on what you learned:

### 3A: Improve scan accuracy (requires working eval)
- Read the per-file breakdown from Step 2
- Identify the weakest file and dimension
- Edit the relevant prompt in `prompts/` (triage.prompt, deep_analysis.prompt,
  synthesis.prompt, triage_supervisor.prompt)
- Optionally adjust thresholds in `src/graph/graphs/scan_task_graph.cpp`
- Rebuild (`area_build`) and restart (`area_server_restart`) if you changed C++
- Restart (`area_server_restart`) if you only changed prompts
- Re-run `area_evaluate`. Keep only if score improves; revert otherwise.

### 3B: Improve code quality (always available)
- Fix bugs found during build or testing
- Improve agent tools (`src/tools/`)
- Better smali parsing or pattern detection
- Improve the TUI or server robustness
- Add missing features described in CLAUDE.md

Only change ONE thing. Isolate the variable so you know what helped.

## Step 4: Add a use-case e2e test (MANDATORY)

**You MUST add a test for your change.** No exceptions.

Create a new test:
1. `mkdir -p tests/use-cases/<descriptive-name>`
2. Write `tests/use-cases/<descriptive-name>/test.sh`
3. Add `assets/` with test data if needed (e.g. smali files)

Use the test helpers — study an existing test first:
```bash
cat tests/use-cases/query-tables/test.sh
```

Available helpers:
- `ask "prompt"` — send a message to the agent, returns its response
- `assert_contains "$output" "pattern" "description"` — grep check
- `assert_not_contains "$output" "pattern" "description"` — inverse
- `assert_file_exists "path" "description"` — file created
- `assert_file_contains "path" "pattern" "description"` — grep file

## Step 5: Verify everything

1. `area_test_unit` — unit tests pass
2. `area_test_e2e` — all e2e tests pass (including your new one)

If you did 3A (prompt improvement), run `area_evaluate` again and compare.

## Rules

- ONE change per run. Don't try to fix everything.
- Every change gets a test. This is not optional.
- Don't modify `autoresearch/evaluate.sh` or `autoresearch/corpus/`
- Don't modify the graph engine (`src/graph/engine/`)
- If C++ changed, `area_test_unit` must pass
- Use MCP tools, not raw shell commands
- Explain what you changed and why
