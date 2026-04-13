#!/bin/bash
# bench/eval.sh — score the area agent against a private RE corpus.
#
# Iterates over each subdirectory in $AREA_BENCH_DIR. Each subdir must
# contain one or more binaries (.exe/.dll/.so/.bin/.elf/...) and a
# reference PDF writeup. The agent is driven via `area chat` with a
# standard RE prompt; its output is then graded by bench/judge.py
# against the reference PDF. Scores and capability-gap tags land in
# bench/.scores/<run_id>/ (gitignored).
#
# Nothing under $AREA_BENCH_DIR is read into the repo.
#
# Usage:
#   AREA_BENCH_DIR=$CORPUS_DIR bench/eval.sh                 # all subdirs
#   AREA_BENCH_DIR=$CORPUS_DIR bench/eval.sh entry-name      # one subdir
#
# Env:
#   AREA_BENCH_DIR  required — corpus root (each subdir = one entry)
#   AREA_BIN        optional — area binary (default: repo ./area)
#   AREA_CONFIG     optional — config.json to seed the temp server
#                             (default: /opt/area/config.json)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BENCH_DIR="${AREA_BENCH_DIR:-}"
if [[ -z "$BENCH_DIR" ]]; then
    echo "bench: AREA_BENCH_DIR not set" >&2
    exit 2
fi
if [[ ! -d "$BENCH_DIR" ]]; then
    echo "bench: $BENCH_DIR is not a directory" >&2
    exit 2
fi

AREA_BIN="${AREA_BIN:-$ROOT/area}"
AREA_CONFIG="${AREA_CONFIG:-/opt/area/config.json}"
if [[ ! -x "$AREA_BIN" ]]; then
    echo "bench: area binary not found at $AREA_BIN (run 'make' first)" >&2
    exit 2
fi
if [[ ! -f "$AREA_CONFIG" ]]; then
    echo "bench: seed config not found at $AREA_CONFIG" >&2
    exit 2
fi

RUN_ID="$(date +%Y%m%d-%H%M%S)"
SCORES_DIR="$ROOT/bench/.scores/$RUN_ID"
mkdir -p "$SCORES_DIR"
echo "bench: run $RUN_ID"
echo "bench: scores -> $SCORES_DIR"

# --- Driver: sudo when running against the root systemd server --------------
# The GhidraTool shells out to docker which requires root (or docker group
# membership). The production server under systemd runs as root and already
# has that. Rather than stand up our own temp server with sudo, we just pipe
# through it via `sudo area chat`. Chat IDs are namespaced per run so no state
# bleeds between entries.
AREA_CHAT=( sudo -n "$AREA_BIN" chat )
if ! sudo -n true 2>/dev/null; then
    echo "bench: passwordless sudo is required (Ghidra runs under docker as root)" >&2
    exit 2
fi
if [[ ! -S /opt/area/area.sock ]]; then
    echo "bench: /opt/area/area.sock not found — is area.service running?" >&2
    echo "       start it with 'sudo systemctl start area.service'" >&2
    exit 2
fi

# --- Pick target subdirs ----------------------------------------------------
SUBDIRS=("$@")
if [[ ${#SUBDIRS[@]} -eq 0 ]]; then
    SUBDIRS=()
    while IFS= read -r -d '' d; do
        SUBDIRS+=("$(basename "$d")")
    done < <(find "$BENCH_DIR" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z)
fi

# --- Per-entry eval ---------------------------------------------------------
SUMMARY_TSV="$SCORES_DIR/summary.tsv"
printf "entry\tscore\tgaps\n" > "$SUMMARY_TSV"

for sub in "${SUBDIRS[@]}"; do
    entry="$BENCH_DIR/$sub"
    if [[ ! -d "$entry" ]]; then
        echo "bench: skip $sub (not a directory)" >&2
        continue
    fi

    # Find binaries (reasonable RE targets)
    mapfile -t bins < <(find "$entry" -maxdepth 2 -type f \
        \( -iname "*.exe" -o -iname "*.dll" -o -iname "*.so" \
           -o -iname "*.bin" -o -iname "*.elf" -o -iname "*.sys" \) | sort)
    # Find reference PDF (first match)
    pdf="$(find "$entry" -maxdepth 2 -type f -iname "*.pdf" | head -1 || true)"

    if [[ -z "$pdf" ]]; then
        echo "bench: skip $sub — no reference PDF" >&2
        continue
    fi
    if [[ ${#bins[@]} -eq 0 ]]; then
        echo "bench: skip $sub — no binaries" >&2
        continue
    fi

    echo
    echo "=== $sub ==="
    echo "  pdf:      $(basename "$pdf")"
    echo "  binaries: ${#bins[@]}"

    prompt_file="$SCORES_DIR/$sub.prompt.txt"
    agent_out="$SCORES_DIR/$sub.agent.txt"
    verdict="$SCORES_DIR/$sub.verdict.json"

    # --- Pre-fetch Ghidra data for every binary so the agent doesn't need to
    # orchestrate tool calls; it just reads and writes. This sidesteps the
    # "agent loops forever on tool calls" failure mode and keeps the bench
    # measuring writeup quality, not tool orchestration.
    ghidra_ctx="$SCORES_DIR/$sub.ghidra.txt"
    : > "$ghidra_ctx"
    for b in "${bins[@]}"; do
        echo "" >> "$ghidra_ctx"
        echo "========== GHIDRA: $b ==========" >> "$ghidra_ctx"
        for mode in overview imports strings; do
            echo "" >> "$ghidra_ctx"
            echo "--- $mode ---" >> "$ghidra_ctx"
            sudo "$AREA_BIN" ghidra "$b" "$mode" >> "$ghidra_ctx" 2>&1 || echo "(ghidra $mode failed)" >> "$ghidra_ctx"
        done
    done
    echo "  prefetched: $(wc -l < "$ghidra_ctx") lines of Ghidra data"

    {
        echo "You are a senior malware reverse engineer. Produce ONE final writeup answering the questions below using ONLY the Ghidra data provided. Do not invent addresses, function names, or string literals that aren't present in the Ghidra output — if something is not in the data, say \"unknown — not in provided Ghidra data\"."
        echo
        echo "You may issue additional GHIDRA tool calls if you need to see decompiled C for a specific function:"
        echo "  GHIDRA: <path> | decompile | <FUN_name>"
        echo "  GHIDRA: <path> | decompile | 0x<address>"
        echo "  GHIDRA: <path> | xrefs | <FUN_name_or_address>"
        echo "Budget: at most 10 such calls, then emit the final answer."
        echo
        echo "Final response format (the framework parses this exactly):"
        echo "  THOUGHT: <one line>"
        echo "  ANSWER: <writeup>"
        echo "  ...markdown writeup addressing all questions..."
        echo "  </writeup>"
        echo
        echo "Questions (answer every one, cite hex addresses and exact strings from the Ghidra data):"
        echo "  1. File format, architecture, compiler, packer (if any)."
        echo "  2. Entry point / DllMain / relevant exports — with their addresses as shown."
        echo "  3. Key imports that hint at functionality — list by name."
        echo "  4. Most suspicious strings, quoted verbatim with addresses."
        echo "  5. Name ~5 of the most interesting functions (by function name from the overview). For each, say in 2-3 sentences what you think it does based on imports/strings xrefs, cite its address. Decompile it only if needed."
        echo "  6. Stack-constructed strings or XOR-obfuscated data visible in the provided data — decode them if you can; otherwise mark \"unknown — needs stack_string_reconstruction\" or \"unknown — needs xor_decode\"."
        echo "  7. Host-based indicators visible in strings (files, registry keys, services, mutexes)."
        echo "  8. Network-based indicators visible in strings (domains, IPs, URLs, ports, protocols) — quote the strings."
        echo "  9. Overall classification (dropper / C2 / spyware / ransomware / backdoor / keylogger / proxy / etc.) with confidence."
        echo " 10. Anything else notable — shellcode patterns, embedded resources, VM-detection tricks, crypto keys."
        echo
        echo "========================= GHIDRA DATA ========================="
        cat "$ghidra_ctx"
        echo "===================== END GHIDRA DATA ========================="
        echo
        echo "Now emit the writeup."
    } > "$prompt_file"

    # Fresh chat id per entry so context doesn't bleed across entries
    chat_id="bench-$RUN_ID-$sub"
    "${AREA_CHAT[@]}" "$chat_id" < "$prompt_file" > "$agent_out" 2>&1 || {
        echo "  agent run failed, see $agent_out"
    }

    # Judge
    if python3 "$ROOT/bench/judge.py" "$pdf" "$agent_out" "$AREA_CONFIG" > "$verdict" 2>"$SCORES_DIR/$sub.judge.err"; then
        score="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("score",0))' "$verdict")"
        gaps="$(python3 -c 'import json,sys;g=json.load(open(sys.argv[1])).get("capability_gaps",[]);print(",".join(g))' "$verdict")"
        echo "  score: $score / 100"
        [[ -n "$gaps" ]] && echo "  gaps:  $gaps"
        printf "%s\t%s\t%s\n" "$sub" "$score" "$gaps" >> "$SUMMARY_TSV"
    else
        echo "  judge failed — see $SCORES_DIR/$sub.judge.err"
        printf "%s\t%s\t%s\n" "$sub" "ERROR" "judge_failure" >> "$SUMMARY_TSV"
    fi
done

echo
echo "=== summary ==="
column -ts$'\t' < "$SUMMARY_TSV" || cat "$SUMMARY_TSV"
echo
echo "bench: done — $SCORES_DIR"
