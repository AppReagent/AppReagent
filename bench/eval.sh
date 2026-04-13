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

    {
        echo "You are a senior malware reverse engineer. Produce a thorough RE writeup for the following binaries. Use the GHIDRA tool aggressively — one call per mode (overview, imports, strings, decompile, xrefs) per binary is the floor. When the question asks about a specific address, function, count, or decoded string, give the bit-exact answer. When uncertain, say so."
        echo
        echo "Answer these canonical questions for each binary (PMA-style):"
        echo "  1. File format, architecture, compiler, packer (if any)."
        echo "  2. Key imports that hint at functionality."
        echo "  3. Most suspicious strings (quote hex addresses)."
        echo "  4. Entry-point address (main / DllMain / export of interest)."
        echo "  5. For each notable subroutine: decompile, name its purpose, cite address."
        echo "  6. Stack strings and obfuscated data — decode them explicitly."
        echo "  7. Host-based indicators (files, registry, services, mutexes)."
        echo "  8. Network-based indicators (domains, IPs, URLs, ports, protocols)."
        echo "  9. Overall classification (dropper / C2 / spyware / ransomware / backdoor / etc.) with confidence."
        echo " 10. Anything else notable — shellcode, embedded resources, VM-detection, crypto keys."
        echo
        echo "Binaries:"
        for b in "${bins[@]}"; do echo "  - $b"; done
        echo
        echo "Write the final writeup in markdown between <writeup>…</writeup> tags. Use the GHIDRA tool — do not guess."
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
