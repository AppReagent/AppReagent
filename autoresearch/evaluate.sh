#!/bin/bash
# AutoResearch Evaluation Script
# Scans all corpus files, compares results against labels.json ground truth.
# Outputs: numeric score (0-100) to stdout, per-file breakdown to stderr.
# On hard failure: outputs "FAIL:<reason>" to stdout instead.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_DIR"

CORPUS_DIR="$SCRIPT_DIR/corpus"
LABELS="$CORPUS_DIR/labels.json"
AREA="./area"

if [[ ! -x "$AREA" ]]; then
    echo "FAIL:no_binary"
    exit 0
fi

if [[ ! -f "$LABELS" ]]; then
    echo "FAIL:no_labels"
    exit 0
fi

RUN_ID="eval-$(date +%s)-$$"
OUTPUT="scan-outputs/${RUN_ID}.jsonl"

echo "Scanning corpus (run $RUN_ID)..." >&2
if ! "$AREA" scan "$CORPUS_DIR" --run-id "$RUN_ID" 2>/dev/null; then
    # Scan may return 1 on errors but still produce partial results — continue
    echo "  (scan returned non-zero, scoring partial results)" >&2
fi

if [[ ! -f "$OUTPUT" ]]; then
    echo "FAIL:no_output"
    exit 0
fi

python3 - "$LABELS" "$OUTPUT" <<'PYEOF'
import json, sys, os

labels_path = sys.argv[1]
output_path = sys.argv[2]

with open(labels_path) as f:
    labels = json.load(f)

# Parse JSONL output — extract file_result entries
results = {}
with open(output_path) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            if entry.get("type") == "file_result":
                fp = entry.get("file_path", "")
                for label_key in labels:
                    if fp.endswith(label_key) or fp.endswith(os.path.basename(label_key)):
                        # Prefer longer (more specific) match
                        if label_key not in results or len(fp) > len(results[label_key].get("file_path", "")):
                            results[label_key] = entry
        except json.JSONDecodeError:
            continue

total_class = 0.0
total_calib = 0.0
total_evidence = 0.0
n_files = len(labels)
hard_fail = False
hard_fail_files = []

for label_key, label in sorted(labels.items()):
    expected_class = label["expected_class"]
    result = results.get(label_key)

    if not result:
        print(f"  {label_key}: MISSING", file=sys.stderr)
        continue

    actual_risk = result.get("risk", "unknown")
    actual_score = result.get("risk_score", 0)
    risk_profile = result.get("risk_profile", {})

    # "skipped" means triage filtered everything => not_relevant
    actual_class = actual_risk if actual_risk != "skipped" else "not_relevant"

    # --- Classification (50%) ---
    cls = 0.0
    if actual_class == expected_class:
        cls = 1.0
    elif expected_class == "relevant" and actual_class == "partially_relevant":
        cls = 0.5
    elif expected_class == "partially_relevant" and actual_class in ("relevant", "not_relevant"):
        cls = 0.25

    if expected_class == "not_relevant" and actual_class == "relevant":
        hard_fail = True
        hard_fail_files.append(label_key)

    total_class += cls

    # --- Risk calibration (30%) ---
    cal = 0.0
    min_rs = label.get("min_risk_score")
    max_rs = label.get("max_risk_score")
    in_range = True
    if min_rs is not None and actual_score < min_rs:
        in_range = False
    if max_rs is not None and actual_score > max_rs:
        in_range = False

    if in_range:
        cal = 1.0
    else:
        # Partial credit within 15 points of range
        gap = 0
        if min_rs is not None and actual_score < min_rs:
            gap = min_rs - actual_score
        if max_rs is not None and actual_score > max_rs:
            gap = actual_score - max_rs
        if gap <= 15:
            cal = 0.5

    total_calib += cal

    # --- Evidence quality (20%) ---
    must_mention = label.get("must_mention", [])
    must_not_mention = label.get("must_not_mention", [])
    ev = 0.0

    # Build searchable text from risk_profile
    text_parts = []
    if isinstance(risk_profile, dict):
        for k in ("answer", "evidence_summary", "recommendation"):
            text_parts.append(str(risk_profile.get(k, "")))
        for rm in risk_profile.get("relevant_methods", []):
            if isinstance(rm, dict):
                text_parts.append(str(rm.get("finding", "")))
    elif isinstance(risk_profile, str):
        text_parts.append(risk_profile)
    search_text = " ".join(text_parts).lower()

    if must_mention or must_not_mention:
        mention_score = 1.0
        if must_mention:
            hits = sum(1 for kw in must_mention if kw.lower() in search_text)
            mention_score = hits / len(must_mention)

        not_mention_score = 1.0
        if must_not_mention:
            violations = sum(1 for kw in must_not_mention if kw.lower() in search_text)
            not_mention_score = 1.0 - (violations / len(must_not_mention))

        parts = []
        if must_mention:
            parts.append(mention_score)
        if must_not_mention:
            parts.append(not_mention_score)
        ev = sum(parts) / len(parts) if parts else 1.0
    else:
        ev = 1.0  # No criteria = full marks

    total_evidence += ev

    tag = "OK" if cls == 1.0 and cal == 1.0 and ev >= 0.75 else "WEAK"
    if cls == 0 or (expected_class == "not_relevant" and actual_class == "relevant"):
        tag = "FAIL"
    print(f"  {label_key}: {actual_class}(exp={expected_class}) "
          f"score={actual_score} cls={cls:.1f} cal={cal:.1f} ev={ev:.2f} [{tag}]",
          file=sys.stderr)

class_pct = (total_class / n_files) * 50
calib_pct = (total_calib / n_files) * 30
evidence_pct = (total_evidence / n_files) * 20
final = int(round(class_pct + calib_pct + evidence_pct))

print(file=sys.stderr)
print(f"  Classification: {class_pct:.1f}/50 ({total_class:.1f}/{n_files})", file=sys.stderr)
print(f"  Calibration:    {calib_pct:.1f}/30 ({total_calib:.1f}/{n_files})", file=sys.stderr)
print(f"  Evidence:       {evidence_pct:.1f}/20 ({total_evidence:.1f}/{n_files})", file=sys.stderr)
print(f"  TOTAL:          {final}/100", file=sys.stderr)

if hard_fail:
    print(f"FAIL:false_positive ({', '.join(hard_fail_files)})")
else:
    print(final)
PYEOF
