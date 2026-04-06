# AppReagent AutoResearch Program

## Objective

Maximize the corpus evaluation score (output of `./autoresearch/evaluate.sh`).

The score (0-100) measures:
- **Classification accuracy** (50%): Does the pipeline correctly label malware as relevant and benign as not_relevant?
- **Risk score calibration** (30%): Are risk scores in the expected ranges? (malware >70, benign <20, suspicious 20-60)
- **Evidence quality** (20%): Does the analysis mention the key indicators present in the code?

## Editable Assets

You may modify ONLY these files:

**Primary (no rebuild needed):**
- `prompts/triage.prompt`
- `prompts/triage_supervisor.prompt`
- `prompts/deep_analysis.prompt`
- `prompts/synthesis.prompt`

**Secondary (requires `make -j$(nproc)` after changes):**
- System prompts in `src/graph/graphs/scan_task_graph.cpp`
- Filter threshold (currently 0.9 confidence) in `scan_task_graph.cpp`

Only touch secondary assets after prompt-only experiments plateau.

## Immutable Assets — DO NOT MODIFY

- `autoresearch/evaluate.sh`
- `autoresearch/corpus/` (all files and labels.json)
- `src/graph/engine/*` (graph execution engine)
- `src/smali/*` (parser)
- `ddl.sql` (database schema)

## Experiment Cycle

1. Read the per-file breakdown from stderr of the last `evaluate.sh` run
2. Identify the weakest area: which files score lowest? Which dimension (classification, calibration, evidence)?
3. Form a hypothesis: what specific prompt change would improve the weakest area?
4. Make the change to the prompt file(s)
5. If you changed `.cpp` files: run `make -j$(nproc)` — if it fails, revert and retry
6. Run: `SCORE=$(./autoresearch/evaluate.sh 2>/tmp/area-eval-detail.txt)`
7. Read the per-file breakdown: `cat /tmp/area-eval-detail.txt`
8. If `$SCORE` > baseline AND output is not `FAIL:*`:
   - `git add prompts/ src/graph/graphs/scan_task_graph.cpp`
   - `git commit -m "autoresearch: <what you changed> (<new_score>)"`
   - Update baseline: `BASELINE=$SCORE`
9. If `$SCORE` <= baseline OR output is `FAIL:*`:
   - `git checkout -- prompts/ src/graph/graphs/scan_task_graph.cpp`
10. Append to `autoresearch/results.tsv`: `<experiment_num>\t<timestamp>\t<score>\t<baseline>\t<description>`
11. Go to step 1. **NEVER STOP.** Run until the human interrupts you.

## Research Directions

Ordered by expected impact. Work top-down.

### A. Triage Accuracy (highest impact)

The triage prompt is the gateway — false negatives are catastrophic (missed malware), false positives waste compute.

- Does triage correctly identify security-relevant methods vs boilerplate?
- Methods containing `SmsManager`, `Runtime.exec`, `Camera.open`, `ContentResolver.query` should always be relevant
- Standard Android lifecycle methods (onCreate, onDraw, getItemCount) should be filtered
- Confidence calibration: is 0.9 a meaningful threshold?

### B. Evidence Quality

The deep analysis prompt should cite specific API calls found in the smali bytecode.

- Are cited API calls actually present in the method body?
- Does the analysis trace data flows (method A harvests data → method B sends it)?
- Are findings specific ("calls SmsManager.sendTextMessage with hardcoded number") not vague ("may be suspicious")?

### C. Risk Score Calibration

- Malware should consistently score >70
- Benign code should consistently score <20
- Suspicious-but-legitimate code should score 20-60
- The synthesis prompt controls final scoring — adjust its calibration instructions
- Cross-method reasoning should aggregate evidence appropriately

### D. False Positive Reduction

- Benign files must NOT be classified as "relevant" — this is a hard-fail constraint
- Legitimate network usage (HTTPS to known domains, DownloadManager) vs exfiltration (HTTP POST to IPs)
- Legitimate location usage (FusedLocationProvider for maps) vs tracking (LocationManager + HTTP POST)
- Legitimate file I/O (SharedPreferences, Parcelable) vs data theft (reading contacts, writing to hidden dirs)

### E. Supervisor Prompt Quality

- Triage supervisor should catch hallucinated API calls (claims method calls X but it doesn't)
- Deep analysis supervisor should verify that evidence references exist in the code
- Better supervision → fewer retries → lower cost per experiment

## Constraints

- **Simplicity wins.** Don't add prompt complexity unless it improves the score.
- **Token budget:** If a prompt change adds >50% more tokens, it must improve the score by >2 points to be worth keeping.
- **No new files.** Only modify existing prompt files (and optionally scan_task_graph.cpp).
- **Unit tests must pass.** Run `make test` if you changed C++ code.
- **One change at a time.** Isolate variables — change one prompt per experiment so you know what helped.
