# bench/program.md — the coding agent's RE self-improvement loop

## Objective

Raise the score produced by `bench/eval.sh` on the RE corpus at `$AREA_BENCH_DIR`.
Higher score = the area agent answers more of the reference writeup's questions
correctly using its own tools, without handwaving.

## Editable assets

You may modify any of:

- **Prompts**: `prompts/agent_system.prompt`, plus any per-format
  `*_format_context.prompt` files. Start here — prompt changes are cheap and
  reversible.
- **Ghidra script**: `scripts/ghidra/AreaAnalyze.java`. Add new analysis modes,
  richer JSON output, address-based lookups, stack-string reconstruction,
  whatever the gap tags demand.
- **GhidraTool**: `src/features/ghidra/GhidraTool.cpp`, `include/features/ghidra/GhidraTool.h`.
  Wire new modes through. Add unit tests in `tests/features/ghidra/test_ghidra_tool.cpp`.
- **New tools**: new files under `src/features/<name>/` if a capability is
  legitimately separate from Ghidra (e.g. a shellcode pattern matcher).
  Register them in `src/features/server/AreaServer.cpp`.
- **Agent loop**: `src/infra/agent/Agent.cpp` — only if a tool-dispatch change
  is needed. Touch sparingly.

## Do NOT modify

- `bench/` itself — especially `bench/eval.sh` and `bench/judge.prompt`.
  Changing the scoring harness is cheating.
- Anything under `$AREA_BENCH_DIR` — the corpus is read-only and is not
  committed to this repo.
- `ddl.sql`, database schema, existing scan/analyze graphs unless the change
  is strictly additive.

## Experiment cycle

1. **Read the last run's gaps**:
   `cat bench/.scores/<latest>/summary.tsv` and every `*.verdict.json`.
   Look at `capability_gaps[]` across entries — the most repeated tag is the
   single biggest lever.
2. **Pick the smallest change that could plausibly close the top gap.**
   - If the gap is a missing Ghidra analysis (e.g. `disasm_at_address`), add
     a mode in `AreaAnalyze.java` + a new parse branch in `GhidraTool.cpp`.
   - If the gap is prompt-shaped ("agent didn't know to use GHIDRA"), edit
     `agent_system.prompt` or add a `pe_format_context.prompt`.
3. **Write a unit test for the new capability.** Deterministic test in
   `tests/features/ghidra/` (or similar) against a small fixture binary.
   The unit test is the contract: bench eval is just validation.
4. **Build**: `make -j$(nproc)`. If it fails, revert.
5. **Run unit tests**: `./area_tests --gtest_filter='<your new test>*'`.
   If they fail, fix before rebuilding for the bench.
6. **Rerun the bench**: `AREA_BENCH_DIR=<corpus> bench/eval.sh`.
7. **Compare scores**:
   - Higher average score AND no entry regressed by more than 5 points → keep,
     commit, update baseline.
   - Otherwise → revert (`git checkout -- <files>`) and try a different tack.
8. **Commit message template**:
   `bench: <what you changed> (<new_avg> up from <old_avg>)`
9. **Loop**. Never stop until the human interrupts you.

## Principles

- **Deterministic tools over LLM guessing.** Every time you're tempted to make
  the prompt smarter, ask instead: could a tool return the answer directly?
  A new Ghidra script mode that emits `{"function_at": 0x1000D02E, "name": "DllMain"}`
  is more valuable than a prompt that tries to make the agent guess from bytes.
- **Unit tests before bench iterations.** Bench runs are minutes-long; unit
  tests are seconds. Prove the capability deterministically, then measure.
- **Small steps, isolated variables.** One change per experiment, one commit
  per improvement. If two ideas overlap, do them in sequence.
- **Agent output is markdown between `<writeup>...</writeup>` tags.** If the
  agent is stuffing GHIDRA raw output into the writeup verbatim, the prompt
  needs to steer it toward interpretation instead of dumping.
- **No cheating.** Do not read the reference PDFs, do not modify
  `bench/.scores/`, do not infer gold values from judge output (the judge
  prompt forbids leaking them but double-check). If an entry in summary.tsv
  ever goes from ERROR to 100 in one step, you did something wrong.

## Gap tags to watch for

These are the most likely tags on a cold start and the roughly-correct fix for each:

| Tag                             | Likely fix                                         |
|---------------------------------|----------------------------------------------------|
| `pe_headers`                    | Ghidra overview already does this — check agent    |
|                                 | prompt / output routing, not tool                  |
| `disasm_at_address`             | New Ghidra mode: `function_at <hex>` → decompile   |
| `stack_string_reconstruction`   | New Ghidra mode: scan for `mov [ebp+N], imm8`      |
|                                 | runs, assemble, report per function                |
| `xor_decode`                    | New tool: `DECODE: xor <hex_blob> <key>` or        |
|                                 | Ghidra script pass that recognizes XOR loops       |
| `xref_traversal`                | Ghidra xrefs already works — prompt tuning         |
| `function_classification`       | Prompt improvement — tell agent to cite evidence   |
|                                 | from decompiled body, not guess                    |
| `shellcode_recognition`         | New tool: shellcode prologue fingerprint matcher   |
| `multi_binary_analysis`         | Agent loop — encourage per-binary then correlate   |
| `packer_detection`              | Ghidra metadata has compiler; add packer heuristic |
