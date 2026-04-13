#!/usr/bin/env python3
"""
bench/judge.py — grade an area agent's RE writeup against a reference PDF.

Usage: judge.py <reference.pdf> <agent_output.txt> [config.json]

Loads the reference PDF (pypdf text extraction, cached in a private venv),
reads the agent output, and asks an LLM judge to grade the agent against
the reference. Config.json supplies the LLM endpoint and API key (same
format area itself uses). Prints a JSON verdict to stdout:

    {
        "score": <int 0..100>,
        "per_question": [
            {"id": <n>, "question": <str>, "verdict": "correct|partial|missing|wrong", "reason": <str>}
        ],
        "capability_gaps": [<short tag>, ...],
        "notes": <str>
    }

Nothing from the reference PDF is written back to the repo — only
question IDs and verdict tags (no gold values) leak into the summary.
"""

import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.error

# --- Args -------------------------------------------------------------------

if len(sys.argv) < 3:
    print(json.dumps({"error": "usage: judge.py <ref.pdf> <agent.txt> [config.json]"}))
    sys.exit(2)

ref_pdf = sys.argv[1]
agent_out = sys.argv[2]
config_path = sys.argv[3] if len(sys.argv) > 3 else "/opt/area/config.json"

if not os.path.isfile(ref_pdf):
    print(json.dumps({"error": f"reference pdf not found: {ref_pdf}"}))
    sys.exit(2)
if not os.path.isfile(agent_out):
    print(json.dumps({"error": f"agent output not found: {agent_out}"}))
    sys.exit(2)

# --- PDF text extraction ----------------------------------------------------

VENV = os.environ.get("BENCH_VENV", "/tmp/pdfenv")
if not os.path.isfile(f"{VENV}/bin/python"):
    subprocess.run(["python3", "-m", "venv", VENV], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([f"{VENV}/bin/pip", "install", "-q", "pypdf"], check=True)

pdf_text = subprocess.run(
    [f"{VENV}/bin/python", "-c",
     "import sys, pypdf\n"
     "r = pypdf.PdfReader(sys.argv[1])\n"
     "print('\\n'.join((p.extract_text() or '') for p in r.pages))\n",
     ref_pdf],
    capture_output=True, text=True, check=True,
).stdout

agent_text = open(agent_out, encoding="utf-8", errors="replace").read()

# --- Load config for LLM endpoint -------------------------------------------

def strip_comments(s: str) -> str:
    # Drop // line comments and /* block */ comments before json.loads.
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
    s = re.sub(r"(?m)^[^\"\n]*?(//[^\n]*)", lambda m: m.group(0).replace(m.group(1), ""), s)
    return s

cfg = json.loads(strip_comments(open(config_path).read()))
endpoints = cfg.get("ai_endpoints", [])
# Prefer tier 2, then tier 1, then tier 0
endpoints.sort(key=lambda e: -int(e.get("tier", 0)))
if not endpoints:
    print(json.dumps({"error": "no ai_endpoints in config"}))
    sys.exit(2)
ep = endpoints[0]

url = ep.get("url", "").rstrip("/")
if "/v1" not in url:
    url += "/v1/chat/completions"
elif not url.endswith("/chat/completions"):
    url += "/chat/completions"

model = ep.get("model") or "auto"
api_key = ep.get("api_key", "")

# --- Rubric -----------------------------------------------------------------

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT, "bench/judge.prompt"), encoding="utf-8") as f:
    rubric = f.read()

# Truncate to fit — large PDFs are noisy, later pages are usually screenshots.
MAX_REF = 40000
MAX_AGENT = 40000
if len(pdf_text) > MAX_REF:
    pdf_text = pdf_text[:MAX_REF] + "\n[... reference truncated ...]"
if len(agent_text) > MAX_AGENT:
    agent_text = agent_text[:MAX_AGENT] + "\n[... agent output truncated ...]"

user_msg = (
    f"{rubric}\n\n"
    f"<reference_writeup>\n{pdf_text}\n</reference_writeup>\n\n"
    f"<agent_writeup>\n{agent_text}\n</agent_writeup>\n"
)

# --- Call LLM ---------------------------------------------------------------

payload = {
    "model": model,
    "messages": [
        {"role": "system", "content": "You are a strict RE-writeup grader. Respond ONLY with a single JSON object. No prose outside the object."},
        {"role": "user", "content": user_msg},
    ],
    "temperature": 0,
    "max_tokens": 16000,
}

# Allow overriding the judge model via env. Default to a known-fast,
# non-reasoning model — reasoning models burn the max_tokens budget on
# internal thinking and return empty content.
JUDGE_MODEL_OVERRIDE = os.environ.get("BENCH_JUDGE_MODEL", "openai/gpt-oss-120b")

def call_llm(ep_url: str, ep_model: str, ep_key: str) -> dict:
    req_url = ep_url.rstrip("/")
    if "/v1" not in req_url:
        req_url += "/v1/chat/completions"
    elif not req_url.endswith("/chat/completions"):
        req_url += "/chat/completions"
    p = dict(payload)
    p["model"] = JUDGE_MODEL_OVERRIDE or ep_model or "auto"
    req = urllib.request.Request(
        req_url,
        data=json.dumps(p).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {ep_key}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=600) as resp:
        return json.loads(resp.read().decode("utf-8"))

# Try the chosen endpoint, then every other endpoint in priority order,
# retrying each once after a short backoff on 5xx / timeout.
body = None
last_err = None
tried = []
for candidate in endpoints:
    c_url = candidate.get("url", "")
    c_model = candidate.get("model") or "auto"
    c_key = candidate.get("api_key", "")
    for attempt in range(2):
        try:
            body = call_llm(c_url, c_model, c_key)
            break
        except urllib.error.HTTPError as e:
            last_err = f"http {e.code} from {candidate.get('id','?')}"
            if e.code < 500:
                break  # client error, different endpoint won't help
        except Exception as e:
            last_err = f"{type(e).__name__} from {candidate.get('id','?')}: {e}"
        if attempt == 0:
            import time; time.sleep(3)
    if body is not None:
        break
    tried.append(candidate.get("id", "?"))

if body is None:
    print(json.dumps({"error": f"judge failed across {len(tried)} endpoint(s): {last_err}", "tried": tried}))
    sys.exit(1)

try:
    msg = body["choices"][0]["message"]
    content = msg.get("content") or msg.get("reasoning") or ""
    if not content:
        print(json.dumps({"error": "judge response had neither content nor reasoning", "raw": str(body)[:500]}))
        sys.exit(1)
except (KeyError, IndexError):
    print(json.dumps({"error": "judge response missing choices", "raw": str(body)[:500]}))
    sys.exit(1)

# The model sometimes wraps JSON in markdown fences. Strip them.
m = re.search(r"\{.*\}", content, flags=re.S)
if not m:
    print(json.dumps({"error": "judge did not return JSON", "raw": content[:500]}))
    sys.exit(1)

try:
    verdict = json.loads(m.group(0))
except json.JSONDecodeError as e:
    print(json.dumps({"error": f"judge JSON parse: {e}", "raw": content[:500]}))
    sys.exit(1)

# Normalize shape so callers can rely on it.
verdict.setdefault("score", 0)
verdict.setdefault("per_question", [])
verdict.setdefault("capability_gaps", [])
verdict.setdefault("notes", "")

print(json.dumps(verdict, indent=2))
