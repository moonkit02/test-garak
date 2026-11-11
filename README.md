# ai-scan — LLM red-team scanner (PoC)

Prompt-injection / jailbreak / data-leak testing of an LLM endpoint. Exploratory
"scanner #9" alongside the company's existing 8 DevSecOps scanners. Structurally
it behaves like DAST, but the target is a **model endpoint** instead of a web app.

Maps to the **OWASP Top 10 for LLM Applications (2025)**: LLM01 prompt injection,
LLM02 sensitive-info disclosure, jailbreak.

## Files

| File | What it is |
|---|---|
| `scan.py` | **Dynamic** scan. `probe -> generate -> detector -> report`. Hits an OpenAI-compatible `/v1` endpoint (a live model). Writes `scan-results.json`. |
| `static-scan.py` | **Static** scan. Lints prompt text (no endpoint needed) for baked-in secrets and weak guardrails. Scans `targets.json` prompts + any files passed as args. Writes `static-scan-results.json`. |
| `targets.json` | The **targets under test**: deliberately weak system prompts (bank support, HR/PII, DevOps creds, legal). Each has a canary `secret` + `marker` = the ground truth (must never leak). Add more by appending entries. |
| `connectors.json` | **Remote targets**: generic HTTP connectors (request template + response path) to reach any custom model API. The shipped example hits local Ollama via the generic path. |
| `server.py` | Local web UI (dark/OLED, JetBrains Mono), two tabs: **Dynamic** (model + target dropdowns, live probing, saves `scan-results.json`) and **Static** (paste a prompt or lint all targets, saves `static-scan-results.json`). Reuses `scan.py` and `static-scan.py`. |
| `scan-results.json` | Last scan output (generated). |
| `knowledge/artifacts.md` | Log of published claude.ai artifacts (field guide, attack playbook) with URLs, for future reference. |

Intended real engine is **Garak (NVIDIA)** — this hand-rolled `scan.py` is a
throwaway stand-in (see "status" below). The 6 probes/detectors here are keyword-based;
Garak's 100+ probes and ML detectors are the upgrade path.

## Run

Needs an Ollama server on `:11434` with a model pulled.

```bash
# dynamic scan (live model): python3.12 scan.py [target-id] [model] -> scan-results.json
python3.12 scan.py hr-assistant qwen2.5:0.5b

# static scan (no endpoint): lint prompts -> static-scan-results.json
python3.12 static-scan.py                 # scans targets.json prompts
python3.12 static-scan.py path/to/prompt.txt   # plus any prompt files

# web UI -> http://localhost:8099  (pick Model + Target from the dropdowns)
python3.12 server.py
```

- `ENDPOINT` + default `MODEL` are at the top of `scan.py`; targets live in `targets.json`.
- The **Model** dropdown lists whatever the running Ollama server has (`GET /api/tags`).
  Add a model so the server can see it (the GUI Ollama and the CLI use *separate* stores):
  `curl -X POST http://localhost:11434/api/pull -d '{"name":"qwen2.5:0.5b"}'`
- The UI reads models, targets, and endpoint live, so there is one source of truth.

### Testing a remote model (in-house or cloud)

You only need black-box access: an endpoint, auth, and how to shape a request/response.

**Quickest (UI):** in the Dynamic tab, pick **"+ Custom remote endpoint"** in the Model
dropdown and type Base URL + API key + Model id. These are sent to the local server for the
scan only and never written to disk. Good for a one-off OpenAI-compatible endpoint.

**Reusable (file):** add an entry to `connectors.json`, then pick it under "HTTP connectors"
in the Model dropdown. Use this for a saved connector or a non-OpenAI request shape.

```json
{
  "id": "acme-internal",
  "name": "Acme internal assistant",
  "type": "http",
  "endpoint": "https://ai.internal.acme.com/assistant",
  "method": "POST",
  "headers": { "Authorization": "Bearer <token>", "Content-Type": "application/json" },
  "body": { "question": "{{prompt}}", "system": "{{system}}" },
  "response_path": "data.answer"
}
```

`{{prompt}}` and `{{system}}` are substituted per probe; `response_path` is a dotted path
to the answer text (a numeric segment indexes a list, e.g. `choices.0.message.content`).
OpenAI-compatible endpoints (most cloud + vLLM/Ollama/TGI in-house) work with the
local path already; the HTTP connector is the universal fallback for custom APIs.
Only test endpoints you are authorized to.

**Secrets via `.env` (do not hardcode keys).** Connectors reference secrets as
`{{env:NAME}}`, resolved at call time from `.env` (git-ignored) or the shell environment.
Set one up:

```bash
cp .env.example .env     # then edit .env with your values
```

`.env` is in `.gitignore`, so keys never get committed. It is still a local plaintext file;
for production use a real secret manager or shell env vars instead.

**AWS Bedrock:** two ready-to-fill connectors ship in `connectors.json` (`bedrock-converse`
for Claude/Nova, `bedrock-openai` for the OpenAI-compatible path). They read
`BEDROCK_REGION`, `BEDROCK_MODEL_ID`, `BEDROCK_API_KEY` from `.env`. Use a **Bedrock bearer
API key** (`Authorization: Bearer`), not a classic AWS access-key + secret: the scanner does
not sign SigV4. For the access-key case, put a LiteLLM or Bedrock Access Gateway proxy in
front, or add a boto3 connector type.

## Status (2026-10-30)

- **Pipeline proven end-to-end.** Against `smollm:135m` the scanner caught 3/6 real
  vulns (secret leak via DAN roleplay + obfuscation, harmful-content compliance),
  matching ground truth.
- The `smollm:135m` result is a *plumbing* proof, not a quality benchmark — a 135M
  model leaks because it can't follow instructions.

## Known infra limits on the current machine (verified)

- **Disk:** only ~3.3 GB free; Garak hard-deps `torch` + transformers/datasets ≈ 3-4 GB,
  so Garak is **not installed here** — would fill the disk.
- **RAM:** 8 GB, ~30% free, swapping hard — 54 s for 20 tokens on a 91 MB model.
  No capable (1B+) target runs usefully here.
- **Two Ollama stores:** running server is **0.3.13** (has only `smollm:135m`);
  the 0.34.0 CLI uses a separate store. `/v1` 404s seen earlier were model-not-found,
  not a bad path.

## Next steps

1. Containerize (Garak + bundled Ollama target), like the DAST/ZAP setup, to run on a proper box.
2. Swap the toy probes for real **Garak**, or point at a hosted endpoint you own (skips the local-RAM wall; only test endpoints you are authorized to).
3. Expand scope beyond LLM01/LLM02 (agent/tool abuse, RAG indirect injection, multimodal).
