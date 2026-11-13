# TODO

- [ ] DVLA agent miss: garak `agent_breaker.AgentBreaker` is wired to our `.env` gateway (commit 1c3093f, wiring checked, not yet run on a target). User runs it from the UI on `dvla-target.json`. Pass = `GetUserTransactions` called with a non-'1' id in the :8200 `[tool]` log. Old logs: 96/96 calls used '1'
- [ ] Empty replies in latentinjection: log prompt length and the raw model response in bank-bot to find the cause
- [ ] Endpoint shapes: session bootstrap, cookie session + CSRF, WebSocket (add a mock endpoint for each)
- [ ] Optional LLM judge for the `refused` bucket, using the customer's own LLM endpoint
- [ ] Evidence handling for SaaS: redact replies, delete raw garak reports after re-judge, request audit log
- [ ] Validate on a third-party chatbot that allows testing
- [x] connector.py (http-json, SSE), garak through the function generator
- [x] HAR import + connection test (CLI and UI)
- [x] Verdict tiers confirmed / likely / suspected / refused, `--rejudge`
- [x] Web UI runs ai-scan.py (new target from HAR or saved target, job log, Stop)
- [x] Leak-rate 95% bound, UI repeats default 20
- [x] Per-check 95% range next to the pooled one (CLI column, UI column, `summary[].rate_low_95/high_95`)
- [x] Remove probes_ext.py, garak-data/, overlapping scan.py probes
- [x] Move DVLA wrapper into labs/
