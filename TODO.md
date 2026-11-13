# TODO

- [ ] DVLA agent miss: find what condition makes DVLA leak (lab docs + `[tool]` log on :8200), then decide if a general, not target-tuned, agent check is possible (PIT-T-53 / PIT-T-70)
- [ ] Empty replies in latentinjection: log prompt length and the raw model response in bank-bot to find the cause
- [ ] Endpoint shapes: session bootstrap, cookie session + CSRF, WebSocket (add a mock endpoint for each)
- [ ] Report per-check leak-rate bounds next to the pooled one
- [ ] Optional LLM judge for the `refused` bucket, using the customer's own LLM endpoint
- [ ] Evidence handling for SaaS: redact replies, delete raw garak reports after re-judge, request audit log
- [ ] Validate on a third-party chatbot that allows testing
- [x] connector.py (http-json, SSE), garak through the function generator
- [x] HAR import + connection test (CLI and UI)
- [x] Verdict tiers confirmed / likely / suspected / refused, `--rejudge`
- [x] Web UI runs ai-scan.py (new target from HAR or saved target, job log, Stop)
- [x] Leak-rate 95% bound, UI repeats default 20
- [x] Remove probes_ext.py, garak-data/, overlapping scan.py probes
- [x] Move DVLA wrapper into labs/
