#!/usr/bin/env python3
"""connector: one send(prompt) -> reply text for every endpoint shape the scanner supports.

Our checks and garak (through its "function" generator) both call send(), so a new
endpoint shape is added here once and every check gets it.
Shapes now: "http-json" (one JSON reply) and "sse" (text/event-stream, reply joined from events).
Target config keys: base_url, chat_body (with {{prompt}}), reply_path, transport.
For sse, reply_path is the path inside each event's JSON, e.g. "delta".

config_from_har() builds that config from a browser HAR export, keeping structure only:
no token, cookie, password or reply text is copied into the config.
"""
import json, os, sys, time, urllib.error, urllib.request
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scan  # _fill, _dig, .env loader

def _open(url, body, headers, timeout=180):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", **headers})
    # back off on 429 so a rate-limited target is not counted as "no reply"
    for wait in (2, 5, 15, None):
        try:
            return urllib.request.urlopen(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            if e.code != 429 or wait is None:
                raise
            time.sleep(int(e.headers.get("Retry-After") or wait))

def post(url, body, headers):
    with _open(url, body, headers) as r:
        return json.load(r)

def read_sse(lines, path):
    out = []
    for raw in lines:
        line = (raw.decode(errors="replace") if isinstance(raw, bytes) else raw).strip()
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            break
        try:
            event = json.loads(data)
        except ValueError:
            out.append(data)  # plain-text event
            continue
        try:
            out.append(str(scan._dig(event, path) or ""))
        except (KeyError, IndexError, TypeError):
            pass  # meta event without the text field (start, usage, ...)
    return "".join(out)

def send(cfg, path, prompt, headers):
    body = scan._fill(cfg.get("chat_body", {"message": "{{prompt}}"}), prompt, "")
    url, rp = cfg["base_url"] + path, cfg.get("reply_path", "reply")
    if cfg.get("transport", "http-json") == "sse":
        with _open(url, body, {"Accept": "text/event-stream", **headers}) as r:
            return read_sse(r, rp)
    with _open(url, body, headers) as r:
        return str(scan._dig(json.load(r), rp) or "")

def detect_reply_path(cfg, path, prompt, headers):
    # used when the HAR held no response body (some browsers drop streamed bodies)
    body = scan._fill(cfg.get("chat_body", {"message": "{{prompt}}"}), prompt, "")
    with _open(cfg["base_url"] + path, body, headers) as r:
        text = r.read().decode(errors="replace")
    return pick_reply_path(_events(text) if cfg.get("transport") == "sse" else [_json(text)])

def garak_send(prompt, **_):
    # runs inside garak's process; the target (with its token) arrives by env var, never on disk
    t = json.loads(os.environ["AI_SCAN_TARGET"])
    try:
        return [send(t["cfg"], t["path"], prompt, t["headers"])]
    except Exception as e:
        print(f"connector: {e}", file=sys.stderr)
        return [None]

# ---- HAR import -------------------------------------------------------------

def _leaves(obj, path=()):
    # every string value in a JSON tree with its path, e.g. (("messages", 0, "content"), "hi")
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _leaves(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _leaves(v, path + (i,))
    elif isinstance(obj, str):
        yield path, obj

def _set(obj, path, value):
    for k in path[:-1]:
        obj = obj[k]
    obj[path[-1]] = value

def _dotted(path):
    return ".".join(str(p) for p in path)

def _json(text):
    try:
        return json.loads(text or "")
    except ValueError:
        return None

def _events(text):
    return [e for e in (_json(l[5:].strip()) for l in (text or "").splitlines() if l.startswith("data:"))
            if isinstance(e, (dict, list))]

def pick_reply_path(samples):
    # the reply text is the string field that is longest in total across the samples
    total = Counter()
    for s in samples:
        for p, v in _leaves(s):
            total[p] += len(v)
    return _dotted(total.most_common(1)[0][0]) if total else None

def config_from_har(har):
    if not har["log"]["entries"]:
        raise ValueError("this HAR has no requests. Open DevTools > Network before you log in and chat, "
                         "set the filter to All, and keep the record button on")
    posts = [e for e in har["log"]["entries"] if e["request"]["method"] == "POST"]
    req_json = lambda e: _json((e["request"].get("postData") or {}).get("text"))
    resp_text = lambda e: e["response"].get("content", {}).get("text") or ""
    path_of = lambda e: urlparse(e["request"]["url"]).path

    # login = the POST that sends a password-like field; works on sanitized HARs, which drop auth headers
    login = next((e for e in posts if isinstance(req_json(e), dict)
                  and any("pass" in str(k).lower() for k in req_json(e))), None)
    chats = [e for e in posts if e is not login and isinstance(req_json(e), (dict, list))]
    if not chats:
        raise ValueError("no JSON POST besides login found; is the chat in this HAR?")
    # the chat endpoint is the POST the page called most often
    top = Counter(path_of(e) for e in chats).most_common(1)[0][0]
    calls = [e for e in chats if path_of(e) == top]

    # the prompt field = the string that changes between calls, else the longest one
    bodies = [req_json(e) for e in calls]
    leaves = dict(_leaves(bodies[-1]))
    changing = [p for p in leaves if len({dict(_leaves(b)).get(p) for b in bodies}) > 1]
    prompt_path = max(changing or leaves, key=lambda p: len(leaves[p]))
    template = json.loads(json.dumps(bodies[-1]))
    _set(template, prompt_path, "{{prompt}}")

    mime = calls[-1]["response"].get("content", {}).get("mimeType", "")
    sse = "event-stream" in mime
    samples = [ev for e in calls for ev in _events(resp_text(e))] if sse else \
              [j for j in (_json(resp_text(e)) for e in calls) if j is not None]
    u = urlparse(calls[-1]["request"]["url"])
    cfg = {"_about": f"built from HAR: POST {top} ({'sse' if sse else 'http-json'})",
           "base_url": f"{u.scheme}://{u.netloc}", "transport": "sse" if sse else "http-json",
           "chat_body": template, "reply_path": pick_reply_path(samples),  # None = detect on first live reply
           "chat_paths": {"default": top}}

    if login:
        token = next((p for p, _ in _leaves(_json(resp_text(login)) or {}) if "token" in str(p[-1]).lower()), None)
        user = next((v for k, v in req_json(login).items() if "user" in k.lower() or "email" in k.lower()), "")
        cfg.update({"login_path": path_of(login), "token_path": _dotted(token) if token else "token",
                    "tester": {"username": user, "password": "{{env:AI_SCAN_PASSWORD}}"}})
    else:
        # ponytail: cookie sessions are not handled yet; only a bearer token supplied at scan time
        cfg["auth_header"] = "Bearer {{env:AI_SCAN_TOKEN}}"
    return cfg

def _selftest():
    lines = [b"event: start", b'data: {"type":"meta"}', b'data: {"delta":"Hel"}', b"", b'data: {"delta":"lo"}',
             b"data: [DONE]", b'data: {"delta":"x"}']
    assert read_sse(lines, "delta") == "Hello"
    assert read_sse(["data: plain"], "delta") == "plain"
    assert pick_reply_path([{"id": "abc", "reply": "a long answer"}]) == "reply"
    sse_text = 'data: {"id":"1","delta":"Your order"}\n\ndata: {"id":"1","delta":" is shipped"}\n\ndata: [DONE]\n'
    entry = lambda url, body, text, mime: {"request": {"method": "POST", "url": url, "headers": [],
                                           "postData": {"text": json.dumps(body)}},
                                           "response": {"content": {"text": text, "mimeType": mime}}}
    har = {"log": {"entries": [
        entry("http://h:1/login", {"username": "alice", "password": "pw"}, '{"token":"t0k"}', "application/json"),
        entry("http://h:1/api/stream", {"session": "s1", "message": "hi"}, sse_text, "text/event-stream"),
        entry("http://h:1/api/stream", {"session": "s1", "message": "where is my order"}, sse_text, "text/event-stream"),
    ]}}
    cfg = config_from_har(har)
    assert cfg["transport"] == "sse" and cfg["chat_paths"] == {"default": "/api/stream"}, cfg
    assert cfg["chat_body"] == {"session": "s1", "message": "{{prompt}}"} and cfg["reply_path"] == "delta", cfg
    assert cfg["login_path"] == "/login" and cfg["token_path"] == "token" and cfg["tester"]["username"] == "alice"
    assert "pw" not in json.dumps(cfg) and "t0k" not in json.dumps(cfg)  # no secret copied
    print("selftest ok")

if __name__ == "__main__":
    _selftest()
