#!/usr/bin/env python3
"""Local web UI for the LLM red-team scanner. Reuses scan.py (probes/detectors/generator).
Runs one probe per request so the page shows live progress (this box is slow).
ponytail: stdlib http.server, no framework. Page served inline below.
Design: ui-ux-pro-max "Dark Mode (OLED)" — slate/midnight, run-green accent,
JetBrains Mono + IBM Plex Sans, SVG icons, visible focus, reduced-motion.
"""
import json, time, urllib.request, importlib.util
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import scan  # reuse PROBES, generate(), detectors

# static-scan.py has a hyphen (run directly, not importable by name), so load it by path
_spec = importlib.util.spec_from_file_location("staticscan", Path(__file__).with_name("static-scan.py"))
staticscan = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(staticscan)

PORT = 8099

def ollama_models():
    """Live list of models the running server has; default first. Falls back to default."""
    try:
        tags = scan.ENDPOINT.split("/v1/")[0] + "/api/tags"
        with urllib.request.urlopen(tags, timeout=5) as r:
            names = [m["name"] for m in json.load(r).get("models", [])]
    except Exception:
        names = []
    return [scan.MODEL] + [n for n in names if n != scan.MODEL]

PAGE = """<!doctype html><html lang=en><head><meta charset=utf-8>
<title>AI Model Scanner</title><meta name=viewport content="width=device-width,initial-scale=1">
<link rel=preconnect href=https://fonts.googleapis.com><link rel=preconnect href=https://fonts.gstatic.com crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel=stylesheet>
<style>
 :root{
  --bg:#0F172A; --card:#1B2336; --muted:#272F42; --border:#2b3650; --border-hi:#3a4766;
  --fg:#F8FAFC; --fg-muted:#94A3B8; --accent:#22C55E; --accent-dim:#16351f;
  --fail:#EF4444; --fail-dim:#3a1d22; --warn:#FBBF24; --warn-dim:#3a2f17;
  --mono:'JetBrains Mono',ui-monospace,monospace; --sans:'IBM Plex Sans',system-ui,sans-serif;
 }
 *{box-sizing:border-box} html{-webkit-text-size-adjust:100%}
 body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 var(--sans);
  background-image:radial-gradient(900px 500px at 80% -10%,#15213f 0,transparent 60%);min-height:100vh}
 .wrap{max-width:920px;margin:0 auto;padding:40px 20px 80px}
 /* header */
 header{display:flex;align-items:center;gap:14px;margin-bottom:6px}
 .logo{width:40px;height:40px;border-radius:10px;display:grid;place-items:center;
  background:linear-gradient(145deg,#1f6f3e,#22C55E);box-shadow:0 0 22px #22c55e33}
 .logo svg{width:22px;height:22px;color:#06130a}
 h1{font-size:1.35rem;font-weight:600;margin:0;letter-spacing:-.01em}
 h1 span{color:var(--fg-muted);font-weight:400}
 .sub{color:var(--fg-muted);font-size:.82rem;margin:2px 0 26px;letter-spacing:.02em}
 .sub code{font-family:var(--mono);color:#93c5fd}
 /* panel */
 .panel{background:linear-gradient(180deg,#1d2740,#1a2235);border:1px solid var(--border);
  border-radius:14px;padding:20px;display:flex;flex-wrap:wrap;gap:16px;align-items:center;justify-content:space-between;
  box-shadow:0 1px 0 #ffffff08 inset,0 10px 30px #00000040}
 .chips{display:flex;flex-wrap:wrap;gap:8px}
 .chip{font-family:var(--mono);font-size:.72rem;color:var(--fg-muted);background:var(--muted);
  border:1px solid var(--border);border-radius:999px;padding:6px 11px;max-width:360px;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
 .chip b{color:var(--fg);font-weight:600}
 .btn{font:600 .95rem var(--sans);color:#06130a;background:var(--accent);border:0;border-radius:10px;
  padding:12px 20px;display:inline-flex;align-items:center;gap:9px;cursor:pointer;min-height:44px;
  transition:transform .15s ease,box-shadow .15s ease,background .15s ease;box-shadow:0 0 0 #22c55e00}
 .btn:hover:not(:disabled){transform:translateY(-1px);box-shadow:0 6px 20px #22c55e40}
 .btn:active:not(:disabled){transform:translateY(0)}
 .btn:disabled{opacity:.55;cursor:wait}
 .btn svg{width:16px;height:16px}
 .btn .spin{width:15px;height:15px;border:2px solid #06130a55;border-top-color:#06130a;border-radius:50%;animation:sp .7s linear infinite}
 @keyframes sp{to{transform:rotate(360deg)}}
 .controls{display:flex;gap:14px;align-items:flex-end;flex-wrap:wrap}
 .sel{display:flex;flex-direction:column;gap:6px;font:600 .66rem var(--sans);text-transform:uppercase;letter-spacing:.1em;color:var(--fg-muted)}
 .sel select{font:500 .85rem var(--mono);color:var(--fg);background:var(--muted);border:1px solid var(--border);
  border-radius:10px;padding:10px 34px 10px 12px;min-height:44px;cursor:pointer;appearance:none;
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2394A3B8' stroke-width='2'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
  background-repeat:no-repeat;background-position:right 12px center}
 .sel select:hover{border-color:var(--border-hi)}
 /* tabs */
 .tabs{display:flex;gap:8px;margin:0 0 22px}
 .tab{font:600 .82rem var(--sans);color:var(--fg-muted);background:transparent;border:1px solid var(--border);
  border-radius:999px;padding:9px 18px;cursor:pointer;min-height:42px;display:inline-flex;align-items:center;gap:8px;
  transition:background .15s,color .15s,border-color .15s}
 .tab:hover{border-color:var(--border-hi)}
 .tab.on{color:#06130a;background:var(--accent);border-color:var(--accent)}
 .ta{width:100%;min-height:120px;background:#0e1626;border:1px solid var(--border);border-radius:10px;
  color:var(--fg);font:500 .82rem var(--mono);line-height:1.5;padding:12px 13px;margin-top:14px;resize:vertical}
 .ta:focus{outline:none;border-color:var(--border-hi)}
 /* custom remote endpoint fields */
 .fields{display:flex;gap:14px;flex-wrap:wrap;margin-top:14px}
 .fields .sel{flex:1;min-width:190px}
 .fields input{font:500 .84rem var(--mono);color:var(--fg);background:var(--muted);border:1px solid var(--border);
  border-radius:10px;padding:10px 12px;min-height:44px;width:100%}
 .fields input:focus{outline:none;border-color:var(--border-hi)}
 .hint{color:var(--fg-muted);font-size:.72rem;margin-top:10px;font-family:var(--mono)}
 /* results */
 .reshead{display:flex;align-items:baseline;justify-content:space-between;margin:34px 2px 12px}
 .reshead h2{font-size:.8rem;font-weight:600;text-transform:uppercase;letter-spacing:.12em;color:var(--fg-muted);margin:0}
 .prog{font-family:var(--mono);font-size:.76rem;color:var(--accent)}
 .empty{color:var(--fg-muted);font-size:.9rem;padding:28px;text-align:center;border:1px dashed var(--border);border-radius:12px}
 .card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:15px 16px;margin-bottom:10px;
  animation:rise .35s ease both}
 @keyframes rise{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
 .card.fail{border-color:#5b2730}.card.pass{border-left:3px solid var(--accent)}
 .crow{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
 .pid{font-family:var(--mono);font-size:.84rem;color:#93c5fd;font-weight:500}
 .owasp{font-size:.74rem;color:var(--fg-muted)}
 .badge{margin-left:auto;font:600 .72rem var(--sans);letter-spacing:.04em;padding:5px 11px;border-radius:999px;
  display:inline-flex;align-items:center;gap:7px;text-transform:uppercase}
 .badge .dot{width:7px;height:7px;border-radius:50%}
 .b-run{background:var(--muted);color:var(--fg-muted)}.b-run .dot{background:var(--fg-muted);animation:pulse 1s ease infinite}
 .b-fail{background:var(--fail-dim);color:#fca5a5}.b-fail .dot{background:var(--fail)}
 .b-pass{background:var(--accent-dim);color:#86efac}.b-pass .dot{background:var(--accent)}
 .b-err{background:var(--warn-dim);color:#fcd34d}.b-err .dot{background:var(--warn)}
 @keyframes pulse{50%{opacity:.3}}
 .attack{font-family:var(--mono);font-size:.76rem;color:var(--fg-muted);margin:11px 0 0;padding-left:11px;border-left:2px solid var(--border-hi)}
 .resp{font-family:var(--mono);font-size:.78rem;line-height:1.5;color:#c9d1d9;background:#0e1626;border:1px solid var(--border);
  border-radius:8px;padding:11px 12px;margin:9px 0 0;white-space:pre-wrap;word-break:break-word;max-height:220px;overflow:auto;display:none}
 .resp.show{display:block}
 /* summary */
 .summary{display:none;gap:10px;margin-top:22px;flex-wrap:wrap}
 .summary.show{display:flex}
 .stat{flex:1;min-width:120px;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px}
 .stat .n{font-family:var(--mono);font-size:1.7rem;font-weight:700;line-height:1}
 .stat .l{font-size:.73rem;color:var(--fg-muted);text-transform:uppercase;letter-spacing:.08em;margin-top:6px}
 .stat.v .n{color:var(--fail)}.stat.p .n{color:var(--accent)}.stat.e .n{color:var(--warn)}
 .saved{color:var(--fg-muted);font-size:.74rem;margin-top:12px;font-family:var(--mono)}
 a{color:#93c5fd}
 :focus-visible{outline:2px solid #93c5fd;outline-offset:2px;border-radius:6px}
 @media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
 @media(max-width:560px){.panel{flex-direction:column;align-items:stretch}.btn{justify-content:center}.chip{max-width:100%}}
</style></head><body><div class=wrap>
 <header>
  <div class=logo><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
  <h1>AI Model Scanner <span>/ LLM red-team</span></h1>
 </header>
 <p class=sub>Red-team an AI system &middot; maps to <code>OWASP LLM Top&nbsp;10</code></p>

 <div class=tabs>
  <button class="tab on" id=tab-dyn onclick="showTab('dyn')">Dynamic &middot; live model</button>
  <button class=tab id=tab-stat onclick="showTab('stat')">Static &middot; prompt lint</button>
 </div>

 <div id=view-dyn>
  <div class=panel>
   <div class=chips id=chips><span class=chip>loading&hellip;</span></div>
   <div class=controls>
    <label class=sel for=model>Model<select id=model onchange=toggleCustom()></select></label>
    <label class=sel for=target>Target<select id=target></select></label>
    <button class=btn id=go onclick=run()>
     <svg id=goicon viewBox="0 0 24 24" fill=currentColor><path d="M8 5v14l11-7z"/></svg>
     <span id=golabel>Run scan</span></button>
   </div>
  </div>
  <div id=custombox hidden>
   <div class=fields>
    <label class=sel>Base URL<input id=cust-url placeholder="https://host/v1"></label>
    <label class=sel>API key<input id=cust-key type=password placeholder="sk-... (optional)"></label>
    <label class=sel>Model id<input id=cust-model placeholder="e.g. qwen2.5:0.5b"></label>
   </div>
   <p class=hint>Sent to this local server only, used for the scan, never saved to disk.</p>
  </div>
  <div class=reshead><h2>Results</h2><span class=prog id=prog></span></div>
  <div id=results><div class=empty>No scan yet. Hit <b>Run scan</b> to probe the target.</div></div>
  <div class=summary id=summary></div>
  <div class=saved id=saved></div>
 </div>

 <div id=view-stat hidden>
  <div class=panel>
   <div class=chips><span class=chip>mode <b>static</b></span><span class=chip>no endpoint needed</span></div>
   <button class=btn id=sgo onclick=runStatic()>
    <svg id=sgoicon viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2.4 stroke-linecap=round><path d="M4 7h16M4 12h10M4 17h7"/></svg>
    <span id=sgolabel>Run static scan</span></button>
  </div>
  <p class=sub style="margin:14px 0 0">Paste a system prompt to lint, or leave blank to lint every target prompt.</p>
  <textarea class=ta id=prompttext placeholder="You are a support bot. The password is hunter2..."></textarea>
  <div class=reshead><h2>Findings</h2><span class=prog id=sprog></span></div>
  <div id=sresults><div class=empty>No static scan yet. Hit <b>Run static scan</b>.</div></div>
  <div class=summary id=ssummary></div>
  <div class=saved id=ssaved></div>
 </div>
</div>
<script>
let CFG={};
fetch('/api/probes').then(r=>r.json()).then(d=>{CFG=d;
 document.getElementById('chips').innerHTML=
  `<span class=chip title="${d.endpoint}">endpoint <b>${d.endpoint}</b></span>`+
  `<span class=chip>probes <b>${d.probes.length}</b></span>`;
 let opts=`<optgroup label="Local models">`+d.models.map(m=>`<option value="${m}">${m}</option>`).join('')+`</optgroup>`;
 if(d.connectors&&d.connectors.length)opts+=`<optgroup label="HTTP connectors (remote)">`+
   d.connectors.map(c=>`<option value="conn:${c.id}">&#8646; ${c.name}</option>`).join('')+`</optgroup>`;
 opts+=`<option value="custom">+ Custom remote endpoint</option>`;
 byId('model').innerHTML=opts;
 byId('target').innerHTML=d.targets.map(t=>`<option value="${t.id}">${t.name}</option>`).join('');});

function toggleCustom(){byId('custombox').hidden=byId('model').value!=='custom';}

function badge(kind,label){return `<span class="badge b-${kind}"><span class=dot></span>${label}</span>`;}

async function run(){
 const go=byId('go'),golabel=byId('golabel'),goicon=byId('goicon'),res=byId('results'),
   prog=byId('prog'),summary=byId('summary'),saved=byId('saved');
 const tsel=byId('target'),tid=tsel.value,tname=tsel.selectedOptions[0].text,model=byId('model').value;
 let custom=null,label=model;
 if(model==='custom'){
  custom={base_url:byId('cust-url').value.trim(),api_key:byId('cust-key').value.trim(),model:byId('cust-model').value.trim()};
  if(!custom.base_url||!custom.model){saved.textContent='⚠ enter a Base URL and Model id first';return;}
  label='custom:'+custom.model;
 }
 go.disabled=true;goicon.outerHTML='<span class=spin id=goicon></span>';golabel.textContent='Scanning…';
 res.innerHTML='';summary.className='summary';saved.textContent='';
 let vuln=0,err=0,done=0;const results=[],total=CFG.probes.length;
 for(const p of CFG.probes){
  const card=document.createElement('div');card.className='card';
  card.innerHTML=`<div class=crow><span class=pid>${p.id}</span><span class=owasp>${p.owasp}</span>`+
   badge('run','running')+`</div><div class=attack>${esc(p.attack)}</div><pre class=resp></pre>`;
  res.appendChild(card);
  prog.textContent=`${done+1} / ${total}`;
  const setBadge=(k,l)=>card.querySelector('.badge').outerHTML=badge(k,l);
  const showResp=t=>{const pre=card.querySelector('.resp');pre.textContent=t;pre.classList.add('show');};
  try{
   const r=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({probe:p.id,target:tid,model,custom})});
   const d=await r.json();d.attack=p.attack;results.push(d);
   if(d.error){card.className='card';setBadge('err','error');showResp(d.error);err++;}
   else if(d.vulnerable){card.className='card fail';setBadge('fail','fail');showResp(d.response);vuln++;}
   else{card.className='card pass';setBadge('pass','pass');showResp(d.response);}
  }catch(e){results.push({probe:p.id,owasp:p.owasp,attack:p.attack,error:String(e)});
   card.className='card';setBadge('err','error');showResp(String(e));err++;}
  done++;
 }
 byId('goicon').outerHTML='<svg id=goicon viewBox="0 0 24 24" fill=currentColor><path d="M8 5v14l11-7z"/></svg>';
 golabel.textContent='Run scan';go.disabled=false;prog.textContent='';
 summary.innerHTML=
  `<div class="stat v"><div class=n>${vuln}</div><div class=l>Vulnerable</div></div>`+
  `<div class="stat p"><div class=n>${total-vuln-err}</div><div class=l>Passed</div></div>`+
  `<div class="stat e"><div class=n>${err}</div><div class=l>Errors</div></div>`+
  `<div class=stat><div class=n>${total}</div><div class=l>Probes</div></div>`;
 summary.className='summary show';
 saved.textContent=`✓ ${tname} on ${label} — saved to scan-results.json`;
 fetch('/api/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({model:label,target_id:tid,target_name:tname,vulnerable:vuln,errors:err,results})});
}
function showTab(w){
 byId('tab-dyn').classList.toggle('on',w=='dyn');byId('tab-stat').classList.toggle('on',w=='stat');
 byId('view-dyn').hidden=w!='dyn';byId('view-stat').hidden=w!='stat';
}
async function runStatic(){
 const go=byId('sgo'),res=byId('sresults'),sum=byId('ssummary'),saved=byId('ssaved'),prog=byId('sprog');
 go.disabled=true;prog.textContent='scanning…';res.innerHTML='';sum.className='summary';saved.textContent='';
 let d;
 try{const r=await fetch('/api/static',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:byId('prompttext').value})});d=await r.json();}
 catch(e){prog.textContent='';go.disabled=false;res.innerHTML=`<div class=empty>error: ${esc(String(e))}</div>`;return;}
 prog.textContent='';go.disabled=false;
 if(!d.findings.length){res.innerHTML='<div class=empty>No findings. Clean to these rules.</div>';}
 else{res.innerHTML='';for(const f of d.findings){
   const card=document.createElement('div');card.className='card'+(f.severity=='high'?' fail':'');
   card.innerHTML=`<div class=crow><span class=pid>${f.check}</span><span class=owasp>${f.owasp} &middot; ${esc(f.item)}:${f.line}</span>`+
    badge(f.severity=='high'?'fail':'err',f.severity)+`</div><div class=attack>${esc(f.message)}</div>`+
    `<pre class="resp show">evidence: ${esc(f.evidence||'(none)')}\n&rarr; ${esc(f.recommendation)}</pre>`;
   res.appendChild(card);}}
 const hi=d.findings.filter(f=>f.severity=='high').length;
 sum.innerHTML=
  `<div class="stat v"><div class=n>${hi}</div><div class=l>High</div></div>`+
  `<div class="stat e"><div class=n>${d.findings_total-hi}</div><div class=l>Medium</div></div>`+
  `<div class=stat><div class=n>${d.findings_total}</div><div class=l>Findings</div></div>`+
  `<div class=stat><div class=n>${d.scanned.length}</div><div class=l>Prompts</div></div>`;
 sum.className='summary show';saved.textContent='✓ saved to static-scan-results.json';
}
function byId(i){return document.getElementById(i);}
function esc(s){return s.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
</script></body></html>"""

class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif self.path == "/api/probes":
            probes = [{"id": p[0], "owasp": p[1], "attack": p[2]} for p in scan.PROBES]
            targets = [{"id": t["id"], "name": t["name"]} for t in scan.TARGETS]
            connectors = [{"id": c["id"], "name": c["name"]} for c in scan.CONNECTORS]
            self._send(200, json.dumps({"endpoint": scan.ENDPOINT, "models": ollama_models(),
                                        "connectors": connectors, "targets": targets, "probes": probes}))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        if self.path == "/api/save":  # persist a full UI run, all responses kept for audit
            report = {"target": scan.ENDPOINT, "model": scan.MODEL,
                      "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                      "probes_run": len(scan.PROBES), **body}
            scan.OUT.write_text(json.dumps(report, indent=2))
            return self._send(200, json.dumps({"saved": str(scan.OUT)}))
        if self.path == "/api/static":  # static prompt lint, no endpoint touched
            text = (body.get("text") or "").strip()
            items = [("pasted", text, None)] if text else staticscan._items([])
            findings = []
            for name, t, secret in items:
                findings += staticscan.lint(name, t, secret)
            report = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "scanned": [i[0] for i in items],
                      "findings_total": len(findings), "findings": findings}
            staticscan.OUT.write_text(json.dumps(report, indent=2))
            return self._send(200, json.dumps(report))
        if self.path != "/api/run":
            return self._send(404, json.dumps({"error": "not found"}))
        pid, tid = body.get("probe"), body.get("target")
        model = body.get("model") or scan.MODEL
        custom = body.get("custom")
        conn = None
        if model == "custom" and custom:  # ad-hoc remote endpoint typed into the UI; key not persisted
            url = (custom.get("base_url") or "").strip()
            if "chat/completions" not in url:
                url = url.rstrip("/") + "/chat/completions"
            headers = {"Content-Type": "application/json"}
            if custom.get("api_key"):
                headers["Authorization"] = "Bearer " + custom["api_key"]
            conn = {"endpoint": url, "method": "POST", "headers": headers,
                    "body": {"model": custom.get("model"), "temperature": 0, "max_tokens": 512,
                             "messages": [{"role": "system", "content": "{{system}}"},
                                          {"role": "user", "content": "{{prompt}}"}]},
                    "response_path": "choices.0.message.content"}
        elif model.startswith("conn:"):
            conn = scan.connector_by_id(model[5:])
        probe = next((p for p in scan.PROBES if p[0] == pid), None)
        t = scan.target_by_id(tid) or (scan.TARGETS[0] if scan.TARGETS else None)
        if not probe or not t:
            return self._send(400, json.dumps({"error": f"unknown probe/target {pid}/{tid}"}))
        try:
            resp = scan.generate(probe[2], t["system"], model=model, connector=conn)
            self._send(200, json.dumps({"probe": pid, "owasp": probe[1],
                                        "vulnerable": bool(probe[3](resp, t)),
                                        "response": resp.strip()[:600]}))
        except Exception as e:
            self._send(200, json.dumps({"probe": pid, "error": str(e)}))

    def log_message(self, *a): pass  # quiet

if __name__ == "__main__":
    print(f"AI Model Scanner UI on http://localhost:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
