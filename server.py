#!/usr/bin/env python3
"""Local web UI for ai-scan.

App scan tab: upload a browser HAR (or pick a target config), test the connection, then run
ai-scan.py (our data-leak checks + garak) as a background job with live progress and a stop button.
Static tab: lint system prompts with static-scan.py, no endpoint touched.
The HAR is parsed in memory and never stored. The password or token goes to the scan process
by env var only. ponytail: stdlib http.server, page served inline, jobs kept in memory.
"""
import json, os, re, signal, subprocess, sys, time, importlib.util, urllib.error
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import scan

def _load(name, file):
    # ai-scan.py and static-scan.py have hyphens, so load them by path
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod

aiscan = _load("aiscan", "ai-scan.py")
staticscan = _load("staticscan", "static-scan.py")

PORT = 8099
APP_TARGETS = HERE / "app-targets"  # configs built from uploaded HARs (structure only, no secrets)
CONFIG_DIRS = (HERE / "data-leak", APP_TARGETS)
DEFAULT_PROBES = "promptinject,latentinjection.LatentInjectionReport"
JOBS = {}

def configs():
    return {f"{d.name}/{p.name}": p for d in CONFIG_DIRS if d.exists() for p in sorted(d.glob("*-target.json"))}

def load_cfg(cid, secret):
    path = configs().get(cid)
    if not path:
        raise ValueError(f"unknown config {cid}")
    text = path.read_text()
    if secret:
        # fill the placeholders here instead of os.environ, which threads would share
        esc = json.dumps(secret)[1:-1]
        text = text.replace("{{env:AI_SCAN_PASSWORD}}", esc).replace("{{env:AI_SCAN_TOKEN}}", esc)
    return path, scan._resolve_env(json.loads(text))

def summary(raw):
    path = next(iter(raw["chat_paths"].values()))
    auth = (f"login {raw['login_path']} as {raw['tester']['username']}" if raw.get("login_path")
            else "bearer token" if raw.get("auth_header") else "none")
    return {"endpoint": f"POST {raw['base_url']}{path} ({raw.get('transport', 'http-json')})",
            "body": json.dumps(raw.get("chat_body")), "auth": auth, "reply_path": raw.get("reply_path"),
            "second_account": "other_account" in raw}

PAGE = """<!doctype html><html lang=en><head><meta charset=utf-8>
<title>ai-scan</title><meta name=viewport content="width=device-width,initial-scale=1">
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
 [hidden]{display:none!important}
 body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 var(--sans);
  background-image:radial-gradient(900px 500px at 80% -10%,#15213f 0,transparent 60%);min-height:100vh}
 .wrap{max-width:920px;margin:0 auto;padding:40px 20px 80px}
 header{display:flex;align-items:center;gap:14px;margin-bottom:6px}
 .logo{width:40px;height:40px;border-radius:10px;display:grid;place-items:center;
  background:linear-gradient(145deg,#1f6f3e,#22C55E);box-shadow:0 0 22px #22c55e33}
 .logo svg{width:22px;height:22px;color:#06130a}
 h1{font-size:1.35rem;font-weight:600;margin:0;letter-spacing:-.01em}
 h1 span{color:var(--fg-muted);font-weight:400}
 .sub{color:var(--fg-muted);font-size:.82rem;margin:2px 0 26px;letter-spacing:.02em}
 .sub code{font-family:var(--mono);color:#93c5fd}
 .panel{background:linear-gradient(180deg,#1d2740,#1a2235);border:1px solid var(--border);
  border-radius:14px;padding:20px;display:flex;flex-wrap:wrap;gap:16px;align-items:flex-end;justify-content:space-between;
  box-shadow:0 1px 0 #ffffff08 inset,0 10px 30px #00000040;margin-top:14px}
 .chips{display:flex;flex-wrap:wrap;gap:8px}
 .chip{font-family:var(--mono);font-size:.72rem;color:var(--fg-muted);background:var(--muted);
  border:1px solid var(--border);border-radius:999px;padding:6px 11px;max-width:360px;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
 .chip b{color:var(--fg);font-weight:600}
 .btn{font:600 .95rem var(--sans);color:#06130a;background:var(--accent);border:0;border-radius:10px;
  padding:12px 20px;display:inline-flex;align-items:center;gap:9px;cursor:pointer;min-height:44px;
  transition:transform .15s ease,box-shadow .15s ease,background .15s ease}
 .btn:hover:not(:disabled){transform:translateY(-1px);box-shadow:0 6px 20px #22c55e40}
 .btn:disabled{opacity:.55;cursor:wait}
 .btn{white-space:nowrap}
 .stat .n.word{font-size:1rem;color:var(--fg-muted)!important;line-height:1.7rem}
 .btn.ghost{background:transparent;color:var(--fg);border:1px solid var(--border-hi)}
 .btn.ghost:hover:not(:disabled){box-shadow:none;border-color:var(--fail);color:#fca5a5}
 .btn svg{width:16px;height:16px}
 .controls{display:flex;gap:14px;align-items:flex-end;flex-wrap:wrap;flex:1}
 .sel{display:flex;flex-direction:column;gap:6px;font:600 .66rem var(--sans);text-transform:uppercase;letter-spacing:.1em;color:var(--fg-muted)}
 .sel select,.sel input{font:500 .85rem var(--mono);color:var(--fg);background:var(--muted);border:1px solid var(--border);
  border-radius:10px;padding:10px 12px;min-height:44px;text-transform:none;letter-spacing:0}
 .sel select{cursor:pointer;max-width:340px}
 .sel input[type=number]{width:90px}
 .sel input#probes{width:320px;max-width:100%}
 .sel input[type=file]{padding:8px}
 .sel select:focus,.sel input:focus{outline:none;border-color:var(--border-hi)}
 .tabs{display:flex;gap:8px;margin:0 0 8px}
 .tab{font:600 .82rem var(--sans);color:var(--fg-muted);background:transparent;border:1px solid var(--border);
  border-radius:999px;padding:9px 18px;cursor:pointer;min-height:42px}
 .tab:hover{border-color:var(--border-hi)}
 .tab.on{color:#06130a;background:var(--accent);border-color:var(--accent)}
 .ta{width:100%;min-height:120px;background:#0e1626;border:1px solid var(--border);border-radius:10px;
  color:var(--fg);font:500 .82rem var(--mono);line-height:1.5;padding:12px 13px;margin-top:14px;resize:vertical}
 .hint{color:var(--fg-muted);font-size:.72rem;margin:10px 2px 0;font-family:var(--mono)}
 .reshead{display:flex;align-items:baseline;justify-content:space-between;margin:34px 2px 12px}
 .reshead h2{font-size:.8rem;font-weight:600;text-transform:uppercase;letter-spacing:.12em;color:var(--fg-muted);margin:0}
 .prog{font-family:var(--mono);font-size:.76rem;color:var(--accent)}
 .empty{color:var(--fg-muted);font-size:.9rem;padding:28px;text-align:center;border:1px dashed var(--border);border-radius:12px}
 .card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:15px 16px;margin-bottom:10px}
 .card.fail{border-color:#5b2730}
 .crow{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
 .pid{font-family:var(--mono);font-size:.84rem;color:#93c5fd;font-weight:500}
 .owasp{font-size:.74rem;color:var(--fg-muted)}
 .badge{margin-left:auto;font:600 .72rem var(--sans);letter-spacing:.04em;padding:5px 11px;border-radius:999px;
  display:inline-flex;align-items:center;gap:7px;text-transform:uppercase}
 .badge .dot{width:7px;height:7px;border-radius:50%}
 .b-fail{background:var(--fail-dim);color:#fca5a5}.b-fail .dot{background:var(--fail)}
 .b-pass{background:var(--accent-dim);color:#86efac}.b-pass .dot{background:var(--accent)}
 .b-err{background:var(--warn-dim);color:#fcd34d}.b-err .dot{background:var(--warn)}
 .attack{font-family:var(--mono);font-size:.76rem;color:var(--fg-muted);margin:11px 0 0;padding-left:11px;border-left:2px solid var(--border-hi);
  white-space:pre-wrap;word-break:break-word;max-height:90px;overflow:auto}
 .resp{font-family:var(--mono);font-size:.78rem;line-height:1.5;color:#c9d1d9;background:#0e1626;border:1px solid var(--border);
  border-radius:8px;padding:11px 12px;margin:9px 0 0;white-space:pre-wrap;word-break:break-word;max-height:260px;overflow:auto;display:none}
 .resp.show{display:block}
 .summary{display:none;gap:10px;margin-top:22px;flex-wrap:wrap}
 .summary.show{display:flex}
 .stat{flex:1;min-width:120px;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px}
 .stat .n{font-family:var(--mono);font-size:1.7rem;font-weight:700;line-height:1}
 .stat .l{font-size:.73rem;color:var(--fg-muted);text-transform:uppercase;letter-spacing:.08em;margin-top:6px}
 .stat.v .n{color:var(--fail)}.stat.p .n{color:var(--accent)}.stat.e .n{color:var(--warn)}
 .saved{color:var(--fg-muted);font-size:.74rem;margin-top:12px;font-family:var(--mono)}
 table{width:100%;border-collapse:collapse;font:.8rem var(--mono);margin-top:12px}
 th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--border)}
 th{color:var(--fg-muted);font:600 .66rem var(--sans);text-transform:uppercase;letter-spacing:.1em}
 .tbl{overflow-x:auto}
 :focus-visible{outline:2px solid #93c5fd;outline-offset:2px;border-radius:6px}
 @media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
 @media(max-width:560px){.panel{flex-direction:column;align-items:stretch}.btn{justify-content:center}}
</style></head><body><div class=wrap>
 <header>
  <div class=logo><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
  <h1>ai-scan <span>/ AI chatbot security scan</span></h1>
 </header>
 <p class=sub>Data-leak checks + garak &middot; maps to <code>OWASP LLM Top&nbsp;10</code> and the Arcanum PI taxonomy</p>

 <div class=tabs>
  <button class="tab on" id=tab-app onclick="showTab('app')">App scan</button>
  <button class=tab id=tab-stat onclick="showTab('stat')">Static &middot; prompt lint</button>
 </div>

 <div id=view-app>
  <div class=panel>
   <div class=controls>
    <label class=sel for=src>Target<select id=src onchange=srcChange()></select></label>
    <label class=sel for=harfile id=harbox>HAR file<input id=harfile type=file accept=".har,application/json"></label>
    <label class=sel for=secret>Test account password or token<input id=secret type=password autocomplete=off placeholder="if the config needs one"></label>
   </div>
   <button class=btn id=tbtn onclick=testConn()>Test connection</button>
  </div>
  <p class=hint>The HAR is read once for the endpoint shape and is not stored. The password or token is used for this scan only.</p>
  <pre class=resp id=conn></pre>

  <div class=panel>
   <div class=controls>
    <label class=sel for=garak>garak<select id=garak><option value=1>on</option><option value=0>off</option></select></label>
    <label class=sel for=probes>garak probes<input id=probes></label>
    <label class=sel for=cap>Prompts / probe<input id=cap type=number value=5 min=1 max=50></label>
    <label class=sel for=repeats>Repeats<input id=repeats type=number value=20 min=1 max=30></label>
   </div>
   <p class=hint style="flex-basis:100%;margin:0">Repeats apply to each data-leak check. With 0 leaks in N requests,
    leaks rarer than about 3/N per request can still be missed, so fewer repeats = weaker "no leak".</p>
   <div class=controls style="flex:0">
    <button class=btn id=go onclick=runScan()>
     <svg viewBox="0 0 24 24" fill=currentColor><path d="M8 5v14l11-7z"/></svg><span>Run scan</span></button>
    <button class="btn ghost" id=stop hidden onclick=stopScan()>Stop</button>
   </div>
  </div>

  <div class=reshead><h2>Results</h2><span class=prog id=prog></span></div>
  <div id=results><div class=empty>No scan yet. Pick a target or upload a HAR, test the connection, then run the scan.</div></div>
  <pre class=resp id=log></pre>
  <div class=saved id=saved></div>
 </div>

 <div id=view-stat hidden>
  <div class=panel>
   <div class=chips><span class=chip>mode <b>static</b></span><span class=chip>no endpoint needed</span></div>
   <button class=btn id=sgo onclick=runStatic()><span>Run static scan</span></button>
  </div>
  <p class=sub style="margin:14px 0 0">Paste a system prompt to lint, or leave blank to lint every prompt in targets.json.</p>
  <textarea class=ta id=prompttext placeholder="You are a support bot. The password is hunter2..."></textarea>
  <div class=reshead><h2>Findings</h2><span class=prog id=sprog></span></div>
  <div id=sresults><div class=empty>No static scan yet.</div></div>
  <div class=summary id=ssummary></div>
  <div class=saved id=ssaved></div>
 </div>
</div>
<script>
const ORDER={confirmed:0,likely:1,suspected:2,refused:3};
const KIND={confirmed:'fail',likely:'fail',suspected:'err',refused:'pass'};
let JOB=null;
byId('probes').value='__PROBES__';

async function loadConfigs(pick){
 const d=await (await fetch('/api/configs')).json();
 NEEDS=Object.fromEntries(d.configs.map(c=>[c.id,c.needs_secret]));
 byId('src').innerHTML='<option value="__har">Upload a HAR file</option>'+
  d.configs.map(c=>`<option value="${esc(c.id)}">${esc(c.id)}</option>`).join('');
 if(pick)byId('src').value=pick;
 srcChange();
}
let NEEDS={};
function srcChange(){
 const v=byId('src').value; byId('harbox').hidden=v!=='__har';
 byId('secret').placeholder=v==='__har'||NEEDS[v]?'required: test account password or token':'not needed for this config';
}
async function post(url,body){
 const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
 const d=await r.json(); if(!r.ok||d.error)throw new Error(d.error||('HTTP '+r.status)); return d;
}
async function ensureConfig(){
 if(byId('src').value!=='__har')return byId('src').value;
 const f=byId('harfile').files[0]; if(!f)throw new Error('choose a HAR file first');
 let har; try{har=JSON.parse(await f.text());}catch(e){throw new Error('this file is not valid HAR/JSON');}
 const d=await post('/api/har',{name:f.name.replace(/\\.har$/i,''),har});
 await loadConfigs(d.config); return d.config;
}
async function testConn(){
 const out=byId('conn'),b=byId('tbtn'); out.className='resp show'; out.textContent='testing...'; b.disabled=true;
 try{
  const id=await ensureConfig(), d=await post('/api/test',{config:id,secret:byId('secret').value}), s=d.summary;
  out.textContent=`config:    ${id}\nendpoint:  ${s.endpoint}\nbody:      ${s.body}\nauth:      ${s.auth}\nreply at:  ${s.reply_path}\n`+
   `2nd account: ${s.second_account?'yes (data-leak checks will run)':'no (data-leak checks: not tested)'}\n\nsent:  ${d.sent}\nreply: ${d.reply}`;
 }catch(e){out.textContent='error: '+e.message;}
 b.disabled=false;
}
async function runScan(){
 const go=byId('go'); go.disabled=true; byId('saved').textContent='';
 try{
  const id=await ensureConfig();
  const d=await post('/api/scan',{config:id,secret:byId('secret').value,garak:byId('garak').value==='1',
   probes:byId('probes').value.trim(),cap:+byId('cap').value,repeats:+byId('repeats').value});
  JOB=d.job; byId('stop').hidden=false; byId('results').innerHTML=''; byId('log').className='resp show';
  byId('prog').textContent='running...'; poll();
 }catch(e){go.disabled=false; byId('saved').textContent='error: '+e.message;}
}
async function poll(){
 const d=await (await fetch('/api/job?id='+JOB)).json();
 byId('log').textContent=d.log||'starting...'; byId('log').scrollTop=1e9;
 if(!d.done){setTimeout(poll,2000);return;}
 byId('go').disabled=false; byId('stop').hidden=true;
 byId('prog').textContent=d.code===0?'done':'stopped (exit '+d.code+')';
 if(d.report)render(d.report,d.out);
}
async function stopScan(){try{await post('/api/stop',{id:JOB});}catch(e){}}
function render(r,out){
 const res=byId('results'); let html='';
 const own=r.own_checks; let leak='not tested',tools='-';
 if(own&&typeof own==='object'){
  const a=own.summary.filter(x=>x.check.startsWith('authz.')),t=own.summary.filter(x=>x.check.startsWith('recon.'));
  leak=a.reduce((s,x)=>s+x.leaks,0)+'/'+a.reduce((s,x)=>s+x.valid,0);
  if(t.length)tools=t.reduce((s,x)=>s+x.leaks,0)+'/'+t.reduce((s,x)=>s+x.valid,0);
 }
 const modes=Object.entries((r.garak||{}).by_mode||{}),tot=v=>modes.reduce((s,[,m])=>s+(m[v]||0),0);
 html+=`<div class="summary show">`+
  stat('v',leak,'Data leak (other account)')+stat('e',tools,'Tool names disclosed')+
  (modes.length?stat('v',tot('confirmed'),'garak confirmed')+stat('v',tot('likely'),'garak likely')+
   stat('e',tot('suspected'),'garak suspected')+stat('p',tot('refused'),'refused (quoted)'):'')+`</div>`;
 if(own&&typeof own==='object'){
  html+=`<div class=tbl><table><tr><th>Check</th><th>Mode</th><th>PIT</th><th>Hits</th><th>Values</th></tr>`+
   own.summary.filter(x=>!x.check.startsWith('control')).map(x=>`<tr><td>${esc(x.check)}</td><td>${esc(x.mode)}</td><td>${esc(x.pit)}</td>`+
   `<td>${x.leaks}/${x.valid}</td><td>${esc(x.leaked_values.join(', ')||'-')}</td></tr>`).join('')+`</table></div>`;
  html+=Object.entries(own.authz_sensitivity||{}).map(([m,s])=>`<p class=hint>${esc(m)}: `+(!s.valid?'no valid requests':
   !s.leaks?`0/${s.valid} leaks. A leak rate of ${(s.rate_high_95*100).toFixed(1)}% or more per request would have shown up 95% of the time; rarer leaks can still be missed.`
   :`${s.leaks}/${s.valid} leaks. Leak rate ${(s.rate_low_95*100).toFixed(1)}% to ${(s.rate_high_95*100).toFixed(1)}% per request (95%).`)+`</p>`).join('');
  if(!own.control_passed)html+=`<p class=hint>Control FAILED: the tester could not read its own data, so "no leak" proves nothing.</p>`;
 } else html+=`<p class=hint>Data-leak checks: ${esc(String(own||'not run'))}</p>`;
 const f=modes.flatMap(([mode,m])=>m.findings.map(x=>({...x,mode}))).filter(x=>x.verdict!=='refused')
  .sort((a,b)=>ORDER[a.verdict]-ORDER[b.verdict]).slice(0,60);
 html+=f.map(x=>`<div class="card${x.verdict==='confirmed'||x.verdict==='likely'?' fail':''}"><div class=crow>`+
  `<span class=pid>${esc(x.probe)}</span><span class=owasp>${esc(x.pit)} &middot; ${esc(x.mode)}</span>`+
  `<span class="badge b-${KIND[x.verdict]}"><span class=dot></span>${x.verdict}</span></div>`+
  `<div class=attack>${esc(x.prompt)}</div><pre class="resp show">${esc(x.output)}</pre></div>`).join('');
 res.innerHTML=html; byId('saved').textContent='report: '+out;
}
// a word like "not tested" is not a result, so it gets neutral styling instead of the red/amber number style
function stat(k,n,l){const w=!/^[\\d\\/-]+$/.test(String(n));
 return `<div class="stat ${k}"><div class="n${w?' word':''}">${n}</div><div class=l>${l}</div></div>`;}
function showTab(w){
 byId('tab-app').classList.toggle('on',w=='app');byId('tab-stat').classList.toggle('on',w=='stat');
 byId('view-app').hidden=w!='app';byId('view-stat').hidden=w!='stat';
}
async function runStatic(){
 const go=byId('sgo'),res=byId('sresults'),sum=byId('ssummary'),saved=byId('ssaved'),prog=byId('sprog');
 go.disabled=true;prog.textContent='scanning...';res.innerHTML='';sum.className='summary';saved.textContent='';
 let d;
 try{d=await post('/api/static',{text:byId('prompttext').value});}
 catch(e){prog.textContent='';go.disabled=false;res.innerHTML=`<div class=empty>error: ${esc(e.message)}</div>`;return;}
 prog.textContent='';go.disabled=false;
 res.innerHTML=d.findings.length?d.findings.map(f=>`<div class="card${f.severity=='high'?' fail':''}"><div class=crow>`+
  `<span class=pid>${f.check}</span><span class=owasp>${f.owasp} &middot; ${esc(f.item)}:${f.line}</span>`+
  `<span class="badge b-${f.severity=='high'?'fail':'err'}"><span class=dot></span>${f.severity}</span></div>`+
  `<div class=attack>${esc(f.message)}</div><pre class="resp show">evidence: ${esc(f.evidence||'(none)')}\\n-> ${esc(f.recommendation)}</pre></div>`).join('')
  :'<div class=empty>No findings. Clean to these rules.</div>';
 const hi=d.findings.filter(f=>f.severity=='high').length;
 sum.innerHTML=stat('v',hi,'High')+stat('e',d.findings_total-hi,'Medium')+stat('',d.findings_total,'Findings')+stat('',d.scanned.length,'Prompts');
 sum.className='summary show';saved.textContent='saved to static-scan-results.json';
}
function byId(i){return document.getElementById(i);}
function esc(s){return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
loadConfigs();
</script></body></html>""".replace("__PROBES__", DEFAULT_PROBES)

class H(BaseHTTPRequestHandler):
    def _send(self, code, obj, ctype="application/json"):
        b = (obj if isinstance(obj, str) else json.dumps(obj)).encode()
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if u.path == "/api/configs":
            return self._send(200, {"configs": [{"id": cid, "needs_secret": "{{env:AI_SCAN_" in p.read_text()}
                                                for cid, p in configs().items()]})
        if u.path == "/api/job":
            j = JOBS.get((parse_qs(u.query).get("id") or [""])[0])
            if not j:
                return self._send(404, {"error": "unknown job"})
            code = j["proc"].poll()
            log = j["log"].read_text(errors="replace")[-6000:] if j["log"].exists() else ""
            report = json.loads(j["out"].read_text()) if code is not None and j["out"].exists() else None
            return self._send(200, {"done": code is not None, "code": code, "log": log,
                                    "report": report, "out": str(j["out"])})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            handler = {"/api/har": self.har, "/api/test": self.test, "/api/scan": self.scan,
                       "/api/stop": self.stop, "/api/static": self.static}.get(self.path)
            if not handler:
                return self._send(404, {"error": "not found"})
            self._send(200, handler(body))
        except Exception as e:
            self._send(400, {"error": str(e)})

    def har(self, body):
        # the HAR may hold the tester's password and chat text: read structure, store only the config
        cfg = aiscan.connector.config_from_har(body["har"])
        name = re.sub(r"[^a-z0-9-]+", "-", (body.get("name") or "app").lower()).strip("-")[:40] or "app"
        APP_TARGETS.mkdir(exist_ok=True)
        p = APP_TARGETS / f"{name}-target.json"
        p.write_text(json.dumps(cfg, indent=2))
        return {"config": f"{APP_TARGETS.name}/{p.name}"}

    def test(self, body):
        path, cfg = load_cfg(body.get("config"), body.get("secret"))
        try:
            headers = aiscan.dls.get_auth_headers(cfg)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                who = cfg.get("tester", {}).get("username") or "the test account"
                hint = "the password or token field is empty" if not body.get("secret") else "check the password or token"
                raise ValueError(f"login as {who} was refused (HTTP {e.code}): {hint}")
            raise
        chat_path = next(iter(cfg["chat_paths"].values()))
        raw = json.loads(path.read_text())
        if not cfg.get("reply_path"):  # HAR had no response body: learn it from one live reply
            raw["reply_path"] = cfg["reply_path"] = aiscan.connector.detect_reply_path(cfg, chat_path, aiscan.HELLO, headers)
            path.write_text(json.dumps(raw, indent=2))
        reply = aiscan.connector.send(cfg, chat_path, aiscan.HELLO, headers)
        return {"summary": summary(raw), "sent": aiscan.HELLO, "reply": reply[:600] or "(empty: check reply_path)"}

    def scan(self, body):
        path, _ = load_cfg(body.get("config"), "")  # validates the id
        probes = body.get("probes") or DEFAULT_PROBES
        if not re.fullmatch(r"[A-Za-z0-9_.,]+", probes):
            raise ValueError("probes: comma-separated garak probe names only")
        cap = max(1, min(int(body.get("cap") or 5), 50))
        repeats = max(1, min(int(body.get("repeats") or 2), 30))
        jid = time.strftime("%Y%m%d-%H%M%S")
        aiscan.RUN_DIR.mkdir(exist_ok=True)
        out, log = aiscan.RUN_DIR / f"ui-{jid}.json", aiscan.RUN_DIR / f"ui-{jid}.log"
        cmd = [sys.executable, str(HERE / "ai-scan.py"), "-c", str(path), "--repeats", str(repeats), "-o", str(out)]
        if body.get("garak"):
            cmd += ["--with-garak", "--garak-probes", probes, "--cap", str(cap)]
        env = {**os.environ, "PYTHONUNBUFFERED": "1"}
        if body.get("secret"):  # by env var only, so it is never written to disk
            env["AI_SCAN_PASSWORD"] = env["AI_SCAN_TOKEN"] = body["secret"]
        # own session, so Stop also ends the garak process that ai-scan starts
        proc = subprocess.Popen(cmd, stdout=open(log, "w"), stderr=subprocess.STDOUT, env=env,
                                cwd=HERE, start_new_session=True)
        JOBS[jid] = {"proc": proc, "log": log, "out": out}
        return {"job": jid}

    def stop(self, body):
        j = JOBS.get(body.get("id"))
        if j and j["proc"].poll() is None:
            os.killpg(j["proc"].pid, signal.SIGTERM)
        return {"stopped": bool(j)}

    def static(self, body):  # static prompt lint, no endpoint touched
        text = (body.get("text") or "").strip()
        items = [("pasted", text, None)] if text else staticscan._items([])
        findings = [f for name, t, secret in items for f in staticscan.lint(name, t, secret)]
        report = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "scanned": [i[0] for i in items],
                  "findings_total": len(findings), "findings": findings}
        staticscan.OUT.write_text(json.dumps(report, indent=2))
        return report

    def log_message(self, *a):
        pass

if __name__ == "__main__":
    print(f"ai-scan UI on http://localhost:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
