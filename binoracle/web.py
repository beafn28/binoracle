"""Local web interface for binoracle (stdlib http.server only, no extra deps).

`binoracle serve` starts a localhost-only dashboard to drive every command and option from
the browser, with the interactive HTML report embedded. It calls the workflows in-process."""
from __future__ import annotations

import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import load_config
from .llm import make_backend
from .oracles import build_registry
from .store.session import SessionStore
from .workflows.triage import run_triage
from .workflows.vulnhunt import run_hunt
from .workflows.primitives import run_primitives
from .workflows.verify import auto_verify
from .workflows.enrich import enrich_findings, executive_summary
from .workflows.rop import build_rop_chain
from .workflows.shellcode import gen_shellcode
from .workflows.fuzz import generate_fuzz
from .workflows.fmtstring import fmtstring_help
from .workflows.skeleton import generate_skeleton
from .workflows.verify import verify_address
from .report.html import render_html
from .report.render import render_triage

_registries = {}


def _reg(binary):
    if binary not in _registries:
        _registries[binary] = build_registry(binary, enable_dynamic=True)
    return _registries[binary]


def _tool_text(reg, name, **kw):
    t = reg.get(name)
    if not t:
        return f"(tool {name} unavailable)"
    r = t.run(**kw)
    return r.data if r.ok else f"[unavailable] {r.error}"


def run_command(payload: dict) -> dict:
    cmd = payload.get("command", "")
    binary = (payload.get("binary") or "").strip()
    opts = payload.get("options", {}) or {}
    config = load_config()

    import os
    if cmd == "doctor":
        llm = make_backend(config)
        reg = _reg(binary) if binary and os.path.exists(binary) else build_registry(__file__)
        lines = [f"LLM backend: {llm.info()}", ""] + reg.status()
        return {"ok": True, "text": "\n".join(lines)}

    if cmd == "cyclic":
        reg = build_registry(__file__)
        if opts.get("find"):
            return {"ok": True, "text": reg.get("cyclic_offset").run(value=opts["find"]).data}
        return {"ok": True, "text": reg.get("cyclic").run(length=int(opts.get("length", 200))).data}

    if cmd == "shellcode":
        return {"ok": True, "text": gen_shellcode(arch=opts.get("arch", "amd64"),
                                                  kind=opts.get("kind", "sh"),
                                                  arg=opts.get("arg") or None)}

    # everything else needs a real binary
    if not binary or not os.path.exists(binary):
        return {"ok": False, "text": f"error: binary not found: {binary!r}"}
    reg = _reg(binary)

    if cmd == "checksec":
        return {"ok": True, "text": _tool_text(reg, "r2_checksec") + "\n\n" + _tool_text(reg, "r2_hardening")}
    if cmd == "dashboard":
        cs = reg.get("r2_checksec").run()
        m = cs.meta if cs.ok else {}
        def onoff(v):
            return str(v).lower() in ("true", "1")
        hard_txt = _tool_text(reg, "r2_hardening")
        def hd(name):
            for line in hard_txt.splitlines():
                if line.lower().startswith(name.lower()):
                    return "not detected" not in line.lower()
            return False
        relro = "unknown"
        elf_mit = reg.get("elf_mitigations")
        if elf_mit:
            r = elf_mit.run()
            if r.ok:
                mm = __import__("re").search(r"RELRO:\s*(\w+)", r.data)
                if mm:
                    relro = mm.group(1)
        info = reg.get("r2_info").run().data if reg.get("r2_info") else ""
        fmt = "?"
        for line in info.splitlines():
            if line.strip().startswith("bintype"):
                fmt = line.split()[-1]
        store = SessionStore(config.db_path(), binary)
        run_triage(reg, binary, store=store)
        hunt = run_hunt(reg, binary, llm=None, config=config, store=store, lang=config.lang)
        findings, _ = auto_verify(reg, hunt.findings, store=store)
        by_sev = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
        verified = 0
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            if f.verdict == "verified":
                verified += 1
        sinks = []
        st = reg.get("r2_sinks").run()
        if st.ok:
            sinks = st.meta.get("sinks", [])
        funcs = 0
        fr = reg.get("r2_functions").run()
        if fr.ok:
            funcs = len([l for l in fr.data.splitlines() if l.strip() and l.strip()[0] == "0"])
        store.close()
        data = {
            "arch": m.get("arch", "?"), "bits": m.get("bits", "?"), "format": fmt,
            "mitigations": {
                "NX": onoff(m.get("nx")), "PIE": onoff(m.get("pic")),
                "Canary": onoff(m.get("canary")), "RELRO": relro,
                "FORTIFY": hd("FORTIFY"), "ASan": hd("AddressSanitizer"),
                "CFI": hd("CFI"), "SafeStack": hd("SafeStack"),
            },
            "findings": {"total": len(findings), "verified": verified, "by_sev": by_sev},
            "sinks": sinks, "functions": funcs,
        }
        return {"ok": True, "data": data}
    if cmd == "gadgets":
        return {"ok": True, "text": _tool_text(reg, "r2_rop", filter=opts.get("filter") or None)}
    if cmd == "vtables":
        return {"ok": True, "text": _tool_text(reg, "r2_vtables")}
    if cmd == "heap":
        return {"ok": True, "text": _tool_text(reg, "r2_heap")}
    if cmd == "disasm":
        return {"ok": True, "text": _tool_text(reg, "r2_disasm", target=opts.get("target", "main"))}
    if cmd == "rop":
        return {"ok": True, "text": build_rop_chain(binary, goal=opts.get("goal", "auto"),
                                                    libc_path=opts.get("libc") or None)}
    if cmd == "fmtstring":
        off = opts.get("offset")
        return {"ok": True, "text": fmtstring_help(offset=int(off) if off else None,
                                                   target_addr=opts.get("addr") or None,
                                                   value=opts.get("value") or None)}
    if cmd == "fuzz":
        return {"ok": True, "text": generate_fuzz(binary, target_func=opts.get("func") or None,
                                                  mode=opts.get("mode", "afl"))}
    if cmd == "skeleton":
        off = opts.get("offset")
        return {"ok": True, "text": generate_skeleton(reg, binary,
                                                      offset=int(off) if off else None)}
    if cmd == "verify":
        addr = opts.get("reach")
        if not addr:
            return {"ok": False, "text": "indica una direccion en 'reach' (0x...)"}
        reachable, _i, ev = verify_address(reg, addr)
        return {"ok": True, "text": ("REACHABLE\n" if reachable else "no probada\n") + ev}
    if cmd == "primitives":
        store = SessionStore(config.db_path(), binary)
        llm = make_backend(config) if opts.get("ai") else None
        res = run_primitives(reg, binary, llm=llm, config=config, store=store)
        store.close()
        return {"ok": True, "text": res.answer}

    if cmd in ("triage", "hunt", "report"):
        store = SessionStore(config.db_path(), binary)
        report = run_triage(reg, binary, store=store)
        findings = []
        answer = ""
        ledger = None
        if cmd in ("hunt", "report"):
            hunt = run_hunt(reg, binary, llm=None, config=config, store=store, lang=config.lang)
            findings, _ = auto_verify(reg, hunt.findings, store=store)
            ledger = hunt.ledger
            answer = hunt.answer
            if opts.get("ai"):
                llm = make_backend(config)
                if llm.available() and findings:
                    findings = enrich_findings(llm, findings, lang=config.lang)
                    mit = next((t for (ti, sr, t) in report.sections if "checksec" in (sr+ti).lower()), "")
                    s = executive_summary(llm, binary, findings, mitigations=mit, lang=config.lang)
                    if s:
                        answer = s
        # build a ledger from triage if none
        if ledger is None:
            from .agent.grounding import GroundingLedger
            ledger = GroundingLedger()
            for i, (ti, sr, tx) in enumerate(report.sections, 1):
                ledger.record(i, ti, sr, tx)
        html = render_html(binary, triage=report, findings=findings, ledger=ledger,
                           answer=answer, lang=config.lang)
        store.close()
        return {"ok": True, "html": html, "text": f"{len(findings)} finding(s). Report rendered below."}

    return {"ok": False, "text": f"unknown command: {cmd}"}




def save_upload(payload: dict) -> dict:
    import base64, os, tempfile
    name = os.path.basename(payload.get("filename", "upload.bin")) or "upload.bin"
    try:
        data = base64.b64decode(payload.get("b64", ""))
    except Exception as e:
        return {"ok": False, "text": f"bad upload: {e}"}
    d = tempfile.mkdtemp(prefix="binoracle_up_")
    path = os.path.join(d, name)
    with open(path, "wb") as f:
        f.write(data)
    try:
        os.chmod(path, 0o755)
    except OSError:
        pass
    # if a C/C++ source was uploaded, compile it so the dashboard can analyze it
    ext = os.path.splitext(name)[1].lower()
    if ext in (".c", ".cc", ".cpp", ".cxx"):
        return _compile_source(d, name, path, ext)
    return {"ok": True, "path": path, "size": len(data)}


def _compile_source(d, name, path, ext):
    import os, shutil, subprocess
    is_cpp = ext != ".c"
    out_bin = os.path.join(d, os.path.splitext(name)[0])
    flags = ["-fno-stack-protector", "-no-pie", "-w", "-o", out_bin]
    # 1) local compiler (fast, matches host arch)
    comp = (shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")) if is_cpp \
           else (shutil.which("cc") or shutil.which("gcc") or shutil.which("clang"))
    local_err = ""
    if comp:
        r = subprocess.run([comp, *flags, path], capture_output=True, text=True)
        if r.returncode == 0 and os.path.exists(out_bin):
            return {"ok": True, "path": out_bin, "size": os.path.getsize(out_bin),
                    "compiled": True, "how": "local"}
        local_err = r.stderr
    # 2) Docker x86-64 fallback (for Linux/x86-64 sources, e.g. inline asm on an arm64 host)
    docker = shutil.which("docker")
    if docker:
        cc = "g++" if is_cpp else "gcc"
        try:
            up = subprocess.run(
                [docker, "run", "--rm", "--platform", "linux/amd64", "-v", d + ":/w", "-w", "/w",
                 "gcc:13", "bash", "-c",
                 f"{cc} -fno-stack-protector -no-pie -w -o /w/{os.path.basename(out_bin)} /w/{name}"],
                capture_output=True, text=True, timeout=180)
            if up.returncode == 0 and os.path.exists(out_bin):
                return {"ok": True, "path": out_bin, "size": os.path.getsize(out_bin),
                        "compiled": True, "how": "docker/linux-amd64"}
            docker_err = up.stderr or up.stdout
        except Exception as e:
            docker_err = str(e)
        return {"ok": False, "text": "compilation failed.\n\n[local]\n" + (local_err or "(no local compiler)") +
                "\n\n[docker x86-64]\n" + docker_err}
    return {"ok": False, "text": ("compilation failed and Docker is not available for an "
            "x86-64 fallback.\n\n[local]\n" + (local_err or "(no local compiler on PATH)"))}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, INDEX_HTML)
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        if self.path not in ("/api/run", "/api/upload"):
            self._send(404, "not found", "text/plain")
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
            result = save_upload(payload) if self.path == "/api/upload" else run_command(payload)
        except Exception as e:
            result = {"ok": False, "text": f"error: {e}"}
        self._send(200, json.dumps(result), "application/json")


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True):
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}"
    print(f"binoracle web UI on {url}  (Ctrl-C to stop)")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: bound to a non-localhost address with NO authentication. This server "
              "compiles uploaded code, analyzes binaries and can execute them. Only expose it on "
              "a trusted network; never on the public internet.")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
        httpd.shutdown()


INDEX_HTML = r"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>binoracle</title>
<style>
:root{--bg:#0a0e14;--panel:#111722;--panel2:#0e131c;--fg:#e2e8f0;--mut:#7b8794;--line:#1e2632;--acc:#2ee6a6;--acc2:#4aa3ff;--code:#070a10;--codefg:#a9c7e8;--field:#0b0e12;--crit:#e5484d;--high:#f76808;--med:#f5b800;--low:#30a46c;--info:#5b8def}
:root[data-theme=light]{--bg:#f4f6f9;--panel:#fff;--panel2:#f0f2f5;--fg:#0f1720;--mut:#64707d;--line:#e4e8ee;--acc:#0d9f6e;--acc2:#2f6feb;--code:#0d1117;--codefg:#a9c7e8;--field:#ffffff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;height:100vh;display:flex;flex-direction:column;overflow:hidden}
header{display:flex;align-items:center;gap:14px;padding:11px 18px;border-bottom:1px solid var(--line);background:linear-gradient(180deg,var(--panel),var(--panel2))}
.brand{display:flex;align-items:center;gap:9px;font-weight:800;letter-spacing:.3px}
.brand .tag{font-weight:400;color:var(--mut);font:12px ui-monospace,monospace}
.dot{width:11px;height:11px;border-radius:50%;background:var(--acc);box-shadow:0 0 12px var(--acc),0 0 4px var(--acc)}
.prompt{flex:1;display:flex;align-items:center;gap:8px;background:var(--field);border:1px solid var(--line);border-radius:9px;padding:0 12px;min-width:180px}
.prompt span{color:var(--acc);font:13px ui-monospace,monospace}
#target{flex:1;background:none;border:none;color:var(--fg);padding:9px 0;font-family:ui-monospace,monospace;outline:none}
.aitoggle{display:flex;align-items:center;gap:6px;color:var(--mut);font:12px ui-monospace,monospace;padding:0 6px;user-select:none}
.aitoggle input{accent-color:var(--acc)}
.go{background:linear-gradient(135deg,var(--acc),#1fbf8a);color:#04120c;border:none;border-radius:9px;padding:9px 16px;font-weight:700;cursor:pointer}
.go:hover{filter:brightness(1.08)}
.icon-btn{background:var(--field);border:1px solid var(--line);color:var(--fg);border-radius:9px;width:38px;height:36px;cursor:pointer;font-size:15px}
main{flex:1;display:flex;min-height:0}
.side{width:210px;border-right:1px solid var(--line);background:var(--panel2);overflow:auto;padding:8px 8px 20px}
.side .grp{color:var(--mut);font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;padding:12px 12px 4px}
.side button{display:flex;align-items:center;gap:10px;width:100%;text-align:left;background:none;border:none;color:var(--fg);padding:8px 11px;border-radius:8px;cursor:pointer;font-size:13px;border-left:2px solid transparent}
.side button .ic{width:18px;text-align:center;color:var(--mut);font-size:13px}
.side button:hover{background:var(--panel)}
.side button.active{background:var(--panel);border-left-color:var(--acc);color:var(--acc)}
.side button.active .ic{color:var(--acc)}
.work{flex:1;display:flex;flex-direction:column;min-width:0}
.opts{padding:11px 18px;border-bottom:1px solid var(--line);display:flex;gap:12px;flex-wrap:wrap;align-items:end;background:var(--panel2);min-height:0}
.opts:empty{display:none}
.f{display:flex;flex-direction:column;gap:3px}
.f label{font-size:10px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
.f input,.f select{background:var(--field);border:1px solid var(--line);color:var(--fg);border-radius:7px;padding:7px 10px;min-width:120px;font-family:ui-monospace,monospace}
.run{background:linear-gradient(135deg,var(--acc2),#3b8ee0);color:#fff;border:none;border-radius:8px;padding:9px 18px;cursor:pointer;font-weight:700}
.chk{display:flex;align-items:center;gap:6px}
.out{flex:1;overflow:auto;padding:20px}
iframe{width:100%;height:100%;border:0;background:#fff;border-radius:10px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}
.grid{display:grid;gap:16px}
.kpis{grid-template-columns:repeat(4,1fr)}
.kpi{position:relative;overflow:hidden}
.kpi .v{font-size:34px;font-weight:800;line-height:1}
.kpi .l{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.05em;margin-top:6px}
.kpi .bar{position:absolute;left:0;bottom:0;height:3px;width:100%;background:var(--acc)}
.row2{grid-template-columns:1fr 1fr}
.row3{grid-template-columns:1.1fr 1fr 1fr}
h3{margin:0 0 14px;font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.06em}
.mit-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:9px}
.mit{display:flex;justify-content:space-between;align-items:center;border:1px solid var(--line);border-radius:9px;padding:9px 12px;background:var(--panel2)}
.mit .k{font-size:12px;color:var(--mut)}
.mit .b{font-weight:800;font-size:12px;padding:2px 9px;border-radius:20px}
.b.ok{background:rgba(48,163,108,.16);color:#37d391}
.b.bad{background:rgba(229,72,77,.16);color:#ff6b70}
.b.warn{background:rgba(245,184,0,.16);color:#ffcb2e}
.b.mut{background:rgba(123,135,148,.16);color:var(--mut)}
.chips{display:flex;flex-wrap:wrap;gap:7px}
.chip{background:var(--code);border:1px solid var(--line);border-radius:7px;padding:5px 10px;font:12px ui-monospace,monospace;color:var(--codefg)}
.legend{display:flex;flex-direction:column;gap:7px;justify-content:center}
.legend div{display:flex;align-items:center;gap:8px;font-size:12px}
.legend i{width:10px;height:10px;border-radius:3px}
.qa{display:flex;flex-wrap:wrap;gap:10px;margin-top:2px}
.qa button{background:var(--panel2);border:1px solid var(--line);color:var(--fg);border-radius:9px;padding:9px 14px;cursor:pointer;font-weight:600;display:flex;gap:7px;align-items:center}
.qa button:hover{border-color:var(--acc)}
.console{background:var(--code);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.console .bar{display:flex;align-items:center;gap:8px;padding:9px 14px;border-bottom:1px solid var(--line);color:var(--mut);font:12px ui-monospace,monospace}
.console .bar .d{width:9px;height:9px;border-radius:50%}
.console pre{margin:0;padding:16px;font:12.5px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--codefg);white-space:pre-wrap;word-break:break-word}
.empty{height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;color:var(--mut);gap:14px;text-align:center}
.empty .big{font:700 40px ui-monospace,monospace;color:var(--acc);letter-spacing:2px;opacity:.8}
.spin{color:var(--acc2)}
footer{border-top:1px solid var(--line);background:var(--panel2);padding:6px 18px;display:flex;gap:10px;align-items:center;font:11px ui-monospace,monospace;color:var(--mut);flex-wrap:wrap}
.pill{padding:2px 9px;border-radius:20px;border:1px solid var(--line)}
.pill.on{color:#37d391;border-color:rgba(48,163,108,.4)}
.pill.off{color:var(--mut)}
</style></head>
<body>
<header>
  <div class="brand"><span class="dot"></span>binoracle<span class="tag">// local binary RE + exploitation</span></div>
  <div class="prompt"><span>&#10095;</span><input id="target" placeholder="ruta al binario  o  fuente.c" spellcheck="false"></div>
  <label class="aitoggle"><input type="checkbox" id="aiGlobal" checked>IA</label><button class="go" onclick="dash()">Analizar</button>
  <input type="file" id="file" style="display:none"><button class="icon-btn" id="attach" title="adjuntar binario">+</button><button class="icon-btn" onclick="toggleTheme()" title="tema">&#9681;</button>
</header>
<main>
  <nav class="side" id="side"></nav>
  <section class="work">
    <div class="opts" id="opts"></div>
    <div class="out" id="out"></div>
  </section>
</main>
<footer id="footer"><span class="pill off">oracles: --</span></footer>
<script>
const SEVC={critical:'#e5484d',high:'#f76808',medium:'#f5b800',low:'#30a46c',info:'#5b8def'};
const CMDS=[
 {g:"Panel"},
 {c:"dashboard",n:"Dashboard",ic:"#"},
 {c:"report",n:"Informe completo",ic:"="},
 {g:"Analisis"},
 {c:"triage",n:"Triage",ic:">"},
 {c:"hunt",n:"Hunt",ic:"*"},
 {c:"primitives",n:"Primitivas",ic:"%"},
 {c:"checksec",n:"Checksec + hardening",ic:"!"},
 {c:"disasm",n:"Disasm",ic:"~",opts:[{k:"target",t:"text",label:"funcion",def:"main"}]},
 {c:"gadgets",n:"Gadgets ROP",ic:"+",opts:[{k:"filter",t:"text",label:"filtro (pop rdi)"}]},
 {c:"vtables",n:"C++ / vtables",ic:"^"},
 {c:"heap",n:"Heap surface",ic:":"},
 {g:"Explotacion"},
 {c:"rop",n:"Cadena ROP",ic:"&",opts:[{k:"goal",t:"sel",label:"goal",vals:["auto","system","execve","ret2libc","syscall"]},{k:"libc",t:"text",label:"libc"}]},
 {c:"shellcode",n:"Shellcode",ic:"$",nobin:true,opts:[{k:"arch",t:"sel",label:"arch",vals:["amd64","i386","aarch64","arm"]},{k:"kind",t:"sel",label:"kind",vals:["sh","cat","execve"]},{k:"arg",t:"text",label:"arg"}]},
 {c:"fmtstring",n:"Format-string",ic:"%",opts:[{k:"offset",t:"text",label:"offset"},{k:"addr",t:"text",label:"addr"},{k:"value",t:"text",label:"value"}]},
 {c:"fuzz",n:"Fuzz harness",ic:"~",opts:[{k:"mode",t:"sel",label:"mode",vals:["afl","libfuzzer"]},{k:"func",t:"text",label:"func"}]},
 {c:"skeleton",n:"Exploit skeleton",ic:"|",opts:[{k:"offset",t:"text",label:"offset"}]},
 {c:"verify",n:"Verify reachability",ic:"?",opts:[{k:"reach",t:"text",label:"addr 0x.."}]},
 {g:"Utiles"},
 {c:"cyclic",n:"Cyclic / offset",ic:"@",nobin:true,opts:[{k:"length",t:"text",label:"length",def:"200"},{k:"find",t:"text",label:"find 0x.."}]},
 {c:"doctor",n:"Doctor",ic:"+",nobin:true},
];
const side=document.getElementById('side');
CMDS.forEach(it=>{ if(it.g){const d=document.createElement('div');d.className='grp';d.textContent=it.g;side.appendChild(d);return;}
 const b=document.createElement('button');b.innerHTML='<span class="ic">'+it.ic+'</span>'+it.n;b.onclick=()=>select(it,b);side.appendChild(b);});
let current=null;
function select(it,btn){current=it;[...side.querySelectorAll('button')].forEach(x=>x.classList.remove('active'));btn.classList.add('active');
 const opts=document.getElementById('opts');opts.innerHTML='';
 (it.opts||[]).forEach(o=>{const f=document.createElement('div');f.className='f';const lab=document.createElement('label');lab.textContent=o.label;let el;
  if(o.t==='sel'){el=document.createElement('select');o.vals.forEach(v=>{const op=document.createElement('option');op.value=v;op.textContent=v;el.appendChild(op);});}
  else if(o.t==='check'){f.className='f chk';el=document.createElement('input');el.type='checkbox';}
  else{el=document.createElement('input');el.type='text';if(o.def)el.value=o.def;}
  el.id='opt_'+o.k; if(o.t==='check'){f.appendChild(el);f.appendChild(lab);}else{f.appendChild(lab);f.appendChild(el);} opts.appendChild(f);});
 const run=document.createElement('button');run.className='run';run.textContent='Ejecutar';run.onclick=()=>exec(it.c,collect());opts.appendChild(run);
 if(it.c==='dashboard') dash();
}
function collect(){const o={};(current.opts||[]).forEach(x=>{const el=document.getElementById('opt_'+x.k);o[x.k]=x.t==='check'?el.checked:el.value;});return o;}
async function api(command,options){const binary=document.getElementById('target').value.trim();
 var g=document.getElementById('aiGlobal');var ai=g?g.checked:false;var opt=Object.assign({ai:ai},options||{});
 const r=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({command,binary,options:opt})});return r.json();}
async function exec(command,options){const out=document.getElementById('out');out.innerHTML='<div class="empty"><div class="spin">ejecutando '+command+'...</div></div>';
 const j=await api(command,options);
 if(j.data){renderDash(j.data);return;}
 if(j.html){out.innerHTML='';const ifr=document.createElement('iframe');out.appendChild(ifr);ifr.srcdoc=j.html;return;}
 out.innerHTML='';const box=document.createElement('div');box.className='console';
 box.innerHTML='<div class="bar"><span class="d" style="background:'+(j.ok?'#30a46c':'#e5484d')+'"></span>'+command+'</div>';
 const pre=document.createElement('pre');pre.textContent=j.text||'(sin salida)';box.appendChild(pre);out.appendChild(box);
}
async function dash(){const out=document.getElementById('out');const bin=document.getElementById('target').value.trim();
 if(!bin){out.innerHTML='<div class="empty"><div class="big">&#10095;_</div><div>Pon la ruta de un binario arriba y pulsa Analizar</div></div>';return;}
 out.innerHTML='<div class="empty"><div class="spin">analizando '+bin.split('/').pop()+'...</div></div>';
 const j=await api('dashboard',{});if(j.data)renderDash(j.data);else out.innerHTML='<div class="console"><pre>'+(j.text||'error')+'</pre></div>';
}
function donut(bySev,total){const r=52,c=2*Math.PI*r;let off=0;let segs='';
 ['critical','high','medium','low','info'].forEach(k=>{const v=bySev[k]||0;if(!v)return;const frac=v/total;const len=frac*c;
  segs+='<circle cx="70" cy="70" r="'+r+'" fill="none" stroke="'+SEVC[k]+'" stroke-width="16" stroke-dasharray="'+len+' '+(c-len)+'" stroke-dashoffset="'+(-off)+'" transform="rotate(-90 70 70)"/>';off+=len;});
 if(total===0)segs='<circle cx="70" cy="70" r="'+r+'" fill="none" stroke="var(--line)" stroke-width="16"/>';
 return '<svg width="140" height="140" viewBox="0 0 140 140">'+segs+'<text x="70" y="66" text-anchor="middle" font-size="30" font-weight="800" fill="var(--fg)">'+total+'</text><text x="70" y="86" text-anchor="middle" font-size="10" fill="var(--mut)">HALLAZGOS</text></svg>';
}
function gauge(score){const a=Math.PI*(score/100);const cx=90,cy=90,r=70;const x=cx-r*Math.cos(a),y=cy-r*Math.sin(a);
 const col=score<30?'#30a46c':score<60?'#f5b800':'#e5484d';const big=0;
 const bg='<path d="M20 90 A70 70 0 0 1 160 90" fill="none" stroke="var(--line)" stroke-width="14" stroke-linecap="round"/>';
 const fg='<path d="M20 90 A70 70 0 0 1 '+x.toFixed(1)+' '+y.toFixed(1)+'" fill="none" stroke="'+col+'" stroke-width="14" stroke-linecap="round"/>';
 return '<svg width="180" height="104" viewBox="0 0 180 104">'+bg+fg+'<text x="90" y="82" text-anchor="middle" font-size="30" font-weight="800" fill="'+col+'">'+score+'</text><text x="90" y="99" text-anchor="middle" font-size="10" fill="var(--mut)">EXPLOTABILIDAD</text></svg>';
}
function mitChip(k,v){let cls,txt;if(k==='RELRO'){txt=String(v).toUpperCase();cls=v==='Full'?'ok':(v==='Partial'?'warn':'bad');}
 else if(typeof v==='boolean'){const good=(k==='NX'||k==='PIE'||k==='Canary'||k==='FORTIFY'||k==='CFI'||k==='SafeStack')?v:!v;txt=v?'ON':'OFF';cls=good?'ok':'bad';}
 else{txt=String(v);cls='mut';}
 return '<div class="mit"><span class="k">'+k+'</span><span class="b '+cls+'">'+txt+'</span></div>';}
function renderDash(d){const out=document.getElementById('out');const s=d.findings.by_sev;const m=d.mitigations;
 let score=Math.min(100,(d.sinks.length*8)+(m.NX?0:20)+(m.Canary?0:15)+(m.PIE?0:10)+(m.RELRO==='Full'?0:5)+(d.findings.verified*10));
 const leg=['critical','high','medium','low','info'].map(k=>'<div><i style="background:'+SEVC[k]+'"></i>'+k+' <b style="margin-left:auto">'+(s[k]||0)+'</b></div>').join('');
 out.innerHTML=
 '<div class="grid kpis" style="margin-bottom:16px">'
 +kpi(d.findings.total,'hallazgos','var(--acc2)')
 +kpi(d.findings.verified,'verificados','var(--acc)')
 +kpi((s.critical+s.high),'severidad alta','var(--high)')
 +kpi(d.sinks.length,'sinks peligrosos','var(--med)')
 +'</div>'
 +'<div class="grid row3" style="margin-bottom:16px">'
 +'<div class="card"><h3>Distribucion por severidad</h3><div style="display:flex;gap:18px;align-items:center">'+donut(s,d.findings.total)+'<div class="legend" style="flex:1">'+leg+'</div></div></div>'
 +'<div class="card"><h3>Explotabilidad</h3><div style="display:flex;justify-content:center;padding-top:6px">'+gauge(score)+'</div></div>'
 +'<div class="card"><h3>Binario</h3><div class="chips" style="flex-direction:column;gap:8px"><div class="chip">arch: '+d.arch+' '+d.bits+'-bit</div><div class="chip">formato: '+d.format+'</div><div class="chip">funciones: '+d.functions+'</div></div></div>'
 +'</div>'
 +'<div class="grid row2" style="margin-bottom:16px">'
 +'<div class="card"><h3>Mitigaciones</h3><div class="mit-grid">'+Object.keys(m).map(k=>mitChip(k,m[k])).join('')+'</div></div>'
 +'<div class="card"><h3>Sinks peligrosos</h3><div class="chips">'+(d.sinks.length?d.sinks.map(x=>'<div class="chip">'+x+'</div>').join(''):'<span style="color:var(--mut)">ninguno</span>')+'</div>'
 +'<h3 style="margin-top:18px">Acciones</h3><div class="qa">'
 +'<button onclick="exec(\'report\',{ai:false})">Informe completo</button>'
 +'<button onclick="exec(\'rop\',{goal:\'auto\'})">Construir cadena ROP</button>'
 +'<button onclick="exec(\'gadgets\',{})">Gadgets</button>'
 +'<button onclick="exec(\'primitives\',{})">Primitivas</button>'
 +'</div></div>'
 +'</div>';
}
function kpi(v,l,c){return '<div class="card kpi"><div class="v" style="color:'+c+'">'+v+'</div><div class="l">'+l+'</div><div class="bar" style="background:'+c+'"></div></div>';}
function b64enc(buf){var bytes=new Uint8Array(buf);var bin='';var chunk=0x8000;for(var i=0;i<bytes.length;i+=chunk){bin+=String.fromCharCode.apply(null,bytes.subarray(i,i+chunk));}return btoa(bin);}
async function upload(inp){var f=inp.files[0];if(!f)return;var out=document.getElementById('out');out.innerHTML='<div class="empty"><div class="spin">subiendo '+f.name+'...</div></div>';
 var buf=await f.arrayBuffer();var b64=b64enc(buf);
 var r=await fetch('/api/upload',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename:f.name,b64:b64})});var j=await r.json();
 if(j.ok){document.getElementById('target').value=j.path;dash();}else{out.innerHTML='<div class="console"><pre>'+(j.text||'error')+'</pre></div>';}}
function toggleTheme(){const r=document.documentElement;r.setAttribute('data-theme',r.getAttribute('data-theme')==='light'?'dark':'light');}
async function loadStatus(){try{const j=await api('doctor','');const f=document.getElementById('footer');const lines=(j.text||'').split('\n');
 const pills=lines.filter(l=>l.includes('[ok]')||l.includes('[--]')).map(l=>{const on=l.includes('[ok]');const name=l.replace(/\[..\]/,'').split(':')[0].trim();return '<span class="pill '+(on?'on':'off')+'">'+name+'</span>';});
 const llm=(lines.find(l=>l.startsWith('LLM'))||'').replace('LLM backend:','LLM:').trim();
 f.innerHTML='<span class="pill">'+llm+'</span>'+pills.join('');}catch(e){}}
(function(){const dark=!window.matchMedia||window.matchMedia('(prefers-color-scheme: dark)').matches;document.documentElement.setAttribute('data-theme',dark?'dark':'light');
 document.getElementById('out').innerHTML='<div class="empty"><div class="big">&#10095;_</div><div>Pon la ruta de un binario arriba y pulsa <b>Analizar</b></div></div>';
 loadStatus();document.getElementById('target').addEventListener('keydown',e=>{if(e.key==='Enter')dash();});
 document.getElementById('attach').onclick=function(){document.getElementById('file').click();};
 document.getElementById('file').onchange=function(){upload(this);};})();
</script>
</body></html>
"""
