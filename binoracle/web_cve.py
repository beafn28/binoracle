"""CVE verification web UI for bin0racle.

`binoracle web` starts a localhost-only server on port 8000 that lets you
run CVE investigations from the browser and export reports as PDF.

No external deps — uses only Python stdlib + what binoracle already requires.
"""
from __future__ import annotations

import base64
import html as _html
import json
import os
import queue
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

# ── Job store ─────────────────────────────────────────────────────────────────

class _Job:
    __slots__ = ("id", "cve_id", "status", "logs", "result", "inv",
                 "_q", "created", "t0")

    def __init__(self, cve_id: str):
        self.id: str = uuid.uuid4().hex[:8]
        self.cve_id: str = cve_id.upper()
        self.status: str = "running"
        self.logs: list[dict] = []
        self.result: Optional[dict] = None
        self.inv = None
        self._q: queue.Queue = queue.Queue()
        self.created: float = time.time()
        self.t0: float = time.time()


_jobs: dict[str, _Job] = {}
_jobs_lock = threading.Lock()


def _start_job(cve_id: str, config) -> _Job:
    job = _Job(cve_id)
    with _jobs_lock:
        _jobs[job.id] = job

    def _run():
        from .workflows.cve_agent import investigate_cve
        job.t0 = time.time()

        def on_step(msg: str):
            entry = {"t": round(time.time() - job.t0, 1), "msg": msg}
            job.logs.append(entry)
            job._q.put(("step", entry))

        try:
            inv = investigate_cve(
                job.cve_id,
                config=config,
                on_step=on_step,
                budget_s=600,
            )
            job.inv = inv
            job.status = "done"
            # Collect evidence for the UI
            ve = getattr(inv, "verified_evidence", None) or {}
            wp_res = getattr(inv, "wp_result", None)
            evidence = {}
            if wp_res and hasattr(wp_res, "evidence"):
                evidence = dict(wp_res.evidence or {})
            job.result = {
                "verified": inv.verified,
                "cve_id": job.cve_id,
                "detail": getattr(inv, "detail", ""),
                "elapsed": round(time.time() - job.t0, 1),
                "verified_evidence": ve,
                "evidence": evidence,
                "logs": job.logs,
            }
            job._q.put(("done", job.result))
        except Exception as exc:
            job.status = "done"
            job.result = {"verified": False, "cve_id": job.cve_id,
                          "error": str(exc), "logs": job.logs}
            job._q.put(("done", job.result))

    threading.Thread(target=_run, daemon=True, name=f"cve-{job.id}").start()
    return job


# ── HTTP handler ──────────────────────────────────────────────────────────────

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


class _Handler(BaseHTTPRequestHandler):
    config = None  # set by serve()

    def log_message(self, fmt, *args):  # silence stdlib access log
        pass

    def do_GET(self):
        p = urlparse(self.path)
        path = p.path.rstrip("/") or "/"

        if path == "/":
            self._serve_html()
        elif path == "/static/logo.png":
            self._serve_logo()
        elif path.startswith("/api/stream/"):
            job_id = path.split("/")[-1]
            self._sse(job_id)
        elif path.startswith("/api/result/"):
            job_id = path.split("/")[-1]
            self._json_result(job_id)
        elif path.startswith("/api/screenshot/"):
            b64 = path.split("/")[-1]
            self._serve_screenshot(b64)
        else:
            self._404()

    def do_POST(self):
        p = urlparse(self.path)
        if p.path == "/api/run":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            cve_id = str(data.get("cve_id", "")).strip()
            if not cve_id:
                self._send_json(400, {"error": "cve_id required"})
                return
            job = _start_job(cve_id, self.__class__.config)
            self._send_json(200, {"job_id": job.id, "cve_id": job.cve_id})
        else:
            self._404()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # ── routes ────────────────────────────────────────────────────────────────

    def _serve_logo(self):
        logo_path = os.path.join(_STATIC_DIR, "logo.png")
        if os.path.isfile(logo_path):
            with open(logo_path, "rb") as fh:
                data = fh.read()
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            # SVG placeholder crystal ball
            svg = _LOGO_SVG.encode()
            self.send_response(200)
            self.send_header("Content-Type", "image/svg+xml")
            self.send_header("Content-Length", str(len(svg)))
            self.end_headers()
            self.wfile.write(svg)

    def _serve_screenshot(self, b64_path: str):
        try:
            path = base64.urlsafe_b64decode(b64_path + "==").decode()
            if not os.path.isabs(path) or not os.path.isfile(path):
                raise ValueError
            with open(path, "rb") as fh:
                data = fh.read()
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            self._404()

    def _sse(self, job_id: str):
        with _jobs_lock:
            job = _jobs.get(job_id)
        if not job:
            self._404()
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        # Replay already-logged steps first
        for entry in list(job.logs):
            self._write_sse("step", entry)

        if job.status == "done" and job.result:
            self._write_sse("done", job.result)
            return

        # Stream new events
        while True:
            try:
                kind, payload = job._q.get(timeout=25)
                self._write_sse(kind, payload)
                if kind == "done":
                    break
            except queue.Empty:
                # heartbeat
                try:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                except Exception:
                    break
            except Exception:
                break

    def _write_sse(self, event: str, data):
        try:
            payload = json.dumps(data, ensure_ascii=False)
            msg = f"event: {event}\ndata: {payload}\n\n".encode()
            self.wfile.write(msg)
            self.wfile.flush()
        except Exception:
            pass

    def _json_result(self, job_id: str):
        with _jobs_lock:
            job = _jobs.get(job_id)
        if not job:
            self._send_json(404, {"error": "not found"})
            return
        if job.status != "done" or not job.result:
            self._send_json(202, {"status": "running"})
            return
        self._send_json(200, job.result)

    def _send_json(self, code: int, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _404(self):
        self.send_response(404)
        self.end_headers()

    def _serve_html(self):
        body = _HTML_PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ── Entry point ───────────────────────────────────────────────────────────────

def serve(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True,
          config=None):
    _Handler.config = config
    server = ThreadingHTTPServer((host, port), _Handler)
    url = f"http://{host}:{port}"
    print(f"\n  bin\033[1;33m0\033[0mracle CVE Lab → \033[1;96m{url}\033[0m")
    print("  Ctrl+C to stop.\n")
    if open_browser:
        import webbrowser
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")


# ── SVG placeholder logo ──────────────────────────────────────────────────────

_LOGO_SVG = """\
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 220" width="200" height="220">
  <rect width="200" height="220" fill="#0a0b10"/>
  <!-- base -->
  <ellipse cx="100" cy="192" rx="52" ry="10" fill="none" stroke="#00d4ff" stroke-width="1.5"/>
  <rect x="80" y="182" width="40" height="12" rx="4" fill="none" stroke="#00d4ff" stroke-width="1.5"/>
  <!-- glow circle -->
  <circle cx="100" cy="95" r="72" fill="none" stroke="#00d4ff" stroke-width="1.2" opacity="0.3"/>
  <!-- main circle -->
  <circle cx="100" cy="95" r="68" fill="#0d1520" stroke="#00d4ff" stroke-width="2.2"/>
  <!-- inner shine -->
  <ellipse cx="84" cy="62" rx="22" ry="12" fill="white" opacity="0.06"/>
  <!-- binary / hex values -->
  <text x="42"  y="78"  font-family="monospace" font-size="13" fill="#00d4ff">1001</text>
  <text x="110" y="78"  font-family="monospace" font-size="13" fill="#ff9e2c">0xE9</text>
  <text x="48"  y="98"  font-family="monospace" font-size="13" fill="#00d4ff">0110</text>
  <text x="108" y="98"  font-family="monospace" font-size="13" fill="#00d4ff">1011</text>
  <text x="44"  y="118" font-family="monospace" font-size="13" fill="#ff9e2c" font-weight="bold">RCE</text>
  <text x="108" y="118" font-family="monospace" font-size="13" fill="#00d4ff">0101</text>
  <text x="48"  y="138" font-family="monospace" font-size="13" fill="#00d4ff">1100</text>
  <text x="108" y="138" font-family="monospace" font-size="13" fill="#ff9e2c">0x90</text>
  <!-- dot -->
  <circle cx="100" cy="52" r="4" fill="white" opacity="0.7"/>
  <!-- label -->
  <text x="100" y="212" font-family="monospace" font-size="14" fill="white"
        text-anchor="middle" font-weight="bold"
  >bin<tspan fill="#ff9e2c">0</tspan>racle</text>
</svg>"""


# ── HTML page ─────────────────────────────────────────────────────────────────

_HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>bin0racle CVE Lab</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet"
  href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Inter:wght@400;500;600&display=swap">
<style>
:root {
  --bg:     #0a0b10;
  --bg2:    #111420;
  --bg3:    #181c2a;
  --border: #1e2538;
  --cyan:   #00d4ff;
  --orange: #ff9e2c;
  --green:  #00e676;
  --red:    #ff5252;
  --yellow: #ffd740;
  --text:   #d0d8f0;
  --dim:    #6070a0;
  --mono:   'Fira Code', monospace;
  --sans:   'Inter', system-ui, sans-serif;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html, body { height: 100%; background: var(--bg); color: var(--text); font-family: var(--sans); font-size: 14px; }

/* scrollbar */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg2); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

/* ── layout ── */
#app { display: flex; flex-direction: column; height: 100vh; overflow: hidden; }

header {
  display: flex; align-items: center; gap: 14px;
  padding: 12px max(16px,env(safe-area-inset-left,0px));
  background: var(--bg2); border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}
header img { width: 44px; height: 44px; object-fit: contain; }
.h-title { font-family: var(--mono); font-size: 18px; font-weight: 600; letter-spacing: .04em; }
.h-title .o { color: var(--orange); }
.h-sub  { font-size: 11px; color: var(--dim); margin-top: 2px; letter-spacing: .05em; }

main {
  flex: 1; overflow: hidden; display: flex; flex-direction: column;
  padding: 16px max(16px,env(safe-area-inset-left,0px));
  gap: 12px;
}

/* ── run panel ── */
.run-panel {
  display: flex; gap: 8px; align-items: center; flex-shrink: 0;
}
#cve-input {
  flex: 1; max-width: 340px;
  background: var(--bg3); border: 1px solid var(--border);
  border-radius: 6px; color: var(--text);
  font-family: var(--mono); font-size: 14px; padding: 8px 12px;
  outline: none; transition: border .15s;
}
#cve-input:focus { border-color: var(--cyan); }
#cve-input::placeholder { color: var(--dim); }
#run-btn {
  background: var(--cyan); color: #000; border: none; border-radius: 6px;
  font-family: var(--sans); font-weight: 600; font-size: 13px;
  padding: 8px 18px; cursor: pointer; transition: opacity .15s, transform .1s;
  white-space: nowrap;
}
#run-btn:hover { opacity: .88; }
#run-btn:active { transform: scale(.97); }
#run-btn:disabled { opacity: .4; cursor: not-allowed; }
#status-badge {
  font-family: var(--mono); font-size: 12px; padding: 4px 10px;
  border-radius: 4px; display: none;
}
.badge-running { background: rgba(0,212,255,.12); color: var(--cyan); border: 1px solid rgba(0,212,255,.3); }
.badge-done-ok { background: rgba(0,230,118,.12); color: var(--green); border: 1px solid rgba(0,230,118,.3); }
.badge-done-fail { background: rgba(255,210,0,.1); color: var(--yellow); border: 1px solid rgba(255,210,0,.2); }

/* ── verdict ── */
#verdict {
  display: none; border-radius: 6px; padding: 10px 16px;
  font-family: var(--mono); font-size: 15px; font-weight: 600;
  letter-spacing: .06em; flex-shrink: 0;
}
.verdict-ok   { background: rgba(0,230,118,.12); color: var(--green); border: 1px solid rgba(0,230,118,.3); }
.verdict-fail { background: rgba(255,210,0,.08); color: var(--yellow); border: 1px solid rgba(255,210,0,.18); }

/* ── tabs ── */
.tabs-wrap { flex: 1; display: flex; flex-direction: column; overflow: hidden; min-height: 0; }
.tab-bar {
  display: flex; gap: 2px; padding-bottom: 0;
  border-bottom: 1px solid var(--border); flex-shrink: 0;
}
.tab-btn {
  background: none; border: none; color: var(--dim);
  font-family: var(--sans); font-size: 13px; font-weight: 500;
  padding: 7px 14px; cursor: pointer; border-bottom: 2px solid transparent;
  margin-bottom: -1px; transition: color .15s, border-color .15s;
}
.tab-btn:hover { color: var(--text); }
.tab-btn.active { color: var(--cyan); border-bottom-color: var(--cyan); }
.tab-pane { display: none; flex: 1; overflow-y: auto; padding: 12px 0; }
.tab-pane.active { display: flex; flex-direction: column; }

/* ── log terminal ── */
#log-terminal {
  flex: 1; overflow-y: auto; overflow-x: hidden;
  font-family: var(--mono); font-size: 12.5px; line-height: 1.65;
  background: var(--bg3); border: 1px solid var(--border); border-radius: 6px;
  padding: 10px 14px;
}
.log-line { display: flex; gap: 10px; }
.log-t    { color: var(--dim); min-width: 54px; flex-shrink: 0; }
.log-ok   { color: var(--green); }
.log-warn { color: var(--yellow); }
.log-err  { color: var(--red); }
.log-info { color: var(--text); }
.log-sep  { color: var(--cyan); opacity: .6; letter-spacing: .2em; }

/* ── evidence cards ── */
.evidence-grid { display: flex; flex-direction: column; gap: 8px; }
.ev-card {
  background: var(--bg3); border: 1px solid var(--border); border-radius: 6px;
  overflow: hidden;
}
.ev-card-head {
  padding: 8px 12px; background: rgba(255,255,255,.03);
  font-size: 11px; font-weight: 600; letter-spacing: .08em; color: var(--dim);
  text-transform: uppercase;
}
.ev-card-body { padding: 10px 12px; font-family: var(--mono); font-size: 12px; }
.ev-val { color: var(--cyan); word-break: break-all; }

/* ── http requests ── */
.http-entry { margin-bottom: 10px; }
.http-line {
  font-family: var(--mono); font-size: 12px; padding: 4px 10px;
  background: var(--bg3); border: 1px solid var(--border); border-radius: 4px;
  color: var(--text); white-space: pre-wrap; word-break: break-all;
}
.http-method { color: var(--orange); font-weight: 600; }
.http-status-2 { color: var(--green); }
.http-status-4, .http-status-5 { color: var(--red); }

/* ── screenshots ── */
.shots-grid { display: flex; flex-direction: column; gap: 12px; }
.shot-wrap {
  border: 1px solid var(--border); border-radius: 6px; overflow: hidden;
}
.shot-label {
  padding: 6px 12px; background: rgba(255,255,255,.03);
  font-size: 11px; color: var(--dim); letter-spacing: .06em; text-transform: uppercase;
}
.shot-wrap img { width: 100%; display: block; }

/* ── export btn ── */
#export-btn {
  margin-top: 4px; align-self: flex-start;
  background: none; border: 1px solid var(--border); border-radius: 6px;
  color: var(--text); font-family: var(--sans); font-size: 13px;
  padding: 7px 16px; cursor: pointer; display: flex; align-items: center; gap: 7px;
  transition: border-color .15s;
}
#export-btn:hover { border-color: var(--cyan); color: var(--cyan); }
#export-btn:disabled { opacity: .4; cursor: not-allowed; }

/* ── empty state ── */
.empty-msg {
  color: var(--dim); font-size: 13px; padding: 20px 0;
  display: flex; align-items: center; justify-content: center; flex: 1;
}

/* ── print styles ── */
@media print {
  #app { height: auto; overflow: visible; }
  .run-panel, .tab-bar, #export-btn, #status-badge { display: none !important; }
  #verdict { display: flex !important; }
  .tab-pane { display: flex !important; break-inside: avoid; }
  .tabs-wrap { overflow: visible; }
  #log-terminal { max-height: none; overflow: visible; border: none; background: white; color: black; }
  .log-t { color: #666; }
  .ev-card { border: 1px solid #ccc; }
  .shot-wrap { break-inside: avoid; }
  header img { width: 56px; height: 56px; }
  body { background: white; color: black; }
  :root { --bg: white; --bg2: #f5f5f5; --bg3: #f0f0f0; --border: #ddd;
          --text: #111; --dim: #666; --cyan: #0066cc; --orange: #cc6600;
          --green: #006600; --yellow: #996600; }
}

@media (max-width: 600px) {
  .run-panel { flex-wrap: wrap; }
  #cve-input { max-width: 100%; }
}
</style>
</head>
<body>
<div id="app">
  <header>
    <img src="/static/logo.png" alt="bin0racle logo" id="logo-img">
    <div>
      <div class="h-title">bin<span class="o">0</span>racle</div>
      <div class="h-sub">CVE VERIFICATION LAB · @beafn28</div>
    </div>
    <div style="margin-left:auto;display:flex;align-items:center;gap:10px">
      <span id="status-badge"></span>
    </div>
  </header>

  <main>
    <div class="run-panel">
      <input id="cve-input" type="text" placeholder="CVE-2024-1071" autocomplete="off" spellcheck="false">
      <button id="run-btn">▶ Run</button>
      <button id="export-btn" disabled>⬇ Export PDF</button>
    </div>

    <div id="verdict"></div>

    <div class="tabs-wrap">
      <div class="tab-bar">
        <button class="tab-btn active" data-tab="log">Log</button>
        <button class="tab-btn" data-tab="evidence">Evidence</button>
        <button class="tab-btn" data-tab="http">HTTP Requests</button>
        <button class="tab-btn" data-tab="screenshots">Screenshots</button>
      </div>

      <div id="tab-log" class="tab-pane active">
        <div id="log-terminal"><div class="empty-msg">Enter a CVE ID and press Run</div></div>
      </div>
      <div id="tab-evidence" class="tab-pane">
        <div id="evidence-content" class="evidence-grid">
          <div class="empty-msg">Run a CVE investigation to see evidence</div>
        </div>
      </div>
      <div id="tab-http" class="tab-pane">
        <div id="http-content">
          <div class="empty-msg">HTTP requests will appear here after the run</div>
        </div>
      </div>
      <div id="tab-screenshots" class="tab-pane">
        <div id="shots-content" class="shots-grid">
          <div class="empty-msg">Screenshots will appear here after the run</div>
        </div>
      </div>
    </div>
  </main>
</div>

<script>
(function () {
  'use strict';

  const $ = id => document.getElementById(id);
  let currentJobId = null;
  let currentEs = null;

  // ── tabs ──────────────────────────────────────────────────────────────────
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      $('tab-' + btn.dataset.tab).classList.add('active');
    });
  });

  // ── run ───────────────────────────────────────────────────────────────────
  $('run-btn').addEventListener('click', startRun);
  $('cve-input').addEventListener('keydown', e => { if (e.key === 'Enter') startRun(); });

  async function startRun() {
    const cveId = $('cve-input').value.trim().toUpperCase();
    if (!cveId.match(/^CVE-\d{4}-\d+$/i)) {
      alert('Enter a valid CVE ID, e.g. CVE-2024-1071');
      return;
    }

    // Reset UI
    if (currentEs) { currentEs.close(); currentEs = null; }
    $('log-terminal').innerHTML = '';
    $('evidence-content').innerHTML = '<div class="empty-msg">Waiting…</div>';
    $('http-content').innerHTML = '<div class="empty-msg">Waiting…</div>';
    $('shots-content').innerHTML = '<div class="empty-msg">Waiting…</div>';
    $('verdict').style.display = 'none';
    $('verdict').className = '';
    setStatus('running', 'Running…');
    $('run-btn').disabled = true;
    $('export-btn').disabled = true;

    // Switch to log tab
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    document.querySelector('[data-tab="log"]').classList.add('active');
    $('tab-log').classList.add('active');

    try {
      const res = await fetch('/api/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cve_id: cveId }),
      });
      const data = await res.json();
      if (!data.job_id) { alert('Server error: ' + JSON.stringify(data)); return; }
      currentJobId = data.job_id;
      listenSSE(data.job_id);
    } catch (e) {
      setStatus('fail', 'Error');
      $('run-btn').disabled = false;
      alert('Could not connect to bin0racle server: ' + e);
    }
  }

  // ── SSE ───────────────────────────────────────────────────────────────────
  function listenSSE(jobId) {
    const es = new EventSource('/api/stream/' + jobId);
    currentEs = es;

    es.addEventListener('step', e => {
      const d = JSON.parse(e.data);
      appendLog(d.t, d.msg);
    });

    es.addEventListener('done', e => {
      es.close();
      const d = JSON.parse(e.data);
      renderResult(d);
      $('run-btn').disabled = false;
      $('export-btn').disabled = false;
    });

    es.onerror = () => {
      if (currentJobId) {
        setTimeout(() => fetchResult(currentJobId), 1500);
      }
    };
  }

  async function fetchResult(jobId) {
    try {
      const r = await fetch('/api/result/' + jobId);
      if (r.status === 202) return; // still running
      const d = await r.json();
      renderResult(d);
      $('run-btn').disabled = false;
      $('export-btn').disabled = false;
    } catch {}
  }

  // ── log rendering ─────────────────────────────────────────────────────────
  const terminal = $('log-terminal');
  let autoScroll = true;
  terminal.addEventListener('scroll', () => {
    const atBottom = terminal.scrollHeight - terminal.scrollTop - terminal.clientHeight < 60;
    autoScroll = atBottom;
  });

  function appendLog(t, msg) {
    // detect log level
    let cls = 'log-info';
    if (msg.startsWith('[OK]'))   cls = 'log-ok';
    else if (msg.startsWith('[WARN]')) cls = 'log-warn';
    else if (msg.startsWith('[ERR]'))  cls = 'log-err';
    else if (msg.startsWith('──') || msg.startsWith('╠') || msg.startsWith('╚')) cls = 'log-sep';

    const line = document.createElement('div');
    line.className = 'log-line';
    line.innerHTML =
      `<span class="log-t">${t}s</span>` +
      `<span class="${cls}">${escHtml(msg)}</span>`;
    terminal.appendChild(line);
    if (autoScroll) terminal.scrollTop = terminal.scrollHeight;
  }

  // ── result rendering ──────────────────────────────────────────────────────
  function renderResult(d) {
    // verdict
    const vEl = $('verdict');
    if (d.verified) {
      vEl.className = 'verdict-ok';
      vEl.textContent = '★  VERIFICADO — ' + d.cve_id;
    } else {
      vEl.className = 'verdict-fail';
      vEl.textContent = '✖  NO CONFIRMADO — ' + d.cve_id;
    }
    vEl.style.display = 'flex';

    setStatus(d.verified ? 'ok' : 'fail',
      d.verified ? `✓ ${d.cve_id}` : `✗ ${d.cve_id}`);

    // evidence
    renderEvidence(d.verified_evidence || {}, d.evidence || {});

    // HTTP requests
    renderHttp(d.evidence || {});

    // screenshots
    renderScreenshots(d.evidence || {});
  }

  function renderEvidence(ve, ev) {
    const container = $('evidence-content');
    const cards = [];

    // verified_evidence fields
    const veFields = {
      payload_ganador: 'Winning payload',
      estrategia: 'Strategy',
      tiempo_base_mediana_s: 'Baseline (median)',
      tiempo_1_ganador_s: 'Response 1',
      tiempo_2_ganador_s: 'Response 2',
      contenedor: 'Container',
    };
    for (const [k, label] of Object.entries(veFields)) {
      if (ve[k]) cards.push([label, ve[k]]);
    }

    // key evidence dict entries (non-screenshots, non-HTTP)
    const skip = new Set(['screenshots', 'http_log', 'http_requests',
                          'nonce_scraping_diagnostico', 'laboratorio_vivo']);
    for (const [k, v] of Object.entries(ev)) {
      if (skip.has(k)) continue;
      if (typeof v === 'object') {
        cards.push([k.replace(/_/g,' '), JSON.stringify(v, null, 2)]);
      } else {
        cards.push([k.replace(/_/g,' '), String(v)]);
      }
    }

    if (cards.length === 0) {
      container.innerHTML = '<div class="empty-msg">No evidence keys found</div>';
      return;
    }
    container.innerHTML = cards.map(([label, val]) => `
      <div class="ev-card">
        <div class="ev-card-head">${escHtml(label)}</div>
        <div class="ev-card-body"><span class="ev-val">${escHtml(String(val))}</span></div>
      </div>`).join('');
  }

  function renderHttp(ev) {
    const container = $('http-content');
    const reqs = ev.http_requests || ev.http_log || [];
    if (!reqs.length) {
      container.innerHTML = '<div class="empty-msg">No HTTP requests captured</div>';
      return;
    }
    container.innerHTML = reqs.map(r => {
      const method = (r.method || 'POST').toUpperCase();
      const url    = r.url || r.endpoint || '';
      const status = r.status || r.status_code || '';
      const body   = r.body || r.payload || '';
      const resp   = r.response || '';
      const sCls   = status ? ('http-status-' + String(status)[0]) : '';
      return `
        <div class="http-entry">
          <div class="http-line">
            <span class="http-method">${escHtml(method)}</span>
            ${escHtml(url)}
            ${status ? `<span class="${sCls}" style="margin-left:8px">${escHtml(String(status))}</span>` : ''}
          </div>
          ${body ? `<div class="http-line" style="color:var(--dim);margin-top:4px">${escHtml(body)}</div>` : ''}
          ${resp ? `<div class="http-line" style="color:var(--dim)">${escHtml(String(resp).slice(0,200))}</div>` : ''}
        </div>`;
    }).join('');
  }

  function renderScreenshots(ev) {
    const shots = ev.screenshots || [];
    const container = $('shots-content');
    if (!shots.length) {
      container.innerHTML = '<div class="empty-msg">No screenshots captured</div>';
      return;
    }
    container.innerHTML = shots.map((s, i) => {
      const path = typeof s === 'string' ? s : (s.path || '');
      const label = typeof s === 'object' ? (s.label || s.title || `Screenshot ${i+1}`) : `Screenshot ${i+1}`;
      if (!path) return '';
      const b64 = btoa(path).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
      return `
        <div class="shot-wrap">
          <div class="shot-label">${escHtml(label)}</div>
          <img src="/api/screenshot/${b64}" alt="${escHtml(label)}" loading="lazy">
        </div>`;
    }).join('');
  }

  // ── status badge ──────────────────────────────────────────────────────────
  function setStatus(kind, text) {
    const badge = $('status-badge');
    badge.className = 'badge-' + (kind === 'running' ? 'running' : kind === 'ok' ? 'done-ok' : 'done-fail');
    badge.textContent = text;
    badge.style.display = 'inline-block';
  }

  // ── PDF export ────────────────────────────────────────────────────────────
  $('export-btn').addEventListener('click', () => window.print());

  // ── utils ─────────────────────────────────────────────────────────────────
  function escHtml(s) {
    return String(s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
})();
</script>
</body>
</html>"""
