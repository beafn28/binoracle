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

# ── History persistence ───────────────────────────────────────────────────────

_HISTORY_DIR = os.path.expanduser("~/.binoracle/history")
os.makedirs(_HISTORY_DIR, exist_ok=True)


def _save_history(job: "_Job"):
    if not job.result:
        return
    try:
        path = os.path.join(_HISTORY_DIR, f"{job.id}.json")
        record = {
            "job_id": job.id,
            "cve_id": job.cve_id,
            "verified": job.result.get("verified", False),
            "elapsed": job.result.get("elapsed", 0),
            "created": job.created,
            "result": job.result,
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(record, fh, ensure_ascii=False)
    except Exception:
        pass


def _load_history(limit: int = 50) -> list:
    records = []
    try:
        for fname in os.listdir(_HISTORY_DIR):
            if not fname.endswith(".json"):
                continue
            try:
                with open(os.path.join(_HISTORY_DIR, fname), encoding="utf-8") as fh:
                    rec = json.load(fh)
                records.append(rec)
            except Exception:
                pass
    except Exception:
        pass
    records.sort(key=lambda r: r.get("created", 0), reverse=True)
    return records[:limit]

# ── Binary lab job store ──────────────────────────────────────────────────────

import subprocess as _subprocess
import tempfile as _tempfile

_BIN_UPLOAD_DIR = os.path.expanduser("~/.binoracle/uploads")
os.makedirs(_BIN_UPLOAD_DIR, exist_ok=True)

_bin_files: dict[str, str] = {}   # file_id → absolute path
_bin_files_lock = threading.Lock()

_bin_jobs: dict[str, "_BinJob"] = {}
_bin_jobs_lock = threading.Lock()


class _BinJob:
    __slots__ = ("id", "file_id", "cmd_label", "status", "lines", "_q", "t0")

    def __init__(self, file_id: str, cmd_label: str):
        self.id: str = uuid.uuid4().hex[:8]
        self.file_id = file_id
        self.cmd_label = cmd_label
        self.status = "running"
        self.lines: list[str] = []
        self._q: queue.Queue = queue.Queue()
        self.t0 = time.time()


def _start_bin_job(file_id: str, cmd_args: list[str], label: str) -> "_BinJob":
    job = _BinJob(file_id, label)
    with _bin_jobs_lock:
        _bin_jobs[job.id] = job

    def _run():
        try:
            proc = _subprocess.Popen(
                ["python", "-m", "binoracle"] + cmd_args,
                stdout=_subprocess.PIPE,
                stderr=_subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            for line in proc.stdout:
                line = line.rstrip()
                job.lines.append(line)
                job._q.put(("line", line))
            proc.wait()
        except Exception as exc:
            job.lines.append(f"[ERR] {exc}")
            job._q.put(("line", f"[ERR] {exc}"))
        job.status = "done"
        job._q.put(("done", {"lines": job.lines}))

    threading.Thread(target=_run, daemon=True, name=f"bin-{job.id}").start()
    return job


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
            # Merge attempt_evidence screenshots/HTTP even when not confirmed
            attempt_ev = getattr(inv, "attempt_evidence", None) or {}
            for _k in ("screenshots", "http_requests", "http_log"):
                if _k in attempt_ev and _k not in evidence:
                    evidence[_k] = attempt_ev[_k]
            sf = getattr(inv, "source_fetch", None) or {}
            job.result = {
                "verified": inv.verified,
                "cve_id": job.cve_id,
                "detail": getattr(inv, "detail", ""),
                "elapsed": round(time.time() - job.t0, 1),
                "verified_evidence": ve,
                "evidence": evidence,
                "logs": job.logs,
                # CVE metadata
                "description": getattr(inv, "description", ""),
                "cvss_score": getattr(inv, "cvss_score", None),
                "cvss_severity": getattr(inv, "cvss_severity", ""),
                "cvss_vector": getattr(inv, "cvss_vector", ""),
                "published": getattr(inv, "published", ""),
                "vuln_class": getattr(inv, "vuln_class", ""),
                "poc_source": getattr(inv, "poc_source_used", ""),
                "affected_version": sf.get("resolved_version", ""),
            }
            _save_history(job)
            job._q.put(("done", job.result))
        except Exception as exc:
            job.status = "done"
            job.result = {"verified": False, "cve_id": job.cve_id,
                          "error": str(exc), "logs": job.logs}
            _save_history(job)
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
        elif path == "/api/history":
            self._json_history()
        elif path.startswith("/api/result/"):
            job_id = path.split("/")[-1]
            self._json_result(job_id)
        elif path.startswith("/api/screenshot/"):
            b64 = path.split("/")[-1]
            self._serve_screenshot(b64)
        elif path.startswith("/api/binary/stream/"):
            self._bin_sse(path.split("/")[-1])
        elif path.startswith("/api/binary/result/"):
            self._bin_result(path.split("/")[-1])
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
        elif p.path == "/api/binary/upload":
            self._bin_upload()
        elif p.path == "/api/binary/run":
            self._bin_run()
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

    def _json_history(self):
        records = _load_history(50)
        summary = [
            {
                "job_id": r["job_id"],
                "cve_id": r["cve_id"],
                "verified": r.get("verified", False),
                "elapsed": r.get("elapsed", 0),
                "created": r.get("created", 0),
            }
            for r in records
        ]
        self._send_json(200, summary)

    def _json_result(self, job_id: str):
        with _jobs_lock:
            job = _jobs.get(job_id)
        if job:
            if job.status != "done" or not job.result:
                self._send_json(202, {"status": "running"})
                return
            self._send_json(200, job.result)
            return
        # Fall back to persisted history
        try:
            path = os.path.join(_HISTORY_DIR, f"{job_id}.json")
            with open(path, encoding="utf-8") as fh:
                rec = json.load(fh)
            self._send_json(200, rec.get("result", rec))
        except Exception:
            self._send_json(404, {"error": "not found"})

    def _bin_upload(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            data = json.loads(body)
            filename = os.path.basename(str(data.get("filename", "binary")))[:120]
            b64 = data.get("data", "")
            file_bytes = base64.b64decode(b64)
            file_id = uuid.uuid4().hex[:8]
            safe_name = "".join(c for c in filename if c.isalnum() or c in "._-") or "binary"
            path = os.path.join(_BIN_UPLOAD_DIR, f"{file_id}_{safe_name}")
            with open(path, "wb") as fh:
                fh.write(file_bytes)
            with _bin_files_lock:
                _bin_files[file_id] = path
            self._send_json(200, {"file_id": file_id, "filename": filename,
                                  "size": len(file_bytes)})
        except Exception as exc:
            self._send_json(400, {"error": str(exc)})

    def _bin_run(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            data = json.loads(body)
            file_id = str(data.get("file_id", ""))
            cmd = str(data.get("cmd", "identify"))
            extra = data.get("extra", [])
        except Exception:
            self._send_json(400, {"error": "bad json"}); return
        # Special: ask/chat — no file needed
        _NO_FILE_CMDS = {"ask", "chat", "doctor", "tools"}
        if cmd in _NO_FILE_CMDS:
            safe_extra = [a for a in (extra or []) if isinstance(a, str) and len(a) < 500]
            job = _start_bin_job("__ask__", [cmd] + safe_extra, f"{cmd}")
            self._send_json(200, {"job_id": job.id}); return

        with _bin_files_lock:
            path = _bin_files.get(file_id)
        if not path or not os.path.isfile(path):
            self._send_json(404, {"error": "file not found"}); return
        # Allowed commands that take a file path as first positional arg
        _ALLOWED = {"identify", "elf", "pe", "macho", "apk", "java", "wasm",
                    "evm", "har", "asar", "plist", "dotnet", "firmware",
                    "go", "rust", "core", "js", "sqlite", "jeb", "secrets",
                    "gadgets", "arsenal", "rop", "shellcode", "fmtstring",
                    "rawshellcode", "analyze", "autopoc", "autopwn", "funcid",
                    "heap", "primitives", "explain", "diff", "audit", "verify"}
        if cmd not in _ALLOWED:
            self._send_json(400, {"error": f"cmd '{cmd}' not allowed"}); return
        # extra args whitelist: only safe strings
        safe_extra = [a for a in (extra or []) if isinstance(a, str)
                      and len(a) < 80 and a.replace("-","").replace("_","").isalnum()]
        job = _start_bin_job(file_id, [cmd] + safe_extra + [path], f"{cmd} {os.path.basename(path)}")
        self._send_json(200, {"job_id": job.id})

    def _bin_sse(self, job_id: str):
        with _bin_jobs_lock:
            job = _bin_jobs.get(job_id)
        if not job:
            self._404(); return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        for line in list(job.lines):
            self._write_sse("line", line)
        if job.status == "done":
            self._write_sse("done", {"lines": job.lines}); return
        while True:
            try:
                kind, payload = job._q.get(timeout=25)
                self._write_sse(kind, payload)
                if kind == "done": break
            except queue.Empty:
                try:
                    self.wfile.write(b": ping\n\n"); self.wfile.flush()
                except Exception: break
            except Exception: break

    def _bin_result(self, job_id: str):
        with _bin_jobs_lock:
            job = _bin_jobs.get(job_id)
        if not job:
            self._send_json(404, {"error": "not found"}); return
        if job.status != "done":
            self._send_json(202, {"status": "running"}); return
        self._send_json(200, {"lines": job.lines, "cmd": job.cmd_label})

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
  href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Inter:wght@300;400;500;600;700&display=swap">
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
  display: flex; gap: 2px; padding-bottom: 0; overflow-x: auto;
  border-bottom: 1px solid var(--border); flex-shrink: 0;
}
.tab-bar::-webkit-scrollbar { height: 2px; }
.tab-btn {
  background: none; border: none; color: var(--dim);
  font-family: var(--sans); font-size: 13px; font-weight: 500;
  padding: 7px 14px; cursor: pointer; border-bottom: 2px solid transparent;
  margin-bottom: -1px; transition: color .15s, border-color .15s; white-space: nowrap;
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
.log-phase-header {
  display: flex; align-items: center; gap: 10px; margin: 8px 0 4px;
  font-size: 11px; font-weight: 600; letter-spacing: .1em; color: var(--cyan);
  text-transform: uppercase;
}
.log-phase-header::after {
  content: ''; flex: 1; height: 1px; background: var(--border);
}

/* ── report tab ── */
.report-wrap { display: flex; flex-direction: column; gap: 20px; padding-bottom: 20px; }
.report-header {
  display: flex; align-items: flex-start; gap: 16px;
  padding: 20px; background: var(--bg3); border: 1px solid var(--border); border-radius: 8px;
}
.report-header img { width: 56px; height: 56px; object-fit: contain; flex-shrink: 0; }
.report-header-text h1 { font-family: var(--mono); font-size: 20px; font-weight: 600; }
.report-header-text .rh-meta { font-size: 12px; color: var(--dim); margin-top: 4px; }
.report-verdict-ok  { color: var(--green); }
.report-verdict-fail { color: var(--yellow); }

.report-section { background: var(--bg3); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
.report-section-title {
  padding: 10px 16px; font-size: 11px; font-weight: 700; letter-spacing: .1em;
  text-transform: uppercase; color: var(--cyan); background: rgba(0,212,255,.05);
  border-bottom: 1px solid var(--border);
}
.report-section-body { padding: 14px 16px; }

.report-step {
  display: flex; gap: 14px; align-items: flex-start; padding: 10px 0;
  border-bottom: 1px solid var(--border);
}
.report-step:last-child { border-bottom: none; }
.report-step-num {
  min-width: 28px; height: 28px; border-radius: 50%;
  background: rgba(0,212,255,.12); color: var(--cyan); border: 1px solid rgba(0,212,255,.3);
  display: flex; align-items: center; justify-content: center;
  font-size: 11px; font-weight: 700; flex-shrink: 0; margin-top: 1px;
}
.report-step-content h4 { font-size: 13px; font-weight: 600; margin-bottom: 4px; }
.report-step-content p  { font-size: 12px; color: var(--dim); line-height: 1.6; margin: 0; }
.report-step-content code {
  font-family: var(--mono); font-size: 11px; background: rgba(255,255,255,.06);
  padding: 2px 6px; border-radius: 3px; color: var(--orange); word-break: break-all;
}

.report-evidence-grid { display: grid; grid-template-columns: repeat(auto-fill,minmax(260px,1fr)); gap: 10px; }
.report-ev-card { background: rgba(255,255,255,.03); border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; }
.report-ev-label { font-size: 10px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; color: var(--dim); margin-bottom: 4px; }
.report-ev-val   { font-family: var(--mono); font-size: 12px; color: var(--cyan); word-break: break-all; }

.report-shots { display: flex; flex-direction: column; gap: 12px; }
.report-shot  { border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
.report-shot-label { padding: 6px 12px; font-size: 10px; font-weight: 700; letter-spacing: .07em; text-transform: uppercase; color: var(--dim); background: rgba(255,255,255,.03); border-bottom: 1px solid var(--border); }
.report-shot img { width: 100%; display: block; }

/* ── binary analysis tab ── */
.binary-wrap { display: flex; flex-direction: column; gap: 12px; }
.binary-finding {
  background: var(--bg3); border: 1px solid var(--border); border-radius: 6px; overflow: hidden;
}
.binary-finding-head {
  padding: 8px 12px; background: rgba(255,158,44,.06); border-bottom: 1px solid var(--border);
  font-size: 11px; font-weight: 700; letter-spacing: .07em; text-transform: uppercase; color: var(--orange);
}
.binary-finding-body {
  padding: 10px 12px; font-family: var(--mono); font-size: 12px; line-height: 1.65; white-space: pre-wrap; color: var(--text);
}

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

/* ── history panel ── */
#history-btn {
  background: none; border: 1px solid var(--border); border-radius: 6px;
  color: var(--dim); font-family: var(--sans); font-size: 12px; font-weight: 500;
  padding: 6px 12px; cursor: pointer; display: flex; align-items: center; gap: 6px;
  transition: color .15s, border-color .15s; white-space: nowrap;
}
#history-btn:hover { color: var(--cyan); border-color: var(--cyan); }
#history-btn .hist-count {
  background: rgba(0,212,255,.15); color: var(--cyan); border-radius: 10px;
  padding: 1px 7px; font-size: 10px; font-weight: 700;
}
.hist-panel {
  position: fixed; top: 0; right: 0; bottom: 0; width: 320px;
  background: var(--bg2); border-left: 1px solid var(--border);
  display: flex; flex-direction: column; z-index: 100;
  transform: translateX(100%); transition: transform .22s ease;
  box-shadow: -4px 0 20px rgba(0,0,0,.4);
}
.hist-panel.open { transform: translateX(0); }
.hist-panel-head {
  display: flex; align-items: center; justify-content: space-between;
  padding: 14px 16px; border-bottom: 1px solid var(--border);
  font-size: 13px; font-weight: 600; letter-spacing: .05em; color: var(--cyan);
}
.hist-panel-head button {
  background: none; border: none; color: var(--dim); cursor: pointer;
  font-size: 18px; line-height: 1; padding: 2px 6px;
}
.hist-panel-head button:hover { color: var(--text); }
.hist-list { flex: 1; overflow-y: auto; padding: 8px 0; }
.hist-item {
  display: flex; align-items: center; gap: 10px;
  padding: 10px 16px; cursor: pointer; border-bottom: 1px solid rgba(255,255,255,.04);
  transition: background .12s;
}
.hist-item:hover { background: rgba(255,255,255,.04); }
.hist-item.active { background: rgba(0,212,255,.07); }
.hist-icon {
  font-size: 9px; font-weight: 700; letter-spacing: .06em;
  flex-shrink: 0; padding: 2px 6px; border-radius: 3px;
  font-family: var(--mono); white-space: nowrap;
}
.hist-cve { font-family: var(--mono); font-size: 13px; font-weight: 600; }
.hist-meta { font-size: 10px; color: var(--dim); margin-top: 2px; }
.hist-empty { color: var(--dim); font-size: 13px; text-align: center; padding: 32px 16px; }
.hist-overlay {
  position: fixed; inset: 0; z-index: 99; background: rgba(0,0,0,.35);
  display: none;
}
.hist-overlay.open { display: block; }

/* ── empty state ── */
.empty-msg {
  color: var(--dim); font-size: 13px; padding: 20px 0;
  display: flex; align-items: center; justify-content: center; flex: 1;
}

/* ── wiki link ── */
.wiki-link {
  font-family: var(--mono); font-size: 11px; color: var(--dim);
  text-decoration: none; padding: 4px 10px; border-radius: 4px;
  border: 1px solid var(--border); transition: all .15s; letter-spacing: .04em;
}
.wiki-link:hover { color: var(--cyan); border-color: var(--cyan); }

/* ── binary lab ── */
#binlab-content { padding: 16px 20px; }
.binlab-upload-zone {
  border: 2px dashed var(--border); border-radius: 10px;
  padding: 40px 20px; text-align: center; cursor: pointer;
  transition: border-color .15s, background .15s;
  background: var(--bg2);
}
.binlab-upload-zone.drag-over { border-color: var(--cyan); background: rgba(0,212,255,.05); }
.binlab-drop-icon {
  font-family: var(--mono); font-size: 16px; font-weight: 700;
  color: var(--cyan); letter-spacing: .12em; margin-bottom: 10px;
}
.binlab-drop-sub { font-size: 11px; color: var(--dim); letter-spacing: .06em; margin-bottom: 16px; }
.binlab-browse-btn {
  font-family: var(--mono); font-size: 11px; cursor: pointer;
  padding: 7px 20px; border-radius: 5px; border: 1px solid var(--cyan);
  color: var(--cyan); background: rgba(0,212,255,.08); transition: background .15s;
  letter-spacing: .06em;
}
.binlab-browse-btn:hover { background: rgba(0,212,255,.18); }
.binlab-file-row {
  display: flex; align-items: center; gap: 10px; padding: 8px 0 14px;
  border-bottom: 1px solid var(--border); margin-bottom: 14px;
}
.binlab-fname { font-family: var(--mono); font-size: 13px; font-weight: 600; color: var(--text); }
.binlab-fsize { font-size: 11px; color: var(--dim); }
.binlab-clear-btn {
  margin-left: auto; font-family: var(--mono); font-size: 10px;
  background: none; border: 1px solid var(--border); border-radius: 3px;
  color: var(--dim); padding: 3px 10px; cursor: pointer; transition: all .12s;
}
.binlab-clear-btn:hover { color: #ff4444; border-color: #ff4444; }
.binlab-tools { margin-bottom: 14px; display: flex; flex-direction: column; gap: 12px; }
.binlab-tool-group { }
.binlab-tool-label {
  font-family: var(--mono); font-size: 9px; color: var(--dim);
  letter-spacing: .1em; margin-bottom: 7px;
}
.binlab-tool-row { display: flex; flex-wrap: wrap; gap: 7px; }
.binlab-tool-btn {
  font-family: var(--mono); font-size: 11px; cursor: pointer;
  padding: 5px 14px; border-radius: 4px; border: 1px solid var(--border);
  color: var(--text); background: var(--bg3); transition: all .12s;
  letter-spacing: .04em;
}
.binlab-tool-btn:hover { border-color: var(--cyan); color: var(--cyan); background: rgba(0,212,255,.07); }
.binlab-tool-btn.running { border-color: var(--orange); color: var(--orange); }
.binlab-terminal {
  background: var(--bg2); border: 1px solid var(--border); border-radius: 6px;
  padding: 12px 14px; font-family: var(--mono); font-size: 11.5px;
  line-height: 1.6; color: var(--text); height: 320px; overflow-y: auto;
  white-space: pre-wrap; word-break: break-all;
}
.bl-line-ok   { color: var(--green); }
.bl-line-err  { color: #ff4444; }
.bl-line-warn { color: var(--orange); }
.bl-line-sep  { color: var(--cyan); font-weight: 600; }
.bl-line-head { color: var(--cyan); font-weight: 700; }

/* ── ask oracle ── */
.ask-wrap { padding: 16px 20px; display: flex; flex-direction: column; height: 100%; }
.ask-desc { font-size: 12px; color: var(--dim); margin-bottom: 12px; }
.ask-desc code { font-family: var(--mono); color: var(--cyan); }
.ask-row { display: flex; gap: 8px; margin-bottom: 10px; }
.ask-input {
  flex: 1; background: var(--bg2); border: 1px solid var(--border);
  border-radius: 6px; padding: 8px 14px; color: var(--text);
  font-family: var(--mono); font-size: 13px; outline: none;
}
.ask-input:focus { border-color: var(--cyan); }
.ask-btn {
  background: var(--cyan); color: #000; border: none; border-radius: 6px;
  font-family: var(--mono); font-size: 13px; font-weight: 700;
  padding: 0 20px; cursor: pointer; transition: opacity .15s;
}
.ask-btn:disabled { opacity: .5; cursor: not-allowed; }
.ask-terminal {
  flex: 1; background: var(--bg2); border: 1px solid var(--border);
  border-radius: 6px; padding: 12px 14px; font-family: var(--mono);
  font-size: 11.5px; line-height: 1.65; color: var(--text);
  overflow-y: auto; white-space: pre-wrap; word-break: break-word;
  min-height: 260px;
}

/* ── tools catalog ── */
.tools-catalog { padding: 14px 20px; }
.tools-search-row { margin-bottom: 14px; }
.tools-search {
  width: 100%; max-width: 380px; background: var(--bg2);
  border: 1px solid var(--border); border-radius: 6px; padding: 7px 14px;
  color: var(--text); font-family: var(--mono); font-size: 12px; outline: none;
}
.tools-search:focus { border-color: var(--cyan); }
.tools-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 10px;
}
.tool-card {
  background: var(--bg2); border: 1px solid var(--border); border-radius: 7px;
  padding: 12px 14px; cursor: pointer; transition: border-color .12s, background .12s;
}
.tool-card:hover { border-color: var(--cyan); background: rgba(0,212,255,.04); }
.tool-card-name {
  font-family: var(--mono); font-size: 13px; font-weight: 700; color: var(--cyan);
  margin-bottom: 4px;
}
.tool-card-cat {
  font-family: var(--mono); font-size: 9px; letter-spacing: .08em;
  color: var(--dim); margin-bottom: 6px; text-transform: uppercase;
}
.tool-card-desc { font-size: 11px; color: var(--dim); line-height: 1.5; }
.tool-card-cli {
  margin-top: 8px; font-family: var(--mono); font-size: 10px;
  color: var(--bg); background: var(--cyan); padding: 2px 8px;
  border-radius: 3px; display: inline-block; letter-spacing: .02em;
}
.tool-cat-header {
  grid-column: 1 / -1; font-family: var(--mono); font-size: 10px;
  letter-spacing: .12em; color: var(--dim); border-bottom: 1px solid var(--border);
  padding-bottom: 6px; margin-top: 8px; text-transform: uppercase;
}

/* ── print styles ── */
@media print {
  #app { height: auto; overflow: visible; }
  header, .run-panel, .tab-bar, #export-btn, #status-badge, #verdict { display: none !important; }
  /* hide every tab except the report */
  .tab-pane { display: none !important; }
  #tab-report { display: flex !important; padding: 0 !important; }
  .tabs-wrap { overflow: visible; }
  #print-report { display: block !important; }
  body { background: white; color: #111; font-family: 'Inter', system-ui, sans-serif; }
  :root { --bg: white; --bg2: #f7f8fa; --bg3: #f0f2f5; --border: #d8dce6;
          --text: #111; --dim: #555; --cyan: #0055cc; --orange: #c05000;
          --green: #006622; --yellow: #7a5c00; }
  .report-section-title { background: #eef2ff; color: #0055cc; border-bottom: 1px solid #c8d4f0; }
  .report-step-num { background: #eef2ff; color: #0055cc; border-color: #c8d4f0; }
  .report-finding { break-inside: avoid; }
  .report-shot { break-inside: avoid; page-break-inside: avoid; }
}

@media (max-width: 600px) {
  .run-panel { flex-wrap: wrap; }
  #cve-input { max-width: 100%; }
}

/* ── CVE info panel ── */
#cve-info-panel {
  margin: 0 24px 16px;
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 20px;
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 10px 24px;
  align-items: start;
}
.cve-info-desc {
  font-size: 12px; color: var(--text); line-height: 1.6;
  grid-column: 1 / -1; border-bottom: 1px solid var(--border);
  padding-bottom: 10px; margin-bottom: 2px;
}
.cve-info-row {
  display: flex; flex-wrap: wrap; gap: 10px; grid-column: 1 / -1;
}
.cve-info-chip {
  font-family: var(--mono); font-size: 10px; font-weight: 600;
  padding: 3px 10px; border-radius: 3px; border: 1px solid var(--border);
  background: var(--bg3); color: var(--dim); letter-spacing: .04em;
  display: flex; align-items: center; gap: 6px;
}
.cve-info-chip b { color: var(--text); font-weight: 600; }
.cvss-crit  { color: #ff4444; border-color: rgba(255,68,68,.4);  background: rgba(255,68,68,.08); }
.cvss-high  { color: var(--orange); border-color: rgba(255,158,44,.4); background: rgba(255,158,44,.08); }
.cvss-med   { color: #ffd700; border-color: rgba(255,215,0,.4); background: rgba(255,215,0,.08); }
.cvss-low   { color: var(--green); border-color: rgba(0,230,118,.4); background: rgba(0,230,118,.08); }
.cve-poc-link {
  font-family: var(--mono); font-size: 10px; color: var(--cyan);
  text-decoration: none; padding: 3px 10px; border-radius: 3px;
  border: 1px solid rgba(0,212,255,.3); background: rgba(0,212,255,.07);
}
.cve-poc-link:hover { background: rgba(0,212,255,.15); }
.rerun-btn {
  font-family: var(--mono); font-size: 11px; color: var(--dim);
  background: none; border: 1px solid var(--border); border-radius: 4px;
  padding: 4px 12px; cursor: pointer; transition: all .15s;
  letter-spacing: .04em;
}
.rerun-btn:hover { color: var(--text); border-color: var(--cyan); }

/* ── phase progress tracker ── */
#phase-tracker {
  margin: 0 24px 8px;
  display: none;
}
.phase-track-inner {
  display: flex; gap: 0; overflow-x: auto;
}
.pt-step {
  display: flex; align-items: center; flex: 1; min-width: 0;
  font-size: 9px; font-family: var(--mono); color: var(--dim);
  letter-spacing: .04em; white-space: nowrap; overflow: hidden;
  text-overflow: ellipsis;
}
.pt-step.active { color: var(--cyan); }
.pt-step.done   { color: var(--green); }
.pt-dot {
  width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0;
  background: var(--bg3); border: 1px solid var(--border); margin-right: 5px;
}
.pt-step.active .pt-dot { background: var(--cyan); border-color: var(--cyan); box-shadow: 0 0 6px var(--cyan); }
.pt-step.done   .pt-dot { background: var(--green); border-color: var(--green); }
.pt-line { flex: none; width: 16px; height: 1px; background: var(--border); margin: 0 2px; }
.pt-step.done  ~ .pt-step .pt-line { background: var(--green); }

/* ── copy button ── */
.copy-btn {
  font-size: 9px; font-family: var(--mono); letter-spacing: .04em;
  background: none; border: 1px solid var(--border); border-radius: 3px;
  color: var(--dim); padding: 2px 7px; cursor: pointer; transition: all .15s;
  flex-shrink: 0;
}
.copy-btn:hover { color: var(--cyan); border-color: var(--cyan); }
.copy-btn.copied { color: var(--green); border-color: var(--green); }

/* ── evidence cards with copy button ── */
.ev-card-body {
  display: flex; align-items: flex-start; gap: 8px;
}
.ev-val { flex: 1; min-width: 0; word-break: break-all; }
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
      <a class="wiki-link" href="https://beafn28.github.io/binoracle/" target="_blank" rel="noopener">Docs</a>
      <button id="history-btn" title="Session history">
        History <span class="hist-count" id="hist-count">0</span>
      </button>
    </div>
  </header>

  <!-- History panel -->
  <div class="hist-overlay" id="hist-overlay"></div>
  <div class="hist-panel" id="hist-panel">
    <div class="hist-panel-head">
      <span>Investigation History</span>
      <button id="hist-close" title="Close">×</button>
    </div>
    <div class="hist-list" id="hist-list">
      <div class="hist-empty">No previous investigations</div>
    </div>
  </div>

  <div id="phase-tracker">
    <div class="phase-track-inner" id="phase-track-inner"></div>
  </div>

  <main>
    <div class="run-panel">
      <input id="cve-input" type="text" placeholder="CVE-2024-1071" autocomplete="off" spellcheck="false">
      <button id="run-btn">Run</button>
      <button id="export-btn" disabled>Export PDF</button>
    </div>

    <div id="verdict"></div>
    <div id="cve-info-panel" style="display:none"></div>

    <div class="tabs-wrap">
      <div class="tab-bar">
        <button class="tab-btn active" data-tab="log">Live Log</button>
        <button class="tab-btn" data-tab="report">Report</button>
        <button class="tab-btn" data-tab="evidence">Evidence</button>
        <button class="tab-btn" data-tab="binary" id="tab-btn-binary" style="display:none">Binary Analysis</button>
        <button class="tab-btn" data-tab="http">HTTP Requests</button>
        <button class="tab-btn" data-tab="screenshots">Screenshots</button>
        <button class="tab-btn" data-tab="binlab">Binary Lab</button>
        <button class="tab-btn" data-tab="ask">Ask Oracle</button>
        <button class="tab-btn" data-tab="tools">All Tools</button>
      </div>

      <div id="tab-log" class="tab-pane active">
        <div id="log-terminal"><div class="empty-msg">Enter a CVE ID and press Run</div></div>
      </div>
      <div id="tab-report" class="tab-pane">
        <div id="report-content">
          <div class="empty-msg">Run a CVE investigation to generate the report</div>
        </div>
      </div>
      <div id="tab-evidence" class="tab-pane">
        <div id="evidence-content" class="evidence-grid">
          <div class="empty-msg">Run a CVE investigation to see evidence</div>
        </div>
      </div>
      <div id="tab-binary" class="tab-pane">
        <div id="binary-content" class="binary-wrap">
          <div class="empty-msg">No binary analysis data for this CVE</div>
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
      <div id="tab-binlab" class="tab-pane">
        <div id="binlab-content">
          <div class="binlab-upload-zone" id="binlab-drop">
            <div class="binlab-drop-inner">
              <div class="binlab-drop-icon">[ DROP BINARY HERE ]</div>
              <div class="binlab-drop-sub">ELF · PE · APK · Mach-O · WASM · JAR · .NET · Firmware · HAR · SQLite · EVM · JS</div>
              <label class="binlab-browse-btn">
                Browse File
                <input type="file" id="binlab-file" style="display:none">
              </label>
            </div>
          </div>
          <div id="binlab-info" style="display:none">
            <div class="binlab-file-row">
              <span id="binlab-fname" class="binlab-fname"></span>
              <span id="binlab-fsize" class="binlab-fsize"></span>
              <button class="binlab-clear-btn" id="binlab-clear">Remove</button>
            </div>
            <div class="binlab-tools" id="binlab-tools">
              <div class="binlab-tool-group">
                <div class="binlab-tool-label">STATIC ANALYSIS</div>
                <div class="binlab-tool-row" id="binlab-static-row"></div>
              </div>
              <div class="binlab-tool-group">
                <div class="binlab-tool-label">EXPLOITATION</div>
                <div class="binlab-tool-row">
                  <button class="binlab-tool-btn" data-cmd="gadgets">ROP Gadgets</button>
                  <button class="binlab-tool-btn" data-cmd="arsenal">ROP Arsenal</button>
                  <button class="binlab-tool-btn" data-cmd="rop">Build ROP Chain</button>
                  <button class="binlab-tool-btn" data-cmd="shellcode">Shellcode</button>
                  <button class="binlab-tool-btn" data-cmd="fmtstring">Format String</button>
                  <button class="binlab-tool-btn" data-cmd="primitives">Primitives</button>
                  <button class="binlab-tool-btn" data-cmd="autopoc" style="border-color:var(--orange);color:var(--orange)">Auto-PoC</button>
                  <button class="binlab-tool-btn" data-cmd="autopwn" style="border-color:#ff4444;color:#ff4444">Auto-Pwn</button>
                </div>
              </div>
              <div class="binlab-tool-group">
                <div class="binlab-tool-label">MISC</div>
                <div class="binlab-tool-row">
                  <button class="binlab-tool-btn" data-cmd="secrets">Secrets Scan</button>
                  <button class="binlab-tool-btn" data-cmd="funcid">Function ID</button>
                  <button class="binlab-tool-btn" data-cmd="analyze">Full Analysis</button>
                </div>
              </div>
            </div>
            <div id="binlab-terminal" class="binlab-terminal">
              <div class="empty-msg">Select a tool above to run</div>
            </div>
          </div>
        </div>
      </div>
      <div id="tab-ask" class="tab-pane">
        <div class="ask-wrap">
          <div class="ask-desc">Ask the Oracle a free-form question about a binary, CVE, or security concept. Runs <code>binoracle ask</code>.</div>
          <div class="ask-row">
            <input id="ask-input" class="ask-input" type="text" placeholder="What protections does this binary have? How does CVE-2024-1071 work?" autocomplete="off" spellcheck="false">
            <button id="ask-btn" class="ask-btn">Ask</button>
          </div>
          <div id="ask-terminal" class="ask-terminal"><div class="empty-msg">Type a question above and press Ask</div></div>
        </div>
      </div>

      <div id="tab-tools" class="tab-pane">
        <div class="tools-catalog">
          <div class="tools-search-row">
            <input id="tools-search" class="tools-search" type="text" placeholder="Filter tools…" autocomplete="off">
          </div>
          <div class="tools-grid" id="tools-grid"></div>
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
    _logPhases = []; _currentPhase = null;
    $('log-terminal').innerHTML = '';
    $('report-content').innerHTML = '<div class="empty-msg">Run a CVE investigation to generate the report</div>';
    $('evidence-content').innerHTML = '<div class="empty-msg">Waiting…</div>';
    $('http-content').innerHTML = '<div class="empty-msg">Waiting…</div>';
    $('shots-content').innerHTML = '<div class="empty-msg">Waiting…</div>';
    $('binary-content').innerHTML = '<div class="empty-msg">No binary analysis data for this CVE</div>';
    $('tab-btn-binary').style.display = 'none';
    $('verdict').style.display = 'none';
    $('verdict').className = '';
    $('cve-info-panel').style.display = 'none';
    $('phase-track-inner').innerHTML = '';
    $('phase-tracker').style.display = 'block';
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
      setTimeout(loadHistory, 1500);
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

  // ── phase name translations ───────────────────────────────────────────────
  const PHASE_LABELS = {
    'CONSULTA NVD':     'Vulnerability Intelligence',
    'HIPÓTESIS LLM':    'Hypothesis & Planning',
    'ANÁLISIS DE CÓDIGO': 'Source Code Analysis',
    'ENDPOINT':         'Endpoint Discovery',
    'VERIFICACIÓN':     'Dynamic Verification',
    'LABORATORIO':      'Lab Environment Setup',
    'BOOTSTRAP':        'Lab Bootstrap',
    'EXPLOIT':          'Exploit Execution',
    'EVIDENCIA':        'Evidence Collection',
    'RESULTADO':        'Result',
    'ANÁLISIS BINARIO': 'Binary Analysis',
    'REVERSING':        'Binary Reversing',
    'DECOMPILACIÓN':    'Decompilation',
    'ANÁLISIS NATIVO':  'Native Code Analysis',
    'GROUNDING':        'Code Grounding',
    'NONCE':            'Nonce Resolution',
    'PAYLOAD':          'Payload Testing',
  };

  function translatePhase(raw) {
    const key = raw.replace(/^──+\s*|\s*──+$/g,'').trim().toUpperCase();
    for (const [k, v] of Object.entries(PHASE_LABELS)) {
      if (key.includes(k)) return v;
    }
    return raw.replace(/^──+\s*|\s*──+$/g,'').trim();
  }

  // ── log rendering ─────────────────────────────────────────────────────────
  const terminal = $('log-terminal');
  let autoScroll = true;
  terminal.addEventListener('scroll', () => {
    const atBottom = terminal.scrollHeight - terminal.scrollTop - terminal.clientHeight < 60;
    autoScroll = atBottom;
  });

  // Store phases for the report
  let _logPhases = [];   // [{name, label, entries:[{t,msg}]}]
  let _currentPhase = null;

  function _updatePhaseTracker() {
    const inner = $('phase-track-inner');
    if (!inner || !_logPhases.length) return;
    inner.innerHTML = _logPhases.map((ph, i) => {
      const isDone = i < _logPhases.length - 1;
      const isActive = i === _logPhases.length - 1;
      const cls = isDone ? 'done' : isActive ? 'active' : '';
      const sep = i < _logPhases.length - 1 ? '<div class="pt-line"></div>' : '';
      return `<div class="pt-step ${cls}"><div class="pt-dot"></div>${escHtml(ph.label)}</div>${sep}`;
    }).join('');
  }

  function appendLog(t, msg) {
    // detect phase headers (── PHASE NAME ──────)
    const isSep = msg.startsWith('──') || msg.startsWith('╠') || msg.startsWith('╚');
    if (isSep && msg.includes('──')) {
      const label = translatePhase(msg);
      _currentPhase = {name: msg, label, entries: []};
      _logPhases.push(_currentPhase);
      _updatePhaseTracker();
      // render phase header
      const hdr = document.createElement('div');
      hdr.className = 'log-phase-header';
      hdr.textContent = label;
      terminal.appendChild(hdr);
      if (autoScroll) terminal.scrollTop = terminal.scrollHeight;
      return;
    }

    if (_currentPhase) _currentPhase.entries.push({t, msg});

    let cls = 'log-info';
    if (msg.startsWith('[OK]'))    cls = 'log-ok';
    else if (msg.startsWith('[WARN]')) cls = 'log-warn';
    else if (msg.startsWith('[ERR]'))  cls = 'log-err';
    else if (isSep)                   cls = 'log-sep';

    // Humanize common verbose patterns
    const display = humanizeLog(msg);

    const line = document.createElement('div');
    line.className = 'log-line';
    line.innerHTML =
      `<span class="log-t">${t}s</span>` +
      `<span class="${cls}">${escHtml(display)}</span>`;
    terminal.appendChild(line);
    if (autoScroll) terminal.scrollTop = terminal.scrollHeight;
  }

  function humanizeLog(msg) {
    return msg
      .replace(/^\[OK\]\s*/,    '')
      .replace(/^\[WARN\]\s*/, 'WARNING: ')
      .replace(/^\[ERR\]\s*/,  'ERROR: ')
      .replace(/^\[INFO\]\s*/, '');
  }

  // ── result rendering ──────────────────────────────────────────────────────
  function renderResult(d) {
    // verdict
    const vEl = $('verdict');
    if (d.verified) {
      vEl.className = 'verdict-ok';
      vEl.textContent = 'CONFIRMED — ' + d.cve_id;
    } else {
      vEl.className = 'verdict-fail';
      vEl.textContent = 'NOT CONFIRMED — ' + d.cve_id;
    }
    vEl.style.display = 'flex';

    setStatus(d.verified ? 'ok' : 'fail',
      d.verified ? `CONFIRMED: ${d.cve_id}` : `NOT CONFIRMED: ${d.cve_id}`);

    // CVE info panel
    renderCveInfo(d);

    // evidence
    renderEvidence(d.verified_evidence || {}, d.evidence || {});

    // HTTP requests
    renderHttp(d.evidence || {});

    // screenshots
    renderScreenshots(d.evidence || {});

    // professional report
    buildReport(d);

    // binary analysis
    renderBinary(d);

    // stop phase tracker
    $('phase-tracker').style.display = 'none';
  }

  function renderCveInfo(d) {
    const panel = $('cve-info-panel');
    if (!d.description && !d.cvss_score && !d.vuln_class && !d.affected_version && !d.poc_source) {
      panel.style.display = 'none';
      return;
    }
    const score = d.cvss_score;
    let scoreCls = '';
    if (score >= 9) scoreCls = 'cvss-crit';
    else if (score >= 7) scoreCls = 'cvss-high';
    else if (score >= 4) scoreCls = 'cvss-med';
    else if (score > 0) scoreCls = 'cvss-low';

    const chips = [];
    if (score) chips.push(`<span class="cve-info-chip ${scoreCls}">CVSS <b>${score.toFixed(1)}</b>${d.cvss_severity ? ' · ' + escHtml(d.cvss_severity.toUpperCase()) : ''}</span>`);
    if (d.vuln_class) chips.push(`<span class="cve-info-chip">Class <b>${escHtml(d.vuln_class.toUpperCase())}</b></span>`);
    if (d.affected_version) chips.push(`<span class="cve-info-chip">Affected <b>${escHtml(d.affected_version)}</b></span>`);
    if (d.published) chips.push(`<span class="cve-info-chip">Published <b>${escHtml(d.published.slice(0,10))}</b></span>`);
    if (d.poc_source) chips.push(`<a class="cve-poc-link" href="${escHtml(d.poc_source)}" target="_blank" rel="noopener">PoC Source</a>`);
    chips.push(`<button class="rerun-btn" id="rerun-btn">Run Again</button>`);

    panel.innerHTML = `
      ${d.description ? `<div class="cve-info-desc">${escHtml(d.description)}</div>` : ''}
      <div class="cve-info-row">${chips.join('')}</div>
    `;
    panel.style.display = 'grid';

    const rerunBtn = document.getElementById('rerun-btn');
    if (rerunBtn) rerunBtn.addEventListener('click', () => {
      $('cve-input').value = d.cve_id;
      startRun();
    });
  }

  // ── professional report builder ──────────────────────────────────────────
  function buildReport(d) {
    const ev = d.evidence || {};
    const ve = d.verified_evidence || {};
    const shots = ev.screenshots || [];
    const now = new Date().toISOString().slice(0,10);

    // Key evidence values for the technical findings section
    const techFields = [
      ['Winning Payload',     ve.payload_ganador],
      ['Strategy',            ve.estrategia],
      ['Baseline Response',   ve.tiempo_base_mediana_s != null ? ve.tiempo_base_mediana_s + 's' : null],
      ['Delayed Response 1',  ve.tiempo_1_ganador_s != null ? ve.tiempo_1_ganador_s + 's' : null],
      ['Delayed Response 2',  ve.tiempo_2_ganador_s != null ? ve.tiempo_2_ganador_s + 's' : null],
      ['Container',           ve.contenedor],
    ];
    const skip = new Set(['screenshots','http_log','http_requests','nonce_scraping_diagnostico',
                          'laboratorio_vivo','parametros_resueltos_con_valor_real']);
    for (const [k, v] of Object.entries(ev)) {
      if (!skip.has(k) && v != null && typeof v !== 'object')
        techFields.push([k.replace(/_/g,' '), String(v)]);
    }
    const techCards = techFields.filter(([,v]) => v != null);

    // Build investigation steps from phases collected during streaming.
    // If _logPhases is empty (fast run loaded from history), rebuild from raw logs.
    let phases = _logPhases;
    if (!phases.length && d.logs && d.logs.length) {
      phases = [];
      let cur = null;
      for (const entry of d.logs) {
        const isSep = entry.msg.startsWith('──') || entry.msg.startsWith('╠') || entry.msg.startsWith('╚');
        if (isSep && entry.msg.includes('──')) {
          cur = {name: entry.msg, label: translatePhase(entry.msg), entries: []};
          phases.push(cur);
        } else if (cur) {
          cur.entries.push(entry);
        }
      }
    }
    const stepItems = phases.map((ph, i) => {
      const best = ph.entries.find(e => e.msg.startsWith('[OK]'))
                || ph.entries.find(e => e.msg.startsWith('[WARN]'))
                || ph.entries[ph.entries.length - 1]
                || {msg: ''};
      return {num: i + 1, label: ph.label, detail: humanizeLog(best.msg)};
    });

    const verdictCls = d.verified ? 'report-verdict-ok' : 'report-verdict-fail';
    const verdictTxt = d.verified
      ? 'CONFIRMED — vulnerability reproduced in isolated lab'
      : 'NOT CONFIRMED — dynamic reproduction did not succeed';

    const shotsHtml = shots.map((s, i) => {
      const path  = typeof s === 'string' ? s : (s.path || '');
      const label = typeof s === 'object' ? (s.label || s.title || `Screenshot ${i+1}`) : `Screenshot ${i+1}`;
      if (!path) return '';
      const b64 = btoa(path).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
      return `<div class="report-shot">
        <div class="report-shot-label">${escHtml(label)}</div>
        <img src="/api/screenshot/${b64}" alt="${escHtml(label)}" loading="lazy">
      </div>`;
    }).join('');

    const techHtml = techCards.map(([label, val]) => `
      <div class="report-ev-card">
        <div class="report-ev-label">${escHtml(label)}</div>
        <div class="report-ev-val">${escHtml(String(val))}</div>
      </div>`).join('');

    const stepsHtml = stepItems.map(s => `
      <div class="report-step">
        <div class="report-step-num">${s.num}</div>
        <div class="report-step-content">
          <h4>${escHtml(s.label)}</h4>
          <p>${escHtml(s.detail)}</p>
        </div>
      </div>`).join('');

    // CVE metadata for report
    const rScore = d.cvss_score;
    let rScoreColor = '#888';
    if (rScore >= 9) rScoreColor = '#ff4444';
    else if (rScore >= 7) rScoreColor = '#ff9e2c';
    else if (rScore >= 4) rScoreColor = '#ffd700';
    else if (rScore > 0) rScoreColor = '#00e676';
    const metaChips = [];
    if (rScore) metaChips.push(`<span style="font-family:monospace;font-size:11px;font-weight:700;color:${rScoreColor};padding:2px 8px;border:1px solid ${rScoreColor}44;border-radius:3px;background:${rScoreColor}11">CVSS ${rScore.toFixed(1)}${d.cvss_severity ? ' · ' + d.cvss_severity.toUpperCase() : ''}</span>`);
    if (d.vuln_class) metaChips.push(`<span style="font-family:monospace;font-size:11px;padding:2px 8px;border:1px solid #333;border-radius:3px;background:#1a1a2a;color:#aaa">${escHtml(d.vuln_class.toUpperCase())}</span>`);
    if (d.affected_version) metaChips.push(`<span style="font-family:monospace;font-size:11px;padding:2px 8px;border:1px solid #333;border-radius:3px;background:#1a1a2a;color:#aaa">Affected: ${escHtml(d.affected_version)}</span>`);
    if (d.published) metaChips.push(`<span style="font-family:monospace;font-size:11px;padding:2px 8px;border:1px solid #333;border-radius:3px;background:#1a1a2a;color:#aaa">${escHtml(d.published.slice(0,10))}</span>`);
    const metaHtml = metaChips.length ? `<div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px">${metaChips.join('')}</div>` : '';
    const descHtml = d.description ? `<div style="margin-top:10px;font-size:12px;color:#aaa;line-height:1.6;border-top:1px solid #222;padding-top:10px">${escHtml(d.description)}</div>` : '';

    $('report-content').innerHTML = `
      <div class="report-wrap">
        <div class="report-header">
          <img src="/static/logo.png" alt="bin0racle">
          <div class="report-header-text">
            <h1>${escHtml(d.cve_id)} — Verification Report</h1>
            <div class="rh-meta">bin0racle Autonomous CVE Lab · ${now} · @beafn28</div>
            <div class="rh-meta ${verdictCls}" style="margin-top:6px;font-weight:600">${verdictTxt}</div>
            ${metaHtml}
            ${descHtml}
          </div>
        </div>

        ${stepsHtml ? `<div class="report-section">
          <div class="report-section-title">Investigation Steps</div>
          <div class="report-section-body">${stepsHtml}</div>
        </div>` : ''}

        ${techCards.length ? `<div class="report-section">
          <div class="report-section-title">Technical Evidence</div>
          <div class="report-section-body">
            <div class="report-evidence-grid">${techHtml}</div>
          </div>
        </div>` : ''}

        ${shots.length ? `<div class="report-section">
          <div class="report-section-title">Screenshots</div>
          <div class="report-section-body">
            <div class="report-shots">${shotsHtml}</div>
          </div>
        </div>` : ''}

        ${(()=>{
          const reqs = ev.http_requests || ev.http_log || [];
          if (!reqs.length) return '';
          const reqHtml = reqs.slice(0,5).map(r => {
            const method = (r.method||'POST').toUpperCase();
            const url = r.url||r.endpoint||'';
            const status = r.status||r.status_code||'';
            const body = r.body||r.payload||'';
            const resp = r.response||'';
            return `<div style="margin-bottom:10px">
              <div style="font-family:var(--mono);font-size:11px;background:rgba(0,0,0,.2);border:1px solid var(--border);border-radius:4px;padding:6px 10px;color:var(--text)">
                <span style="color:var(--orange);font-weight:600">${escHtml(method)}</span> ${escHtml(url)}${status ? ` <span style="color:var(--green)">${escHtml(String(status))}</span>` : ''}
              </div>
              ${body ? `<div style="font-family:var(--mono);font-size:11px;background:rgba(0,0,0,.12);border:1px solid var(--border);border-top:none;border-radius:0 0 4px 4px;padding:6px 10px;color:var(--dim)">${escHtml(String(body).slice(0,300))}</div>` : ''}
            </div>`;
          }).join('');
          return `<div class="report-section">
            <div class="report-section-title">HTTP Evidence</div>
            <div class="report-section-body">${reqHtml}</div>
          </div>`;
        })()}

        <div class="report-section">
          <div class="report-section-title">Conclusion</div>
          <div class="report-section-body">
            <p style="font-size:13px;line-height:1.7;color:var(--text)">
              ${d.verified
                ? `The vulnerability <strong>${escHtml(d.cve_id)}</strong> was successfully reproduced in an isolated lab environment. The evidence above confirms that the described attack vector is exploitable under the documented conditions. Detailed reproduction steps and proof-of-concept payloads are included in this report.`
                : `Dynamic reproduction of <strong>${escHtml(d.cve_id)}</strong> was attempted but could not be confirmed in the automated lab. This may indicate that the lab conditions do not fully match the target environment, that additional configuration is required, or that the vulnerability requires manual interaction. The investigation steps and collected data above provide context for further manual testing.`
              }
            </p>
          </div>
        </div>
      </div>`;
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
    container.innerHTML = cards.map(([label, val]) => {
      const id = 'cp-' + Math.random().toString(36).slice(2);
      return `<div class="ev-card">
        <div class="ev-card-head">${escHtml(label)}</div>
        <div class="ev-card-body">
          <span class="ev-val">${escHtml(String(val))}</span>
          <button class="copy-btn" data-val="${escHtml(String(val))}" data-id="${id}" id="${id}">COPY</button>
        </div>
      </div>`;
    }).join('');
    container.querySelectorAll('.copy-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const v = btn.dataset.val;
        navigator.clipboard.writeText(v).then(() => {
          btn.textContent = 'COPIED'; btn.classList.add('copied');
          setTimeout(() => { btn.textContent = 'COPY'; btn.classList.remove('copied'); }, 1500);
        }).catch(() => {
          const sel = document.createElement('textarea');
          sel.value = v; document.body.appendChild(sel);
          sel.select(); document.execCommand('copy');
          document.body.removeChild(sel);
          btn.textContent = 'COPIED'; btn.classList.add('copied');
          setTimeout(() => { btn.textContent = 'COPY'; btn.classList.remove('copied'); }, 1500);
        });
      });
    });
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

  function renderBinary(d) {
    const ev = d.evidence || {};
    const binaryKeys = ['binary_analysis','static_analysis','decompilation',
                        'native_analysis','android_analysis','strings_analysis',
                        'checksec','disassembly','jadx_output','ghidra_output'];
    const findings = [];
    for (const k of binaryKeys) {
      if (ev[k]) findings.push([k.replace(/_/g,' '), ev[k]]);
    }
    // also collect any log lines that look binary-related
    const binPatterns = /disasm|decompil|jadx|ghidra|objdump|checksec|strings|native|\.so\b|\.apk\b|\.dex\b|reversing|IDA|radare|r2\b|firmware/i;
    const binLogs = (_logPhases || []).flatMap(ph =>
      ph.entries.filter(e => binPatterns.test(e.msg))
    );
    if (binLogs.length) {
      findings.push(['Reversing Log Entries', binLogs.map(e => `[${e.t}s] ${e.msg}`).join('\n')]);
    }

    const btn = $('tab-btn-binary');
    if (findings.length) {
      btn.style.display = '';
      $('binary-content').innerHTML = findings.map(([label, val]) => `
        <div class="binary-finding">
          <div class="binary-finding-head">${escHtml(label)}</div>
          <div class="binary-finding-body">${escHtml(String(val))}</div>
        </div>`).join('');
    } else {
      btn.style.display = 'none';
      $('binary-content').innerHTML = '<div class="empty-msg">No binary analysis data for this CVE</div>';
    }
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
  $('export-btn').addEventListener('click', () => {
    // Switch to report tab so print CSS picks it up
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    document.querySelector('[data-tab="report"]').classList.add('active');
    $('tab-report').classList.add('active');
    setTimeout(() => window.print(), 80);
  });

  // ── history panel ─────────────────────────────────────────────────────────
  let _historyData = [];
  let _activeHistJobId = null;

  async function loadHistory() {
    try {
      const r = await fetch('/api/history');
      _historyData = await r.json();
      renderHistoryList();
      $('hist-count').textContent = _historyData.length;
    } catch {}
  }

  function renderHistoryList() {
    const list = $('hist-list');
    if (!_historyData.length) {
      list.innerHTML = '<div class="hist-empty">No previous investigations</div>';
      return;
    }
    list.innerHTML = _historyData.map(rec => {
      const icon = rec.verified ? 'CONF' : 'FAIL';
      const iconColor = rec.verified ? 'var(--green)' : 'var(--yellow)';
      const dt = new Date(rec.created * 1000);
      const dtStr = dt.toLocaleDateString('en-GB', {month:'short',day:'numeric'})
                  + ' ' + dt.toLocaleTimeString('en-GB', {hour:'2-digit',minute:'2-digit'});
      const elapsed = rec.elapsed ? rec.elapsed.toFixed(1) + 's' : '';
      const isActive = rec.job_id === _activeHistJobId ? ' active' : '';
      const iconBg = rec.verified ? 'rgba(0,230,118,.15)' : 'rgba(255,210,0,.12)';
      const iconBorder = rec.verified ? 'rgba(0,230,118,.35)' : 'rgba(255,210,0,.3)';
      return `<div class="hist-item${isActive}" data-jid="${escHtml(rec.job_id)}" data-cve="${escHtml(rec.cve_id)}">
        <span class="hist-icon" style="color:${iconColor};background:${iconBg};border:1px solid ${iconBorder}">${icon}</span>
        <div style="flex:1;min-width:0">
          <div class="hist-cve">${escHtml(rec.cve_id)}</div>
          <div class="hist-meta">${dtStr}${elapsed ? ' · ' + elapsed : ''}</div>
        </div>
      </div>`;
    }).join('');

    list.querySelectorAll('.hist-item').forEach(el => {
      el.addEventListener('click', () => {
        const jobId = el.dataset.jid;
        const cveId = el.dataset.cve;
        openHistoryItem(jobId, cveId);
      });
    });
  }

  async function openHistoryItem(jobId, cveId) {
    closeHistPanel();
    _activeHistJobId = jobId;
    // Reset UI for the loaded run
    _logPhases = []; _currentPhase = null;
    $('log-terminal').innerHTML = '<div class="empty-msg">Loading from history…</div>';
    $('verdict').style.display = 'none';
    $('export-btn').disabled = true;
    $('cve-input').value = cveId;

    try {
      const r = await fetch('/api/result/' + jobId);
      if (!r.ok) { alert('Could not load history item'); return; }
      const d = await r.json();

      // Replay logs
      $('log-terminal').innerHTML = '';
      (d.logs || []).forEach(entry => appendLog(entry.t, entry.msg));

      renderResult(d);
      $('export-btn').disabled = false;
      setStatus(d.verified ? 'ok' : 'fail', d.verified ? `CONFIRMED: ${cveId}` : `NOT CONFIRMED: ${cveId}`);
    } catch (e) {
      alert('Error loading history: ' + e);
    }
    renderHistoryList();  // refresh active highlight
  }

  function openHistPanel() {
    $('hist-panel').classList.add('open');
    $('hist-overlay').classList.add('open');
    loadHistory();
  }
  function closeHistPanel() {
    $('hist-panel').classList.remove('open');
    $('hist-overlay').classList.remove('open');
  }

  $('history-btn').addEventListener('click', openHistPanel);
  $('hist-close').addEventListener('click', closeHistPanel);
  $('hist-overlay').addEventListener('click', closeHistPanel);

  // Load count on page load
  loadHistory();

  // ── utils ─────────────────────────────────────────────────────────────────
  function escHtml(s) {
    return String(s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // ── Ask Oracle ───────────────────────────────────────────────────────────
  (function () {
    const askBtn = $('ask-btn');
    const askInput = $('ask-input');
    const askTerm = $('ask-terminal');
    if (!askBtn) return;

    function runAsk() {
      const q = askInput.value.trim();
      if (!q) return;
      askBtn.disabled = true;
      askTerm.innerHTML = '';
      appendAskLine('> ' + q, 'ask-q-line');
      fetch('/api/binary/run', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({file_id: '__ask__', cmd: '__ask__', extra: [q]}),
      }).then(r => r.json()).then(d => {
        if (!d.job_id) { appendAskLine('Error: ' + JSON.stringify(d)); askBtn.disabled = false; return; }
        const es = new EventSource('/api/binary/stream/' + d.job_id);
        es.addEventListener('line', e => appendAskLine(JSON.parse(e.data)));
        es.addEventListener('done', () => { es.close(); askBtn.disabled = false; });
        es.onerror = () => { es.close(); askBtn.disabled = false; };
      }).catch(e => { appendAskLine('Error: ' + e); askBtn.disabled = false; });
    }

    function appendAskLine(line, cls) {
      const div = document.createElement('div');
      if (cls) div.className = cls;
      else if (line.startsWith('[OK]') || line.startsWith('OK:')) div.style.color = 'var(--green)';
      else if (line.startsWith('[ERR]') || line.startsWith('error')) div.style.color = '#ff4444';
      div.textContent = line;
      if (askTerm.querySelector('.empty-msg')) askTerm.innerHTML = '';
      askTerm.appendChild(div);
      askTerm.scrollTop = askTerm.scrollHeight;
    }

    askBtn.addEventListener('click', runAsk);
    askInput.addEventListener('keydown', e => { if (e.key === 'Enter') runAsk(); });
  })();

  // ── Tools Catalog ─────────────────────────────────────────────────────────
  (function () {
    const TOOLS = [
      // CVE
      {name:'cve',       cat:'CVE',       cli:'binoracle cve CVE-XXXX-YYYY',   desc:'Full autonomous CVE verification in an isolated lab'},
      {name:'cveplan',   cat:'CVE',       cli:'binoracle cveplan CVE-XXXX',    desc:'Plan exploitation strategy for a CVE without running it'},
      {name:'triage',    cat:'CVE',       cli:'binoracle triage CVE-XXXX',     desc:'Quick triage: exploitability and impact assessment'},
      {name:'hunt',      cat:'CVE',       cli:'binoracle hunt --target URL',   desc:'Autonomous vulnerability hunting against a target'},
      {name:'scan',      cat:'CVE',       cli:'binoracle scan TARGET',         desc:'Broad vulnerability scan of a target application'},
      {name:'cve-chain', cat:'CVE',       cli:'binoracle cve-chain ...',       desc:'Chain multiple CVEs into an exploit sequence'},
      // Binary static
      {name:'identify',  cat:'BINARY',    cli:'binoracle identify FILE',       desc:'Identify file type and architecture (ELF/PE/APK/…)'},
      {name:'elf',       cat:'BINARY',    cli:'binoracle elf FILE',            desc:'ELF layout, sections, mitigations (NX/PIE/RELRO/canary)'},
      {name:'pe',        cat:'BINARY',    cli:'binoracle pe FILE',             desc:'Windows PE/DLL: imports, exports, sections, mitigations'},
      {name:'macho',     cat:'BINARY',    cli:'binoracle macho FILE',          desc:'Mach-O binary analysis (macOS/iOS)'},
      {name:'apk',       cat:'BINARY',    cli:'binoracle apk FILE',            desc:'Android APK: permissions, manifest, native libs'},
      {name:'java',      cat:'BINARY',    cli:'binoracle java FILE',           desc:'JAR/.class: manifest, entry points, hardcoded creds'},
      {name:'dotnet',    cat:'BINARY',    cli:'binoracle dotnet FILE',         desc:'.NET/CLI managed assembly static analysis'},
      {name:'wasm',      cat:'BINARY',    cli:'binoracle wasm FILE',           desc:'WebAssembly: sections, imports, exports, types'},
      {name:'go',        cat:'BINARY',    cli:'binoracle go FILE',             desc:'Go binary: version, modules, build settings'},
      {name:'rust',      cat:'BINARY',    cli:'binoracle rust FILE',           desc:'Rust binary: rustc version, Cargo dependencies'},
      {name:'firmware',  cat:'BINARY',    cli:'binoracle firmware FILE',       desc:'Firmware: UEFI, SquashFS images'},
      {name:'core',      cat:'BINARY',    cli:'binoracle core FILE',           desc:'ELF core dump: signal, threads, crash context'},
      {name:'rawshellcode',cat:'BINARY',  cli:'binoracle rawshellcode FILE',   desc:'Disassemble raw shellcode (no ELF/PE wrapper)'},
      {name:'jeb',       cat:'BINARY',    cli:'binoracle jeb FILE',            desc:'JEB decompiler integration for Android/Java'},
      // Exploitation
      {name:'gadgets',   cat:'EXPLOIT',   cli:'binoracle gadgets FILE',        desc:'Search ROP gadgets in a binary'},
      {name:'arsenal',   cat:'EXPLOIT',   cli:'binoracle arsenal FILE',        desc:'Best gadget per arg register, syscall, pivot, one_gadget'},
      {name:'rop',       cat:'EXPLOIT',   cli:'binoracle rop FILE',            desc:'Build a ROP chain (ret2libc / execve) with pwntools'},
      {name:'shellcode', cat:'EXPLOIT',   cli:'binoracle shellcode ARCH',      desc:'Generate shellcode (execve /bin/sh, cat) with pwntools'},
      {name:'fmtstring', cat:'EXPLOIT',   cli:'binoracle fmtstring FILE',      desc:'Format-string leak/write helper'},
      {name:'primitives',cat:'EXPLOIT',   cli:'binoracle primitives FILE',     desc:'Binary exploitation primitives (UAF, ROP, dirty-pipe)'},
      {name:'heap',      cat:'EXPLOIT',   cli:'binoracle heap FILE',           desc:'Heap analysis and exploit primitive finder'},
      {name:'kernel-exploit',cat:'EXPLOIT',cli:'binoracle kernel-exploit ...',desc:'Kernel exploit strategy and helpers'},
      {name:'autopoc',   cat:'EXPLOIT',   cli:'binoracle autopoc FILE',        desc:'Generate a proof-of-concept exploit automatically'},
      {name:'autopwn',   cat:'EXPLOIT',   cli:'binoracle autopwn FILE',        desc:'Fully autonomous exploit generation and execution'},
      {name:'fuzz',      cat:'EXPLOIT',   cli:'binoracle fuzz FILE',           desc:'Generate a fuzzing harness (libFuzzer / AFL)'},
      {name:'cyclic',    cat:'EXPLOIT',   cli:'binoracle cyclic N',            desc:'Generate/lookup cyclic pattern for offset finding'},
      {name:'exploit-skeleton',cat:'EXPLOIT',cli:'binoracle exploit-skeleton FILE',desc:'Pwntools exploit skeleton scaffolding'},
      // Analysis
      {name:'analyze',   cat:'ANALYSIS',  cli:'binoracle analyze FILE',        desc:'Full one-shot analysis: .c source or binary'},
      {name:'explain',   cat:'ANALYSIS',  cli:'binoracle explain FILE',        desc:'Explain what a binary or function does in plain English'},
      {name:'ask',       cat:'ANALYSIS',  cli:'binoracle ask "question"',      desc:'Ask a grounded question about a binary or CVE'},
      {name:'chat',      cat:'ANALYSIS',  cli:'binoracle chat',                desc:'Interactive chat session with the Oracle'},
      {name:'diff',      cat:'ANALYSIS',  cli:'binoracle diff A B',            desc:'Diff two binaries or versions to find the patch'},
      {name:'funcid',    cat:'ANALYSIS',  cli:'binoracle funcid FILE',         desc:'Function identification via signature matching'},
      {name:'audit',     cat:'ANALYSIS',  cli:'binoracle audit FILE',          desc:'Security audit of a binary or source file'},
      {name:'secrets',   cat:'ANALYSIS',  cli:'binoracle secrets FILE',        desc:'Scan for hardcoded secrets, keys, tokens'},
      {name:'verify',    cat:'ANALYSIS',  cli:'binoracle verify CVE FILE',     desc:'Verify a CVE against a specific binary'},
      {name:'view',      cat:'ANALYSIS',  cli:'binoracle view FILE',           desc:'Build an interactive HTML report and open in browser'},
      {name:'report',    cat:'ANALYSIS',  cli:'binoracle report FILE',         desc:'Generate a professional security report'},
      // Data formats
      {name:'evm',       cat:'DATA',      cli:'binoracle evm FILE',            desc:'EVM bytecode: selectors, opcodes, storage slots'},
      {name:'har',       cat:'DATA',      cli:'binoracle har FILE',            desc:'HAR network capture: requests, hosts, auth headers'},
      {name:'sqlite',    cat:'DATA',      cli:'binoracle sqlite FILE',         desc:'SQLite: schema, table contents (read-only)'},
      {name:'asar',      cat:'DATA',      cli:'binoracle asar FILE',           desc:'Electron ASAR archive: file tree, entry point'},
      {name:'plist',     cat:'DATA',      cli:'binoracle plist FILE',          desc:'Apple plist (Info.plist) static analysis'},
      {name:'js',        cat:'DATA',      cli:'binoracle js FILE',             desc:'JavaScript static analysis'},
      // Dynamic
      {name:'dynamic',   cat:'DYNAMIC',   cli:'binoracle dynamic ...',         desc:'Dynamic analysis: ADB, Frida, browser instrumentation'},
      // Learning
      {name:'rag',       cat:'LEARN',     cli:'binoracle rag',                 desc:'Retrieval-augmented knowledge base'},
      {name:'kb',        cat:'LEARN',     cli:'binoracle kb',                  desc:'Local knowledge base management'},
      {name:'learn',     cat:'LEARN',     cli:'binoracle learn',               desc:'Feed new knowledge to the Oracle'},
      {name:'doctor',    cat:'SYSTEM',    cli:'binoracle doctor',              desc:'Check environment, tools and dependencies'},
    ];

    const grid = document.getElementById('tools-grid');
    const searchEl = document.getElementById('tools-search');
    if (!grid) return;

    const CATS_ORDER = ['CVE','BINARY','EXPLOIT','ANALYSIS','DATA','DYNAMIC','LEARN','SYSTEM'];

    function renderCatalog(filter) {
      const f = (filter || '').toLowerCase();
      const matched = TOOLS.filter(t =>
        !f || t.name.includes(f) || t.desc.toLowerCase().includes(f) || t.cat.toLowerCase().includes(f));
      let html = '';
      const bycat = {};
      for (const t of matched) {
        (bycat[t.cat] = bycat[t.cat]||[]).push(t);
      }
      for (const cat of CATS_ORDER) {
        if (!bycat[cat]) continue;
        html += `<div class="tool-cat-header">${cat}</div>`;
        for (const t of bycat[cat]) {
          html += `<div class="tool-card" data-name="${escHtml(t.name)}">
            <div class="tool-card-name">${escHtml(t.name)}</div>
            <div class="tool-card-desc">${escHtml(t.desc)}</div>
            <div class="tool-card-cli">${escHtml(t.cli)}</div>
          </div>`;
        }
      }
      grid.innerHTML = html || '<div class="empty-msg">No tools match</div>';

      // clicking a CVE tool fills the CVE input and switches tab
      grid.querySelectorAll('.tool-card').forEach(card => {
        card.addEventListener('click', () => {
          const name = card.dataset.name;
          if (name === 'cve' || name === 'cveplan' || name === 'triage') {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            document.querySelector('[data-tab="log"]').classList.add('active');
            $('tab-log').classList.add('active');
            $('cve-input').focus();
          } else if (['identify','elf','pe','macho','apk','java','dotnet','wasm','go','rust',
                       'firmware','core','rawshellcode','jeb','gadgets','arsenal','rop',
                       'shellcode','fmtstring','primitives','heap','autopoc','autopwn',
                       'fuzz','analyze','funcid','secrets','evm','har','sqlite','asar','plist','js'].includes(name)) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            document.querySelector('[data-tab="binlab"]').classList.add('active');
            $('tab-binlab').classList.add('active');
          } else if (name === 'ask' || name === 'chat' || name === 'explain') {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            document.querySelector('[data-tab="ask"]').classList.add('active');
            $('tab-ask').classList.add('active');
            $('ask-input').focus();
          }
        });
      });
    }

    renderCatalog('');
    if (searchEl) searchEl.addEventListener('input', () => renderCatalog(searchEl.value));
  })();

  // ── Binary Lab ────────────────────────────────────────────────────────────
  (function () {
    let _binFileId = null;
    let _binEs = null;

    const STATIC_TOOLS = [
      {cmd: 'identify',  label: 'Identify'},
      {cmd: 'elf',       label: 'ELF'},
      {cmd: 'pe',        label: 'PE / DLL'},
      {cmd: 'macho',     label: 'Mach-O'},
      {cmd: 'apk',       label: 'APK'},
      {cmd: 'java',      label: 'JAR / Class'},
      {cmd: 'wasm',      label: 'WASM'},
      {cmd: 'dotnet',    label: '.NET'},
      {cmd: 'go',        label: 'Go'},
      {cmd: 'rust',      label: 'Rust'},
      {cmd: 'firmware',  label: 'Firmware'},
      {cmd: 'har',       label: 'HAR'},
      {cmd: 'sqlite',    label: 'SQLite'},
      {cmd: 'evm',       label: 'EVM'},
      {cmd: 'asar',      label: 'ASAR'},
      {cmd: 'plist',     label: 'Plist'},
      {cmd: 'js',        label: 'JavaScript'},
      {cmd: 'rawshellcode', label: 'Raw Shellcode'},
      {cmd: 'core',      label: 'Core Dump'},
      {cmd: 'jeb',       label: 'JEB'},
    ];

    const staticRow = document.getElementById('binlab-static-row');
    if (staticRow) {
      staticRow.innerHTML = STATIC_TOOLS.map(t =>
        `<button class="binlab-tool-btn" data-cmd="${t.cmd}">${t.label}</button>`
      ).join('');
    }

    const drop = document.getElementById('binlab-drop');
    const fileInput = document.getElementById('binlab-file');
    const binInfo = document.getElementById('binlab-info');
    const fnEl = document.getElementById('binlab-fname');
    const fsEl = document.getElementById('binlab-fsize');
    const clearBtn = document.getElementById('binlab-clear');
    const terminal = document.getElementById('binlab-terminal');

    if (!drop) return;

    drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('drag-over'); });
    drop.addEventListener('dragleave', () => drop.classList.remove('drag-over'));
    drop.addEventListener('drop', e => {
      e.preventDefault(); drop.classList.remove('drag-over');
      const f = e.dataTransfer.files[0]; if (f) handleFile(f);
    });
    drop.addEventListener('click', e => {
      if (e.target !== fileInput) fileInput.click();
    });
    if (fileInput) fileInput.addEventListener('change', e => {
      const f = e.target.files[0]; if (f) handleFile(f);
    });

    async function handleFile(file) {
      drop.style.display = 'none';
      binInfo.style.display = 'block';
      fnEl.textContent = file.name;
      fsEl.textContent = '(' + (file.size > 1048576
        ? (file.size/1048576).toFixed(1)+'MB'
        : Math.round(file.size/1024)+'KB') + ')';
      terminal.innerHTML = '<div class="empty-msg">Uploading…</div>';

      // Read as base64
      const ab = await file.arrayBuffer();
      const bytes = new Uint8Array(ab);
      let binary = '';
      const chunk = 8192;
      for (let i = 0; i < bytes.length; i += chunk)
        binary += String.fromCharCode(...bytes.subarray(i, i+chunk));
      const b64 = btoa(binary);

      try {
        const r = await fetch('/api/binary/upload', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({filename: file.name, data: b64}),
        });
        const d = await r.json();
        if (!d.file_id) { terminal.textContent = 'Upload failed: ' + JSON.stringify(d); return; }
        _binFileId = d.file_id;
        terminal.innerHTML = `<span class="bl-line-ok">File uploaded (${d.size} bytes). Select a tool above to analyze.</span>`;
        // Auto-run identify
        runBinTool('identify');
      } catch (e) {
        terminal.textContent = 'Upload error: ' + e;
      }
    }

    if (clearBtn) clearBtn.addEventListener('click', () => {
      _binFileId = null;
      if (_binEs) { _binEs.close(); _binEs = null; }
      drop.style.display = '';
      binInfo.style.display = 'none';
      terminal.innerHTML = '<div class="empty-msg">Select a tool above to run</div>';
      if (fileInput) fileInput.value = '';
    });

    document.querySelectorAll('#tab-binlab .binlab-tool-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        if (!_binFileId) { terminal.textContent = 'Upload a file first.'; return; }
        runBinTool(btn.dataset.cmd);
      });
    });

    function runBinTool(cmd) {
      if (!_binFileId) return;
      if (_binEs) { _binEs.close(); _binEs = null; }
      terminal.innerHTML = '';
      document.querySelectorAll('#tab-binlab .binlab-tool-btn').forEach(b => {
        b.classList.toggle('running', b.dataset.cmd === cmd);
      });

      fetch('/api/binary/run', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({file_id: _binFileId, cmd}),
      }).then(r => r.json()).then(d => {
        if (!d.job_id) { terminal.textContent = 'Error: ' + JSON.stringify(d); return; }
        const es = new EventSource('/api/binary/stream/' + d.job_id);
        _binEs = es;
        es.addEventListener('line', e => {
          const line = JSON.parse(e.data);
          appendBinLine(line);
        });
        es.addEventListener('done', () => {
          es.close(); _binEs = null;
          document.querySelectorAll('#tab-binlab .binlab-tool-btn').forEach(b => b.classList.remove('running'));
        });
        es.onerror = () => { es.close(); _binEs = null; };
      }).catch(e => { terminal.textContent = 'Error: ' + e; });
    }

    function appendBinLine(line) {
      const div = document.createElement('div');
      let cls = '';
      if (line.startsWith('[OK]') || line.startsWith('OK:'))  cls = 'bl-line-ok';
      else if (line.startsWith('[ERR]') || line.startsWith('ERROR') || line.startsWith('error')) cls = 'bl-line-err';
      else if (line.startsWith('[WARN]') || line.startsWith('WARN'))  cls = 'bl-line-warn';
      else if (line.startsWith('──') || line.startsWith('===') || line.startsWith('---')) cls = 'bl-line-sep';
      else if (line.match(/^[A-Z][A-Z _]{2,}:?\s*$/)) cls = 'bl-line-head';
      if (cls) div.className = cls;
      div.textContent = line;
      if (terminal.querySelector('.empty-msg')) terminal.innerHTML = '';
      terminal.appendChild(div);
      terminal.scrollTop = terminal.scrollHeight;
    }
  })();

})();
</script>
</body>
</html>"""
