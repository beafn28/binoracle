#!/usr/bin/env python3
"""
gen_evidence_pages.py — Generate visual evidence pages for dynamically verified CVEs.

For each CVE with dynamic_verify.verified=True, produces a professional HTML page
showing: confirmation summary, Burp-style HTTP request/response, screenshots gallery,
and lab logs. Also patches index.html with an EVIDENCIA button for each confirmed CVE.

Usage:
    python3 scripts/gen_evidence_pages.py
"""
import json
import os
import re
import sys
from html import escape

BATCH_DIR = os.path.join(os.path.dirname(__file__), "..", "binoracle_batch_reports")
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")
INDEX_HTML = os.path.join(os.path.dirname(__file__), "..", "index.html")

BATCH_DIR = os.path.realpath(BATCH_DIR)
REPORTS_DIR = os.path.realpath(REPORTS_DIR)
INDEX_HTML = os.path.realpath(INDEX_HTML)

os.makedirs(REPORTS_DIR, exist_ok=True)


def _h(s: str) -> str:
    return escape(str(s) if s is not None else "")


def _status_cls(code) -> str:
    try:
        c = int(code)
        if 200 <= c < 300: return "s2xx"
        if 300 <= c < 400: return "s3xx"
        if 400 <= c < 500: return "s4xx"
    except Exception:
        pass
    return "s5xx"


def _status_text(code) -> str:
    texts = {200:"OK",201:"Created",204:"No Content",301:"Moved",302:"Found",
             400:"Bad Request",401:"Unauthorized",403:"Forbidden",404:"Not Found",
             405:"Method Not Allowed",422:"Unprocessable Entity",
             500:"Internal Server Error",503:"Service Unavailable"}
    try:
        return texts.get(int(code), "")
    except Exception:
        return ""


def _vuln_color(vuln_class: str) -> str:
    mapping = {
        "sqli": "#1d4ed8", "sql": "#1d4ed8",
        "xss": "#7c3aed",
        "rce": "#b91c1c", "code-injection": "#b91c1c",
        "path-traversal": "#0369a1",
        "file-upload": "#c2410c",
        "ssrf": "#0d9488",
        "auth-bypass": "#d97706", "missing-authorization": "#d97706",
        "command-injection": "#dc2626",
        "ssti": "#7c2d12",
    }
    cls = (vuln_class or "").lower()
    for key, color in mapping.items():
        if key in cls:
            return color
    return "#374151"


def _reconstruct_request(ve: dict, llm: dict) -> str:
    """Build a raw HTTP request string from evidence fields."""
    method = ve.get("metodo") or llm.get("http_method") or "POST"
    endpoint = ve.get("endpoint") or llm.get("endpoint") or "/"
    payload_winner = ve.get("payload_ganador") or ""
    sqli_param = ve.get("sqli_param") or ""
    path_param = ve.get("path_param") or ""
    params = llm.get("parameters") or {}
    custom_headers = llm.get("custom_headers") or {}
    login_user = ve.get("login_bajo_privilegio") or ""
    login_pass = ve.get("login_bajo_privilegio_password") or ""

    lines = [f"{method} {endpoint} HTTP/1.1"]
    lines.append("Host: target-lab")
    lines.append("User-Agent: Mozilla/5.0 (binoracle-lab)")

    # Content-type based on method/params
    has_body = method in ("POST", "PUT", "PATCH")
    if has_body:
        # Detect content type from params structure
        if isinstance(params, dict) and params:
            lines.append("Content-Type: application/json")
        else:
            lines.append("Content-Type: application/x-www-form-urlencoded")

    # Custom headers
    for k, v in custom_headers.items():
        if k.lower() not in ("host", "content-type", "user-agent"):
            lines.append(f"{k}: {v}")

    # Auth cookie
    if login_user:
        lines.append(f"Cookie: wordpress_logged_in_[hash]=[session-{login_user}]")

    lines.append("")  # blank line before body

    # Build body or query string
    if method == "GET":
        # For GET with SQLi, inject param into URL
        if sqli_param and payload_winner:
            # Show the endpoint with the SQLi param highlighted
            if "?" not in endpoint:
                lines[0] = f"GET {endpoint}?{sqli_param}={payload_winner} HTTP/1.1"
            else:
                lines[0] = f"GET {endpoint}&{sqli_param}={payload_winner} HTTP/1.1"
        elif path_param and payload_winner:
            # Path traversal: show param
            if "?" not in endpoint:
                lines[0] = f"GET {endpoint}?{path_param}={payload_winner} HTTP/1.1"
        # GET body is empty
        lines.append("")
    else:
        # POST/PUT body
        if isinstance(params, dict) and params:
            # Inject winning payload into params
            body_params = dict(params)
            if payload_winner:
                # Find the most likely injection param and replace
                for key in body_params:
                    if any(kw in key.lower() for kw in ["query", "args", "payload", "cmd", "code", "template", "input", "value", "data"]):
                        body_params[key] = payload_winner
                        break
                else:
                    # Put it in the first param
                    first = list(body_params.keys())[0]
                    body_params[first] = payload_winner
            lines.append(json.dumps(body_params, ensure_ascii=False))
        elif payload_winner:
            lines.append(f"data={payload_winner}")
        else:
            lines.append("")

    return "\n".join(lines)


def _reconstruct_response(ve: dict, dv: dict) -> str:
    """Build a raw HTTP response string from evidence fields."""
    status = ve.get("status_code_respuesta")
    body = ve.get("respuesta_cuerpo_recorte") or ""
    mysql_ver = ve.get("mysql_version_extraida") or ""
    marker = ve.get("marker") or ve.get("marcador_confirmado") or ""

    if not status:
        status = "200"

    status_txt = _status_text(status)
    lines = [
        f"HTTP/1.1 {status} {status_txt}",
        "Content-Type: text/html; charset=UTF-8",
        "X-Powered-By: PHP",
        "",
    ]

    # Add body
    if body:
        lines.append(body[:2000])
    elif mysql_ver:
        lines.append(f"MySQL version confirmed: {mysql_ver}")
    elif marker:
        lines.append(f"Confirmation marker: {marker}")

    return "\n".join(lines)


def _highlight_in_pre(text: str, highlights: list) -> str:
    """Escape HTML then wrap highlight strings in <mark>."""
    escaped = escape(text)
    for h in highlights:
        if h and len(h) > 2:
            escaped = escaped.replace(escape(h),
                f'<mark style="background:#f9a825;color:#000;padding:1px 3px;border-radius:2px;font-weight:700">{escape(h)}</mark>',
                1)
    return escaped


def _burp_highlight_request(raw: str, payload: str) -> str:
    """Color-code the raw HTTP request for display."""
    lines = raw.split("\n")
    out = []
    is_body = False
    for i, line in enumerate(lines):
        if i == 0:
            # Method line
            out.append(f'<span style="color:#fff;font-weight:700">{_h(line)}</span>')
        elif not is_body and line == "":
            is_body = True
            out.append("")
        elif not is_body and ":" in line:
            # Header
            k, _, v = line.partition(":")
            out.append(
                f'<span style="color:#9cdcfe">{_h(k)}</span>'
                f'<span style="color:#94a3b8">:</span>'
                f'<span style="color:#ce9178">{_h(v)}</span>'
            )
        else:
            # Body — highlight the payload
            highlighted = _highlight_in_pre(line, [payload])
            out.append(highlighted)
    return "\n".join(out)


def _burp_highlight_response(raw: str, markers: list) -> str:
    """Color-code the raw HTTP response, highlighting confirmation markers."""
    lines = raw.split("\n")
    out = []
    is_body = False
    for i, line in enumerate(lines):
        if i == 0:
            out.append(f'<span style="color:#fff;font-weight:700">{_h(line)}</span>')
        elif not is_body and line == "":
            is_body = True
            out.append("")
        elif not is_body and ":" in line:
            k, _, v = line.partition(":")
            out.append(
                f'<span style="color:#9cdcfe">{_h(k)}</span>'
                f'<span style="color:#94a3b8">:</span>'
                f'<span style="color:#ce9178">{_h(v)}</span>'
            )
        else:
            highlighted = _highlight_in_pre(line, markers)
            out.append(highlighted)
    return "\n".join(out)


CSS = """
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0a0f1a;--surf:#050a14;--surf2:#0d1424;--surf3:#111827;
  --brd:#1e293b;--fg:#e2e8f0;--mut:#475569;--acc:#38bdf8;--grn:#22c55e;
  --red:#ef4444;--yel:#f59e0b;--mono:'JetBrains Mono',monospace;--sans:'Inter',sans-serif;
  color-scheme:dark}
body{background:var(--bg);color:var(--fg);font-family:var(--sans);font-size:13px;
  line-height:1.6;padding:0 0 60px}
a{color:var(--acc)}
/* header */
.hdr{background:var(--surf);border-bottom:2px solid var(--brd);padding:16px 32px;
  display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.brand{font-size:20px;font-weight:900;color:var(--acc);font-family:var(--mono);flex-shrink:0}
.hdr-cve{font-family:var(--mono);font-size:14px;font-weight:700;color:var(--acc);
  background:rgba(56,189,248,.1);border:1px solid rgba(56,189,248,.3);border-radius:5px;
  padding:3px 10px}
.badge-verified{background:#065f46;color:var(--grn);border:1px solid rgba(34,197,94,.4);
  border-radius:5px;padding:4px 12px;font-size:11px;font-weight:800;letter-spacing:.08em;
  font-family:var(--mono)}
.badge-cvss{border-radius:5px;padding:3px 10px;font-size:11px;font-weight:700;color:#fff}
.badge-cls{border-radius:5px;padding:3px 10px;font-size:11px;font-weight:700;color:#fff}
.hdr-spacer{flex:1}
.hdr-date{color:var(--mut);font-size:11px}
/* conf banner */
.conf{background:#7c1b1b;color:#fecaca;font-size:10px;font-weight:700;text-align:center;
  padding:5px;letter-spacing:.08em}
/* content */
.wrap{max-width:1200px;margin:0 auto;padding:28px 32px}
.section{margin-bottom:28px}
.section-title{font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;
  color:var(--mut);margin-bottom:12px;font-family:var(--sans)}
/* summary box */
.summary-box{background:#052e1a;border:2px solid rgba(34,197,94,.4);border-radius:12px;
  padding:20px 24px}
.summary-detail{font-size:13px;color:#bbf7d0;line-height:1.65;margin-bottom:14px;
  font-family:var(--mono)}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));
  gap:10px;margin-top:12px}
.summary-field{background:rgba(0,0,0,.3);border-radius:8px;padding:10px 14px}
.sf-label{font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;
  color:#4ade80;margin-bottom:4px}
.sf-value{font-family:var(--mono);font-size:12px;color:#bbf7d0;word-break:break-all}
/* burp panels */
.burp-wrap{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:800px){.burp-wrap{grid-template-columns:1fr}}
.burp-panel{background:var(--surf2);border:2px solid var(--brd);border-radius:12px;overflow:hidden}
.burp-hdr{background:#0d1117;border-bottom:2px solid var(--brd);padding:10px 16px;
  display:flex;align-items:center;gap:10px}
.burp-method{font-family:var(--mono);font-weight:700;font-size:12px;padding:3px 10px;
  border-radius:4px;color:#fff;flex-shrink:0}
.GET{background:#15803d} .POST{background:#1d4ed8} .PUT{background:#9333ea}
.DELETE{background:#dc2626} .PATCH{background:#d97706}
.burp-url{font-family:var(--mono);font-size:12px;color:#9cdcfe;flex:1;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.burp-status{font-family:var(--mono);font-weight:700;font-size:12px;padding:3px 10px;border-radius:4px;flex-shrink:0}
.s2xx{background:rgba(26,127,55,.25);color:#4ade80;border:1px solid rgba(26,127,55,.4)}
.s3xx{background:rgba(234,179,8,.15);color:#facc15;border:1px solid rgba(234,179,8,.3)}
.s4xx{background:rgba(207,34,46,.15);color:#f87171;border:1px solid rgba(207,34,46,.3)}
.s5xx{background:rgba(207,34,46,.2);color:#f87171;border:1px solid rgba(207,34,46,.35)}
.burp-pane-title{font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;
  color:var(--mut);margin-bottom:8px;display:flex;align-items:center;gap:8px}
.copy-btn{font-size:9px;background:var(--surf3);border:1px solid var(--brd);border-radius:3px;
  padding:1px 7px;color:var(--mut);cursor:pointer;font-family:var(--mono);transition:background .15s}
.copy-btn:hover{background:var(--acc);color:#fff}
.burp-body{font-family:var(--mono);font-size:12px;white-space:pre-wrap;word-break:break-all;
  line-height:1.65;color:#d4d4d4;background:#1e1e1e;border-radius:6px;
  padding:14px 16px;overflow-x:auto;max-height:420px;overflow-y:auto;margin:14px 14px 14px}
/* screenshots */
.shots-grid{display:flex;flex-direction:column;gap:24px}
.shot-card{background:var(--surf2);border:1px solid var(--brd);border-radius:12px;overflow:hidden}
.shot-hdr{padding:10px 16px;display:flex;align-items:center;gap:10px;
  border-bottom:1px solid var(--brd)}
.shot-num{background:var(--acc);color:#000;font-weight:800;font-size:10px;
  padding:2px 8px;border-radius:12px;font-family:var(--mono)}
.shot-caption{font-size:12px;color:var(--fg);flex:1}
.shot-img-wrap{background:#000;text-align:center;padding:16px}
.shot-img{max-width:100%;max-height:600px;border-radius:6px;display:inline-block}
/* logs */
details{background:var(--surf2);border:1px solid var(--brd);border-radius:8px;overflow:hidden}
details summary{padding:12px 16px;cursor:pointer;font-size:11px;font-weight:700;
  letter-spacing:.1em;text-transform:uppercase;color:var(--mut);list-style:none;
  display:flex;align-items:center;gap:8px}
details summary::-webkit-details-marker{display:none}
details summary::before{content:"▶";font-size:9px;color:var(--mut);transition:transform .2s}
details[open] summary::before{transform:rotate(90deg)}
.log-wrap{padding:14px 16px}
.log-line{font-family:var(--mono);font-size:11px;line-height:1.6;color:#94a3b8;
  white-space:pre-wrap;word-break:break-all}
.log-line.ok{color:#4ade80} .log-line.err{color:#f87171} .log-line.warn{color:#fbbf24}
/* no data */
.no-data{color:var(--mut);font-style:italic;padding:20px;text-align:center}
@media(max-width:700px){.wrap{padding:16px 16px}}
</style>
"""

SCRIPT = """
<script>
function copyText(id){
  const el = document.getElementById(id);
  if(!el) return;
  navigator.clipboard.writeText(el.innerText || el.textContent).catch(()=>{
    const r = document.createRange();
    r.selectNode(el);
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(r);
    document.execCommand('copy');
  });
}
</script>
"""


def _cvss_color(score) -> str:
    try:
        s = float(score)
        if s >= 9.0: return "#b91c1c"
        if s >= 7.0: return "#d97706"
        if s >= 4.0: return "#2563eb"
    except Exception:
        pass
    return "#374151"


def build_page(cve_id: str, rec: dict) -> str:
    ve = rec.get("verified_evidence") or {}
    dv = rec.get("dynamic_verify") or {}
    llm = rec.get("llm_notes") or {}

    cvss_score = rec.get("cvss_score", "")
    cvss_sev = rec.get("cvss_severity", "")
    vuln_class = rec.get("vuln_class") or llm.get("vuln_class") or "?"
    published = rec.get("published", "")

    method = (ve.get("metodo") or llm.get("http_method") or "POST").upper()
    endpoint = ve.get("endpoint") or llm.get("endpoint") or "/"
    payload = ve.get("payload_ganador") or ""
    status = ve.get("status_code_respuesta") or "?"
    response_body = ve.get("respuesta_cuerpo_recorte") or ""
    detail = dv.get("detail") or ""
    screenshots = ve.get("screenshots") or []
    logs = dv.get("logs") or []
    mysql_ver = ve.get("mysql_version_extraida") or ""
    sqli_param = ve.get("sqli_param") or ""
    path_param = ve.get("path_param") or ""
    login_user = ve.get("login_bajo_privilegio") or ""
    is_gap = rec.get("is_gap", False)

    # Determine confirmation markers to highlight
    markers = [m for m in [mysql_ver, ve.get("canary_secret"), ve.get("marker"),
                            ve.get("marcador_confirmado")] if m and len(m) > 3]
    # Also find BIN_ marker in response body
    bin_match = re.search(r'BIN_[0-9a-f]{8,}', response_body)
    if bin_match:
        markers.insert(0, bin_match.group(0))
    if not markers and "root:x:0:0" in response_body:
        markers.append("root:x:0:0")

    # Reconstruct raw HTTP request and response
    raw_req = _reconstruct_request(ve, llm)
    raw_resp = _reconstruct_response(ve, dv)

    # Create a unique ID for the request text (for copy button)
    req_id = f"req_{cve_id.replace('-','_')}"
    resp_id = f"resp_{cve_id.replace('-','_')}"

    # Build summary fields
    summary_fields = []
    if payload:
        summary_fields.append(("Payload confirmado", payload))
    if sqli_param:
        summary_fields.append(("Parámetro SQLi", sqli_param))
    if path_param:
        summary_fields.append(("Parámetro path", path_param))
    if mysql_ver:
        summary_fields.append(("Versión MySQL extraída", mysql_ver))
    summary_fields.append(("Método + endpoint", f"{method} {endpoint}"))
    summary_fields.append(("HTTP status", str(status)))
    if login_user:
        summary_fields.append(("Usuario de lab", login_user))
    if is_gap:
        summary_fields.append(("Tipo CVE", "HUECO — verificado sin PoC público"))

    # Build screenshot blocks
    shots_html = ""
    if screenshots:
        shot_items = []
        for i, sh in enumerate(screenshots):
            caption = sh.get("caption_es") or sh.get("caption_en") or f"Paso {i+1}"
            png_b64 = sh.get("png_b64") or ""
            url = sh.get("url") or ""
            if not png_b64:
                continue
            url_line = f'<div style="font-family:var(--mono);font-size:10px;color:var(--mut);padding:4px 16px 8px">{_h(url)}</div>' if url else ""
            shot_items.append(f"""
<div class="shot-card">
  <div class="shot-hdr">
    <span class="shot-num">PASO {i+1}</span>
    <span class="shot-caption">{_h(caption)}</span>
  </div>
  {url_line}
  <div class="shot-img-wrap">
    <img class="shot-img" src="data:image/png;base64,{png_b64}" alt="Paso {i+1}: {_h(caption)}" loading="lazy">
  </div>
</div>""")
        shots_html = "\n".join(shot_items)
    else:
        shots_html = '<div class="no-data">Sin capturas de pantalla para este CVE (Playwright no disponible en el contenedor del lab)</div>'

    # Build log lines
    logs_html = ""
    if logs:
        log_lines = []
        for entry in logs:
            line = str(entry) if not isinstance(entry, str) else entry
            cls = "ok" if any(k in line for k in ["OK","✓","confirmada","verificada","CONFIRM"]) \
                  else "err" if any(k in line for k in ["ERROR","FAIL","✗","KO"]) \
                  else "warn" if "warn" in line.lower() else ""
            log_lines.append(f'<div class="log-line {cls}">{_h(line)}</div>')
        logs_html = "\n".join(log_lines)
    else:
        logs_html = '<div class="log-line">Sin logs de laboratorio capturados</div>'

    # Summary fields HTML
    sf_html = "\n".join(
        f'<div class="summary-field"><div class="sf-label">{_h(label)}</div><div class="sf-value">{_h(val)}</div></div>'
        for label, val in summary_fields
    )

    page = f"""<!doctype html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_h(cve_id)} — Evidencia Dinámica — bin0racle</title>
{CSS}
{SCRIPT}
</head>
<body>

<div class="conf">CONFIDENCIAL — SOLO PARA OBJETIVOS AUTORIZADOS (PENTEST / CTF / LABORATORIO)</div>

<div class="hdr">
  <div class="brand">bin<span style="color:#f59e0b">0</span>racle</div>
  <div class="hdr-cve">{_h(cve_id)}</div>
  <span class="badge-verified">DINÁMICAMENTE VERIFICADO ✓</span>
  <span class="badge-cvss" style="background:{_cvss_color(cvss_score)}">{_h(cvss_score)} {_h(cvss_sev)}</span>
  <span class="badge-cls" style="background:{_vuln_color(vuln_class)}">{_h(vuln_class)}</span>
  <div class="hdr-spacer"></div>
  <div class="hdr-date">{_h(published)} · Lab Docker efímero</div>
</div>

<div class="wrap">

  <!-- SECTION: Confirmation Summary -->
  <div class="section">
    <div class="section-title">Confirmación de Explotación</div>
    <div class="summary-box">
      <div class="summary-detail">{_h(detail)}</div>
      <div class="summary-grid">{sf_html}</div>
    </div>
  </div>

  <!-- SECTION: HTTP Evidence (Burp-style) -->
  <div class="section">
    <div class="section-title">Petición HTTP — Estilo Burp Suite</div>
    <div class="burp-wrap">
      <div class="burp-panel">
        <div class="burp-hdr">
          <span class="burp-method {_h(method)}">{_h(method)}</span>
          <span class="burp-url" title="{_h(endpoint)}">{_h(endpoint)}</span>
          <span style="font-size:10px;color:var(--mut);font-family:var(--mono)">REQUEST →</span>
        </div>
        <div style="padding:14px 14px 0">
          <div class="burp-pane-title">
            REQUEST
            <button class="copy-btn" onclick="copyText('{req_id}')">COPY</button>
          </div>
        </div>
        <pre class="burp-body" id="{req_id}">{_burp_highlight_request(raw_req, payload)}</pre>
      </div>
      <div class="burp-panel">
        <div class="burp-hdr">
          <span class="burp-status {_status_cls(status)}">HTTP {_h(status)} {_h(_status_text(status))}</span>
          <div class="hdr-spacer"></div>
          <span style="font-size:10px;color:var(--mut);font-family:var(--mono)">← RESPONSE</span>
        </div>
        <div style="padding:14px 14px 0">
          <div class="burp-pane-title">
            RESPONSE
            <button class="copy-btn" onclick="copyText('{resp_id}')">COPY</button>
          </div>
        </div>
        <pre class="burp-body" id="{resp_id}">{_burp_highlight_response(raw_resp, markers)}</pre>
      </div>
    </div>
  </div>

  <!-- SECTION: Screenshots -->
  <div class="section">
    <div class="section-title">Capturas de Pantalla — Lab Efímero Docker</div>
    <div class="shots-grid">{shots_html}</div>
  </div>

  <!-- SECTION: Lab Logs (collapsible) -->
  <div class="section">
    <details>
      <summary>Log del Laboratorio ({len(logs)} entradas)</summary>
      <div class="log-wrap">{logs_html}</div>
    </details>
  </div>

</div>
</body>
</html>"""
    return page


def patch_index_html(verified_cves: list):
    """Add EVIDENCIA button for each confirmed CVE in index.html."""
    if not os.path.exists(INDEX_HTML):
        print(f"index.html not found at {INDEX_HTML}")
        return

    with open(INDEX_HTML, encoding="utf-8") as f:
        content = f.read()

    # Add CSS for btn-evidence if not already there
    if "btn-evidence" not in content:
        content = content.replace(
            ".btn-pdf{background:#1a2535;color:#a3a3a3;border:1px solid #374151}",
            ".btn-pdf{background:#1a2535;color:#a3a3a3;border:1px solid #374151}\n"
            ".btn-evidence{background:#065f46;color:#4ade80;border:1px solid rgba(74,222,128,.35)}\n"
            ".btn-evidence:hover{background:#166534;border-color:#4ade80}"
        )

    patched = 0
    for cve_id in verified_cves:
        evidence_link = f'<a href="{cve_id}_evidence.html" class="btn-evidence" target="_blank">EVIDENCIA</a>'
        # Only add if not already present
        if f"{cve_id}_evidence.html" in content:
            continue
        # Find the td-links block for this CVE
        # Look for the row with this CVE id followed by its td-links
        pattern = rf'(<code>{re.escape(cve_id)}</code>.*?<div class="td-links">)(.*?)(</div>\s*</td>\s*</tr>)'
        def _add_btn(m):
            return m.group(1) + m.group(2) + f'\n    {evidence_link}' + m.group(3)
        new_content, n = re.subn(pattern, _add_btn, content, count=1, flags=re.DOTALL)
        if n > 0:
            content = new_content
            patched += 1

    with open(INDEX_HTML, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"index.html: added EVIDENCIA button for {patched} CVEs")


def main():
    DYN_VERIFIED = [
        "CVE-2023-32590", "CVE-2024-12025", "CVE-2024-12404", "CVE-2024-12849",
        "CVE-2024-50498", "CVE-2024-54374", "CVE-2024-55972", "CVE-2024-55980",
        "CVE-2024-9932",  "CVE-2024-9933",  "CVE-2025-27516", "CVE-2025-57633",
        "CVE-2026-129502","CVE-2026-130082","CVE-2026-130647","CVE-2026-134694",
        "CVE-2026-27641", "CVE-2026-55849", "CVE-2026-77355",
    ]

    generated = []
    skipped = []

    for cve_id in DYN_VERIFIED:
        json_path = os.path.join(BATCH_DIR, f"{cve_id}.json")
        if not os.path.exists(json_path):
            print(f"  SKIP {cve_id}: no JSON in batch dir")
            skipped.append(cve_id)
            continue

        with open(json_path, encoding="utf-8") as f:
            rec = json.load(f)

        # Double-check dynamic verification
        dv = rec.get("dynamic_verify") or {}
        if not dv.get("verified"):
            print(f"  SKIP {cve_id}: dynamic_verify.verified not True")
            skipped.append(cve_id)
            continue

        try:
            html = build_page(cve_id, rec)
            out_path = os.path.join(REPORTS_DIR, f"{cve_id}_evidence.html")
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(html)
            shots = len((rec.get("verified_evidence") or {}).get("screenshots") or [])
            vuln = rec.get("vuln_class") or "?"
            cvss = rec.get("cvss_score") or "?"
            print(f"  OK  {cve_id}: {vuln} CVSS={cvss} shots={shots} → {os.path.basename(out_path)}")
            generated.append(cve_id)
        except Exception as e:
            import traceback
            print(f"  ERR {cve_id}: {e}")
            traceback.print_exc()
            skipped.append(cve_id)

    print(f"\nGenerated: {len(generated)}, Skipped: {len(skipped)}")

    # Patch index.html
    patch_index_html(generated)

    return 0 if not skipped else 1


if __name__ == "__main__":
    sys.exit(main())
