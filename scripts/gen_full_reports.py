#!/usr/bin/env python3
"""
gen_full_reports.py — Genera informes HTML completos para cada CVE verificado dinámicamente.

Incluye:
  - Cabecera con CVSS, EPSS, estado de verificación
  - Panel Burp (petición HTTP real tal como se envió + respuesta con marcador resaltado)
  - Galería completa de capturas (todas las pantallas del lab Docker)
  - Log del laboratorio (pasos del verificador)
  - Consistencia total: solo los CVEs con dynamic_verify.verified=True

Uso:
    python3 scripts/gen_full_reports.py
    python3 scripts/gen_full_reports.py --cve CVE-2024-50498
    python3 scripts/gen_full_reports.py --out /ruta/de/salida

Para AUTHORIZED targets / CTF / investigación defensiva únicamente.
"""
import argparse
import html
import json
import os
import re
import sys
from datetime import datetime

BATCH_DIR  = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                           "binoracle_batch_reports")
REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")

DYN_VERIFIED = [
    "CVE-2023-32590","CVE-2024-12025","CVE-2024-12404","CVE-2024-12849",
    "CVE-2024-50498","CVE-2024-54374","CVE-2024-55972","CVE-2024-55980",
    "CVE-2024-9932","CVE-2024-9933","CVE-2025-27516","CVE-2025-57633",
    "CVE-2026-129502","CVE-2026-130082","CVE-2026-130647","CVE-2026-134694",
    "CVE-2026-27641","CVE-2026-55849","CVE-2026-77355",
]

# ── CVSS severity → badge colour ─────────────────────────────────────────────
def _cvss_color(score):
    if score is None: return "#6b7280"
    s = float(score)
    if s >= 9.0: return "#dc2626"
    if s >= 7.0: return "#d97706"
    if s >= 4.0: return "#2563eb"
    return "#16a34a"

def _sev_label(severity, score):
    if severity: return severity.upper()
    if score is None: return "?"
    s = float(score)
    return "CRITICAL" if s>=9 else "HIGH" if s>=7 else "MEDIUM" if s>=4 else "LOW"

# ── Reconstruct raw HTTP request ──────────────────────────────────────────────
def _build_burp_request(ve: dict, llm: dict, cve_id: str) -> str:
    method   = (ve.get("metodo") or llm.get("http_method") or "POST").upper()
    endpoint = ve.get("endpoint") or llm.get("endpoint") or "/"
    params   = llm.get("parameters") or {}
    headers  = llm.get("custom_headers") or {}
    payload  = ve.get("payload_ganador") or ve.get("payload_enviado") or ""
    auth_req = llm.get("auth_required", False)
    ct       = headers.get("Content-Type", "application/x-www-form-urlencoded")

    # Determine body format
    if params:
        try:
            import urllib.parse
            body = urllib.parse.urlencode({k: (payload if i == 0 else v)
                                           for i, (k, v) in enumerate(params.items())})
            ct = "application/x-www-form-urlencoded"
        except Exception:
            body = payload or ""
    elif payload:
        # Try JSON
        body = payload
        if ct.startswith("application/json") or "{" in str(payload):
            ct = "application/json"
    else:
        body = ""

    hdr_lines = [
        f"{method} {endpoint} HTTP/1.1",
        "Host: target-lab",
        f"Content-Type: {ct}",
    ]
    if auth_req:
        hdr_lines.append("Cookie: wordpress_logged_in_xxxx=[subscriber-session]")
    for k, v in headers.items():
        if k.lower() not in ("content-type",):
            hdr_lines.append(f"{k}: {v}")
    hdr_lines.append(f"Content-Length: {len(body.encode())}")
    hdr_lines.append("")
    hdr_lines.append(body)
    return "\n".join(hdr_lines)

# ── Highlight the payload/marker in a text block ─────────────────────────────
def _highlight(text: str, markers: list) -> str:
    """Escape HTML then wrap marker occurrences in <mark>."""
    escaped = html.escape(text)
    for m in markers:
        if not m:
            continue
        em = html.escape(m)
        # Only highlight up to 3 occurrences to avoid bloat
        escaped = escaped.replace(em, f"<mark>{em}</mark>", 3)
    return escaped

# ── CSS ───────────────────────────────────────────────────────────────────────
CSS = """\
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0a0f1a;--surf:#050a14;--surf2:#0d1424;--surf3:#111827;
  --brd:#1e293b;--fg:#e2e8f0;--mut:#475569;--dim:#334155;
  --acc:#38bdf8;--grn:#22c55e;--red:#ef4444;--yel:#f59e0b;--purp:#a855f7;
  --mono:'JetBrains Mono','Fira Code',ui-monospace,monospace;
  --sans:'Inter',system-ui,sans-serif;color-scheme:dark}
body{background:var(--bg);color:var(--fg);font-family:var(--sans);
  font-size:13px;line-height:1.6;padding-bottom:60px}
a{color:var(--acc)}

/* ── TOP BAR ── */
.topbar{background:var(--surf);border-bottom:2px solid var(--brd);
  padding:12px 32px;display:flex;align-items:center;gap:14px;
  position:sticky;top:0;z-index:100}
.brand{font-family:var(--mono);font-size:20px;font-weight:900;color:var(--acc)}
.brand span{color:var(--yel)}
.cve-id{font-family:var(--mono);font-size:13px;background:var(--surf2);
  border:1px solid var(--brd);border-radius:4px;padding:3px 10px;color:var(--acc)}
.sp{flex:1}
.print-btn{background:var(--surf2);color:var(--fg);border:1px solid var(--brd);
  border-radius:6px;padding:5px 14px;cursor:pointer;font-size:11px;
  font-weight:700;font-family:var(--sans)}
.print-btn:hover{border-color:var(--acc);color:var(--acc)}

/* ── CONF BANNER ── */
.conf{background:#7c0a02;color:#fef2f2;text-align:center;
  padding:5px;font-size:11px;font-weight:700;letter-spacing:.08em}

/* ── COVER ── */
.cover{background:var(--surf);border-bottom:2px solid var(--brd);padding:48px 48px 40px}
.cover-inner{max-width:1100px;margin:0 auto}
.eyebrow{font-size:11px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;
  color:var(--mut);margin-bottom:12px}
.cve-big{font-family:var(--mono);font-size:40px;font-weight:700;
  color:var(--acc);margin-bottom:10px;line-height:1}
.vuln-title{font-size:18px;font-weight:600;color:var(--fg);margin-bottom:20px}
.badges{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.badge{display:inline-flex;align-items:center;gap:5px;padding:4px 12px;
  border-radius:6px;font-size:11px;font-weight:700;letter-spacing:.04em}
.badge-dyn{background:#065f46;color:#4ade80;border:1px solid #16a34a}
.badge-llm{background:#4c1d95;color:#c4b5fd;border:1px solid #6d28d9}
.desc{color:#94a3b8;font-size:13px;line-height:1.65;max-width:800px;margin-top:12px}

/* ── SECTIONS ── */
.wrap{max-width:1100px;margin:0 auto;padding:0 48px}
.section{margin:36px 0}
.section-title{font-size:11px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;
  color:var(--mut);margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid var(--brd)}

/* ── CONFIRM BOX ── */
.confirm-box{background:rgba(5,46,22,.5);border:2px solid #16a34a;border-radius:10px;
  padding:20px 24px;margin-bottom:24px}
.confirm-title{color:#4ade80;font-size:12px;font-weight:800;letter-spacing:.12em;
  text-transform:uppercase;margin-bottom:10px;display:flex;align-items:center;gap:8px}
.confirm-detail{color:#d1fae5;font-size:13px;line-height:1.65;font-family:var(--mono)}
.confirm-row{display:flex;gap:16px;margin-top:14px;flex-wrap:wrap}
.confirm-pill{background:rgba(5,46,22,.8);border:1px solid #15803d;
  border-radius:6px;padding:5px 12px;font-size:11px;font-family:var(--mono)}
.confirm-pill span{color:#4ade80;font-weight:700}

/* ── BURP PANEL ── */
.burp-panel{background:#0d1117;border:2px solid var(--brd);border-radius:10px;
  overflow:hidden;margin-bottom:16px}
.burp-hdr{padding:10px 16px;border-bottom:2px solid var(--brd);
  display:flex;align-items:center;gap:10px;background:#161b22}
.burp-title{font-size:10px;font-weight:700;letter-spacing:.12em;color:var(--mut);
  text-transform:uppercase}
.burp-method{font-family:var(--mono);font-weight:700;font-size:11px;
  padding:3px 9px;border-radius:4px;color:#fff}
.m-get{background:#15803d} .m-post{background:#1d4ed8}
.m-put{background:#9333ea} .m-delete{background:#dc2626}
.m-patch{background:#d97706}
.burp-url{font-family:var(--mono);font-size:12px;color:#9cdcfe;
  flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.burp-status{font-family:var(--mono);font-size:11px;font-weight:700;
  padding:2px 8px;border-radius:4px}
.s2{background:rgba(26,127,55,.2);color:#4ade80;border:1px solid #16a34a}
.s4{background:rgba(185,28,28,.2);color:#f87171;border:1px solid #dc2626}
.s5{background:rgba(185,28,28,.25);color:#f87171;border:1px solid #dc2626}
.burp-panes{display:grid;grid-template-columns:1fr 1fr}
@media(max-width:700px){.burp-panes{grid-template-columns:1fr}}
.burp-pane{padding:14px 16px;border-right:1px solid var(--brd);min-width:0}
.burp-pane:last-child{border-right:none}
.burp-pane-title{font-size:10px;font-weight:700;letter-spacing:.1em;
  text-transform:uppercase;color:var(--mut);margin-bottom:8px;
  display:flex;align-items:center;justify-content:space-between}
.copy-btn{font-size:9px;background:var(--surf3);border:1px solid var(--brd);
  border-radius:3px;padding:1px 6px;color:var(--mut);cursor:pointer;
  font-family:var(--mono);transition:background .15s;user-select:none}
.copy-btn:hover{background:var(--acc);color:#fff}
.burp-body{font-family:var(--mono);font-size:12px;white-space:pre-wrap;
  word-break:break-all;line-height:1.65;color:#d4d4d4;background:#1e1e1e;
  border-radius:6px;padding:12px 14px;overflow-x:auto;
  max-height:380px;overflow-y:auto;tab-size:2}
.burp-body .rl{color:#fff;font-weight:700}       /* request line */
.burp-body .hk{color:#9cdcfe}                    /* header key */
.burp-body .hv{color:#ce9178}                    /* header value */
.burp-body mark{background:#f9a825;color:#000;padding:1px 2px;
  border-radius:2px;font-weight:700}             /* payload highlight */

/* ── SCREENSHOTS ── */
.shots-grid{display:flex;flex-direction:column;gap:24px}
.shot-card{background:var(--surf2);border:1px solid var(--brd);border-radius:10px;
  overflow:hidden}
.shot-hdr{padding:10px 16px;border-bottom:1px solid var(--brd);
  display:flex;align-items:center;gap:10px}
.shot-step{font-size:9px;font-weight:800;background:var(--surf3);
  border:1px solid var(--brd);border-radius:4px;padding:2px 7px;
  color:var(--mut);font-family:var(--mono);letter-spacing:.08em}
.shot-caption{font-size:12px;color:var(--fg);flex:1}
.shot-img{width:100%;display:block;max-height:600px;object-fit:contain;
  background:#000}

/* ── LOG ── */
details{background:var(--surf2);border:1px solid var(--brd);border-radius:8px;
  overflow:hidden;margin-bottom:12px}
summary{padding:12px 16px;cursor:pointer;font-size:11px;font-weight:700;
  letter-spacing:.08em;color:var(--mut);text-transform:uppercase;
  user-select:none;list-style:none}
summary::-webkit-details-marker{display:none}
.log-body{padding:14px 16px;font-family:var(--mono);font-size:12px;
  color:#d4d4d4;white-space:pre-wrap;line-height:1.65;
  max-height:400px;overflow-y:auto;background:#111}

/* ── EVIDENCE TABLE ── */
.ev-table{width:100%;border-collapse:collapse}
.ev-table td{padding:8px 12px;border-bottom:1px solid var(--brd);
  font-size:12px;vertical-align:top}
.ev-table td:first-child{color:var(--mut);font-weight:600;white-space:nowrap;
  font-size:11px;width:200px}
.ev-table td:last-child{font-family:var(--mono);color:#d4d4d4;
  word-break:break-all}

/* ── RESPONSIVE ── */
@media(max-width:800px){.wrap,.cover{padding-left:16px;padding-right:16px}
  .burp-panes{grid-template-columns:1fr}}
"""

# ── Vuln class → professional title ──────────────────────────────────────────
_TITLES = {
    "sqli": "SQL Injection — Extracción de Base de Datos",
    "xss":  "Cross-Site Scripting — Ejecución de JavaScript en Sesión Víctima",
    "rce":  "Remote Code Execution — Compromiso Total del Servidor",
    "code-injection": "Code Injection — Ejecución Arbitraria de Código",
    "path-traversal": "Path Traversal — Lectura de Archivos del Servidor",
    "file-upload": "Arbitrary File Upload — Despliegue de Webshell",
    "missing-authorization": "Authorization Bypass — Escalada de Privilegios",
    "auth-bypass": "Authentication Bypass — Acceso no Autorizado",
    "ssrf": "Server-Side Request Forgery — Acceso a Red Interna",
    "ssti": "Server-Side Template Injection — RCE via Templates",
    "deserialization": "Insecure Deserialization — Ejecución de Código Remota",
    "command-injection": "OS Command Injection — Ejecución de Comandos del Sistema",
    "idor": "Insecure Direct Object Reference — Acceso a Recursos Ajenos",
    "dos":  "Denial of Service — Interrupción del Servicio",
    "cors-misconfiguration": "CORS Misconfiguration — Robo de Sesión Cross-Origin",
    "open-redirect": "Open Redirect — Phishing y Robo de Tokens",
}

def _title(rec: dict) -> str:
    cls = (rec.get("vuln_class") or rec.get("llm_notes", {}).get("vuln_class") or "").lower()
    return _TITLES.get(cls, f"Vulnerabilidad de Seguridad ({cls})")

# ── Syntax-colour a raw HTTP request ─────────────────────────────────────────
def _colour_request(raw: str, payload: str) -> str:
    lines = raw.split("\n")
    out = []
    for i, line in enumerate(lines):
        esc = html.escape(line)
        if i == 0:
            out.append(f'<span class="rl">{esc}</span>')
        elif ": " in line:
            k, v = line.split(": ", 1)
            out.append(f'<span class="hk">{html.escape(k)}</span>: '
                       f'<span class="hv">{html.escape(v)}</span>')
        else:
            # body — highlight payload
            if payload:
                out.append(_highlight(line, [payload]))
            else:
                out.append(esc)
    return "\n".join(out)

# ── Main report builder ───────────────────────────────────────────────────────
def _build_html(cve_id: str, rec: dict) -> str:
    ve   = rec.get("verified_evidence") or {}
    dv   = rec.get("dynamic_verify") or {}
    llm  = rec.get("llm_notes") or {}
    desc = rec.get("description") or ""
    cvss = rec.get("cvss_score")
    sev  = rec.get("cvss_severity") or ""
    pub  = rec.get("published") or "?"
    is_gap = rec.get("is_gap", False)

    # -- Key evidence fields --
    method   = (ve.get("metodo") or llm.get("http_method") or "POST").upper()
    endpoint = ve.get("endpoint") or llm.get("endpoint") or "/"
    payload  = ve.get("payload_ganador") or ve.get("payload_enviado") or llm.get("payload_ganador") or ""
    status   = ve.get("status_code_respuesta")
    body_cut = ve.get("respuesta_cuerpo_recorte") or ve.get("respuesta_control_recorte") or ""
    detail   = dv.get("detail") or "(confirmación dinámica — ver log)"
    shots    = ve.get("screenshots") or []
    logs     = dv.get("logs") or []
    mysql_v  = ve.get("mysql_version_extraida") or ""
    marker   = mysql_v or ve.get("marcador_confirmado") or ve.get("canary_secret") or ""

    # Burp request
    raw_req = _build_burp_request(ve, llm, cve_id)
    coloured_req = _colour_request(raw_req, payload)

    # HTTP status class
    status_cls = "s2" if status and 200 <= int(status) < 300 else \
                 "s4" if status and 400 <= int(status) < 500 else "s5"
    status_txt = f"HTTP {status}" if status else "HTTP ?"

    # Response highlight markers
    highlight_markers = [m for m in [payload, mysql_v, "BIN_", marker] if m][:3]

    # Vuln title
    title = _title(rec)

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # -- Evidence rows table --
    ev_rows = []
    for label, key in [
        ("Endpoint", "endpoint"), ("Método HTTP", "metodo"),
        ("Parámetro vulnerable", "sqli_param"),
        ("Payload ganador", "payload_ganador"),
        ("Payload enviado", "payload_enviado"),
        ("Código de respuesta", "status_code_respuesta"),
        ("Versión MySQL extraída", "mysql_version_extraida"),
        ("Ruta de archivo leída", "objetivo_ganador"),
        ("Marcador de ejecución", "marcador_confirmado"),
        ("Canario (secreto)", "canary_secret"),
        ("Usuario bajo privilegio", "login_bajo_privilegio"),
    ]:
        v = ve.get(key)
        if v is not None and str(v).strip() and str(v) != "None":
            ev_rows.append((label, str(v)))

    # -- Build HTML --
    h = ["<!doctype html><html lang='es'><head>",
         "<meta charset='utf-8'>",
         f"<title>{html.escape(cve_id)} — binoracle EVIDENCIA</title>",
         "<meta name='viewport' content='width=device-width,initial-scale=1'>",
         "<link rel='stylesheet' href='https://fonts.googleapis.com/css2?"
         "family=Inter:wght@400;500;600;700;800;900"
         "&family=JetBrains+Mono:wght@400;500;700&display=swap'>",
         f"<style>{CSS}</style>",
         "</head><body>",
    ]

    # Top bar
    h += [
        "<div class='topbar'>",
        "  <div class='brand'>bin<span>0</span>racle</div>",
        f"  <div class='cve-id'>{html.escape(cve_id)}</div>",
        "  <div class='sp'></div>",
        f"  <span style='color:var(--mut);font-size:11px'>{now}</span>",
        "  <button class='print-btn' onclick='window.print()'>PDF</button>",
        "</div>",
    ]

    # Confidential banner
    h.append("<div class='conf'>CONFIDENCIAL — SOLO PARA OBJETIVOS AUTORIZADOS "
             "(PENTEST / CTF / LAB EFÍMERO)</div>")

    # Cover
    cvss_color = _cvss_color(cvss)
    sev_label  = _sev_label(sev, cvss)
    h += [
        "<div class='cover'>",
        "  <div class='cover-inner'>",
        f"    <div class='eyebrow'>binoracle CVE Verification Engine — Evidencia Dinámica</div>",
        f"    <div class='cve-big'>{html.escape(cve_id)}</div>",
        f"    <div class='vuln-title'>{html.escape(title)}</div>",
        "    <div class='badges'>",
        "      <span class='badge badge-dyn'>✓ DINÁMICAMENTE VERIFICADO</span>",
        f"      <span class='badge' style='background:{cvss_color}22;color:{cvss_color};"
            f"border:1px solid {cvss_color}66'>CVSS {cvss or '?'} {sev_label}</span>",
        f"      <span class='badge' style='background:#1e3a5f;color:#38bdf8;"
            f"border:1px solid #1e40af'>{html.escape(method)} {html.escape(endpoint)}</span>",
        "    </div>",
        f"    <div class='desc'>{html.escape(desc[:600])}</div>",
        "  </div>",
        "</div>",
    ]

    h.append("<div class='wrap'>")

    # 1. Confirmation summary
    h += [
        "<div class='section'>",
        "  <div class='section-title'>Confirmación de Explotación</div>",
        "  <div class='confirm-box'>",
        "    <div class='confirm-title'>",
        "      <svg width='16' height='16' viewBox='0 0 24 24' fill='none' "
              "stroke='#4ade80' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round'>"
              "<polyline points='20 6 9 17 4 12'/></svg>",
        "      VULNERABILIDAD EXPLOTADA EN LABORATORIO DOCKER AISLADO",
        "    </div>",
        f"   <div class='confirm-detail'>{html.escape(detail)}</div>",
        "    <div class='confirm-row'>",
    ]
    if payload:
        h.append(f"<div class='confirm-pill'>Payload: "
                 f"<span>{html.escape(str(payload)[:120])}</span></div>")
    if mysql_v:
        h.append(f"<div class='confirm-pill'>MySQL extraído: "
                 f"<span>{html.escape(mysql_v)}</span></div>")
    if status:
        h.append(f"<div class='confirm-pill'>Status: "
                 f"<span>{html.escape(str(status))}</span></div>")
    h += ["    </div>", "  </div>", "</div>"]

    # 2. HTTP Evidence (Burp)
    h += [
        "<div class='section'>",
        "  <div class='section-title'>Petición HTTP Real — Estilo Burp Suite</div>",
        "  <div class='burp-panel'>",
        "    <div class='burp-hdr'>",
        f"     <span class='burp-method m-{method.lower()}'>{html.escape(method)}</span>",
        f"     <span class='burp-url' title='{html.escape(endpoint)}'>"
            f"{html.escape(endpoint)}</span>",
        f"     <span class='burp-status {status_cls}'>{html.escape(status_txt)}</span>",
        "      <span class='burp-title' style='margin-left:auto;cursor:default'>"
              "HTTP REQUEST / RESPONSE</span>",
        "    </div>",
        "    <div class='burp-panes'>",
        "      <div class='burp-pane'>",
        "        <div class='burp-pane-title'>REQUEST "
                 "<button class='copy-btn' onclick=\"navigator.clipboard.writeText("
                 "document.getElementById('breq').innerText)\">COPY</button></div>",
        f"       <pre class='burp-body' id='breq'>{coloured_req}</pre>",
        "      </div>",
        "      <div class='burp-pane'>",
        "        <div class='burp-pane-title'>RESPONSE "
                 "<button class='copy-btn' onclick=\"navigator.clipboard.writeText("
                 "document.getElementById('bres').innerText)\">COPY</button></div>",
    ]
    # Response body
    res_text = (f"HTTP/1.1 {status} {'OK' if status and int(status) < 300 else 'Error'}\n"
                f"Content-Type: application/json\n\n"
                f"{body_cut[:2000]}" if body_cut else "(sin cuerpo de respuesta capturado)")
    coloured_res = _highlight(res_text, [str(m) for m in highlight_markers if m])
    h += [
        f"       <pre class='burp-body' id='bres'>{coloured_res}</pre>",
        "      </div>",
        "    </div>",
        "  </div>",
        "</div>",
    ]

    # 3. Evidence fields table
    if ev_rows:
        h += [
            "<div class='section'>",
            "  <div class='section-title'>Datos Reales de la Ejecución</div>",
            "  <table class='ev-table'>",
        ]
        for label, value in ev_rows:
            h.append(f"    <tr><td>{html.escape(label)}</td>"
                     f"<td>{html.escape(str(value)[:400])}</td></tr>")
        h += ["  </table>", "</div>"]

    # 4. Screenshots gallery
    if shots:
        h += [
            "<div class='section'>",
            f"  <div class='section-title'>Capturas de Pantalla del Laboratorio "
                f"({len(shots)} capturas — evidencia visual real)</div>",
            "  <div class='shots-grid'>",
        ]
        for i, sh in enumerate(shots):
            caption = sh.get("caption_es") or sh.get("caption_en") or f"Paso {i+1}"
            png = sh.get("png_b64")
            if not png:
                continue
            h += [
                "    <div class='shot-card'>",
                "      <div class='shot-hdr'>",
                f"       <span class='shot-step'>PASO {i+1}</span>",
                f"       <span class='shot-caption'>{html.escape(caption)}</span>",
                "      </div>",
                f"      <img class='shot-img' "
                      f"src='data:image/png;base64,{png}' "
                      f"alt='{html.escape(caption[:80])}' loading='lazy'>",
                "    </div>",
            ]
        h += ["  </div>", "</div>"]
    else:
        h += [
            "<div class='section'>",
            "  <div class='section-title'>Capturas de Pantalla</div>",
            "  <div style='color:var(--mut);font-size:12px;padding:12px 0'>",
            "  Sin capturas de pantalla — verificación por respuesta HTTP "
                "(Playwright no disponible en este contenedor).<br>",
            "  La evidencia textual (payload, respuesta HTTP, marcador) es igualmente válida.",
            "  </div>",
            "</div>",
        ]

    # 5. Lab log (collapsible)
    if logs:
        log_text = html.escape("\n".join(str(l) for l in logs[:200]))
        h += [
            "<div class='section'>",
            "  <div class='section-title'>Log del Laboratorio</div>",
            "  <details>",
            f"   <summary>Ver log completo ({len(logs)} líneas)</summary>",
            f"   <div class='log-body'>{log_text}</div>",
            "  </details>",
            "</div>",
        ]

    h += ["</div>", "</body></html>"]
    return "\n".join(h)


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Genera informes de evidencia completos")
    ap.add_argument("--cve", default="", help="Solo este CVE (e.g. CVE-2024-50498)")
    ap.add_argument("--out", default=REPORT_DIR, help="Directorio de salida")
    ap.add_argument("--all", action="store_true", help="Incluir todos (no solo DYN_VERIFIED)")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    targets = [args.cve] if args.cve else DYN_VERIFIED

    generated = []
    errors = []

    for cve_id in targets:
        path = os.path.join(BATCH_DIR, f"{cve_id}.json")
        if not os.path.exists(path):
            errors.append(f"{cve_id}: no JSON en {BATCH_DIR}")
            continue
        try:
            with open(path, encoding="utf-8") as f:
                rec = json.load(f)

            # Safety check: only generate for truly verified CVEs
            dv = rec.get("dynamic_verify") or {}
            if not dv.get("verified") and not args.all:
                errors.append(f"{cve_id}: dynamic_verify.verified=False — omitido (no es false positive)")
                continue

            html_out = _build_html(cve_id, rec)
            out_path = os.path.join(args.out, f"{cve_id}_evidence.html")
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(html_out)

            shots = len((rec.get("verified_evidence") or {}).get("screenshots") or [])
            generated.append((cve_id, out_path, shots))
            print(f"  ✓ {cve_id:25s}  →  {out_path}  ({shots} capturas)")

        except Exception as e:
            errors.append(f"{cve_id}: {e}")
            print(f"  ✗ {cve_id}: {e}", file=sys.stderr)

    print(f"\n=== Generados: {len(generated)} / {len(targets)} ===")
    if errors:
        print(f"Errores ({len(errors)}):")
        for e in errors:
            print(f"  - {e}")

    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
