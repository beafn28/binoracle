"""Self-contained, professional, bilingual (ES/EN) interactive HTML report.

No external assets. Light/dark toggle (persisted), language toggle, KPI dashboard,
mitigation risk panel, severity distribution, filterable findings, attack surface and the
full evidence trail. Opens in any browser, works offline, safe to share."""
from __future__ import annotations

import html as _html
import json as _json
import re
from datetime import datetime
from typing import List, Optional

from ..store.session import Finding

_SEV = ["critical", "high", "medium", "low", "info"]
_SEV_COLOR = {"critical": "#e5484d", "high": "#f76808", "medium": "#f5b800",
              "low": "#30a46c", "info": "#5b8def"}
_VERDICT_COLOR = {"verified": "#30a46c", "grounded": "#5b8def", "unverified": "#f5b800"}


def _esc(s) -> str:
    return _html.escape(str(s if s is not None else ""))


def _badge(text, color):
    return f'<span class="badge" style="background:{color}">{_esc(text)}</span>'


def _md(s) -> str:
    """Minimal, safe markdown: escape, then render **bold**, `code` and paragraphs."""
    import re as _re
    t = _esc(s)
    t = _re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
    t = _re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    return t


def _parse_mitigations(triage) -> dict:
    """Pull NX/PIE/Canary/RELRO/arch out of the checksec triage section, if present."""
    m = {"NX": None, "PIE": None, "Canary": None, "RELRO": None, "Arch": None}
    if triage is None:
        return m
    for title, source, text in triage.sections:
        blob = f"{title}\n{source}\n{text}".lower()
        if "checksec" in blob or "mitig" in blob or "nx" in blob:
            for line in text.splitlines():
                low = line.lower()
                if "nx" in low and m["NX"] is None:
                    m["NX"] = "false" not in low and "nx_off" not in low
                if ("pie" in low or "pic" in low) and m["PIE"] is None:
                    m["PIE"] = "true" in low and "false" not in low.split(":")[-1]
                if "canary" in low and m["Canary"] is None:
                    m["Canary"] = "true" in low and "false" not in low.split(":")[-1]
                if "relro" in low and m["RELRO"] is None:
                    m["RELRO"] = "full" if "full" in low else ("partial" if "partial" in low else "none")
                ma = re.search(r"arch:\s*([a-z0-9_\- ]+)", low)
                if ma and m["Arch"] is None:
                    m["Arch"] = ma.group(1).strip()
    return m


def render_html(binary: str, triage=None, findings: Optional[List[Finding]] = None,
                ledger=None, answer: str = "", lang: str = "es", embed: bool = False) -> str:
    findings = findings or []
    ts = datetime.now().isoformat(timespec="seconds")
    mit = _parse_mitigations(triage)

    counts = {s: 0 for s in _SEV}
    verified = 0
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        if f.verdict == "verified":
            verified += 1
    total = len(findings)

    # severity distribution bar
    seg = ""
    for s in _SEV:
        if counts.get(s):
            pct = counts[s] / total * 100 if total else 0
            seg += f'<span style="width:{pct:.1f}%;background:{_SEV_COLOR[s]}" title="{s}: {counts[s]}"></span>'
    empty_seg = '<span style="width:100%;background:var(--line)"></span>'
    dist = '<div class="dist">' + (seg or empty_seg) + '</div>'

    # KPI cards
    def kpi(labkey, val, color="var(--fg)"):
        return (f'<div class="kpi"><div class="kpi-v" style="color:{color}">{val}</div>'
                f'<div class="kpi-l" data-i18n="{labkey}"></div></div>')
    kpis = (
        kpi("kpi_total", total) +
        kpi("kpi_verified", verified, _VERDICT_COLOR["verified"]) +
        kpi("kpi_high", counts["critical"] + counts["high"], _SEV_COLOR["high"]) +
        kpi("kpi_sources", len(ledger.sources()) if ledger else 0)
    )

    # mitigation panel: good/bad coloring (NX on = good, PIE on = good, Canary on = good)
    def mit_item(key, value):
        if value is None:
            state, cls = "?", "mut"
        elif key in ("NX", "PIE", "Canary"):
            good = bool(value) if isinstance(value, bool) else False
            state = ("ON" if good else "OFF") if isinstance(value, bool) else str(value)
            cls = "ok" if good else "bad"
        elif key == "RELRO":
            state = str(value).upper()
            cls = "ok" if value == "full" else ("warn" if value == "partial" else "bad")
        else:
            state, cls = str(value), "mut"
        return f'<div class="mit {cls}"><span class="mit-k">{_esc(key)}</span><span class="mit-v">{_esc(state)}</span></div>'
    mit_panel = "".join(mit_item(k, mit[k]) for k in ("Arch", "NX", "PIE", "Canary", "RELRO"))

    # findings cards
    cards = ""
    for f in sorted(findings, key=lambda x: _SEV.index(x.severity) if x.severity in _SEV else 9):
        cards += f'''
        <div class="card" data-sev="{_esc(f.severity)}">
          <div class="card-h" onclick="this.parentNode.classList.toggle('open')">
            {_badge(f.severity.upper(), _SEV_COLOR.get(f.severity,'#666'))}
            {_badge(f.verdict, _VERDICT_COLOR.get(f.verdict,'#666'))}
            <span class="title">{_esc(f.title)}</span>
            <span class="loc">{_esc(f.location)}</span>
            <span class="chev">&#9656;</span>
          </div>
          <div class="card-b">
            <h4 data-i18n="rationale"></h4><div class="md">{_md(f.rationale)}</div>
            <h4 data-i18n="evidence"></h4><pre>{_esc(f.evidence)}</pre>
            <h4 data-i18n="recommendation"></h4><div class="md">{_md(f.recommendation)}</div>
          </div>
        </div>'''

    triage_sections = ""
    if triage is not None:
        for title, source, text in triage.sections:
            triage_sections += (f'<details class="sec"><summary>{_esc(title)}'
                                f'<span class="src">{_esc(source)}</span></summary>'
                                f'<pre>{_esc(text)}</pre></details>')

    trail = ""
    if ledger is not None and getattr(ledger, "entries", None):
        for e in ledger.entries:
            trail += (f'<details class="sec"><summary>step {e.step}: {_esc(e.tool)}'
                      f'<span class="src">{_esc(e.source)}</span></summary>'
                      f'<pre>{_esc(e.data)}</pre></details>')

    answer_html = f'<div class="panel md summary"><div class="panel-t" data-i18n="exec_summary"></div>{_md(answer)}</div>' if answer else ""
    sev_buttons = "".join(
        f'<button class="fbtn" data-f="{s}" onclick="flt(this)"><i style="background:{_SEV_COLOR[s]}"></i>'
        f'<span data-i18n="sev_{s}"></span> <b>{counts.get(s,0)}</b></button>' for s in _SEV)

    i18n = _json.dumps(_I18N)

    header_html = "" if embed else f'''<header>
  <div class="brand"><span class="dot"></span> binoracle <em data-i18n="subtitle"></em></div>
  <div class="hmeta"><code>{_esc(binary)}</code> &middot; {ts}</div>
  <div class="controls">
    <button id="lang" class="ctl" onclick="toggleLang()">EN</button>
    <button id="theme" class="ctl" onclick="toggleTheme()">&#9788;</button>
  </div>
</header>'''
    return f'''<!doctype html>
<html lang="{lang}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>binoracle - {_esc(binary)}</title>
<style>{_CSS}</style></head>
<body>
{header_html}
<main>
  <section class="dash">
    <div class="kpis">{kpis}</div>
    <div class="panel">
      <div class="panel-t" data-i18n="severity_dist"></div>
      {dist}
      <div class="panel-t" style="margin-top:14px" data-i18n="mitigations"></div>
      <div class="mits">{mit_panel}</div>
    </div>
  </section>

  {answer_html}

  <h2 data-i18n="findings"></h2>
  <div class="toolbar">
    <input id="q" placeholder="" oninput="search()">
    {sev_buttons}
  </div>
  <div id="cards">{cards or '<p class="empty" data-i18n="no_findings"></p>'}</div>

  <h2 data-i18n="attack_surface"></h2>
  {triage_sections or '<p class="empty" data-i18n="no_triage"></p>'}

  <h2 data-i18n="evidence_trail"></h2>
  {trail or '<p class="empty" data-i18n="no_trail"></p>'}

  <footer data-i18n="footer"></footer>
</main>
<script>
const I18N = {i18n};
let lang = localStorage.getItem('bo_lang') || '{lang}';
function applyI18n(){{
  document.querySelectorAll('[data-i18n]').forEach(el=>{{
    const k = el.dataset.i18n; const t = (I18N[lang]||{{}})[k];
    if(t!==undefined) el.textContent = t;
  }});
  document.getElementById('q').placeholder = (I18N[lang]||{{}}).search || '';
  document.getElementById('lang').textContent = lang==='es'?'EN':'ES';
  document.documentElement.lang = lang;
}}
function toggleLang(){{ lang = lang==='es'?'en':'es'; localStorage.setItem('bo_lang',lang); applyI18n(); }}
function setTheme(t){{ document.documentElement.setAttribute('data-theme',t); localStorage.setItem('bo_theme',t);
  document.getElementById('theme').innerHTML = t==='dark'?'&#9788;':'&#9789;'; }}
function toggleTheme(){{ setTheme(document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark'); }}
const off = new Set();
function flt(b){{const f=b.dataset.f; if(off.has(f)){{off.delete(f);b.classList.remove('boff')}}else{{off.add(f);b.classList.add('boff')}} apply();}}
function apply(){{document.querySelectorAll('.card').forEach(c=>{{c.style.display=off.has(c.dataset.sev)?'none':''}});search();}}
function search(){{const q=(document.getElementById('q').value||'').toLowerCase();
  document.querySelectorAll('.card').forEach(c=>{{if(off.has(c.dataset.sev))return;
    c.style.display=c.textContent.toLowerCase().includes(q)?'':'none';}});}}
(function init(){{
  const saved = localStorage.getItem('bo_theme');
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  setTheme(saved || (prefersDark?'dark':'light'));
  applyI18n();
}})();
</script>
</body></html>'''


_I18N = {
    "es": {
        "subtitle": "informe de reversing y explotacion",
        "kpi_total": "hallazgos", "kpi_verified": "verificados",
        "kpi_high": "severidad alta", "kpi_sources": "fuentes consultadas",
        "severity_dist": "Distribucion por severidad", "mitigations": "Mitigaciones",
        "exec_summary": "Resumen ejecutivo",
        "findings": "Hallazgos", "attack_surface": "Superficie de ataque",
        "evidence_trail": "Rastro de evidencia (grounding)",
        "rationale": "Razonamiento", "evidence": "Evidencia", "recommendation": "Recomendacion",
        "search": "buscar hallazgos...",
        "sev_critical": "critico", "sev_high": "alto", "sev_medium": "medio",
        "sev_low": "bajo", "sev_info": "info",
        "no_findings": "Sin hallazgos respaldados por evidencia.",
        "no_triage": "Sin triage capturado.", "no_trail": "No se consulto ningun oracle.",
        "footer": "Generado por binoracle. Cada afirmacion esta atribuida al oracle que la produjo.",
    },
    "en": {
        "subtitle": "reverse engineering & exploitation report",
        "kpi_total": "findings", "kpi_verified": "verified",
        "kpi_high": "high severity", "kpi_sources": "sources consulted",
        "severity_dist": "Severity distribution", "mitigations": "Mitigations",
        "exec_summary": "Executive summary",
        "findings": "Findings", "attack_surface": "Attack surface",
        "evidence_trail": "Evidence trail (grounding)",
        "rationale": "Rationale", "evidence": "Evidence", "recommendation": "Recommendation",
        "search": "search findings...",
        "sev_critical": "critical", "sev_high": "high", "sev_medium": "medium",
        "sev_low": "low", "sev_info": "info",
        "no_findings": "No evidence-backed findings.",
        "no_triage": "No triage captured.", "no_trail": "No oracle tools were consulted.",
        "footer": "Generated by binoracle. Every fact is attributed to the oracle that produced it.",
    },
}

_CSS = """
:root{--bg:#f6f7f9;--panel:#ffffff;--fg:#1a2027;--mut:#6b7683;--line:#e3e7ec;--acc:#2f6feb;--code:#f0f2f5;--codefg:#243b53}
:root[data-theme=dark]{--bg:#0d1117;--panel:#161b22;--fg:#d7dde4;--mut:#8b95a1;--line:#232a33;--acc:#4aa3ff;--code:#0b0e12;--codefg:#cfe3ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,sans-serif}
header{display:flex;align-items:center;gap:16px;padding:14px 22px;border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:9;flex-wrap:wrap}
.brand{font-weight:700;font-size:16px;display:flex;align-items:center;gap:8px}
.brand em{font-style:normal;font-weight:400;color:var(--mut);font-size:12px}
.dot{width:10px;height:10px;border-radius:50%;background:var(--acc);box-shadow:0 0 10px var(--acc)}
.hmeta{color:var(--mut);font-size:12px;flex:1;min-width:160px}
.hmeta code{background:var(--code);padding:2px 6px;border-radius:5px;color:var(--codefg)}
.controls{display:flex;gap:8px}
.ctl{background:var(--panel);border:1px solid var(--line);color:var(--fg);border-radius:8px;padding:5px 11px;cursor:pointer;font-size:13px;min-width:38px}
.ctl:hover{border-color:var(--acc)}
main{max-width:1040px;margin:0 auto;padding:22px 16px 90px}
.dash{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:8px}
@media(max-width:720px){.dash{grid-template-columns:1fr}}
.kpis{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
.kpi-v{font-size:30px;font-weight:800;line-height:1}
.kpi-l{color:var(--mut);font-size:12px;margin-top:6px;text-transform:uppercase;letter-spacing:.04em}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
.panel-t{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;margin-bottom:8px}
.dist{display:flex;height:12px;border-radius:6px;overflow:hidden;background:var(--line)}
.dist span{display:block;height:100%}
.mits{display:flex;flex-wrap:wrap;gap:8px}
.mit{display:flex;flex-direction:column;border:1px solid var(--line);border-radius:9px;padding:7px 12px;min-width:74px}
.mit-k{font-size:10px;color:var(--mut);text-transform:uppercase}
.mit-v{font-weight:700;font-size:14px}
.mit.ok .mit-v{color:#2f9e5f}.mit.bad .mit-v{color:#e5484d}.mit.warn .mit-v{color:#e5a000}.mit.mut .mit-v{color:var(--mut)}
h2{font-size:15px;border-bottom:1px solid var(--line);padding-bottom:7px;margin:30px 0 12px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:14px}
#q{flex:1;min-width:180px;background:var(--panel);border:1px solid var(--line);border-radius:8px;color:var(--fg);padding:8px 11px}
.fbtn{display:flex;align-items:center;gap:6px;background:var(--panel);color:var(--fg);border:1px solid var(--line);border-radius:16px;padding:5px 12px;cursor:pointer;font-size:12px;text-transform:capitalize}
.fbtn i{width:9px;height:9px;border-radius:50%}.fbtn b{color:var(--fg)}.fbtn.boff{opacity:.35}
.card{border:1px solid var(--line);border-radius:11px;margin:10px 0;background:var(--panel);overflow:hidden}
.card-h{padding:12px 14px;cursor:pointer;display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.card-h .title{font-weight:650}.card-h .loc{color:var(--mut);font-size:12px;margin-left:auto;font-family:ui-monospace,monospace}
.card-h .chev{transition:transform .15s;color:var(--mut)}
.card.open .card-h .chev{transform:rotate(90deg)}
.card-b{display:none;padding:2px 15px 16px;border-top:1px solid var(--line)}
.card.open .card-b{display:block}
h4{margin:15px 0 5px;color:var(--mut);text-transform:uppercase;font-size:11px;letter-spacing:.05em}
pre{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:11px;overflow:auto;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--codefg);white-space:pre}
.sec{border:1px solid var(--line);border-radius:9px;margin:8px 0;background:var(--panel)}
.sec>summary{padding:10px 13px;cursor:pointer;font-weight:600;display:flex;justify-content:space-between;align-items:center;gap:10px}
.sec .src{color:var(--mut);font-weight:400;font-size:11px;font-family:ui-monospace,monospace}
.sec pre{margin:0 13px 13px}
.md{white-space:pre-wrap}
.md code{background:var(--code);padding:1px 5px;border-radius:4px;font:12px ui-monospace,monospace;color:var(--codefg)}
.summary{margin-bottom:8px;border-left:3px solid var(--acc)}
.empty{color:var(--mut);font-style:italic}
footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);color:var(--mut);font-size:12px}
"""
