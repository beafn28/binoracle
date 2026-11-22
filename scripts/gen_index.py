#!/usr/bin/env python3
"""Generate index.html — filterable table of all CVEs (history + batch)."""
import json, os, html as html_mod

HISTORY   = "/Users/beatrizfresnonaumova/.binoracle/history"
BATCH_DIR = os.path.join(os.path.dirname(__file__), "..", "binoracle_batch_reports")
OUT       = "/Users/beatrizfresnonaumova/Downloads/binoracle_reports"
DATE      = "22 NOVIEMBRE 2026"

def h(s): return html_mod.escape(str(s or ""))

rows = []
seen = set()

def add_row(cve, cls, tech, score, sev, poc, auth, aff, desc, pub, endpoint, verified, gap=False, is_gap=False):
    if cve in seen:
        return
    seen.add(cve)
    rows.append(dict(cve=cve,cls=cls,tech=tech,score=score,sev=sev,poc=poc,
                     auth=auth,aff=aff,desc=desc,pub=pub,endpoint=endpoint,verified=verified,
                     gap=gap,is_gap=is_gap))

# 1. History (all verified)
for fname in sorted(os.listdir(HISTORY)):
    if not fname.endswith(".json"): continue
    with open(os.path.join(HISTORY, fname)) as fh:
        data = json.load(fh)
    r  = data.get("result", {})
    ve = r.get("verified_evidence", {})
    cve = data.get("cve_id", "?")
    cls  = r.get("vuln_class", "?")
    tech = ve.get("tecnica", "")
    if not tech:
        if ve.get("respuesta_true_len"): tech = "boolean-blind"
        elif ve.get("bypass_header"):    tech = "auth-bypass"
        elif ve.get("marker"):           tech = "stored-xss"
        elif ve.get("canary_path"):      tech = "path-traversal"
    score = r.get("cvss_score", "?")
    sev   = (r.get("cvss_severity") or "CRITICAL").upper()
    poc      = bool(r.get("poc_source", ""))
    auth     = bool(ve.get("login_bajo_privilegio", ""))
    aff      = r.get("affected_version", "?") or "?"
    desc     = (r.get("description") or "")[:120]
    pub      = r.get("published", "?") or "?"
    endpoint = ve.get("endpoint", "?") or "?"
    verified_hist = data.get("verified", True)
    is_gap_h = bool(data.get("is_gap", False) or r.get("is_gap", False))
    gap_h    = is_gap_h or not poc
    add_row(cve, cls, tech, score, sev, poc, auth, aff, desc, pub, endpoint, verified=verified_hist,
            gap=gap_h, is_gap=is_gap_h)

# 2. Batch reports
batch_dir = os.path.realpath(BATCH_DIR)
if os.path.isdir(batch_dir):
    for fname in sorted(os.listdir(batch_dir)):
        if not fname.endswith(".json"): continue
        with open(os.path.join(batch_dir, fname)) as fh:
            data = json.load(fh)
        cve  = data.get("cve_id", "?")
        llm  = data.get("llm_notes") or {}
        ae   = data.get("attempt_evidence") or {}
        cls  = data.get("vuln_class", "?") or "?"
        tech = ae.get("tecnica","") or llm.get("technique","") or cls
        score = data.get("cvss_score", "?")
        sev   = (data.get("cvss_severity") or "HIGH").upper()
        poc      = bool(data.get("poc_source_used", ""))
        auth     = bool(ae.get("login_bajo_privilegio",""))
        aff      = llm.get("affected_version","?") or "?"
        desc     = (data.get("description") or "")[:120]
        pub      = data.get("published","?") or "?"
        endpoint = ae.get("endpoint","") or llm.get("endpoint","?") or "?"
        verified = bool(data.get("verified", False))
        is_gap_b = bool(data.get("is_gap", False))
        gap_b    = is_gap_b or not poc
        add_row(cve, cls, tech, score, sev, poc, auth, aff, desc, pub, endpoint, verified=verified,
                gap=gap_b, is_gap=is_gap_b)

# Sort by score desc
rows.sort(key=lambda x: float(x["score"]) if str(x["score"]).replace(".","").isdigit() else 0, reverse=True)

SEV_COLOR = {"CRITICAL":"#dc2626","HIGH":"#d97706","MEDIUM":"#2563eb","LOW":"#16a34a"}

def sev_badge(sev, score):
    color = SEV_COLOR.get(sev, "#6b7280")
    return f'<span class="badge" style="background:{color}">{score} {sev}</span>'

def cls_badge(cls):
    colors = {"sqli":"#1e40af","xss":"#9333ea","path-traversal":"#0891b2",
              "lfi":"#0891b2","auth-bypass":"#c2410c","missing-authorization":"#c2410c",
              "command-injection":"#991b1b"}
    color = colors.get(cls.lower(), "#374151")
    return f'<span class="badge badge-sm" style="background:{color}">{h(cls)}</span>'

def _pdf_btn(row):
    return f'<a href="{h(row["cve"])}_informe_pdf.pdf" class="btn-pdf" target="_blank">PDF</a>'

def poc_badge(has_poc, verified=False, is_gap=False, gap=False):
    if is_gap and verified:
        return '<span class="badge badge-sm" style="background:#7c3aed">0-day GAP</span>'
    if gap and verified and not has_poc:
        return '<span class="badge badge-sm" style="background:#6d28d9">LLM-razonado</span>'
    if has_poc and verified:
        return '<span class="badge badge-sm" style="background:#1e40af">PoC publico</span>'
    if has_poc and not verified:
        return '<span class="badge badge-sm" style="background:#374151">PoC (no verif.)</span>'
    if not has_poc and verified:
        return '<span class="badge badge-sm" style="background:#0369a1">HUECO ✓ Verif.</span>'
    return '<span class="badge badge-sm" style="background:#374151">HUECO</span>'

def auth_badge(auth):
    if auth:
        return '<span class="badge badge-sm" style="background:#374151">subscriber</span>'
    return '<span class="badge badge-sm" style="background:#065f46">unauthenticated</span>'

rows_html = ""
for i, row in enumerate(rows):
    sev_lc = row["sev"].lower()
    rows_html += f"""
<tr class="cve-row" data-cls="{row['cls'].lower()}" data-sev="{row['sev'].lower()}" data-poc="{str(row['poc']).lower()}" data-auth="{str(row['auth']).lower()}" data-gap="{str(row.get('gap',False)).lower()}">
  <td class="td-num">{i+1}</td>
  <td class="td-cve"><a href="{h(row['cve'])}_informe_pdf.html" target="_blank"><code>{h(row['cve'])}</code></a></td>
  <td>{sev_badge(row['sev'], row['score'])}</td>
  <td>{cls_badge(row['cls'])}</td>
  <td><code class="tech">{h(row['tech'] or row['cls'])}</code></td>
  <td>{poc_badge(row['poc'], row.get('verified', True), row.get('is_gap', False), row.get('gap', False))}</td>
  <td>{auth_badge(row['auth'])}</td>
  <td class="td-aff"><code>{h(row['aff'])}</code></td>
  <td class="td-pub">{h(row['pub'])}</td>
  <td class="td-desc">{h(row['desc'])}</td>
  <td class="td-links">
    <a href="{h(row['cve'])}_informe_pdf.html" class="btn-report" target="_blank">HTML</a>
    {_pdf_btn(row)}
  </td>
</tr>"""

verified_rows = [r for r in rows if r.get("verified", True)]
stats = {
    "total": len(rows),
    "verified": len(verified_rows),
    "critical": sum(1 for r in rows if r["sev"] == "CRITICAL"),
    "high": sum(1 for r in rows if r["sev"] == "HIGH"),
    "sqli": sum(1 for r in rows if "sqli" in r["cls"].lower()),
    "hueco_ver": sum(1 for r in verified_rows if not r["poc"]),
    "unauth": sum(1 for r in rows if not r["auth"]),
    "llm_reasoned": sum(1 for r in verified_rows if r.get("gap") and not r["poc"]),
    "gap_total": sum(1 for r in verified_rows if r.get("is_gap")),
}

page = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>binoracle — CVE Index</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0a0f1a;color:#e2e8f0;font-family:'Inter',sans-serif;font-size:13px;padding:0 0 60px;min-height:100vh}}
header{{background:#050a14;border-bottom:1px solid #1e293b;padding:20px 40px;display:flex;align-items:center;gap:16px}}
.brand{{font-size:22px;font-weight:900;color:#38bdf8;letter-spacing:-.02em;font-family:'JetBrains Mono',monospace}}
.brand-sub{{font-size:11px;color:#475569;font-weight:500;letter-spacing:.08em;text-transform:uppercase}}
.hdr-spacer{{flex:1}}
.hdr-date{{font-size:11px;color:#475569}}
.stats-bar{{display:flex;gap:0;background:#050a14;border-bottom:1px solid #1e293b}}
.stat{{padding:14px 28px;border-right:1px solid #1e293b;text-align:center}}
.stat-n{{font-size:24px;font-weight:900;line-height:1}}
.stat-l{{font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#475569;margin-top:3px}}
.s-crit{{color:#ef4444}} .s-high{{color:#f59e0b}} .s-blue{{color:#3b82f6}}
.s-purple{{color:#a855f7}} .s-green{{color:#22c55e}} .s-white{{color:#e2e8f0}}
.filters{{padding:16px 40px;background:#0d1424;border-bottom:1px solid #1e293b;display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
.filter-label{{font-size:10px;font-weight:700;letter-spacing:.08em;color:#64748b;text-transform:uppercase;margin-right:4px}}
.f-btn{{padding:4px 12px;border-radius:20px;border:1px solid #1e293b;background:transparent;color:#94a3b8;font-size:11px;font-weight:600;cursor:pointer;transition:all .15s}}
.f-btn:hover,.f-btn.active{{background:#1e40af;border-color:#1e40af;color:#fff}}
.search-box{{padding:5px 14px;border-radius:6px;border:1px solid #1e293b;background:#0a0f1a;color:#e2e8f0;font-size:12px;min-width:200px;margin-left:auto}}
.search-box:focus{{outline:none;border-color:#3b82f6}}
.wrap{{padding:0 40px}}
table{{width:100%;border-collapse:collapse;margin-top:16px}}
th{{padding:8px 10px;text-align:left;font-size:9px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;color:#475569;border-bottom:2px solid #1e293b;background:#050a14;position:sticky;top:0;z-index:2}}
td{{padding:9px 10px;border-bottom:1px solid #111827;vertical-align:top}}
tr.cve-row:hover td{{background:#0d1424}}
tr.hidden{{display:none}}
.td-num{{color:#334155;font-size:11px;width:30px}}
.td-cve a{{color:#38bdf8;text-decoration:none;font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700}}
.td-cve a:hover{{text-decoration:underline}}
.td-aff,.td-pub{{color:#64748b;font-size:11px}}
.td-desc{{color:#94a3b8;font-size:11px;max-width:260px;line-height:1.5}}
code,.tech{{font-family:'JetBrains Mono',monospace;font-size:11px}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:9.5px;font-weight:700;color:#fff;white-space:nowrap;letter-spacing:.02em}}
.badge-sm{{font-size:9px;padding:1px 6px}}
.td-links{{display:flex;gap:4px;white-space:nowrap}}
.btn-report,.btn-pdf{{padding:3px 10px;border-radius:4px;text-decoration:none;font-size:10px;font-weight:700;display:inline-block}}
.btn-report{{background:#1e3a5f;color:#38bdf8;border:1px solid #1e40af}}
.btn-pdf{{background:#1a2535;color:#a3a3a3;border:1px solid #374151}}
.btn-report:hover{{background:#1e40af}}
.btn-pdf:hover{{background:#374151;color:#e2e8f0}}
.no-results{{padding:40px;text-align:center;color:#475569;font-size:14px;display:none}}
.badge-new{{background:#065f46;color:#4ade80;border:1px solid #16a34a;font-size:8px;padding:1px 5px;border-radius:3px;vertical-align:middle;margin-left:4px;letter-spacing:.08em;font-weight:800}}
th.sortable{{cursor:pointer;user-select:none}}
th.sortable:hover{{color:#94a3b8}}
th.sortable::after{{content:' ↕';opacity:.4;font-size:9px}}
th.sortable.asc::after{{content:' ↑';opacity:1;color:#38bdf8}}
th.sortable.desc::after{{content:' ↓';opacity:1;color:#38bdf8}}
.filter-count{{margin-left:auto;font-size:11px;color:#475569;font-family:'JetBrains Mono',monospace}}
.filter-count span{{color:#38bdf8;font-weight:700}}
@media(max-width:900px){{.td-desc,.td-pub,.td-aff{{display:none}}.wrap{{padding:0 16px}}.filters{{padding:12px 16px}}header{{padding:14px 16px}}}}
</style>
</head>
<body>

<header>
  <div>
    <div class="brand">bin0racle</div>
    <div class="brand-sub">CVE Verification Engine</div>
  </div>
  <div class="hdr-spacer"></div>
  <div class="hdr-date">{DATE} &mdash; {stats['total']} CVEs ({stats['verified']} verificados)</div>
</header>

<div class="stats-bar">
  <div class="stat"><div class="stat-n s-white">{stats['total']}</div><div class="stat-l">Total CVEs</div></div>
  <div class="stat"><div class="stat-n s-green">{stats['verified']}</div><div class="stat-l">Verificados</div></div>
  <div class="stat"><div class="stat-n s-crit">{stats['critical']}</div><div class="stat-l">Critical</div></div>
  <div class="stat"><div class="stat-n s-high">{stats['high']}</div><div class="stat-l">High</div></div>
  <div class="stat"><div class="stat-n s-blue">{stats['sqli']}</div><div class="stat-l">SQLi</div></div>
  <div class="stat"><div class="stat-n s-purple">{stats['hueco_ver']}</div><div class="stat-l">HUECO Verif.</div></div>
  <div class="stat"><div class="stat-n s-green">{stats['unauth']}</div><div class="stat-l">Unauthenticated</div></div>
  <div class="stat"><div class="stat-n" style="color:#a78bfa">{stats['llm_reasoned']}</div><div class="stat-l">LLM Razonado</div></div>
  <div class="stat"><div class="stat-n" style="color:#7c3aed">{stats['gap_total']}</div><div class="stat-l">0-day GAP</div></div>
</div>

<div class="filters">
  <span class="filter-label">Clase</span>
  <button class="f-btn active" data-filter="cls" data-val="all">Todos</button>
  <button class="f-btn" data-filter="cls" data-val="sqli">SQLi</button>
  <button class="f-btn" data-filter="cls" data-val="xss">XSS</button>
  <button class="f-btn" data-filter="cls" data-val="path-traversal">Path Traversal</button>
  <button class="f-btn" data-filter="cls" data-val="missing-authorization">Auth Bypass</button>
  <button class="f-btn" data-filter="cls" data-val="command-injection">RCE/Cmd</button>
  <button class="f-btn" data-filter="cls" data-val="ssti">SSTI</button>
  <button class="f-btn" data-filter="cls" data-val="ssrf">SSRF</button>
  &nbsp;
  <span class="filter-label">Severidad</span>
  <button class="f-btn active" data-filter="sev" data-val="all">Todas</button>
  <button class="f-btn" data-filter="sev" data-val="critical">Critical</button>
  <button class="f-btn" data-filter="sev" data-val="high">High</button>
  <button class="f-btn" data-filter="sev" data-val="medium">Medium</button>
  &nbsp;
  <span class="filter-label">PoC</span>
  <button class="f-btn active" data-filter="poc" data-val="all">Todos</button>
  <button class="f-btn" data-filter="poc" data-val="false">HUECO</button>
  <button class="f-btn" data-filter="poc" data-val="true">PoC publico</button>
  &nbsp;
  <span class="filter-label">Auth</span>
  <button class="f-btn active" data-filter="auth" data-val="all">Todos</button>
  <button class="f-btn" data-filter="auth" data-val="false">Unauthenticated</button>
  <button class="f-btn" data-filter="auth" data-val="true">Autenticado</button>
  &nbsp;
  <span class="filter-label">LLM</span>
  <button class="f-btn active" data-filter="gap" data-val="all">Todos</button>
  <button class="f-btn" data-filter="gap" data-val="true" style="border-color:#7c3aed;color:#a78bfa">Sin PoC previo</button>
  <input class="search-box" type="text" id="search" placeholder="Buscar CVE, plugin, endpoint...">
  <span class="filter-count" id="filter-count"><span id="vis-count">{stats['total']}</span> / {stats['total']} CVEs</span>
</div>

<div class="wrap">
<table id="cve-table">
<thead>
<tr>
  <th>#</th>
  <th class="sortable" data-col="cve">CVE</th>
  <th class="sortable" data-col="cvss">CVSS</th>
  <th>Clase</th>
  <th>Tecnica</th>
  <th>PoC</th>
  <th>Auth</th>
  <th class="td-aff">Version</th>
  <th class="sortable td-pub" data-col="pub">Publicado</th>
  <th class="td-desc">Descripcion</th>
  <th>Informe</th>
</tr>
</thead>
<tbody>
{rows_html}
</tbody>
</table>
<div class="no-results" id="no-results">Sin resultados para los filtros seleccionados.</div>
</div>

<script>
const filters = {{}};
let sortCol = null, sortDir = 1;
const total = document.querySelectorAll('.cve-row').length;

// Add NEW badge to 2026 CVEs
document.querySelectorAll('.cve-row').forEach(row => {{
  const pub = row.querySelector('.td-pub');
  if (pub && pub.textContent.trim().startsWith('2026')) {{
    const cveLink = row.querySelector('.td-cve a');
    if (cveLink) cveLink.insertAdjacentHTML('afterend', '<span class="badge-new">NEW</span>');
  }}
}});

// Add data-cvss numeric attribute for sorting
document.querySelectorAll('.cve-row').forEach(row => {{
  const badge = row.querySelector('.badge');
  if (badge) {{
    const m = badge.textContent.match(/[\\d.]+/);
    row.dataset.cvss = m ? parseFloat(m[0]) : 0;
  }}
  const cve = row.querySelector('code');
  row.dataset.cveId = cve ? cve.textContent : '';
  const pubEl = row.querySelector('.td-pub');
  row.dataset.pubDate = pubEl ? pubEl.textContent.trim() : '';
}});

document.querySelectorAll('.f-btn').forEach(btn => {{
  btn.addEventListener('click', () => {{
    const type = btn.dataset.filter;
    const val  = btn.dataset.val;
    filters[type] = val === 'all' ? null : val;
    document.querySelectorAll(`.f-btn[data-filter="${{type}}"]`).forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    applyFilters();
  }});
}});

document.getElementById('search').addEventListener('input', applyFilters);

// Sortable column headers
document.querySelectorAll('th.sortable').forEach(th => {{
  th.addEventListener('click', () => {{
    const col = th.dataset.col;
    if (sortCol === col) {{
      sortDir *= -1;
    }} else {{
      sortCol = col;
      sortDir = col === 'cvss' ? -1 : 1;
    }}
    document.querySelectorAll('th.sortable').forEach(h => h.classList.remove('asc','desc'));
    th.classList.add(sortDir > 0 ? 'asc' : 'desc');
    sortRows();
    applyFilters();
  }});
}});

function sortRows() {{
  const tbody = document.querySelector('#cve-table tbody');
  const rows = Array.from(tbody.querySelectorAll('.cve-row'));
  rows.sort((a, b) => {{
    let av, bv;
    if (sortCol === 'cvss') {{
      av = parseFloat(a.dataset.cvss) || 0;
      bv = parseFloat(b.dataset.cvss) || 0;
    }} else if (sortCol === 'cve') {{
      av = a.dataset.cveId;
      bv = b.dataset.cveId;
    }} else if (sortCol === 'pub') {{
      av = a.dataset.pubDate;
      bv = b.dataset.pubDate;
    }} else return 0;
    return av < bv ? -sortDir : av > bv ? sortDir : 0;
  }});
  rows.forEach((r, i) => {{
    r.querySelector('.td-num').textContent = i + 1;
    tbody.appendChild(r);
  }});
}}

function applyFilters() {{
  const q = document.getElementById('search').value.toLowerCase();
  let visible = 0;
  document.querySelectorAll('.cve-row').forEach(row => {{
    let show = true;
    if (filters.cls && !row.dataset.cls.includes(filters.cls)) show = false;
    if (filters.sev && row.dataset.sev !== filters.sev) show = false;
    if (filters.poc && row.dataset.poc !== filters.poc) show = false;
    if (filters.auth && row.dataset.auth !== filters.auth) show = false;
    if (filters.gap && row.dataset.gap !== filters.gap) show = false;
    if (q && !row.textContent.toLowerCase().includes(q)) show = false;
    row.classList.toggle('hidden', !show);
    if (show) visible++;
  }});
  document.getElementById('no-results').style.display = visible ? 'none' : 'block';
  document.getElementById('filter-count').innerHTML =
    `<span id="vis-count">${{visible}}</span> / ${{total}} CVEs`;
}}
</script>
</body>
</html>"""

out_path = os.path.join(OUT, "index.html")
with open(out_path, "w", encoding="utf-8") as f:
    f.write(page)
print(f"index.html generado: {out_path}")
print(f"  {stats['total']} CVEs, {stats['verified']} verificados, {stats['critical']} critical, {stats['hueco_ver']} HUECO verif.")
