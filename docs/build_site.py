#!/usr/bin/env python3
"""Build the binoracle GitHub Pages site."""
import os, re, shutil, textwrap
import markdown as md

SITE = os.path.join(os.path.dirname(__file__), "site")
DOCS = os.path.dirname(__file__)
ROOT = os.path.dirname(DOCS)

PAGES = []  # Pages are written as custom HTML functions; no markdown-to-HTML conversion needed
# Tutorial is generated inline (no source .md needed)
GEN_PAGES = ["tutorial.html", "tutorial-es.html"]

# ---------------------------------------------------------------------------
# Inline SVG icons (Lucide-style, 20x20)
# ---------------------------------------------------------------------------
ICONS = {
    "shield": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    "cpu":    '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>',
    "server": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>',
    "lock":   '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
    "terminal": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>',
    "package":  '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="16.5" y1="9.4" x2="7.5" y2="4.21"/><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>',
    "github":   '<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0 1 12 6.844a9.59 9.59 0 0 1 2.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0 0 22 12.017C22 6.484 17.522 2 12 2z"/></svg>',
    "book":     '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>',
    "zap":      '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
    "search":   '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
    "arrow-right": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>',
    "check":    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
    "layers":   '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>',
}

def ico(name, cls=""):
    svg = ICONS.get(name, "")
    if cls:
        svg = svg.replace("<svg ", f'<svg class="{cls}" ', 1)
    return svg

# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------
CSS = """
:root {
  --bg:    #0d1117;
  --surf:  #161b22;
  --surf2: #21262d;
  --brd:   #30363d;
  --tx:    #e6edf3;
  --muted: #8b949e;
  --acc:   #58a6ff;
  --acc2:  #1f6feb;
  --pur:   #bc8cff;
  --grn:   #3fb950;
  --yel:   #d29922;
  --red:   #f85149;
  --code:  #7ee2b8;
  --r:     8px;
  --nav-h: 56px;
  --sb-w:  240px;
  font-size: 16px;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; scroll-padding-top: calc(var(--nav-h) + 16px); }
body {
  background: var(--bg);
  color: var(--tx);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  line-height: 1.6;
  min-height: 100vh;
  padding-top: var(--nav-h);
}

/* ── Top nav ───────────────────────────────────────────── */
.nav {
  position: fixed; top: 0; left: 0; right: 0; z-index: 100;
  height: var(--nav-h);
  background: rgba(13,17,23,.95); backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--brd);
  display: flex; align-items: center; gap: 0;
  padding: 0 20px;
}
.nav-brand {
  display: flex; align-items: center; gap: 10px;
  font-weight: 700; font-size: 15px; color: var(--tx);
  text-decoration: none; white-space: nowrap; flex-shrink: 0;
  margin-right: 20px;
}
.nav-brand img { width: 28px; height: 30px; display: block; }
.nav-brand:hover { color: var(--acc); }
.nav-links {
  display: flex; align-items: center; gap: 2px; flex-shrink: 0;
}
.nav-links a {
  color: var(--muted); text-decoration: none; font-size: 14px;
  padding: 6px 12px; border-radius: 6px;
  transition: color .15s, background .15s;
  white-space: nowrap;
}
.nav-links a:hover { color: var(--tx); background: var(--surf2); }
.nav-links a.active { color: var(--acc); }

/* Search */
.nav-search-wrap {
  position: relative; display: flex; align-items: center;
  margin-left: 12px; flex: 1; max-width: 260px;
}
.s-ico {
  position: absolute; left: 10px; color: var(--muted);
  display: flex; pointer-events: none;
}
#nav-search-input {
  width: 100%; background: var(--surf); border: 1px solid var(--brd);
  border-radius: 8px; color: var(--tx);
  font-size: 13px; padding: 6px 68px 6px 34px;
  outline: none; transition: border-color .15s;
}
#nav-search-input:focus { border-color: var(--acc); }
#nav-search-input::placeholder { color: var(--muted); }
.s-kbd {
  position: absolute; right: 8px; display: flex; gap: 2px;
  pointer-events: none;
}
.s-kbd kbd, kbd {
  background: var(--surf2); border: 1px solid var(--brd);
  border-radius: 4px; padding: 1px 5px;
  font-size: 11px; font-family: inherit; color: var(--muted);
}
#search-results {
  display: none; position: absolute; top: calc(100% + 6px); left: 0;
  width: 340px; background: var(--surf); border: 1px solid var(--brd);
  border-radius: 10px; overflow: hidden;
  box-shadow: 0 8px 32px rgba(0,0,0,.5); z-index: 200;
}
#search-results.open { display: block; }
.sr-header {
  padding: 8px 14px; font-size: 11px; font-weight: 700;
  text-transform: uppercase; letter-spacing: .07em; color: var(--muted);
  border-bottom: 1px solid var(--brd);
}
.sr-item {
  display: flex; align-items: center; gap: 10px;
  padding: 10px 14px; text-decoration: none; color: var(--tx);
  transition: background .1s;
}
.sr-item:hover, .sr-item.active { background: var(--surf2); }
.sr-icon { color: var(--muted); flex-shrink: 0; display: flex; }
.sr-title { font-size: 13px; font-weight: 500; }
.sr-tags { font-size: 11px; color: var(--muted); margin-top: 1px; }
.sr-enter { color: var(--muted); font-size: 13px; margin-left: auto; flex-shrink: 0; }
.sr-footer {
  display: flex; gap: 16px; padding: 8px 14px;
  border-top: 1px solid var(--brd); font-size: 11px; color: var(--muted);
}
.sr-footer span { display: flex; align-items: center; gap: 4px; }
.sr-empty { padding: 16px 14px; font-size: 13px; color: var(--muted); }
mark { background: rgba(88,166,255,.25); color: var(--acc); border-radius: 2px; }

.nav-lang {
  display: flex; align-items: center; gap: 6px; margin-left: 12px;
  font-size: 13px; flex-shrink: 0;
}
.nav-lang span { color: var(--tx); font-weight: 600; }
.nav-lang a { color: var(--muted); text-decoration: none; }
.nav-lang a:hover { color: var(--acc); }
.nav-gh {
  display: flex; align-items: center; gap: 7px; margin-left: 12px;
  color: var(--muted); text-decoration: none; font-size: 14px;
  padding: 6px 12px; border: 1px solid var(--brd); border-radius: 7px;
  transition: color .15s, border-color .15s; flex-shrink: 0;
}
.nav-gh:hover { color: var(--tx); border-color: var(--muted); }

/* ── Doc layout ────────────────────────────────────────── */
.doc-layout {
  display: flex; min-height: calc(100vh - var(--nav-h));
}

/* ── Sidebar ───────────────────────────────────────────── */
.doc-sidebar {
  width: var(--sb-w); flex-shrink: 0;
  position: sticky; top: var(--nav-h);
  height: calc(100vh - var(--nav-h)); overflow-y: auto;
  padding: 24px 0 40px;
  border-right: 1px solid var(--brd);
  scrollbar-width: thin; scrollbar-color: var(--brd) transparent;
}
.doc-sidebar a {
  display: block; padding: 5px 20px;
  font-size: 13.5px; color: var(--muted); text-decoration: none;
  border-left: 2px solid transparent;
  transition: color .15s, border-color .15s;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.doc-sidebar a:hover { color: var(--tx); }
.doc-sidebar a.active {
  color: var(--acc); border-left-color: var(--acc);
  background: rgba(88,166,255,.06);
}
.sidebar-section {
  padding: 16px 20px 6px;
  font-size: 11px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .09em; color: var(--muted);
}
.sidebar-sep {
  border: none; border-top: 1px solid var(--brd);
  margin: 12px 20px;
}

/* ── Main content ──────────────────────────────────────── */
.doc-content {
  flex: 1; min-width: 0;
  padding: 40px 48px 80px;
  max-width: 900px;
}
.doc-content h1 {
  font-size: 2rem; font-weight: 700; line-height: 1.25;
  color: var(--tx); margin-bottom: 12px;
  padding-bottom: 14px; border-bottom: 1px solid var(--brd);
}
.doc-content h2 {
  font-size: 1.35rem; font-weight: 600; color: var(--tx);
  margin: 40px 0 12px; padding-bottom: 8px;
  border-bottom: 1px solid var(--brd);
}
.doc-content h3 {
  font-size: 1.1rem; font-weight: 600; color: var(--tx);
  margin: 28px 0 10px;
}
.doc-content h4 {
  font-size: .95rem; font-weight: 600; color: var(--acc);
  margin: 20px 0 8px; text-transform: uppercase;
  letter-spacing: .06em; font-size: 11px;
}
.doc-content p { margin-bottom: 14px; color: var(--tx); }
.doc-content ul, .doc-content ol {
  margin: 0 0 14px 20px;
}
.doc-content li { margin-bottom: 6px; }
.doc-content a { color: var(--acc); text-decoration: none; }
.doc-content a:hover { text-decoration: underline; }
.page-lead {
  font-size: 1.05rem; color: var(--muted);
  margin-bottom: 28px; line-height: 1.65;
}

/* ── Metrics ───────────────────────────────────────────── */
.doc-metrics {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(130px, 1fr));
  gap: 10px; margin: 24px 0;
}
.doc-metric {
  background: var(--surf); border: 1px solid var(--brd);
  border-radius: var(--r); padding: 16px;
  text-align: center;
}
.metric-value {
  font-size: 1.75rem; font-weight: 700; color: var(--acc);
  line-height: 1; font-variant-numeric: tabular-nums;
}
.metric-label {
  font-size: 12px; color: var(--muted); margin-top: 4px;
}

/* ── Callouts ──────────────────────────────────────────── */
.doc-callout {
  border-left: 3px solid var(--brd); border-radius: 0 var(--r) var(--r) 0;
  background: var(--surf); padding: 14px 18px;
  margin: 20px 0; font-size: 14px; line-height: 1.6;
}
.doc-callout.tip    { border-left-color: var(--grn); background: rgba(63,185,80,.07); }
.doc-callout.danger { border-left-color: var(--red); background: rgba(248,81,73,.07); }
.doc-callout.info   { border-left-color: var(--acc); background: rgba(88,166,255,.07); }
.doc-callout.warning{ border-left-color: var(--yel); background: rgba(210,153,34,.07); }
.doc-callout strong { color: var(--tx); }

/* ── Code ──────────────────────────────────────────────── */
pre {
  background: var(--surf2); border: 1px solid var(--brd);
  border-radius: var(--r); padding: 16px 18px;
  overflow-x: auto; margin: 16px 0;
  font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
  font-size: 13px; line-height: 1.65; color: var(--code);
}
pre.doc-pipeline {
  color: var(--muted); font-size: 12px; line-height: 1.8;
  border-style: dashed;
}
code {
  font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
  font-size: .875em; color: var(--code);
  background: var(--surf2); border: 1px solid var(--brd);
  border-radius: 4px; padding: 1px 6px;
}
pre code { background: none; border: none; padding: 0; font-size: inherit; }

/* ── Tables ────────────────────────────────────────────── */
table {
  width: 100%; border-collapse: collapse;
  margin: 16px 0; font-size: 14px;
  border: 1px solid var(--brd); border-radius: var(--r);
  overflow: hidden; display: block; overflow-x: auto;
}
th {
  background: var(--surf2); color: var(--muted);
  font-size: 11px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .07em; padding: 10px 14px; text-align: left;
  border-bottom: 1px solid var(--brd);
}
td {
  padding: 10px 14px; border-bottom: 1px solid var(--brd);
  vertical-align: middle;
}
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(255,255,255,.025); }
.cmp-yes  { color: var(--grn); font-weight: 600; }
.cmp-no   { color: var(--muted); }
.cmp-partial { color: var(--yel); font-weight: 500; }

/* ── Two-column ────────────────────────────────────────── */
.doc-two-col {
  display: grid; grid-template-columns: 1fr 1fr;
  gap: 24px; margin: 20px 0;
}
@media (max-width: 700px) {
  .doc-two-col { grid-template-columns: 1fr; }
}

/* ── Details / summary ─────────────────────────────────── */
details {
  background: var(--surf); border: 1px solid var(--brd);
  border-radius: var(--r); margin: 16px 0; overflow: hidden;
}
summary {
  padding: 12px 16px; cursor: pointer; font-weight: 600;
  font-size: 14px; color: var(--acc); list-style: none;
  user-select: none;
}
summary::-webkit-details-marker { display: none; }
summary::before {
  content: '▶'; display: inline-block; margin-right: 8px;
  font-size: 10px; transition: transform .2s;
}
details[open] summary::before { transform: rotate(90deg); }
details > *:not(summary) { padding: 0 16px 16px; }

/* ── Footer ────────────────────────────────────────────── */
footer {
  border-top: 1px solid var(--brd);
  background: var(--surf);
  margin-top: 40px;
}
.footer {
  max-width: 1200px; margin: 0 auto;
  padding: 24px 48px;
  display: flex; align-items: center; justify-content: space-between;
  gap: 20px; flex-wrap: wrap;
  font-size: 13px; color: var(--muted);
}
.footer-links {
  display: flex; gap: 20px;
}
.footer-links a { color: var(--muted); text-decoration: none; }
.footer-links a:hover { color: var(--tx); }

/* ── Responsive ────────────────────────────────────────── */
@media (max-width: 900px) {
  .doc-sidebar { display: none; }
  .doc-content { padding: 24px 20px 60px; }
  .nav-search-wrap { max-width: 180px; }
}
@media (max-width: 600px) {
  .nav-links { display: none; }
  .nav-gh span { display: none; }
  .doc-metrics { grid-template-columns: repeat(2, 1fr); }
  .footer { padding: 20px 16px; }
}
"""

_TEMPLATE = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} - binoracle docs</title>
<style>
:root {{ --bg:#0e1116; --panel:#151a21; --line:#242b34; --tx:#e6e9ee; --mut:#8b97a6; --acc:#6f9bff;
        --code:#0b0f14; --codetx:#7ee2b8; }}
@media (prefers-color-scheme: light) {{
  :root {{ --bg:#f6f7f9; --panel:#fff; --line:#e5e7eb; --tx:#1c2024; --mut:#6b7280; --acc:#3757e0;
          --code:#f1f3f5; --codetx:#0b3d2e; }}
}}
* {{ box-sizing: border-box; }}
body {{ margin:0; background:var(--bg); color:var(--tx); font-family:-apple-system,system-ui,
       Segoe UI,Roboto,sans-serif; display:flex; min-height:100vh; }}
nav {{ width:220px; flex:0 0 220px; background:var(--panel); border-right:1px solid var(--line);
      padding:20px 14px; position:sticky; top:0; height:100vh; overflow-y:auto; }}
nav a {{ display:block; padding:8px 10px; border-radius:6px; color:var(--tx); text-decoration:none;
        font-size:14px; margin-bottom:2px; }}
nav a.active {{ background:var(--acc); color:#fff; }}
nav a:hover:not(.active) {{ background:var(--line); }}
nav .brand {{ font-weight:700; font-size:16px; margin-bottom:16px; color:var(--acc); }}
main {{ flex:1; padding:32px 40px; max-width:900px; }}
h1, h2, h3 {{ color:var(--tx); }}
h1 {{ border-bottom:1px solid var(--line); padding-bottom:10px; }}
code {{ background:var(--code); color:var(--codetx); padding:2px 5px; border-radius:4px;
       font-size:0.9em; }}
pre {{ background:var(--code); color:var(--codetx); padding:14px; border-radius:8px;
      overflow-x:auto; line-height:1.5; }}
pre code {{ background:none; padding:0; }}
a {{ color:var(--acc); }}
table {{ border-collapse:collapse; width:100%; margin:12px 0; }}
th, td {{ border:1px solid var(--line); padding:6px 10px; text-align:left; font-size:0.92em; }}
blockquote {{ border-left:3px solid var(--acc); margin:12px 0; padding:4px 14px; color:var(--mut); }}
</style>
</head>
<body>
<nav>
  <div class="brand"><img src="assets/logo.svg" alt="binoracle" width="64" height="70" style="display:block;margin:0 auto 10px;"><span style="display:block;text-align:center;">binoracle docs</span></div>
  {navlinks}
</nav>
<main>
{body}
</main>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# HTML building blocks
# ---------------------------------------------------------------------------
SEARCH_INDEX = [
    ("Home", "index.html", ["cve", "binary", "re", "exploit", "install", "quick start", "pipeline", "overview"]),
    ("Docs (ES)", "index-es.html", ["instalacion", "motor cve", "binario", "informes", "mcp", "configuracion"]),
    ("Tutorial (EN)", "tutorial.html", ["tutorial", "step by step", "configure", "binary re", "reports"]),
    ("Tutorial (ES)", "tutorial-es.html", ["tutorial", "paso a paso", "configurar", "binario", "informes"]),
    ("Roadmap", "roadmap.html", ["roadmap", "v0.2", "v0.3", "v0.4", "v0.5", "features", "planned"]),
    ("Architecture", "architecture.html", ["architecture", "components", "cli", "workflows", "oracles", "mcp server", "store", "diagrama"]),
    ("CVE Chains", "cve-chains.html", ["cve chain", "multi-cve", "cadena", "exploit chain", "rce", "cve-chain"]),
    ("Firmware Analysis", "firmware.html", ["firmware", "embedded", "flash", "squashfs", "binwalk", "iot", "layers"]),
    ("Kernel Exploits", "kernel-exploits.html", ["kernel", "exploit", "ret2usr", "smep", "kaslr", "lpe", "privilege escalation", "lkm"]),
    ("LoRA Fine-tuning", "finetune.html", ["finetune", "lora", "sft", "dataset", "jsonl", "training", "model", "fine-tuning"]),
    ("MCP Tools Reference", "mcp-tools.html", ["mcp", "tools", "claude desktop", "vscode", "server", "api", "tools reference"]),
]

def nav(current="index", lang_other=None):
    links = [
        ("index",    "index.html",    "Home"),
        ("docs",     "index-es.html", "Docs"),
        ("tutorial", "tutorial.html", "Tutorial"),
        ("roadmap",  "roadmap.html",  "Roadmap"),
    ]
    items = ""
    for key, href, label in links:
        cls = ' class="active"' if key == current else ""
        items += f'<a href="{href}"{cls}>{label}</a>\n'
    lang_html = ''
    if lang_other:
        alt_label, alt_href = lang_other
        cur_label = "ES" if alt_label == "EN" else "EN"
        lang_html = f'<div class="nav-lang"><span>{cur_label}</span><a href="{alt_href}">{alt_label}</a></div>'
    # Page icons per category
    page_icons = {
        "index.html": "zap", "index-es.html": "book", "tutorial.html": "terminal",
        "tutorial-es.html": "terminal", "roadmap.html": "layers",
        "architecture.html": "cpu", "cve-chains.html": "shield",
        "firmware.html": "package", "kernel-exploits.html": "lock",
        "finetune.html": "cpu", "mcp-tools.html": "server",
    }
    # Page descriptions
    page_desc = {
        "index.html": "Overview, install, quick start",
        "index-es.html": "Inicio, instalación, motor CVE",
        "tutorial.html": "Step-by-step guide — CVE to exploit",
        "tutorial-es.html": "Guía paso a paso — CVE al exploit",
        "roadmap.html": "v0.2–v0.5 planned features",
        "architecture.html": "Components, oracles, MCP, workflows",
        "cve-chains.html": "Multi-CVE chaining, exploit chains",
        "firmware.html": "IoT firmware extraction & analysis",
        "kernel-exploits.html": "Kernel LPE, ret2usr, SMEP bypass",
        "finetune.html": "LoRA fine-tuning on security data",
        "mcp-tools.html": "Claude Desktop / VS Code MCP tools",
    }
    search_items_js = ""
    for title, href, keywords in SEARCH_INDEX:
        kw_js = ", ".join(f'"{k}"' for k in keywords)
        icon = page_icons.get(href, "book")
        desc = page_desc.get(href, "")
        search_items_js += f'  {{title:"{title}",href:"{href}",kw:[{kw_js}],icon:"{icon}",desc:"{desc}"}},\n'
    s_ico_svg = ico('search','').replace('width="20" height="20"','width="15" height="15"')
    return f"""
<nav class="nav">
  <a class="nav-brand" href="index.html">
    <img src="assets/logo.svg" alt="binoracle logo">
    binoracle
  </a>
  <div class="nav-links">
    {items}
  </div>
  <div class="nav-search-wrap" id="nav-search-wrap">
    <span class="s-ico">{s_ico_svg}</span>
    <input type="search" id="nav-search-input" placeholder="Search docs..." autocomplete="off" aria-label="Search docs" spellcheck="false">
    <span class="s-kbd"><kbd>⌘</kbd><kbd>K</kbd></span>
    <div id="search-results"></div>
  </div>
  {lang_html}
  <a class="nav-gh" href="https://github.com/beafn28/binoracle" target="_blank" rel="noopener">
    {ico('github')} GitHub
  </a>
</nav>
<script>
(function(){{
var ICONS={{}};
{chr(10).join(f"ICONS['{k}']='{v.replace(chr(39), chr(92)+chr(39))}'" for k,v in {
    'zap': ico('zap','sr-icon').replace('width="20" height="20"','width="16" height="16"'),
    'book': ico('book','sr-icon').replace('width="20" height="20"','width="16" height="16"'),
    'terminal': ico('terminal','sr-icon').replace('width="20" height="20"','width="16" height="16"'),
    'layers': ico('layers','sr-icon').replace('width="20" height="20"','width="16" height="16"'),
    'cpu': ico('cpu','sr-icon').replace('width="20" height="20"','width="16" height="16"'),
    'shield': ico('shield','sr-icon').replace('width="20" height="20"','width="16" height="16"'),
    'package': ico('package','sr-icon').replace('width="20" height="20"','width="16" height="16"'),
    'lock': ico('lock','sr-icon').replace('width="20" height="20"','width="16" height="16"'),
    'server': ico('server','sr-icon').replace('width="20" height="20"','width="16" height="16"'),
}.items())}
var idx=[
{search_items_js}];
var inp=document.getElementById('nav-search-input');
var box=document.getElementById('search-results');
var cur=-1;
if(!inp)return;
function esc(s){{return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;')}}
function hi(text,q){{
  if(!q)return esc(text);
  var i=text.toLowerCase().indexOf(q.toLowerCase());
  if(i<0)return esc(text);
  return esc(text.slice(0,i))+'<mark>'+esc(text.slice(i,i+q.length))+'</mark>'+esc(text.slice(i+q.length));
}}
function render(hits,q){{
  if(!hits.length){{
    box.innerHTML='<div class="sr-empty">No results for <strong>'+esc(q)+'</strong></div>';
    box.classList.add('open');cur=-1;return;
  }}
  var html='<div class="sr-header">Pages — '+hits.length+' found</div>';
  hits.forEach(function(e,i){{
    var icon=ICONS[e.icon]||ICONS['book'];
    html+='<a class="sr-item" href="'+e.href+'" data-idx="'+i+'">'
      +'<span class="sr-icon">'+icon+'</span>'
      +'<span style="flex:1;min-width:0"><div class="sr-title">'+hi(e.title,q)+'</div>'
      +(e.desc?'<div class="sr-tags">'+esc(e.desc)+'</div>':'')
      +'</span>'
      +'<span class="sr-enter">↩</span>'
      +'</a>';
  }});
  html+='<div class="sr-footer">'
    +'<span><kbd>↑</kbd><kbd>↓</kbd> navegar</span>'
    +'<span><kbd>↩</kbd> abrir</span>'
    +'<span><kbd>Esc</kbd> cerrar</span>'
    +'</div>';
  box.innerHTML=html;
  box.classList.add('open');
  cur=-1;
}}
function setActive(n){{
  var items=box.querySelectorAll('.sr-item');
  if(!items.length)return;
  if(cur>=0&&cur<items.length)items[cur].classList.remove('active');
  cur=(n+items.length)%items.length;
  items[cur].classList.add('active');
  items[cur].scrollIntoView({{block:'nearest'}});
}}
inp.addEventListener('input',function(){{
  var q=inp.value.trim().toLowerCase();
  if(!q){{box.innerHTML='';box.classList.remove('open');cur=-1;return;}}
  var hits=idx.filter(function(e){{
    return e.title.toLowerCase().includes(q)||e.kw.some(function(k){{return k.includes(q);}});
  }});
  render(hits,q);
}});
inp.addEventListener('focus',function(){{
  if(!inp.value.trim()&&!box.classList.contains('open')){{
    render(idx,'');
  }}
}});
inp.addEventListener('keydown',function(e){{
  if(!box.classList.contains('open'))return;
  if(e.key==='ArrowDown'){{e.preventDefault();setActive(cur+1);}}
  else if(e.key==='ArrowUp'){{e.preventDefault();setActive(cur-1);}}
  else if(e.key==='Enter'){{
    var items=box.querySelectorAll('.sr-item');
    if(cur>=0&&cur<items.length){{e.preventDefault();location.href=items[cur].href;}}
  }}
  else if(e.key==='Escape'){{box.classList.remove('open');inp.blur();cur=-1;}}
}});
document.addEventListener('keydown',function(e){{
  if((e.metaKey||e.ctrlKey)&&e.key==='k'){{e.preventDefault();inp.focus();inp.select();}}
}});
document.addEventListener('click',function(e){{
  if(!document.getElementById('nav-search-wrap').contains(e.target)){{
    box.classList.remove('open');cur=-1;
  }}
}});
}})();
</script>"""

def footer():
    return """
<footer>
  <div class="footer">
    <span>MIT &copy; 2024&ndash;2026 Beatriz Fresno Naumova</span>
    <div class="footer-links">
      <a href="index.html">Home</a>
      <a href="roadmap.html">Roadmap</a>
      <a href="https://github.com/beafn28/binoracle/issues" target="_blank" rel="noopener">Issues</a>
      <a href="https://github.com/beafn28/binoracle" target="_blank" rel="noopener">GitHub</a>
    </div>
  </div>
</footer>"""

def shell(title, current, body, lang_other=None):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<meta name="description" content="binoracle — autonomous CVE exploit research and binary reverse engineering, fully local.">
<style>{CSS}</style>
</head>
<body>
{nav(current, lang_other)}
{body}
{footer()}
</body>
</html>"""

# ---------------------------------------------------------------------------
# Wiki sidebar — shared across all documentation pages
# ---------------------------------------------------------------------------
def wiki_sidebar(current, lang="en"):
    section_map = {
        "index": [
            ("#overview",         "Overview"),
            ("#quick-start",      "Quick Start"),
            ("#two-pipelines",    "Two Pipelines"),
            ("#cve-engine",       "CVE Engine"),
            ("#cve-how",          "↳ How it works"),
            ("#cve-vuln-classes", "↳ Vuln classes"),
            ("#cve-commands",     "↳ Commands"),
            ("#binary-re",        "Binary RE Engine"),
            ("#re-analysis",      "↳ Analysis types"),
            ("#re-exploitation",  "↳ Exploitation"),
            ("#re-formats",       "↳ Formats"),
            ("#re-commands",      "↳ Commands"),
            ("#reports",          "Reports"),
            ("#mcp-server",       "MCP Integration"),
            ("#cli-reference",    "CLI Reference"),
            ("#installation",     "Installation"),
            ("#configuration",    "Configuration"),
            ("#comparison",       "Comparison"),
            ("#roadmap",          "Roadmap"),
        ],
        "docs": [
            ("#descripcion",    "Descripción"),
            ("#instalacion",    "Instalación"),
            ("#dos-motores",    "Dos motores"),
            ("#motor-cve",      "Motor CVE"),
            ("#motor-re-binario","Motor RE Binario"),
            ("#informes",       "Informes"),
            ("#integracion-mcp","Integración MCP"),
            ("#referencia-comandos","Referencia CLI"),
            ("#arquitectura",   "Arquitectura"),
            ("#corpus",         "Corpus"),
            ("#configuracion",  "Configuración"),
            ("#comparacion",    "Comparación"),
            ("#hoja-ruta",      "Hoja de ruta"),
        ],
        "tutorial": (
            [
                ("#overview",  "Overview"),
                ("#install",   "Installation"),
                ("#configure", "Configuration"),
                ("#cve",       "CVE Engine"),
                ("#binary",    "Binary RE"),
                ("#mcp",       "MCP Server"),
                ("#reports",   "Reports"),
                ("#corpus",    "Practice Corpus"),
            ] if lang == "en" else [
                ("#descripcion",  "Descripción"),
                ("#instalacion",  "Instalación"),
                ("#configuracion","Configuración"),
                ("#motor-cve",    "Motor CVE"),
                ("#binario",      "Motor RE Binario"),
                ("#mcp",          "Servidor MCP"),
                ("#informes",     "Informes"),
                ("#corpus",       "Corpus de práctica"),
            ]
        ),
        "roadmap": [
            ("#v02",          "v0.2"),
            ("#v03",          "v0.3"),
            ("#v04",          "v0.4"),
            ("#v05",          "v0.5"),
            ("#cross-cutting","Cross-cutting quality"),
            ("#out-of-scope", "Out of scope"),
        ],
        "architecture": [
            ("#overview",     "Overview"),
            ("#components",   "Components"),
            ("#diagram",      "Architecture Diagram"),
            ("#data-flow",    "Data Flow"),
            ("#cli-layer",    "CLI Layer"),
            ("#agent-layer",  "Agent Layer"),
            ("#oracle-layer", "Oracle Layer"),
            ("#report-layer", "Report Layer"),
            ("#store",        "Session Store"),
            ("#mcp-layer",    "MCP Server"),
        ],
        "cve-chains": [
            ("#overview",     "Overview"),
            ("#what-is",      "What are CVE chains"),
            ("#pipeline",     "Chain Pipeline"),
            ("#diagram",      "Chain Flow Diagram"),
            ("#command",      "Command Reference"),
            ("#examples",     "Examples"),
            ("#output",       "Output Format"),
        ],
        "firmware": [
            ("#overview",     "Overview"),
            ("#layers",       "Firmware Layers"),
            ("#extraction",   "Extraction"),
            ("#analysis",     "Binary Analysis"),
            ("#mitigations",  "Mitigations"),
            ("#use-cases",    "Use Cases"),
        ],
        "kernel-exploits": [
            ("#overview",     "Overview"),
            ("#techniques",   "Techniques"),
            ("#radare2",      "Radare2 Workflow"),
            ("#smep-bypass",  "SMEP Bypass"),
            ("#examples",     "Examples"),
        ],
        "finetune": [
            ("#overview",     "Overview"),
            ("#architecture", "LoRA Architecture"),
            ("#dataset",      "Dataset Generation"),
            ("#command",      "finetune Command"),
            ("#jsonl",        "JSONL Format"),
            ("#workflow",     "Full Workflow"),
        ],
        "mcp-tools": [
            ("#overview",     "Overview"),
            ("#setup",        "Setup"),
            ("#tools-list",   "Tools Reference"),
            ("#claude-desktop","Claude Desktop"),
            ("#vscode",       "VS Code"),
            ("#examples",     "Examples"),
        ],
        "web-ui": [
            ("#overview",     "Overview"),
            ("#start",        "Starting the UI"),
            ("#exploit-dev",  "Exploit Dev"),
            ("#binary-lab",   "Binary Lab"),
            ("#all-tools",    "All Tools"),
        ],
    }

    sections = section_map.get(current, [])
    toc_html = "".join(f'<a href="{h}">{l}</a>\n' for h, l in sections)

    lang_toggle = ""

    if lang == "en":
        sec_lbl, nav_lbl, lnk_lbl = "On this page", "Navigation", "Links"
    else:
        sec_lbl, nav_lbl, lnk_lbl = "En esta página", "Navegación", "Enlaces"

    toc_block = (
        f'<p class="sidebar-section">{sec_lbl}</p>\n{toc_html}'
        f'<hr class="sidebar-sep">\n'
    ) if toc_html else ""

    if lang == "en":
        nav_items = [
            ("index",          "index.html",         "Home"),
            ("docs",           "index-es.html",      "Docs (ES)"),
            ("tutorial",       "tutorial.html",      "Tutorial"),
            ("roadmap",        "roadmap.html",       "Roadmap"),
            ("architecture",   "architecture.html",  "Architecture"),
            ("cve-chains",     "cve-chains.html",    "CVE Chains"),
            ("firmware",       "firmware.html",      "Firmware"),
            ("kernel-exploits","kernel-exploits.html","Kernel Exploits"),
            ("finetune",       "finetune.html",      "Fine-tuning"),
            ("mcp-tools",      "mcp-tools.html",     "MCP Tools"),
            ("web-ui",         "web-ui.html",        "Web UI"),
        ]
    else:
        nav_items = [
            ("docs",     "index-es.html",    "Inicio"),
            ("index",    "index.html",       "Home (EN)"),
            ("tutorial", "tutorial-es.html", "Tutorial"),
            ("roadmap",  "roadmap.html",     "Roadmap"),
        ]

    nav_html = ""
    for key, href, label in nav_items:
        cls = ' class="active"' if key == current else ""
        nav_html += f'<a href="{href}"{cls}>{label}</a>\n'

    return (
        f'<aside class="doc-sidebar">\n'
        f'{lang_toggle}'
        f'{toc_block}'
        f'<p class="sidebar-section">{nav_lbl}</p>\n'
        f'{nav_html}'
        f'<hr class="sidebar-sep">\n'
        f'<p class="sidebar-section">{lnk_lbl}</p>\n'
        f'<a href="https://github.com/beafn28/binoracle" target="_blank" rel="noopener">GitHub ↗</a>\n'
        f'<a href="https://github.com/beafn28/binoracle/issues" target="_blank" rel="noopener">Issues ↗</a>\n'
        f'</aside>'
    )

# ---------------------------------------------------------------------------
# Landing page (English wiki home)
# ---------------------------------------------------------------------------
def index_page():
    vuln_rows = [
        ("SSTI", "Jinja2, Twig, Smarty", "yes"),
        ("SQLi (GET / POST / JSON / header)", "Python, Ruby, PHP, Java", "yes"),
        ("Path traversal / LFI", "Python, Ruby, Node, httpd", "yes"),
        ("RCE / command injection", "Python, Ruby, Node", "yes"),
        ("XSS (reflected / stored)", "Python, Node", "yes"),
        ("SSRF", "Python, Node", "yes"),
        ("XXE", "Java / Maven", "yes"),
        ("Deserialization", "Java, Ruby (Marshal)", "yes"),
        ("Auth bypass / IDOR", "Python, Ruby, Node", "yes"),
        ("File upload / webshell", "Python", "yes"),
        ("Open redirect", "Python, Ruby, Node", "yes"),
        ("CSRF", "Python, Ruby", "yes"),
        ("WordPress plugins (100+)", "WP Docker", "yes"),
        ("Joomla extensions", "Joomla Docker", "yes"),
        ("Drupal modules", "Drupal Docker", "yes"),
        ("Apache httpd", "httpd Docker", "yes"),
        ("Spring / Struts / Log4j", "Maven", "yes"),
        ("PHP Composer packages", "PHP Docker", "yes"),
        ("npm / Node.js / Next.js", "Node Docker", "yes"),
        ("Ruby gems (Rails, Rack, Sinatra)", "Ruby Docker", "yes"),
    ]
    vuln_trs = "\n".join(
        f'<tr><td>{cls}</td><td><code>{eco}</code></td><td class="cmp-yes">{poc}</td></tr>'
        for cls, eco, poc in vuln_rows
    )

    exploit_rows = [
        ("Stack", "ret2win, ret2libc, ret2plt, ret2csu, SROP (x86-64/x86-32/aarch64), stack pivot, ROP chains"),
        ("Heap", "tcache dup, fastbin dup, UAF, double-free, House-of-Force/Spirit/Orange/Mind, large-bin attack, Botcake"),
        ("Format string", "%n arbitrary write, GOT overwrite, canary leak, PIE leak"),
        ("Low-level", "shellcode (NX off), bad-char scrubbing, IO_FILE exploit, DL-resolve, GOT hijack"),
        ("Canary bypass", "leak + reuse, fork brute-force"),
        ("PIE bypass", "partial overwrite, leak chain"),
    ]
    exploit_trs = "\n".join(
        f"<tr><td><strong>{fam}</strong></td><td>{tech}</td></tr>"
        for fam, tech in exploit_rows
    )

    format_rows = [
        ("ELF (x86-64 / x86 / ARM / MIPS / RISC-V)", "radare2, pyelftools, pwntools, angr, pwndbg"),
        ("PE / PE+ (Windows)", "pefile, LIEF, radare2"),
        ("Mach-O (macOS / iOS)", "LIEF, radare2"),
        ("APK / DEX (Android)", "apktool, jadx, androguard"),
        (".NET assemblies", "dnlib, ILSpy"),
        ("Go binaries", "go-dis, symbol recovery"),
        ("Rust binaries", "LIEF + symbol demangling"),
        ("WASM modules", "wabt, binaryen"),
        ("EVM bytecode", "pyevmasm"),
        ("SQLite databases", "sqlite3 schema + data dump"),
    ]
    format_trs = "\n".join(
        f"<tr><td>{fmt}</td><td>{be}</td></tr>"
        for fmt, be in format_rows
    )

    cmd_rows = [
        ("triage", "Mitigations, symbols, imports, sections"),
        ("decompile", "Ghidra / radare2 / angr / pwndbg + LLM annotation"),
        ("pwn", "Full exploit chain, technique auto-selected"),
        ("rop", "ROP gadget search and chain synthesis"),
        ("chain", "Gadget enumeration + pwntools script output"),
        ("heap", "Heap exploit primitives (tcache / fastbin / UAF / House-of-X)"),
        ("fmt", "Format string exploitation"),
        ("srop", "SROP chain generator"),
        ("shellcode", "Shellcode with bad-char filtering"),
        ("fuzz", "Dumb and smart fuzzer (AFL integration)"),
        ("dynamic", "strace / ltrace / gdb automation"),
        ("hardening", "Mitigation audit with bypass notes"),
        ("cve", "Full CVE pipeline: fetch -&gt; lab -&gt; PoC -&gt; report"),
        ("cve-batch", "Parallelised batch CVE pipeline"),
        ("vuln-hunt", "Static taint analysis (sinks, sources)"),
        ("ioc-scan", "IOC and malware indicator scan"),
        ("audit", "All oracles + LLM synthesis"),
        ("reachability", "Source-to-sink reachability"),
        ("diff", "Patch diff and N-day analysis"),
        ("apk", "Android APK audit"),
        ("dotnet", ".NET assembly inspection"),
        ("wasm", "WASM module inspection"),
        ("sqlite", "SQLite schema + data audit"),
        ("evm", "EVM bytecode inspection"),
        ("mcp-server", "Start MCP server"),
        ("web", "Start local web UI"),
    ]
    cmd_trs = "\n".join(
        f"<tr><td><code>{cmd}</code></td><td>{desc}</td></tr>"
        for cmd, desc in cmd_rows
    )

    cmp_rows = [
        ("Autonomous CVE pipeline (NVD -&gt; lab -&gt; PoC)", "yes", "no"),
        ("Local LLM via Ollama", "yes", "no"),
        ("Ephemeral Docker labs per CVE", "yes", "no"),
        ("Playwright screenshot evidence in reports", "yes", "no"),
        ("WordPress / Joomla / Drupal lab scaffolding", "yes", "no"),
        ("MCP server (~100 tools)", "yes", "no"),
        ("APK / .NET / WASM / EVM analysis", "yes", "partial"),
        ("Fully offline operation", "yes", "partial"),
        ("Stack / heap / format string / SROP exploit chains", "yes", "yes"),
        ("ROP chain synthesis", "yes", "yes"),
        ("Multi-backend decompilation", "yes", "yes"),
        ("Practice corpus", "yes", "yes"),
    ]
    cmp_trs = "\n".join(
        f'<tr><td>{cap}</td><td class="cmp-yes">{b}</td>'
        f'<td class="cmp-{"yes" if r == "yes" else ("partial" if r == "partial" else "no")}">{r}</td></tr>'
        for cap, b, r in cmp_rows
    )

    body = f"""
<div class="doc-layout">
  {wiki_sidebar("index", "en")}
  <main class="doc-content">

    <h1 id="overview">binoracle</h1>
    <p class="page-lead">Autonomous CVE exploit research and binary reverse engineering tool. All analysis runs locally — no data is sent to external services.</p>

    <div class="doc-metrics">
      <div class="doc-metric"><div class="metric-value">20+</div><div class="metric-label">CVE classes</div></div>
      <div class="doc-metric"><div class="metric-value">50+</div><div class="metric-label">Exploit families</div></div>
      <div class="doc-metric"><div class="metric-value">10</div><div class="metric-label">Binary formats</div></div>
      <div class="doc-metric"><div class="metric-value">~100</div><div class="metric-label">MCP tools</div></div>
      <div class="doc-metric"><div class="metric-value">40+</div><div class="metric-label">Practice samples</div></div>
    </div>

    <div class="doc-callout danger">
      <strong>Legal notice.</strong> binoracle is a research and educational tool. All CVE labs run exclusively against Docker containers you provision locally on your own machine. Do not use this tool against systems you do not own or for which you lack explicit written authorization.
    </div>

    <h2 id="quick-start">Quick Start</h2>
    <p>Prerequisites: Python 3.10+, Docker 20.x+, Ollama 0.3+.</p>
    <pre><code># 1. Install binoracle
pip install binoracle

# 2. Install Ollama and pull the model (Linux / macOS)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder:7b

# 3. Configure the LLM backend
export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=http://127.0.0.1:11434/v1
export BINORACLE_MODEL=qwen2.5-coder:7b

# 4. Run the CVE engine on a real CVE
binoracle cve CVE-2025-27516

# 5. Analyse a binary
binoracle triage ./target_binary</code></pre>

    <div class="doc-callout tip">
      <strong>Persist configuration.</strong> Add the three <code>export</code> lines to <code>~/.bashrc</code> or <code>~/.zshrc</code> so they survive shell restarts.
    </div>

    <h2 id="two-pipelines">Two Pipelines</h2>
    <p>binoracle exposes two independent analysis pipelines that can be used separately or combined.</p>
    <div class="doc-two-col">
      <div>
        <h4>CVE Pipeline</h4>
        <p>Takes a CVE identifier. Retrieves the NVD descriptor, passes it to a local LLM which generates exploit hypotheses autonomously. Provisions an ephemeral Docker Compose lab, executes the proof-of-concept, records Playwright screenshots at every verification step, and emits a self-contained HTML report to disk.</p>
        <p>No data is sent to external services. The LLM runs entirely on your machine via Ollama.</p>
        <pre><code>binoracle cve CVE-2025-27516
binoracle cve-batch CVE-2025-27516 CVE-2024-23334</code></pre>
      </div>
      <div>
        <h4>Binary RE Pipeline</h4>
        <p>Takes a binary file. Runs static analysis (symbols, imports, sections, mitigations), optionally dynamic tracing, feeds the decompiled output to the LLM which selects an exploit technique and generates a working pwntools script. Outputs a structured HTML report with the full reasoning chain.</p>
        <p>Supports ELF, PE, Mach-O, APK, WASM, Go, Rust, .NET, EVM, and SQLite formats.</p>
        <pre><code>binoracle triage ./binary
binoracle pwn    ./binary</code></pre>
      </div>
    </div>

    <h2 id="cve-engine">CVE Engine — Autonomous Exploit Development</h2>
    <p>The CVE engine is a fully autonomous exploit-development pipeline. It receives a CVE identifier and, without any analyst-supplied hints, derives a working proof-of-concept, verifies it in an isolated Docker lab, and emits a self-contained HTML report with Playwright screenshots.</p>

    <pre class="doc-pipeline"> NVD / NIST          LLM local           Source code         Docker lab         Playwright          HTML report
 CVE descriptor  ──▶  Qwen 2.5 Coder  ──▶  static scanner  ──▶  ephemeral env  ──▶  screenshots    ──▶  disk only
                      zero hints           deterministic        Docker Compose      each step           HTML+CSS</pre>

    <h3 id="cve-how">How it works — 7 stages</h3>
    <table>
      <thead><tr><th>Stage</th><th>What happens</th><th>Component</th></tr></thead>
      <tbody>
        <tr>
          <td><strong>1 · NVD fetch</strong></td>
          <td>Retrieves the CVE record (CVSS score, affected version, plain-language description) from NIST/NVD plus any GitHub advisories or Exploit-DB entries found in the wild.</td>
          <td><code>cve_agent.py</code></td>
        </tr>
        <tr>
          <td><strong>2 · LLM hypothesis</strong></td>
          <td>The local LLM reads the raw description and proposes a structured exploit plan: vulnerability class (SSTI, SQLi, XSS, RCE…), affected endpoint or parameter, payload strategy, and which Docker scaffolder to provision. No human prompts guide this step.</td>
          <td><code>cve_agent.py</code></td>
        </tr>
        <tr>
          <td><strong>3 · Source-code download</strong></td>
          <td>The engine downloads the exact vulnerable version of the package (WordPress plugin, PyPI/npm/Composer/RubyGems package, or CMS) from its public registry and caches it locally.</td>
          <td><code>cve_agent.py</code></td>
        </tr>
        <tr>
          <td><strong>4 · Deterministic scanner</strong></td>
          <td>A static scanner reads the source code — no LLM at this step — and traces the injection path deterministically: it locates the REST/AJAX endpoint, the DB write, the render context (href, html, js_innerHTML, url, js_string), and derives the exact payload transform needed (e.g. base64-encode for WP REST API). This is the layer that catches render contexts the LLM might miss.</td>
          <td><code>websource.py</code></td>
        </tr>
        <tr>
          <td><strong>5 · Docker lab</strong></td>
          <td>Spins up an ephemeral Docker Compose environment scoped to the CVE: the right CMS version, the right DB, the right plugin or package. For WordPress CVEs this includes wp-cli installation, plugin activation, and subscriber/admin user creation. The lab is torn down automatically after the run.</td>
          <td><code>wpverify.py</code></td>
        </tr>
        <tr>
          <td><strong>6 · Headless browser verification</strong></td>
          <td>Playwright drives a real Chromium instance to execute the exploit: injects payloads via the REST/AJAX endpoint as a low-privilege user, then loads the admin view and checks whether the XSS fires (document.title marker), the SQLi leaks data, or the SSRF reaches the internal host. Captures a screenshot at every verification step.</td>
          <td><code>wpverify.py</code></td>
        </tr>
        <tr>
          <td><strong>7 · Report</strong></td>
          <td>Emits a self-contained HTML report to disk: executive summary, CVSS score, full LLM reasoning chain, winning payload, step-by-step Playwright screenshots, complete curl / Python PoC, and remediation guidance.</td>
          <td><code>report.py</code></td>
        </tr>
      </tbody>
    </table>

    <div class="doc-callout tip">
      <strong>Deterministic scanner vs. LLM.</strong> The two layers complement each other. The LLM identifies the vulnerability class and rough attack surface. The deterministic scanner reads the actual source code to find the exact endpoint, DB table, column name, payload transform, and render context — without hallucinating. Only the scanner output is used for the actual exploit attempt.
    </div>

    <h3 id="cve-vuln-classes">Supported vulnerability classes</h3>
    <table>
      <thead><tr><th>Class</th><th>Ecosystems</th><th>Auto PoC</th></tr></thead>
      <tbody>{vuln_trs}</tbody>
    </table>

    <h3 id="cve-commands">Commands</h3>
    <pre><code># Single CVE, default language (Spanish)
binoracle cve CVE-2025-27516

# Single CVE, English report, open in browser
binoracle cve CVE-2025-27516 --lang en --open-report

# Single CVE, custom output directory
binoracle cve CVE-2025-27516 --out ./reports/

# Batch run, parallelized
binoracle cve-batch CVE-2025-27516 CVE-2024-23334 CVE-2025-59681

# Batch with output directory
binoracle cve-batch CVE-2025-27516 CVE-2024-23334 --out ./reports/</code></pre>

    <h2 id="binary-re">Binary RE Engine — Reversing &amp; Exploitation</h2>
    <p>The binary RE engine takes a binary file and autonomously produces an exploit chain, decompiled output with LLM annotations, and a structured HTML report. It covers 50+ exploit techniques across all major binary formats. All analysis runs locally — the binary is never uploaded anywhere.</p>

    <pre class="doc-pipeline"> Binary input
     │
     ├── 1 · Static triage ── checksec, symbols, imports, section layout, entropy scan
     │
     ├── 2 · Multi-backend decompile ── Ghidra / radare2 / angr / pwndbg (auto-selected)
     │                                   + LLM annotation of decompiled pseudocode
     │
     ├── 3 · Vuln pattern detection ── taint analysis, dangerous sinks, format-string calls,
     │                                  integer overflows, UAF patterns, stack smashing hints
     │
     ├── 4 · Technique selection ── LLM picks the right primitive based on mitigations
     │                               (NX/PIE/RELRO/canary) and gadget availability
     │
     ├── 5 · Dynamic (optional) ── strace / ltrace / gdb automation, crash triage
     │
     └── 6 · Exploit generation ── pwntools script, gadget chains, shellcode (bad-char filtered)
                                    + self-contained HTML report</pre>

    <h3 id="re-analysis">Analysis types</h3>
    <table>
      <thead><tr><th>Type</th><th>Command</th><th>What it produces</th></tr></thead>
      <tbody>
        <tr><td><strong>Static triage</strong></td><td><code>binoracle triage</code></td><td>NX, PIE, RELRO, canary, Fortify, CFI status; symbol table; imported functions; section layout; entropy scan for packed/encrypted regions</td></tr>
        <tr><td><strong>Decompilation</strong></td><td><code>binoracle decompile</code></td><td>Pseudo-C output from Ghidra, radare2, angr and/or pwndbg; LLM-annotated to highlight dangerous patterns (gets, strcpy, printf, malloc/free, memcpy with attacker-controlled size)</td></tr>
        <tr><td><strong>Vuln hunt</strong></td><td><code>binoracle vuln-hunt</code></td><td>Source-to-sink taint analysis across the decompiled output; flags reachable sinks, controlled buffer sizes, and format-string arguments</td></tr>
        <tr><td><strong>Dynamic trace</strong></td><td><code>binoracle dynamic</code></td><td>strace (syscall trace), ltrace (library call trace), gdb crash triage with register dump and backtrace; crash offset computation</td></tr>
        <tr><td><strong>Fuzzing</strong></td><td><code>binoracle fuzz</code></td><td>Dumb fuzzing with mutation engine; AFL integration for coverage-guided fuzzing; crash deduplication</td></tr>
        <tr><td><strong>Hardening audit</strong></td><td><code>binoracle hardening</code></td><td>Full mitigation inventory with per-mitigation bypass notes (e.g. partial overwrite for PIE, fork brute-force for canary)</td></tr>
        <tr><td><strong>Patch diff / N-day</strong></td><td><code>binoracle diff</code></td><td>Binary diff between two versions; highlights new/removed functions and changed basic blocks; isolates the patched vulnerability for N-day analysis</td></tr>
        <tr><td><strong>IOC scan</strong></td><td><code>binoracle ioc-scan</code></td><td>YARA rules, embedded IPs/domains, hardcoded credentials, suspicious API call patterns</td></tr>
        <tr><td><strong>Full audit</strong></td><td><code>binoracle audit</code></td><td>Runs all static oracles in one pass + LLM synthesis report</td></tr>
      </tbody>
    </table>

    <h3 id="re-exploitation">Exploit chain generation</h3>
    <p>The engine selects an exploit primitive based on detected mitigations and available gadgets, then generates a complete pwntools script.</p>
    <table>
      <thead><tr><th>Family</th><th>Techniques</th></tr></thead>
      <tbody>{exploit_trs}</tbody>
    </table>

    <div class="doc-callout tip">
      <strong>Technique selection logic.</strong> The LLM reads the mitigation report and the decompiled output together. If NX is on it uses ROP; if PIE is on it adds a leak gadget first; if a canary is present it looks for a format-string leak or fork brute-force; if the heap allocator is ptmalloc it selects the right House-of-X variant based on libc version. The pwntools script is emitted with inline comments explaining every step.
    </div>

    <h3 id="re-formats">Supported formats</h3>
    <table>
      <thead><tr><th>Format</th><th>Analysis backends</th></tr></thead>
      <tbody>{format_trs}</tbody>
    </table>

    <h3 id="re-commands">Commands</h3>
    <pre><code>binoracle triage ./binary        # static triage: mitigations, symbols, imports, sections
binoracle decompile ./binary     # multi-backend decompile + LLM annotation
binoracle vuln-hunt ./binary     # taint analysis: sources, sinks, dangerous patterns
binoracle pwn ./binary           # full exploit chain, technique auto-selected
binoracle rop ./binary           # ROP gadget search + chain synthesis
binoracle chain ./binary         # gadget enumeration + pwntools script output
binoracle heap ./binary          # heap exploit: tcache/fastbin/UAF/House-of-X auto-selected
binoracle fmt ./binary           # format string: %n write, GOT overwrite, canary/PIE leak
binoracle srop ./binary          # SROP chain generator (sigreturn-oriented programming)
binoracle shellcode ./binary     # shellcode gen with bad-char filtering
binoracle fuzz ./binary          # dumb + AFL coverage-guided fuzzer
binoracle dynamic ./binary       # strace / ltrace / gdb automation + crash triage
binoracle hardening ./binary     # NX, PIE, RELRO, canary, Fortify, CFI audit
binoracle diff ./v1_binary ./v2_binary  # patch diff + N-day analysis
binoracle ioc-scan ./binary      # IOC scan: YARA, IPs, credentials, API patterns
binoracle audit ./binary         # all static oracles + LLM synthesis</code></pre>

    <h2 id="reports">Reports</h2>
    <p>Every CVE investigation and binary analysis writes a self-contained HTML report to disk. Reports are single-file HTML with embedded CSS — no external dependencies required to view them.</p>
    <table>
      <thead><tr><th>Section</th><th>Contents</th></tr></thead>
      <tbody>
        <tr><td>Executive summary</td><td>CVSS score, severity rating, affected component and version</td></tr>
        <tr><td>Hypothesis</td><td>Full LLM reasoning chain showing how the exploit was derived</td></tr>
        <tr><td>Lab</td><td>Docker Compose specification, service versions, network configuration</td></tr>
        <tr><td>Evidence</td><td>Playwright screenshots captured at each verification step</td></tr>
        <tr><td>PoC</td><td>Complete, runnable curl / Python / pwntools exploit code</td></tr>
        <tr><td>Remediation</td><td>Specific fix guidance with before/after code examples</td></tr>
      </tbody>
    </table>
    <pre><code># Open report immediately after run
binoracle cve CVE-2025-27516 --open-report

# Write to a specific directory
binoracle cve CVE-2025-27516 --out ./reports/

# Batch with output directory
binoracle cve-batch CVE-2025-27516 CVE-2024-23334 --out ./reports/</code></pre>

    <h2 id="mcp-server">MCP Integration</h2>
    <p>binoracle exposes its full toolkit as an MCP server, making all analysis capabilities available to any MCP-compatible client: Claude Desktop, Cursor, Zed, and others. The server runs locally and does not require network access.</p>
    <pre><code>binoracle mcp-server</code></pre>
    <p>Add to your client configuration:</p>
    <pre><code>{{
  "mcpServers": {{
    "binoracle": {{
      "command": "binoracle",
      "args": ["mcp-server"]
    }}
  }}
}}</code></pre>
    <details>
      <summary>All MCP tools (~100)</summary>
      <p style="margin-top:.75rem;line-height:2">
        <code>triage</code> <code>pwn</code> <code>rop_chain</code> <code>heap_exploit</code> <code>fmt_exploit</code> <code>decompile</code> <code>cve_investigate</code> <code>vuln_hunt</code> <code>iocscan</code> <code>hardening</code> <code>audit</code> <code>reachability</code> <code>diff_patch</code> <code>elf_layout</code> <code>pe_inspect</code> <code>apk_audit</code> <code>dotnet_inspect</code> <code>wasm_inspect</code> <code>sqlite_audit</code> <code>evm_inspect</code> <code>fuzz</code> <code>dynamic_trace</code> <code>coredump</code> <code>shellcode</code> <code>srop_chain</code> <code>got_hijack</code> <code>io_file</code> <code>dlresolve</code> <code>canary_leak</code> <code>pie_leak</code> <code>format_string</code> <code>heap_triage</code> <code>heap_tcache</code> <code>heap_fastbin</code> <code>heap_uaf</code> <code>heap_house</code> <code>stack_pivot</code> <code>ret2csu</code> <code>ret2plt</code> <code>ret2libc</code> <code>ret2win</code> <code>rop_search</code> <code>symbol_recovery</code> <code>import_scan</code> <code>export_scan</code> <code>section_dump</code> <code>string_extract</code> <code>entropy_scan</code> <code>yara_scan</code> <code>cve_batch</code> <code>vuln_classify</code> <code>patch_diff</code> <code>n_day_analysis</code> <code>cwe_map</code> <code>cvss_score</code> <code>exploit_db_search</code> <code>lab_provision</code> <code>lab_teardown</code> <code>lab_exec</code> <code>playwright_capture</code> <code>report_generate</code> <code>report_open</code> <code>web</code>
      </p>
    </details>

    <h2 id="cli-reference">CLI Reference</h2>
    <table>
      <thead><tr><th>Command</th><th>Description</th></tr></thead>
      <tbody>{cmd_trs}</tbody>
    </table>

    <h2 id="installation">Installation</h2>
    <pre><code>pip install binoracle</code></pre>
    <p>Optional dependency sets install additional backends:</p>
    <pre><code>pip install binoracle[elf]         # pyelftools extras
pip install binoracle[pwn]         # pwntools + ROPgadget
pip install binoracle[symbolic]    # angr symbolic execution
pip install binoracle[screenshots] # Playwright for CVE report screenshots
pip install binoracle[all]         # everything above</code></pre>

    <table>
      <thead><tr><th></th><th>Minimum</th><th>Recommended</th></tr></thead>
      <tbody>
        <tr><td>Python</td><td>3.10</td><td>3.12</td></tr>
        <tr><td>RAM</td><td>8 GB</td><td>16 GB</td></tr>
        <tr><td>Docker</td><td>20.x</td><td>25.x</td></tr>
        <tr><td>Ollama</td><td>0.3</td><td>latest</td></tr>
        <tr><td>GPU</td><td>&mdash;</td><td>8 GB VRAM (Qwen 7B quantized)</td></tr>
      </tbody>
    </table>

    <h2 id="configuration">Configuration</h2>
    <p>All configuration is via environment variables. No configuration file is required.</p>
    <table>
      <thead><tr><th>Variable</th><th>Default</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td><code>BINORACLE_BACKEND</code></td><td><code>openai</code></td><td>LLM backend protocol (openai-compatible)</td></tr>
        <tr><td><code>BINORACLE_BASE_URL</code></td><td><em>none</em></td><td>LLM API base URL (e.g. http://127.0.0.1:11434/v1)</td></tr>
        <tr><td><code>BINORACLE_MODEL</code></td><td><em>none</em></td><td>Model identifier (e.g. qwen2.5-coder:7b)</td></tr>
        <tr><td><code>BINORACLE_API_KEY</code></td><td><em>none</em></td><td>API key — only needed for cloud backends</td></tr>
        <tr><td><code>BINORACLE_LANG</code></td><td><code>es</code></td><td>Report language: <code>es</code> or <code>en</code></td></tr>
      </tbody>
    </table>
    <pre><code># Local Ollama (recommended — fully offline)
export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=http://127.0.0.1:11434/v1
export BINORACLE_MODEL=qwen2.5-coder:7b

# OpenAI-compatible cloud backend (optional)
export BINORACLE_BASE_URL=https://api.openai.com/v1
export BINORACLE_API_KEY=sk-...
export BINORACLE_MODEL=gpt-4o-mini

# English reports
export BINORACLE_LANG=en</code></pre>

    <h2 id="architecture">Architecture</h2>
    <img src="assets/architecture.svg" alt="binoracle architecture diagram" style="width:100%;border-radius:var(--r);border:1px solid var(--brd);margin:1rem 0;">

    <h2 id="corpus">Practice Corpus</h2>
    <p>The repository includes 40+ intentionally vulnerable binaries for local exploitation practice. Each binary is built with a specific vulnerability and mitigations set to exercise a particular technique.</p>
    <pre><code># Build all samples (requires Docker or gcc)
samples/build.sh

# Run the exploit chain against a sample
binoracle pwn samples/bin/ret2libc
binoracle pwn samples/bin/tcache_dup
binoracle pwn samples/bin/house_of_orange
binoracle pwn samples/bin/format_string
binoracle pwn samples/bin/srop_x64</code></pre>
    <p>Techniques covered: ret2win, ret2libc, SROP, tcache dup, fastbin dup, UAF, format string GOT overwrite, canary leak, PIE leak, CSU chain, DL-resolve, heap botcake, house-of-orange, unsafe-unlink, stack pivot, IO_FILE, callhijack, dlresolve32.</p>

    <h2 id="comparison">Comparison</h2>
    <table>
      <thead><tr><th>Capability</th><th>binoracle</th><th>REA</th></tr></thead>
      <tbody>{cmp_trs}</tbody>
    </table>

    <h2 id="roadmap">Roadmap</h2>
    <ul>
      <li>Kernel exploit chains (ret2usr, UAF in drivers)</li>
      <li>Firmware analysis (UEFI, embedded Linux)</li>
      <li>LibFuzzer corpus seeded from CVE PoCs</li>
      <li>Multi-CVE chains (web RCE &mdash; local privilege escalation)</li>
      <li>CVSS v4 scoring</li>
      <li>Burp Suite MCP bridge</li>
      <li>JEB decompiler (Android native)</li>
      <li>Fine-tuned model for exploit hypothesis generation</li>
    </ul>

  </main>
</div>"""
    return shell("binoracle — autonomous security research tool", "index", body, lang_other=("ES", "index-es.html"))

# ---------------------------------------------------------------------------
# Doc page renderer
# ---------------------------------------------------------------------------
def doc_page(source_path, title, current, lang_other=None):
    with open(source_path, encoding="utf-8") as f:
        raw = f.read()

    # Strip <div align="center"> wrappers — they're GitHub-only presentational
    # markup that prevents the markdown library from processing the content inside.
    raw = re.sub(r'<div[^>]*>\n', '', raw)
    raw = re.sub(r'</div>\n?', '', raw)
    # Remove standalone logo <img> tags at the top (we show it in the nav already)
    raw = re.sub(r'<img[^>]*logo\.svg[^>]*>\n?', '', raw)

    converter = md.Markdown(extensions=["tables", "fenced_code", "toc", "md_in_html"])
    html_body = converter.convert(raw)
    toc = converter.toc  # type: ignore

    sidebar = f"""
<aside class="doc-sidebar">
  <h4>On this page</h4>
  {toc if toc else ""}
  <h4 style="margin-top:1.5rem;">Navigation</h4>
  <a href="index.html">Home</a>
  <a href="index-es.html">Docs (ES)</a>
  <a href="roadmap.html">Roadmap</a>
  <a href="https://github.com/beafn28/binoracle" target="_blank" rel="noopener">GitHub</a>
</aside>"""

    body = f"""
<div class="doc-layout">
  {sidebar}
  <main class="doc-content">
    {html_body}
  </main>
</div>"""
    return shell(title, current, body, lang_other=lang_other)

# ---------------------------------------------------------------------------
# Spanish wiki home (pure HTML — avoids markdown conversion issues)
# ---------------------------------------------------------------------------
def docs_es_page():
    vuln_rows_es = [
        ("SSTI", "Jinja2, Twig, Smarty", "sí"),
        ("SQLi (GET / POST / JSON / cabecera)", "Python, Ruby, PHP, Java", "sí"),
        ("Path traversal / LFI", "Python, Ruby, Node, httpd", "sí"),
        ("RCE / inyección de comandos", "Python, Ruby, Node", "sí"),
        ("XSS (reflejado / almacenado)", "Python, Node", "sí"),
        ("SSRF", "Python, Node", "sí"),
        ("XXE", "Java / Maven", "sí"),
        ("Deserialización", "Java, Ruby (Marshal)", "sí"),
        ("Bypass de autenticación / IDOR", "Python, Ruby, Node", "sí"),
        ("Subida de ficheros / webshell", "Python", "sí"),
        ("Redirección abierta", "Python, Ruby, Node", "sí"),
        ("CSRF", "Python, Ruby", "sí"),
        ("Plugins WordPress (100+)", "WP Docker", "sí"),
        ("Extensiones Joomla", "Joomla Docker", "sí"),
        ("Módulos Drupal", "Drupal Docker", "sí"),
        ("Apache httpd", "httpd Docker", "sí"),
        ("Spring / Struts / Log4j", "Maven", "sí"),
        ("Paquetes PHP Composer", "PHP Docker", "sí"),
        ("npm / Node.js / Next.js", "Node Docker", "sí"),
        ("Gems Ruby (Rails, Rack, Sinatra)", "Ruby Docker", "sí"),
    ]
    vuln_trs = "\n".join(
        f'<tr><td>{cls}</td><td><code>{eco}</code></td><td class="cmp-yes">{poc}</td></tr>'
        for cls, eco, poc in vuln_rows_es
    )

    exploit_rows_es = [
        ("Stack", "ret2win, ret2libc, ret2plt, ret2csu, SROP (x86-64/x86-32/aarch64), stack pivot, cadenas ROP"),
        ("Heap", "tcache dup, fastbin dup, UAF, double-free, House-of-Force/Spirit/Orange/Mind, large-bin attack, Botcake"),
        ("Format string", "escritura arbitraria con %n, sobrescritura GOT, fuga de canary, fuga de PIE"),
        ("Bajo nivel", "shellcode (NX off), limpieza de bad-chars, exploit IO_FILE, DL-resolve, secuestro GOT"),
        ("Bypass de canary", "fuga + reutilización, fuerza bruta en fork"),
        ("Bypass de PIE", "sobrescritura parcial, cadena de fugas"),
    ]
    exploit_trs = "\n".join(
        f"<tr><td><strong>{fam}</strong></td><td>{tech}</td></tr>"
        for fam, tech in exploit_rows_es
    )

    format_rows_es = [
        ("ELF (x86-64 / x86 / ARM / MIPS / RISC-V)", "radare2, pyelftools, pwntools, angr, pwndbg"),
        ("PE / PE+ (Windows)", "pefile, LIEF, radare2"),
        ("Mach-O (macOS / iOS)", "LIEF, radare2"),
        ("APK / DEX (Android)", "apktool, jadx, androguard"),
        ("Ensamblados .NET", "dnlib, ILSpy"),
        ("Binarios Go", "go-dis, recuperación de símbolos"),
        ("Binarios Rust", "LIEF + demangling de símbolos"),
        ("Módulos WASM", "wabt, binaryen"),
        ("Bytecode EVM", "pyevmasm"),
        ("Bases de datos SQLite", "sqlite3 schema + volcado de datos"),
    ]
    format_trs = "\n".join(
        f"<tr><td>{fmt}</td><td>{be}</td></tr>"
        for fmt, be in format_rows_es
    )

    cmd_rows_es = [
        ("triage", "Mitigaciones, símbolos, importaciones, secciones"),
        ("decompile", "Ghidra / radare2 / angr / pwndbg + anotación LLM"),
        ("pwn", "Cadena de exploit completa, técnica seleccionada automáticamente"),
        ("rop", "Búsqueda de gadgets ROP y síntesis de cadenas"),
        ("chain", "Enumeración de gadgets + script pwntools"),
        ("heap", "Primitivas de exploit heap (tcache / fastbin / UAF / House-of-X)"),
        ("fmt", "Explotación de format string"),
        ("srop", "Generador de cadenas SROP"),
        ("shellcode", "Shellcode con filtrado de bad-chars"),
        ("fuzz", "Fuzzer simple e inteligente (integración AFL)"),
        ("dynamic", "strace / ltrace / automatización gdb"),
        ("hardening", "Auditoría de mitigaciones con notas de bypass"),
        ("cve", "Pipeline CVE completo: obtener &rarr; lab &rarr; PoC &rarr; informe"),
        ("cve-batch", "Pipeline CVE por lotes, paralelizado"),
        ("vuln-hunt", "Análisis de taint estático (sinks, sources)"),
        ("ioc-scan", "Escáner de IOC e indicadores de malware"),
        ("audit", "Todos los oráculos + síntesis LLM"),
        ("reachability", "Alcanzabilidad source-to-sink"),
        ("diff", "Diff de parche y análisis N-day"),
        ("apk", "Auditoría completa de APK Android"),
        ("dotnet", "Inspección de ensamblados .NET"),
        ("wasm", "Inspección de módulos WASM"),
        ("sqlite", "Auditoría de esquema y datos SQLite"),
        ("evm", "Inspección de bytecode EVM"),
        ("mcp-server", "Iniciar servidor MCP"),
        ("web", "Iniciar interfaz web local"),
    ]
    cmd_trs = "\n".join(
        f"<tr><td><code>{cmd}</code></td><td>{desc}</td></tr>"
        for cmd, desc in cmd_rows_es
    )

    cmp_rows_es = [
        ("Pipeline autónomo CVE (NVD &rarr; lab &rarr; PoC)", "sí", "no"),
        ("LLM local via Ollama", "sí", "no"),
        ("Laboratorios Docker efímeros por CVE", "sí", "no"),
        ("Evidencia Playwright en informes", "sí", "no"),
        ("Scaffolding WordPress / Joomla / Drupal", "sí", "no"),
        ("Servidor MCP (~100 herramientas)", "sí", "no"),
        ("Análisis APK / .NET / WASM / EVM", "sí", "parcial"),
        ("Operación 100 % offline", "sí", "parcial"),
        ("Cadenas stack / heap / format string / SROP", "sí", "sí"),
        ("Síntesis de cadenas ROP", "sí", "sí"),
        ("Decompilación multi-backend", "sí", "sí"),
        ("Corpus de práctica", "sí", "sí"),
    ]
    cmp_trs = "\n".join(
        f'<tr><td>{cap}</td><td class="cmp-yes">{b}</td>'
        f'<td class="cmp-{"yes" if r == "sí" else ("partial" if r == "parcial" else "no")}">{r}</td></tr>'
        for cap, b, r in cmp_rows_es
    )

    body = f"""
<div class="doc-layout">
  {wiki_sidebar("docs", "es")}
  <main class="doc-content">

    <h1 id="descripcion">binoracle</h1>
    <p class="page-lead">Herramienta de investigación autónoma de exploits CVE y reversing binario. Todo el análisis se ejecuta localmente — ningún dato sale de tu máquina.</p>

    <div class="doc-metrics">
      <div class="doc-metric"><div class="metric-value">20+</div><div class="metric-label">Clases CVE</div></div>
      <div class="doc-metric"><div class="metric-value">50+</div><div class="metric-label">Familias de exploit</div></div>
      <div class="doc-metric"><div class="metric-value">10</div><div class="metric-label">Formatos binarios</div></div>
      <div class="doc-metric"><div class="metric-value">~100</div><div class="metric-label">Herramientas MCP</div></div>
      <div class="doc-metric"><div class="metric-value">40+</div><div class="metric-label">Muestras de práctica</div></div>
    </div>

    <div class="doc-callout danger">
      <strong>Aviso legal.</strong> binoracle es una herramienta de investigación y educación. Todos los laboratorios CVE se ejecutan contra contenedores Docker que tú aprovisionas localmente en tu propia máquina. No la uses contra sistemas que no sean tuyos o para los que no dispongas de autorización escrita explícita.
    </div>

    <h2 id="instalacion">Instalación</h2>
    <p>Requisitos previos: Python 3.10+, Docker 20.x+, Ollama 0.3+.</p>
    <pre><code># 1. Instalar binoracle
pip install binoracle

# 2. Instalar Ollama y descargar el modelo (Linux / macOS)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder:7b

# 3. Configurar el backend LLM
export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=http://127.0.0.1:11434/v1
export BINORACLE_MODEL=qwen2.5-coder:7b

# 4. Investigar un CVE con el motor autónomo
binoracle cve CVE-2025-27516

# 5. Analizar un binario
binoracle triage ./binario_objetivo</code></pre>

    <div class="doc-callout tip">
      <strong>Configuración persistente.</strong> Añade las tres líneas <code>export</code> a <code>~/.bashrc</code> o <code>~/.zshrc</code> para que persistan entre reinicios de sesión.
    </div>

    <h2 id="dos-motores">Dos motores</h2>
    <p>binoracle expone dos pipelines de análisis independientes que pueden usarse por separado o en combinación.</p>
    <div class="doc-two-col">
      <div>
        <h4>Motor CVE</h4>
        <p>Recibe un identificador CVE. Obtiene el descriptor de NVD y se lo pasa a un LLM local que genera hipótesis de exploit de forma autónoma. Levanta un laboratorio Docker Compose efímero, ejecuta el PoC, registra capturas de pantalla Playwright en cada paso de verificación y escribe un informe HTML autocontenido en disco.</p>
        <p>Ningún dato se envía a servicios externos. El LLM se ejecuta íntegramente en tu máquina mediante Ollama.</p>
        <pre><code>binoracle cve CVE-2025-27516
binoracle cve-batch CVE-2025-27516 CVE-2024-23334</code></pre>
      </div>
      <div>
        <h4>Motor RE Binario</h4>
        <p>Recibe un fichero binario. Ejecuta análisis estático (símbolos, importaciones, secciones, mitigaciones), opcionalmente trazado dinámico, alimenta el código decompilado al LLM que selecciona la técnica de exploit y genera un script pwntools funcional. Genera un informe HTML con la cadena de razonamiento completa.</p>
        <p>Compatible con ELF, PE, Mach-O, APK, WASM, Go, Rust, .NET, EVM y SQLite.</p>
        <pre><code>binoracle triage ./binario
binoracle pwn    ./binario</code></pre>
      </div>
    </div>

    <h2 id="motor-cve">Motor CVE</h2>
    <p>El motor CVE es completamente autónomo. El LLM local recibe únicamente la descripción cruda de NVD — sin pistas del analista, sin prompts guiados, sin plantillas precargadas. Las hipótesis se generan exclusivamente a partir de esa descripción.</p>

    <pre class="doc-pipeline"> NVD / NIST          LLM local           Lab Docker         Playwright          Informe HTML
 Descriptor CVE  --&gt;  Qwen 2.5 Coder  --&gt;  entorno efímero  --&gt;  capturas       --&gt;  solo en disco
                      sin pistas           Docker Compose      cada paso           HTML+CSS</pre>

    <p>Cada ejecución CVE levanta un entorno Docker Compose nuevo exclusivo para ese CVE. El entorno se elimina automáticamente al terminar la ejecución. No se conserva estado de laboratorio entre ejecuciones.</p>

    <h3>Clases de vulnerabilidad soportadas</h3>
    <table>
      <thead><tr><th>Clase</th><th>Ecosistemas</th><th>Auto PoC</th></tr></thead>
      <tbody>{vuln_trs}</tbody>
    </table>

    <h3>Comandos</h3>
    <pre><code># CVE individual, idioma por defecto (español)
binoracle cve CVE-2025-27516

# CVE individual, informe en inglés, abrir en navegador
binoracle cve CVE-2025-27516 --lang en --open-report

# CVE individual, directorio de salida personalizado
binoracle cve CVE-2025-27516 --out ./informes/

# Lote paralelizado
binoracle cve-batch CVE-2025-27516 CVE-2024-23334 CVE-2025-59681

# Lote con directorio de salida
binoracle cve-batch CVE-2025-27516 CVE-2024-23334 --out ./informes/</code></pre>

    <h2 id="motor-re-binario">Motor RE Binario</h2>
    <p>Pipeline de análisis estático y dinámico para ficheros binarios. Cubre 50+ familias de exploit en las categorías stack, heap, format string y bajo nivel. Todo el análisis se ejecuta localmente sin subir el binario.</p>

    <pre class="doc-pipeline"> Binario de entrada
     |
     +-- Análisis estático  -- símbolos, importaciones, secciones, mitigaciones (NX/PIE/RELRO/canary)
     |
     +-- Análisis LLM ------  revisión de código decompilado, patrones de vuln, selección de técnica
     |
     +-- Dinámica (opc.) ---  strace / ltrace / automatización gdb
     |
     +-- Generación exploit - script pwntools + informe HTML estructurado</pre>

    <h3>Familias de exploit</h3>
    <table>
      <thead><tr><th>Familia</th><th>Técnicas</th></tr></thead>
      <tbody>{exploit_trs}</tbody>
    </table>

    <h3>Formatos soportados</h3>
    <table>
      <thead><tr><th>Formato</th><th>Backends de análisis</th></tr></thead>
      <tbody>{format_trs}</tbody>
    </table>

    <h3>Comandos</h3>
    <pre><code>binoracle triage ./binario        # mitigaciones, símbolos, importaciones, secciones
binoracle decompile ./binario     # multi-backend: Ghidra, radare2, angr, pwndbg + LLM
binoracle pwn ./binario           # cadena de exploit completa, técnica seleccionada automáticamente
binoracle rop ./binario           # búsqueda de gadgets ROP + síntesis de cadenas
binoracle chain ./binario         # enumeración de gadgets + script pwntools
binoracle heap ./binario          # primitivas de exploit heap
binoracle fmt ./binario           # explotación de format string
binoracle srop ./binario          # generación de cadenas SROP
binoracle shellcode ./binario     # shellcode con filtrado de bad-chars
binoracle hardening ./binario     # auditoría NX, PIE, RELRO, canary, Fortify, CFI</code></pre>

    <h2 id="informes">Informes</h2>
    <p>Cada investigación CVE y cada análisis binario escribe un informe HTML autocontenido en disco. Los informes son ficheros HTML únicos con CSS embebido — no requieren dependencias externas para visualizarlos.</p>
    <table>
      <thead><tr><th>Sección</th><th>Contenido</th></tr></thead>
      <tbody>
        <tr><td>Resumen ejecutivo</td><td>Puntuación CVSS, severidad, componente y versión afectados</td></tr>
        <tr><td>Hipótesis</td><td>Cadena de razonamiento completa del LLM mostrando cómo se derivó el exploit</td></tr>
        <tr><td>Laboratorio</td><td>Especificación Docker Compose, versiones de servicios, configuración de red</td></tr>
        <tr><td>Evidencia</td><td>Capturas de pantalla Playwright tomadas en cada paso de verificación</td></tr>
        <tr><td>PoC</td><td>Código de exploit completo y ejecutable: curl / Python / pwntools</td></tr>
        <tr><td>Remediación</td><td>Guía de corrección específica con ejemplos de código antes/después</td></tr>
      </tbody>
    </table>
    <pre><code># Abrir informe inmediatamente tras la ejecución
binoracle cve CVE-2025-27516 --open-report

# Escribir en un directorio específico
binoracle cve CVE-2025-27516 --out ./informes/

# Lote con directorio de salida
binoracle cve-batch CVE-2025-27516 CVE-2024-23334 --out ./informes/</code></pre>

    <h2 id="integracion-mcp">Integración MCP</h2>
    <p>binoracle expone su conjunto completo de herramientas como servidor MCP, poniendo todas las capacidades de análisis a disposición de cualquier cliente compatible: Claude Desktop, Cursor, Zed y otros. El servidor se ejecuta localmente y no requiere acceso a red.</p>
    <pre><code>binoracle mcp-server</code></pre>
    <p>Añade a la configuración de tu cliente:</p>
    <pre><code>{{
  "mcpServers": {{
    "binoracle": {{
      "command": "binoracle",
      "args": ["mcp-server"]
    }}
  }}
}}</code></pre>
    <details>
      <summary>Todas las herramientas MCP (~100)</summary>
      <p style="margin-top:.75rem;line-height:2">
        <code>triage</code> <code>pwn</code> <code>rop_chain</code> <code>heap_exploit</code> <code>fmt_exploit</code> <code>decompile</code> <code>cve_investigate</code> <code>vuln_hunt</code> <code>iocscan</code> <code>hardening</code> <code>audit</code> <code>reachability</code> <code>diff_patch</code> <code>elf_layout</code> <code>pe_inspect</code> <code>apk_audit</code> <code>dotnet_inspect</code> <code>wasm_inspect</code> <code>sqlite_audit</code> <code>evm_inspect</code> <code>fuzz</code> <code>dynamic_trace</code> <code>coredump</code> <code>shellcode</code> <code>srop_chain</code> <code>got_hijack</code> <code>io_file</code> <code>dlresolve</code> <code>canary_leak</code> <code>pie_leak</code> <code>format_string</code> <code>heap_triage</code> <code>heap_tcache</code> <code>heap_fastbin</code> <code>heap_uaf</code> <code>heap_house</code> <code>stack_pivot</code> <code>ret2csu</code> <code>ret2plt</code> <code>ret2libc</code> <code>ret2win</code> <code>rop_search</code> <code>symbol_recovery</code> <code>import_scan</code> <code>export_scan</code> <code>section_dump</code> <code>string_extract</code> <code>entropy_scan</code> <code>yara_scan</code> <code>cve_batch</code> <code>vuln_classify</code> <code>patch_diff</code> <code>n_day_analysis</code> <code>cwe_map</code> <code>cvss_score</code> <code>exploit_db_search</code> <code>lab_provision</code> <code>lab_teardown</code> <code>lab_exec</code> <code>playwright_capture</code> <code>report_generate</code> <code>report_open</code> <code>web</code>
      </p>
    </details>

    <h2 id="referencia-comandos">Referencia CLI</h2>
    <table>
      <thead><tr><th>Comando</th><th>Descripción</th></tr></thead>
      <tbody>{cmd_trs}</tbody>
    </table>

    <h2 id="arquitectura">Arquitectura</h2>
    <img src="assets/architecture.svg" alt="Arquitectura de binoracle" style="width:100%;border-radius:var(--r);border:1px solid var(--brd);margin:1rem 0;">

    <h2 id="corpus">Corpus de práctica</h2>
    <p>El repositorio incluye 40+ binarios vulnerables intencionalmente para practicar explotación local. Cada binario está compilado con una vulnerabilidad específica y un conjunto de mitigaciones para ejercitar una técnica concreta.</p>
    <pre><code># Compilar todas las muestras (requiere Docker o gcc)
samples/build.sh

# Ejecutar la cadena de exploit contra una muestra
binoracle pwn samples/bin/ret2libc
binoracle pwn samples/bin/tcache_dup
binoracle pwn samples/bin/house_of_orange
binoracle pwn samples/bin/format_string
binoracle pwn samples/bin/srop_x64</code></pre>
    <p>Técnicas cubiertas: ret2win, ret2libc, SROP, tcache dup, fastbin dup, UAF, sobrescritura GOT por format string, fuga de canary, fuga de PIE, cadena CSU, DL-resolve, heap botcake, house-of-orange, unsafe-unlink, stack pivot, IO_FILE, callhijack, dlresolve32.</p>

    <h2 id="configuracion">Configuración</h2>
    <p>Toda la configuración se realiza mediante variables de entorno. No se requiere fichero de configuración.</p>
    <table>
      <thead><tr><th>Variable</th><th>Por defecto</th><th>Descripción</th></tr></thead>
      <tbody>
        <tr><td><code>BINORACLE_BACKEND</code></td><td><code>openai</code></td><td>Protocolo del backend LLM (compatible con openai)</td></tr>
        <tr><td><code>BINORACLE_BASE_URL</code></td><td><em>ninguno</em></td><td>URL base de la API LLM (p.ej. http://127.0.0.1:11434/v1)</td></tr>
        <tr><td><code>BINORACLE_MODEL</code></td><td><em>ninguno</em></td><td>Identificador del modelo (p.ej. qwen2.5-coder:7b)</td></tr>
        <tr><td><code>BINORACLE_API_KEY</code></td><td><em>ninguno</em></td><td>Clave API — solo necesaria para backends en la nube</td></tr>
        <tr><td><code>BINORACLE_LANG</code></td><td><code>es</code></td><td>Idioma del informe: <code>es</code> o <code>en</code></td></tr>
      </tbody>
    </table>
    <pre><code># LLM local via Ollama (recomendado — completamente offline)
export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=http://127.0.0.1:11434/v1
export BINORACLE_MODEL=qwen2.5-coder:7b

# Backend en la nube compatible con OpenAI (opcional)
export BINORACLE_BASE_URL=https://api.openai.com/v1
export BINORACLE_API_KEY=sk-...
export BINORACLE_MODEL=gpt-4o-mini

# Informes en inglés
export BINORACLE_LANG=en</code></pre>

    <h2 id="comparacion">Comparación</h2>
    <table>
      <thead><tr><th>Capacidad</th><th>binoracle</th><th>REA</th></tr></thead>
      <tbody>{cmp_trs}</tbody>
    </table>

    <h2 id="hoja-ruta">Hoja de ruta</h2>
    <ul>
      <li>Cadenas de exploit de kernel (ret2usr, UAF en drivers)</li>
      <li>Análisis de firmware (UEFI, Linux embebido)</li>
      <li>Corpus LibFuzzer sembrado desde PoC de CVE</li>
      <li>Cadenas multi-CVE (RCE web &mdash; escalada de privilegios local)</li>
      <li>Puntuación CVSS v4</li>
      <li>Puente Burp Suite MCP</li>
      <li>Decompilador JEB (Android nativo)</li>
      <li>Modelo ajustado para generación de hipótesis de exploit</li>
    </ul>

  </main>
</div>"""
    return shell("binoracle — documentación en español", "docs", body, lang_other=("EN", "index.html"))

# ---------------------------------------------------------------------------
# Roadmap page
# ---------------------------------------------------------------------------
def roadmap_page():
    with open(os.path.join(ROOT, "ROADMAP.md"), encoding="utf-8") as f:
        raw = f.read()

    # Split by level-2 headings: ['intro', '## Head1', 'body1', '## Head2', 'body2', ...]
    chunks = re.split(r'^(## .+)$', raw, flags=re.MULTILINE)
    intro_raw = chunks[0]

    # Extract the two guiding principles from intro
    rules = re.findall(
        r'\d+\.\s+\*\*(.+?)\.\*\*\s+(.+?)(?=\n\d+\.|\n---|\Z)',
        intro_raw, re.DOTALL
    )
    principles_html = ''
    for rule_title, rule_body in rules[:2]:
        body_text = rule_body.strip().split('\n')[0].strip()
        if len(body_text) > 150:
            body_text = body_text[:150].rsplit(' ', 1)[0] + '…'
        principles_html += (
            f'<div class="rm-principle"><strong>{rule_title}.</strong> {body_text}</div>\n'
        )

    def eff_class(eff):
        e = eff.upper()
        if 'L' in e and 'M' not in e:
            return 'rm-eff-l'
        if 'M' in e:
            return 'rm-eff-m'
        return 'rm-eff-s'

    def render_section(heading_raw, content):
        heading = heading_raw[3:].strip()
        ver, title = (heading.split(' - ', 1) if ' - ' in heading else ('', heading))

        # First non-empty, non-bullet, non-heading paragraph
        desc = ''
        for para in re.split(r'\n\n+', content.strip()):
            p = para.strip()
            if p and not p.startswith('-') and not p.startswith('#'):
                desc = p.split('\n')[0].strip()
                break
        if len(desc) > 220:
            desc = desc[:220].rsplit(' ', 1)[0] + '…'

        # Items: "- **[Effort] Name.**"
        items = re.findall(r'^- \*\*\[([^\]]+)\] (.+?)\.\*\*', content, re.MULTILINE)

        h_lower = heading.lower()
        if ver.startswith('v'):
            badge_type = 'version'
            badge_label = ver
        elif 'quality' in h_lower or 'ongoing' in h_lower:
            badge_type = 'ongoing'
            badge_label = 'ongoing'
        else:
            badge_type = 'scope'
            badge_label = 'out of scope'

        items_html = ''
        for effort, name in items:
            name_clean = re.sub(r'~~(.+?)~~', r'\1', name)
            ec = eff_class(effort)
            items_html += (
                f'<div class="rm-item">'
                f'<span class="rm-item-effort {ec}">{effort}</span>'
                f'<span class="rm-item-name">{name_clean}</span>'
                f'</div>\n'
            )

        desc_html   = f'<p class="rm-desc">{desc}</p>' if desc else ''
        items_grid  = f'<div class="rm-items">{items_html}</div>' if items_html else ''

        # Derive a stable anchor ID from the version/heading
        if ver.startswith('v'):
            card_id = ver.replace('.', '')
        elif 'quality' in h_lower or 'ongoing' in h_lower:
            card_id = 'cross-cutting'
        else:
            card_id = 'out-of-scope'

        return f"""<div class="rm-card" id="{card_id}">
  <div class="rm-card-header">
    <span class="rm-badge {badge_type}">{badge_label}</span>
    <span class="rm-card-title">{title}</span>
  </div>
  <div class="rm-card-body">
    {desc_html}
    {items_grid}
  </div>
</div>
"""

    cards_html = ''
    for i in range(1, len(chunks), 2):
        if i + 1 < len(chunks):
            cards_html += render_section(chunks[i], chunks[i + 1])

    effort_legend = """
<div class="rm-effort-legend">
  <span><span class="rm-item-effort rm-eff-s">S</span> days</span>
  <span><span class="rm-item-effort rm-eff-m">M</span> week or two</span>
  <span><span class="rm-item-effort rm-eff-l">L</span> multi-week / research</span>
</div>"""

    body = f"""
<div class="doc-layout">
  {wiki_sidebar("roadmap", "en")}
  <main class="doc-content">
    <h1>Roadmap</h1>
    <p class="page-lead">Direction for versions after 0.1.0. Every item ships as a verified attack path — never a prompt.</p>

    <div class="rm-principles" style="margin:0 0 1.25rem;">
      {principles_html}
    </div>
    {effort_legend}
    <hr style="border:none;border-top:1px solid var(--brd);margin:1.5rem 0;">
    {cards_html}
  </main>
</div>"""
    return shell("Roadmap — binoracle", "roadmap", body)

# ---------------------------------------------------------------------------
# Tutorial page (English)
# ---------------------------------------------------------------------------
def tutorial_page():
    body = f"""
<div class="doc-layout">
  {wiki_sidebar("tutorial", "en")}
  <main class="doc-content">

    <h1 id="overview">binoracle Tutorial</h1>
    <p>This tutorial walks through every capability binoracle provides — from initial setup to running a full CVE investigation and generating an exploit chain against a local binary. All operations run entirely on your machine; no external API keys or cloud services are required.</p>

    <blockquote>
      <strong>Legal notice</strong> — binoracle is a research and educational tool.
      All CVE labs run against Docker containers you provision locally.
      Do not use this tool against systems you do not own or lack explicit written authorization to test.
    </blockquote>

    <h2 id="install">1. Installation</h2>
    <p>binoracle requires Python 3.10 or later and Docker 20+. Install via pip:</p>
    <pre><code>pip install binoracle</code></pre>
    <p>Install optional extras to unlock additional analysis backends:</p>
    <pre><code>pip install binoracle[pwn]        # pwntools + ROPgadget
pip install binoracle[symbolic]   # angr symbolic execution
pip install binoracle[screenshots] # Playwright screenshots in CVE reports
pip install binoracle[all]        # all of the above</code></pre>

    <p>Verify the installation:</p>
    <pre><code>binoracle --version</code></pre>

    <h2 id="configure">2. Configuration</h2>
    <p>binoracle needs a local LLM to generate exploit hypotheses. The recommended setup is <strong>Qwen 2.5 Coder 7B</strong> running via <a href="https://ollama.com" target="_blank" rel="noopener">Ollama</a>.</p>

    <h3>Install Ollama and pull the model</h3>
    <pre><code># Linux / macOS
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder:7b</code></pre>

    <h3>Set environment variables</h3>
    <pre><code>export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=http://127.0.0.1:11434/v1
export BINORACLE_MODEL=qwen2.5-coder:7b
export BINORACLE_LANG=en    # report language: en or es</code></pre>

    <p>Add these to your shell profile (<code>~/.bashrc</code>, <code>~/.zshrc</code>) to persist them across sessions.</p>

    <h3>System requirements</h3>
    <table>
      <thead><tr><th>Dependency</th><th>Minimum</th><th>Recommended</th></tr></thead>
      <tbody>
        <tr><td>Python</td><td>3.10</td><td>3.12</td></tr>
        <tr><td>RAM</td><td>8 GB</td><td>16 GB</td></tr>
        <tr><td>Docker</td><td>20.x</td><td>25.x</td></tr>
        <tr><td>Ollama</td><td>0.3</td><td>latest</td></tr>
        <tr><td>GPU (optional)</td><td>—</td><td>8 GB VRAM (Qwen 7B quantized)</td></tr>
      </tbody>
    </table>

    <h2 id="cve">3. CVE Engine</h2>
    <p>The CVE engine takes a CVE identifier, retrieves the descriptor from NVD, feeds it to the local LLM, and autonomously generates and verifies an exploit proof-of-concept against an ephemeral Docker lab.</p>

    <h3>Basic usage</h3>
    <pre><code># Investigate a single CVE
binoracle cve CVE-2025-27516

# Batch, parallelized
binoracle cve-batch CVE-2025-27516 CVE-2024-23334 CVE-2025-59681

# Force English report
binoracle cve CVE-2025-27516 --lang en

# Save to a specific directory
binoracle cve CVE-2025-27516 --out ./reports/

# Open report automatically when finished
binoracle cve CVE-2025-27516 --open-report</code></pre>

    <h3>What the engine does, step by step</h3>
    <table>
      <thead><tr><th>Step</th><th>What happens</th></tr></thead>
      <tbody>
        <tr><td><strong>1 — NVD fetch</strong></td><td>Retrieves the CVE record: identifier, CVSS score, affected package version, and the plain-language description.</td></tr>
        <tr><td><strong>2 — LLM hypothesis</strong></td><td>Qwen 2.5 Coder reads the description and outputs a structured hypothesis: vulnerability class (SSTI, SQLi, RCE…), affected endpoint, payload strategy, and the technology scaffolder to use.</td></tr>
        <tr><td><strong>3 — Scaffolder selection</strong></td><td>The engine maps the detected ecosystem (Flask, Rails, Spring, WordPress…) to the matching Docker Compose lab template.</td></tr>
        <tr><td><strong>4 — Docker lab</strong></td><td>An ephemeral lab is built and started with the vulnerable package pinned at the affected version. The lab is torn down when the run finishes.</td></tr>
        <tr><td><strong>5 — Playwright verification</strong></td><td>The PoC is executed against the running lab. Playwright captures screenshots at each HTTP step, records request/response pairs, and writes the structured HTML report.</td></tr>
      </tbody>
    </table>

    <h3>Supported vulnerability classes</h3>
    <table>
      <thead><tr><th>Class</th><th>Scaffolders</th></tr></thead>
      <tbody>
        <tr><td>SSTI (Jinja2, Twig, Smarty)</td><td><code>pip</code> / <code>gem</code></td></tr>
        <tr><td>SQLi (GET / POST / JSON / header)</td><td><code>pip</code> / <code>gem</code> / <code>php</code> / <code>maven</code></td></tr>
        <tr><td>Path traversal / LFI</td><td><code>pip</code> / <code>gem</code> / <code>npm</code> / <code>httpd</code></td></tr>
        <tr><td>RCE / command injection</td><td><code>pip</code> / <code>gem</code> / <code>npm</code></td></tr>
        <tr><td>XSS (reflected / stored)</td><td><code>pip</code> / <code>npm</code></td></tr>
        <tr><td>SSRF</td><td><code>pip</code> / <code>npm</code></td></tr>
        <tr><td>XXE</td><td><code>java</code> / <code>maven</code></td></tr>
        <tr><td>Deserialization</td><td><code>java</code> / <code>gem (Marshal)</code></td></tr>
        <tr><td>Auth bypass / IDOR</td><td><code>pip</code> / <code>gem</code> / <code>npm</code></td></tr>
        <tr><td>File upload / webshell</td><td><code>pip</code></td></tr>
        <tr><td>CSRF</td><td><code>pip</code> / <code>gem</code></td></tr>
        <tr><td>WordPress plugins (100+)</td><td>WP Docker</td></tr>
        <tr><td>Joomla / Drupal extensions</td><td>CMS Docker</td></tr>
        <tr><td>Java / Maven (Spring, Struts, Log4j)</td><td><code>maven</code></td></tr>
        <tr><td>PHP Composer packages</td><td><code>php</code></td></tr>
        <tr><td>npm / Node.js / Next.js</td><td><code>npm</code></td></tr>
        <tr><td>Ruby gems (Rails, Rack, Sinatra)</td><td><code>gem</code></td></tr>
      </tbody>
    </table>

    <h2 id="binary">4. Binary RE Engine</h2>
    <p>The binary engine provides automated exploit generation, static analysis, decompilation, and ROP chain synthesis across a wide range of binary formats.</p>

    <h3>Automated exploit chain</h3>
    <pre><code># Full exploit chain — technique is auto-selected
binoracle pwn ./binary

# Static analysis: mitigations, symbols, imports, sections
binoracle triage ./binary

# Multi-backend decompilation
binoracle decompile ./binary

# ROP gadget search and chain synthesis
binoracle rop ./binary

# Hardening assessment with bypass notes
binoracle hardening ./binary</code></pre>

    <h3>Exploit families</h3>
    <table>
      <thead><tr><th>Family</th><th>Techniques</th></tr></thead>
      <tbody>
        <tr><td><strong>Stack</strong></td><td>ret2win, ret2libc, ret2plt, ret2csu, SROP (x86-64/x86-32/aarch64), stack pivot, ROP chains</td></tr>
        <tr><td><strong>Heap</strong></td><td>tcache dup, fastbin dup, UAF, double-free, House-of-Force, House-of-Spirit, House-of-Orange, House-of-Mind, large-bin attack, unsafe-unlink, Botcake</td></tr>
        <tr><td><strong>Format string</strong></td><td>%n arbitrary write, GOT overwrite, canary leak, PIE leak</td></tr>
        <tr><td><strong>Low-level</strong></td><td>shellcode (NX off), bad-char scrubbing, IO_FILE exploit, DL-resolve, GOT hijack</td></tr>
        <tr><td><strong>Canary</strong></td><td>leak + reuse, fork brute-force</td></tr>
        <tr><td><strong>PIE</strong></td><td>partial overwrite, leak chain</td></tr>
      </tbody>
    </table>

    <h3>Working with the practice corpus</h3>
    <p>binoracle ships 40+ intentionally vulnerable binaries for local practice.</p>
    <pre><code># Compile the corpus (requires Docker or gcc)
samples/build.sh

# Run triage on a classic ret2win binary
binoracle triage samples/bin/ret2win

# Generate a full exploit chain
binoracle pwn samples/bin/ret2libc
binoracle pwn samples/bin/format_string
binoracle pwn samples/bin/tcache_dup</code></pre>

    <p>Techniques covered: ret2win, ret2libc, SROP, tcache dup, fastbin dup, UAF, format string GOT overwrite, canary leak, PIE leak, CSU chain, DL-resolve, heap botcake, house-of-orange, unsafe-unlink, stack pivot, IO_FILE, callhijack, dlresolve32.</p>

    <h2 id="mcp">5. MCP Server</h2>
    <p>Start the MCP server to expose all binoracle capabilities as ~100 tools to MCP-compatible clients such as Claude Desktop, Cursor, or Zed.</p>
    <pre><code>binoracle mcp-server</code></pre>

    <p>Add the server to your client configuration:</p>
    <pre><code>// claude_desktop_config.json
{{
  "mcpServers": {{
    "binoracle": {{
      "command": "binoracle",
      "args": ["mcp-server"]
    }}
  }}
}}</code></pre>

    <p>Key MCP tools: <code>triage</code>, <code>pwn</code>, <code>rop_chain</code>, <code>heap_exploit</code>, <code>fmt_exploit</code>, <code>decompile</code>, <code>cve_investigate</code>, <code>vuln_hunt</code>, <code>hardening</code>, <code>audit</code>, <code>reachability</code>, <code>diff_patch</code>, <code>elf_layout</code>, <code>pe_inspect</code>, <code>apk_audit</code>, <code>dotnet_inspect</code>, <code>wasm_inspect</code>, <code>sqlite_audit</code>, <code>evm_inspect</code>, <code>fuzz</code>, <code>dynamic_trace</code>, <code>coredump</code>.</p>

    <h2 id="reports">6. Reports</h2>
    <p>Each CVE investigation produces a structured HTML report containing:</p>
    <ul>
      <li>Executive summary with CVSS score and severity classification</li>
      <li>LLM hypothesis with the full reasoning chain</li>
      <li>Lab scaffold configuration and Docker Compose specification</li>
      <li>Playwright screenshots at each verification step</li>
      <li>Complete PoC code (curl, Python, pwntools)</li>
      <li>Remediation recommendations with specific fix guidance</li>
    </ul>
    <pre><code># Open the report immediately after the run
binoracle cve CVE-2025-27516 --open-report

# Save to a specific output directory
binoracle cve CVE-2025-27516 --out ./reports/my-research/</code></pre>

    <h2 id="corpus">7. Practice Corpus</h2>
    <p>The practice corpus is a set of intentionally vulnerable binaries designed to cover every exploit technique binoracle supports. Compile them with Docker or native gcc:</p>
    <pre><code># Build with Docker (no local toolchain needed)
samples/build.sh --docker

# Build with the system toolchain
samples/build.sh</code></pre>

    <p>After building, the binaries are in <code>samples/bin/</code>. Work through them in order of increasing difficulty:</p>
    <table>
      <thead><tr><th>Binary</th><th>Technique</th><th>Difficulty</th></tr></thead>
      <tbody>
        <tr><td><code>ret2win</code></td><td>Simple return address overwrite</td><td>Beginner</td></tr>
        <tr><td><code>ret2libc</code></td><td>Ret-to-libc with ROP stub</td><td>Beginner</td></tr>
        <tr><td><code>format_string</code></td><td>GOT overwrite via %n</td><td>Intermediate</td></tr>
        <tr><td><code>canary_leak</code></td><td>Stack canary leak + reuse</td><td>Intermediate</td></tr>
        <tr><td><code>tcache_dup</code></td><td>tcache double-free primitive</td><td>Intermediate</td></tr>
        <tr><td><code>house_of_orange</code></td><td>House-of-Orange heap exploitation</td><td>Advanced</td></tr>
        <tr><td><code>srop_chain</code></td><td>Sigreturn-oriented programming</td><td>Advanced</td></tr>
        <tr><td><code>io_file</code></td><td>IO_FILE structure hijack</td><td>Advanced</td></tr>
      </tbody>
    </table>

  </main>
</div>"""
    return shell("Tutorial — binoracle", "tutorial", body)

# ---------------------------------------------------------------------------
# Tutorial page (Spanish)
# ---------------------------------------------------------------------------
def tutorial_es_page():
    body = f"""
<div class="doc-layout">
  {wiki_sidebar("tutorial", "es")}
  <main class="doc-content">

    <h1 id="descripcion">Tutorial de binoracle</h1>
    <p>Este tutorial recorre todas las capacidades de binoracle: desde la instalación inicial hasta ejecutar una investigación CVE completa y generar una cadena de exploit contra un binario local. Todo se ejecuta en tu máquina; no se requieren claves de API externas ni servicios en la nube.</p>

    <blockquote>
      <strong>Aviso legal</strong> — binoracle es una herramienta de investigación y educación.
      Todos los laboratorios CVE se ejecutan contra contenedores Docker que tú creas localmente.
      No la uses contra sistemas que no sean tuyos o para los que no tengas permiso escrito explícito.
    </blockquote>

    <h2 id="instalacion">1. Instalación</h2>
    <p>binoracle requiere Python 3.10 o superior y Docker 20+. Instala con pip:</p>
    <pre><code>pip install binoracle</code></pre>
    <p>Instala extras opcionales para desbloquear backends de análisis adicionales:</p>
    <pre><code>pip install binoracle[pwn]        # pwntools + ROPgadget
pip install binoracle[symbolic]   # ejecución simbólica angr
pip install binoracle[screenshots] # capturas Playwright en informes CVE
pip install binoracle[all]        # todo lo anterior</code></pre>
    <p>Verifica la instalación:</p>
    <pre><code>binoracle --version</code></pre>

    <h2 id="configuracion">2. Configuración</h2>
    <p>binoracle necesita un LLM local para generar hipótesis de exploit. La configuración recomendada es <strong>Qwen 2.5 Coder 7B</strong> ejecutándose mediante <a href="https://ollama.com" target="_blank" rel="noopener">Ollama</a>.</p>

    <h3>Instalar Ollama y descargar el modelo</h3>
    <pre><code># Linux / macOS
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder:7b</code></pre>

    <h3>Variables de entorno</h3>
    <pre><code>export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=http://127.0.0.1:11434/v1
export BINORACLE_MODEL=qwen2.5-coder:7b
export BINORACLE_LANG=es    # idioma del informe: es o en</code></pre>

    <p>Añade estas líneas a tu perfil de shell (<code>~/.bashrc</code>, <code>~/.zshrc</code>) para que persistan entre sesiones.</p>

    <h3>Requisitos del sistema</h3>
    <table>
      <thead><tr><th>Dependencia</th><th>Mínimo</th><th>Recomendado</th></tr></thead>
      <tbody>
        <tr><td>Python</td><td>3.10</td><td>3.12</td></tr>
        <tr><td>RAM</td><td>8 GB</td><td>16 GB</td></tr>
        <tr><td>Docker</td><td>20.x</td><td>25.x</td></tr>
        <tr><td>Ollama</td><td>0.3</td><td>latest</td></tr>
        <tr><td>GPU (opcional)</td><td>—</td><td>8 GB VRAM (Qwen 7B cuantizado)</td></tr>
      </tbody>
    </table>

    <h2 id="motor-cve">3. Motor CVE</h2>
    <p>El motor CVE toma un identificador CVE, recupera el descriptor de NVD, lo envía al LLM local, y genera y verifica de forma autónoma un proof-of-concept de exploit contra un laboratorio Docker efímero.</p>

    <h3>Uso básico</h3>
    <pre><code># Investigar un CVE individual
binoracle cve CVE-2025-27516

# Lote, paralelizado
binoracle cve-batch CVE-2025-27516 CVE-2024-23334 CVE-2025-59681

# Informe en inglés
binoracle cve CVE-2025-27516 --lang en

# Guardar en directorio específico
binoracle cve CVE-2025-27516 --out ./informes/

# Abrir el informe al terminar
binoracle cve CVE-2025-27516 --open-report</code></pre>

    <h3>Pasos del motor, en detalle</h3>
    <table>
      <thead><tr><th>Paso</th><th>Qué ocurre</th></tr></thead>
      <tbody>
        <tr><td><strong>1 — Obtención NVD</strong></td><td>Recupera el registro CVE: identificador, puntuación CVSS, versión del paquete afectado y la descripción en lenguaje natural.</td></tr>
        <tr><td><strong>2 — Hipótesis LLM</strong></td><td>Qwen 2.5 Coder lee la descripción y genera una hipótesis estructurada: clase de vulnerabilidad (SSTI, SQLi, RCE…), endpoint afectado, estrategia de payload y scaffolder tecnológico.</td></tr>
        <tr><td><strong>3 — Selección del scaffolder</strong></td><td>El motor mapea el ecosistema detectado (Flask, Rails, Spring, WordPress…) a la plantilla Docker Compose correspondiente.</td></tr>
        <tr><td><strong>4 — Laboratorio Docker</strong></td><td>Se construye y arranca un lab efímero con el paquete vulnerable fijado en la versión afectada. El lab se destruye al finalizar la ejecución.</td></tr>
        <tr><td><strong>5 — Verificación Playwright</strong></td><td>El PoC se ejecuta contra el lab. Playwright captura pantallas en cada paso HTTP, registra los pares solicitud/respuesta y escribe el informe HTML estructurado.</td></tr>
      </tbody>
    </table>

    <h3>Clases de vulnerabilidad soportadas</h3>
    <table>
      <thead><tr><th>Clase</th><th>Scaffolders</th></tr></thead>
      <tbody>
        <tr><td>SSTI (Jinja2, Twig, Smarty)</td><td><code>pip</code> / <code>gem</code></td></tr>
        <tr><td>SQLi (GET / POST / JSON / header)</td><td><code>pip</code> / <code>gem</code> / <code>php</code> / <code>maven</code></td></tr>
        <tr><td>Path traversal / LFI</td><td><code>pip</code> / <code>gem</code> / <code>npm</code> / <code>httpd</code></td></tr>
        <tr><td>RCE / inyección de comandos</td><td><code>pip</code> / <code>gem</code> / <code>npm</code></td></tr>
        <tr><td>XSS (reflected / stored)</td><td><code>pip</code> / <code>npm</code></td></tr>
        <tr><td>SSRF</td><td><code>pip</code> / <code>npm</code></td></tr>
        <tr><td>XXE</td><td><code>java</code> / <code>maven</code></td></tr>
        <tr><td>Deserialización</td><td><code>java</code> / <code>gem (Marshal)</code></td></tr>
        <tr><td>Auth Bypass / IDOR</td><td><code>pip</code> / <code>gem</code> / <code>npm</code></td></tr>
        <tr><td>Subida de ficheros / Webshell</td><td><code>pip</code></td></tr>
        <tr><td>CSRF</td><td><code>pip</code> / <code>gem</code></td></tr>
        <tr><td>Plugins WordPress (100+)</td><td>WP Docker</td></tr>
        <tr><td>Extensiones Joomla / Drupal</td><td>CMS Docker</td></tr>
        <tr><td>Java / Maven (Spring, Struts, Log4j)</td><td><code>maven</code></td></tr>
        <tr><td>Paquetes PHP Composer</td><td><code>php</code></td></tr>
        <tr><td>npm / Node.js / Next.js</td><td><code>npm</code></td></tr>
        <tr><td>Gems Ruby (Rails, Rack, Sinatra)</td><td><code>gem</code></td></tr>
      </tbody>
    </table>

    <h2 id="binario">4. Motor de Reversing Binario</h2>
    <p>El motor binario proporciona generación de exploits automatizada, análisis estático, decompilación y síntesis de cadenas ROP para una amplia variedad de formatos binarios.</p>

    <h3>Uso básico</h3>
    <pre><code># Cadena de exploit completa — técnica seleccionada automáticamente
binoracle pwn ./binario

# Análisis estático: mitigaciones, símbolos, importaciones, secciones
binoracle triage ./binario

# Decompilación multi-motor
binoracle decompile ./binario

# Búsqueda de gadgets ROP y síntesis de cadena
binoracle rop ./binario

# Evaluación de hardening con notas de bypass
binoracle hardening ./binario</code></pre>

    <h3>Familias de exploit</h3>
    <table>
      <thead><tr><th>Familia</th><th>Técnicas</th></tr></thead>
      <tbody>
        <tr><td><strong>Stack</strong></td><td>ret2win, ret2libc, ret2plt, ret2csu, SROP (x86-64/x86-32/aarch64), stack pivot, cadenas ROP</td></tr>
        <tr><td><strong>Heap</strong></td><td>tcache dup, fastbin dup, UAF, double-free, House-of-Force/Spirit/Orange/Mind, large-bin attack, Botcake</td></tr>
        <tr><td><strong>Format String</strong></td><td>escritura arbitraria con %n, sobrescritura GOT, fuga de canary, fuga de PIE</td></tr>
        <tr><td><strong>Bajo nivel</strong></td><td>shellcode (NX off), limpieza de bad-chars, exploit IO_FILE, DL-resolve, secuestro GOT</td></tr>
        <tr><td><strong>Canary</strong></td><td>fuga + reutilización, fuerza bruta en fork</td></tr>
        <tr><td><strong>PIE</strong></td><td>sobrescritura parcial, cadena de fugas</td></tr>
      </tbody>
    </table>

    <h3>Corpus de práctica</h3>
    <pre><code># Compilar el corpus (requiere Docker o gcc)
samples/build.sh --docker

# Análisis del binario más sencillo
binoracle triage samples/bin/ret2win

# Generar cadena de exploit
binoracle pwn samples/bin/ret2libc
binoracle pwn samples/bin/format_string
binoracle pwn samples/bin/tcache_dup</code></pre>

    <table>
      <thead><tr><th>Binario</th><th>Técnica</th><th>Dificultad</th></tr></thead>
      <tbody>
        <tr><td><code>ret2win</code></td><td>Sobrescritura de dirección de retorno</td><td>Principiante</td></tr>
        <tr><td><code>ret2libc</code></td><td>Ret-to-libc con stub ROP</td><td>Principiante</td></tr>
        <tr><td><code>format_string</code></td><td>Sobrescritura GOT con %n</td><td>Intermedio</td></tr>
        <tr><td><code>canary_leak</code></td><td>Fuga de canary de pila + reutilización</td><td>Intermedio</td></tr>
        <tr><td><code>tcache_dup</code></td><td>Primitiva double-free tcache</td><td>Intermedio</td></tr>
        <tr><td><code>house_of_orange</code></td><td>Explotación heap House-of-Orange</td><td>Avanzado</td></tr>
        <tr><td><code>srop_chain</code></td><td>Programación orientada a Sigreturn</td><td>Avanzado</td></tr>
        <tr><td><code>io_file</code></td><td>Secuestro de estructura IO_FILE</td><td>Avanzado</td></tr>
      </tbody>
    </table>

    <h2 id="mcp">5. Servidor MCP</h2>
    <p>Inicia el servidor MCP para exponer todas las capacidades de binoracle como ~100 herramientas a clientes compatibles con MCP como Claude Desktop, Cursor o Zed.</p>
    <pre><code>binoracle mcp-server</code></pre>
    <pre><code>// claude_desktop_config.json
{{
  "mcpServers": {{
    "binoracle": {{
      "command": "binoracle",
      "args": ["mcp-server"]
    }}
  }}
}}</code></pre>

    <h2 id="informes">6. Informes</h2>
    <p>Cada investigación CVE genera un informe HTML con:</p>
    <ul>
      <li>Resumen ejecutivo con puntuación CVSS y clasificación de severidad</li>
      <li>Hipótesis del LLM con la cadena de razonamiento completa</li>
      <li>Configuración del laboratorio y especificación Docker Compose</li>
      <li>Capturas de pantalla de Playwright en cada paso de verificación</li>
      <li>Código PoC completo (curl, Python, pwntools)</li>
      <li>Recomendaciones de remediación con orientación específica</li>
    </ul>

    <h2 id="corpus">7. Corpus de práctica</h2>
    <p>binoracle incluye más de 40 binarios intencionalmente vulnerables para práctica local. Compílalos con Docker o gcc nativo:</p>
    <pre><code>samples/build.sh</code></pre>
    <p>Técnicas cubiertas: ret2win, ret2libc, SROP, tcache dup, fastbin dup, UAF, format string GOT overwrite, canary leak, PIE leak, CSU chain, DL-resolve, heap botcake, house-of-orange, unsafe-unlink, stack pivot, IO_FILE, callhijack, dlresolve32.</p>

  </main>
</div>"""
    return shell("Tutorial de binoracle", "tutorial", body)

# ---------------------------------------------------------------------------
# Architecture page
# ---------------------------------------------------------------------------
def architecture_page():
    arch_svg = """<svg viewBox="0 0 820 500" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-height:500px;font-family:system-ui,sans-serif">
  <defs>
    <marker id="arr" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="#58a6ff"/>
    </marker>
  </defs>
  <!-- Background boxes -->
  <rect x="10" y="10" width="800" height="480" rx="12" fill="#161b22" stroke="#30363d"/>
  <!-- CLI layer -->
  <rect x="30" y="30" width="140" height="60" rx="8" fill="#1f6feb" stroke="#58a6ff"/>
  <text x="100" y="55" text-anchor="middle" fill="#fff" font-size="13" font-weight="700">CLI</text>
  <text x="100" y="73" text-anchor="middle" fill="#b3d4ff" font-size="10">binoracle/cli.py</text>
  <!-- CVE Agent -->
  <rect x="220" y="30" width="150" height="60" rx="8" fill="#0d2847" stroke="#58a6ff"/>
  <text x="295" y="55" text-anchor="middle" fill="#58a6ff" font-size="13" font-weight="700">CVE Agent</text>
  <text x="295" y="73" text-anchor="middle" fill="#8b949e" font-size="10">workflows/cve_agent.py</text>
  <!-- Workflows -->
  <rect x="420" y="30" width="150" height="60" rx="8" fill="#0d2847" stroke="#bc8cff"/>
  <text x="495" y="55" text-anchor="middle" fill="#bc8cff" font-size="13" font-weight="700">Workflows</text>
  <text x="495" y="73" text-anchor="middle" fill="#8b949e" font-size="10">workflows/*.py</text>
  <!-- MCP Server -->
  <rect x="620" y="30" width="150" height="60" rx="8" fill="#0d2847" stroke="#3fb950"/>
  <text x="695" y="55" text-anchor="middle" fill="#3fb950" font-size="13" font-weight="700">MCP Server</text>
  <text x="695" y="73" text-anchor="middle" fill="#8b949e" font-size="10">mcp_server.py</text>
  <!-- Oracles -->
  <rect x="30" y="160" width="140" height="60" rx="8" fill="#0d2847" stroke="#d29922"/>
  <text x="100" y="185" text-anchor="middle" fill="#d29922" font-size="13" font-weight="700">Oracles</text>
  <text x="100" y="203" text-anchor="middle" fill="#8b949e" font-size="10">oracles/*.py</text>
  <!-- Report -->
  <rect x="220" y="160" width="150" height="60" rx="8" fill="#0d2847" stroke="#f85149"/>
  <text x="295" y="185" text-anchor="middle" fill="#f85149" font-size="13" font-weight="700">Report / HTML</text>
  <text x="295" y="203" text-anchor="middle" fill="#8b949e" font-size="10">report/html.py</text>
  <!-- Store -->
  <rect x="420" y="160" width="150" height="60" rx="8" fill="#0d2847" stroke="#58a6ff"/>
  <text x="495" y="185" text-anchor="middle" fill="#58a6ff" font-size="13" font-weight="700">Session Store</text>
  <text x="495" y="203" text-anchor="middle" fill="#8b949e" font-size="10">store/session.py</text>
  <!-- RAG / KB -->
  <rect x="620" y="160" width="150" height="60" rx="8" fill="#0d2847" stroke="#bc8cff"/>
  <text x="695" y="185" text-anchor="middle" fill="#bc8cff" font-size="13" font-weight="700">RAG / KB</text>
  <text x="695" y="203" text-anchor="middle" fill="#8b949e" font-size="10">rag.py + kb/*.md</text>
  <!-- LLM Backend -->
  <rect x="230" y="310" width="360" height="60" rx="8" fill="#0a1628" stroke="#30363d" stroke-dasharray="5,3"/>
  <text x="410" y="335" text-anchor="middle" fill="#8b949e" font-size="13" font-weight="700">LLM Backend</text>
  <text x="410" y="353" text-anchor="middle" fill="#8b949e" font-size="10">local (Ollama/llama.cpp) · remote (Anthropic API)</text>
  <!-- Docker / Sandbox -->
  <rect x="230" y="400" width="360" height="60" rx="8" fill="#0a1628" stroke="#30363d" stroke-dasharray="5,3"/>
  <text x="410" y="425" text-anchor="middle" fill="#8b949e" font-size="13" font-weight="700">Docker Sandbox</text>
  <text x="410" y="443" text-anchor="middle" fill="#8b949e" font-size="10">wpverify · drupalverify · genericverify · autopoc</text>
  <!-- Arrows: CLI -> CVE Agent -->
  <line x1="170" y1="60" x2="218" y2="60" stroke="#58a6ff" stroke-width="1.5" marker-end="url(#arr)"/>
  <!-- CLI -> Workflows -->
  <line x1="170" y1="65" x2="418" y2="65" stroke="#bc8cff" stroke-width="1" stroke-dasharray="4,2" marker-end="url(#arr)"/>
  <!-- CVE Agent -> Workflows -->
  <line x1="370" y1="60" x2="418" y2="60" stroke="#58a6ff" stroke-width="1.5" marker-end="url(#arr)"/>
  <!-- Workflows -> MCP -->
  <line x1="570" y1="60" x2="618" y2="60" stroke="#3fb950" stroke-width="1.5" marker-end="url(#arr)"/>
  <!-- CVE Agent -> Oracles -->
  <line x1="295" y1="90" x2="130" y2="158" stroke="#d29922" stroke-width="1.5" marker-end="url(#arr)"/>
  <!-- CVE Agent -> Report -->
  <line x1="295" y1="90" x2="295" y2="158" stroke="#f85149" stroke-width="1.5" marker-end="url(#arr)"/>
  <!-- CVE Agent -> Store -->
  <line x1="320" y1="90" x2="460" y2="158" stroke="#58a6ff" stroke-width="1" stroke-dasharray="4,2" marker-end="url(#arr)"/>
  <!-- Workflows -> RAG -->
  <line x1="495" y1="90" x2="695" y2="158" stroke="#bc8cff" stroke-width="1" stroke-dasharray="4,2" marker-end="url(#arr)"/>
  <!-- CVE Agent -> LLM -->
  <line x1="295" y1="220" x2="350" y2="308" stroke="#30363d" stroke-width="1.5" marker-end="url(#arr)"/>
  <!-- Workflows -> LLM -->
  <line x1="495" y1="220" x2="460" y2="308" stroke="#30363d" stroke-width="1.5" marker-end="url(#arr)"/>
  <!-- Workflows -> Docker -->
  <line x1="495" y1="220" x2="460" y2="398" stroke="#30363d" stroke-width="1.5" stroke-dasharray="5,2" marker-end="url(#arr)"/>
</svg>"""

    body = f"""
<div class="doc-layout">
{wiki_sidebar("architecture", "en")}
<main class="doc-content" style="max-width:860px">
  <h1 id="overview">Architecture</h1>
  <p class="page-lead">binoracle is built as a layered, modular Python package. Each layer has a single responsibility — the CLI wires them together, but every component can be imported and used independently.</p>

  <div style="margin:1.5rem 0;border:1px solid var(--brd);border-radius:var(--r);overflow:hidden;padding:1.5rem;background:var(--surf)">
    {arch_svg}
  </div>
  <p style="font-size:.82rem;color:var(--muted);text-align:center;margin-top:.25rem">Figure 1 — Component map. Solid arrows = primary data paths. Dashed arrows = optional/lazy paths.</p>

  <h2 id="components">Components at a glance</h2>
  <div class="table-wrap"><table>
    <thead><tr><th>Component</th><th>File / Package</th><th>Responsibility</th></tr></thead>
    <tbody>
      <tr><td><code>cli.py</code></td><td>binoracle/cli.py</td><td>Argument parsing, command dispatch, terminal output formatting</td></tr>
      <tr><td>CVE Agent</td><td>workflows/cve_agent.py</td><td>End-to-end CVE investigation: NVD lookup → LLM hypothesis → Docker lab → verification</td></tr>
      <tr><td>Workflows</td><td>workflows/*.py</td><td>Binary RE workflows: autopwn, cveplan, wpverify, drupalverify, firmware, kernel, finetune…</td></tr>
      <tr><td>Oracles</td><td>oracles/*.py</td><td>Grounded data extraction: radare2, checksec, angr, capstone, pwntools, pefile, pyelftools</td></tr>
      <tr><td>Report</td><td>report/html.py</td><td>Self-contained HTML report generation (CVE, binary, dataset)</td></tr>
      <tr><td>Session Store</td><td>store/session.py</td><td>Persistent JSON store for findings across a session</td></tr>
      <tr><td>RAG / KB</td><td>rag.py + kb/</td><td>Retrieval-augmented generation: searches the markdown knowledge base for technique context</td></tr>
      <tr><td>MCP Server</td><td>mcp_server.py</td><td>Exposes every tool as an MCP endpoint for Claude Desktop / VS Code / Zed</td></tr>
    </tbody>
  </table></div>

  <h2 id="diagram">Architecture Diagram</h2>
  <p>The diagram above shows two main pipelines flowing through the architecture:</p>
  <ol>
    <li><strong>CVE Pipeline</strong> — CLI → CVE Agent → Oracles + LLM + Docker → Report + Store</li>
    <li><strong>Binary RE Pipeline</strong> — CLI → Workflows → Oracles + LLM → Findings → Report</li>
  </ol>
  <p>Both pipelines share the same LLM backend, session store, RAG corpus, and HTML report generator. The MCP server wraps every tool and exposes it to AI assistants like Claude.</p>

  <h2 id="data-flow">Data Flow</h2>
  <p>When you run <code>binoracle cve CVE-2024-1234 -o report.html</code>, the following happens:</p>
  <ol>
    <li><strong>cli.py</strong> parses the command and calls <code>cmd_cve(args, config)</code>.</li>
    <li><code>investigate_cve()</code> in <strong>cve_agent.py</strong> starts. It fetches the CVE from NVD, extracts CVSS score, severity, vector and description.</li>
    <li>The LLM backend is queried for a hypothesis: target binary, trigger input, vulnerability class, affected version, attack plan.</li>
    <li>If a public PoC exists on GitHub, it is fetched and read. The hypothesis is updated with real data.</li>
    <li>The source code of the target is downloaded (PyPI, npm, GitHub) and statically analysed with radare2 / grep / AST analysis to <em>ground</em> the hypothesis in real function names and line numbers.</li>
    <li>A Docker Compose lab is scaffolded and started. The PoC script is executed inside the sandbox. Output, screenshots and HTTP responses are captured.</li>
    <li>The <code>Investigation</code> dataclass is populated with all evidence and serialised to cache (<code>~/.cache/binoracle/investigations/</code>).</li>
    <li><code>render_investigation()</code> generates the markdown report. <code>render_investigation_page()</code> wraps it in the professional HTML template.</li>
    <li>The HTML is written to the path you passed with <code>-o</code>. The terminal shows only the verdict box and the saved-path confirmation.</li>
  </ol>

  <h2 id="cli-layer">CLI Layer</h2>
  <p><code>binoracle/cli.py</code> is the single entry point. It defines subcommands using <code>argparse</code> subparsers:</p>
  <pre><code>binoracle cve &lt;CVE-ID&gt; [-o report.html] [--json evidence.json]
binoracle investigate &lt;CVE-ID&gt; [--binary elf] [-o report.html]
binoracle cve-chain &lt;CVE-ID&gt; [&lt;CVE-ID&gt; ...]
binoracle autopwn &lt;binary&gt; [-o report.html]
binoracle decompile &lt;binary&gt; [-f func] [--engine ghidra|r2]
binoracle triage &lt;binary&gt;
binoracle hunt &lt;binary&gt;
binoracle firmware &lt;image&gt; [--extract-to dir]
binoracle kernel-exploit &lt;module.ko&gt;
binoracle finetune --collect | --train [--adapter lora]
binoracle mcp-server</code></pre>
  <p>Each subcommand handler (<code>cmd_cve</code>, <code>cmd_autopwn</code>, …) is a plain function that takes <code>(args, config)</code> and returns nothing. The exit code is set by <code>sys.exit()</code> only on explicit errors.</p>
  <p>The <code>config</code> object is built from environment variables and <code>~/.config/binoracle/config.toml</code>. No config file is required — sensible defaults apply for everything except the LLM backend URL.</p>

  <h2 id="agent-layer">Agent Layer</h2>
  <p><code>workflows/cve_agent.py</code> is the largest file (~4500 lines). It contains:</p>
  <ul>
    <li>The <code>Investigation</code> dataclass — the central data model for a CVE investigation.</li>
    <li><code>investigate_cve()</code> — the main orchestrator. It is a plain function, not a class. All state lives in the <code>Investigation</code> object passed by reference through helpers.</li>
    <li>All the step functions: <code>fetch_cve()</code>, <code>query_llm_hypothesis()</code>, <code>fetch_public_poc()</code>, <code>ground_in_source()</code>, <code>scaffold_lab()</code>, <code>run_poc()</code>, <code>capture_screenshots()</code>, <code>render_investigation()</code>.</li>
    <li>The investigation cache (read/write JSON to <code>~/.cache/binoracle/investigations/</code>).</li>
  </ul>
  <p>The agent never calls the CLI or the MCP server. It only knows about the <code>Investigation</code> dataclass and the step functions. This keeps it testable in isolation.</p>

  <h2 id="oracle-layer">Oracle Layer</h2>
  <p>Oracles are thin wrappers around external tools that return structured data:</p>
  <ul>
    <li><code>oracles/r2session.py</code> — manages a persistent <code>r2pipe</code> session. Runs radare2 JSON commands and caches results for the binary's lifetime.</li>
    <li><code>oracles/checksec.py</code> — parses <code>r2 iS</code> and <code>r2 i</code> output to extract NX, PIE, Canary, RELRO, ASLR.</li>
    <li><code>oracles/angr_oracle.py</code> — symbolic execution with angr. Used for auto-verification of stack overflows (finds exact overflow offset).</li>
    <li><code>oracles/capstone_fallback.py</code> — disassembly fallback when r2 is not installed.</li>
    <li><code>oracles/pefile_oracle.py</code> — PE header analysis (DllCharacteristics, imports, sections).</li>
    <li><code>oracles/elf_oracle.py</code> — ELF analysis via pyelftools (DWARF, symbol table, section flags).</li>
  </ul>
  <p>All oracles are <em>lazily imported</em> — they only load when the tool they wrap is actually available. Missing an oracle never crashes binoracle; it degrades gracefully to what is installed.</p>

  <h2 id="report-layer">Report Layer</h2>
  <p><code>report/html.py</code> (~2500 lines) generates three kinds of self-contained HTML reports:</p>
  <ul>
    <li><strong>Binary RE report</strong> — <code>render_html()</code>: KPI dashboard, findings table, mitigation panel, decompiled functions, attack surface.</li>
    <li><strong>CVE investigation report</strong> — <code>render_investigation_page()</code>: CVE hero header, CVSS/status badges, metadata grid, full markdown evidence below.</li>
    <li><strong>Dataset SFT report</strong> — <code>render_dataset_page()</code>: summary + JSONL download button.</li>
  </ul>
  <p>All reports are <em>self-contained</em>: fonts are loaded from Google Fonts, everything else is inline or base64-embedded. No internet connection is needed to open a saved report.</p>

  <h2 id="store">Session Store</h2>
  <p><code>store/session.py</code> provides a lightweight append-only JSON store. Each <code>Finding</code> is a dataclass with title, severity, verdict, evidence, and location. Findings are written to <code>~/.local/share/binoracle/sessions/</code> and can be resumed across CLI invocations.</p>

  <h2 id="mcp-layer">MCP Server</h2>
  <p><code>mcp_server.py</code> exposes every binoracle capability as an MCP tool. The server uses the <code>mcp</code> Python package (FastMCP) and communicates over stdio. See the <a href="mcp-tools.html">MCP Tools Reference</a> for the full tool list.</p>
  <p>Start the server with:</p>
  <pre><code>binoracle mcp-server</code></pre>

</main>
</div>"""
    return shell("Architecture — binoracle docs", "architecture", body)


# ---------------------------------------------------------------------------
# CVE Chains page
# ---------------------------------------------------------------------------
def cve_chains_page():
    chain_svg = """<svg viewBox="0 0 760 180" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-height:200px;font-family:system-ui,sans-serif">
  <defs>
    <marker id="arr2" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="#58a6ff"/>
    </marker>
  </defs>
  <rect x="10" y="10" width="740" height="160" rx="10" fill="#161b22" stroke="#30363d"/>
  <rect x="30" y="45" width="130" height="90" rx="8" fill="#0d2847" stroke="#58a6ff"/>
  <text x="95" y="80" text-anchor="middle" fill="#58a6ff" font-size="12" font-weight="700">CVE-A</text>
  <text x="95" y="97" text-anchor="middle" fill="#8b949e" font-size="10">Initial access</text>
  <text x="95" y="113" text-anchor="middle" fill="#8b949e" font-size="9">e.g. auth bypass</text>
  <line x1="162" y1="90" x2="210" y2="90" stroke="#58a6ff" stroke-width="1.5" marker-end="url(#arr2)"/>
  <text x="186" y="82" text-anchor="middle" fill="#8b949e" font-size="9">pivot</text>
  <rect x="212" y="45" width="130" height="90" rx="8" fill="#0d2847" stroke="#bc8cff"/>
  <text x="277" y="80" text-anchor="middle" fill="#bc8cff" font-size="12" font-weight="700">CVE-B</text>
  <text x="277" y="97" text-anchor="middle" fill="#8b949e" font-size="10">Privilege escalation</text>
  <text x="277" y="113" text-anchor="middle" fill="#8b949e" font-size="9">e.g. LPE / SUID</text>
  <line x1="344" y1="90" x2="392" y2="90" stroke="#58a6ff" stroke-width="1.5" marker-end="url(#arr2)"/>
  <text x="368" y="82" text-anchor="middle" fill="#8b949e" font-size="9">chain</text>
  <rect x="394" y="45" width="130" height="90" rx="8" fill="#0d2847" stroke="#d29922"/>
  <text x="459" y="80" text-anchor="middle" fill="#d29922" font-size="12" font-weight="700">CVE-C</text>
  <text x="459" y="97" text-anchor="middle" fill="#8b949e" font-size="10">Lateral movement</text>
  <text x="459" y="113" text-anchor="middle" fill="#8b949e" font-size="9">e.g. RCE / SSRF</text>
  <line x1="526" y1="90" x2="574" y2="90" stroke="#58a6ff" stroke-width="1.5" marker-end="url(#arr2)"/>
  <text x="550" y="82" text-anchor="middle" fill="#8b949e" font-size="9">exploit</text>
  <rect x="576" y="45" width="130" height="90" rx="8" fill="#1a3822" stroke="#3fb950"/>
  <text x="641" y="80" text-anchor="middle" fill="#3fb950" font-size="12" font-weight="700">GOAL</text>
  <text x="641" y="97" text-anchor="middle" fill="#8b949e" font-size="10">Full compromise</text>
  <text x="641" y="113" text-anchor="middle" fill="#8b949e" font-size="9">root / data exfil</text>
</svg>"""

    body = f"""
<div class="doc-layout">
{wiki_sidebar("cve-chains", "en")}
<main class="doc-content" style="max-width:860px">
  <h1 id="overview">CVE Chains</h1>
  <p class="page-lead">A CVE chain is an ordered sequence of two or more vulnerabilities that, when exploited in sequence, achieve an impact impossible with any single CVE alone. binoracle's <code>cve-chain</code> command investigates every CVE in the chain and synthesises an end-to-end attack narrative.</p>

  <h2 id="what-is">What are CVE chains?</h2>
  <p>Many real-world attacks require multiple steps:</p>
  <ol>
    <li>An unauthenticated attacker exploits an <strong>auth bypass</strong> (CVE-A) to gain a low-privilege session.</li>
    <li>From that session they exploit a <strong>local privilege escalation</strong> (CVE-B) to gain root on the host.</li>
    <li>From root they pivot via an <strong>SSRF or RCE</strong> (CVE-C) to reach an internal service.</li>
  </ol>
  <p>Each CVE alone might be rated MEDIUM. The chain is effectively CRITICAL. binoracle tracks the combined impact, pivot conditions and chained CVSS score across the full sequence.</p>

  <div style="margin:1.5rem 0;border:1px solid var(--brd);border-radius:var(--r);overflow:hidden;padding:1.5rem;background:var(--surf)">
    {chain_svg}
  </div>
  <p style="font-size:.82rem;color:var(--muted);text-align:center;margin-top:.25rem">Figure 1 — A three-CVE attack chain: initial access → privilege escalation → lateral movement → full compromise.</p>

  <h2 id="pipeline">Chain Pipeline</h2>
  <p>When you invoke <code>binoracle cve-chain CVE-A CVE-B CVE-C</code>, the engine:</p>
  <ol>
    <li>Investigates each CVE independently — NVD lookup, LLM hypothesis, source grounding, Docker verification. Each produces an <code>Investigation</code> object.</li>
    <li>Analyses <strong>pivot conditions</strong>: does CVE-A's output (e.g. authenticated session, leaked credential, file write) provide the preconditions for CVE-B?</li>
    <li>Computes a <strong>combined CVSS</strong> and <strong>combined impact statement</strong> for the whole chain.</li>
    <li>Generates a unified HTML report with per-CVE sections and a chain summary at the top.</li>
  </ol>

  <h2 id="command">Command Reference</h2>
  <pre><code>binoracle cve-chain &lt;CVE-1&gt; [&lt;CVE-2&gt; ...] [options]

Options:
  -o FILE, --html FILE     Export combined HTML report
  --json FILE              Dump full chain evidence as JSON
  --lang es|en             Report language (default: config)
  --budget N               Max seconds per CVE (default: 300)
  --no-cache               Bypass the investigation cache

Examples:
  # Two-step: auth bypass + privilege escalation
  binoracle cve-chain CVE-2024-1071 CVE-2023-23752 -o chain.html

  # Three-step chain with JSON evidence
  binoracle cve-chain CVE-2023-1 CVE-2023-2 CVE-2023-3 --json chain.json -o chain.html

  # Quick chain, skip Docker verification
  binoracle cve-chain CVE-A CVE-B --budget 60</code></pre>

  <div class="doc-callout tip">
    <strong>Tip:</strong> Pass CVEs in exploit order — first the one that provides initial access, then each subsequent pivot. The engine infers pivot conditions automatically but ordering helps the LLM produce a better narrative.
  </div>

  <h2 id="examples">Example chains</h2>
  <h3>WordPress: subscriber takeover → admin file write</h3>
  <pre><code>binoracle cve-chain CVE-2024-1071 CVE-2024-27956 -o wp-chain.html</code></pre>
  <p><strong>CVE-2024-1071</strong>: SQL injection via Ultimate Member plugin lets an unauthenticated user read the <code>wp_users</code> table and extract hashed passwords or directly set a known password via the injection.<br>
  <strong>CVE-2024-27956</strong>: WP-Automatic plugin RCE via SQLi with authenticated user — using the credentials from CVE-1, an attacker gains admin-level file write, achieving full RCE.</p>

  <h3>Apache + local: information disclosure → RCE</h3>
  <pre><code>binoracle cve-chain CVE-2021-41773 CVE-2021-42013 -o apache-chain.html</code></pre>
  <p><strong>CVE-2021-41773</strong>: Apache 2.4.49 path traversal — read /etc/passwd, discover enabled CGI modules.<br>
  <strong>CVE-2021-42013</strong>: Apache 2.4.49/50 RCE via path traversal in CGI — combine with the traversal to achieve unauthenticated code execution.</p>

  <h3>Container escape chain</h3>
  <pre><code>binoracle cve-chain CVE-2022-0492 CVE-2022-25636 -o escape-chain.html</code></pre>
  <p><strong>CVE-2022-0492</strong>: Linux cgroup v1 container escape — from container to host namespace.<br>
  <strong>CVE-2022-25636</strong>: Netfilter heap out-of-bounds write for LPE — escalate to root on the host after escape.</p>

  <h2 id="output">Output Format</h2>
  <p>The <code>--json</code> flag dumps a JSON object with this structure:</p>
  <pre><code>{{
  "chain": ["CVE-A", "CVE-B", "CVE-C"],
  "combined_impact": "Full RCE with no authentication required",
  "combined_cvss_estimate": 9.8,
  "pivot_conditions": [
    {{"from": "CVE-A", "to": "CVE-B", "condition": "Authenticated session with subscriber role"}},
    {{"from": "CVE-B", "to": "CVE-C", "condition": "Local file write in web root"}}
  ],
  "investigations": [
    {{ /* Investigation object for CVE-A */ }},
    {{ /* Investigation object for CVE-B */ }},
    {{ /* Investigation object for CVE-C */ }}
  ]
}}</code></pre>
  <p>Each <code>Investigation</code> object is the same schema as the single <code>--json</code> output from <code>binoracle cve</code> — the chain output embeds them all with the pivot analysis on top.</p>

</main>
</div>"""
    return shell("CVE Chains — binoracle docs", "cve-chains", body)


# ---------------------------------------------------------------------------
# Firmware Analysis page
# ---------------------------------------------------------------------------
def firmware_page():
    layers_svg = """<svg viewBox="0 0 500 280" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-height:280px;font-family:system-ui,sans-serif">
  <rect x="10" y="10" width="480" height="260" rx="10" fill="#161b22" stroke="#30363d"/>
  <rect x="30" y="30" width="440" height="40" rx="6" fill="#0d2847" stroke="#58a6ff"/>
  <text x="250" y="56" text-anchor="middle" fill="#58a6ff" font-size="13" font-weight="700">Application Layer (busybox, httpd, openvpn, daemons)</text>
  <rect x="30" y="80" width="440" height="40" rx="6" fill="#0d2847" stroke="#bc8cff"/>
  <text x="250" y="106" text-anchor="middle" fill="#bc8cff" font-size="13" font-weight="700">Filesystem (SquashFS / JFFS2 / CRAMFS)</text>
  <rect x="30" y="130" width="440" height="40" rx="6" fill="#0d2847" stroke="#d29922"/>
  <text x="250" y="156" text-anchor="middle" fill="#d29922" font-size="13" font-weight="700">Kernel (Linux uImage / zImage / vmlinuz)</text>
  <rect x="30" y="180" width="440" height="40" rx="6" fill="#0d2847" stroke="#3fb950"/>
  <text x="250" y="206" text-anchor="middle" fill="#3fb950" font-size="13" font-weight="700">Bootloader (U-Boot / RedBoot / CFE)</text>
  <rect x="30" y="230" width="440" height="30" rx="6" fill="#161b22" stroke="#30363d"/>
  <text x="250" y="250" text-anchor="middle" fill="#8b949e" font-size="11">Flash / NAND / NOR — physical storage</text>
</svg>"""

    body = f"""
<div class="doc-layout">
{wiki_sidebar("firmware", "en")}
<main class="doc-content" style="max-width:860px">
  <h1 id="overview">Firmware Analysis</h1>
  <p class="page-lead">binoracle can analyse firmware images from IoT devices, routers, embedded systems and industrial controllers. It extracts the filesystem, identifies binaries with known vulnerability classes, and applies the full radare2 + LLM analysis pipeline to each one.</p>

  <h2 id="layers">Firmware Layers</h2>
  <div style="margin:1.5rem 0;border:1px solid var(--brd);border-radius:var(--r);overflow:hidden;padding:1.5rem;background:var(--surf)">
    {layers_svg}
  </div>
  <p>A typical firmware image packages several layers: a bootloader, a compressed kernel, and a compressed root filesystem. binoracle works at the <strong>filesystem layer</strong> — it extracts the SquashFS/JFFS2/CRAMFS image and analyses the ELF binaries inside it.</p>

  <h2 id="extraction">Extraction</h2>
  <pre><code>binoracle firmware &lt;image.bin&gt; [options]

Options:
  --extract-to DIR         Write extracted files to DIR (default: ./firmware_out/)
  --list                   List all ELF binaries found, don't analyse
  --focus GLOB             Only analyse binaries matching this glob (e.g. '*/httpd')
  --depth N                Max directory depth to recurse (default: unlimited)
  -o FILE                  HTML report output path
  --json FILE              Dump findings as JSON</code></pre>

  <p>Extraction is handled by a chain of format detectors:</p>
  <ol>
    <li><strong>File signature detection</strong> — identifies SquashFS, JFFS2, CRAMFS, gzip, lzma, bzip2, 7z, cpio, tar, zip by magic bytes.</li>
    <li><strong>Binwalk-style carving</strong> (built-in, no binwalk dependency) — scans for embedded archives at any offset within the image.</li>
    <li><strong>Recursive extraction</strong> — decompresses each layer. For SquashFS it calls <code>unsquashfs</code> (must be installed); for other formats it uses Python's stdlib (<code>tarfile</code>, <code>zipfile</code>, <code>gzip</code>, <code>lzma</code>).</li>
    <li><strong>ELF enumeration</strong> — walks the extracted tree and collects every file with ELF magic bytes, regardless of extension.</li>
  </ol>

  <div class="doc-callout warn">
    <strong>Requirement:</strong> <code>unsquashfs</code> must be installed to extract SquashFS images (<code>apt install squashfs-tools</code> / <code>brew install squashfs</code>). For other formats only Python stdlib is needed.
  </div>

  <h2 id="analysis">Binary Analysis</h2>
  <p>Each extracted ELF is run through the full binoracle RE pipeline:</p>
  <ol>
    <li><strong>Triage</strong> — checksec, architecture detection (ARM32, ARM64, MIPS, x86, x64, PowerPC), libc version estimation from embedded strings.</li>
    <li><strong>Hunt</strong> — static vulnerability hunting: format strings, dangerous function calls (<code>strcpy</code>, <code>gets</code>, <code>system</code>, <code>popen</code>), hardcoded credentials in <code>.rodata</code>, world-writable sockets.</li>
    <li><strong>LLM analysis</strong> — context-aware analysis of decompiled output for the highest-risk functions identified in the hunt step.</li>
    <li><strong>Auto-verify</strong> (optional, x86/x64 only) — angr symbolic execution to prove reachability and compute overflow offsets.</li>
  </ol>
  <pre><code># Analyse a TP-Link firmware image, focus on the httpd binary
binoracle firmware tplink_archer_c7.bin --focus '*/httpd' -o firmware-report.html

# List all ELF binaries in a firmware image without analysing
binoracle firmware openwrt-snapshot.bin --list

# Full analysis, all binaries, write JSON
binoracle firmware netgear-r7000.bin --json firmware.json -o firmware.html</code></pre>

  <h2 id="mitigations">Mitigations in Embedded Systems</h2>
  <p>Embedded firmware often lacks modern exploit mitigations. binoracle's triage step reports:</p>
  <div class="table-wrap"><table>
    <thead><tr><th>Mitigation</th><th>What it means</th><th>Typical embedded status</th></tr></thead>
    <tbody>
      <tr><td>NX / DEP</td><td>Non-executable stack/heap</td><td>Often absent on MIPS/ARM32 without hardware support</td></tr>
      <tr><td>Stack canary</td><td>Detects stack overflows before return</td><td>Absent in ~60% of embedded binaries (stripped builds)</td></tr>
      <tr><td>PIE / ASLR</td><td>Randomised base address</td><td>Often absent; fixed addresses make ROP chains reliable</td></tr>
      <tr><td>RELRO</td><td>Read-only GOT after relocation</td><td>Partial RELRO common; Full RELRO rare</td></tr>
      <tr><td>FORTIFY_SOURCE</td><td>Runtime bounds checks on libc calls</td><td>Rarely present in stripped builds</td></tr>
    </tbody>
  </table></div>
  <p>When mitigations are absent, binoracle notes this explicitly in the report and adjusts the exploitability assessment — a stack overflow in a binary with no NX, no canary and no ASLR is rated as <em>trivially exploitable</em>.</p>

  <h2 id="use-cases">Use Cases</h2>
  <h3>Router hardcoded credentials</h3>
  <p>Many routers embed hardcoded SSH/Telnet/web credentials in <code>.rodata</code>. binoracle's hunt step searches for strings matching <code>admin</code>, <code>password</code>, <code>root</code>, <code>1234</code> adjacent to auth-related function calls and flags them as findings.</p>

  <h3>MIPS/ARM buffer overflows in httpd</h3>
  <p>The most common vulnerability class in embedded web servers is an unchecked <code>strcpy</code> from a URL or CGI parameter into a stack buffer. binoracle identifies these statically and, for x86/x64 test builds, can symbolically verify them with angr.</p>

  <h3>Industrial controller (ICS/SCADA) firmware</h3>
  <p>Many ICS controllers run Linux on ARM with stripped binaries and no ASLR. binoracle can analyse their management daemons, Modbus/DNP3 stacks, and OPC-UA servers for memory corruption and injection flaws.</p>

</main>
</div>"""
    return shell("Firmware Analysis — binoracle docs", "firmware", body)


# ---------------------------------------------------------------------------
# Kernel Exploits page
# ---------------------------------------------------------------------------
def kernel_exploits_page():
    body = f"""
<div class="doc-layout">
{wiki_sidebar("kernel-exploits", "en")}
<main class="doc-content" style="max-width:860px">
  <h1 id="overview">Kernel Exploits</h1>
  <p class="page-lead">binoracle's kernel exploit module analyses Linux kernel modules (.ko files) and kernel-space binaries for memory corruption vulnerabilities. It integrates radare2's kernel-aware disassembly with LLM-guided analysis to identify exploitable paths.</p>

  <div class="doc-callout warn">
    <strong>Warning:</strong> Kernel exploitation is inherently dangerous. Always work in an isolated VM or container. Never run kernel exploits on production systems. binoracle scaffolds a QEMU VM for safe kernel exploit testing.
  </div>

  <h2 id="techniques">Supported Techniques</h2>
  <div class="table-wrap"><table>
    <thead><tr><th>Technique</th><th>Target</th><th>binoracle support</th></tr></thead>
    <tbody>
      <tr><td>ret2usr</td><td>x86/x64, no SMEP</td><td>Full — detects missing SMEP, generates ret2usr PoC</td></tr>
      <tr><td>Stack canary bypass</td><td>Kernel modules</td><td>Detects absence of stack protector in .ko</td></tr>
      <tr><td>KASLR bypass</td><td>All architectures</td><td>Identifies info leak primitives that can leak kernel base</td></tr>
      <tr><td>SMEP bypass (ret2kernel)</td><td>x64 with SMEP</td><td>Identifies kernel ROP gadgets for CR4 manipulation</td></tr>
      <tr><td>Heap spray / slab overflow</td><td>kmalloc slab</td><td>Detects kmalloc calls adjacent to unchecked copies</td></tr>
      <tr><td>UAF in kernel objects</td><td>cdev / proc / netlink</td><td>Identifies object lifetime issues in driver code</td></tr>
      <tr><td>Arbitrary read/write via ioctl</td><td>Char device drivers</td><td>Full ioctl handler analysis</td></tr>
      <tr><td>LPE via SUID binary + kernel bug</td><td>Combined</td><td>Chains kernel vulnerability with SUID binary analysis</td></tr>
    </tbody>
  </table></div>

  <h2 id="radare2">Radare2 Workflow</h2>
  <p>binoracle opens the kernel module with <code>r2 -AA</code> in kernel analysis mode. Key commands used:</p>
  <pre><code># Load a kernel module for analysis
binoracle kernel-exploit my_driver.ko -o kernel-report.html

# What radare2 does internally:
# r2 -A -e anal.arch=x86 -e anal.bits=64 my_driver.ko
# afl           - list all functions
# pdf @ sym.ioctl_handler    - disassemble ioctl handler
# pdd @ sym.ioctl_handler    - decompile (requires r2ghidra)
# axt sym.kmalloc            - find all callers of kmalloc
# axt sym.copy_from_user     - find all callers of copy_from_user
# /R pop rdi; ret            - find ROP gadgets</code></pre>

  <p>The analysis pipeline for a kernel module:</p>
  <ol>
    <li><strong>Symbol extraction</strong> — <code>nm -u</code> to find imported kernel symbols (kmalloc, kfree, copy_from_user, copy_to_user, printk).</li>
    <li><strong>Entry point analysis</strong> — <code>init_module</code>, <code>cleanup_module</code>, and all <code>file_operations</code> callbacks (read, write, ioctl, mmap, poll).</li>
    <li><strong>Taint tracking</strong> — data flow from <code>copy_from_user</code> to dangerous sinks (kmalloc size, memcpy length, kfree pointer).</li>
    <li><strong>Mitigation check</strong> — presence of <code>__stack_chk_guard</code>, <code>-fstack-protector-strong</code> artefacts, CFI instrumentation.</li>
    <li><strong>LLM analysis</strong> — decompiled ioctl handler analysed for integer overflow before kmalloc, missing bounds checks in copy_from_user, and type confusion.</li>
  </ol>

  <h2 id="smep-bypass">SMEP Bypass Example</h2>
  <p>When SMEP is enabled (CR4 bit 20 set), user-space shellcode cannot be executed in kernel context. binoracle generates a ROP chain that clears CR4 bit 20 before returning to user-space payload:</p>
  <pre><code># Example generated PoC structure (simplified):
# 1. Trigger the kernel vulnerability to control RIP
# 2. ROP chain to clear SMEP: mov cr4, rax; ret (gadget in kernel .text)
# 3. Return to user-space shellcode (commit_creds(prepare_kernel_cred(0)))
# 4. ret2user: restore registers and iretq to user-space

# binoracle generates this automatically when it detects:
# - A controllable kernel RIP
# - SMEP enabled (detected from /proc/cpuinfo or kernel config)
# - Suitable CR4 manipulation gadget in the target kernel

binoracle kernel-exploit vuln_driver.ko --kernel vmlinuz --config .config -o report.html</code></pre>

  <h2 id="examples">Examples</h2>
  <h3>Simple stack overflow in ioctl handler</h3>
  <pre><code># A driver with a stack buffer overflow in copy_from_user:
# static long dev_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {{
#   char buf[64];
#   copy_from_user(buf, (void*)arg, 512);  // overflow!
# }}

binoracle kernel-exploit overflow_driver.ko -o overflow-report.html</code></pre>
  <p>binoracle will: detect the overflow (copy_from_user with size &gt; buffer), measure the offset to the return address, check for stack canary, and generate a ret2usr PoC if SMEP is absent or a SMEP-bypass ROP chain if SMEP is present.</p>

  <h3>Use-after-free in a cdev</h3>
  <pre><code># A driver that frees an object in .release but uses it in a concurrent .read:
binoracle kernel-exploit uaf_driver.ko -o uaf-report.html</code></pre>
  <p>binoracle analyses the <code>file_operations</code> struct, identifies <code>release</code> and <code>read</code> callbacks sharing a pointer, checks for missing locking (absence of mutex/spinlock calls around the shared pointer), and flags the UAF as a finding.</p>

  <h3>QEMU test environment</h3>
  <pre><code># Scaffold a QEMU VM for safe kernel testing:
binoracle kernel-exploit my_driver.ko --qemu --kernel bzImage --initrd initrd.img

# This starts a QEMU VM with:
# - The vulnerable kernel + driver loaded
# - A minimal BusyBox rootfs
# - The generated PoC pre-loaded as /tmp/exploit
# - A serial console for interaction</code></pre>

</main>
</div>"""
    return shell("Kernel Exploits — binoracle docs", "kernel-exploits", body)


# ---------------------------------------------------------------------------
# Fine-tuning / LoRA page
# ---------------------------------------------------------------------------
def finetune_page():
    body = f"""
<div class="doc-layout">
{wiki_sidebar("finetune", "en")}
<main class="doc-content" style="max-width:860px">
  <h1 id="overview">LoRA Fine-tuning</h1>
  <p class="page-lead">binoracle can generate a supervised fine-tuning (SFT) dataset from your own CVE investigations and binary analysis sessions, then fine-tune a local LLM with LoRA adapters — producing a model that is significantly better at your specific technology stack and vulnerability classes.</p>

  <h2 id="architecture">LoRA Architecture</h2>
  <p>LoRA (Low-Rank Adaptation) adds a small number of trainable parameters to a frozen base model. Instead of updating all weights (which requires 40–80 GB of GPU RAM for a 7B model), LoRA injects trainable rank-decomposition matrices into the attention layers:</p>
  <pre><code>W' = W + BA   where B ∈ R^(d×r), A ∈ R^(r×k), r &lt;&lt; min(d,k)</code></pre>
  <p>At inference time the LoRA weights are merged with the base model — no extra latency. For security-focused fine-tuning, rank <code>r=8</code> or <code>r=16</code> is typically sufficient.</p>
  <div class="table-wrap"><table>
    <thead><tr><th>Parameter</th><th>Typical value</th><th>Effect</th></tr></thead>
    <tbody>
      <tr><td><code>r</code> (rank)</td><td>8–16</td><td>Higher = more capacity, more GPU RAM</td></tr>
      <tr><td><code>alpha</code></td><td>16–32</td><td>Scaling factor (typically 2×rank)</td></tr>
      <tr><td>Target modules</td><td>q_proj, v_proj</td><td>Which attention matrices get LoRA</td></tr>
      <tr><td>Dropout</td><td>0.05</td><td>Regularisation</td></tr>
      <tr><td>Epochs</td><td>3–5</td><td>More = better fit, risk of overfitting on small datasets</td></tr>
      <tr><td>Learning rate</td><td>2e-4</td><td>Cosine schedule with warmup</td></tr>
    </tbody>
  </table></div>

  <h2 id="dataset">Dataset Generation</h2>
  <p>Every CVE investigation and binary analysis session binoracle completes is a potential training example. The <code>finetune --collect</code> command converts completed investigations into SFT examples in ShareGPT format:</p>
  <pre><code>binoracle finetune --collect --output sft_dataset.jsonl

# Options:
#   --min-cvss 5.0     Only include investigations with CVSS >= 5.0
#   --verified-only    Only include verified (confirmed) investigations
#   --include-binary   Include binary RE sessions (default: CVE only)
#   --lang es|en       Dataset language
#   --since 2024-01-01 Only include sessions since this date</code></pre>
  <p>Each collected session becomes one or more training examples. For a CVE investigation, binoracle generates:</p>
  <ul>
    <li>A <strong>hypothesis example</strong>: system prompt + CVE description → target, trigger, attack plan</li>
    <li>A <strong>PoC example</strong>: system prompt + CVE + grounded source analysis → PoC script</li>
    <li>A <strong>verdict example</strong>: system prompt + CVE + lab output → verification verdict</li>
  </ul>
  <p>For a binary RE session it generates examples for triage, vulnerability hypothesis, and exploit strategy.</p>

  <h2 id="command">finetune Command</h2>
  <pre><code>binoracle finetune [--collect | --train | --merge | --push] [options]

Subcommands:
  --collect            Generate SFT JSONL from completed sessions
  --train              Train LoRA adapter on a JSONL dataset
  --merge              Merge LoRA adapter into base model (creates new GGUF)
  --push               Push merged model to Ollama local registry

Options (--collect):
  --output FILE        JSONL output path (default: sft_dataset.jsonl)
  --verified-only      Only include verified investigations
  --min-cvss N         Minimum CVSS score to include
  --since DATE         Only include sessions from this date onward

Options (--train):
  --dataset FILE       JSONL dataset to train on (required)
  --base-model NAME    Base model in Ollama (default: config llm.model)
  --adapter-name NAME  Name for the LoRA adapter (default: binoracle-lora)
  --rank N             LoRA rank (default: 8)
  --epochs N           Training epochs (default: 3)
  --lr FLOAT           Learning rate (default: 2e-4)
  --gpu N              Number of GPUs (default: auto-detect)

Options (--merge):
  --adapter NAME       Adapter to merge (default: binoracle-lora)
  --output NAME        Output model name in Ollama

Options (--push):
  --model NAME         Merged model to push</code></pre>

  <h2 id="jsonl">JSONL Format</h2>
  <p>The dataset uses ShareGPT format — the same format used by most open-source fine-tuning frameworks (LLaMA-Factory, Axolotl, Unsloth):</p>
  <pre><code>// sft_dataset.jsonl — one JSON object per line
{{
  "conversations": [
    {{
      "from": "system",
      "value": "You are binoracle, an autonomous CVE exploit researcher..."
    }},
    {{
      "from": "human",
      "value": "CVE-2024-1071: SQL injection in Ultimate Member WordPress plugin via the 'sorting' parameter. CVSS 9.8 CRITICAL. Affected: Ultimate Member &lt;= 2.8.3."
    }},
    {{
      "from": "gpt",
      "value": "Target: WordPress with Ultimate Member plugin &lt;= 2.8.3\\nTrigger: HTTP GET /wp-json/um/v1/account?sorting=... with SQL injection payload\\nClass: sqli (time-based blind)\\nAffected table: wp_users\\n..."
    }}
  ],
  "source": "binoracle-investigation",
  "cve": "CVE-2024-1071",
  "cvss": 9.8,
  "verified": true
}}</code></pre>

  <h2 id="workflow">Full Workflow</h2>
  <p>A complete fine-tuning workflow from investigation to deployed model:</p>
  <pre><code># Step 1: Run several CVE investigations to build up a dataset
binoracle investigate CVE-2024-1071 --source wordpress
binoracle investigate CVE-2024-27956
binoracle investigate CVE-2023-23752
# ... run 20-50 investigations for a useful dataset

# Step 2: Collect all verified sessions into a JSONL dataset
binoracle finetune --collect --verified-only --output my_dataset.jsonl
# Output: my_dataset.jsonl with N training examples

# Step 3: Train a LoRA adapter on the dataset
binoracle finetune --train --dataset my_dataset.jsonl --base-model qwen2.5-coder:7b --adapter-name my-lora --epochs 3
# This requires: a GPU with >=8 GB VRAM (or CPU with patience)
# Training takes ~30 min for 500 examples on a 7B model with one RTX 3080

# Step 4: Merge the adapter into the base model
binoracle finetune --merge --adapter my-lora --output binoracle-custom:latest

# Step 5: Use the fine-tuned model
BINORACLE_MODEL=binoracle-custom:latest binoracle cve CVE-2024-1234 -o report.html</code></pre>

  <div class="doc-callout tip">
    <strong>GPU requirements:</strong> Training a 7B model with LoRA requires ~8 GB VRAM (quantised to 4-bit via bitsandbytes). Training a 13B model requires ~16 GB. Training a 34B model requires ~24 GB. CPU training is possible but very slow (~10× slower than GPU).
  </div>

</main>
</div>"""
    return shell("LoRA Fine-tuning — binoracle docs", "finetune", body)


# ---------------------------------------------------------------------------
# MCP Tools Reference page
# ---------------------------------------------------------------------------
def mcp_tools_page():
    tools = [
        ("investigate_cve", "cve_id: str, lang?: str", "Full CVE investigation: NVD lookup → LLM hypothesis → Docker lab → HTML report bytes"),
        ("cve_chain", "cve_ids: list[str], lang?: str", "Multi-CVE chain analysis with pivot condition inference and combined impact"),
        ("autopwn", "binary_path: str, techniques?: list[str]", "Automated exploit development for a local ELF binary"),
        ("triage_binary", "binary_path: str", "Checksec + architecture detection + mitigation summary"),
        ("hunt_binary", "binary_path: str", "Static vulnerability hunt: format strings, dangerous calls, hardcoded secrets"),
        ("decompile_function", "binary_path: str, function: str, engine?: str", "Decompile a function with Ghidra, r2ghidra or pdc"),
        ("analyse_firmware", "image_path: str, focus?: str", "Extract and analyse ELF binaries from a firmware image"),
        ("kernel_exploit", "module_path: str, kernel?: str", "Analyse a Linux kernel module for exploitable vulnerabilities"),
        ("generate_dataset", "output_path: str, verified_only?: bool", "Generate SFT JSONL dataset from completed investigation sessions"),
        ("render_report", "markdown: str, cve?: str, lang?: str", "Render a markdown string as a professional CVE HTML report"),
        ("list_sessions", "", "List all investigation sessions in the local store"),
        ("get_session", "session_id: str", "Get the full Investigation object for a completed session"),
        ("fetch_cve", "cve_id: str", "Fetch CVE metadata from NVD (CVSS, vector, description, published date)"),
    ]
    rows = ""
    for name, params, desc in tools:
        rows += f'<tr><td><code>{name}</code></td><td><code style="font-size:.8em">{params}</code></td><td>{desc}</td></tr>\n'

    body = f"""
<div class="doc-layout">
{wiki_sidebar("mcp-tools", "en")}
<main class="doc-content" style="max-width:860px">
  <h1 id="overview">MCP Tools Reference</h1>
  <p class="page-lead">binoracle exposes every capability as an MCP (Model Context Protocol) tool. Connect Claude Desktop, VS Code with Continue, Zed, or any MCP-compatible client to run binoracle's full exploit research pipeline from within your AI assistant.</p>

  <h2 id="setup">Setup</h2>
  <p>Start the MCP server:</p>
  <pre><code>binoracle mcp-server</code></pre>
  <p>The server communicates over <strong>stdio</strong> and implements the <a href="https://modelcontextprotocol.io" target="_blank" rel="noopener">MCP specification</a>. No network port is opened — the client process spawns binoracle as a subprocess and communicates via stdin/stdout pipes.</p>

  <h2 id="claude-desktop">Claude Desktop</h2>
  <p>Add binoracle to <code>~/.claude/claude_desktop_config.json</code>:</p>
  <pre><code>{{
  "mcpServers": {{
    "binoracle": {{
      "command": "binoracle",
      "args": ["mcp-server"],
      "env": {{
        "BINORACLE_BACKEND": "ollama",
        "BINORACLE_MODEL": "qwen2.5-coder:7b"
      }}
    }}
  }}
}}</code></pre>
  <p>Restart Claude Desktop. You will see binoracle's tools appear in the tool picker. You can now ask Claude things like:</p>
  <ul>
    <li>"Investigate CVE-2024-1071 and give me the HTML report"</li>
    <li>"Triage the binary at /path/to/binary and find vulnerabilities"</li>
    <li>"Decompile the main function of /tmp/challenge"</li>
    <li>"Analyse this firmware image: /tmp/router.bin"</li>
  </ul>

  <h2 id="vscode">VS Code (Continue)</h2>
  <p>Add to <code>~/.continue/config.json</code>:</p>
  <pre><code>{{
  "mcpServers": [
    {{
      "name": "binoracle",
      "command": "binoracle",
      "args": ["mcp-server"]
    }}
  ]
}}</code></pre>
  <p>After adding it, Continue will auto-discover all binoracle tools. Use <code>@binoracle</code> in the Continue chat to scope tool calls.</p>

  <h2 id="tools-list">Tools Reference</h2>
  <div class="table-wrap"><table>
    <thead><tr><th>Tool</th><th>Parameters</th><th>Description</th></tr></thead>
    <tbody>{rows}</tbody>
  </table></div>

  <h2 id="examples">Examples</h2>
  <h3>Ask Claude to investigate a CVE</h3>
  <p>In Claude Desktop, with binoracle connected:</p>
  <pre><code>User: Investigate CVE-2024-27956 and tell me if it's exploitable.
       Save the report to /tmp/report.html

Claude: [calls investigate_cve(cve_id="CVE-2024-27956")]
        [calls render_report(markdown=..., cve="CVE-2024-27956")]
        The CVE is confirmed exploitable. CVSS 9.8 CRITICAL.
        Class: sqli (authentication bypass). Affected: WP Automatic <= 3.92.0.
        Report saved to /tmp/report.html.</code></pre>

  <h3>Binary analysis in Claude Desktop</h3>
  <pre><code">User: There's a binary at /tmp/challenge. Find vulnerabilities and
       give me an exploit strategy.

Claude: [calls triage_binary(binary_path="/tmp/challenge")]
        [calls hunt_binary(binary_path="/tmp/challenge")]
        [calls decompile_function(binary_path="/tmp/challenge", function="main")]
        [calls autopwn(binary_path="/tmp/challenge")]

        I found a stack-based buffer overflow in main() at offset 0x104.
        No canary, no PIE, NX enabled.
        Strategy: ret2plt → leak libc → ret2libc for shell.
        Here's the pwntools script: ...</code></pre>

  <h3>Firmware analysis via MCP</h3>
  <pre><code>User: Analyse this IoT firmware: /tmp/firmware.bin
       Focus on network-facing daemons.

Claude: [calls analyse_firmware(image_path="/tmp/firmware.bin", focus="*/httpd")]
        Found 3 binaries: httpd, utelnetd, miniupnpd
        httpd (MIPS32, no NX, no canary):
          - strcpy overflow in CGI parameter handler (HIGH)
          - hardcoded admin:admin credential in .rodata (HIGH)
        utelnetd: telnet enabled with no auth (CRITICAL)
        miniupnpd: format string in AddPortMapping handler (HIGH)</code></pre>

  <div class="doc-callout">
    <strong>Note:</strong> All file paths in MCP tool calls must be absolute paths accessible to the binoracle server process. If binoracle is running in a container or VM, paths must be accessible inside that environment.
  </div>

</main>
</div>"""
    return shell("MCP Tools Reference — binoracle docs", "mcp-tools", body)


def web_ui_page():
    body = f"""
<div class="doc-layout">
{wiki_sidebar("web-ui")}
<main class="doc-content">
<h1 id="overview">Web UI</h1>
<p class="page-lead">A full visual interface for every binoracle capability — no terminal needed. Output streams live via Server-Sent Events as investigations run.</p>

<h2 id="start">Starting the UI</h2>
<pre><code># default port 8000
binoracle web

# custom port
binoracle web --port 9090</code></pre>
<p>Then open <strong>http://localhost:8000</strong>. The page reconnects automatically if the server restarts.</p>

<h2 id="exploit-dev">Exploit Dev</h2>
<p>Type a CVE ID (e.g. <code>CVE-2024-1071</code>) into the input bar and press <strong>Run</strong>. The engine runs the full autonomous pipeline:</p>
<pre class="doc-pipeline"> CVE ID input
   │
   ├── NVD lookup ────── CVSS score, description, affected version
   ├── LLM hypothesis ── vulnerability class, endpoint, payload
   ├── Code analysis ─── source download, sink/source tracing
   ├── Docker lab ─────── ephemeral WordPress / app container
   ├── PoC execution ──── Playwright screenshots at each step
   └── Report ──────────  CVSS badge, evidence, PDF export</pre>

<p>The <strong>phase tracker</strong> shows progress across all stages. When the run finishes the Report tab populates automatically and the <strong>Export PDF</strong> button becomes active.</p>

<h3>Export PDF</h3>
<p>Click <strong>Export PDF</strong> in the top bar to download a complete A4 PDF of the report — dark theme, embedded screenshots, step-by-step evidence. No print dialog appears; the file saves directly.</p>
<div class="doc-callout tip">
  <strong>Tip.</strong> The PDF is generated server-side by Playwright. It includes all screenshots that appear in the Report tab at the moment you click the button.
</div>

<h2 id="binary-lab">Binary Lab</h2>
<p>Drag and drop any binary (ELF, PE, APK, Mach-O, WASM, JAR, .NET, Go, Rust, firmware, HAR, SQLite, EVM, JS, core dump) or use the Browse button. After upload the file is identified automatically. The lab has two sub-panels:</p>

<h3>EXPLOIT DEV AUTÓNOMO</h3>
<table>
<thead><tr><th>Group</th><th>Tools</th></tr></thead>
<tbody>
<tr><td><strong>Exploitation</strong></td><td><code>gadgets</code> <code>arsenal</code> <code>rop</code> <code>shellcode</code> <code>fmtstring</code> <code>primitives</code> <code>autopoc</code> <code>autopwn</code></td></tr>
<tr><td><strong>Fuzzing</strong></td><td><code>fuzz</code> <code>exploit-skeleton</code> <code>cve-corpus</code></td></tr>
<tr><td><strong>Utilities</strong></td><td><code>cyclic</code> (pattern generation) · <code>shellcode</code> (arch selector) · <code>kernel-exploit</code> (technique) — no file required</td></tr>
</tbody>
</table>

<h3>ANÁLISIS DE BINARIOS</h3>
<table>
<thead><tr><th>Group</th><th>Tools</th></tr></thead>
<tbody>
<tr><td><strong>Static Analysis</strong></td><td><code>identify</code> <code>elf</code> <code>pe</code> <code>macho</code> <code>apk</code> <code>java</code> <code>wasm</code> <code>dotnet</code> <code>go</code> <code>rust</code> <code>firmware</code> <code>har</code> <code>sqlite</code> <code>evm</code> <code>asar</code> <code>plist</code> <code>js</code> <code>rawshellcode</code> <code>core</code> <code>jeb</code></td></tr>
<tr><td><strong>Deep Analysis</strong></td><td><code>secrets</code> <code>funcid</code> <code>analyze</code> <code>explain</code> <code>audit</code> <code>heap</code> <code>triage</code> <code>hunt</code></td></tr>
</tbody>
</table>
<p>All output streams live to the terminal at the bottom of the lab. The active button highlights in orange.</p>

<h2 id="all-tools">Tabs reference</h2>
<table>
<thead><tr><th>Tab</th><th>Purpose</th></tr></thead>
<tbody>
<tr><td><strong>Live Log</strong></td><td>Real-time streaming output from any running job</td></tr>
<tr><td><strong>Report</strong></td><td>Professional investigation report — CVSS, phases, evidence, PDF export</td></tr>
<tr><td><strong>Evidence</strong></td><td>All collected evidence with copy-to-clipboard</td></tr>
<tr><td><strong>Screenshots</strong></td><td>Playwright screenshots captured at each step</td></tr>
<tr><td><strong>Binary Lab</strong></td><td>Upload + Exploit Dev / Análisis panels</td></tr>
</tbody>
</table>
</main>
</div>"""
    return shell("Web UI Reference — binoracle docs", "web-ui", body)


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
def build():
    # Clean and recreate site/
    if os.path.exists(SITE):
        shutil.rmtree(SITE)
    os.makedirs(SITE)

    # Copy assets
    assets_src = os.path.join(DOCS, "assets")
    assets_dst = os.path.join(SITE, "assets")
    if os.path.exists(assets_src):
        shutil.copytree(assets_src, assets_dst)

    # Landing page
    with open(os.path.join(SITE, "index.html"), "w", encoding="utf-8") as f:
        f.write(index_page())
    print("  index.html")

    # Tutorial pages
    with open(os.path.join(SITE, "tutorial.html"), "w", encoding="utf-8") as f:
        f.write(tutorial_page())
    print("  tutorial.html")
    with open(os.path.join(SITE, "tutorial-es.html"), "w", encoding="utf-8") as f:
        f.write(tutorial_es_page())
    print("  tutorial-es.html")

    # Roadmap page
    with open(os.path.join(SITE, "roadmap.html"), "w", encoding="utf-8") as f:
        f.write(roadmap_page())
    print("  roadmap.html")

    # Spanish wiki home
    with open(os.path.join(SITE, "index-es.html"), "w", encoding="utf-8") as f:
        f.write(docs_es_page())
    print("  index-es.html")

    # New wiki pages
    with open(os.path.join(SITE, "architecture.html"), "w", encoding="utf-8") as f:
        f.write(architecture_page())
    print("  architecture.html")

    with open(os.path.join(SITE, "cve-chains.html"), "w", encoding="utf-8") as f:
        f.write(cve_chains_page())
    print("  cve-chains.html")

    with open(os.path.join(SITE, "firmware.html"), "w", encoding="utf-8") as f:
        f.write(firmware_page())
    print("  firmware.html")

    with open(os.path.join(SITE, "kernel-exploits.html"), "w", encoding="utf-8") as f:
        f.write(kernel_exploits_page())
    print("  kernel-exploits.html")

    with open(os.path.join(SITE, "finetune.html"), "w", encoding="utf-8") as f:
        f.write(finetune_page())
    print("  finetune.html")

    with open(os.path.join(SITE, "mcp-tools.html"), "w", encoding="utf-8") as f:
        f.write(mcp_tools_page())
    print("  mcp-tools.html")

    with open(os.path.join(SITE, "web-ui.html"), "w", encoding="utf-8") as f:
        f.write(web_ui_page())
    print("  web-ui.html")

    print(f"\nSite written to {SITE}/")

if __name__ == "__main__":
    build()
