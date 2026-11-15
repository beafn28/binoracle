#!/usr/bin/env python3
"""Build the binoracle GitHub Pages site."""
import os, shutil, textwrap
import markdown as md

SITE = os.path.join(os.path.dirname(__file__), "site")
DOCS = os.path.dirname(__file__)
ROOT = os.path.dirname(DOCS)

PAGES = [
    ("README.es.md", "index-es.html", "binoracle — documentación en español"),
    (os.path.join(ROOT, "ROADMAP.md"), "roadmap.html", "Roadmap — binoracle"),
]
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
  font-size: 16px;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  background: var(--bg);
  color: var(--tx);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  line-height: 1.6;
  min-height: 100vh;
}

/* NAV */
.nav {
  position: sticky; top: 0; z-index: 100;
  display: flex; align-items: center; gap: 1.5rem;
  padding: .75rem 2rem;
  background: rgba(13,17,23,.92);
  backdrop-filter: blur(10px);
  border-bottom: 1px solid var(--brd);
}
.nav-brand { display: flex; align-items: center; gap: .6rem; text-decoration: none; color: var(--tx); font-weight: 700; font-size: 1.05rem; }
.nav-brand img { width: 28px; height: 28px; }
.nav-links { display: flex; gap: 1.25rem; margin-left: auto; }
.nav-links a { color: var(--muted); text-decoration: none; font-size: .9rem; transition: color .15s; }
.nav-links a:hover, .nav-links a.active { color: var(--tx); }
.nav-gh { display: flex; align-items: center; gap: .4rem; padding: .35rem .85rem; background: var(--surf2); border: 1px solid var(--brd); border-radius: 6px; color: var(--tx); text-decoration: none; font-size: .85rem; transition: border-color .15s; }
.nav-gh:hover { border-color: var(--acc); }

/* HERO */
.hero {
  display: flex; flex-direction: column; align-items: center; text-align: center;
  padding: 5rem 2rem 4rem;
  background: radial-gradient(ellipse 80% 50% at 50% -10%, rgba(31,107,235,.18), transparent);
}
.hero img { width: 72px; height: 72px; margin-bottom: 1.5rem; }
.hero h1 { font-size: 3rem; font-weight: 800; letter-spacing: -.03em; color: var(--tx); }
.hero .tagline { margin-top: .6rem; font-size: 1.15rem; color: var(--muted); max-width: 560px; }
.hero .install-box {
  margin: 2rem 0 1.5rem;
  display: flex; align-items: center; gap: .75rem;
  background: var(--surf); border: 1px solid var(--brd);
  border-radius: var(--r); padding: .75rem 1.25rem;
  font-family: 'JetBrains Mono', 'Courier New', monospace; font-size: .9rem;
  color: var(--code);
}
.install-box .prompt { color: var(--muted); user-select: none; }
.hero-cta { display: flex; gap: 1rem; flex-wrap: wrap; justify-content: center; }
.btn { display: inline-flex; align-items: center; gap: .4rem; padding: .6rem 1.25rem; border-radius: var(--r); font-size: .9rem; font-weight: 600; text-decoration: none; transition: all .15s; }
.btn-primary { background: var(--acc2); color: #fff; border: 1px solid var(--acc2); }
.btn-primary:hover { background: #388bfd; border-color: #388bfd; }
.btn-secondary { background: transparent; color: var(--tx); border: 1px solid var(--brd); }
.btn-secondary:hover { border-color: var(--muted); }
.badges { margin-top: 1.5rem; display: flex; gap: .5rem; flex-wrap: wrap; justify-content: center; }
.badges img { height: 20px; }

/* SECTIONS */
.section { padding: 4rem 2rem; max-width: 1100px; margin: 0 auto; }
.section-title { font-size: 1.5rem; font-weight: 700; color: var(--tx); margin-bottom: .5rem; }
.section-sub { color: var(--muted); margin-bottom: 2.5rem; font-size: .95rem; }
.divider { border: none; border-top: 1px solid var(--brd); margin: 0; }

/* FEATURE CARDS */
.feature-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.25rem; }
.feature-card {
  background: var(--surf); border: 1px solid var(--brd);
  border-radius: var(--r); padding: 1.5rem;
  display: flex; flex-direction: column; gap: .75rem;
}
.feature-card:hover { border-color: var(--acc); }
.feature-icon { width: 42px; height: 42px; border-radius: 10px; display: flex; align-items: center; justify-content: center; }
.feature-icon.blue { background: rgba(88,166,255,.12); color: var(--acc); }
.feature-icon.purple { background: rgba(188,140,255,.12); color: var(--pur); }
.feature-icon.green { background: rgba(63,185,80,.12); color: var(--grn); }
.feature-card h3 { font-size: 1.05rem; font-weight: 700; color: var(--tx); }
.feature-card p { font-size: .9rem; color: var(--muted); line-height: 1.55; }
.tag-list { display: flex; gap: .4rem; flex-wrap: wrap; margin-top: .25rem; }
.tag { font-size: .75rem; padding: .2rem .55rem; border-radius: 20px; background: var(--surf2); border: 1px solid var(--brd); color: var(--muted); font-family: monospace; }

/* CVE PIPELINE STEPS */
.pipeline-diagram { width: 100%; border-radius: var(--r); overflow: hidden; border: 1px solid var(--brd); margin-bottom: 2rem; }
.pipeline-diagram img { width: 100%; display: block; }
.steps-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 1rem; }
.step { background: var(--surf); border-radius: var(--r); padding: 1.1rem 1.25rem; border-left: 3px solid var(--brd); }
.step.s1 { border-color: var(--muted); }
.step.s2 { border-color: var(--pur); }
.step.s3 { border-color: var(--acc); }
.step.s4 { border-color: var(--yel); }
.step.s5 { border-color: var(--grn); }
.step-num { font-size: .7rem; font-weight: 700; color: var(--muted); text-transform: uppercase; letter-spacing: .08em; margin-bottom: .4rem; }
.step h4 { font-size: .95rem; font-weight: 700; color: var(--tx); margin-bottom: .3rem; }
.step p { font-size: .82rem; color: var(--muted); line-height: 1.4; }

/* TABLES */
.table-wrap { overflow-x: auto; border-radius: var(--r); border: 1px solid var(--brd); margin-bottom: 1.5rem; }
.table-wrap table { width: 100%; border-collapse: collapse; font-size: .9rem; }
.table-wrap th { background: var(--surf2); color: var(--muted); font-weight: 600; text-transform: uppercase; letter-spacing: .05em; font-size: .75rem; padding: .7rem 1rem; text-align: left; border-bottom: 1px solid var(--brd); }
.table-wrap td { padding: .65rem 1rem; border-bottom: 1px solid var(--brd); color: var(--tx); vertical-align: top; }
.table-wrap tr:last-child td { border-bottom: none; }
.table-wrap tr:hover td { background: var(--surf2); }
.table-wrap code { background: var(--surf2); padding: .1em .35em; border-radius: 4px; font-size: .85em; color: var(--code); font-family: monospace; }

/* TWO-COLUMN TABLE LAYOUT */
.table-pair { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }

/* ZERO CLOUD */
.zero-cloud {
  background: linear-gradient(135deg, rgba(5,46,22,.8) 0%, rgba(13,17,23,1) 100%);
  border: 1px solid rgba(63,185,80,.3); border-radius: 12px;
  padding: 2.5rem 2rem; text-align: center; margin: 2rem 0;
  display: flex; flex-direction: column; align-items: center; gap: 1rem;
}
.zero-cloud .lock-icon { width: 48px; height: 48px; background: rgba(63,185,80,.12); border-radius: 50%; display: flex; align-items: center; justify-content: center; color: var(--grn); }
.zero-cloud h3 { font-size: 1.3rem; font-weight: 700; color: var(--grn); }
.zero-cloud p { color: var(--muted); max-width: 500px; font-size: .95rem; }
.zero-cloud ul { list-style: none; display: flex; flex-wrap: wrap; gap: .75rem; justify-content: center; }
.zero-cloud li { display: flex; align-items: center; gap: .4rem; font-size: .88rem; color: var(--tx); }
.zero-cloud li svg { color: var(--grn); }

/* QUICK START */
.code-card {
  background: var(--surf); border: 1px solid var(--brd);
  border-radius: var(--r); overflow: hidden;
}
.code-header { display: flex; align-items: center; gap: .5rem; padding: .65rem 1rem; background: var(--surf2); border-bottom: 1px solid var(--brd); }
.code-header .dot { width: 10px; height: 10px; border-radius: 50%; }
.dot-red { background: #f85149; }
.dot-yel { background: #d29922; }
.dot-grn { background: #3fb950; }
.code-header span { font-size: .82rem; color: var(--muted); margin-left: .25rem; font-family: monospace; }
.code-card pre { padding: 1.25rem 1.5rem; overflow-x: auto; font-family: 'JetBrains Mono', 'Courier New', monospace; font-size: .85rem; line-height: 1.65; color: var(--tx); }
.code-card pre .comment { color: var(--muted); }
.code-card pre .cmd { color: var(--code); }
.code-card pre .kw { color: var(--acc); }
.code-card pre .val { color: var(--pur); }

/* ARCHITECTURE */
.arch-diagram { width: 100%; border-radius: var(--r); overflow: hidden; border: 1px solid var(--brd); }
.arch-diagram img { width: 100%; display: block; }

/* FOOTER */
.footer {
  border-top: 1px solid var(--brd);
  padding: 2rem;
  display: flex; justify-content: space-between; align-items: center;
  flex-wrap: wrap; gap: 1rem;
  color: var(--muted); font-size: .85rem;
  max-width: 1100px; margin: 0 auto;
}
.footer a { color: var(--muted); text-decoration: none; }
.footer a:hover { color: var(--tx); }
.footer-links { display: flex; gap: 1.25rem; }

/* DOC PAGE */
.doc-layout { display: flex; gap: 0; min-height: calc(100vh - 54px); }
.doc-sidebar {
  width: 220px; flex-shrink: 0;
  padding: 1.5rem 1rem;
  border-right: 1px solid var(--brd);
  position: sticky; top: 54px; height: calc(100vh - 54px); overflow-y: auto;
}
.doc-sidebar h4 { font-size: .72rem; font-weight: 700; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); margin-bottom: .75rem; }
.doc-sidebar a { display: block; padding: .3rem .5rem; color: var(--muted); text-decoration: none; font-size: .88rem; border-radius: 5px; }
.doc-sidebar a:hover { color: var(--tx); background: var(--surf2); }
.doc-content { flex: 1; padding: 2.5rem 2rem; max-width: 820px; }
.doc-content h1 { font-size: 2rem; font-weight: 800; margin-bottom: .5rem; color: var(--tx); }
.doc-content h2 { font-size: 1.3rem; font-weight: 700; margin: 2rem 0 .75rem; padding-bottom: .4rem; border-bottom: 1px solid var(--brd); color: var(--tx); }
.doc-content h3 { font-size: 1.05rem; font-weight: 700; margin: 1.5rem 0 .5rem; color: var(--tx); }
.doc-content p { margin-bottom: 1rem; color: var(--tx); line-height: 1.65; }
.doc-content ul, .doc-content ol { margin: .5rem 0 1rem 1.5rem; color: var(--tx); }
.doc-content li { margin-bottom: .3rem; }
.doc-content code { background: var(--surf2); padding: .15em .4em; border-radius: 4px; font-size: .88em; color: var(--code); font-family: monospace; }
.doc-content pre { background: var(--surf); border: 1px solid var(--brd); border-radius: var(--r); padding: 1rem 1.25rem; overflow-x: auto; margin: 1rem 0; }
.doc-content pre code { background: none; padding: 0; color: var(--tx); font-size: .88rem; }
.doc-content blockquote { border-left: 3px solid var(--acc2); padding: .5rem 1rem; color: var(--muted); background: var(--surf); border-radius: 0 var(--r) var(--r) 0; margin: 1rem 0; }
.doc-content table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: .9rem; }
.doc-content th { background: var(--surf2); color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .05em; padding: .6rem .9rem; text-align: left; border-bottom: 1px solid var(--brd); }
.doc-content td { padding: .6rem .9rem; border-bottom: 1px solid var(--brd); }
.doc-content img { max-width: 100%; border-radius: var(--r); border: 1px solid var(--brd); }
.doc-content a { color: var(--acc); }
.doc-content a:hover { text-decoration: underline; }

@media (max-width: 700px) {
  .nav-links { display: none; }
  .hero h1 { font-size: 2.2rem; }
  .table-pair { grid-template-columns: 1fr; }
  .doc-layout { flex-direction: column; }
  .doc-sidebar { width: 100%; position: static; height: auto; border-right: none; border-bottom: 1px solid var(--brd); }
}
"""

# ---------------------------------------------------------------------------
# HTML building blocks
# ---------------------------------------------------------------------------
def nav(current="index"):
    links = [
        ("index", "index.html", "Home"),
        ("docs", "index-es.html", "Docs"),
        ("tutorial", "tutorial.html", "Tutorial"),
        ("roadmap", "roadmap.html", "Roadmap"),
    ]
    items = ""
    for key, href, label in links:
        cls = ' class="active"' if key == current else ""
        items += f'<a href="{href}"{cls}>{label}</a>\n'
    return f"""
<nav class="nav">
  <a class="nav-brand" href="index.html">
    <img src="assets/logo.svg" alt="binoracle logo">
    binoracle
  </a>
  <div class="nav-links">
    {items}
    <a class="nav-gh" href="https://github.com/beafn28/binoracle" target="_blank" rel="noopener">
      {ico('github')} GitHub
    </a>
  </div>
</nav>"""

def footer():
    return """
<footer>
  <div class="footer">
    <span>MIT &copy; 2024&ndash;2025 Beatriz Fresno Naumova</span>
    <div class="footer-links">
      <a href="index.html">Home</a>
      <a href="roadmap.html">Roadmap</a>
      <a href="https://github.com/beafn28/binoracle/issues" target="_blank" rel="noopener">Issues</a>
      <a href="https://github.com/beafn28/binoracle" target="_blank" rel="noopener">GitHub</a>
    </div>
  </div>
</footer>"""

def shell(title, current, body):
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
{nav(current)}
{body}
{footer()}
</body>
</html>"""

# ---------------------------------------------------------------------------
# Landing page
# ---------------------------------------------------------------------------
def index_page():
    vuln_rows = [
        ("SSTI (Jinja2, Twig, Smarty)", "pip / gem"),
        ("SQLi (GET / POST / JSON / header)", "pip / gem / php / maven"),
        ("Path traversal / LFI", "pip / gem / npm / httpd"),
        ("RCE / command injection", "pip / gem / npm"),
        ("XSS (reflected / stored)", "pip / npm"),
        ("SSRF", "pip / npm"),
        ("XXE", "java / maven"),
        ("Deserialization", "java / gem (Marshal)"),
        ("Auth bypass / IDOR", "pip / gem / npm"),
        ("File upload / webshell", "pip"),
        ("CSRF", "pip / gem"),
        ("WordPress plugins (100+)", "WP Docker"),
        ("Joomla / Drupal extensions", "CMS Docker"),
        ("Java / Maven (Spring, Struts, Log4j)", "maven"),
        ("PHP Composer packages", "php"),
        ("npm / Node.js / Next.js", "npm"),
        ("Ruby gems (Rails, Rack, Sinatra)", "gem"),
    ]
    vuln_trs = "\n".join(
        f"<tr><td>{cls}</td><td><code>{sc}</code></td><td>{ico('check')} yes</td></tr>"
        for cls, sc in vuln_rows
    )

    exploit_rows = [
        ("Stack", "ret2win, ret2libc, ret2plt, ret2csu, SROP (x86-64/x86-32/aarch64), stack pivot, ROP chains"),
        ("Heap", "tcache dup, fastbin dup, UAF, double-free, House-of-Force/Spirit/Orange/Mind, large-bin attack, Botcake"),
        ("Format string", "%n arbitrary write, GOT overwrite, canary leak, PIE leak"),
        ("Low-level", "shellcode (NX off), bad-char scrubbing, IO_FILE exploit, DL-resolve, GOT hijack"),
        ("Canary", "leak + reuse, fork brute-force"),
        ("PIE", "partial overwrite, leak chain"),
    ]
    exploit_trs = "\n".join(
        f"<tr><td><strong>{fam}</strong></td><td>{tech}</td></tr>"
        for fam, tech in exploit_rows
    )

    format_rows = [
        ("ELF (x86-64 / x86 / ARM / MIPS / RISC-V)", "radare2, pyelftools, pwntools, angr"),
        ("PE / PE+ (Windows)", "pefile, LIEF, radare2"),
        ("Mach-O (macOS / iOS)", "LIEF, radare2"),
        ("APK / DEX (Android)", "apktool, jadx, androguard"),
        (".NET assemblies", "dnlib, ILSpy"),
        ("WASM modules", "wabt, binaryen"),
        ("Go / Rust binaries", "LIEF + symbol recovery"),
        ("EVM bytecode", "pyevmasm"),
        ("SQLite databases", "sqlite3 schema + data dump"),
    ]
    format_trs = "\n".join(
        f"<tr><td>{fmt}</td><td>{be}</td></tr>"
        for fmt, be in format_rows
    )

    body = f"""
<section class="hero">
  <img src="assets/logo.svg" alt="binoracle">
  <h1>binoracle</h1>
  <p class="tagline">Autonomous CVE exploit research and binary reverse engineering — 100% local, zero cloud calls.</p>
  <div class="install-box">
    <span class="prompt">$</span>
    pip install binoracle
  </div>
  <div class="hero-cta">
    <a class="btn btn-primary" href="https://github.com/beafn28/binoracle" target="_blank" rel="noopener">{ico('github')} GitHub</a>
    <a class="btn btn-secondary" href="roadmap.html">{ico('arrow-right')} Roadmap</a>
  </div>
  <div class="badges">
    <img src="https://img.shields.io/pypi/v/binoracle?color=blue&label=PyPI" alt="PyPI">
    <img src="https://img.shields.io/badge/python-%3E%3D3.10-blue" alt="Python">
    <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT">
  </div>
</section>

<hr class="divider">

<div class="section">
  <h2 class="section-title">Two independent analysis pipelines</h2>
  <p class="section-sub">binoracle combines a CVE exploit research engine with a binary reverse engineering engine, both running fully offline on your machine.</p>
  <div class="feature-grid">
    <div class="feature-card">
      <div class="feature-icon blue">{ico('shield')}</div>
      <h3>CVE Engine</h3>
      <p>Retrieves a CVE descriptor from NVD and submits it to a local LLM which autonomously generates exploit hypotheses without external hints. Provisions an ephemeral Docker Compose lab, executes the proof-of-concept, captures Playwright screenshots, and emits a structured HTML report.</p>
      <div class="tag-list">
        <span class="tag">NVD</span><span class="tag">Qwen 2.5 Coder 7B</span><span class="tag">Docker</span><span class="tag">Playwright</span>
      </div>
    </div>
    <div class="feature-card">
      <div class="feature-icon purple">{ico('cpu')}</div>
      <h3>Binary RE Engine</h3>
      <p>Static and dynamic analysis of ELF, PE, Mach-O, APK, WASM, Go, Rust, .NET, JS, EVM, and SQLite artifacts. Covers exploit generation across stack, heap, format string, and SROP primitives, plus ROP chain synthesis and multi-backend decompilation. All operations are local.</p>
      <div class="tag-list">
        <span class="tag">50+ exploit families</span><span class="tag">pwntools</span><span class="tag">radare2</span><span class="tag">angr</span>
      </div>
    </div>
    <div class="feature-card">
      <div class="feature-icon green">{ico('server')}</div>
      <h3>MCP Server</h3>
      <p>Exposes binoracle's full capability set as ~100 MCP tools, enabling integration with Claude Desktop, Cursor, Zed, and other MCP-compatible clients. Start the server with one command and add it to your client's configuration.</p>
      <div class="tag-list">
        <span class="tag">~100 tools</span><span class="tag">Claude Desktop</span><span class="tag">Cursor</span><span class="tag">Zed</span>
      </div>
    </div>
  </div>
</div>

<hr class="divider">

<div class="section">
  <h2 class="section-title">How the CVE engine works</h2>
  <p class="section-sub">The engine is fully autonomous — the local LLM receives only the NVD description and no analyst-supplied hints. All exploit hypotheses are derived from that description alone.</p>
  <div class="pipeline-diagram"><img src="assets/cve-flow.svg" alt="CVE engine pipeline"></div>
  <div class="steps-grid">
    <div class="step s1"><div class="step-num">Step 1</div><h4>NVD Fetch</h4><p>Retrieves the CVE record: identifier, CVSS score, affected package, and plain-language description.</p></div>
    <div class="step s2"><div class="step-num">Step 2</div><h4>LLM Hypothesis</h4><p>Qwen 2.5 Coder reads the description and generates a structured hypothesis: class, endpoint, payload strategy, ecosystem scaffolder.</p></div>
    <div class="step s3"><div class="step-num">Step 3</div><h4>Scaffolder Selection</h4><p>The engine maps the detected ecosystem to the matching Docker Compose lab template.</p></div>
    <div class="step s4"><div class="step-num">Step 4</div><h4>Docker Lab</h4><p>An ephemeral lab is built with the vulnerable package pinned at the affected version. Torn down after the run.</p></div>
    <div class="step s5"><div class="step-num">Step 5</div><h4>Playwright Verify</h4><p>The PoC executes against the lab. Playwright captures screenshots at each HTTP step and writes the HTML report.</p></div>
  </div>
  <h3 style="margin:2rem 0 1rem; color:var(--tx);">Supported vulnerability classes</h3>
  <div class="table-wrap"><table><thead><tr><th>Class</th><th>Scaffolder</th><th>Auto PoC</th></tr></thead><tbody>{vuln_trs}</tbody></table></div>
  <div style="background:var(--surf);border:1px solid var(--brd);border-radius:var(--r);padding:1rem 1.5rem;margin-top:1rem;">
    <p style="font-family:monospace;font-size:.88rem;color:var(--tx);">
      <span style="color:var(--muted)"># Single CVE</span><br>binoracle cve CVE-2025-27516<br><br>
      <span style="color:var(--muted)"># Batch, parallelized</span><br>binoracle cve-batch CVE-2025-27516 CVE-2024-23334 CVE-2025-59681
    </p>
  </div>
</div>

<hr class="divider">

<div class="section">
  <h2 class="section-title">Binary RE capabilities</h2>
  <p class="section-sub">50+ exploit families automated end-to-end. Static analysis, dynamic tracing, decompilation, and exploit chain generation across multiple binary formats.</p>
  <div class="table-pair">
    <div>
      <h3 style="color:var(--tx);margin-bottom:.75rem;">Exploit families</h3>
      <div class="table-wrap"><table><thead><tr><th>Family</th><th>Techniques</th></tr></thead><tbody>{exploit_trs}</tbody></table></div>
    </div>
    <div>
      <h3 style="color:var(--tx);margin-bottom:.75rem;">Supported formats</h3>
      <div class="table-wrap"><table><thead><tr><th>Format</th><th>Backends</th></tr></thead><tbody>{format_trs}</tbody></table></div>
    </div>
  </div>
</div>

<hr class="divider">

<div class="section">
  <div class="zero-cloud">
    <div class="lock-icon">{ico('lock')}</div>
    <h3>Zero cloud calls</h3>
    <p>No data leaves your machine at any point. The LLM runs locally via Ollama, Docker labs are ephemeral and local, and reports are written to disk.</p>
    <ul>
      <li>{ico('check')} LLM via Ollama at localhost:11434</li>
      <li>{ico('check')} Docker labs torn down after each run</li>
      <li>{ico('check')} Reports written to disk only</li>
      <li>{ico('check')} No telemetry, no account required</li>
    </ul>
  </div>
</div>

<hr class="divider">

<div class="section">
  <h2 class="section-title">Quick start</h2>
  <p class="section-sub">Three steps from zero to running your first CVE investigation.</p>
  <div class="code-card">
    <div class="code-header"><div class="dot dot-red"></div><div class="dot dot-yel"></div><div class="dot dot-grn"></div><span>terminal</span></div>
    <pre><span class="comment"># 1. Install binoracle</span>
<span class="cmd">pip install binoracle</span>

<span class="comment"># 2. Install Ollama and pull the model</span>
<span class="cmd">curl -fsSL https://ollama.com/install.sh | sh</span>
<span class="cmd">ollama pull qwen2.5-coder:7b</span>

<span class="comment"># 3. Configure the LLM backend</span>
<span class="kw">export</span> <span class="val">BINORACLE_BACKEND</span>=openai
<span class="kw">export</span> <span class="val">BINORACLE_BASE_URL</span>=http://127.0.0.1:11434/v1
<span class="kw">export</span> <span class="val">BINORACLE_MODEL</span>=qwen2.5-coder:7b

<span class="cmd">binoracle cve CVE-2025-27516</span>
<span class="cmd">binoracle pwn ./vulnerable_binary</span></pre>
  </div>
</div>

<hr class="divider">

<div class="section">
  <h2 class="section-title">Architecture</h2>
  <p class="section-sub">Interface layer (CLI, MCP server, web UI) → Workflow layer → Oracle / LLM Bridge / Lab Scaffolder backends.</p>
  <div class="arch-diagram"><img src="assets/architecture.svg" alt="binoracle architecture"></div>
</div>
"""
    return shell("binoracle — autonomous security research tool", "index", body)

# ---------------------------------------------------------------------------
# Doc page renderer
# ---------------------------------------------------------------------------
def doc_page(source_path, title, current):
    with open(source_path, encoding="utf-8") as f:
        raw = f.read()
    converter = md.Markdown(extensions=["tables", "fenced_code", "toc"])
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
    return shell(title, current, body)

# ---------------------------------------------------------------------------
# Tutorial page (English)
# ---------------------------------------------------------------------------
def tutorial_page():
    body = """
<div class="doc-layout">
  <aside class="doc-sidebar">
    <h4>Contents</h4>
    <a href="#overview">Overview</a>
    <a href="#install">Installation</a>
    <a href="#configure">Configuration</a>
    <a href="#cve">CVE Engine</a>
    <a href="#binary">Binary RE Engine</a>
    <a href="#mcp">MCP Server</a>
    <a href="#reports">Reports</a>
    <a href="#corpus">Practice Corpus</a>
    <h4 style="margin-top:1.5rem;">Navigation</h4>
    <a href="index.html">Home</a>
    <a href="tutorial-es.html">Tutorial (ES)</a>
    <a href="roadmap.html">Roadmap</a>
    <a href="https://github.com/beafn28/binoracle" target="_blank" rel="noopener">GitHub</a>
  </aside>
  <main class="doc-content">
    <h1 id="overview">binoracle Tutorial</h1>
    <p>This tutorial walks through every capability binoracle provides — from initial setup to running a full CVE investigation and generating an exploit chain against a local binary. All operations run entirely on your machine; no external API keys or cloud services are required.</p>
    <blockquote><strong>Legal notice</strong> — binoracle is a research and educational tool. All CVE labs run against Docker containers you provision locally. Do not use this tool against systems you do not own or lack explicit written authorization to test.</blockquote>
    <h2 id="install">1. Installation</h2>
    <p>binoracle requires Python 3.10 or later and Docker 20+.</p>
    <pre><code>pip install binoracle\npip install binoracle[pwn]        # pwntools + ROPgadget\npip install binoracle[symbolic]   # angr symbolic execution\npip install binoracle[screenshots] # Playwright screenshots\npip install binoracle[all]        # all of the above</code></pre>
    <h2 id="configure">2. Configuration</h2>
    <p>Install <a href="https://ollama.com" target="_blank" rel="noopener">Ollama</a> and pull the model:</p>
    <pre><code>curl -fsSL https://ollama.com/install.sh | sh\nollama pull qwen2.5-coder:7b</code></pre>
    <p>Set environment variables (add to <code>~/.bashrc</code> or <code>~/.zshrc</code>):</p>
    <pre><code>export BINORACLE_BACKEND=openai\nexport BINORACLE_BASE_URL=http://127.0.0.1:11434/v1\nexport BINORACLE_MODEL=qwen2.5-coder:7b\nexport BINORACLE_LANG=en</code></pre>
    <table><thead><tr><th>Dependency</th><th>Minimum</th><th>Recommended</th></tr></thead><tbody>
      <tr><td>Python</td><td>3.10</td><td>3.12</td></tr>
      <tr><td>RAM</td><td>8 GB</td><td>16 GB</td></tr>
      <tr><td>Docker</td><td>20.x</td><td>25.x</td></tr>
      <tr><td>Ollama</td><td>0.3</td><td>latest</td></tr>
      <tr><td>GPU (optional)</td><td>—</td><td>8 GB VRAM (Qwen 7B quantized)</td></tr>
    </tbody></table>
    <h2 id="cve">3. CVE Engine</h2>
    <p>The CVE engine takes a CVE identifier, retrieves the descriptor from NVD, feeds it to the local LLM, and autonomously generates and verifies an exploit proof-of-concept against an ephemeral Docker lab.</p>
    <pre><code>binoracle cve CVE-2025-27516\nbinoracle cve-batch CVE-2025-27516 CVE-2024-23334\nbinoracle cve CVE-2025-27516 --lang en --out ./reports/ --open-report</code></pre>
    <table><thead><tr><th>Step</th><th>What happens</th></tr></thead><tbody>
      <tr><td><strong>1 — NVD fetch</strong></td><td>Retrieves CVE record: identifier, CVSS score, affected package, description.</td></tr>
      <tr><td><strong>2 — LLM hypothesis</strong></td><td>Qwen reads the description and outputs: vulnerability class, endpoint, payload strategy, scaffolder.</td></tr>
      <tr><td><strong>3 — Scaffolder selection</strong></td><td>Maps the detected ecosystem to the matching Docker Compose lab template.</td></tr>
      <tr><td><strong>4 — Docker lab</strong></td><td>Ephemeral lab built with the vulnerable package at the affected version. Torn down when done.</td></tr>
      <tr><td><strong>5 — Playwright verify</strong></td><td>PoC executes against the lab. Playwright captures screenshots, records HTTP pairs, writes HTML report.</td></tr>
    </tbody></table>
    <h3>Supported vulnerability classes</h3>
    <table><thead><tr><th>Class</th><th>Scaffolders</th></tr></thead><tbody>
      <tr><td>SSTI (Jinja2, Twig, Smarty)</td><td><code>pip</code> / <code>gem</code></td></tr>
      <tr><td>SQLi (GET / POST / JSON / header)</td><td><code>pip</code> / <code>gem</code> / <code>php</code> / <code>maven</code></td></tr>
      <tr><td>Path traversal / LFI</td><td><code>pip</code> / <code>gem</code> / <code>npm</code> / <code>httpd</code></td></tr>
      <tr><td>RCE / command injection</td><td><code>pip</code> / <code>gem</code> / <code>npm</code></td></tr>
      <tr><td>XSS (reflected / stored)</td><td><code>pip</code> / <code>npm</code></td></tr>
      <tr><td>SSRF / CSRF / XXE</td><td><code>pip</code> / <code>npm</code> / <code>java</code></td></tr>
      <tr><td>Deserialization</td><td><code>java</code> / <code>gem (Marshal)</code></td></tr>
      <tr><td>Auth bypass / IDOR</td><td><code>pip</code> / <code>gem</code> / <code>npm</code></td></tr>
      <tr><td>File upload / webshell</td><td><code>pip</code></td></tr>
      <tr><td>WordPress plugins (100+)</td><td>WP Docker</td></tr>
      <tr><td>Joomla / Drupal extensions</td><td>CMS Docker</td></tr>
      <tr><td>Java / Maven (Spring, Struts, Log4j)</td><td><code>maven</code></td></tr>
      <tr><td>PHP / npm / Ruby gems</td><td><code>php</code> / <code>npm</code> / <code>gem</code></td></tr>
    </tbody></table>
    <h2 id="binary">4. Binary RE Engine</h2>
    <pre><code>binoracle pwn ./binary          # full exploit chain, auto-selected technique\nbinoracle triage ./binary       # mitigations, symbols, imports, sections\nbinoracle decompile ./binary    # Ghidra, radare2, angr, pwndbg\nbinoracle rop ./binary          # ROP gadget search + chain synthesis\nbinoracle hardening ./binary    # hardening assessment with bypass notes</code></pre>
    <table><thead><tr><th>Family</th><th>Techniques</th></tr></thead><tbody>
      <tr><td><strong>Stack</strong></td><td>ret2win, ret2libc, ret2plt, ret2csu, SROP (x86-64/x86-32/aarch64), stack pivot, ROP chains</td></tr>
      <tr><td><strong>Heap</strong></td><td>tcache dup, fastbin dup, UAF, double-free, House-of-Force/Spirit/Orange/Mind, large-bin attack, Botcake</td></tr>
      <tr><td><strong>Format string</strong></td><td>%n arbitrary write, GOT overwrite, canary leak, PIE leak</td></tr>
      <tr><td><strong>Low-level</strong></td><td>shellcode (NX off), bad-char scrubbing, IO_FILE exploit, DL-resolve, GOT hijack</td></tr>
      <tr><td><strong>Canary / PIE</strong></td><td>leak + reuse, fork brute-force, partial overwrite, leak chain</td></tr>
    </tbody></table>
    <h3>Practice corpus</h3>
    <pre><code>samples/build.sh\nbinoracle triage samples/bin/ret2win\nbinoracle pwn samples/bin/ret2libc\nbinoracle pwn samples/bin/format_string\nbinoracle pwn samples/bin/tcache_dup</code></pre>
    <table><thead><tr><th>Binary</th><th>Technique</th><th>Difficulty</th></tr></thead><tbody>
      <tr><td><code>ret2win</code></td><td>Simple return address overwrite</td><td>Beginner</td></tr>
      <tr><td><code>ret2libc</code></td><td>Ret-to-libc with ROP stub</td><td>Beginner</td></tr>
      <tr><td><code>format_string</code></td><td>GOT overwrite via %n</td><td>Intermediate</td></tr>
      <tr><td><code>canary_leak</code></td><td>Stack canary leak + reuse</td><td>Intermediate</td></tr>
      <tr><td><code>tcache_dup</code></td><td>tcache double-free primitive</td><td>Intermediate</td></tr>
      <tr><td><code>house_of_orange</code></td><td>House-of-Orange heap exploitation</td><td>Advanced</td></tr>
      <tr><td><code>srop_chain</code></td><td>Sigreturn-oriented programming</td><td>Advanced</td></tr>
      <tr><td><code>io_file</code></td><td>IO_FILE structure hijack</td><td>Advanced</td></tr>
    </tbody></table>
    <h2 id="mcp">5. MCP Server</h2>
    <pre><code>binoracle mcp-server</code></pre>
    <pre><code>// claude_desktop_config.json\n{\n  "mcpServers": {\n    "binoracle": { "command": "binoracle", "args": ["mcp-server"] }\n  }\n}</code></pre>
    <p>Key tools: <code>triage</code>, <code>pwn</code>, <code>rop_chain</code>, <code>heap_exploit</code>, <code>fmt_exploit</code>, <code>decompile</code>, <code>cve_investigate</code>, <code>vuln_hunt</code>, <code>hardening</code>, <code>audit</code>, <code>reachability</code>, <code>diff_patch</code>, <code>elf_layout</code>, <code>pe_inspect</code>, <code>apk_audit</code>, <code>dotnet_inspect</code>, <code>wasm_inspect</code>, <code>sqlite_audit</code>, <code>evm_inspect</code>, <code>fuzz</code>, <code>dynamic_trace</code>, <code>coredump</code> (~100 total).</p>
    <h2 id="reports">6. Reports</h2>
    <p>Each CVE investigation produces an HTML report with: executive summary + CVSS score, LLM hypothesis + reasoning chain, lab scaffold + Docker Compose spec, Playwright screenshots at each verification step, complete PoC code (curl / Python / pwntools), remediation recommendations.</p>
    <pre><code>binoracle cve CVE-2025-27516 --open-report\nbinoracle cve CVE-2025-27516 --out ./reports/my-research/</code></pre>
    <h2 id="corpus">7. Practice Corpus</h2>
    <p>40+ intentionally vulnerable binaries covering every exploit technique. Build with Docker or native gcc:</p>
    <pre><code>samples/build.sh</code></pre>
    <p>Techniques: ret2win, ret2libc, SROP, tcache dup, fastbin dup, UAF, format string GOT overwrite, canary leak, PIE leak, CSU chain, DL-resolve, heap botcake, house-of-orange, unsafe-unlink, stack pivot, IO_FILE, callhijack, dlresolve32.</p>
  </main>
</div>"""
    return shell("Tutorial — binoracle", "tutorial", body)

# ---------------------------------------------------------------------------
# Tutorial page (Spanish)
# ---------------------------------------------------------------------------
def tutorial_es_page():
    body = """
<div class="doc-layout">
  <aside class="doc-sidebar">
    <h4>Contenido</h4>
    <a href="#descripcion">Descripción</a>
    <a href="#instalacion">Instalación</a>
    <a href="#configuracion">Configuración</a>
    <a href="#motor-cve">Motor CVE</a>
    <a href="#binario">Motor RE Binario</a>
    <a href="#mcp">Servidor MCP</a>
    <a href="#informes">Informes</a>
    <a href="#corpus">Corpus de práctica</a>
    <h4 style="margin-top:1.5rem;">Navegación</h4>
    <a href="index.html">Inicio</a>
    <a href="tutorial.html">Tutorial (EN)</a>
    <a href="roadmap.html">Roadmap</a>
    <a href="https://github.com/beafn28/binoracle" target="_blank" rel="noopener">GitHub</a>
  </aside>
  <main class="doc-content">
    <h1 id="descripcion">Tutorial de binoracle</h1>
    <p>Este tutorial recorre todas las capacidades de binoracle: desde la instalación inicial hasta ejecutar una investigación CVE completa y generar una cadena de exploit contra un binario local. Todo se ejecuta en tu máquina; no se requieren claves de API externas ni servicios en la nube.</p>
    <blockquote><strong>Aviso legal</strong> — binoracle es una herramienta de investigación y educación. Todos los laboratorios CVE se ejecutan contra contenedores Docker que tú creas localmente. No la uses contra sistemas que no sean tuyos o para los que no tengas permiso escrito explícito.</blockquote>
    <h2 id="instalacion">1. Instalación</h2>
    <p>binoracle requiere Python 3.10 o superior y Docker 20+.</p>
    <pre><code>pip install binoracle\npip install binoracle[pwn]        # pwntools + ROPgadget\npip install binoracle[symbolic]   # ejecución simbólica angr\npip install binoracle[screenshots] # capturas Playwright\npip install binoracle[all]        # todo lo anterior</code></pre>
    <h2 id="configuracion">2. Configuración</h2>
    <p>Instala <a href="https://ollama.com" target="_blank" rel="noopener">Ollama</a> y descarga el modelo:</p>
    <pre><code>curl -fsSL https://ollama.com/install.sh | sh\nollama pull qwen2.5-coder:7b</code></pre>
    <p>Variables de entorno (añade a <code>~/.bashrc</code> o <code>~/.zshrc</code>):</p>
    <pre><code>export BINORACLE_BACKEND=openai\nexport BINORACLE_BASE_URL=http://127.0.0.1:11434/v1\nexport BINORACLE_MODEL=qwen2.5-coder:7b\nexport BINORACLE_LANG=es</code></pre>
    <table><thead><tr><th>Dependencia</th><th>Mínimo</th><th>Recomendado</th></tr></thead><tbody>
      <tr><td>Python</td><td>3.10</td><td>3.12</td></tr>
      <tr><td>RAM</td><td>8 GB</td><td>16 GB</td></tr>
      <tr><td>Docker</td><td>20.x</td><td>25.x</td></tr>
      <tr><td>Ollama</td><td>0.3</td><td>latest</td></tr>
      <tr><td>GPU (opcional)</td><td>—</td><td>8 GB VRAM (Qwen 7B cuantizado)</td></tr>
    </tbody></table>
    <h2 id="motor-cve">3. Motor CVE</h2>
    <p>El motor CVE toma un identificador CVE, recupera el descriptor de NVD, lo envía al LLM local, y genera y verifica de forma autónoma un proof-of-concept de exploit contra un laboratorio Docker efímero.</p>
    <pre><code>binoracle cve CVE-2025-27516\nbinoracle cve-batch CVE-2025-27516 CVE-2024-23334\nbinoracle cve CVE-2025-27516 --lang es --out ./informes/ --open-report</code></pre>
    <table><thead><tr><th>Paso</th><th>Qué ocurre</th></tr></thead><tbody>
      <tr><td><strong>1 — Obtención NVD</strong></td><td>Recupera el registro CVE: identificador, CVSS, versión afectada, descripción.</td></tr>
      <tr><td><strong>2 — Hipótesis LLM</strong></td><td>Qwen lee la descripción y genera: clase de vulnerabilidad, endpoint, payload, scaffolder.</td></tr>
      <tr><td><strong>3 — Selección scaffolder</strong></td><td>Mapea el ecosistema detectado a la plantilla Docker Compose correspondiente.</td></tr>
      <tr><td><strong>4 — Laboratorio Docker</strong></td><td>Lab efímero con el paquete vulnerable en la versión afectada. Se destruye al terminar.</td></tr>
      <tr><td><strong>5 — Verificación Playwright</strong></td><td>El PoC se ejecuta contra el lab. Playwright captura pantallas y escribe el informe HTML.</td></tr>
    </tbody></table>
    <h3>Clases de vulnerabilidad soportadas</h3>
    <table><thead><tr><th>Clase</th><th>Scaffolders</th></tr></thead><tbody>
      <tr><td>SSTI (Jinja2, Twig, Smarty)</td><td><code>pip</code> / <code>gem</code></td></tr>
      <tr><td>SQLi (GET / POST / JSON / header)</td><td><code>pip</code> / <code>gem</code> / <code>php</code> / <code>maven</code></td></tr>
      <tr><td>Path traversal / LFI</td><td><code>pip</code> / <code>gem</code> / <code>npm</code> / <code>httpd</code></td></tr>
      <tr><td>RCE / inyección de comandos</td><td><code>pip</code> / <code>gem</code> / <code>npm</code></td></tr>
      <tr><td>XSS / SSRF / CSRF / XXE</td><td><code>pip</code> / <code>npm</code> / <code>java</code></td></tr>
      <tr><td>Deserialización</td><td><code>java</code> / <code>gem (Marshal)</code></td></tr>
      <tr><td>Auth Bypass / IDOR / File upload</td><td><code>pip</code> / <code>gem</code> / <code>npm</code></td></tr>
      <tr><td>Plugins WordPress (100+)</td><td>WP Docker</td></tr>
      <tr><td>Extensiones Joomla / Drupal</td><td>CMS Docker</td></tr>
      <tr><td>Java / Maven (Spring, Struts, Log4j)</td><td><code>maven</code></td></tr>
      <tr><td>PHP / npm / Ruby gems</td><td><code>php</code> / <code>npm</code> / <code>gem</code></td></tr>
    </tbody></table>
    <h2 id="binario">4. Motor de Reversing Binario</h2>
    <pre><code>binoracle pwn ./binario          # cadena de exploit completa\nbinoracle triage ./binario       # mitigaciones, símbolos, importaciones\nbinoracle decompile ./binario    # Ghidra, radare2, angr, pwndbg\nbinoracle rop ./binario          # búsqueda de gadgets ROP + síntesis\nbinoracle hardening ./binario    # hardening con notas de bypass</code></pre>
    <table><thead><tr><th>Familia</th><th>Técnicas</th></tr></thead><tbody>
      <tr><td><strong>Stack</strong></td><td>ret2win, ret2libc, ret2plt, ret2csu, SROP, stack pivot, cadenas ROP</td></tr>
      <tr><td><strong>Heap</strong></td><td>tcache dup, fastbin dup, UAF, double-free, House-of-Force/Spirit/Orange/Mind, Botcake</td></tr>
      <tr><td><strong>Format String</strong></td><td>escritura arbitraria con %n, sobrescritura GOT, fuga de canary, fuga de PIE</td></tr>
      <tr><td><strong>Bajo nivel</strong></td><td>shellcode, bad-chars, IO_FILE, DL-resolve, secuestro GOT</td></tr>
      <tr><td><strong>Canary / PIE</strong></td><td>fuga + reutilización, fuerza bruta en fork, sobrescritura parcial</td></tr>
    </tbody></table>
    <h3>Corpus de práctica</h3>
    <pre><code>samples/build.sh\nbinoracle triage samples/bin/ret2win\nbinoracle pwn samples/bin/ret2libc\nbinoracle pwn samples/bin/format_string\nbinoracle pwn samples/bin/tcache_dup</code></pre>
    <table><thead><tr><th>Binario</th><th>Técnica</th><th>Dificultad</th></tr></thead><tbody>
      <tr><td><code>ret2win</code></td><td>Sobrescritura de dirección de retorno</td><td>Principiante</td></tr>
      <tr><td><code>ret2libc</code></td><td>Ret-to-libc con stub ROP</td><td>Principiante</td></tr>
      <tr><td><code>format_string</code></td><td>Sobrescritura GOT con %n</td><td>Intermedio</td></tr>
      <tr><td><code>canary_leak</code></td><td>Fuga de canary + reutilización</td><td>Intermedio</td></tr>
      <tr><td><code>tcache_dup</code></td><td>Primitiva double-free tcache</td><td>Intermedio</td></tr>
      <tr><td><code>house_of_orange</code></td><td>Explotación heap House-of-Orange</td><td>Avanzado</td></tr>
      <tr><td><code>srop_chain</code></td><td>Programación orientada a Sigreturn</td><td>Avanzado</td></tr>
      <tr><td><code>io_file</code></td><td>Secuestro de estructura IO_FILE</td><td>Avanzado</td></tr>
    </tbody></table>
    <h2 id="mcp">5. Servidor MCP</h2>
    <pre><code>binoracle mcp-server</code></pre>
    <pre><code>// claude_desktop_config.json\n{\n  "mcpServers": {\n    "binoracle": { "command": "binoracle", "args": ["mcp-server"] }\n  }\n}</code></pre>
    <h2 id="informes">6. Informes</h2>
    <p>Cada investigación CVE genera un informe HTML con: resumen ejecutivo + CVSS, hipótesis del LLM + cadena de razonamiento, configuración del lab + Docker Compose, capturas Playwright, código PoC completo, recomendaciones de remediación.</p>
    <pre><code>binoracle cve CVE-2025-27516 --open-report\nbinoracle cve CVE-2025-27516 --out ./informes/</code></pre>
    <h2 id="corpus">7. Corpus de práctica</h2>
    <p>Más de 40 binarios intencionalmente vulnerables. Compiílalos con Docker o gcc:</p>
    <pre><code>samples/build.sh</code></pre>
    <p>Técnicas cubiertas: ret2win, ret2libc, SROP, tcache dup, fastbin dup, UAF, format string GOT overwrite, canary leak, PIE leak, CSU chain, DL-resolve, heap botcake, house-of-orange, unsafe-unlink, stack pivot, IO_FILE, callhijack, dlresolve32.</p>
  </main>
</div>"""
    return shell("Tutorial — binoracle", "tutorial", body)

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
def build():
    if os.path.exists(SITE):
        shutil.rmtree(SITE)
    os.makedirs(SITE)

    assets_src = os.path.join(DOCS, "assets")
    assets_dst = os.path.join(SITE, "assets")
    if os.path.exists(assets_src):
        shutil.copytree(assets_src, assets_dst)

    with open(os.path.join(SITE, "index.html"), "w", encoding="utf-8") as f:
        f.write(index_page())
    print("  index.html")

    with open(os.path.join(SITE, "tutorial.html"), "w", encoding="utf-8") as f:
        f.write(tutorial_page())
    print("  tutorial.html")

    with open(os.path.join(SITE, "tutorial-es.html"), "w", encoding="utf-8") as f:
        f.write(tutorial_es_page())
    print("  tutorial-es.html")

    for src, out, title in PAGES:
        src_path = src if os.path.isabs(src) else os.path.join(DOCS, src)
        if not os.path.exists(src_path):
            print(f"  SKIP {out} (source not found: {src_path})")
            continue
        current = out.replace(".html", "").replace("index-es", "docs")
        html = doc_page(src_path, title, current)
        with open(os.path.join(SITE, out), "w", encoding="utf-8") as f:
            f.write(html)
        print(f"  {out}")

    print(f"\nSite written to {SITE}/")

if __name__ == "__main__":
    build()
