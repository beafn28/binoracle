#!/usr/bin/env python3
"""Build a static docs site from this repo's own markdown docs (docs/*.md and ROADMAP.md).

ROADMAP.md, "Cross-cutting quality" -- "A docs site with a guided tutorial over the `samples/`
corpus." The tutorial itself is `docs/TUTORIAL.md`; this script is the "site" half -- it turns
every page into real, static HTML with a shared nav, so there's something to literally open in a
browser instead of just a folder of markdown files on GitHub. No server, no JS framework, no
network at build or view time: `python3 docs/build_site.py` writes `docs/site/*.html`, and
`docs/site/index.html` is openable directly (`file://...`) or servable with any static host.

Needs the `markdown` package (`pip install markdown`, or `pip install -e ".[docs]"`); degrades
with a clear, non-zero-exit error (not a stack trace) if it's missing, same convention as every
other optional-dependency feature in this codebase."""
from __future__ import annotations

import html
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT_DIR = os.path.join(HERE, "site")

# (source path relative to repo root, output filename, nav label)
PAGES = [
    ("docs/TUTORIAL.md", "tutorial.html", "Tutorial guiado"),
    ("docs/USAGE.md", "usage.html", "Guia de uso"),
    ("docs/ENGINE.md", "engine.html", "Motor interno"),
    ("ROADMAP.md", "roadmap.html", "Roadmap"),
]

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
  <div class="brand">binoracle docs</div>
  {navlinks}
</nav>
<main>
{body}
</main>
</body>
</html>
"""


def _nav(current: str) -> str:
    links = ['<a href="index.html" class="{c}">Inicio</a>'.format(
        c="active" if current == "index.html" else "")]
    for _, fname, label in PAGES:
        cls = "active" if fname == current else ""
        links.append(f'<a href="{fname}" class="{cls}">{html.escape(label)}</a>')
    return "\n  ".join(links)


def _render_page(md_text: str, title: str, out_name: str) -> str:
    import markdown as _md
    body = _md.markdown(md_text, extensions=["tables", "fenced_code", "toc"])
    return _TEMPLATE.format(title=html.escape(title), navlinks=_nav(out_name), body=body)


def build() -> int:
    try:
        import markdown  # noqa: F401
    except ImportError:
        print("error: el paquete 'markdown' no esta instalado.\n"
              "  pip install markdown\n", file=sys.stderr)
        return 1

    os.makedirs(OUT_DIR, exist_ok=True)
    index_md = (
        "# binoracle\n\n"
        "Copiloto LLM local, fundamentado en oraculos (radare2/angr/gdb/sandbox real), "
        "para ingenieria inversa y explotacion de binarios.\n\n"
        "## Empieza aqui\n\n"
        "- **[Tutorial guiado](tutorial.html)** -- de cero a un exploit verificado, paso a paso, "
        "sobre el corpus de practica real en `samples/`.\n"
        "- **[Guia de uso](usage.html)** -- instalacion, CLI, servidor MCP, UI web.\n"
        "- **[Motor interno](engine.html)** -- como funciona por debajo (oraculos, sandbox, "
        "grounding).\n"
        "- **[Roadmap](roadmap.html)** -- que esta construido, que sigue, y la auditoria honesta "
        "de cada incremento.\n"
    )
    with open(os.path.join(OUT_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(_render_page(index_md, "binoracle", "index.html"))

    for src_rel, out_name, label in PAGES:
        src_path = os.path.join(ROOT, src_rel)
        if not os.path.exists(src_path):
            print(f"warning: falta {src_rel}, se omite", file=sys.stderr)
            continue
        with open(src_path, "r", encoding="utf-8") as f:
            md_text = f.read()
        html_out = _render_page(md_text, label, out_name)
        with open(os.path.join(OUT_DIR, out_name), "w", encoding="utf-8") as f:
            f.write(html_out)
        print(f"wrote {os.path.join('docs', 'site', out_name)}")

    print(f"\nSitio listo: abre {os.path.join(OUT_DIR, 'index.html')} en tu navegador.")
    return 0


if __name__ == "__main__":
    sys.exit(build())
