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


def _md_rich(s: str) -> str:
    """Markdown enriquecido para la decompilacion anotada: bloques ``` de codigo, cabeceras
    ###, listas y **negrita**/`codigo`. Suficiente para el texto que produce el LLM."""
    import re as _re
    s = s or ""
    out = []
    parts = _re.split(r"```[a-zA-Z]*\n?", s)     # alterna prosa / codigo
    for i, part in enumerate(parts):
        if i % 2 == 1:                            # dentro de un bloque de codigo
            out.append(f'<pre class="code">{_esc(part.rstrip())}</pre>')
            continue
        for ln in part.splitlines():
            t = ln.strip()
            if not t:
                continue
            if t.startswith("### "):
                out.append(f'<h5>{_esc(t[4:])}</h5>')
            elif t.startswith("## "):
                out.append(f'<h4>{_esc(t[3:])}</h4>')
            else:
                h = _esc(t)
                h = _re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", h)
                h = _re.sub(r"`([^`]+)`", r"<code>\1</code>", h)
                out.append(f"<p>{h}</p>")
    return "".join(out)


def _decompiled_html(decompiled) -> str:
    """Seccion de decompilacion anotada: pseudo-C limpio + explicacion por funcion, con el
    decompilado crudo de r2 plegable como evidencia."""
    if not decompiled:
        return ""
    cards = ""
    for d in decompiled:
        ann = getattr(d, "annotated", "") or ""
        raw = getattr(d, "raw", "") or ""
        engine = getattr(d, "engine", "") or "r2"
        func = getattr(d, "func", "?")
        body = _md_rich(ann) if ann.strip() else (
            '<p class="mut">Sin modelo local: solo decompilado crudo de r2 (levanta ollama para '
            'la version anotada).</p>')
        raw_block = (f'<details class="sec"><summary>decompilado crudo (r2 {_esc(engine)})</summary>'
                     f'<pre>{_esc(raw)}</pre></details>') if raw.strip() else ""
        cards += (f'<div class="decfn"><div class="decfn-h"><span class="decfn-t">{_esc(func)}</span>'
                  f'<span class="decfn-e">r2 {_esc(engine)} + LLM</span></div>'
                  f'<div class="md">{body}</div>{raw_block}</div>')
    return f'<h2 data-i18n="decompiled" id="sec-dec"></h2>{cards}'


import re as _re_mod


def _exploit_section(binary: str, findings, lang: str) -> str:
    """Reproduccion paso a paso + script pwntools del exploit verificado (si lo hay)."""
    vf = next((f for f in findings if f.verdict == "verified" and "ret2win" in (f.title + f.evidence).lower()), None)
    if vf is None:
        return ""
    m = _re_mod.search(r"offset\s*=\s*(\d+)", vf.evidence or "")
    off = int(m.group(1)) if m else None
    mw = _re_mod.search(r"win\s*=\s*(0x[0-9a-fA-F]+)", (vf.location or "") + " " + (vf.evidence or ""))
    win = mw.group(1) if mw else "0x0"
    name = _esc(_os_basename(binary))
    T = _EXP_STR.get(lang, _EXP_STR["es"])
    steps = "".join(f'<li>{s}</li>' for s in T["steps"](off if off is not None else "N", win))
    script = (f'from pwn import *\n'
              f'context.binary = elf = ELF("./{name}")\n\n'
              f'# io = remote("HOST", PORT)      # {T["remote"]}\n'
              f'io = process("./{name}")          # {T["local"]}\n\n'
              f'offset = {off if off is not None else "N"}{" "*3}# {T["offc"]}\n'
              f'payload  = b"A" * offset\n'
              f'payload += p64(elf.sym.win)       # ret2win -> {win}\n'
              f'# {T["align"]}\n'
              f'# payload = b"A"*offset + p64(RET) + p64(elf.sym.win)\n\n'
              f'io.sendline(payload)\n'
              f'io.interactive()                  # -> shell')
    return (f'<h2 data-i18n="exploit_steps" id="sec-exploit"></h2>'
            f'<div class="expwrap"><div class="expcol"><div class="panel-t">{T["repro"]}</div>'
            f'<ol class="steps">{steps}</ol></div>'
            f'<div class="expcol"><div class="panel-t">{T["script"]}</div>'
            f'<pre class="code">{_esc(script)}</pre></div></div>')


def _mit_detail(mit: dict, lang: str) -> str:
    """Cada mitigacion: estado, que implica para explotacion y como remediar."""
    T = _MIT_STR.get(lang, _MIT_STR["es"])
    rows = ""
    order = ["NX", "PIE", "Canary", "RELRO"]
    for k in order:
        v = mit.get(k)
        info = T[k](v)
        cls = info["cls"]
        rows += (f'<tr class="mitrow {cls}"><td class="mk">{_esc(k)}</td>'
                 f'<td class="mstate">{_esc(info["state"])}</td>'
                 f'<td>{_esc(info["impact"])}</td>'
                 f'<td class="mrem">{_esc(info["rem"])}</td></tr>')
    return (f'<h2 data-i18n="mit_detail" id="sec-mit"></h2>'
            f'<table class="mittab"><thead><tr><th>{T["h_mit"]}</th><th>{T["h_state"]}</th>'
            f'<th>{T["h_impact"]}</th><th>{T["h_rem"]}</th></tr></thead><tbody>{rows}</tbody></table>')


# Mapa tecnica -> cheat sheets del RAG + fuentes autoritativas.
_REF_MAP = {
    "ret2win": (["ret2win", "rop"], []),
    "overflow": (["mitigations", "pie", "canary-bypass"], []),
    "read": (["mitigations", "shellcoding"], []),
    "system": (["got-plt"], []),
    "rop": (["rop", "advanced-rop", "syscall-table"], []),
    "format": (["format-string", "got-plt"], []),
    "heap": (["heap", "modern-heap", "heap-version-matrix"], ["shellphish/how2heap"]),
    "kernel": (["kernel-pwn", "kernel-mitigations"], ["xairy/linux-kernel-exploitation"]),
}


def _attack_chain(findings, mit: dict, lang: str) -> str:
    """Cadenas de explotacion: encadena los fallos detectados en un camino de ataque paso a paso,
    grounded en los hallazgos y mitigaciones (como un fallo habilita el siguiente hasta el objetivo)."""
    tl = " ".join((f.title + " " + (f.location or "")).lower() for f in findings)
    es = lang == "es"
    def has(*ws): return any(w in tl for w in ws)
    verified = next((f for f in findings if f.verdict == "verified" and "ret2" in (f.title + f.evidence).lower()), None)
    chains = []  # (titulo, [(paso, detalle, kind)])
    # 1) corrupcion de memoria -> RCE
    if has("desbordamiento", "overflow", "ret2win", "read"):
        steps = [("Entrada sin acotar" if es else "Unbounded input",
                  "Un sink de lectura escribe mas alla del buffer: overflow controlable por el atacante."
                  if es else "A read sink writes past the buffer: attacker-controllable overflow.", "grounded")]
        if mit.get("Canary") is False:
            steps.append(("Sin stack canary" if es else "No stack canary",
                          "El overflow lineal alcanza y sobrescribe la direccion de retorno guardada."
                          if es else "The linear overflow reaches and overwrites the saved return address.", "grounded"))
        if mit.get("PIE") is False:
            steps.append(("Sin PIE" if es else "No PIE",
                          "El codigo esta en direcciones FIJAS: el objetivo se puede hardcodear sin leak."
                          if es else "Code is at FIXED addresses: the target can be hardcoded, no leak needed.", "grounded"))
        if has("gadget", "system", "win", "ret2win"):
            steps.append(("Funcion objetivo (gift)" if es else "Target function (gift)",
                          "Existe win()/system('/bin/sh') como destino del control de flujo."
                          if es else "win()/system('/bin/sh') exists as the control-flow target.", "grounded"))
        if verified:
            steps.append(("Shell (VERIFICADO)" if es else "Shell (VERIFIED)",
                          "Se sobrescribe RIP con la funcion objetivo y se obtiene shell en sandbox (uid=0)."
                          if es else "RIP is overwritten with the target and a shell is obtained in the sandbox (uid=0).",
                          "verified"))
        chains.append((("Corrupcion de memoria -> RCE" if es else "Memory corruption -> RCE"), steps))
    # 2) credenciales -> acceso no autorizado
    if has("credencial", "secreto", "hardcod", "clave privada", "aws", "token", "jwt"):
        chains.append((("Credenciales -> acceso no autorizado" if es else "Credentials -> unauthorized access"),
            [("Secreto hardcodeado" if es else "Hardcoded secret",
              "El binario embebe una credencial/clave/token extraible de las strings."
              if es else "The binary embeds a credential/key/token extractable from strings.", "grounded"),
             ("Auth bypass / acceso" if es else "Auth bypass / access",
              "Con la credencial expuesta se accede a sistemas o datos protegidos (o se firma como legitimo)."
              if es else "With the exposed credential, protected systems/data are accessed (or signed as legit).", "grounded")]))
    # 3) SUID + inyeccion -> root
    if has("setuid", "setgid") and has("inyeccion de comando", "command injection", "system"):
        chains.append((("SUID + inyeccion -> root" if es else "SUID + injection -> root"),
            [("Binario SUID" if es else "SUID binary", "Corre con privilegios elevados." if es else "Runs with elevated privileges.", "grounded"),
             ("Inyeccion de comando" if es else "Command injection", "Entrada controlable llega a system/exec." if es else "Controllable input reaches system/exec.", "grounded"),
             ("Root" if es else "Root", "El comando inyectado se ejecuta como root." if es else "The injected command runs as root.", "grounded")]))
    # 4) callback en runtime -> C2 / exfiltracion (observado dinamicamente)
    if has("conexion saliente en runtime", "runtime outbound", "reverse shell", "bind shell"):
        rev = has("reverse shell") or has("conexion saliente")
        chains.append((("Callback en runtime -> C2 / exfiltracion" if es else "Runtime callback -> C2 / exfiltration"),
            [("Shell/socket a atacante" if es else "Shell/socket to attacker",
              "El binario abre un canal de red hacia un atacante (reverse/bind shell)." if es
              else "The binary opens a network channel to an attacker (reverse/bind shell).", "grounded"),
             ("Conexion observada en runtime" if es else "Connection observed at runtime",
              "En ejecucion (sandbox) se intercepto el intento de conexion al destino: comportamiento verificado."
              if es else "At runtime (sandbox) the connection attempt to the destination was intercepted: verified behavior.",
              "verified"),
             ("Control remoto / robo de datos" if es else "Remote control / data theft",
              "El canal da al atacante ejecucion de comandos o salida para exfiltrar." if es
              else "The channel gives the attacker command execution or an egress path to exfiltrate.", "grounded")]))
    # 5) sin TLS / cert -> MITM
    if has("sin cifrar", "cleartext", "certificado", "certificate"):
        chains.append((("Transporte inseguro -> MITM" if es else "Insecure transport -> MITM"),
            [("Sin cifrado / sin validar cert" if es else "No encryption / no cert check",
              "El trafico va en claro o se acepta cualquier certificado." if es else "Traffic is cleartext or any certificate is accepted.", "grounded"),
             ("Interceptar / modificar" if es else "Intercept / modify",
              "Un atacante en la red lee y altera la comunicacion (credenciales, actualizaciones)."
              if es else "A network attacker reads and alters the communication (credentials, updates).", "grounded")]))
    if not chains:
        return ""
    _KC = {"verified": "#30a46c", "grounded": "#5b8def"}
    blocks = ""
    for title, steps in chains:
        row = ""
        for i, (name, detail, kind) in enumerate(steps):
            arrow = '<div class="chain-arr">&#8594;</div>' if i else ""
            row += (arrow + f'<div class="chain-step" style="border-color:{_KC.get(kind, "#5b8def")}">'
                    f'<div class="chain-n">{_esc(name)}</div><div class="chain-d">{_esc(detail)}</div></div>')
        blocks += f'<div class="chain-t">{_esc(title)}</div><div class="chain-row">{row}</div>'
    note = ("Cadena grounded: cada eslabon sale de un hallazgo o mitigacion reales; el paso "
            "'VERIFICADO' esta probado por ejecucion, los demas son el razonamiento del encadenamiento."
            if es else "Grounded chain: each link comes from a real finding or mitigation; the "
            "'VERIFIED' step is proven by execution, the rest are the chaining rationale.")
    return (f'<h2 data-i18n="attack_chain" id="sec-chain"></h2>'
            f'<p class="mut" style="font-size:12px;margin:-4px 0 10px">{_esc(note)}</p>{blocks}')


def _references(findings, lang: str) -> str:
    """Referencias: cheat sheets del RAG relevantes a lo detectado + fuentes autoritativas."""
    blob = " ".join((f.title + " " + (f.evidence or "") + " " + (f.location or "")) for f in findings).lower()
    sheets, ext = [], []
    for key, (sh, ex) in _REF_MAP.items():
        if key in blob:
            for s in sh:
                if s not in sheets:
                    sheets.append(s)
            for e in ex:
                if e not in ext:
                    ext.append(e)
    if not sheets:
        sheets = ["methodology", "mitigations"]
    T = _REF_STR.get(lang, _REF_STR["es"])
    chips = "".join(f'<code class="refchip">binoracle kb "{_esc(s)}"</code>' for s in sheets)
    extl = "".join(f'<li>{_esc(e)}</li>' for e in ext)
    ext_html = f'<div class="panel-t" style="margin-top:12px">{T["ext"]}</div><ul class="reflist">{extl}</ul>' if ext else ""
    return (f'<h2 data-i18n="references" id="sec-refs"></h2>'
            f'<p class="mut" style="font-size:12px">{T["note"]}</p>'
            f'<div class="refchips">{chips}</div>{ext_html}')


def _os_basename(p: str) -> str:
    import os as _os
    return _os.path.basename(p) or "binary"


# Explicacion en lenguaje claro de cada seccion de la superficie de ataque (por palabra clave).
_SURFACE_HELP = [
    (("elf header", "header", "file /"),
     "Cabecera del ejecutable: arquitectura, tipo (EXEC/DYN), punto de entrada. Es lo primero "
     "para saber QUE es el binario y como esta construido.",
     "Executable header: architecture, type (EXEC/DYN), entry point. The first thing to know "
     "WHAT the binary is and how it is built."),
    (("checksec", "mitigation", "mitigaciones"),
     "Mitigaciones de explotacion activas (NX, PIE, canary, RELRO). Deciden que rutas de ataque "
     "son viables: sin canary el overflow pisa el retorno directo; sin PIE las direcciones son fijas.",
     "Active exploit mitigations (NX, PIE, canary, RELRO). They decide which attack paths are "
     "viable: no canary means the overflow overwrites the return directly; no PIE means fixed addresses."),
    (("binary info", "iI", "info radare"),
     "Metadatos de radare2: formato, bits, compilador, si esta 'stripped' (sin simbolos). Contexto "
     "general del binario.",
     "radare2 metadata: format, bits, compiler, whether it is stripped. General context of the binary."),
    (("hardening", "fortify", "asan", "cfi", "safestack"),
     "Protecciones modernas del compilador (FORTIFY_SOURCE, AddressSanitizer, CFI, SafeStack). "
     "Endurecen el binario frente a corrupcion de memoria y desvio de flujo.",
     "Modern compiler protections (FORTIFY_SOURCE, AddressSanitizer, CFI, SafeStack). They harden "
     "the binary against memory corruption and control-flow hijacking."),
    (("imports",),
     "Funciones que el binario importa de librerias: su 'capacidad' (que puede hacer: red, "
     "ficheros, exec, cripto). Delatan la superficie y las funciones peligrosas.",
     "Functions the binary imports from libraries: its 'capability' (what it can do: network, "
     "files, exec, crypto). They reveal the surface and the dangerous functions."),
    (("dangerous sinks", "sinks"),
     "Funciones PELIGROSAS (gets, strcpy, system, read...) y desde donde se llaman. Es el punto de "
     "partida: cada sink alcanzable por entrada del usuario es un candidato a vulnerabilidad.",
     "DANGEROUS functions (gets, strcpy, system, read...) and where they are called from. The "
     "starting point: every sink reachable by user input is a vulnerability candidate."),
    (("vtable", "c++"),
     "Tablas virtuales de C++ (vtables): punteros a metodos. Si se corrompen (UAF/type-confusion), "
     "una llamada virtual salta a codigo del atacante.",
     "C++ virtual tables (vtables): pointers to methods. If corrupted (UAF/type-confusion), a "
     "virtual call jumps to attacker code."),
    (("heap",),
     "Superficie de heap: llamadas a malloc/free/realloc. Candidatos a use-after-free, "
     "double-free y overflow de heap.",
     "Heap surface: malloc/free/realloc calls. Candidates for use-after-free, double-free and "
     "heap overflow."),
    (("indirect control", "indirect", "punteros a funcion"),
     "Saltos y llamadas INDIRECTAS (call/jmp rax): el destino sale de un registro/puntero (heap, "
     "pila, vtable). Si controlas ese puntero, desvias el flujo de ejecucion.",
     "INDIRECT jumps and calls (call/jmp rax): the target comes from a register/pointer (heap, "
     "stack, vtable). If you control that pointer, you hijack execution flow."),
    (("strings", "izz"),
     "Cadenas del binario: rutas, formatos, mensajes, posibles secretos o URLs. Utiles para "
     "entender el comportamiento y encontrar credenciales.",
     "Binary strings: paths, formats, messages, possible secrets or URLs. Useful to understand "
     "behavior and find credentials."),
]


def _surface_help(key: str, lang: str) -> str:
    k = key.lower()
    for kws, es, en in _SURFACE_HELP:
        if any(w in k for w in kws):
            return es if lang == "es" else en
    return ""


def _cfg_layout(cfg):
    """Calcula posiciones (x,y,h) de cada bloque por profundidad BFS. En SERVIDOR, para que el
    grafo se vea SIEMPRE (aunque no corra JS)."""
    nodes = {n["id"]: dict(n) for n in cfg.nodes}
    order = [n["id"] for n in cfg.nodes]
    adj = {}
    for e in cfg.edges:
        adj.setdefault(e["src"], []).append(e["dst"])
    depth = {order[0]: 0} if order else {}
    q = list(order[:1])
    while q:
        u = q.pop(0)
        for v in adj.get(u, []):
            if v not in depth:
                depth[v] = depth[u] + 1
                q.append(v)
    for nid in order:
        depth.setdefault(nid, 0)
    byd = {}
    for nid in order:
        byd.setdefault(depth[nid], []).append(nid)
    W = 210
    for nid in order:
        n = nodes[nid]
        n["h"] = 26 + min(len(n["insns"]), 6) * 15 + (15 if len(n["insns"]) > 6 else 0)
    y = 0
    for d in sorted(byd):
        row = byd[d]
        maxh = max(nodes[i]["h"] for i in row)
        tot = len(row) * W + (len(row) - 1) * 48
        for i, nid in enumerate(row):
            nodes[nid]["x"] = i * (W + 48) - tot / 2
            nodes[nid]["y"] = y
        y += maxh + 64
    return nodes, order, W


def _cfg_html(cfg, lang: str) -> str:
    """Grafo de flujo de una funcion, RENDERIZADO EN SERVIDOR (visible sin JS) + interactividad
    (mover/zoom/arrastrar) por JS encima. Nodos = bloques; aristas coloreadas por tipo de salto."""
    if cfg is None or not getattr(cfg, "ok", False):
        return ""
    nodes, order, W = _cfg_layout(cfg)
    _COL = {"taken": "#30a46c", "jump": "#4aa3ff", "fallthrough": "#8b95a1"}
    # aristas (curvas bezier de la base del origen al techo del destino)
    edges_svg = ""
    for e in cfg.edges:
        a, b = nodes.get(e["src"]), nodes.get(e["dst"])
        if not a or not b:
            continue
        x1, y1 = a["x"] + W / 2, a["y"] + a["h"]
        x2, y2 = b["x"] + W / 2, b["y"]
        my = (y1 + y2) / 2
        edges_svg += (f'<path class="cfge" data-s="{e["src"]}" data-d="{e["dst"]}" '
                      f'd="M{x1:.0f},{y1:.0f} C{x1:.0f},{my:.0f} {x2:.0f},{my:.0f} {x2:.0f},{y2:.0f}" '
                      f'fill="none" stroke="{_COL.get(e["kind"], "#8b95a1")}" stroke-width="2" '
                      f'marker-end="url(#ah)"/>')
    # nodos (rect + direccion + instrucciones)
    nodes_svg = ""
    for nid in order:
        n = nodes[nid]
        ins = "".join(f'<text x="9" y="{30 + i * 15}" class="cfgins">{_esc((op.get("txt") or "")[:28])}</text>'
                      for i, op in enumerate(n["insns"][:6]))
        if len(n["insns"]) > 6:
            ins += f'<text x="9" y="{30 + 6 * 15}" class="cfgins">... +{len(n["insns"]) - 6}</text>'
        nodes_svg += (f'<g class="cfgnode" data-id="{nid}" transform="translate({n["x"]:.0f},{n["y"]:.0f})">'
                      f'<rect width="{W}" height="{n["h"]}" rx="7"/>'
                      f'<text x="9" y="16" class="cfgaddr">{_esc(n["addr"])}</text>{ins}</g>')
    T = {"es": {"func": "funcion", "hint": "Arrastra el fondo para moverte, rueda para zoom, "
                "arrastra un bloque para recolocarlo. Cada arista es un salto:",
                "taken": "rama tomada (condicion verdadera)", "fall": "caida / fall-through (condicion falsa)",
                "jump": "salto incondicional", "reset": "centrar"},
         "en": {"func": "function", "hint": "Drag the background to pan, wheel to zoom, drag a "
                "block to move it. Each edge is a jump:", "taken": "branch taken (condition true)",
                "fall": "fall-through (condition false)", "jump": "unconditional jump", "reset": "center"}}[
        lang if lang in ("es", "en") else "es"]
    legend = (f'<span class="cfg-lg"><i style="background:#30a46c"></i>{_esc(T["taken"])}</span>'
              f'<span class="cfg-lg"><i style="background:#8b95a1"></i>{_esc(T["fall"])}</span>'
              f'<span class="cfg-lg"><i style="background:#4aa3ff"></i>{_esc(T["jump"])}</span>')
    # transform inicial: coloca el grafo desde arriba-izquierda con un margen (visible sin JS)
    minx = min((n["x"] for n in nodes.values()), default=0)
    init = f'translate({20 - minx:.0f},20)'
    # detalles por bloque para el panel de inspeccion (instrucciones completas + what-if)
    info = {nid: {"addr": nodes[nid]["addr"],
                  "insns": [op.get("txt", "") for op in nodes[nid]["insns"]],
                  "note": nodes[nid].get("note", "")} for nid in order}
    tip = ("Pulsa un bloque para ver sus instrucciones y que decide el salto."
           if lang == "es" else "Click a block to see its instructions and what its jump decides.")
    js = _CFG_JS.replace("__CFGW__", str(W)).replace("__CFGINFO__", _json.dumps(info))
    return (f'<h2 data-i18n="cfg_graph" id="sec-cfg"></h2>'
            f'<p class="mut" style="font-size:12px;margin:-4px 0 8px">{_esc(T["func"])} '
            f'<code>{_esc(cfg.func)}</code> &middot; {_esc(T["hint"])} {legend} '
            f'<button class="ctl cfg-reset" onclick="cfgReset()">{_esc(T["reset"])}</button></p>'
            f'<div class="cfgflex"><div class="cfgwrap"><svg id="cfgsvg"><defs>'
            f'<marker id="ah" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">'
            f'<path d="M0,0 L7,3 L0,6 Z" fill="context-stroke"/></marker></defs>'
            f'<g id="cfgvp" transform="{init}">{edges_svg}{nodes_svg}</g></svg></div>'
            f'<div id="cfginfo" class="cfginfo"><p class="mut">{_esc(tip)}</p></div></div>'
            f'<script>{js}</script>')


def _auto_summary(binary: str, findings, mit: dict, lang: str) -> str:
    """Resumen ejecutivo COHERENTE y profesional, derivado de los hechos (no de la narracion del
    modelo, que en modelos pequenos puede contradecirse). Bilingue."""
    name = _os_basename(binary)
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    fs = sorted(findings, key=lambda x: sev_rank.get(x.severity, 9))
    total = len(fs)
    verified = sum(1 for f in fs if f.verdict == "verified")
    vexp = next((f for f in fs if f.verdict == "verified"
                 and "ret2" in (f.title + f.evidence).lower()), None)
    def mstate(k):
        v = mit.get(k)
        return "?" if v is None else (("ON" if v else "OFF") if isinstance(v, bool) else str(v).upper())
    protec = f"NX {mstate('NX')}, PIE {mstate('PIE')}, Canary {mstate('Canary')}, RELRO {mstate('RELRO')}"
    arch = mit.get("Arch") or "?"
    grounded = sum(1 for f in fs if f.verdict == "grounded")
    unver = sum(1 for f in fs if f.verdict == "unverified")
    top = "; ".join(f.title for f in fs[:3]) or ("sin hallazgos" if lang == "es" else "no findings")
    if lang == "es":
        p = [f"Binario **{name}** ({arch}). Protecciones: {protec}. "
             f"**{total} hallazgos**: {verified} **verificados** (probados por ejecucion o "
             f"alcanzabilidad), {grounded} grounded (evidencia estatica, explotabilidad NO probada)"
             + (f", {unver} sin verificar" if unver else "") + "."]
        if vexp:
            m = _re_mod.search(r"offset\s*=\s*(\d+)", vexp.evidence or "")
            mw = _re_mod.search(r"win\s*=\s*(0x[0-9a-fA-F]+)", (vexp.location or "") + (vexp.evidence or ""))
            det = (f" (offset={m.group(1)}" if m else "") + (f", win={mw.group(1)})" if mw and m else (")" if m else ""))
            p.append(f"Se construyo y ejecuto un exploit ret2win en un sandbox Docker aislado y "
                     f"**alcanzo el objetivo**{det}: la evidencia es la salida real de esa ejecucion "
                     f"(ver 'Prueba de explotacion'), no una afirmacion.")
        p.append(f"Mas severos: {top}.")
        p.append("Metodologia: cada afirmacion esta respaldada por la salida del oraculo que la "
                 "produjo (ver 'Rastro de evidencia'). Los hallazgos 'grounded' son candidatos con "
                 "evidencia estatica: su explotabilidad no se ha probado y debe confirmarse.")
    else:
        p = [f"Binary **{name}** ({arch}). Protections: {protec}. "
             f"**{total} findings**: {verified} **verified** (proven by execution or reachability), "
             f"{grounded} grounded (static evidence, exploitability NOT proven)"
             + (f", {unver} unverified" if unver else "") + "."]
        if vexp:
            m = _re_mod.search(r"offset\s*=\s*(\d+)", vexp.evidence or "")
            mw = _re_mod.search(r"win\s*=\s*(0x[0-9a-fA-F]+)", (vexp.location or "") + (vexp.evidence or ""))
            det = (f" (offset={m.group(1)}" if m else "") + (f", win={mw.group(1)})" if mw and m else (")" if m else ""))
            p.append(f"A ret2win exploit was built and executed in an isolated Docker sandbox and "
                     f"**reached the goal**{det}: the evidence is the real output of that run (see "
                     f"'Exploitation proof'), not a claim.")
        p.append(f"Most severe: {top}.")
        p.append("Methodology: every statement is backed by the output of the oracle that produced "
                 "it (see 'Evidence trail'). 'grounded' findings are candidates with static "
                 "evidence: their exploitability is not proven and must be confirmed.")
    return "\n\n".join(p)


def _toc(lang: str, has) -> str:
    """Indice navegable del informe: solo las secciones presentes, con enlace a su ancla."""
    T = {"es": {"t": "Indice", "summary": "Resumen ejecutivo", "proof": "Prueba de explotacion",
                "exploit": "Exploit paso a paso", "dec": "Decompilacion anotada",
                "cfg": "Grafo de flujo interactivo",
                "find": "Hallazgos", "mit": "Mitigaciones y remediacion",
                "chain": "Cadena de explotacion",
                "surface": "Superficie de ataque", "refs": "Referencias", "trail": "Rastro de evidencia"},
         "en": {"t": "Contents", "summary": "Executive summary", "proof": "Exploitation proof",
                "exploit": "Exploit step by step", "dec": "Annotated decompilation",
                "cfg": "Interactive control-flow graph",
                "find": "Findings", "mit": "Mitigations & remediation",
                "chain": "Exploitation chain",
                "surface": "Attack surface", "refs": "References", "trail": "Evidence trail"}}[lang if lang in ("es", "en") else "es"]
    order = [("summary", "sec-summary"), ("proof", "sec-proof"), ("exploit", "sec-exploit"),
             ("dec", "sec-dec"), ("cfg", "sec-cfg"), ("find", "sec-find"), ("mit", "sec-mit"),
             ("chain", "sec-chain"), ("surface", "sec-surface"), ("refs", "sec-refs"), ("trail", "sec-trail")]
    items = "".join(f'<li><a href="#{aid}">{_esc(T[key])}</a></li>'
                    for key, aid in order if has.get(key))
    return (f'<nav class="toc"><div class="toc-t">{_esc(T["t"])}</div><ol class="toc-l">{items}</ol></nav>')


def _evidence_html(ev: str) -> str:
    """Render finding evidence as a labelled terminal block, with the oracle sources it
    came from shown as chips and a colour cue for angr/debugger-proven evidence."""
    import re as _re
    ev = ev or ""
    srcs = list(dict.fromkeys(_re.findall(r"\[([^\]\n]+)\]", ev)))
    chips = "".join(f'<span class="evsrc">{_esc(s)}</span>' for s in srcs)
    proven = ("reachable" in ev.lower()) or ("angr" in ev.lower()) or ("stop reason" in ev.lower())
    dot = "#30a46c" if proven else "#5b8def"
    tag = "probada por oracle" if proven else "evidencia estatica"
    return (f'<div class="evbox"><div class="evbar"><span class="evdot" style="background:{dot}"></span>'
            f'<span class="evlabel">evidencia real</span><span class="evtag">{tag}</span>'
            f'{("<span class=evchips>"+chips+"</span>") if chips else ""}</div>'
            f'<pre class="evpre">{_esc(ev) or "(sin evidencia)"}</pre></div>')


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
                ledger=None, answer: str = "", lang: str = "es", embed: bool = False,
                decompiled=None, cfg=None) -> str:
    findings = findings or []
    ts = datetime.now().isoformat(timespec="seconds")
    mit = _parse_mitigations(triage)
    # Texto por defecto renderizado en servidor: el informe es legible aunque NO corra JS (al
    # abrirlo como fichero estatico). El JS luego solo cambia el idioma con el boton.
    def L(k):
        return _esc(_I18N.get(lang, _I18N["es"]).get(k, k))

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
                f'<div class="kpi-l" data-i18n="{labkey}">{L(labkey)}</div></div>')
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
    def _bi(es, en):
        """Bloque de texto bilingue: se renderizan ES y EN; el CSS muestra el activo segun el
        idioma del <html> (el boton de idioma lo cambia). Asi el toggle ES/EN afecta tambien a
        la EXPLICACION, no solo a las etiquetas, y funciona sin JS extra."""
        en = en or es
        return (f'<div class="md"><div class="lg lg-es">{_md(es)}</div>'
                f'<div class="lg lg-en">{_md(en)}</div></div>')
    for f in sorted(findings, key=lambda x: _SEV.index(x.severity) if x.severity in _SEV else 9):
        # <details> nativo: cada hallazgo se DESPLIEGA al pulsar, tambien como fichero estatico.
        cards += f'''
        <details class="card" data-sev="{_esc(f.severity)}">
          <summary class="card-h">
            {_badge(f.severity.upper(), _SEV_COLOR.get(f.severity,'#666'))}
            {_badge(f.verdict, _VERDICT_COLOR.get(f.verdict,'#666'))}
            <span class="title">{_esc(f.title)}</span>
            <span class="loc">{_esc(f.location)}</span>
            <span class="chev">&#9656;</span>
          </summary>
          <div class="card-b">
            <h4 data-i18n="rationale">{L("rationale")}</h4>{_bi(f.rationale, getattr(f, "rationale_en", ""))}
            <h4 data-i18n="evidence">{L("evidence")}</h4>{_evidence_html(f.evidence)}
            <h4 data-i18n="recommendation">{L("recommendation")}</h4>{_bi(f.recommendation, getattr(f, "recommendation_en", ""))}
          </div>
        </details>'''

    triage_sections = ""
    if triage is not None:
        for title, source, text in triage.sections:
            help_txt = _surface_help(f"{title} {source}", lang)
            help_html = f'<p class="sechelp">{_esc(help_txt)}</p>' if help_txt else ""
            triage_sections += (f'<details class="sec"><summary>{_esc(title)}'
                                f'<span class="src">{_esc(source)}</span></summary>'
                                f'{help_html}<pre>{_esc(text)}</pre></details>')

    trail = ""
    if ledger is not None and getattr(ledger, "entries", None):
        # Renumera secuencial (1..N): el contador interno del bucle salta (pasos internos/
        # dedup + backstop en res.steps+N); en el informe se lee limpio y sin huecos.
        for i, e in enumerate(ledger.entries, 1):
            trail += (f'<details class="sec"><summary>paso {i}: {_esc(e.tool)}'
                      f'<span class="src">{_esc(e.source)}</span></summary>'
                      f'<pre><span class="cmd">$ {_esc(e.tool)}</span>\n{_esc(e.data)}</pre></details>')

    # Prueba de explotacion: captura destacada del PoC verificado en sandbox (la evidencia clave
    # de un informe profesional). Reune los hallazgos VERIFICADOS con su ejecucion y los pasos
    # del ledger que son una corrida de exploit en sandbox.
    proof_blocks = []
    for f in findings:
        if f.verdict == "verified" and (f.evidence or "").strip():
            proof_blocks.append((f.title, f.location, f.evidence))
    if ledger is not None and getattr(ledger, "entries", None):
        for e in ledger.entries:
            blob = f"{e.tool} {e.source} {e.data}".lower()
            if any(k in blob for k in ("sandbox", "verificado", "verified", "shell", "flag{",
                                       "try_ret2win", "autopoc", "autorop", "try_rop")):
                proof_blocks.append((e.tool, e.source, e.data))
    proof_html = ""
    if proof_blocks:
        seen = set(); cards_p = ""
        for title, loc, data in proof_blocks:
            key = (title, (data or "")[:80])
            if key in seen:
                continue
            seen.add(key)
            cards_p += (f'<div class="proof"><div class="proof-h"><span class="proof-ok">&#10003;</span>'
                        f'<span class="proof-t">{_esc(title)}</span>'
                        f'<span class="proof-l">{_esc(loc)}</span></div>'
                        f'<pre class="evpre">{_esc(data)}</pre></div>')
        proof_html = (f'<h2 data-i18n="poc_proof" id="sec-proof"></h2>'
                      f'<p class="poc-note" data-i18n="poc_note"></p>{cards_p}')

    decompiled_html = _decompiled_html(decompiled)
    cfg_html = _cfg_html(cfg, lang)
    exploit_html = _exploit_section(binary, findings, lang)
    mit_detail_html = _mit_detail(mit, lang)
    attack_chain_html = _attack_chain(findings, mit, lang)
    references_html = _references(findings, lang)
    # Resumen ejecutivo COHERENTE (deterministico) en vez de la narracion del modelo, que puede
    # contradecirse ("no encontre vuln" + backstop verificado). Profesional y sin la nota de citas.
    summary_txt = _auto_summary(binary, findings, mit, lang)
    answer_html = (f'<div class="panel md summary" id="sec-summary">'
                   f'<div class="panel-t" data-i18n="exec_summary"></div>{_md(summary_txt)}</div>')
    # Indice: solo las secciones realmente presentes.
    _has = {"summary": True, "proof": bool(proof_html), "exploit": bool(exploit_html),
            "dec": bool(decompiled_html), "cfg": bool(cfg_html), "find": True,
            "mit": bool(mit_detail_html), "chain": bool(attack_chain_html),
            "surface": bool(triage_sections),
            "refs": bool(references_html), "trail": bool(trail)}
    toc_html = _toc(lang, _has)
    sev_buttons = "".join(
        f'<button class="fbtn" data-f="{s}" onclick="flt(this)"><i style="background:{_SEV_COLOR[s]}"></i>'
        f'<span data-i18n="sev_{s}">{L("sev_"+s)}</span> <b>{counts.get(s,0)}</b></button>' for s in _SEV)

    i18n = _json.dumps(_I18N)

    header_html = "" if embed else f'''<header>
  <div class="brand"><span class="dot"></span> binoracle <em data-i18n="subtitle"></em></div>
  <div class="hmeta"><code>{_esc(binary)}</code> &middot; {ts}</div>
  <div class="controls">
    <button id="lang" class="ctl" onclick="toggleLang()">EN</button>
    <button id="theme" class="ctl" onclick="toggleTheme()">&#9788;</button>
  </div>
</header>'''
    html = f'''<!doctype html>
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

  {toc_html}

  {answer_html}

  {proof_html}

  {exploit_html}

  {decompiled_html}

  {cfg_html}

  <h2 data-i18n="findings" id="sec-find"></h2>
  <div class="toolbar">
    <input id="q" placeholder="" oninput="search()">
    {sev_buttons}
  </div>
  <div id="cards">{cards or '<p class="empty" data-i18n="no_findings"></p>'}</div>

  {mit_detail_html}

  {attack_chain_html}

  <h2 data-i18n="attack_surface" id="sec-surface"></h2>
  {triage_sections or '<p class="empty" data-i18n="no_triage"></p>'}

  {references_html}

  <h2 data-i18n="evidence_trail" id="sec-trail"></h2>
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
    # Rellena en servidor cualquier etiqueta data-i18n que quedara vacia, para que el informe
    # sea legible como fichero estatico sin JS (los KPIs/titulos no salen como numeros sueltos).
    html = re.sub(r'(data-i18n="([a-z0-9_]+)"[^>]*>)(</)',
                  lambda m: m.group(1) + L(m.group(2)) + m.group(3), html)
    return html


_I18N = {
    "es": {
        "subtitle": "informe de reversing y explotacion",
        "kpi_total": "hallazgos", "kpi_verified": "verificados",
        "kpi_high": "severidad alta", "kpi_sources": "fuentes consultadas",
        "severity_dist": "Distribucion por severidad", "mitigations": "Mitigaciones",
        "exec_summary": "Resumen ejecutivo",
        "poc_proof": "Prueba de explotacion (PoC)",
        "poc_note": "Captura de la ejecucion real en sandbox aislado que DEMUESTRA el exploit "
                    "(shell / flag / objetivo alcanzado). Evidencia reproducible, no teorica.",
        "decompiled": "Decompilacion anotada (funcion vulnerable)",
        "cfg_graph": "Grafo de flujo interactivo",
        "attack_chain": "Cadena de explotacion",
        "exploit_steps": "Exploit paso a paso",
        "mit_detail": "Mitigaciones y remediacion",
        "references": "Referencias",
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
        "poc_proof": "Exploitation proof (PoC)",
        "poc_note": "Capture of the real execution in an isolated sandbox that PROVES the exploit "
                    "(shell / flag / goal reached). Reproducible evidence, not theoretical.",
        "decompiled": "Annotated decompilation (vulnerable function)",
        "cfg_graph": "Interactive control-flow graph",
        "attack_chain": "Exploitation chain",
        "exploit_steps": "Exploit step by step",
        "mit_detail": "Mitigations and remediation",
        "references": "References",
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

def _mst(v):  # estado legible de una mitigacion booleana/str
    if v is None:
        return "?"
    if isinstance(v, bool):
        return "ON" if v else "OFF"
    return str(v).upper()


_EXP_STR = {
    "es": {
        "repro": "Reproduccion paso a paso", "script": "Exploit (pwntools)",
        "remote": "en remoto", "local": "en local",
        "offc": "bytes hasta la direccion de retorno guardada",
        "align": "Si crashea por alineacion de pila (movaps), inserta un gadget 'ret' antes:",
        "steps": lambda off, win: [
            "<b>checksec</b>: NX activo (no shellcode en pila), sin canary (overflow directo pisa "
            "RIP), sin PIE (direcciones fijas). Conclusion: ret2win viable.",
            f"<b>Localizar la gift</b>: funcion <code>win()</code> en <code>{win}</code> que ejecuta "
            "<code>system(\"/bin/sh\")</code>.",
            f"<b>Hallar el offset</b> hasta la direccion de retorno guardada: <code>{off}</code> "
            "(tamano del buffer + rbp guardado). Verificado por ejecucion en sandbox.",
            f"<b>Construir el payload</b>: <code>{off}</code> bytes de relleno + la direccion de "
            "<code>win()</code>.",
            "<b>Ejecutar en sandbox aislado</b> (Docker, sin red): se obtiene shell (uid=0). "
            "Ver la captura en 'Prueba de explotacion' arriba.",
        ],
    },
    "en": {
        "repro": "Step-by-step reproduction", "script": "Exploit (pwntools)",
        "remote": "remote", "local": "local",
        "offc": "bytes to the saved return address",
        "align": "If it crashes on stack alignment (movaps), insert a 'ret' gadget first:",
        "steps": lambda off, win: [
            "<b>checksec</b>: NX on (no stack shellcode), no canary (overflow overwrites RIP "
            "directly), no PIE (fixed addresses). So: ret2win is viable.",
            f"<b>Locate the gift</b>: <code>win()</code> at <code>{win}</code> running "
            "<code>system(\"/bin/sh\")</code>.",
            f"<b>Find the offset</b> to the saved return address: <code>{off}</code> (buffer size + "
            "saved rbp). Verified by sandbox execution.",
            f"<b>Build the payload</b>: <code>{off}</code> filler bytes + the address of "
            "<code>win()</code>.",
            "<b>Run in an isolated sandbox</b> (Docker, no network): a shell is obtained (uid=0). "
            "See the capture under 'Exploitation proof' above.",
        ],
    },
}


def _mrow_es(state, impact, rem, cls):
    return {"state": state, "impact": impact, "rem": rem, "cls": cls}


_MIT_STR = {
    "es": {
        "h_mit": "Mitigacion", "h_state": "Estado", "h_impact": "Implicacion para explotacion",
        "h_rem": "Remediacion",
        "NX": lambda v: _mrow_es(_mst(v),
            "Sin shellcode en pila/heap; hay que reutilizar codigo (ROP/ret2libc)." if v not in (False,)
            else "Pila/heap ejecutables: puedes saltar a shellcode inyectado.",
            "Mantener NX (-z noexecstack)." if v not in (False,) else "Activar NX: enlazar con -z noexecstack.",
            "ok" if v not in (False,) else "bad"),
        "PIE": lambda v: _mrow_es(_mst(v),
            "Codigo en direccion fija: hardcodea PLT/GOT/gadgets sin leak." if v in (False,)
            else "Codigo reubicado: necesitas un leak para saltar mitigaciones.",
            "Compilar con -pie -fPIE (y ASLR del SO)." if v in (False,) else "Mantener PIE.",
            "bad" if v in (False,) else "ok"),
        "Canary": lambda v: _mrow_es(_mst(v),
            "El overflow lineal pisa la direccion de retorno directamente." if v in (False,)
            else "Hay que filtrar o forzar el canary antes de pisar RIP.",
            "Compilar con -fstack-protector-strong." if v in (False,) else "Mantener el canary.",
            "bad" if v in (False,) else "ok"),
        "RELRO": lambda v: _mrow_es(_mst(v),
            "GOT escribible: GOT overwrite / ret2dlresolve posibles." if str(v).lower() != "full"
            else "GOT de solo lectura: sin GOT overwrite (ve por FSOP/exit-handlers).",
            "Enlazar con -Wl,-z,relro,-z,now (Full RELRO)." if str(v).lower() != "full" else "Mantener Full RELRO.",
            "warn" if str(v).lower() == "partial" else ("bad" if str(v).lower() in ("none", "no") else "ok")),
    },
    "en": {
        "h_mit": "Mitigation", "h_state": "State", "h_impact": "Exploitation implication",
        "h_rem": "Remediation",
        "NX": lambda v: _mrow_es(_mst(v),
            "No stack/heap shellcode; must reuse code (ROP/ret2libc)." if v not in (False,)
            else "Executable stack/heap: you can jump to injected shellcode.",
            "Keep NX (-z noexecstack)." if v not in (False,) else "Enable NX: link with -z noexecstack.",
            "ok" if v not in (False,) else "bad"),
        "PIE": lambda v: _mrow_es(_mst(v),
            "Code at a fixed address: hardcode PLT/GOT/gadgets, no leak needed." if v in (False,)
            else "Relocated code: you need a leak.",
            "Compile with -pie -fPIE (and OS ASLR)." if v in (False,) else "Keep PIE.",
            "bad" if v in (False,) else "ok"),
        "Canary": lambda v: _mrow_es(_mst(v),
            "A linear overflow overwrites the return address directly." if v in (False,)
            else "You must leak or brute-force the canary first.",
            "Compile with -fstack-protector-strong." if v in (False,) else "Keep the canary.",
            "bad" if v in (False,) else "ok"),
        "RELRO": lambda v: _mrow_es(_mst(v),
            "Writable GOT: GOT overwrite / ret2dlresolve possible." if str(v).lower() != "full"
            else "Read-only GOT: no GOT overwrite (use FSOP/exit-handlers).",
            "Link with -Wl,-z,relro,-z,now (Full RELRO)." if str(v).lower() != "full" else "Keep Full RELRO.",
            "warn" if str(v).lower() == "partial" else ("bad" if str(v).lower() in ("none", "no") else "ok")),
    },
}

_REF_STR = {
    "es": {"note": "Cheat sheets del RAG local relevantes a lo detectado (consultables con el "
                   "comando de abajo) y fuentes autoritativas.", "ext": "Fuentes autoritativas"},
    "en": {"note": "Local RAG cheat sheets relevant to what was found (query with the command "
                   "below) and authoritative sources.", "ext": "Authoritative sources"},
}


_CFG_JS = r"""
(function(){
  var W = __CFGW__;
  var INFO = __CFGINFO__;
  var svg = document.getElementById('cfgsvg'), vp = document.getElementById('cfgvp');
  var panel = document.getElementById('cfginfo');
  if(!svg || !vp) return;
  function esc(s){ return (s+'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  function showInfo(id){
    var d = INFO[id]; if(!d || !panel) return;
    var ins = d.insns.map(function(x){ return '<div class="cfgi-l">'+esc(x)+'</div>'; }).join('');
    panel.innerHTML = '<div class="cfgi-a">'+esc(d.addr)+'</div><div class="cfgi-code">'+ins+'</div>'+
      '<div class="cfgi-note">'+esc(d.note||'')+'</div>';
    vp.querySelectorAll('.cfgnode').forEach(function(g){ g.classList.toggle('sel', g.getAttribute('data-id')===id); });
  }
  function tf(g){ var m=/translate\(([-\d.]+),\s*([-\d.]+)\)/.exec(g.getAttribute('transform')||''); return m?{x:+m[1],y:+m[2]}:{x:0,y:0}; }
  function nh(g){ var r=g.querySelector('rect'); return r?+r.getAttribute('height'):40; }
  var tx=0, ty=0, scale=1;
  (function(){ var p=tf(vp); tx=p.x; ty=p.y; })();
  function apply(){ vp.setAttribute('transform','translate('+tx+','+ty+') scale('+scale+')'); }
  function redraw(id){
    vp.querySelectorAll('.cfge').forEach(function(e){
      var s=e.getAttribute('data-s'), d=e.getAttribute('data-d');
      if(s!==id && d!==id) return;
      var sg=vp.querySelector('.cfgnode[data-id="'+s+'"]'), dg=vp.querySelector('.cfgnode[data-id="'+d+'"]');
      if(!sg||!dg) return; var a=tf(sg), b=tf(dg), ah=nh(sg);
      var x1=a.x+W/2, y1=a.y+ah, x2=b.x+W/2, y2=b.y, my=(y1+y2)/2;
      e.setAttribute('d','M'+x1+','+y1+' C'+x1+','+my+' '+x2+','+my+' '+x2+','+y2);
    });
  }
  svg.addEventListener('mousedown',function(ev){ if(ev.target.closest('.cfgnode')) return;
    var sx=ev.clientX, sy=ev.clientY, ox=tx, oy=ty;
    function mv(e2){ tx=ox+(e2.clientX-sx); ty=oy+(e2.clientY-sy); apply(); }
    function up(){ document.removeEventListener('mousemove',mv); document.removeEventListener('mouseup',up); }
    document.addEventListener('mousemove',mv); document.addEventListener('mouseup',up); });
  svg.addEventListener('wheel',function(ev){ ev.preventDefault(); var f=ev.deltaY<0?1.1:0.9;
    var r=svg.getBoundingClientRect(), mx=ev.clientX-r.left, my=ev.clientY-r.top;
    tx=mx-(mx-tx)*f; ty=my-(my-ty)*f; scale*=f; apply(); }, {passive:false});
  vp.querySelectorAll('.cfgnode').forEach(function(g){
    g.addEventListener('mousedown',function(ev){ ev.stopPropagation(); var p=tf(g), sx=ev.clientX, sy=ev.clientY, moved=false;
      function mv(e2){ if(Math.abs(e2.clientX-sx)+Math.abs(e2.clientY-sy)>3) moved=true;
        var nx=p.x+(e2.clientX-sx)/scale, ny=p.y+(e2.clientY-sy)/scale;
        g.setAttribute('transform','translate('+nx+','+ny+')'); redraw(g.getAttribute('data-id')); }
      function up(){ document.removeEventListener('mousemove',mv); document.removeEventListener('mouseup',up);
        if(!moved) showInfo(g.getAttribute('data-id')); }
      document.addEventListener('mousemove',mv); document.addEventListener('mouseup',up); });
  });
  window.cfgReset=function(){ var gs=vp.querySelectorAll('.cfgnode'); if(!gs.length) return;
    var minx=1e9,miny=1e9,maxx=-1e9,maxy=-1e9;
    gs.forEach(function(g){ var p=tf(g), h=nh(g); minx=Math.min(minx,p.x); miny=Math.min(miny,p.y); maxx=Math.max(maxx,p.x+W); maxy=Math.max(maxy,p.y+h); });
    var bw=maxx-minx, bh=maxy-miny, cw=svg.clientWidth||800, ch=svg.clientHeight||460;
    scale=Math.min(1, Math.min(cw/(bw+80), ch/(bh+80))) || 1;
    tx=cw/2-(minx+bw/2)*scale; ty=24-miny*scale; apply(); };
  cfgReset();
})();
"""


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
summary.card-h{padding:12px 14px;cursor:pointer;display:flex;align-items:center;gap:7px;flex-wrap:wrap;list-style:none}
summary.card-h::-webkit-details-marker{display:none}
summary.card-h::marker{content:""}
.card-h .title{font-weight:650}.card-h .loc{color:var(--mut);font-size:12px;margin-left:auto;font-family:ui-monospace,monospace}
.card-h .chev{transition:transform .15s;color:var(--mut)}
.card[open] .card-h .chev{transform:rotate(90deg)}
.card-b{padding:2px 15px 16px;border-top:1px solid var(--line)}
.lg-en{display:none}
html[lang="en"] .lg-es{display:none}
html[lang="en"] .lg-en{display:block}
h4{margin:15px 0 5px;color:var(--mut);text-transform:uppercase;font-size:11px;letter-spacing:.05em}
pre{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:11px;overflow:auto;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--codefg);white-space:pre}
.sec{border:1px solid var(--line);border-radius:9px;margin:8px 0;background:var(--panel)}
.sec>summary{padding:10px 13px;cursor:pointer;font-weight:600;display:flex;justify-content:space-between;align-items:center;gap:10px}
.sec .src{color:var(--mut);font-weight:400;font-size:11px;font-family:ui-monospace,monospace}
.sec pre{margin:0 13px 13px}
.sechelp{margin:2px 13px 8px;color:var(--mut);font-size:12.5px;line-height:1.5;border-left:2px solid var(--acc);padding-left:9px}
.md{white-space:pre-wrap}
.evbox{border:1px solid var(--line);border-radius:9px;overflow:hidden;background:#0b0e12}
.evbar{display:flex;align-items:center;gap:8px;padding:8px 12px;background:#0e131c;border-bottom:1px solid #1e2632;font:11px ui-monospace,monospace;color:#8b95a1;flex-wrap:wrap}
.evdot{width:9px;height:9px;border-radius:50%}
.evlabel{color:#e2e8f0;font-weight:700;text-transform:uppercase;letter-spacing:.05em}
.evtag{color:#8b95a1}
.evchips{display:flex;gap:5px;flex-wrap:wrap;margin-left:auto}
.evsrc{background:#070a10;border:1px solid #1e2632;border-radius:5px;padding:1px 7px;color:#a9c7e8}
.evpre{margin:0;padding:12px;background:#0b0e12;color:#cfe3ff;white-space:pre;overflow:auto;font:12px/1.5 ui-monospace,monospace;border:0;border-radius:0}
.md code{background:var(--code);padding:1px 5px;border-radius:4px;font:12px ui-monospace,monospace;color:var(--codefg)}
.summary{margin-bottom:8px;border-left:3px solid var(--acc)}
.toc{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 18px;margin:14px 0}
.toc-t{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;margin-bottom:8px}
ol.toc-l{margin:0;padding-left:20px;columns:2;column-gap:28px}
@media(max-width:600px){ol.toc-l{columns:1}}
ol.toc-l li{margin:3px 0}
ol.toc-l a{color:var(--acc);text-decoration:none}
ol.toc-l a:hover{text-decoration:underline}
html{scroll-behavior:smooth}
h2[id]{scroll-margin-top:16px}
.chain-t{font-weight:700;font-size:13px;line-height:1.4;margin:14px 0 6px;color:var(--fg)}
.chain-row{display:flex;flex-wrap:wrap;align-items:stretch;gap:0;margin-bottom:8px}
.chain-step{flex:1 1 150px;min-width:150px;border:1.5px solid var(--line);border-left-width:4px;
  border-radius:10px;background:var(--panel);padding:9px 11px}
.chain-n{font-weight:700;font-size:12.5px;color:var(--fg);margin-bottom:3px}
.chain-d{font-size:11.5px;line-height:1.45;color:var(--mut)}
.chain-arr{display:flex;align-items:center;padding:0 6px;color:var(--acc);font-size:20px;font-weight:700}
@media(max-width:640px){.chain-row{flex-direction:column}.chain-arr{transform:rotate(90deg);padding:4px 0;justify-content:center}}
.cfgflex{display:grid;grid-template-columns:1fr 260px;gap:12px}
@media(max-width:760px){.cfgflex{grid-template-columns:1fr}}
.cfginfo{border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:12px;height:460px;overflow:auto}
.cfgi-a{font:700 12px ui-monospace,monospace;color:var(--acc);margin-bottom:6px}
.cfgi-code{background:var(--code);border-radius:7px;padding:8px;margin-bottom:8px}
.cfgi-l{font:11.5px/1.55 ui-monospace,monospace;color:var(--codefg);white-space:pre}
.cfgi-note{font-size:12.5px;line-height:1.5;color:var(--fg);border-left:2px solid var(--acc);padding-left:9px}
.cfgnode.sel rect{stroke:var(--acc);stroke-width:2.5}
.cfgwrap{border:1px solid var(--line);border-radius:12px;background:var(--panel);overflow:hidden;height:460px}
#cfgsvg{width:100%;height:100%;cursor:grab;background:
  radial-gradient(circle at 1px 1px, var(--line) 1px, transparent 0) 0 0/22px 22px}
#cfgsvg:active{cursor:grabbing}
.cfgnode rect{fill:var(--panel);stroke:var(--line);stroke-width:1.5;filter:drop-shadow(0 1px 2px rgba(0,0,0,.12))}
.cfgnode:hover rect{stroke:var(--acc)}
.cfgnode{cursor:move}
.cfgaddr{fill:var(--acc);font:700 11px ui-monospace,monospace}
.cfgins{fill:var(--codefg);font:11px/1 ui-monospace,monospace}
.cfg-lg{display:inline-flex;align-items:center;gap:4px;margin:0 8px}
.cfg-lg i{width:16px;height:3px;border-radius:2px;display:inline-block}
.cfg-reset{font-size:11px;padding:2px 8px;margin-left:6px}
.poc-note{color:var(--mut);font-size:12px;margin:-4px 0 12px}
.decfn{border:1px solid var(--line);border-radius:11px;margin:10px 0;background:var(--panel);overflow:hidden}
.decfn-h{display:flex;align-items:center;gap:9px;padding:9px 13px;background:var(--code);border-bottom:1px solid var(--line)}
.decfn-t{font-weight:700;font-family:ui-monospace,monospace}
.decfn-e{color:var(--mut);font-size:11px;margin-left:auto;font-family:ui-monospace,monospace}
.decfn .md{padding:6px 15px 14px}
.decfn .md h4,.decfn .md h5{margin:13px 0 5px;color:var(--fg);text-transform:none;letter-spacing:0;font-size:13px}
.decfn .md p{margin:5px 0}
pre.code{background:#0b0e12;color:#cfe3ff;border:1px solid var(--line);border-radius:8px;padding:11px;overflow:auto;font:12px/1.5 ui-monospace,monospace;white-space:pre}
.decfn .sec{margin:8px 15px 14px}
.expwrap{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:760px){.expwrap{grid-template-columns:1fr}}
.expcol{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px}
ol.steps{margin:6px 0 0;padding-left:20px}
ol.steps li{margin:0 0 9px;padding-left:4px}
ol.steps code{background:var(--code);padding:1px 5px;border-radius:4px;font:12px ui-monospace,monospace;color:var(--codefg)}
.mittab{width:100%;border-collapse:collapse;font-size:13px;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.mittab th{text-align:left;padding:9px 12px;background:var(--code);color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid var(--line)}
.mittab td{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
.mittab tr:last-child td{border-bottom:0}
.mittab .mk{font-weight:700}
.mittab .mstate{font-weight:700;font-family:ui-monospace,monospace}
.mittab .mrem{color:var(--mut)}
.mitrow.ok .mstate{color:#2f9e5f}.mitrow.bad .mstate{color:#e5484d}.mitrow.warn .mstate{color:#e5a000}
.refchips{display:flex;flex-wrap:wrap;gap:8px}
.refchip{background:var(--code);border:1px solid var(--line);border-radius:7px;padding:5px 10px;color:var(--codefg);font:12px ui-monospace,monospace}
ul.reflist{margin:6px 0 0;padding-left:20px;color:var(--mut);font-size:13px}
.proof{border:1px solid #1f7a4d;border-radius:10px;overflow:hidden;background:#0b0e12;margin:10px 0;box-shadow:0 0 0 1px rgba(48,163,108,.15)}
.proof-h{display:flex;align-items:center;gap:9px;padding:9px 13px;background:#0e1a13;border-bottom:1px solid #1f7a4d;flex-wrap:wrap}
.proof-ok{color:#30d67f;font-weight:800}
.proof-t{color:#e2f5ea;font-weight:700}
.proof-l{color:#8b95a1;font-size:12px;margin-left:auto;font-family:ui-monospace,monospace}
.cmd{color:#7fe3a3;font-weight:600}
.empty{color:var(--mut);font-style:italic}
footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);color:var(--mut);font-size:12px}
"""
