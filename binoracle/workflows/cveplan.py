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


def render_plan(pl: ExploitPlan, lang: str = "es") -> str:
    es = lang == "es"
    if not pl.ok:
        return ("## Plan de explotacion\n\n" + (pl.note or ""))
    out = ["## " + ("Esquema de explotacion" if es else "Exploitation schema") +
           (f" — {pl.cve}" if pl.cve else "")]
    out.append((f"- **Clase**: {pl.vuln_class}\n- **Primitiva**: {pl.primitive}" if es else
                f"- **Class**: {pl.vuln_class}\n- **Primitive**: {pl.primitive}"))
    out.append("\n### " + ("Fases" if es else "Phases"))
    for i, ph in enumerate(pl.phases, 1):
        out.append(f"{i}. **{ph.name}** — {ph.goal}\n   - " + ("como" if es else "how") + f": {ph.technique}"
                   + (f"\n   - " + ("necesita" if es else "needs") + f": {ph.needs}" if ph.needs else ""))
    if pl.mitigations:
        out.append("\n### " + ("Mitigaciones a sortear" if es else "Mitigations to bypass"))
        out += [f"- {m}" for m in pl.mitigations]
    if pl.kb_refs:
        out.append("\n" + ("Referencias del conocimiento (RAG): " if es else "Knowledge refs (RAG): ")
                   + ", ".join(pl.kb_refs))
    out.append("\n_" + ("Solo objetivos autorizados / CTF / research." if es else
                        "Authorized / CTF / research targets only.") + "_")
    return "\n".join(out)
