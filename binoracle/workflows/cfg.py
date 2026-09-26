"""Grafo de flujo de control (CFG) de una funcion, para el informe interactivo.

Extrae de radare2 (agfj) los bloques basicos y sus saltos, y devuelve una estructura
nodo/arista simple. Cada arista sabe QUE es: rama tomada (condicion verdadera), caida
(condicion falsa/fall-through) o salto incondicional. El informe la pinta como un grafo
interactivo (mover/zoom) con la explicacion de cada salto.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import List


@dataclass
class CFG:
    func: str = ""
    nodes: List[dict] = field(default_factory=list)   # {id, addr, insns:[{addr,txt}], term, note}
    edges: List[dict] = field(default_factory=list)   # {src, dst, kind: taken|fallthrough|jump}

    @property
    def ok(self) -> bool:
        return len(self.nodes) > 0


# jcc -> condicion en lenguaje claro (que se cumple para tomar el salto)
_JCC = {
    "je": "son iguales", "jz": "el resultado es cero", "jne": "son distintos",
    "jnz": "el resultado NO es cero", "jg": "es mayor (con signo)", "jge": "es mayor o igual (con signo)",
    "jl": "es menor (con signo)", "jle": "es menor o igual (con signo)", "ja": "es mayor (sin signo)",
    "jae": "es mayor o igual (sin signo)", "jb": "es menor (sin signo)", "jbe": "es menor o igual (sin signo)",
    "js": "es negativo", "jns": "no es negativo", "jo": "hubo overflow", "jno": "no hubo overflow",
    "jc": "hubo acarreo (carry)", "jnc": "no hubo acarreo",
}


# comparaciones que actuan de PUERTA de decision (password/flag/token/longitud)
_CMP_GATES = ("strcmp", "strncmp", "memcmp", "strcasecmp", "strncasecmp", "strstr")
# sinks peligrosos que, si el bloque los llama, marcan por donde entra o se usa la entrada
_DANGER = ("gets", "read", "fgets", "scanf", "strcpy", "strcat", "sprintf", "memcpy", "recv",
           "system", "popen", "execve", "execl", "printf")
import re as _re


def _call_target(txt: str):
    """Nombre de la funcion llamada en una instruccion `call` (sym.imp.X / X), o None."""
    m = _re.search(r"call\s+(?:0x[0-9a-f]+\s+)?(?:sym\.(?:imp\.)?)?([A-Za-z_][\w.]*)", txt or "")
    return m.group(1) if m else None


def _interpret_cmp(cmp_txt: str) -> str:
    """Explica en lenguaje claro que compara un cmp/test (operandos, constante, chequeo de cero)."""
    parts = cmp_txt.split(None, 1)
    if len(parts) < 2:
        return ""
    mn = parts[0].lower()
    ops = [x.strip() for x in parts[1].split(",")]
    if len(ops) != 2:
        return ""
    a, b = ops
    if mn == "test" and a == b:
        return f" (comprueba si `{a}` es CERO: chequeo de puntero NULL, error o resultado de una funcion)"
    if _re.fullmatch(r"0x[0-9a-fA-F]+|-?\d+", b):
        return (f" (compara `{a}` con la constante `{b}`: posible valor magico, una longitud/tamano, "
                "o un codigo de estado)")
    return f" (compara `{a}` con `{b}`)"


# normalizacion de registros x86-64 a su forma de 64 bits (para el estado por bloque)
_R64 = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
_SUB = {
    "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax", "ebx": "rbx", "bx": "rbx", "bl": "rbx",
    "ecx": "rcx", "cx": "rcx", "cl": "rcx", "edx": "rdx", "dx": "rdx", "dl": "rdx",
    "esi": "rsi", "si": "rsi", "sil": "rsi", "edi": "rdi", "di": "rdi", "dil": "rdi",
    "ebp": "rbp", "bp": "rbp", "esp": "rsp", "sp": "rsp",
}
for _i in range(8, 16):
    _SUB[f"r{_i}d"] = f"r{_i}"; _SUB[f"r{_i}w"] = f"r{_i}"; _SUB[f"r{_i}b"] = f"r{_i}"


def _norm_reg(tok: str):
    t = (tok or "").strip().lower().strip(",")
    if t in _R64:
        return t
    return _SUB.get(t)


_WRITE_MN = ("mov", "movzx", "movsx", "movsxd", "lea", "add", "sub", "xor", "and", "or", "imul",
             "pop", "inc", "dec", "not", "neg", "shl", "shr", "sar", "sal", "cmov", "sete", "xchg")
_RMW_MN = ("add", "sub", "xor", "and", "or", "inc", "dec", "shl", "shr", "sar", "sal", "imul", "xchg")


def _block_state(insns) -> dict:
    """Estado tecnico aproximado del bloque (analisis estatico local, grounded en el disasm):
    registros escritos/leidos, variacion neta de RSP, slots de pila tocados y llamadas. No es
    dataflow completo: es una lectura por instruccion, util para entender que hace el bloque."""
    import re as _re
    regs_w, regs_r, slots, calls = set(), set(), set(), []
    delta = 0
    for op in insns:
        t = (op["txt"] or "").strip()
        if not t:
            continue
        parts = t.replace(",", " ").split()
        mn = parts[0].lower()
        ops = parts[1:]
        if mn == "push":
            delta -= 8
            r = _norm_reg(ops[0]) if ops else None
            if r:
                regs_r.add(r)
        elif mn == "pop":
            delta += 8
            r = _norm_reg(ops[0]) if ops else None
            if r:
                regs_w.add(r)
        elif mn in ("sub", "add") and len(ops) >= 2 and _norm_reg(ops[0]) == "rsp":
            try:
                n = int(ops[1], 0)
                delta += (-n if mn == "sub" else n)
            except ValueError:
                pass
        if mn.startswith("call"):
            m = _re.search(r"(sym\.(?:imp\.)?[\w.]+|0x[0-9a-f]+)", t)
            if m:
                calls.append(m.group(1))
        elif mn in _WRITE_MN and ops:
            d = _norm_reg(ops[0])
            if d and d != "rsp":
                regs_w.add(d)
                if mn in _RMW_MN:
                    regs_r.add(d)
            for o in ops[1:]:
                rr = _norm_reg(o)
                if rr:
                    regs_r.add(rr)
        elif mn in ("cmp", "test"):
            for o in ops:
                rr = _norm_reg(o)
                if rr:
                    regs_r.add(rr)
        for o in ops:
            m = _re.search(r"\[(rbp|rsp)\s*([+-]\s*0x[0-9a-f]+)?", o.lower())
            if m:
                slots.add(m.group(0).replace(" ", "") + "]")
    return {"w": sorted(regs_w), "r": sorted(regs_r), "delta": delta,
            "slots": sorted(slots)[:6], "calls": calls[:4]}


def _state_note(st: dict, lang: str = "es") -> str:
    """Resumen legible del estado tecnico del bloque."""
    if not st:
        return ""
    es = lang == "es"
    parts = []
    if st["w"]:
        parts.append(("escribe" if es else "writes") + ": " + ", ".join(r.upper() for r in st["w"]))
    if st["r"]:
        parts.append(("lee" if es else "reads") + ": " + ", ".join(r.upper() for r in st["r"]))
    if st["delta"]:
        sign = "+" if st["delta"] > 0 else ""
        parts.append(("RSP " if es else "RSP ") + f"{sign}{st['delta']} B")
    if st["slots"]:
        parts.append(("pila" if es else "stack") + ": " + ", ".join(st["slots"]))
    if st["calls"]:
        parts.append(("llama" if es else "calls") + ": " + ", ".join(st["calls"]))
    return " | ".join(parts)


def _branch_note(insns) -> str:
    """Explicacion determinista y MATIZADA (grounded en el disasm) del terminador del bloque: que
    decide, con que operandos, y su implicacion (puertas de auth, chequeos de longitud, sinks).
    Sin LLM, sin inventar."""
    if not insns:
        return ""
    last = (insns[-1]["txt"] or "").strip()
    mn = last.split()[0].lower() if last else ""
    # busca hacia atras: la comparacion (cmp/test) y la ultima llamada previa del bloque
    cmp_txt = ""
    prev_call = None
    for op in insns[:-1]:
        t = (op["txt"] or "").strip()
        m0 = t.split()[0].lower() if t else ""
        if m0 in ("cmp", "test"):
            cmp_txt = t
        elif m0.startswith("call"):
            prev_call = t
    # sinks peligrosos que este bloque invoca (por donde entra/usa la entrada)
    calls = [_call_target(op["txt"]) for op in insns if (op["txt"] or "").strip().lower().startswith("call")]
    danger = [c for c in calls if c and any(d == c or c.endswith("." + d) or d in c for d in _DANGER)]
    danger_note = ""
    if danger:
        danger_note = (f" Este bloque LLAMA a `{danger[0]}` (funcion sensible): aqui entra o se procesa "
                       "la entrada, un punto clave de la superficie de ataque.")

    if mn in _JCC:
        cond = _JCC[mn]
        ctx = _interpret_cmp(cmp_txt) if cmp_txt else ""
        gate = ""
        if prev_call:
            fn = _call_target(prev_call)
            if fn and any(g == fn or fn.endswith("." + g) or g in fn for g in _CMP_GATES):
                gate = (f" La decision depende del RESULTADO de `{fn}`: es una PUERTA de comparacion "
                        "(tipica de password / flag / token / longitud). La rama 'correcta' es la que "
                        "se toma cuando coinciden; controlar esa entrada suele ser el objetivo.")
        base = f"Comprueba `{cmp_txt}`{ctx} y " if cmp_txt else "Salto condicional: "
        return (f"{base}si {cond} toma la RAMA (verde) hacia el destino del salto; si no, CAE (gris) "
                f"al bloque siguiente.{gate}{danger_note}")
    if mn == "jmp":
        return "Salto INCONDICIONAL (azul): el flujo siempre continua en el destino." + danger_note
    if mn in ("ret", "retn", "leave"):
        return ("Fin del bloque: la funcion retorna (fin de este camino). Si aqui se puede pisar la "
                "direccion de retorno guardada, es el punto de control de RIP." + danger_note)
    if mn.startswith("call"):
        fn = _call_target(last)
        who = f" a `{fn}`" if fn else ""
        return (f"Llama{who} y despues continua en el bloque siguiente." + danger_note)
    return "El flujo cae al siguiente bloque (sin salto condicional)." + danger_note


def function_cfg(binary: str, func: str, max_blocks: int = 60) -> CFG:
    try:
        from ..oracles.r2session import get as _r2get
        r = _r2get(binary)
        if r is None:
            return CFG(func=func)
        j = json.loads(r.cmd(f"agfj @ {func}") or "[]")
    except Exception:
        return CFG(func=func)
    if not j:
        return CFG(func=func)
    g = j[0]
    cfg = CFG(func=g.get("name", func))
    ids = {}
    for b in g.get("blocks", [])[:max_blocks]:
        addr = b.get("addr", b.get("offset"))
        if addr is None:
            continue
        insns = [{"addr": hex(op.get("offset", op.get("addr", 0))),
                  "txt": op.get("disasm", op.get("opcode", ""))}
                 for op in b.get("ops", []) if op.get("disasm") or op.get("opcode")]
        term = insns[-1]["txt"] if insns else ""
        ids[addr] = f"b{len(cfg.nodes)}"
        cfg.nodes.append({"id": ids[addr], "addr": hex(addr), "insns": insns, "term": term,
                          "note": _branch_note(insns), "state": _state_note(_block_state(insns))})
    # aristas: jump = rama tomada (o salto incondicional si no hay fail); fail = fall-through
    for b in g.get("blocks", [])[:max_blocks]:
        addr = b.get("addr", b.get("offset"))
        if addr not in ids:
            continue
        jmp, fail = b.get("jump"), b.get("fail")
        if jmp in ids and fail in ids:
            cfg.edges.append({"src": ids[addr], "dst": ids[jmp], "kind": "taken"})
            cfg.edges.append({"src": ids[addr], "dst": ids[fail], "kind": "fallthrough"})
        elif jmp in ids:
            cfg.edges.append({"src": ids[addr], "dst": ids[jmp], "kind": "jump"})
        elif fail in ids:
            cfg.edges.append({"src": ids[addr], "dst": ids[fail], "kind": "fallthrough"})
    return cfg
