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


def _branch_note(insns) -> str:
    """Explicacion determinista (grounded en el disasm) del terminador del bloque: que decide y
    a donde va segun la condicion. Sin LLM, sin inventar."""
    if not insns:
        return ""
    last = (insns[-1]["txt"] or "").strip()
    mn = last.split()[0].lower() if last else ""
    # instruccion previa de comparacion (cmp/test), si la hay
    cmp_txt = ""
    for op in reversed(insns[:-1]):
        t = (op["txt"] or "").strip()
        if t.split()[0].lower() in ("cmp", "test") if t else False:
            cmp_txt = t
            break
    if mn in _JCC:
        base = f"Comprueba `{cmp_txt}` y " if cmp_txt else "Salto condicional: "
        return (f"{base}si {_JCC[mn]} toma la RAMA (verde) hacia el destino del salto; "
                f"si no, CAE (gris) al bloque siguiente.")
    if mn == "jmp":
        return "Salto INCONDICIONAL (azul): el flujo siempre continua en el destino."
    if mn in ("ret", "retn", "leave"):
        return "Fin del bloque: la funcion retorna (fin de este camino)."
    if mn.startswith("call"):
        return "Llama a otra funcion y despues continua en el bloque siguiente."
    return "El flujo cae al siguiente bloque (sin salto condicional)."


def function_cfg(binary: str, func: str, max_blocks: int = 60) -> CFG:
    try:
        import r2pipe
        r = r2pipe.open(binary, flags=["-2"])
        r.cmd("aaa")
        j = json.loads(r.cmd(f"agfj @ {func}") or "[]")
        r.quit()
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
                          "note": _branch_note(insns)})
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
