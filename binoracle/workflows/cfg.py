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
    nodes: List[dict] = field(default_factory=list)   # {id, addr, insns:[{addr,txt}], term}
    edges: List[dict] = field(default_factory=list)   # {src, dst, kind: taken|fallthrough|jump}

    @property
    def ok(self) -> bool:
        return len(self.nodes) > 0


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
        cfg.nodes.append({"id": ids[addr], "addr": hex(addr), "insns": insns, "term": term})
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
