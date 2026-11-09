"""Stripped-binary function ID: BinDiff-style signature matching to recover names before
analysis. ROADMAP v0.4: "Stripped-binary function ID. Signature / BinDiff-style matching to
recover names in stripped targets before analysis."

radare2 is the oracle (same convention as `patchdiff.py`'s use of radiff2): it lists functions
and disassembles them; this module never invents a function body. The signature compared
between a STRIPPED target and a NAMED reference binary (same program, a different build/
optimization level, or just an earlier unstripped copy) is two-tiered:

  1. Call signature (high confidence): the ORDERED list of resolved IMPORT names (libc/libc++
     functions, syscalls -- anything radare2 can already resolve via the dynamic symbol table)
     that the function calls. This survives `strip` entirely: `strip` removes the LOCAL symbol
     table (.symtab), not the dynamic one (.dynsym) a dynamically-linked ELF needs at runtime to
     actually resolve `puts`/`system`/etc through the PLT -- so those names are there whether or
     not the binary is stripped. It is also robust across optimization levels: confirmed live
     comparing `ret2win.c` built at -O0 (unstripped, the reference) against the SAME source
     rebuilt at -O1 and stripped -- `win()`'s prologue/epilogue changed completely (gained an
     `endbr64`, lost its `push rbp`/`pop rbp` frame), but its call signature
     (`[sym.imp.puts, sym.imp.system]`) matched EXACTLY and uniquely against every other
     function in the stripped binary (which all have a different or empty call signature).

  2. Mnemonic-sequence similarity (heuristic/candidate, per this project's own "no false
     positives by construction" rule -- never reported as a sure match): a plain
     `difflib.SequenceMatcher` ratio over each function's opcode-type sequence, for the
     functions that call nothing resolvable (leaf functions, or ones that only call other
     anonymous local functions). Confirmed live that this signal ALONE is weak for short
     functions (ratios for a true match and an unrelated one differed by only ~0.05) -- it is
     only used as a fallback, and the match is labelled `similar` with its score, never
     `exact-calls`."""
from __future__ import annotations

import difflib
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional


def _r2(binary: str, cmd: str, timeout: float = 60.0) -> str:
    exe = shutil.which("r2") or shutil.which("radare2")
    if not exe:
        return ""
    try:
        return subprocess.run([exe, "-q", "-e", "scr.color=0", "-e", "log.quiet=true",
                               "-c", cmd, binary], capture_output=True, text=True,
                              timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return ""


def _r2_json(binary: str, cmd: str, timeout: float = 60.0):
    out = _r2(binary, cmd, timeout)
    for ch in ("[", "{"):
        i = out.find(ch)
        if i >= 0:
            try:
                return json.loads(out[i:])
            except Exception:
                continue
    return None


def r2_available() -> bool:
    return bool(shutil.which("r2") or shutil.which("radare2"))


def _is_anonymous(name: str) -> bool:
    return name.startswith("fcn.") or name.startswith("sym.func.") or name.startswith("loc.")


def _list_functions(binary: str) -> List[dict]:
    fns = _r2_json(binary, "aaa;aflj")
    return fns if isinstance(fns, list) else []


def _function_signature(binary: str, addr: int) -> Dict[str, List[str]]:
    d = _r2_json(binary, "aaa;pdfj @ %d" % addr)
    calls: List[str] = []
    mnemonics: List[str] = []
    if not isinstance(d, dict):
        return {"calls": calls, "mnemonics": mnemonics}
    for op in d.get("ops", []) or []:
        mnemonics.append(op.get("type") or "?")
        if op.get("type") == "call":
            disasm = op.get("disasm", "") or ""
            calls.append(disasm.split()[-1] if disasm else "?")
    return {"calls": calls, "mnemonics": mnemonics}


@dataclass
class FuncMatch:
    addr: int
    size: int
    stripped_name: str
    recovered_name: Optional[str] = None
    confidence: str = "none"      # "exact-calls" | "similar" | "none"
    score: float = 0.0


@dataclass
class FuncIdResult:
    ok: bool = False
    note: str = ""
    stripped: str = ""
    reference: str = ""
    matches: List[FuncMatch] = field(default_factory=list)

    @property
    def recovered(self) -> List[FuncMatch]:
        return [m for m in self.matches if m.recovered_name is not None]


def identify_stripped_functions(stripped_binary: str, reference_binary: str,
                                min_similarity: float = 0.6) -> FuncIdResult:
    """BinDiff-style: construye la firma de cada funcion NOMBRADA de `reference_binary`
    (mismo programa, otra build/nivel de optimizacion, o simplemente una copia sin stripear
    anterior) y la compara contra cada funcion ANONIMA (`fcn.XXXXXXXX`) de `stripped_binary`.
    Nunca toca funciones que ya tienen nombre (imports, entry0, etc) -- solo recupera lo que de
    verdad esta perdido."""
    res = FuncIdResult(stripped=stripped_binary, reference=reference_binary)
    if not r2_available():
        res.note = "radare2 no esta instalado (apt install radare2)"
        return res

    ref_fns = _list_functions(reference_binary)
    named_ref = [f for f in ref_fns
                if not _is_anonymous(f.get("name", "")) and not f.get("name", "").startswith("sym.imp.")]
    if not named_ref:
        res.note = "el binario de referencia no tiene funciones nombradas que comparar"
        return res
    ref_sigs = {f["name"]: _function_signature(reference_binary, f["offset"]) for f in named_ref}

    tgt_fns = _list_functions(stripped_binary)
    anon_tgt = [f for f in tgt_fns if _is_anonymous(f.get("name", ""))]
    if not anon_tgt:
        res.ok = True
        res.note = "el binario stripped no tiene funciones anonimas -- nada que recuperar"
        return res

    for f in anon_tgt:
        sig = _function_signature(stripped_binary, f["offset"])
        best_name, best_conf, best_score = None, "none", 0.0
        for ref_name, ref_sig in ref_sigs.items():
            if sig["calls"] and sig["calls"] == ref_sig["calls"]:
                best_name, best_conf, best_score = ref_name, "exact-calls", 1.0
                break
            if not sig["calls"]:
                ratio = difflib.SequenceMatcher(a=ref_sig["mnemonics"], b=sig["mnemonics"]).ratio()
                if ratio > best_score and ratio >= min_similarity:
                    best_name, best_conf, best_score = ref_name, "similar", ratio
        res.matches.append(FuncMatch(addr=f["offset"], size=f.get("size", 0),
                                     stripped_name=f["name"], recovered_name=best_name,
                                     confidence=best_conf, score=best_score))
    res.ok = True
    n_exact = sum(1 for m in res.matches if m.confidence == "exact-calls")
    n_sim = sum(1 for m in res.matches if m.confidence == "similar")
    res.note = (f"{len(anon_tgt)} funcion(es) anonima(s) en el stripped; {n_exact} recuperada(s) "
               f"por firma de llamadas (alta confianza), {n_sim} por similitud de mnemonics "
               f"(heuristica, sin confirmar)")
    return res


def render_funcid(r: FuncIdResult) -> str:
    out = ["## Stripped-binary function ID (BinDiff-style)\n",
          f"- stripped: `{r.stripped}`\n- referencia: `{r.reference}`\n"]
    if not r.ok:
        return "\n".join(out + ["No disponible: " + r.note])
    out.append(r.note + "\n")
    if not r.matches:
        return "\n".join(out)
    out.append("| direccion | nombre stripped | nombre recuperado | confianza | score |")
    out.append("|---|---|---|---|---|")
    for m in sorted(r.matches, key=lambda x: x.addr):
        name = m.recovered_name or "_(sin recuperar)_"
        tag = {"exact-calls": "ALTA (firma de llamadas exacta)",
              "similar": "heuristica (candidato, sin confirmar)",
              "none": "-"}[m.confidence]
        out.append(f"| {hex(m.addr)} | `{m.stripped_name}` | `{name}` | {tag} | {m.score:.2f} |")
    return "\n".join(out)
