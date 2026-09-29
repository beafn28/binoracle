"""Decompilacion aumentada con LLM (estilo decai de r2ai).

Toma el desensamblado/decompilado de r2 de una funcion y hace que el modelo produzca
pseudo-C legible (con nombres de variables con sentido) MAS una explicacion paso a paso,
incluida cualquier vulnerabilidad de seguridad de memoria. Grounded: el LLM parte SOLO de lo
que r2 muestra, no inventa. Sin modelo, devuelve el decompilado crudo de r2 (sigue siendo util).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..llm.base import Message


@dataclass
class DecompiledFunc:
    func: str
    raw: str = ""            # decompilado/desensamblado crudo de r2
    engine: str = ""         # pdc | pdg | pdf
    annotated: str = ""      # pseudo-C limpio + explicacion (LLM), o "" si no hubo modelo
    notes: list = field(default_factory=list)
    variants: list = field(default_factory=list)   # [(engine, code)] de cada motor disponible
    crosscheck: str = ""     # nota deterministica de contraste entre motores (retroalimentacion)
    tech: dict = field(default_factory=dict)       # ficha tecnica grounded (firma/marco/locales)

    @property
    def ok(self) -> bool:
        return bool(self.raw.strip())


def func_technical(binary: str, func: str) -> dict:
    """Ficha tecnica GROUNDED de la funcion via r2 (afij/afvj): firma, tamano de marco, convencion,
    y variables locales con su offset a RBP, tipo y DISTANCIA a la direccion de retorno guardada
    (|offset| + tamano de palabra) -> el offset de overflow por variable. Best-effort; {} si falla."""
    try:
        import json
        from ..oracles.r2session import get as _r2get
        r = _r2get(binary)
        if r is None:
            return {}
        info = json.loads(r.cmd(f"afij @ {func}") or "[]")
        info = info[0] if info else {}
        av = json.loads(r.cmd(f"afvj @ {func}") or "{}")
    except Exception:
        return {}
    bits = info.get("bits", 64)
    word = bits // 8
    sig = (info.get("signature") or "").strip()
    if not sig:
        try:
            sig = (r.cmd(f"afcf @ {func}") or "").strip().splitlines()[0]
        except Exception:
            sig = ""
    locs = []
    for v in (av.get("bp", []) + av.get("sp", [])):
        ref = v.get("ref", {}) or {}
        off = ref.get("offset")
        base = ref.get("base", "rbp")
        to_ret = (-off + word) if (base == "rbp" and isinstance(off, int) and off < 0) else None
        locs.append({"name": v.get("name", "?"), "type": v.get("type", ""), "base": base,
                     "offset": off, "to_ret": to_ret})
    return {"signature": sig, "frame": info.get("stackframe"), "cc": info.get("calltype"),
            "bits": bits, "ninstrs": info.get("ninstrs"), "nbbs": info.get("nbbs"),
            "locals": locs, "reg_args": av.get("reg", [])}


def _best_decompile(binary: str, func: str) -> tuple[str, str]:
    """Mejor decompilacion disponible, en orden: Ghidra (servidor GhidraMCP arriba) > r2 pdg
    (r2ghidra) > decai (r2ai, LLM alternativo, si hay LLM) > r2 pdc/pdf. Grado de calidad
    decreciente; cada fuente es opcional y cae a la siguiente si no esta disponible."""
    # 1) Ghidra (deterministico, mejor)
    try:
        from ..oracles import ghidra as _gh
        if _gh.available():
            code = _gh.decompile_function(func)
            if code and len(code.strip()) > 80:
                return code, "ghidra"
    except Exception:
        pass
    # 2) r2 pdg (r2ghidra) si da algo sustancioso. Con limite de tiempo real (ver
    # r2session.cmd_timeout): r2pipe no tiene timeout nativo y `pdg` puede colgarse sin fin en
    # ciertas funciones/binarios, lo que se llevaria por delante el informe entero.
    try:
        from ..oracles.r2session import cmd_timeout as _r2cmd
        pdg = _r2cmd(binary, f"pdg @ {func}", timeout=90) or ""
        if len(pdg.strip()) > 120:
            return pdg, "pdg"
    except Exception:
        pass
    # 3) decai (r2ai, LLM) como alternativa, si esta habilitado
    try:
        from ..oracles import decai as _decai
        if _decai.enabled():
            code = _decai.decompile_function(binary, func)
            if code and len(code.strip()) > 40:
                return code, "decai"
    except Exception:
        pass
    # 4) resto de r2 (pdc/pdf)
    return _r2_decompile(binary, func)


def _collect_variants(binary: str, func: str) -> list:
    """Recoge la decompilacion de CADA motor disponible (Ghidra, r2 pdg, decai) para comparar en el
    informe. Best-effort y acotado; devuelve [(engine, code)] no vacios y deduplicados."""
    out = []
    seen = set()

    def add(engine, code):
        if code and code.strip() and code.strip() not in seen:
            seen.add(code.strip())
            out.append((engine, code.strip()))

    try:
        from ..oracles import ghidra as _gh
        if _gh.available():
            add("ghidra", _gh.decompile_function(func) or "")
    except Exception:
        pass
    try:
        from ..oracles.r2session import cmd_timeout as _r2cmd
        pdg = _r2cmd(binary, f"pdg @ {func}", timeout=90) or ""
        if len(pdg.strip()) > 60:
            add("pdg", pdg)
    except Exception:
        pass
    try:
        from ..oracles import decai as _decai
        if _decai.enabled():
            add("decai", _decai.decompile_function(binary, func) or "")
    except Exception:
        pass
    return out


def _crosscheck(variants: list, lang: str = "es") -> str:
    """Contraste determinista entre motores (retroalimentacion): senala si coinciden en las senales
    clave (sinks de riesgo, tamanos de buffer). Grounded: solo mira el texto que cada motor produjo."""
    if len(variants) < 2:
        return ""
    import re as _re
    es = lang == "es"
    sinks = ("read", "gets", "strcpy", "strcat", "sprintf", "memcpy", "scanf", "recv", "system",
             "popen", "execve")
    rows = []
    agree_sink = None
    for engine, code in variants:
        low = code.lower()
        found = sorted({s for s in sinks if s + "(" in low or s + " (" in low})
        sizes = sorted(set(_re.findall(r"\[(\d{1,5})\]", code)) | set(_re.findall(r",\s*(\d{2,6})\s*\)", code)))
        rows.append((engine, found, sizes))
    all_sinks = [set(f) for _, f, _ in rows]
    common = set.intersection(*all_sinks) if all_sinks else set()
    union = set().union(*all_sinks) if all_sinks else set()
    parts = []
    n = len(variants)
    if common:
        parts.append((f"Los {n} motores coinciden en los sinks: {', '.join(sorted(common))}." if es
                      else f"All {n} engines agree on sinks: {', '.join(sorted(common))}."))
    disc = union - common
    if disc:
        det = "; ".join(f"{eng}: {', '.join(f) or '-'}" for eng, f, _ in rows)
        parts.append((f"Discrepancia en sinks ({', '.join(sorted(disc))}) -> {det}. Revisa la funcion "
                      "directamente para resolverlo." if es else
                      f"Sink discrepancy ({', '.join(sorted(disc))}) -> {det}. Inspect the function "
                      "directly to resolve."))
    sizes_seen = {tuple(s) for _, _, s in rows if s}
    if len(sizes_seen) > 1:
        det = "; ".join(f"{eng}: {', '.join(s)}" for eng, _, s in rows if s)
        parts.append((f"Los tamanos/constantes difieren entre motores ({det}): confirma el tamano real "
                      "del buffer antes de calcular offsets." if es else
                      f"Sizes/constants differ across engines ({det}): confirm the real buffer size "
                      "before computing offsets."))
    return " ".join(parts)


def _cmd_bounded(r, cmd: str, timeout: float = 90.0) -> Optional[str]:
    """r.cmd(cmd) con limite de tiempo real sobre una sesion r2 DEDICADA (no compartida): si se
    cuelga (mismo bug que r2session.cmd_timeout -- r2pipe no tiene timeout nativo), se mata el
    proceso r2 propio (seguro, nadie mas lo usa) y se devuelve None en vez de bloquear para
    siempre. El hilo que seguia bloqueado en la lectura se abandona (daemon)."""
    import threading
    result: dict = {}
    def _run():
        try:
            result["v"] = r.cmd(cmd)
        except Exception:
            result["v"] = None
    th = threading.Thread(target=_run, daemon=True)
    th.start()
    th.join(timeout)
    if th.is_alive():
        try:
            r.process.kill()
        except Exception:
            pass
        return None
    return result.get("v")


def _r2_decompile(binary: str, func: str) -> tuple[str, str]:
    """Devuelve (texto, engine) con la mejor decompilacion de r2 disponible para la funcion."""
    try:
        import r2pipe
    except Exception:
        return "", ""
    try:
        r = r2pipe.open(binary, flags=["-2"])
        r.cmd("aaa")
        # r2ghidra (pdg) si esta y da algo sustancioso; si no, el pdc propio; si no, el disasm.
        # Cada comando con limite de tiempo real (ver _cmd_bounded): un `pdg` colgado no debe
        # dejar el informe entero esperando para siempre.
        pdg = _cmd_bounded(r, f"pdg @ {func}") or ""
        if len(pdg.strip()) > 120:
            r.quit(); return pdg, "pdg"
        pdc = _cmd_bounded(r, f"pdc @ {func}") or ""
        if pdc.strip():
            r.quit(); return pdc, "pdc"
        pdf = _cmd_bounded(r, f"pdf @ {func}") or ""
        r.quit()
        return pdf, "pdf"
    except Exception:
        return "", ""


_SYS = ("You are a senior reverse engineer. You are given the decompilation/disassembly of ONE "
        "function produced by a decompiler (radare2 or Ghidra). Produce, in this order and "
        "nothing else:\n"
        "1. A `c` code block with clean, readable C-like pseudocode for the function, using "
        "meaningful variable names (e.g. buf, len, user_input) and correct types (buffer sizes, "
        "etc.). Keep it faithful to the code shown.\n"
        "2. A short 'Explicacion' with numbered steps of what the function does.\n"
        "3. A 'Seguridad' line: if there is a memory-safety or command-exec issue (overflow, "
        "unbounded read, format string, command injection), name it and WHY; if none is evident, "
        "say so. Ground everything ONLY in the code shown; do not invent addresses or calls.")


def decompile_explain(binary: str, func: str, llm=None, lang: str = "es") -> DecompiledFunc:
    """Decompila `func` con r2 y, si hay modelo, la anota (pseudo-C limpio + explicacion)."""
    raw, engine = _best_decompile(binary, func)
    d = DecompiledFunc(func=func, raw=raw, engine=engine)
    if not d.ok:
        d.notes.append(f"r2 no pudo decompilar {func} (funcion no encontrada o binario ilegible)")
        return d
    # Comparativa multi-motor (Ghidra vs r2 vs decai) + contraste determinista (retroalimentacion).
    try:
        d.variants = _collect_variants(binary, func)
        d.crosscheck = _crosscheck(d.variants, lang=lang)
    except Exception:
        pass
    # Ficha tecnica grounded (firma/marco/locales con distancia a RIP).
    try:
        d.tech = func_technical(binary, func)
    except Exception:
        pass
    if llm is None or not getattr(llm, "available", lambda: False)():
        d.notes.append("sin modelo local: se muestra el decompilado crudo de r2 (levanta ollama "
                       "para la version anotada).")
        return d
    ask = "Responde en espanol." if lang == "es" else "Answer in English."
    # Retroalimentacion: si hay varios motores, el LLM ve TODAS las variantes (contrasta y concilia).
    if len(d.variants) > 1:
        blocks = "\n\n".join(f"[{eng}]\n```\n{code[:3500]}\n```" for eng, code in d.variants)
        user = (f"Funcion: {func}\nHay varias decompilaciones de distintos motores; concilialas en UNA "
                f"version fiel (si difieren, quedate con lo mas coherente y menciona la discrepancia en "
                f"'Seguridad').\n\n{blocks}")
    else:
        user = f"Funcion: {func}\nEngine: {engine}\n\n```\n{raw[:6000]}\n```"
    try:
        d.annotated = llm.chat([
            Message("system", _SYS + "\n" + ask),
            Message("user", user),
        ]).strip()
    except Exception as e:
        d.notes.append(f"el modelo no pudo anotar la decompilacion: {e}")
    return d
