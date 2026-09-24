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

    @property
    def ok(self) -> bool:
        return bool(self.raw.strip())


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
        pdg = r.cmd(f"pdg @ {func}") or ""
        if len(pdg.strip()) > 120:
            r.quit(); return pdg, "pdg"
        pdc = r.cmd(f"pdc @ {func}") or ""
        if pdc.strip():
            r.quit(); return pdc, "pdc"
        pdf = r.cmd(f"pdf @ {func}") or ""
        r.quit()
        return pdf, "pdf"
    except Exception:
        return "", ""


_SYS = ("You are a senior reverse engineer. You are given the decompilation/disassembly of ONE "
        "function produced by radare2. Produce, in this order and nothing else:\n"
        "1. A `c` code block with clean, readable C-like pseudocode for the function, using "
        "meaningful variable names (e.g. buf, len, user_input) and correct types (buffer sizes, "
        "etc.). Keep it faithful to the code shown.\n"
        "2. A short 'Explicacion' with numbered steps of what the function does.\n"
        "3. A 'Seguridad' line: if there is a memory-safety or command-exec issue (overflow, "
        "unbounded read, format string, command injection), name it and WHY; if none is evident, "
        "say so. Ground everything ONLY in the code shown; do not invent addresses or calls.")


def decompile_explain(binary: str, func: str, llm=None, lang: str = "es") -> DecompiledFunc:
    """Decompila `func` con r2 y, si hay modelo, la anota (pseudo-C limpio + explicacion)."""
    raw, engine = _r2_decompile(binary, func)
    d = DecompiledFunc(func=func, raw=raw, engine=engine)
    if not d.ok:
        d.notes.append(f"r2 no pudo decompilar {func} (funcion no encontrada o binario ilegible)")
        return d
    if llm is None or not getattr(llm, "available", lambda: False)():
        d.notes.append("sin modelo local: se muestra el decompilado crudo de r2 (levanta ollama "
                       "para la version anotada).")
        return d
    ask = "Responde en espanol." if lang == "es" else "Answer in English."
    try:
        d.annotated = llm.chat([
            Message("system", _SYS + "\n" + ask),
            Message("user", f"Funcion: {func}\nEngine: r2 {engine}\n\n```\n{raw[:6000]}\n```"),
        ]).strip()
    except Exception as e:
        d.notes.append(f"el modelo no pudo anotar la decompilacion: {e}")
    return d
