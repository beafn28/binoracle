"""Fuente de decompilacion alternativa: decai (plugin r2ai) via radare2.

decai decompila con un LLM (ollama/anthropic/openai...) desde dentro de r2 (`decai -d <func>`),
dando pseudo-C con nombres y tipos mas legibles. binoracle lo usa como fuente ALTERNATIVA cuando
esta instalado y hay un LLM configurado y accesible; si no, cae a Ghidra/r2 (nada se rompe).

Se invoca por subproceso `r2 -c "...; decai -d <func>"` con timeout acotado (es una llamada a LLM,
puede tardar). Config del proveedor/modelo: se toma de la de decai (`decai -e`), o se fuerza a la
de binoracle (ollama + su modelo) con BINORACLE_DECAI_MODEL. Habilitado por defecto SOLO si hay LLM
listo; forzar con BINORACLE_DECAI=1 / desactivar con BINORACLE_DECAI=0.

Solo stdlib. Nunca lanza.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import Optional

_PLUGIN_PATHS = (
    "~/.local/share/radare2/plugins/decai.r2.js",
    "~/.config/radare2/plugins/decai.r2.js",
)


def installed() -> bool:
    """decai instalado (fichero del plugin presente) y r2 disponible."""
    if not shutil.which("r2"):
        return False
    return any(os.path.isfile(os.path.expanduser(p)) for p in _PLUGIN_PATHS)


def _ollama_up(timeout: float = 2.0) -> bool:
    import urllib.request
    base = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
    if not base.startswith("http"):
        base = "http://" + base
    try:
        with urllib.request.urlopen(base + "/api/tags", timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def _llm_ready() -> bool:
    """Hay un backend LLM para decai: ollama arriba, o alguna API key configurada."""
    if _ollama_up():
        return True
    if any(os.environ.get(k) for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GROQ_API_KEY",
                                       "MISTRAL_API_KEY", "GEMINI_API_KEY")):
        return True
    keyfile = os.path.expanduser("~/.config/r2ai/apikeys.txt")
    try:
        return os.path.getsize(keyfile) > 0
    except OSError:
        return False


def enabled() -> bool:
    """decai activo: instalado + habilitado. Por defecto ON si hay LLM listo; overridable por env."""
    if not installed():
        return False
    env = os.environ.get("BINORACLE_DECAI")
    if env is not None:
        return env.strip().lower() in ("1", "true", "yes", "on")
    return _llm_ready()


def _default_model() -> Optional[str]:
    """Modelo de ollama a usar si decai no tiene ninguno configurado: prefiere uno de codigo,
    excluye los de embeddings. None si no se puede determinar."""
    import json as _j
    import urllib.request
    base = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
    if not base.startswith("http"):
        base = "http://" + base
    try:
        with urllib.request.urlopen(base + "/api/tags", timeout=3) as r:
            names = [m.get("name", "") for m in _j.loads(r.read().decode()).get("models", [])]
    except Exception:
        return None
    usable = [n for n in names if not any(e in n.lower() for e in ("embed", "bge", "nomic"))]
    if not usable:
        return None
    usable.sort(key=lambda n: (0 if "coder" in n.lower() else 1, len(n)))
    return usable[0]


def _looks_c(s: str) -> bool:
    return "{" in s and (";" in s or "return" in s or ")" in s) and len(s.strip()) > 40


def _clean(out: str) -> Optional[str]:
    """Extrae el bloque de codigo de la salida de decai (quita fences markdown y ruido)."""
    if not out:
        return None
    txt = out.strip()
    if "```" in txt:
        parts = txt.split("```")
        best = ""
        for i in range(1, len(parts), 2):          # fragmentos ENTRE fences
            frag = parts[i]
            explicit_c = frag[:2].lower() == "c\n" or frag[:2].lower() == "c\r"
            if frag[:2].lower() in ("c\n", "c\r") or frag[:2].lower() == "c ":
                frag = frag.split("\n", 1)[1] if "\n" in frag else frag
            frag = frag.strip()
            # un fence 'c' explicito se acepta aunque sea corto; si no, exige que parezca C
            if (explicit_c or _looks_c(frag)) and len(frag) > len(best):
                best = frag
        return best or None                         # si hay fences pero nada util, None (no ruido)
    return txt if _looks_c(txt) else None


def decompile_function(binary: str, func: str, model: Optional[str] = None,
                       timeout: float = 120.0) -> Optional[str]:
    """Pseudo-C de `func` via decai, o None si no disponible/sin LLM/sin resultado."""
    if not installed():
        return None
    r2 = shutil.which("r2")
    to = shutil.which("timeout") or shutil.which("gtimeout")
    model = model or os.environ.get("BINORACLE_DECAI_MODEL") or _default_model()
    # decai -d decompila la funcion ACTUAL: hay que hacer seek antes. Si el nombre es "pelado"
    # (no 0x/sym.), se prueba tal cual y con prefijo sym. como respaldo.
    seek = func
    if not (func.startswith("0x") or "." in func):
        seek = f"sym.{func}"

    def _run(seek_to: str) -> Optional[str]:
        cmds = ["aaa", f"s {seek_to}"]
        if model:
            cmds += ["decai -e api=ollama", f"decai -e model={model}"]
        cmds.append("decai -d")
        argv = [r2, "-q", "-e", "scr.color=0", "-e", "bin.relocs.apply=true",
                "-c", "; ".join(cmds), os.path.abspath(binary)]
        if to:
            argv = [to, str(int(timeout)), *argv]
        try:
            out = subprocess.run(argv, capture_output=True, text=True, timeout=timeout + 10)
            return _clean(out.stdout or "")
        except Exception:
            return None

    return _run(seek) or (_run(func) if seek != func else None)


# --- Oraculo para el agente LLM ---
from .base import Oracle, Tool, ToolParam, ToolResult   # noqa: E402


class DecaiOracle(Oracle):
    """decai (r2ai) como oraculo de decompilacion alternativa. Se registra si decai esta instalado
    y hay un LLM listo (ollama/keys); si no, el recon sigue con Ghidra/r2."""
    name = "decai"

    def __init__(self, binary: str):
        self.binary = binary

    def available(self) -> bool:
        return enabled()

    def why_unavailable(self) -> str:
        if not installed():
            return "decai no instalado (r2pm -Uci decai)"
        return "sin backend LLM para decai (arranca ollama o configura una API key)"

    def _run(self, func: str = "main") -> ToolResult:
        code = decompile_function(self.binary, func)
        if not code:
            return ToolResult(False, f"decai: decai -d {func}", "",
                              error="decai no devolvio decompilacion (sin LLM o funcion no hallada)")
        return ToolResult(True, f"decai: decai -d {func}", code, meta={"engine": "decai", "func": func})

    def tools(self):
        return [Tool(
            name="decai_decompile",
            description="Decompile ONE function with decai (r2ai LLM-augmented pseudo-C), an "
                        "alternative to Ghidra/r2. Arg: func = name or 0x<addr>.",
            params=[ToolParam("func", "function name or address", required=False, default="main")],
            run=self._run, oracle=self.name)]
