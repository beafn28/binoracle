"""Cliente del servidor Ghidra MCP (opcional): decompilacion grado Ghidra cuando esta disponible.

binoracle habla por HTTP con un servidor GhidraMCP local (el plugin de Ghidra expone endpoints en
127.0.0.1:8089 por defecto) para obtener pseudo-C de calidad Ghidra, mejor que `pdg`/`pdc` de r2 en
muchos binarios. Es OPCIONAL y con auto-deteccion: si Ghidra no esta abierto con el plugin y el
binario cargado, `available()` devuelve False y binoracle cae a r2 (nada se rompe).

Requisitos del lado servidor (fuera de binoracle): Ghidra abierto con el plugin GhidraMCP y el
programa cargado; la URL se configura con BINORACLE_GHIDRA_URL (default http://127.0.0.1:8089).

Solo stdlib (urllib). Nunca lanza: ante cualquier fallo devuelve indisponible/None.
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Optional


def base_url() -> str:
    return os.environ.get("BINORACLE_GHIDRA_URL", "http://127.0.0.1:8089").rstrip("/")


def _get(path: str, params: dict = None, timeout: float = 4.0) -> Optional[str]:
    url = base_url() + path
    if params:
        url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v not in (None, "")})
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            if r.status != 200:
                return None
            return r.read().decode("utf-8", "replace")
    except Exception:
        return None


def available(timeout: float = 2.0) -> bool:
    """True si hay un servidor GhidraMCP respondiendo (con un programa cargado)."""
    return _get("/check_connection", timeout=timeout) is not None


def _extract_code(payload: str) -> Optional[str]:
    """Saca el pseudo-C de la respuesta, sea JSON (envuelto en Response) o texto plano."""
    if not payload:
        return None
    payload = payload.strip()
    if payload[:1] in "{[":
        try:
            obj = json.loads(payload)
        except Exception:
            return payload if _looks_c(payload) else None
        # busca recursivamente el valor de texto mas largo que parezca codigo C
        best = [""]
        def walk(o):
            if isinstance(o, str):
                if len(o) > len(best[0]) and _looks_c(o):
                    best[0] = o
            elif isinstance(o, dict):
                # claves preferentes primero
                for k in ("decompilation", "code", "pseudocode", "ccode", "c", "text", "result", "data"):
                    if isinstance(o.get(k), str) and _looks_c(o[k]) and len(o[k]) > len(best[0]):
                        best[0] = o[k]
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        walk(obj)
        return best[0] or None
    return payload if _looks_c(payload) else None


def _looks_c(s: str) -> bool:
    return "{" in s and (";" in s or "return" in s or ")" in s) and len(s.strip()) > 40


def decompile_function(func: str, timeout: float = 60.0) -> Optional[str]:
    """Pseudo-C de `func` (nombre o direccion) via Ghidra, o None si no disponible/sin resultado."""
    payload = _get("/decompile_function", {"address": func, "timeout": int(timeout)},
                   timeout=timeout + 5)
    return _extract_code(payload) if payload else None
