"""Sesion r2 compartida por binario (cache de proceso).

Muchos workflows reabren radare2 y repiten `aaa` (analisis completo), que es lo caro, sobre el
mismo binario (triage, vulnhunt, cfg, chainanalyzer, decompile, backdoors...). Este util mantiene
UNA sesion r2 analizada por ruta de binario y la reutiliza: el `aaa` se hace una sola vez.

Seguro para los consumidores que direccionan con `@ <addr>` o `cmd`/`cmdj` sin dejar estado
(seek temporal), que es como los usa binoracle. La cache se invalida si el fichero cambia (mtime).
close_all() cierra todo al terminar una auditoria. Nunca lanza: si r2pipe no esta, get() devuelve
None y el llamador cae a su propia apertura.
"""
from __future__ import annotations

import os
from typing import Optional

_CACHE: dict = {}   # abspath -> (r2_handle, mtime)


def get(binary: str):
    """Devuelve una sesion r2 con `aaa` ya hecho para `binary`, cacheada. None si no hay r2pipe."""
    try:
        import r2pipe
    except Exception:
        return None
    try:
        key = os.path.abspath(binary)
        mtime = os.path.getmtime(key)
    except OSError:
        return None
    ent = _CACHE.get(key)
    if ent and ent[1] == mtime:
        return ent[0]
    if ent:
        _quit(ent[0])
    try:
        r = r2pipe.open(key, flags=["-2"])
        r.cmd("aaa")
    except Exception:
        return None
    _CACHE[key] = (r, mtime)
    return r


def _quit(r) -> None:
    try:
        r.quit()
    except Exception:
        pass


def close(binary: str) -> None:
    key = os.path.abspath(binary)
    ent = _CACHE.pop(key, None)
    if ent:
        _quit(ent[0])


def close_all() -> None:
    for r, _ in list(_CACHE.values()):
        _quit(r)
    _CACHE.clear()
