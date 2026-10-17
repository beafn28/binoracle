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
import threading
from typing import Optional

_CACHE: dict = {}   # abspath -> (r2_handle, mtime)


def get(binary: str, aaa_timeout: float = 180.0):
    """Devuelve una sesion r2 con `aaa` ya hecho para `binary`, cacheada. None si no hay r2pipe.

    Bug real encontrado en vivo (mismo patron que ya motivo `cmd_timeout` para `pdg`, documentado
    abajo, pero aqui en el propio `aaa` -- el analisis completo que CASI todo workflow dispara al
    abrir cualquier binario por primera vez): `aaa` no tenia NINGUN limite de tiempo. En un
    binario complejo, o bajo CPU muy limitada, puede tardar mucho mas de lo razonable y bloquear
    indefinidamente a quien sea que llamo a `get()` -- a diferencia de `pdg`, que solo afecta al
    decompilador, esto afecta a CUALQUIER workflow que abra un r2 por primera vez (triage,
    vulnhunt, cfg, chainanalyzer, decompile, backdoors, reachability...). Mismo remedio: el `aaa`
    corre en un hilo daemon con `join(aaa_timeout)`; si no vuelve a tiempo, se mata el proceso r2
    y se devuelve None (el llamador ya sabe caer a su propia apertura, por contrato previo de
    `get()`) en vez de colgarse para siempre."""
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
    except Exception:
        return None
    done: dict = {}
    def _run_aaa():
        try:
            r.cmd("aaa")
            done["ok"] = True
        except Exception:
            done["ok"] = False
    th = threading.Thread(target=_run_aaa, daemon=True)
    th.start()
    th.join(aaa_timeout)
    if th.is_alive() or not done.get("ok"):
        try:
            r.process.kill()
        except Exception:
            pass
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


def cmd_timeout(binary: str, cmd: str, timeout: float = 90.0) -> Optional[str]:
    """Como get(binary).cmd(cmd), pero con limite de tiempo real. Bug encontrado en vivo: `pdg @
    func` (decompilador r2ghidra) NO tiene ningun timeout nativo en r2pipe -- si se queda colgado
    (funcion compleja, o el proceso r2 en un estado raro, p.ej. por un servidor Ghidra externo
    emparejado con OTRO binario y una sesion previa que dejo el pipe en mal estado) el pipeline
    ENTERO del informe se queda esperando para siempre, sin ningun error visible.

    Si el comando no vuelve a tiempo: se invalida la sesion compartida de este binario (la
    siguiente llamada a get() abre una nueva, limpia) y se mata el proceso r2 colgado en segundo
    plano -- el hilo que seguia bloqueado en la lectura del pipe se abandona (es daemon, no
    impide que el programa termine) en vez de dejarlo bloquear el resto de la auditoria. Nunca
    lanza; None si no hay sesion o si se agoto el tiempo."""
    r = get(binary)
    if r is None:
        return None
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
        key = os.path.abspath(binary)
        ent = _CACHE.get(key)
        if ent and ent[0] is r:
            _CACHE.pop(key, None)
        try:
            r.process.kill()
        except Exception:
            pass
        return None
    return result.get("v")
