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


def get(binary: str, analysis_timeout: float = 180.0):
    """Devuelve una sesion r2 con `aaa` ya hecho para `binary`, cacheada. None si no hay r2pipe.

    Bug real encontrado en vivo (mismo patron que cmd_timeout() mas abajo, para el `pdg` del
    decompilador): el propio `aaa` inicial -- que PRACTICAMENTE todo oraculo basado en r2
    dispara tarde o temprano, directo o via esta cache compartida -- no tenia NINGUN limite de
    tiempo. En un binario estatico grande (p.ej. una muestra static-PIE del corpus de practica:
    arrastra la libc entera, miles de funciones) el analisis completo puede tardar varios
    minutos; si se queda realmente colgado (p.ej. un bug del propio r2 en un binario raro), el
    pipeline entero esperaba para siempre sin ningun aviso -- el mismo fallo que ya se arreglo
    para `pdg` (ver cmd_timeout) pero en el chequeo de entrada que lo precede a TODOS. Acotado
    con el mismo patron de hilo+join: si no vuelve a tiempo, se mata el proceso r2 colgado y se
    devuelve None (el llamador cae a su propio oraculo/degrada), nunca se bloquea sin limite."""
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
    result: dict = {}
    def _run():
        try:
            r.cmd("aaa")
            result["ok"] = True
        except Exception:
            result["ok"] = False
    th = threading.Thread(target=_run, daemon=True)
    th.start()
    th.join(analysis_timeout)
    if th.is_alive() or not result.get("ok"):
        try:
            r.process.kill()
        except Exception:
            pass
        try:
            r.quit()
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


def cmd_timeout_on(r, cmd: str, timeout: float) -> str:
    """Como cmd_timeout(), pero sobre una sesion r2pipe YA ABIERTA a mano (no la cacheada de
    `get()`) -- para los workflows que deliberadamente abren su propia sesion fresca por llamada
    (audit.py, backdoors.py) en vez de compartir la cache. Mismo mecanismo: thread daemon +
    join(timeout) + kill del proceso r2 si sigue vivo. Nunca lanza; devuelve "" (no None, para
    que encadene bien con `... or ""` en el codigo existente) si se agota el tiempo."""
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
        return ""
    return result.get("v") or ""


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
