"""Impresion de progreso con colores ANSI y una etiqueta de nivel ([INFO]/[OK]/[WARN]/[ERROR]/
[VERIFIED]), para que las decenas de lineas que imprime 'investigate'/'investigate-batch'/
'investigate-watch' (codigo descargado, laboratorio Docker, verificacion dinamica...) se puedan
distinguir de un vistazo en vez de ser un bloque homogeneo de texto del mismo color.

Los pasos que reporta el pipeline (cve_agent.py, wpverify.py...) son texto libre sin un nivel
explicito -- en vez de retocar cientos de llamadas a step()/print() por todo el proyecto para que
etiqueten cada mensaje a mano, `classify()` adivina el nivel por palabras clave ya presentes en
el espanol/ingles que ya usan esos mensajes (confirmado/verificado -> OK, error/fallo/no se pudo
-> ERROR, bloqueo/no confirmado/ignorado -> WARN, el resto -> INFO). Es una heuristica, no
perfecta, pero bastante mejor que ningun color.

Los colores se desactivan solos (texto plano, sin codigos ANSI, solo la etiqueta) si la salida no
es una terminal (se redirige a fichero/pipe, o se ejecuta bajo pytest) o si NO_COLOR esta puesto
(convencion https://no-color.org)."""
from __future__ import annotations

import os
import re
import sys

_RESET = "\033[0m"
_BOLD = "\033[1m"
_COLOR = {
    "info": "\033[36m",       # cyan
    "ok": "\033[32m",         # verde
    "warn": "\033[33m",       # amarillo
    "error": "\033[31m",      # rojo
    "verified": "\033[1;32m", # verde intenso
}
_LABEL = {"info": "INFO", "ok": "OK", "warn": "WARN", "error": "ERROR", "verified": "VERIFIED"}

_ERROR_RE = re.compile(
    r"\berror\b|\bfallo\b|fall[oó]|no se pudo|excepcion|traceback|no se pudo conectar",
    re.IGNORECASE)
_WARN_RE = re.compile(
    r"bloqueo|no confirmad|no se (encontr|reconoc)|no filtr|ignorad[ao]|no tiene pinta|"
    r"no disponible|no mostr[oó] diferencia",
    re.IGNORECASE)
_OK_RE = re.compile(
    r"\bverificad[oa]\b|\bconfirm[oóa]|\bgrounded\b|\brecuperad[oa]\b|exito|listo\b|activ[oa]\b",
    re.IGNORECASE)


def classify(message: str) -> str:
    """Adivina el nivel (info/ok/warn/error) de un mensaje de progreso en texto libre. El orden
    de comprobacion importa: error antes que warn antes que ok, porque un mensaje puede
    mencionar varias palabras clave a la vez ('verificacion dinamica intentada pero NO
    CONFIRMADA' tiene 'confirmada' Y 'no confirmada' -- debe quedar como warn, no ok)."""
    if _ERROR_RE.search(message):
        return "error"
    if _WARN_RE.search(message):
        return "warn"
    if _OK_RE.search(message):
        return "ok"
    return "info"


def _use_color(stream) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("BINORACLE_FORCE_COLOR"):
        return True
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def line(message: str, level: str = "", file=None, prefix: str = "  ") -> None:
    """Imprime `message` con su etiqueta de nivel y color. Si no se da `level`, se adivina con
    classify(). `file` por defecto es sys.stdout -- se pasa sys.stderr explicitamente donde el
    resto del CLI ya usaba stderr (p.ej. un fallo de conexion a Burp), para no cambiar a donde
    va cada mensaje, solo como se ve."""
    stream = file or sys.stdout
    level = level or classify(message)
    label = _LABEL.get(level, level.upper())
    if _use_color(stream):
        color = _COLOR.get(level, "")
        print(f"{prefix}{color}{_BOLD}[{label}]{_RESET}{color} {message}{_RESET}", file=stream)
    else:
        print(f"{prefix}[{label}] {message}", file=stream)


def info(message: str, file=None) -> None:
    line(message, "info", file=file)


def ok(message: str, file=None) -> None:
    line(message, "ok", file=file)


def warn(message: str, file=None) -> None:
    line(message, "warn", file=file)


def error(message: str, file=None) -> None:
    line(message, "error", file=file)


def verified(message: str, file=None) -> None:
    line(message, "verified", file=file)
