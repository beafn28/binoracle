"""Impresion de progreso con colores ANSI, iconos Unicode y recuadros opcionales para los
mensajes de nivel VERIFIED/OK importantes, para que las decenas de lineas que imprime
'investigate'/'investigate-batch'/'investigate-watch' se puedan distinguir de un vistazo.

Los pasos del pipeline son texto libre sin nivel explicito -- classify() adivina el nivel por
palabras clave presentes en los mensajes (error/fallo -> ERROR, bloqueo/no confirmado -> WARN,
verificado/confirmado -> OK, el resto -> INFO).

Los colores e iconos se desactivan solos si la salida no es una terminal o si NO_COLOR esta
puesto (convencion https://no-color.org)."""
from __future__ import annotations

import os
import re
import sys

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_COLOR = {
    "info":     "\033[36m",      # cyan
    "ok":       "\033[32m",      # verde
    "warn":     "\033[33m",      # amarillo
    "error":    "\033[31m",      # rojo
    "verified": "\033[1;32m",    # verde intenso
    "section":  "\033[1;34m",    # azul intenso
}
# Iconos Unicode por nivel (texto plano si no hay color)
_ICON = {
    "info":     "ℹ",
    "ok":       "✓",
    "warn":     "⚠",
    "error":    "✗",
    "verified": "◉",
    "section":  "▸",
}
_LABEL = {
    "info": "INFO", "ok": "OK", "warn": "WARN",
    "error": "ERROR", "verified": "VERIFIED", "section": "STEP",
}

_ERROR_RE = re.compile(
    r"\berror(?!-)|\bfallo\b|fall[oó]|no se pudo|excepcion|traceback|no se pudo conectar",
    re.IGNORECASE)
_WARN_RE = re.compile(
    r"bloqueo|no confirmad|no se (encontr|reconoc)|no filtr|ignorad[ao]|no tiene pinta|"
    r"no disponible|no mostr[oó] diferencia",
    re.IGNORECASE)
_OK_RE = re.compile(
    r"\bverificad[oa]\b|\bconfirm[oóa]|\bgrounded\b|\brecuperad[oa]\b|exito|listo\b|activ[oa]\b",
    re.IGNORECASE)
# Mensajes que merecen un recuadro destacado (verificacion, lab listo, resultado final)
_BOX_RE = re.compile(
    r"verificad[oa] en (laboratorio|sandbox)|laboratorio.*listo|WordPress listo|MySQL listo|"
    r"exploit confirmado|VERIFICADO|no confirmado.*laboratorio|desmontando el laboratorio|"
    r"SQLI confirmada|SQLI VERIFICADA|account.takeover confirmado|"
    r"inyeccion SQL no se confirmo|ninguna.*inyecci[oó]n.*evidencia",
    re.IGNORECASE)
# Mensajes que marcan el inicio de una fase principal → se muestran como sección
_SECTION_RE = re.compile(
    r"^(consultando CVE|levantando laboratorio|intentando verificaci[oó]n din[aá]mica|"
    r"clonando el PoC|leyendo el c[oó]digo real|scaffolded.*lab at|"
    r"confirmando en el c[oó]digo|el LLM reviso la evidencia|capturando pantalla|"
    r"petici[oó]n de control|probando error.based|probando UNION.based|"
    r"probando boolean.blind|probando time.based|enviando la petici[oó]n|"
    r"verificaci[oó]n din[aá]mica.*intentada|iniciando sesi[oó]n como|"
    r"copiando el plugin|creando.*usuario|desarrollando el PoC|"
    r"obteniendo el c[oó]digo fuente|resolviendo plugin)",
    re.IGNORECASE)


def classify(message: str) -> str:
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


def _box(message: str, color: str, icon: str, stream) -> None:
    """Imprime un mensaje dentro de un recuadro Unicode para resultados importantes."""
    width = min(max(len(message) + 6, 50), 90)
    top    = "┌" + "─" * (width - 2) + "┐"
    bottom = "└" + "─" * (width - 2) + "┘"
    pad    = width - len(message) - 4
    mid    = "│ " + icon + " " + message + " " * pad + "│"
    print(f"  {color}{_BOLD}{top}{_RESET}", file=stream)
    print(f"  {color}{_BOLD}{mid}{_RESET}", file=stream)
    print(f"  {color}{_BOLD}{bottom}{_RESET}", file=stream)


def line(message: str, level: str = "", file=None, prefix: str = "  ") -> None:
    """Imprime `message` con icono, etiqueta de nivel y color ANSI. Mensajes de resultado
    importante (lab listo, verificado, exploit confirmado) se muestran dentro de un recuadro."""
    stream = file or sys.stdout
    level = level or classify(message)
    label = _LABEL.get(level, level.upper())
    color = _COLOR.get(level, "")
    icon  = _ICON.get(level, "·")
    use_c = _use_color(stream)
    # Separador de fase principal
    if use_c and _SECTION_RE.match(message.strip()):
        sec_color = _COLOR["section"]
        short = message[:70] + ("…" if len(message) > 70 else "")
        bar = "─" * min(len(short) + 4, 72)
        print(f"\n  {sec_color}{_BOLD}▸ {short}{_RESET}", file=stream)
        print(f"  {sec_color}{_DIM}{bar}{_RESET}", file=stream)
        return
    # Recuadro para mensajes de resultado clave
    if use_c and _BOX_RE.search(message):
        _box(message, color, icon, stream)
        return
    if use_c:
        print(f"{prefix}{color}{_BOLD}{icon} [{label}]{_RESET}{color} {message}{_RESET}", file=stream)
    else:
        print(f"{prefix}[{label}] {message}", file=stream)


def section(title: str, file=None) -> None:
    """Imprime una linea separadora de sección con titulo, para marcar fases del pipeline."""
    stream = file or sys.stdout
    if _use_color(stream):
        color = _COLOR["section"]
        icon  = _ICON["section"]
        width = min(len(title) + 6, 70)
        bar   = "─" * width
        print(f"\n  {color}{_BOLD}{icon} {title}{_RESET}", file=stream)
        print(f"  {color}{_DIM}{bar}{_RESET}", file=stream)
    else:
        print(f"\n── {title} ──", file=stream)


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
