"""Confirmacion DINAMICA de double-free y use-after-free enganchando malloc/free con gdb, en
vez de los candidatos ESTATICOS actuales (r2_heap: "free aparece >=2 veces en la misma funcion"
-- un recuento de llamadas en el codigo, no una prueba de que ocurrio nada malo en ejecucion
real). Motor de heap dinamico del ROADMAP v0.2 ("dynamic confirmation of UAF / double-free by
hooking malloc/free (ltrace / gdb / Frida) instead of the current static candidates").

Mecanismo comun a ambas confirmaciones: engancha malloc/calloc/realloc (captura el valor de
retorno, $rax) y free (captura el argumento, $rdi -- ABI SysV x86-64) con un script de PYTHON de
gdb (gdb.Breakpoint con stop() devolviendo False para no detener de verdad la ejecucion), NO con
bloques `commands` de gdb-batch: `finish` llamado sincronamente dentro de un bloque `commands`
automatico resulto NO ser fiable en esta version de gdb (15.1) -- "Cannot execute this command
while the selected thread is running" -- confirmado en vivo. La tecnica robusta para capturar un
valor de retorno sin `finish` es leer la direccion de retorno de la pila en la ENTRADA de la
funcion (`*(unsigned long*)$rsp`, el ABI de x86-64 la deja ahi antes del prologo) y poner un
breakpoint TEMPORAL ahi para capturar $rax cuando la funcion realmente vuelve.

Los breakpoints en malloc/free solo resuelven a la libc REAL del programa (no al malloc interno
del propio dynamic linker, rtld-malloc.h, que ld.so usa para cargarse a si mismo) si se ponen
DESPUES de parar en main() -- confirmado en vivo: 'break malloc' puesto antes de arrancar el
proceso intercepta el malloc interno del rtld durante la carga de la libreria, no los malloc/
free reales que el programa invoca, y nunca llega a verse ningun evento del programa.

UAF (heap_confirm_uaf): tras cada free(ptr), arma un watchpoint de ACCESO (lectura O escritura)
sobre los primeros 8 bytes del chunk liberado -- el patron de UAF concreto que el motor de
exploits de este proyecto ya construye y verifica (autouaf.py: un struct cuyo PRIMER CAMPO es un
puntero a funcion, liberado y luego usado). Dos problemas reales encontrados y resueltos en vivo
probando esto contra samples/bin/uaf:

1. El propio malloc(), al REUTILIZAR el chunk que su tcache acaba de liberar (lee el puntero
   'next' enlazado que la propia glibc almaceno ahi, con safe-linking), toca esa misma direccion
   -- dispara el watchpoint aunque no sea un UAF del PROGRAMA, es bookkeeping interno de glibc.
   Resuelto con `gdb.solib_name(pc)`: si el PC donde el watchpoint disparo cae DENTRO de una
   libreria compartida (libc.so.6), se ignora; si cae en el binario principal (solib_name
   devuelve None), es un acceso real del programa -- UAF confirmado. (Intentos previos de usar
   gdb.Block.objfile fallaron: ese atributo no existe en la API de Python de gdb; solib_name()
   es la forma correcta y mas simple de resolverlo.)
2. Si una llamada a malloc/calloc/realloc POSTERIOR devuelve la MISMA direccion que se acababa de
   liberar (reutilizacion LEGITIMA del allocator), el watchpoint se desarma en ese momento: un
   uso tras esa reasignacion ya no es un UAF, es memoria valida con nuevo contenido.

Confirmado end-to-end contra samples/bin/uaf (fuente real: 1=new, 2=free, 3=run -> el campo
function-pointer leido DESPUES de liberar el struct): UAF_TOUCH se dispara exactamente en el
punto correcto, y el proceso ademas CRASHEA (SIGSEGV en direccion basura) por la corrupcion del
puntero via tcache safe-linking -- confirmacion independiente, igual que el double-free con
glibc. Control negativo (new, free, new, run: el segundo 'new' reutiliza legitimamente la misma
direccion antes del 'run'): NO se marca UAF.

Alcance: solo el acceso DIRECTO de CPU a la memoria liberada (lecturas/escrituras/llamadas desde
codigo del programa). Un acceso MEDIADO POR SYSCALL (p.ej. read()/write() leyendo o escribiendo
un buffer liberado, como en samples/bin/heapexp) NO se detecta -- los watchpoints hardware de
ptrace no disparan con copy_to_user/copy_from_user del kernel, solo con instrucciones de
CPU en espacio de usuario; limitacion real y documentada de gdb/ptrace en Linux, no un bug de
este codigo. Para ese patron (UAF via syscall) haria falta otra tecnica (p.ej. Frida interceptando
las propias syscalls, o un wrapper LD_PRELOAD), fuera de alcance de este incremento."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import List

from .base import Oracle, Tool, ToolParam, ToolResult

# El prefijo EXACTO con el que glibc imprime sus propios errores fatales de malloc/free
# ("free(): double free detected in tcache 2", "malloc(): invalid pointer", "free(): invalid
# next size (fast)"...) -- nunca "double free or corruption" o "invalid next size" sueltos,
# que un programa (p.ej. how2heap's propio texto educativo, que los menciona como ejemplo de
# que buscar) puede imprimir SIN que haya pasado nada. Es la senal real e inequivoca de que la
# propia glibc aborto, independiente de nuestro propio rastreo de malloc/free.
_GLIBC_FATAL_ERROR_RE = re.compile(r"\b(?:malloc|free|realloc|calloc)\(\):\s")

_ALLOC_FUNCS = ("malloc", "calloc", "realloc")
_FREE_FUNC = "free"

_MALLOC_RET_RE = re.compile(r"^MALLOC_RET (0x[0-9a-fA-F]+)$")
_FREE_ARG_RE = re.compile(r"^FREE_ARG (0x[0-9a-fA-F]+)$")

_GDB_UNRUNNABLE = ("ptrace: operation not permitted", "cannot access memory",
                   "not in executable format", "no executable file specified")

_GDB_PYTHON_SCRIPT = '''\
import gdb

LOG = {log_path!r}
INFILE = {infile!r}
f = open(LOG, "w")

class _RetBP(gdb.Breakpoint):
    """Breakpoint TEMPORAL en la direccion de retorno de una llamada a malloc/calloc/realloc,
    puesto desde el entry-breakpoint (ver _AllocEntryBP) -- captura $rax (el valor devuelto)
    sin usar `finish`, que no es seguro llamar sincronamente dentro de Breakpoint.stop()."""
    def __init__(self, addr):
        super().__init__("*0x%x" % addr, gdb.BP_BREAKPOINT, internal=True, temporary=True)
    def stop(self):
        try:
            rax = int(gdb.parse_and_eval("$rax")) & 0xffffffffffffffff
            f.write("MALLOC_RET 0x%x\\n" % rax)
        except Exception as e:
            f.write("MALLOC_ERR %s\\n" % e)
        f.flush()
        return False

class _AllocEntryBP(gdb.Breakpoint):
    def stop(self):
        try:
            ret_addr = int(gdb.parse_and_eval("*(unsigned long*)$rsp"))
            _RetBP(ret_addr)
        except Exception as e:
            f.write("MALLOC_ENTRY_ERR %s\\n" % e)
        f.flush()
        return False

class _FreeBP(gdb.Breakpoint):
    def stop(self):
        try:
            rdi = int(gdb.parse_and_eval("$rdi")) & 0xffffffffffffffff
            f.write("FREE_ARG 0x%x\\n" % rdi)
        except Exception as e:
            f.write("FREE_ERR %s\\n" % e)
        f.flush()
        return False

gdb.execute("set pagination off")
gdb.execute("set confirm off")
# 'start' (no 'run'), y la redireccion de stdin COMO PARTE de start: asi el proceso se para en
# main() -- dynamic linker ya termino -- ANTES de poner los breakpoints de malloc/free.
gdb.execute("start < %s" % INFILE)
for fn in {alloc_funcs!r}:
    try:
        _AllocEntryBP(fn)
    except gdb.error as e:
        f.write("BP_ERR %s %s\\n" % (fn, e))
try:
    _FreeBP({free_func!r})
except gdb.error as e:
    f.write("BP_ERR %s %s\\n" % ({free_func!r}, e))
try:
    gdb.execute("continue")
except gdb.error as e:
    f.write("CONTINUE_ERR %s\\n" % e)
f.close()
'''


_UAF_TOUCH_RE = re.compile(r"^UAF_TOUCH (0x[0-9a-fA-F]+) \(pc=(0x[0-9a-fA-F]+)")

_GDB_UAF_PYTHON_SCRIPT = '''\
import gdb

LOG = {log_path!r}
INFILE = {infile!r}
f = open(LOG, "w")
watches = {{}}

class _RetBP(gdb.Breakpoint):
    """Ver _GDB_PYTHON_SCRIPT (heap_confirm_double_free) -- misma tecnica (breakpoint temporal
    en la direccion de retorno, sin `finish`) para capturar $rax de malloc/calloc/realloc."""
    def __init__(self, addr, kind, extra=None):
        self.kind = kind
        self.extra = extra
        super().__init__("*0x%x" % addr, gdb.BP_BREAKPOINT, internal=True, temporary=True)
    def stop(self):
        try:
            if self.kind == "malloc_ret":
                rax = int(gdb.parse_and_eval("$rax")) & 0xffffffffffffffff
                f.write("MALLOC_RET 0x%x\\n" % rax)
                wp = watches.pop(rax, None)
                if wp is not None:
                    # esta direccion se acaba de REASIGNAR de verdad -- ya no es memoria
                    # liberada, un uso posterior es valido, no UAF.
                    try:
                        wp.delete()
                    except Exception:
                        pass
                    f.write("WATCH_DISARMED (reasignacion legitima) 0x%x\\n" % rax)
            elif self.kind == "free_ret":
                addr = self.extra
                f.write("FREE_DONE 0x%x\\n" % addr)
                try:
                    watches[addr] = _UafWatch(addr)
                except Exception as e:
                    f.write("WATCH_ERR %s\\n" % e)
        except Exception as e:
            f.write("RET_ERR %s\\n" % e)
        f.flush()
        return False

class _UafWatch(gdb.Breakpoint):
    """Watchpoint de ACCESO (lectura o escritura) sobre los primeros 8 bytes de un chunk recien
    liberado. Si dispara DENTRO de una libreria compartida (gdb.solib_name(pc) no-None), es
    bookkeeping interno de glibc (p.ej. malloc() leyendo el puntero 'next' del propio tcache) --
    se ignora. Si dispara dentro del binario principal (solib_name devuelve None), es un acceso
    REAL del programa a memoria liberada: UAF confirmado."""
    def __init__(self, addr):
        self.addr = addr
        super().__init__("*(unsigned long*)0x%x" % addr, gdb.BP_WATCHPOINT, gdb.WP_ACCESS, internal=True)
    def stop(self):
        pc = int(gdb.selected_frame().pc())
        solib = gdb.solib_name(pc)
        if solib is not None:
            f.write("UAF_TOUCH_IGNORED (pc=0x%x dentro de %s) 0x%x\\n" % (pc, solib, self.addr))
            f.flush()
            return False
        f.write("UAF_TOUCH 0x%x (pc=0x%x, binario principal)\\n" % (self.addr, pc))
        f.flush()
        return False

class _AllocEntryBP(gdb.Breakpoint):
    def stop(self):
        try:
            ret_addr = int(gdb.parse_and_eval("*(unsigned long*)$rsp"))
            _RetBP(ret_addr, "malloc_ret")
        except Exception as e:
            f.write("MALLOC_ENTRY_ERR %s\\n" % e)
        return False

class _FreeBP(gdb.Breakpoint):
    def stop(self):
        try:
            rdi = int(gdb.parse_and_eval("$rdi")) & 0xffffffffffffffff
            ret_addr = int(gdb.parse_and_eval("*(unsigned long*)$rsp"))
            _RetBP(ret_addr, "free_ret", extra=rdi)
        except Exception as e:
            f.write("FREE_ENTRY_ERR %s\\n" % e)
        return False

gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("start < %s" % INFILE)
for fn in {alloc_funcs!r}:
    try:
        _AllocEntryBP(fn)
    except gdb.error as e:
        f.write("BP_ERR %s %s\\n" % (fn, e))
try:
    _FreeBP({free_func!r})
except gdb.error as e:
    f.write("BP_ERR %s %s\\n" % ({free_func!r}, e))
try:
    gdb.execute("continue")
except gdb.error as e:
    f.write("CONTINUE_ERR %s\\n" % e)
f.close()
'''


_CHUNKSTATE_PREFIX = "CHUNKSTATE_JSON "

_GDB_CHUNKS_PYTHON_SCRIPT = '''\
import gdb, json

LOG = {log_path!r}
INFILE = {infile!r}
f = open(LOG, "w")

SIZE_SZ = 8
MIN_CHUNK = 2 * SIZE_SZ
MASK64 = 0xffffffffffffffff

def _decode_next(node_addr, raw):
    """glibc >=2.32 safe-linking: el puntero 'next'/'fd' almacenado en un chunk libre no es la
    direccion real, es PROTECT_PTR(&campo, real) = (direccion_del_propio_campo >> 12) XOR real.
    Como la operacion es su propia inversa, se decodifica igual que se codifico. node_addr es la
    direccion del propio campo (el puntero de usuario para tcache, chunk+2*SIZE_SZ para fastbin:
    coinciden, es el mismo offset dentro del chunk)."""
    if raw == 0:
        return 0
    return (node_addr >> 12) ^ raw

def _chunk_size(chunk_addr):
    try:
        sz = int(gdb.parse_and_eval("*(unsigned long*)0x%x" % (chunk_addr + SIZE_SZ)))
        return sz & ~0x7
    except Exception:
        return None

def _tcache_snapshot():
    out = {{}}
    try:
        tcache = int(gdb.parse_and_eval("(unsigned long)tcache"))
    except Exception:
        return out
    if tcache == 0:
        return out
    for idx in range(64):
        try:
            count = int(gdb.parse_and_eval(
                "((struct tcache_perthread_struct*)0x%x)->counts[%d]" % (tcache, idx)))
            head = int(gdb.parse_and_eval(
                "((struct tcache_perthread_struct*)0x%x)->entries[%d]" % (tcache, idx))) & MASK64
        except Exception:
            continue
        if count == 0 and head == 0:
            continue
        chain = []
        node = head
        seen = set()
        while node and node not in seen and len(chain) < 64:
            seen.add(node)
            chain.append({{"addr": "0x%x" % node, "size": _chunk_size(node - MIN_CHUNK)}})
            try:
                raw = int(gdb.parse_and_eval("*(unsigned long*)0x%x" % node)) & MASK64
            except Exception:
                break
            node = _decode_next(node, raw) & MASK64
        out[str(idx)] = {{"count": count, "chain": chain}}
    return out

def _fastbin_snapshot():
    out = {{}}
    for idx in range(10):
        try:
            head = int(gdb.parse_and_eval("(unsigned long)main_arena.fastbinsY[%d]" % idx)) & MASK64
        except Exception:
            continue
        if head == 0:
            continue
        chain = []
        node = head
        seen = set()
        while node and node not in seen and len(chain) < 64:
            seen.add(node)
            user_ptr = node + MIN_CHUNK
            chain.append({{"addr": "0x%x" % node, "size": _chunk_size(node)}})
            try:
                raw = int(gdb.parse_and_eval("*(unsigned long*)0x%x" % user_ptr)) & MASK64
            except Exception:
                break
            node = _decode_next(user_ptr, raw) & MASK64
        out[str(idx)] = chain
    return out

def _snapshot(label):
    try:
        snap = {{"label": label, "tcache": _tcache_snapshot(), "fastbin": _fastbin_snapshot()}}
        f.write("CHUNKSTATE_JSON " + json.dumps(snap) + "\\n")
    except Exception as e:
        f.write("SNAPSHOT_ERR %s\\n" % e)
    f.flush()

class _RetBP(gdb.Breakpoint):
    """Misma tecnica de breakpoint-en-direccion-de-retorno que el resto de este modulo: dispara
    justo cuando free() REALMENTE termino (el chunk ya esta enlazado en su bin), sin usar
    `finish`."""
    def __init__(self, addr, extra):
        self.extra = extra
        super().__init__("*0x%x" % addr, gdb.BP_BREAKPOINT, internal=True, temporary=True)
    def stop(self):
        f.write("FREE_DONE 0x%x\\n" % self.extra)
        _snapshot("after free(0x%x)" % self.extra)
        return False

class _FreeBP(gdb.Breakpoint):
    def stop(self):
        try:
            rdi = int(gdb.parse_and_eval("$rdi")) & MASK64
            ret_addr = int(gdb.parse_and_eval("*(unsigned long*)$rsp"))
            _RetBP(ret_addr, rdi)
        except Exception as e:
            f.write("FREE_ENTRY_ERR %s\\n" % e)
        return False

gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("start < %s" % INFILE)
_snapshot("inicial")
try:
    _FreeBP({free_func!r})
except gdb.error as e:
    f.write("BP_ERR %s %s\\n" % ({free_func!r}, e))
try:
    gdb.execute("continue")
except gdb.error as e:
    f.write("CONTINUE_ERR %s\\n" % e)
f.close()
'''


def _parse_chunk_log(log_text: str) -> list:
    """Extrae las snapshots CHUNKSTATE_JSON del log, en el orden en que se capturaron (una por
    cada free() real que termino durante la ejecucion, mas la inicial antes de cualquier free)."""
    snapshots = []
    for line in log_text.splitlines():
        line = line.strip()
        if line.startswith(_CHUNKSTATE_PREFIX):
            try:
                snapshots.append(json.loads(line[len(_CHUNKSTATE_PREFIX):]))
            except (ValueError, TypeError):
                continue
    return snapshots


def _format_chunk_report(snapshots: list) -> str:
    if not snapshots:
        return ("(no se capturo ningun estado del heap -- puede que el binario no llame a "
                "free() con este stdin)")
    lines = []
    for snap in snapshots:
        lines.append(f"== {snap.get('label', '?')} ==")
        tcache = snap.get("tcache") or {}
        if not tcache:
            lines.append("  tcache: vacio o sin inicializar (aun no hubo ningun malloc)")
        for idx, info in sorted(tcache.items(), key=lambda kv: int(kv[0])):
            chain = ", ".join(f"{c['addr']}(size={c['size']})" for c in info.get("chain", []))
            lines.append(f"  tcache idx={idx} count={info.get('count')}: {chain}")
        fastbin = snap.get("fastbin") or {}
        for idx, chain_list in sorted(fastbin.items(), key=lambda kv: int(kv[0])):
            chain = ", ".join(f"{c['addr']}(size={c['size']})" for c in chain_list)
            lines.append(f"  fastbin idx={idx}: {chain}")
    return "\n".join(lines)


def _replay_events(log_text: str) -> tuple:
    """Reproduce el log MALLOC_RET/FREE_ARG como una maquina de estados: direcciones vivas
    (devueltas por un allocator y no liberadas aun). Devuelve (double_free_addr_or_None,
    timeline) -- timeline es la lista de eventos en orden, para evidencia legible. Se detiene
    en el PRIMER double-free real (free de una direccion no viva y != NULL): es la prueba que
    hace falta, no hace falta seguir reproduciendo tras confirmarlo."""
    alive = set()
    timeline = []
    double_free_addr = None
    for line in log_text.splitlines():
        line = line.strip()
        m = _MALLOC_RET_RE.match(line)
        if m:
            addr = m.group(1)
            timeline.append(f"malloc-family devuelve {addr}")
            if addr != "0x0":
                alive.add(addr)
            continue
        m = _FREE_ARG_RE.match(line)
        if m:
            addr = m.group(1)
            if addr == "0x0":
                timeline.append("free(NULL) -- no-op valido, no cuenta")
                continue
            if addr in alive:
                timeline.append(f"free({addr}) -- liberacion normal")
                alive.discard(addr)
            else:
                timeline.append(f"free({addr}) -- ESTA DIRECCION NO ESTA VIVA "
                                "(nunca se devolvio de malloc/calloc/realloc en esta "
                                "ejecucion, o ya se habia liberado antes) -- DOUBLE-FREE")
                double_free_addr = addr
                break
    return double_free_addr, timeline


def _parse_uaf_log(log_text: str) -> tuple:
    """Extrae la primera confirmacion real de UAF del log (UAF_TOUCH, no UAF_TOUCH_IGNORED).
    Devuelve (addr_or_None, pc_or_None, timeline-de-eventos-legible)."""
    timeline = []
    uaf_addr = None
    uaf_pc = None
    for line in log_text.splitlines():
        line = line.strip()
        if line.startswith("MALLOC_RET"):
            timeline.append(f"malloc-family devuelve {line.split()[1]}")
        elif line.startswith("FREE_DONE"):
            timeline.append(f"free({line.split()[1]}) completado")
        elif line.startswith("WATCH_DISARMED"):
            timeline.append(line.replace("WATCH_DISARMED", "reasignado legitimamente:"))
        elif line.startswith("UAF_TOUCH_IGNORED"):
            timeline.append(f"(ignorado: {line.split('(', 1)[1]}" if "(" in line else line)
        elif line.startswith("UAF_TOUCH "):
            m = _UAF_TOUCH_RE.match(line)
            if m and uaf_addr is None:
                uaf_addr, uaf_pc = m.group(1), m.group(2)
                timeline.append(f"USE-AFTER-FREE: {line}")
                break
    return uaf_addr, uaf_pc, timeline


class HeapDynamicOracle(Oracle):
    name = "heap_dynamic"

    def __init__(self, binary: str):
        self.binary = binary
        self.gdb = shutil.which("gdb")

    def available(self) -> bool:
        # Linux-only por ahora: usa registros x86-64 SysV (rax/rdi) directamente, igual que
        # dynamic_dbg.py asume para su rama gdb. lldb/macOS queda fuera de este primer incremento.
        return bool(self.gdb) and os.path.exists(self.binary)

    def why_unavailable(self) -> str:
        if not self.gdb:
            return "gdb no esta en el PATH (apt install gdb) -- necesario para enganchar malloc/free"
        return "el binario no existe"

    def tools(self) -> List[Tool]:
        return [
            Tool(
                "heap_confirm_double_free",
                "Confirma DINAMICAMENTE (no heuristica) si un input concreto dispara un "
                "double-free real: engancha malloc/calloc/realloc (valor de retorno) y free "
                "(argumento) con gdb, ejecuta el binario con ese stdin, y reproduce la "
                "secuencia real de allocs/frees. Solo marca verified si una direccion se libera "
                "sin estar viva (nunca asignada en esta ejecucion, o ya liberada antes) -- "
                "free(NULL) nunca cuenta.",
                [ToolParam("stdin_text", "texto que se pasa por stdin al binario"),
                 ToolParam("budget_s", "limite de tiempo en segundos (por defecto 20)",
                           required=False, default=20)],
                lambda stdin_text, budget_s=20: self._confirm(stdin_text, budget_s),
                self.name,
            ),
            Tool(
                "heap_confirm_uaf",
                "Confirma DINAMICAMENTE (no heuristica) si un input concreto dispara un "
                "use-after-free real: tras cada free(), vigila (watchpoint de acceso) los "
                "primeros 8 bytes del chunk liberado -- el patron de UAF con puntero a funcion "
                "que este motor ya explota (ver autouaf.py). Solo marca verified si el programa "
                "(no glibc internamente, filtrado via gdb.solib_name) toca esa memoria antes de "
                "que un malloc/calloc/realloc posterior la reasigne de verdad. Limitacion real: "
                "solo detecta accesos DIRECTOS de CPU, no mediados por syscall (read()/write() "
                "sobre el buffer liberado).",
                [ToolParam("stdin_text", "texto que se pasa por stdin al binario"),
                 ToolParam("budget_s", "limite de tiempo en segundos (por defecto 20)",
                           required=False, default=20)],
                lambda stdin_text, budget_s=20: self._confirm_uaf(stdin_text, budget_s),
                self.name,
            ),
            Tool(
                "heap_dump_state",
                "Vuelca el estado REAL (no estatico) del allocator: para cada free() que "
                "ocurre al ejecutar el binario con el stdin dado, lee directamente los bins de "
                "tcache y fastbin de glibc desde memoria -- que chunks (direccion + tamano "
                "real, leido del propio header del chunk) quedan en que indice de bin, "
                "decodificando los punteros next/fd protegidos por safe-linking (glibc >=2.32). "
                "Util para chunk/bin analysis y para razonar sobre primitivas de tcache/"
                "fastbin-poisoning: muestra el estado exacto que un overflow controlado "
                "tendria que corromper.",
                [ToolParam("stdin_text", "texto que se pasa por stdin al binario"),
                 ToolParam("budget_s", "limite de tiempo en segundos (por defecto 20)",
                           required=False, default=20)],
                lambda stdin_text, budget_s=20: self._dump_state(stdin_text, budget_s),
                self.name,
            ),
            Tool(
                "heap_verify_tcache_poison",
                "Confirma DINAMICAMENTE si un tcache/fastbin-poisoning realmente funciono: "
                "ejecuta el binario con el stdin dado (que ya debe contener el overflow que "
                "escribe el payload calculado por heap_tcache_poison_payload), engancha "
                "malloc/calloc/realloc igual que heap_confirm_double_free, y marca verified si "
                "alguna llamada a malloc-family devuelve EXACTAMENTE target_addr -- la prueba "
                "de que el allocator fue engañado para devolver esa direccion controlada por el "
                "atacante, no una suposicion.",
                [ToolParam("stdin_text", "texto que se pasa por stdin al binario (ya con el overflow incluido)"),
                 ToolParam("target_addr", "direccion que deberia devolver la malloc envenenada (hex o int)"),
                 ToolParam("budget_s", "limite de tiempo en segundos (por defecto 20)",
                           required=False, default=20)],
                lambda stdin_text, target_addr, budget_s=20: self._verify_tcache_poison(
                    stdin_text, target_addr, budget_s),
                self.name,
            ),
        ]

    def _confirm(self, stdin_text, budget_s=20) -> ToolResult:
        try:
            budget_s = float(budget_s)
        except (TypeError, ValueError):
            budget_s = 20.0
        data = stdin_text.encode("utf-8", "backslashreplace") if isinstance(stdin_text, str) else bytes(stdin_text)
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(data)
            infile = tf.name
        log_path = infile + ".heaplog"
        script_path = None
        try:
            script = _GDB_PYTHON_SCRIPT.format(
                log_path=log_path, infile=infile,
                alloc_funcs=list(_ALLOC_FUNCS), free_func=_FREE_FUNC)
            with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as sf:
                sf.write(script)
                script_path = sf.name
            try:
                out = subprocess.run(
                    [self.gdb, "-q", "-batch", "-x", script_path, self.binary],
                    capture_output=True, text=True, timeout=budget_s,
                )
                gdb_txt = out.stdout + ("\n[stderr]\n" + out.stderr if out.stderr else "")
            except subprocess.TimeoutExpired:
                return ToolResult(
                    False, "gdb: heap_confirm_double_free", "",
                    error=f"gdb no volvio dentro de budget_s={budget_s}s (el objetivo pudo "
                          f"quedarse esperando mas entrada, o un bucle); sube budget_s o revisa "
                          f"el stdin dado",
                )
            low = gdb_txt.lower()
            if any(m in low for m in _GDB_UNRUNNABLE):
                return ToolResult(
                    False, "gdb: heap_confirm_double_free", gdb_txt.strip(),
                    error="gdb no pudo ejecutar el objetivo aqui (ptrace no permitido, o el "
                          "host no puede correr este binario)",
                    meta={"dbg_unavailable": True})
            try:
                with open(log_path) as lf:
                    log_text = lf.read()
            except OSError:
                log_text = ""
            addr, timeline = _replay_events(log_text)
            verified = addr is not None
            summary = "\n".join(timeline) if timeline else "(ningun malloc/calloc/realloc/free interceptado)"
            # Bug real encontrado probando esto contra un binario real (how2heap's
            # tcache_house_of_spirit.c, glibc 2.39): su propio texto explicativo imprime
            # literalmente 'double free or corruption' como parte del printf educativo del
            # programa (describiendo el concepto en general, no afirmando que ocurrio aqui) --
            # ese texto queda en `out.stdout`, que `low` tambien cubre, asi que una busqueda de
            # substring SUELTO ("double free" / "corrupt") sobre TODO el texto (salida del
            # programa incluida) marcaba glibc_also_aborted=True aunque el proceso saliera
            # limpio (confirmado: el log de gdb termina en "[Inferior 1 (process N) exited
            # normally]", no en un abort real). Arreglado buscando el prefijo EXACTO con el que
            # SOLO glibc imprime sus propios fatales (`_GLIBC_FATAL_ERROR_RE`) -- how2heap NUNCA
            # reproduce ese formato exacto, solo menciona las palabras sueltas como pista.
            glibc_abort = bool(_GLIBC_FATAL_ERROR_RE.search(low))
            if verified:
                data_out = (f"DOUBLE-FREE CONFIRMADO en ejecucion real: {addr}\n\n"
                           f"Secuencia observada (malloc/free reales, instrumentados con gdb):\n"
                           f"{summary}" +
                           ("\n\n(la propia glibc tambien lo detecto y aborto el proceso -- "
                            "doble confirmacion, independiente de este rastreo)" if glibc_abort else ""))
            else:
                data_out = (f"NO se confirmo double-free con este input -- secuencia observada:\n"
                           f"{summary}\n\n(si no hubo ningun evento, puede que el binario no "
                           f"llegue a llamar a malloc/free con este stdin, o que gdb no haya "
                           f"podido interceptarlos)")
            return ToolResult(
                True, "gdb (python API): break malloc/calloc/realloc/free; replay", data_out,
                meta={"verified": verified, "double_free_addr": addr,
                     "glibc_also_aborted": glibc_abort, "raw_gdb_output": gdb_txt.strip()})
        finally:
            for p in (infile, log_path, script_path):
                if p:
                    try:
                        os.unlink(p)
                    except OSError:
                        pass

    def _confirm_uaf(self, stdin_text, budget_s=20) -> ToolResult:
        try:
            budget_s = float(budget_s)
        except (TypeError, ValueError):
            budget_s = 20.0
        data = stdin_text.encode("utf-8", "backslashreplace") if isinstance(stdin_text, str) else bytes(stdin_text)
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(data)
            infile = tf.name
        log_path = infile + ".uaflog"
        script_path = None
        try:
            script = _GDB_UAF_PYTHON_SCRIPT.format(
                log_path=log_path, infile=infile,
                alloc_funcs=list(_ALLOC_FUNCS), free_func=_FREE_FUNC)
            with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as sf:
                sf.write(script)
                script_path = sf.name
            try:
                out = subprocess.run(
                    [self.gdb, "-q", "-batch", "-x", script_path, self.binary],
                    capture_output=True, text=True, timeout=budget_s,
                )
                gdb_txt = out.stdout + ("\n[stderr]\n" + out.stderr if out.stderr else "")
            except subprocess.TimeoutExpired:
                return ToolResult(
                    False, "gdb: heap_confirm_uaf", "",
                    error=f"gdb no volvio dentro de budget_s={budget_s}s (el objetivo pudo "
                          f"quedarse esperando mas entrada, o un bucle); sube budget_s o revisa "
                          f"el stdin dado",
                )
            low = gdb_txt.lower()
            if any(m in low for m in _GDB_UNRUNNABLE):
                return ToolResult(
                    False, "gdb: heap_confirm_uaf", gdb_txt.strip(),
                    error="gdb no pudo ejecutar el objetivo aqui (ptrace no permitido, o el "
                          "host no puede correr este binario)",
                    meta={"dbg_unavailable": True})
            try:
                with open(log_path) as lf:
                    log_text = lf.read()
            except OSError:
                log_text = ""
            addr, pc, timeline = _parse_uaf_log(log_text)
            verified = addr is not None
            summary = "\n".join(timeline) if timeline else "(ningun malloc/calloc/realloc/free interceptado)"
            if verified:
                data_out = (f"USE-AFTER-FREE CONFIRMADO en ejecucion real: {addr} "
                           f"(tocado desde el binario principal en pc={pc})\n\n"
                           f"Secuencia observada:\n{summary}")
            else:
                data_out = (f"NO se confirmo use-after-free con este input -- secuencia "
                           f"observada:\n{summary}\n\n(solo se detectan accesos DIRECTOS de "
                           f"CPU a la memoria liberada, no mediados por syscall; si el UAF real "
                           f"pasa por read()/write() sobre el buffer liberado, esta tecnica no "
                           f"lo vera)")
            return ToolResult(
                True, "gdb (python API): break malloc/free + watchpoint tras free; replay", data_out,
                meta={"verified": verified, "uaf_addr": addr, "uaf_pc": pc,
                     "raw_gdb_output": gdb_txt.strip()})
        finally:
            for p in (infile, log_path, script_path):
                if p:
                    try:
                        os.unlink(p)
                    except OSError:
                        pass

    def _dump_state(self, stdin_text, budget_s=20) -> ToolResult:
        try:
            budget_s = float(budget_s)
        except (TypeError, ValueError):
            budget_s = 20.0
        data = stdin_text.encode("utf-8", "backslashreplace") if isinstance(stdin_text, str) else bytes(stdin_text)
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(data)
            infile = tf.name
        log_path = infile + ".chunklog"
        script_path = None
        try:
            script = _GDB_CHUNKS_PYTHON_SCRIPT.format(
                log_path=log_path, infile=infile, free_func=_FREE_FUNC)
            with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as sf:
                sf.write(script)
                script_path = sf.name
            try:
                out = subprocess.run(
                    [self.gdb, "-q", "-batch", "-x", script_path, self.binary],
                    capture_output=True, text=True, timeout=budget_s,
                )
                gdb_txt = out.stdout + ("\n[stderr]\n" + out.stderr if out.stderr else "")
            except subprocess.TimeoutExpired:
                return ToolResult(
                    False, "gdb: heap_dump_state", "",
                    error=f"gdb no volvio dentro de budget_s={budget_s}s (el objetivo pudo "
                          f"quedarse esperando mas entrada, o un bucle); sube budget_s o revisa "
                          f"el stdin dado",
                )
            low = gdb_txt.lower()
            if any(m in low for m in _GDB_UNRUNNABLE):
                return ToolResult(
                    False, "gdb: heap_dump_state", gdb_txt.strip(),
                    error="gdb no pudo ejecutar el objetivo aqui (ptrace no permitido, o el "
                          "host no puede correr este binario)",
                    meta={"dbg_unavailable": True})
            try:
                with open(log_path) as lf:
                    log_text = lf.read()
            except OSError:
                log_text = ""
            snapshots = _parse_chunk_log(log_text)
            report = _format_chunk_report(snapshots)
            return ToolResult(
                True, "gdb (python API): walk tcache + main_arena.fastbinsY tras cada free() real",
                report, meta={"snapshots": snapshots, "raw_gdb_output": gdb_txt.strip()})
        finally:
            for p in (infile, log_path, script_path):
                if p:
                    try:
                        os.unlink(p)
                    except OSError:
                        pass

    def _verify_tcache_poison(self, stdin_text, target_addr, budget_s=20) -> ToolResult:
        try:
            budget_s = float(budget_s)
        except (TypeError, ValueError):
            budget_s = 20.0
        try:
            if isinstance(target_addr, int):
                ta = target_addr & 0xffffffffffffffff
            else:
                s = str(target_addr).strip()
                ta = (int(s, 16) if s.lower().startswith("0x") else int(s)) & 0xffffffffffffffff
        except (TypeError, ValueError):
            return ToolResult(False, "heap_verify_tcache_poison", "",
                              error="target_addr debe ser una direccion (hex o int)")
        target_hex = "0x%x" % ta
        # Reutiliza EXACTAMENTE el mismo engranaje de heap_confirm_double_free (hookear
        # malloc/calloc/realloc con breakpoint-en-retorno) -- aqui solo cambia lo que se busca
        # en el log: no una secuencia invalida de free(), sino si alguna malloc-family devolvio
        # la direccion exacta que el payload de poisoning queria forzar.
        data = stdin_text.encode("utf-8", "backslashreplace") if isinstance(stdin_text, str) else bytes(stdin_text)
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(data)
            infile = tf.name
        log_path = infile + ".poisonlog"
        script_path = None
        try:
            script = _GDB_PYTHON_SCRIPT.format(
                log_path=log_path, infile=infile,
                alloc_funcs=list(_ALLOC_FUNCS), free_func=_FREE_FUNC)
            with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as sf:
                sf.write(script)
                script_path = sf.name
            try:
                out = subprocess.run(
                    [self.gdb, "-q", "-batch", "-x", script_path, self.binary],
                    capture_output=True, text=True, timeout=budget_s,
                )
                gdb_txt = out.stdout + ("\n[stderr]\n" + out.stderr if out.stderr else "")
            except subprocess.TimeoutExpired:
                return ToolResult(
                    False, "gdb: heap_verify_tcache_poison", "",
                    error=f"gdb no volvio dentro de budget_s={budget_s}s; sube budget_s o "
                          f"revisa el stdin dado",
                )
            low = gdb_txt.lower()
            if any(m in low for m in _GDB_UNRUNNABLE):
                return ToolResult(
                    False, "gdb: heap_verify_tcache_poison", gdb_txt.strip(),
                    error="gdb no pudo ejecutar el objetivo aqui (ptrace no permitido, o el "
                          "host no puede correr este binario)",
                    meta={"dbg_unavailable": True})
            try:
                with open(log_path) as lf:
                    log_text = lf.read()
            except OSError:
                log_text = ""
            malloc_returns = []
            for line in log_text.splitlines():
                m = _MALLOC_RET_RE.match(line.strip())
                if m:
                    malloc_returns.append(m.group(1))
            verified = target_hex in malloc_returns
            if verified:
                data_out = (f"TCACHE/FASTBIN-POISONING CONFIRMADO: una malloc-family devolvio "
                           f"{target_hex} de verdad en esta ejecucion -- el allocator fue "
                           f"engañado para entregar esa direccion controlada por el atacante.\n\n"
                           f"Direcciones devueltas por malloc/calloc/realloc en orden: "
                           f"{', '.join(malloc_returns) if malloc_returns else '(ninguna)'}")
            else:
                data_out = (f"NO se confirmo: ninguna malloc-family devolvio {target_hex} con "
                           f"este stdin.\n\nDirecciones devueltas: "
                           f"{', '.join(malloc_returns) if malloc_returns else '(ninguna)'}\n\n"
                           f"Revisa que el stdin incluya de verdad el overflow con el payload "
                           f"de heap_tcache_poison_payload, y que field_addr usado para "
                           f"calcularlo fuera realmente la direccion vigente en esta ejecucion "
                           f"(ASLR puede cambiarla entre runs).")
            return ToolResult(
                True, "gdb (python API): break malloc/calloc/realloc; busca target_addr entre los retornos",
                data_out, meta={"verified": verified, "target_addr": target_hex,
                                "malloc_returns": malloc_returns, "raw_gdb_output": gdb_txt.strip()})
        finally:
            for p in (infile, log_path, script_path):
                if p:
                    try:
                        os.unlink(p)
                    except OSError:
                        pass
