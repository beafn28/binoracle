"""Oracle dinamico via Frida: confirmacion de double-free por FUNCTION INTERCEPTION (el mismo
mecanismo logico que `heap_dynamic.py`/`dynamic_dbg.py` usan via gdb/lldb), pero cross-platform
-- Frida instrumenta la misma manera en Linux, macOS y Windows, sin depender de ptrace (que este
proyecto ya documenta como poco fiable en Apple Silicon para lldb/gdb). ROADMAP v0.3: "Frida
dynamic oracle: cross-platform, scriptable hooks (heap tracing, function interception) to
augment/replace gdb/lldb".

Mecanismo: se hookean malloc/calloc/realloc (captura el valor de retorno) y free (captura el
argumento) con `Interceptor.attach` de Frida, se ejecuta el binario con el stdin dado, y se
reproduce la secuencia real de allocs/frees con la MISMA logica de deteccion que la rama gdb
(`heap_dynamic._replay_events`, reutilizada aqui en vez de duplicarla) -- un double-free real es
libre de una direccion que no esta viva.

Quirk real encontrado en vivo (y resuelto) construyendo esto: `send()` de Frida es ASINCRONO --
posta el mensaje a una cola que un hilo del agente vacia hacia el host. Si el proceso instrumentado
ABORTA muy poco despues de un hook (exactamente el caso de un double-free real: glibc aborta
DENTRO de la segunda llamada a free(), justo despues de que nuestro hook de entrada ya disparo),
ese hilo del agente puede destruirse junto con el proceso ANTES de vaciar la cola -- el evento se
pierde en silencio. Confirmado en vivo contra samples/bin/uaf: en una secuencia free,free (la
segunda dispara el abort de glibc), el segundo FREE_ARG faltaba SIEMPRE con `send()` plano.
Arreglado forzando una ACK SINCRONA en cada hook (`send(msg); recv('ack', cb).wait();`): el hilo
instrumentado se BLOQUEA hasta que el host confirma la recepcion, lo que garantiza que el evento
ya esta en manos del host antes de que el proceso pueda seguir ejecutando y abortar.

UAF (frida_confirm_uaf): equivalente cross-platform del watchpoint hardware de
`heap_dynamic.heap_confirm_uaf` via la API `MemoryAccessMonitor` de Frida (watch de PAGINA, no
de byte exacto como gdb -- por eso `onAccess` siempre reporta `details.address`, y se filtra
contra el rango exacto vigilado antes de contar nada como UAF real). Mismo mecanismo de
filtrado que la rama gdb (solo cuenta un acceso si viene del binario PRINCIPAL, no de
bookkeeping interno de glibc) pero via `Process.findModuleByAddress(pc).name` en vez de
`gdb.solib_name(pc)` -- con una diferencia real encontrada en vivo: `findModuleByAddress`
SIEMPRE devuelve un modulo (incluido el propio ejecutable principal), nunca null, al contrario
que `solib_name` (que devuelve None para el binario principal) -- el filtro aqui compara el
NOMBRE del modulo contra el basename del binario, no contra None. Confirmado en vivo contra
samples/bin/uaf con ambos escenarios de heap_dynamic.py (positivo 1,2,3 -> UAF_TOUCH real,
mod=uaf, mismo crash por safe-linking que la rama gdb; negativo 1,2,1,3 -> el watch SI dispara
cuando el segundo malloc() reescribe el puntero 'next' de tcache de la propia glibc
(mod=libc.so.6, UAF_TOUCH_IGNORED), luego WATCH_DISARMED por la reasignacion legitima -- cero
falsos positivos). Reutiliza `heap_dynamic._parse_uaf_log` (mismo formato de log que la rama
gdb) en vez de duplicar el parser.

Alcance honesto: solo UN chunk liberado vigilado a la vez (el mismo patron de objeto-unico que
`autouaf.py` explota y que el propio test matrix de heap_dynamic.py cubre) -- si el programa
libera un SEGUNDO chunk, en una direccion DISTINTA, antes de que el primero se reasigne,
`MemoryAccessMonitor.enable()` se vuelve a llamar con el rango nuevo; esta re-llamada no esta
confirmada en vivo como "añade" en vez de "reemplaza" el conjunto vigilado (comportamiento no
documentado con claridad en la API de Frida, y las pruebas en vivo hechas aqui solo cubrieron
el caso de una direccion reutilizada, no dos direcciones distintas simultaneas) -- asi que un
segundo free() concurrente podria dejar de vigilar el primero. No es el patron que este tool
dice cubrir ni el que `autouaf.py` genera, pero se documenta en vez de asumir cobertura total.

Quirk real encontrado en vivo probando el control negativo (1,2,1,3: libera, reasigna
legitimamente, usa -- no debe marcarse UAF): a diferencia de gdb (`run < INFILE`, donde el
`read()` del programa recibe EOF real -- devuelve 0 -- en cuanto el fichero de entrada se
agota, disparando el `if (read(0,b,7)<=0) exit(0);` de `samples/src/uaf.c`), `Device.input()`
de Frida escribe en un pipe que NO se cierra tras el ultimo byte escrito -- un `read()`
posterior en el programa simplemente BLOQUEA esperando mas datos (nunca ve EOF), hasta que
`budget_s` expira. No es un bug de la deteccion UAF en si (el log capturado hasta ese punto ya
es correcto): es un requisito real de como alimentar stdin con este backend -- a diferencia de
la convencion con gdb, una secuencia para Frida que deba terminar LIMPIAMENTE (sin crash) debe
incluir su propio comando de salida explicito (p.ej. un valor que el programa interprete como
'salir', no depender de que se agote la entrada)."""
from __future__ import annotations

import json
import os
import threading
import time
from typing import List

from .base import Oracle, Tool, ToolParam, ToolResult
from .heap_dynamic import _ALLOC_FUNCS, _FREE_FUNC, _GLIBC_FATAL_ERROR_RE, _parse_uaf_log, _replay_events

try:
    import frida  # type: ignore
    _HAVE_FRIDA = True
except Exception:
    _HAVE_FRIDA = False


_AGENT_JS_TMPL = r'''
function ackSend(msg) {
    send(msg);
    recv('ack', function(){}).wait();
}

var ALLOC_FUNCS = %(alloc_funcs)s;
ALLOC_FUNCS.forEach(function(name) {
    var addr = Module.findGlobalExportByName(name);
    if (addr === null) return;
    Interceptor.attach(addr, {
        onLeave: function(retval) {
            ackSend('MALLOC_RET ' + retval);
        }
    });
});

var freeAddr = Module.findGlobalExportByName(%(free_func)s);
if (freeAddr !== null) {
    Interceptor.attach(freeAddr, {
        onEnter: function(args) {
            ackSend('FREE_ARG ' + args[0]);
        }
    });
}
'''


_UAF_AGENT_JS_TMPL = r'''
function ackSend(msg) {
    send(msg);
    recv('ack', function(){}).wait();
}
function moduleNameAt(addr) {
    try {
        var m = Process.findModuleByAddress(addr);
        return m ? m.name : null;
    } catch (e) { return null; }
}

var MAIN_MODULE = %(main_module)s;
var watches = {};   // addr(str) -> true mientras este vigilado

var ALLOC_FUNCS = %(alloc_funcs)s;
ALLOC_FUNCS.forEach(function(name) {
    var addr = Module.findGlobalExportByName(name);
    if (addr === null) return;
    Interceptor.attach(addr, {
        onLeave: function(retval) {
            var a = retval.toString();
            ackSend('MALLOC_RET ' + a);
            // reasignacion REAL de una direccion vigilada -- memoria valida desde aqui, un uso
            // posterior no es UAF. MemoryAccessMonitor.enable() reemplaza el conjunto de
            // rangos vigilados globalmente (no es por-rango), asi que "desarmar" aqui significa
            // simplemente dejar de contarla: el disable() real ocurre al re-armar (abajo) o al
            // final del script.
            if (watches[a]) {
                delete watches[a];
                ackSend('WATCH_DISARMED (reasignacion legitima) ' + a);
            }
        }
    });
});

var freeAddr = Module.findGlobalExportByName(%(free_func)s);
if (freeAddr !== null) {
    Interceptor.attach(freeAddr, {
        onEnter: function(args) { this.freed = args[0]; },
        onLeave: function(retval) {
            if (this.freed === undefined || this.freed.isNull()) return;
            var addrStr = this.freed.toString();
            ackSend('FREE_DONE ' + addrStr);
            var target = this.freed;
            watches[addrStr] = true;
            try {
                MemoryAccessMonitor.enable([{base: target, size: 8}], {
                    onAccess: function(details) {
                        if (!watches[addrStr]) return;   // ya reasignada legitimamente
                        var pc = details.from;
                        var mod = moduleNameAt(pc);
                        if (mod !== MAIN_MODULE) {
                            ackSend('UAF_TOUCH_IGNORED (pc=' + pc + ' dentro de ' + mod + ') ' + addrStr);
                        } else {
                            ackSend('UAF_TOUCH ' + addrStr + ' (pc=' + pc + ', binario principal)');
                        }
                    }
                });
            } catch (e) { ackSend('WATCH_ERR ' + e); }
        }
    });
}
'''


class FridaDynamicOracle(Oracle):
    name = "frida_dynamic"

    def __init__(self, binary: str):
        self.binary = binary

    def available(self) -> bool:
        return _HAVE_FRIDA and os.path.exists(self.binary)

    def why_unavailable(self) -> str:
        if not _HAVE_FRIDA:
            return ("el paquete 'frida' no esta instalado (pip install frida) -- alternativa "
                    "cross-platform a gdb/lldb para interceptar funciones (heap tracing)")
        return "el binario no existe"

    def tools(self) -> List[Tool]:
        return [
            Tool(
                "frida_confirm_double_free",
                "Igual que heap_confirm_double_free pero via Frida (function interception) en "
                "vez de gdb -- funciona igual en Linux/macOS/Windows sin depender de ptrace. "
                "Engancha malloc/calloc/realloc y free por interceptacion, ejecuta el binario "
                "con el stdin dado, y reproduce la secuencia real para confirmar un double-free "
                "real (libera una direccion que no esta viva). Cross-confirma con el abort de "
                "glibc si aparece en stdout.",
                [ToolParam("stdin_text", "texto que se pasa por stdin al binario"),
                 ToolParam("budget_s", "limite de tiempo en segundos (por defecto 20)",
                           required=False, default=20)],
                lambda stdin_text, budget_s=20: self._confirm_double_free(stdin_text, budget_s),
                self.name,
            ),
            Tool(
                "frida_confirm_uaf",
                "Igual que heap_confirm_uaf pero via Frida (MemoryAccessMonitor) en vez de un "
                "watchpoint hardware de gdb -- funciona igual en Linux/macOS/Windows sin "
                "depender de ptrace. Tras cada free(), vigila los primeros 8 bytes del chunk "
                "liberado y confirma UAF solo si el PROPIO binario (no bookkeeping interno de "
                "glibc) los toca antes de una reasignacion real. Alcance: un chunk vigilado a "
                "la vez (el patron de objeto-unico que autouaf.py explota), igual que la rama gdb.",
                [ToolParam("stdin_text", "texto que se pasa por stdin al binario"),
                 ToolParam("budget_s", "limite de tiempo en segundos (por defecto 20)",
                           required=False, default=20)],
                lambda stdin_text, budget_s=20: self._confirm_uaf(stdin_text, budget_s),
                self.name,
            ),
        ]

    def _confirm_double_free(self, stdin_text, budget_s=20) -> ToolResult:
        try:
            budget_s = float(budget_s)
        except (TypeError, ValueError):
            budget_s = 20.0
        data = (stdin_text.encode("utf-8", "backslashreplace")
                if isinstance(stdin_text, str) else bytes(stdin_text))

        events: list = []
        out_chunks: list = []
        lock = threading.Lock()
        detached = threading.Event()

        def on_message(message, _data):
            if message.get("type") == "send":
                with lock:
                    events.append(message["payload"])
                try:
                    script.post({"type": "ack"})
                except Exception:
                    pass
            elif message.get("type") == "error":
                with lock:
                    events.append("JS_ERROR " + message.get("description", ""))

        def on_output(pid_, fd_, chunk):
            if chunk:
                with lock:
                    out_chunks.append(chunk)

        def on_detached(reason, crash):
            detached.set()

        dev = frida.get_local_device()
        pid = None
        session = None
        script = None
        try:
            try:
                pid = dev.spawn([self.binary], stdio="pipe")
            except Exception as e:
                return ToolResult(False, "frida: spawn", "",
                                  error=f"frida no pudo lanzar el binario aqui: {e}",
                                  meta={"dbg_unavailable": True})
            dev.on("output", on_output)
            try:
                session = dev.attach(pid)
                session.on("detached", on_detached)
                agent_js = _AGENT_JS_TMPL % {
                    "alloc_funcs": json.dumps(list(_ALLOC_FUNCS)),
                    "free_func": json.dumps(_FREE_FUNC),
                }
                script = session.create_script(agent_js)
                script.on("message", on_message)
                script.load()
                dev.resume(pid)
                dev.input(pid, data)
                detached.wait(timeout=budget_s)
                if not detached.is_set():
                    try:
                        dev.kill(pid)
                    except Exception:
                        pass
                    return ToolResult(
                        False, "frida: frida_confirm_double_free", "",
                        error=f"el objetivo no volvio dentro de budget_s={budget_s}s (pudo "
                              f"quedarse esperando mas entrada, o un bucle); sube budget_s o "
                              f"revisa el stdin dado")
                time.sleep(0.2)   # drena cualquier output/mensaje final tras el detach
            finally:
                try:
                    if session:
                        session.detach()
                except Exception:
                    pass
                dev.off("output", on_output)
        finally:
            try:
                if pid is not None:
                    dev.kill(pid)
            except Exception:
                pass

        with lock:
            log_lines = list(events)
            out_text = b"".join(out_chunks).decode("utf-8", "replace")
        log_text = "\n".join(log_lines)
        addr, timeline = _replay_events(log_text)
        verified = addr is not None
        summary = "\n".join(timeline) if timeline else "(ningun malloc/calloc/realloc/free interceptado)"
        # Bug real encontrado probando esto contra un binario real (how2heap's
        # tcache_house_of_spirit.c, glibc 2.39): su propio texto explicativo imprime
        # literalmente 'double free or corruption' como parte del printf educativo del programa
        # (describe el concepto en general, no afirma que ocurrio aqui); buscar ese substring
        # SUELTO en out_text (la salida CAPTURADA DEL PROPIO PROGRAMA) marcaba
        # glibc_also_aborted=True aunque el proceso siguiera vivo y terminara limpio -- mismo
        # bug que el fix de heap_dynamic.py (_confirm), encontrado aqui de forma independiente
        # porque este backend duplica esa logica con su propia fuente de texto.
        #
        # Descartado en vivo como arreglo: el `reason`/`crash` de on_detached -- `reason` resulto
        # ser "process-terminated" para CUALQUIER final de proceso en este entorno (crash real o
        # salida limpia, confirmado probando ambos), y `crash` sale None incluso para un SIGABRT
        # real confirmado por separado (el soporte de deteccion de crash de Frida necesita mas
        # que spawn+resume aqui) -- ninguno de los dos distingue nada fiable en este entorno.
        #
        # Arreglo real: el mismo `_GLIBC_FATAL_ERROR_RE` de heap_dynamic.py -- el prefijo EXACTO
        # con el que SOLO glibc imprime sus propios fatales ("free(): double free detected in
        # tcache 2"...) a stderr, que `out_text` SI captura (confirmado: la muestra sintetica de
        # este proyecto imprime ese mensaje real ahi) y que how2heap NUNCA reproduce -- solo
        # menciona las palabras sueltas como pista de busqueda, sin el prefijo.
        glibc_abort = bool(_GLIBC_FATAL_ERROR_RE.search(out_text.lower()))
        if verified:
            data_out = (f"DOUBLE-FREE CONFIRMADO en ejecucion real (via Frida): {addr}\n\n"
                       f"Secuencia observada (malloc/free reales, instrumentados con Frida):\n"
                       f"{summary}" +
                       ("\n\n(la propia glibc tambien lo detecto y aborto el proceso -- "
                        "doble confirmacion, independiente de este rastreo)" if glibc_abort else ""))
        else:
            data_out = (f"NO se confirmo double-free con este input -- secuencia observada:\n"
                       f"{summary}\n\n(si no hubo ningun evento, puede que el binario no llegue "
                       f"a llamar a malloc/free con este stdin, o que Frida no haya podido "
                       f"interceptarlos)")
        return ToolResult(
            True, "Frida (Interceptor.attach): malloc/calloc/realloc/free; replay", data_out,
            meta={"verified": verified, "double_free_addr": addr,
                 "glibc_also_aborted": glibc_abort, "raw_output": out_text.strip()})

    def _confirm_uaf(self, stdin_text, budget_s=20) -> ToolResult:
        try:
            budget_s = float(budget_s)
        except (TypeError, ValueError):
            budget_s = 20.0
        data = (stdin_text.encode("utf-8", "backslashreplace")
                if isinstance(stdin_text, str) else bytes(stdin_text))

        events: list = []
        lock = threading.Lock()
        detached = threading.Event()

        def on_message(message, _data):
            if message.get("type") == "send":
                with lock:
                    events.append(message["payload"])
                try:
                    script.post({"type": "ack"})
                except Exception:
                    pass
            elif message.get("type") == "error":
                with lock:
                    events.append("JS_ERROR " + message.get("description", ""))

        def on_detached(reason, crash):
            detached.set()

        dev = frida.get_local_device()
        pid = None
        session = None
        script = None
        try:
            try:
                pid = dev.spawn([self.binary], stdio="pipe")
            except Exception as e:
                return ToolResult(False, "frida: spawn", "",
                                  error=f"frida no pudo lanzar el binario aqui: {e}",
                                  meta={"dbg_unavailable": True})
            try:
                session = dev.attach(pid)
                session.on("detached", on_detached)
                agent_js = _UAF_AGENT_JS_TMPL % {
                    "alloc_funcs": json.dumps(list(_ALLOC_FUNCS)),
                    "free_func": json.dumps(_FREE_FUNC),
                    "main_module": json.dumps(os.path.basename(self.binary)),
                }
                script = session.create_script(agent_js)
                script.on("message", on_message)
                script.load()
                dev.resume(pid)
                dev.input(pid, data)
                detached.wait(timeout=budget_s)
                if not detached.is_set():
                    try:
                        dev.kill(pid)
                    except Exception:
                        pass
                    return ToolResult(
                        False, "frida: frida_confirm_uaf", "",
                        error=f"el objetivo no volvio dentro de budget_s={budget_s}s (pudo "
                              f"quedarse esperando mas entrada, o un bucle); sube budget_s o "
                              f"revisa el stdin dado")
                time.sleep(0.2)   # drena cualquier mensaje final tras el detach
            finally:
                try:
                    if session:
                        session.detach()
                except Exception:
                    pass
        finally:
            try:
                if pid is not None:
                    dev.kill(pid)
            except Exception:
                pass

        with lock:
            log_lines = list(events)
        log_text = "\n".join(log_lines)
        addr, pc, timeline = _parse_uaf_log(log_text)
        verified = addr is not None
        summary = "\n".join(timeline) if timeline else "(ningun malloc/calloc/realloc/free interceptado)"
        if verified:
            data_out = (f"USE-AFTER-FREE CONFIRMADO en ejecucion real (via Frida): {addr} "
                       f"(tocado desde el binario principal en pc={pc})\n\n"
                       f"Secuencia observada:\n{summary}")
        else:
            data_out = (f"NO se confirmo use-after-free con este input -- secuencia "
                       f"observada:\n{summary}\n\n(solo se detectan accesos DIRECTOS de CPU "
                       f"a la memoria liberada, no mediados por syscall; si el UAF real pasa "
                       f"por read()/write() sobre el buffer liberado, esta tecnica no lo vera)")
        return ToolResult(
            True, "Frida (MemoryAccessMonitor): free() + watch de 8 bytes; replay", data_out,
            meta={"verified": verified, "uaf_addr": addr, "uaf_pc": pc,
                 "raw_frida_log": log_text.strip()})
