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

Alcance de este primer incremento: solo confirmacion de double-free (la UAF con watchpoint de
`heap_dynamic.py` tiene un equivalente cross-platform en la API `MemoryAccessMonitor` de Frida,
pero queda fuera de este incremento -- ver ROADMAP.md)."""
from __future__ import annotations

import json
import os
import threading
import time
from typing import List

from .base import Oracle, Tool, ToolParam, ToolResult
from .heap_dynamic import _ALLOC_FUNCS, _FREE_FUNC, _replay_events

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
        low = out_text.lower()
        glibc_abort = "double free" in low or "corrupt" in low
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
