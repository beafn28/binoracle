"""JEB connector: talk to a caller-started JEB client that serves MCP (external engine).

JEB is a commercial reverse-engineering platform. Like REA, binoracle does not embed it: the caller
starts their own JEB client serving MCP and points binoracle at it with BINORACLE_JEB_MCP_URL (or the
`url` argument). binoracle then speaks JSON-RPC 2.0 over HTTP to that endpoint to list the engine's
tools and call them (e.g. list project units, decompile a type/method). This is an EXTERNAL-engine
connector, not part of the static grounding core; every response is untrusted data produced by the
caller's JEB instance. It degrades honestly when no endpoint is configured or it cannot be reached.
Design parity with REA's JEB integration (morluto/rea, MIT; REA uses REA_JEB_MCP_URL)."""
from __future__ import annotations

import json
import os

_ENV = "BINORACLE_JEB_MCP_URL"


def _endpoint(url: str = None):
    return url or os.environ.get(_ENV) or None


def _degrade(note: str) -> dict:
    return {"ok": False, "available": False, "tool": "jeb",
            "note": note + f" (arranca un cliente JEB sirviendo MCP y define {_ENV}=<url>)"}


def build_rpc(method: str, params: dict = None, rid: int = 1) -> bytes:
    """Serializa una peticion JSON-RPC 2.0. Pura y testeable sin red."""
    return json.dumps({"jsonrpc": "2.0", "id": rid, "method": method,
                       "params": params or {}}).encode("utf-8")


def parse_rpc(raw: bytes) -> dict:
    """Interpreta una respuesta JSON-RPC 2.0. Devuelve {ok, result} o {ok:False, error}. La salida
    es dato NO confiable (la produce el JEB del llamador)."""
    try:
        doc = json.loads(raw.decode("utf-8", "replace"))
    except Exception as e:
        return {"ok": False, "error": f"respuesta no-JSON: {e}"}
    if isinstance(doc, dict) and "error" in doc and doc["error"]:
        return {"ok": False, "error": doc["error"]}
    return {"ok": True, "result": (doc or {}).get("result")}


def jeb_rpc(method: str, params: dict = None, url: str = None, timeout: int = 60) -> dict:
    """Envia una peticion JSON-RPC al endpoint MCP de JEB. Degrada si no hay endpoint o no responde."""
    import urllib.request
    ep = _endpoint(url)
    if not ep:
        return _degrade("sin endpoint JEB configurado")
    try:
        req = urllib.request.Request(ep, data=build_rpc(method, params),
                                     headers={"Content-Type": "application/json",
                                              "Accept": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(16 * 1024 * 1024)
    except Exception as e:
        return {"ok": False, "available": True, "tool": "jeb",
                "note": f"no se pudo contactar el endpoint JEB ({ep}): {e}"}
    parsed = parse_rpc(raw)
    if not parsed.get("ok"):
        return {"ok": False, "available": True, "tool": "jeb", "note": f"error JEB: {parsed.get('error')}"}
    return {"ok": True, "available": True, "tool": "jeb", "method": method, "result": parsed["result"],
            "limitations": ["conector a un JEB externo del llamador; salida no confiable; no verificada"]}


def jeb_list_tools(url: str = None, timeout: int = 30) -> dict:
    """Lista las herramientas que expone el servidor MCP de JEB (JSON-RPC tools/list)."""
    return jeb_rpc("tools/list", {}, url=url, timeout=timeout)


def jeb_call(name: str, arguments: dict = None, url: str = None, timeout: int = 120) -> dict:
    """Invoca una herramienta del servidor MCP de JEB (JSON-RPC tools/call)."""
    return jeb_rpc("tools/call", {"name": name, "arguments": arguments or {}}, url=url, timeout=timeout)


# ── Android native helpers ───────────────────────────────────────────────────

def jeb_open_apk(apk_path: str, url: str = None, timeout: int = 300) -> dict:
    """Abre un APK en JEB y devuelve el unit handle del proyecto.

    JEB carga el APK, desempaqueta clases.dex, y detecta fragmentos nativos (.so).
    Requiere la herramienta 'open_file' del servidor JEB MCP.
    """
    return jeb_call("open_file", {"path": apk_path}, url=url, timeout=timeout)


def jeb_list_units(url: str = None, timeout: int = 60) -> dict:
    """Lista los units del proyecto activo (clases Dalvik, libs nativas, recursos)."""
    return jeb_call("list_units", {}, url=url, timeout=timeout)


def jeb_list_native_methods(lib_name: str, url: str = None, timeout: int = 120) -> dict:
    """Lista los métodos exportados de una librería nativa (.so) cargada en JEB.

    `lib_name` es el nombre del unit nativo tal como lo devuelve list_units,
    p.ej. 'lib/arm64-v8a/libtarget.so'.
    """
    return jeb_call("list_methods", {"unit": lib_name, "type": "native"}, url=url, timeout=timeout)


def jeb_decompile_native(lib_name: str, function_addr: str,
                          url: str = None, timeout: int = 180) -> dict:
    """Descompila una función nativa de un .so a pseudocódigo C usando JEB.

    `function_addr` es la dirección hexadecimal (con o sin '0x'), p.ej. '0x1234' o '1234'.
    Devuelve el pseudocódigo C en result['code'] si JEB lo soporta.
    """
    addr = function_addr if function_addr.startswith("0x") else "0x" + function_addr
    return jeb_call("decompile", {"unit": lib_name, "address": addr, "lang": "C"},
                    url=url, timeout=timeout)


def jeb_get_cfg(lib_name: str, function_addr: str,
                url: str = None, timeout: int = 120) -> dict:
    """Obtiene el Control Flow Graph (CFG) de una función nativa en formato JSON.

    Devuelve nodos y aristas del grafo; útil para análisis de flujo de control
    sin procesar el pseudocódigo completo.
    """
    addr = function_addr if function_addr.startswith("0x") else "0x" + function_addr
    return jeb_call("get_cfg", {"unit": lib_name, "address": addr}, url=url, timeout=timeout)


def jeb_xrefs(lib_name: str, function_addr: str,
               url: str = None, timeout: int = 60) -> dict:
    """Devuelve las referencias cruzadas (xrefs) a una función nativa."""
    addr = function_addr if function_addr.startswith("0x") else "0x" + function_addr
    return jeb_call("get_xrefs", {"unit": lib_name, "address": addr}, url=url, timeout=timeout)


def jeb_decompile_class(class_name: str, url: str = None, timeout: int = 120) -> dict:
    """Descompila una clase Dalvik/DEX a Java. `class_name` en formato JVM, p.ej. 'Lcom/example/Foo;'."""
    return jeb_call("decompile", {"type": "class", "name": class_name, "lang": "Java"},
                    url=url, timeout=timeout)


def jeb_search_strings(pattern: str, url: str = None, timeout: int = 60) -> dict:
    """Busca strings en todos los units del proyecto activo (Dalvik + nativo)."""
    return jeb_call("search_strings", {"pattern": pattern}, url=url, timeout=timeout)


def jeb_full_native_audit(apk_path: str, url: str = None) -> dict:
    """Auditoría completa de las librerías nativas de un APK.

    Flujo:
      1. Abre el APK en JEB.
      2. Lista todos los units.
      3. Para cada unit nativo (.so), lista sus métodos.
      4. Devuelve {ok, units, native_libs: [{lib, methods}]}.

    No descompila automáticamente para evitar timeouts; usa jeb_decompile_native()
    para funciones específicas después de revisar la lista de métodos.
    """
    r = jeb_open_apk(apk_path, url=url, timeout=300)
    if not r.get("ok"):
        return r
    units_r = jeb_list_units(url=url)
    if not units_r.get("ok"):
        return units_r
    units = units_r.get("result") or []
    if isinstance(units, dict):
        units = units.get("units") or []
    native_libs = []
    for u in units:
        name = u.get("name", "") if isinstance(u, dict) else str(u)
        if name.endswith(".so"):
            methods_r = jeb_list_native_methods(name, url=url)
            methods = (methods_r.get("result") or {}).get("methods", []) if methods_r.get("ok") else []
            native_libs.append({"lib": name, "methods": methods, "method_count": len(methods)})
    return {
        "ok": True, "available": True, "tool": "jeb",
        "apk": apk_path, "units": units, "native_libs": native_libs,
        "limitations": ["salida producida por JEB externo del llamador; dato no confiable"],
    }


def render_jeb(r: dict) -> str:
    out = ["## Conector JEB (motor externo)\n"]
    if not r.get("ok"):
        return "\n".join(out + [f"- No disponible: {r.get('note','')}"])
    out.append(f"- metodo: {r.get('method')}")
    res = r.get("result")
    try:
        pretty = json.dumps(res, indent=2, ensure_ascii=False)
    except Exception:
        pretty = str(res)
    out.append("```json\n" + pretty[:6000] + "\n```")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
