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
        return _degrade(f"sin endpoint JEB configurado")
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
