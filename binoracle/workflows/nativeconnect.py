"""IDA Pro and Hopper connectors: talk to a caller-started client that serves MCP (external engines).

IDA Pro and Hopper are commercial reverse-engineering platforms. Like REA, binoracle does NOT embed
them: the caller runs their own IDA/Hopper instance exposing an MCP endpoint (IDA via an MCP plugin,
Hopper via its scripting bridge) and points binoracle at it with an env var or the `url` argument.
binoracle then speaks JSON-RPC 2.0 over HTTP to list the engine's tools and call them (decompile a
function, list xrefs, read the call graph, run a regex search, etc.). These are EXTERNAL-engine
connectors, not part of the static grounding core; every response is untrusted data produced by the
caller's instance. They degrade honestly when no endpoint is configured or it cannot be reached.
Design parity with REA's IDA/Hopper providers (morluto/rea, MIT)."""
from __future__ import annotations

import json
import os

from .jebconnect import build_rpc, parse_rpc   # generic JSON-RPC 2.0 codec, reused

_ENGINES = {
    "ida": {"env": "BINORACLE_IDA_MCP_URL", "label": "IDA Pro"},
    "hopper": {"env": "BINORACLE_HOPPER_MCP_URL", "label": "Hopper"},
}


def _endpoint(engine: str, url: str = None):
    env = _ENGINES[engine]["env"]
    return url or os.environ.get(env) or None


def _engine_rpc(engine: str, method: str, params: dict = None, url: str = None, timeout: int = 60) -> dict:
    """Send a JSON-RPC request to the engine's MCP endpoint. Degrades if unset/unreachable."""
    import urllib.request
    env = _ENGINES[engine]["env"]
    label = _ENGINES[engine]["label"]
    ep = _endpoint(engine, url)
    if not ep:
        return {"ok": False, "available": False, "tool": engine,
                "note": f"sin endpoint {label} configurado "
                        f"(arranca {label} sirviendo MCP y define {env}=<url>)"}
    try:
        req = urllib.request.Request(ep, data=build_rpc(method, params),
                                     headers={"Content-Type": "application/json",
                                              "Accept": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(16 * 1024 * 1024)
    except Exception as e:
        return {"ok": False, "available": True, "tool": engine,
                "note": f"no se pudo contactar el endpoint {label} ({ep}): {e}"}
    parsed = parse_rpc(raw)
    if not parsed.get("ok"):
        return {"ok": False, "available": True, "tool": engine,
                "note": f"error {label}: {parsed.get('error')}"}
    return {"ok": True, "available": True, "tool": engine, "engine": label, "method": method,
            "result": parsed["result"],
            "limitations": [f"conector a un {label} externo del llamador; salida no confiable; no verificada"]}


# --- IDA Pro ---------------------------------------------------------------------------------------

def ida_list_tools(url: str = None, timeout: int = 30) -> dict:
    """Lista las herramientas que expone el servidor MCP de IDA (JSON-RPC tools/list)."""
    return _engine_rpc("ida", "tools/list", {}, url=url, timeout=timeout)


def ida_call(name: str, arguments: dict = None, url: str = None, timeout: int = 120) -> dict:
    """Invoca una herramienta del servidor MCP de IDA (JSON-RPC tools/call)."""
    return _engine_rpc("ida", "tools/call", {"name": name, "arguments": arguments or {}},
                       url=url, timeout=timeout)


def render_ida(r: dict) -> str:
    return _render_engine(r, "IDA Pro")


# --- Hopper ----------------------------------------------------------------------------------------

def hopper_list_tools(url: str = None, timeout: int = 30) -> dict:
    """Lista las herramientas que expone el servidor MCP de Hopper (JSON-RPC tools/list)."""
    return _engine_rpc("hopper", "tools/list", {}, url=url, timeout=timeout)


def hopper_call(name: str, arguments: dict = None, url: str = None, timeout: int = 120) -> dict:
    """Invoca una herramienta del servidor MCP de Hopper (JSON-RPC tools/call)."""
    return _engine_rpc("hopper", "tools/call", {"name": name, "arguments": arguments or {}},
                       url=url, timeout=timeout)


def render_hopper(r: dict) -> str:
    return _render_engine(r, "Hopper")


def _render_engine(r: dict, label: str) -> str:
    out = [f"## Conector {label} (motor externo)\n"]
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
