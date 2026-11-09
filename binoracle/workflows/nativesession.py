"""Stateful native analysis session: a named handle over the cached radare2 analysis.

binoracle is stateless per call by design, but REA's `open_binary` / `binary_session` /
`inspect_analysis_view` / `close_binary` model is useful ergonomics: analyse once, query many times by
a short handle, then free the engine. This layer provides exactly that WITHOUT changing the grounding
model -- it is a thin registry over the shared `r2session` oracle (which already caches one `aaa` per
file by mtime):

* `open_binary` validates the file, warms the r2 analysis, and returns a session id (handle) plus the
  initial analysis view;
* `inspect_analysis_view` / `binary_session` return the view / status for a handle (or a raw path);
* `close_binary` frees the underlying r2 process and retires the handle;
* `list_binary_sessions` lists the open handles.

A handle resolves back to its path, so the function-level query tools can be driven by handle too.
State is process-local (this server), holds no secrets, and never executes the target -- r2 only
disassembles. For AUTHORIZED analysis."""
from __future__ import annotations

import hashlib
import os
import threading
import time

from ..oracles import r2session
from .nativequery import binary_overview

_LOCK = threading.Lock()
_SESSIONS: dict = {}          # sid -> {binary, label, opened, warmed, closed}


def _sid(path: str) -> str:
    h = hashlib.sha1((os.path.abspath(path) + str(time.time())).encode()).hexdigest()[:12]
    return "bin_" + h


def open_binary(binary: str, label: str = None) -> dict:
    """open_binary: register a binary, warm its radare2 analysis, and return a session handle + the
    initial analysis view. The heavy `aaa` is cached by the r2 oracle, so later queries are fast."""
    if not binary or not os.path.isfile(binary):
        return {"ok": False, "tool": "binary_session", "note": f"fichero no encontrado: {binary}"}
    warmed = r2session.get(binary) is not None       # triggers + caches the analysis
    with _LOCK:
        sid = _sid(binary)
        _SESSIONS[sid] = {"binary": os.path.abspath(binary), "label": label,
                          "opened": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                          "warmed": warmed, "closed": False}
    view = binary_overview(binary) if warmed else {"ok": False, "note": "radare2 no disponible"}
    return {"ok": True, "tool": "binary_session", "session_id": sid, "binary": binary,
            "label": label, "warmed": warmed, "view": view,
            "note": ("sesion abierta y analisis r2 precalentado" if warmed
                     else "sesion abierta; radare2 no disponible (la vista degrada)"),
            "limitations": ["estado local del servidor; r2 desensambla, no ejecuta el binario"]}


def resolve(ref: str):
    """Map a session id OR a raw path to a binary path. None if unknown/closed."""
    if not ref:
        return None
    with _LOCK:
        s = _SESSIONS.get(ref)
    if s and not s["closed"]:
        return s["binary"]
    if os.path.isfile(ref):
        return ref
    return None


def inspect_analysis_view(ref: str) -> dict:
    """inspect_analysis_view: the static analysis view (arch/bits/mitigations/entry + counts) for a
    session handle or a raw path."""
    path = resolve(ref)
    if path is None:
        return {"ok": False, "tool": "binary_session", "note": f"sesion/ruta no encontrada: {ref}"}
    view = binary_overview(path)
    view["session_ref"] = ref
    return view


def binary_session(ref: str) -> dict:
    """binary_session: status of a session handle (or lookup by path)."""
    with _LOCK:
        if ref in _SESSIONS:
            s = dict(_SESSIONS[ref])
            s.update({"ok": True, "tool": "binary_session", "session_id": ref})
            return s
    path = resolve(ref)
    if path:
        return {"ok": True, "tool": "binary_session", "binary": path, "closed": False,
                "note": "sin handle de sesion; ruta valida (sesion implicita)"}
    return {"ok": False, "tool": "binary_session", "note": f"sesion no encontrada: {ref}"}


def close_binary(sid: str) -> dict:
    """close_binary: free the underlying radare2 process and retire the handle."""
    with _LOCK:
        s = _SESSIONS.get(sid)
        if not s:
            return {"ok": False, "tool": "binary_session", "note": f"sesion no encontrada: {sid}"}
        binary = s["binary"]
        s["closed"] = True
    try:
        r2session.close(binary)                      # free the cached r2 process
    except Exception:
        pass
    return {"ok": True, "tool": "binary_session", "session_id": sid, "closed": True,
            "note": "sesion cerrada; proceso r2 liberado"}


def list_binary_sessions() -> dict:
    """list_binary_sessions: the open (and recently closed) session handles."""
    with _LOCK:
        items = [{"session_id": k, "binary": v["binary"], "label": v["label"],
                  "opened": v["opened"], "warmed": v["warmed"], "closed": v["closed"]}
                 for k, v in _SESSIONS.items()]
    open_n = sum(1 for i in items if not i["closed"])
    return {"ok": True, "tool": "binary_session", "open": open_n, "total": len(items),
            "sessions": items}


def render_session(kind: str, r: dict) -> str:
    out = [f"## Sesion de binario ({kind})\n"]
    if not r.get("ok"):
        return "\n".join(out + [f"- No disponible: {r.get('note','')}"])
    if kind == "open":
        out.append(f"- handle: `{r['session_id']}` | binario: `{r['binary']}`"
                   + (f" ({r['label']})" if r.get("label") else ""))
        out.append(f"- r2 precalentado: {r['warmed']}")
        v = r.get("view") or {}
        if v.get("ok"):
            out.append(f"- vista: {v.get('arch')}/{v.get('bits')}-bit {v.get('type')} | "
                       f"funciones={v.get('function_count')} imports={v.get('import_count')} "
                       f"NX={v.get('nx')} PIC={v.get('pic')}")
        out.append("- " + r.get("note", ""))
    elif kind == "view":
        out.append(f"- `{r.get('session_ref')}` -> {r.get('arch')}/{r.get('bits')}-bit {r.get('type')} "
                   f"({r.get('os')})")
        out.append(f"- PIC={r.get('pic')} NX={r.get('nx')} canary={r.get('canary')} | "
                   f"funciones={r.get('function_count')} imports={r.get('import_count')} "
                   f"exports={r.get('export_count')} secciones={r.get('section_count')}")
    elif kind == "status":
        out.append(f"- `{r.get('session_id', '?')}` binario `{r.get('binary')}` | "
                   f"cerrada: {r.get('closed')} | abierta: {r.get('opened','?')}")
        if r.get("note"):
            out.append("- " + r["note"])
    elif kind == "close":
        out.append(f"- `{r['session_id']}` cerrada; {r.get('note','')}")
    elif kind == "list":
        out.append(f"- sesiones: {r['open']} abierta(s) de {r['total']}")
        for s in r["sessions"][:40]:
            flag = "cerrada" if s["closed"] else "abierta"
            out.append(f"  - `{s['session_id']}` [{flag}] {s['binary']}"
                       + (f" ({s['label']})" if s.get("label") else ""))
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
