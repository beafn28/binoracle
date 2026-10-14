"""Android resources + mobile application graph, via apktool-decoded resources.

REA exposes `decode_android_resources` and a mobile application-graph projection. binoracle grounds
them on apktool -- a DECODER (it does not run the app) the caller supplies -- which turns the binary
AXML AndroidManifest and the resource table into text; binoracle then:

* `decode_android_resources`: summarizes the decoded `res/` tree (layouts, drawables, values) and
  the manifest's package/permissions;
* `project_mobile_application_graph`: parses the decoded AndroidManifest and builds a component graph
  -- the app's activities / services / receivers / providers, each with its `exported` flag and the
  intent-filter actions/categories it answers (the app's external entry surface).

The manifest XML parsing is pure (testable without apktool); the apktool run degrades honestly when
the tool is absent. Decoded resources and manifest are untrusted data."""
from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_CACHE: dict = {}


def _cleanup():
    for d in list(_CACHE.values()):
        shutil.rmtree(d, ignore_errors=True)
    _CACHE.clear()


atexit.register(_cleanup)


def _apktool_decode(apk: str, timeout: int = 240):
    """Decode an APK with apktool into a cached dir; return (dir, None) or ('', reason)."""
    if shutil.which("apktool") is None:
        return "", "apktool"
    try:
        key = os.path.abspath(apk)
        mtime = os.path.getmtime(key)
    except OSError as e:
        return "", f"no se pudo abrir el APK: {e}"
    ck = f"{key}:{mtime}"
    if ck in _CACHE and os.path.isdir(_CACHE[ck]):
        return _CACHE[ck], None
    tmp = tempfile.mkdtemp(prefix="binoracle_apktool_")
    out = os.path.join(tmp, "out")
    try:
        subprocess.run(["apktool", "d", "-f", "-o", out, apk], capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmp, ignore_errors=True)
        return "", f"apktool excedio {timeout}s"
    except Exception as e:
        shutil.rmtree(tmp, ignore_errors=True)
        return "", f"fallo apktool: {e}"
    if not os.path.isdir(out):
        shutil.rmtree(tmp, ignore_errors=True)
        return "", "apktool no produjo salida"
    _CACHE[ck] = out
    return out, None


def _missing(reason: str) -> dict:
    if reason == "apktool":
        return {"ok": False, "available": False, "tool": "android_manifest",
                "note": "apktool ausente (https://apktool.org); decodifica recursos/AXML, no ejecuta la app"}
    return {"ok": False, "available": True, "tool": "android_manifest", "note": reason}


def parse_manifest_xml(xml_text: str) -> dict:
    """Parse a decoded (text) AndroidManifest.xml into package, permissions and components with their
    exported flag and intent-filter actions/categories. Pure; no tool needed."""
    try:
        root = ET.fromstring(xml_text)
    except Exception as e:
        return {"ok": False, "note": f"AndroidManifest no parseable: {e}"}
    pkg = root.get("package")
    perms = [e.get(_ANDROID_NS + "name") for e in root.iter("uses-permission")
             if e.get(_ANDROID_NS + "name")]
    app = root.find("application")
    components = []
    if app is not None:
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for el in app.iter(tag):
                name = el.get(_ANDROID_NS + "name")
                exported = el.get(_ANDROID_NS + "exported")
                actions, cats = [], []
                for intent in el.iter("intent-filter"):
                    for a in intent.iter("action"):
                        v = a.get(_ANDROID_NS + "name")
                        if v:
                            actions.append(v)
                    for c in intent.iter("category"):
                        v = c.get(_ANDROID_NS + "name")
                        if v:
                            cats.append(v)
                # exported defaults to true when it has an intent-filter and the attr is unset
                is_exp = (exported == "true") if exported is not None else bool(actions)
                components.append({"type": tag, "name": name, "exported": is_exp,
                                   "actions": sorted(set(actions)), "categories": sorted(set(cats))})
    return {"ok": True, "package": pkg, "permissions": sorted(set(perms)), "components": components}


def project_mobile_application_graph(apk: str) -> dict:
    """project_mobile_application_graph: the app's component graph (activities/services/receivers/
    providers), each with its exported flag and the intent actions it answers."""
    d, err = _apktool_decode(apk)
    if not d:
        return _missing(err)
    mpath = os.path.join(d, "AndroidManifest.xml")
    try:
        with open(mpath, "r", encoding="utf-8", errors="replace") as f:
            xml_text = f.read()
    except Exception as e:
        return {"ok": False, "available": True, "tool": "android_manifest",
                "note": f"sin AndroidManifest decodificado: {e}"}
    m = parse_manifest_xml(xml_text)
    if not m.get("ok"):
        return {"ok": False, "available": True, "tool": "android_manifest", "note": m.get("note")}
    comps = m["components"]
    exported = [c for c in comps if c["exported"]]
    edges = []
    pkg = m["package"] or "app"
    for c in comps:
        edges.append({"from": pkg, "to": c["name"], "kind": c["type"], "exported": c["exported"]})
        for a in c["actions"]:
            edges.append({"from": c["name"], "to": a, "kind": "intent-action", "exported": c["exported"]})
    return {"ok": True, "available": True, "tool": "android_manifest", "package": pkg,
            "permissions": m["permissions"], "component_count": len(comps),
            "exported_count": len(exported), "components": comps, "edges": edges[:2000],
            "limitations": ["grafo de componentes desde el manifest decodificado por apktool; "
                            "no sigue llamadas internas; exported inferido cuando el atributo falta"]}


def decode_android_resources(apk: str) -> dict:
    """decode_android_resources: summarize the decoded res/ tree (layouts/drawables/values) and the
    manifest package/permissions, via apktool."""
    d, err = _apktool_decode(apk)
    if not d:
        return _missing(err)
    res = os.path.join(d, "res")
    buckets = {}
    total = 0
    if os.path.isdir(res):
        for entry in sorted(os.listdir(res)):
            sub = os.path.join(res, entry)
            if os.path.isdir(sub):
                n = sum(len(files) for _, _, files in os.walk(sub))
                buckets[entry] = n
                total += n
    pkg = perms = None
    mpath = os.path.join(d, "AndroidManifest.xml")
    if os.path.isfile(mpath):
        try:
            with open(mpath, "r", encoding="utf-8", errors="replace") as f:
                m = parse_manifest_xml(f.read())
            if m.get("ok"):
                pkg, perms = m["package"], m["permissions"]
        except Exception:
            pass
    return {"ok": True, "available": True, "tool": "android_manifest", "package": pkg,
            "permissions": perms or [], "resource_total": total, "resource_buckets": buckets,
            "limitations": ["recursos decodificados por apktool; apktool decodifica, no ejecuta la app"]}


def render_android_manifest(kind: str, r: dict) -> str:
    out = [f"## Android ({kind})\n"]
    if not r.get("ok"):
        return "\n".join(out + [f"- No disponible: {r.get('note','')}"])
    if kind == "graph":
        out.append(f"- paquete: `{r.get('package')}` | componentes: {r['component_count']} "
                   f"(exportados: {r['exported_count']}) | permisos: {len(r['permissions'])}")
        for c in r["components"][:40]:
            exp = " [exported]" if c["exported"] else ""
            acts = (" <- " + ", ".join(c["actions"][:3])) if c["actions"] else ""
            out.append(f"  - {c['type']} {c['name']}{exp}{acts}")
    elif kind == "resources":
        out.append(f"- paquete: `{r.get('package')}` | recursos: {r['resource_total']} | "
                   f"permisos: {len(r['permissions'])}")
        for k, v in sorted(r["resource_buckets"].items()):
            out.append(f"  - {k}: {v}")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
