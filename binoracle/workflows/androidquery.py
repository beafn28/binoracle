"""First-class Android class/method queries over JADX-decompiled sources.

REA exposes Android inspection as per-class/method tools (`inspect_android_class`,
`inspect_android_method`, `inspect_android_package`, `search_android_classes`,
`trace_android_references`). binoracle grounds them on JADX -- a DECOMPILER (it does not run the
app) that the caller supplies -- decompiling the APK once (cached per file by mtime) and then
querying the recovered `.java` tree. Everything degrades honestly when JADX is absent. The
decompiled source and the app's own identifiers are untrusted data."""
from __future__ import annotations

import atexit
import os
import re
import shutil
import subprocess
import tempfile

_CACHE: dict = {}          # apk abspath -> (src_root, mtime)


def _cleanup():
    for root, _ in list(_CACHE.values()):
        shutil.rmtree(os.path.dirname(root) if os.path.basename(root) == "sources" else root,
                      ignore_errors=True)
    _CACHE.clear()


atexit.register(_cleanup)


def _decompile(apk: str, timeout: int = 240):
    """Decompile the APK with JADX into a cached dir; return the sources root, or ('', reason)."""
    if shutil.which("jadx") is None:
        return "", "jadx"
    try:
        key = os.path.abspath(apk)
        mtime = os.path.getmtime(key)
    except OSError as e:
        return "", f"no se pudo abrir el APK: {e}"
    ent = _CACHE.get(key)
    if ent and ent[1] == mtime and os.path.isdir(ent[0]):
        return ent[0], None
    tmp = tempfile.mkdtemp(prefix="binoracle_androidq_")
    try:
        subprocess.run(["jadx", "--no-res", "-d", tmp, apk], capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmp, ignore_errors=True)
        return "", f"jadx excedio {timeout}s"
    except Exception as e:
        shutil.rmtree(tmp, ignore_errors=True)
        return "", f"fallo jadx: {e}"
    src = os.path.join(tmp, "sources")
    root = src if os.path.isdir(src) else tmp
    _CACHE[key] = (root, mtime)
    return root, None


def _iter_java(root: str):
    for base, _dirs, files in os.walk(root):
        for fn in files:
            if fn.endswith(".java"):
                yield os.path.join(base, fn)


def _classname(root: str, path: str) -> str:
    rel = os.path.relpath(path, root)
    return rel[:-5].replace(os.sep, ".")


def _missing(reason: str) -> dict:
    if reason == "jadx":
        return {"ok": False, "available": False, "tool": "android_query",
                "note": "JADX ausente (instala jadx: https://github.com/skylot/jadx); "
                        "JADX decompila, no ejecuta la app"}
    return {"ok": False, "available": True, "tool": "android_query", "note": reason}


def search_android_classes(apk: str, query: str = "", limit: int = 200) -> dict:
    """search_android_classes: list decompiled classes whose fully-qualified name matches a substring."""
    root, err = _decompile(apk)
    if not root:
        return _missing(err)
    q = (query or "").lower()
    hits = []
    for p in _iter_java(root):
        cn = _classname(root, p)
        if not q or q in cn.lower():
            hits.append(cn)
            if len(hits) >= limit:
                break
    return {"ok": True, "available": True, "tool": "android_query", "query": query,
            "class_count": len(hits), "classes": sorted(hits),
            "limitations": ["clases decompiladas por JADX; JADX decompila, no ejecuta la app"]}


def inspect_android_class(apk: str, classname: str, max_bytes: int = 200000) -> dict:
    """inspect_android_class: the decompiled Java of a class, plus its declared methods."""
    root, err = _decompile(apk)
    if not root:
        return _missing(err)
    target = classname.strip()
    want = os.path.join(root, target.replace(".", os.sep) + ".java")
    path = want if os.path.isfile(want) else None
    if path is None:                       # fall back to a suffix match (inner/relocated classes)
        for p in _iter_java(root):
            if _classname(root, p) == target or _classname(root, p).endswith("." + target):
                path = p
                break
    if path is None:
        return {"ok": False, "available": True, "tool": "android_query",
                "note": f"clase no encontrada: {classname}"}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            code = f.read(max_bytes)
    except Exception as e:
        return {"ok": False, "available": True, "tool": "android_query", "note": str(e)}
    methods = re.findall(r"(?:public|private|protected|static|final|\s)+[\w<>\[\].,\s]+?\b(\w+)\s*\([^;{]*\)\s*\{",
                         code)
    return {"ok": True, "available": True, "tool": "android_query", "class": _classname(root, path),
            "methods": sorted({m for m in methods if m not in ("if", "for", "while", "switch", "catch")})[:120],
            "java": code,
            "limitations": ["Java decompilado por JADX (aproximado); JADX decompila, no ejecuta"]}


def _extract_method(code: str, method: str):
    """Return the source slice of the first method named `method` (brace-matched). None if absent."""
    import re as _re
    for m in _re.finditer(r"\b" + _re.escape(method) + r"\s*\([^;{)]*\)\s*(?:throws[^\{;]*)?\{", code):
        start = m.start()
        i = code.index("{", m.start())
        depth = 0
        for j in range(i, len(code)):
            if code[j] == "{":
                depth += 1
            elif code[j] == "}":
                depth -= 1
                if depth == 0:
                    return code[start:j + 1]
    return None


def inspect_android_method(apk: str, classname: str, method: str) -> dict:
    """inspect_android_method: the decompiled body of one method of a class (brace-matched from the
    JADX Java). Static; degrades if JADX is absent or the class/method is not found."""
    cls = inspect_android_class(apk, classname)
    if not cls.get("ok"):
        return cls
    body = _extract_method(cls.get("java", ""), method)
    if body is None:
        return {"ok": False, "available": True, "tool": "android_query",
                "note": f"metodo no encontrado en {classname}: {method}",
                "methods_available": cls.get("methods", [])}
    return {"ok": True, "available": True, "tool": "android_query", "class": cls["class"],
            "method": method, "body": body[:20000],
            "limitations": ["cuerpo decompilado por JADX (aproximado); JADX decompila, no ejecuta"]}


def inspect_android_package(apk: str, package: str, limit: int = 400) -> dict:
    """inspect_android_package: the classes declared under a package prefix."""
    root, err = _decompile(apk)
    if not root:
        return _missing(err)
    pkg = package.strip().rstrip(".")
    hits = []
    for p in _iter_java(root):
        cn = _classname(root, p)
        if cn == pkg or cn.startswith(pkg + "."):
            hits.append(cn)
            if len(hits) >= limit:
                break
    return {"ok": True, "available": True, "tool": "android_query", "package": pkg,
            "class_count": len(hits), "classes": sorted(hits),
            "limitations": ["clases decompiladas por JADX"]}


def trace_android_references(apk: str, name: str, limit: int = 200) -> dict:
    """trace_android_references: every decompiled site that mentions an identifier (class/method/
    field/string), as class:line with the matching line. A static grep over JADX output."""
    root, err = _decompile(apk)
    if not root:
        return _missing(err)
    needle = name.strip()
    if not needle:
        return {"ok": False, "available": True, "tool": "android_query", "note": "nombre vacio"}
    rx = re.compile(r"\b" + re.escape(needle) + r"\b")
    refs = []
    for p in _iter_java(root):
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, 1):
                    if rx.search(line):
                        refs.append({"class": _classname(root, p), "line": i,
                                     "text": line.strip()[:200]})
                        if len(refs) >= limit:
                            break
        except Exception:
            continue
        if len(refs) >= limit:
            break
    return {"ok": True, "available": True, "tool": "android_query", "name": needle,
            "ref_count": len(refs), "references": refs,
            "limitations": ["referencias estaticas sobre la decompilacion de JADX; "
                            "reflexion/dynamic dispatch no se resuelven"]}


def render_android_query(kind: str, r: dict) -> str:
    out = [f"## Consulta Android (JADX): {kind}\n"]
    if not r.get("ok"):
        return "\n".join(out + [f"- No disponible: {r.get('note','')}"])
    if kind in ("search", "package"):
        label = r.get("query") if kind == "search" else r.get("package")
        out.append(f"- `{label}`: {r['class_count']} clase(s)")
        for c in r["classes"][:60]:
            out.append(f"  - {c}")
    elif kind == "class":
        out.append(f"- clase `{r['class']}` | metodos: {len(r.get('methods') or [])}")
        if r.get("methods"):
            out.append(f"- metodos: {', '.join(r['methods'][:30])}")
        out.append("\n```java\n" + (r.get("java", "")[:4000]) + "\n```")
    elif kind == "references":
        out.append(f"- `{r['name']}`: {r['ref_count']} referencia(s)")
        for x in r["references"][:40]:
            out.append(f"  - {x['class']}:{x['line']}  {x['text']}")
    elif kind == "method":
        out.append(f"- `{r['class']}#{r['method']}`")
        out.append("\n```java\n" + (r.get("body", "")[:4000]) + "\n```")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
