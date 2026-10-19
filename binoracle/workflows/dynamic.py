"""Runtime / dynamic analysis surfaces -- SEPARATE from binoracle's static grounding core.

Everything in this module executes or talks to a LIVE target: an Android device over adb, a process
via Frida, or a web page in a real browser. That is the opposite of the rest of binoracle (static,
offline, never runs the target), so it lives in its own module and is never part of the grounded
"verified by execution" exploit ledger. These are standard reverse-engineering tools; use them only
against targets you are AUTHORIZED to analyze. Each integration is caller-supplied: binoracle does
not bundle adb/Frida, drives one only when present, and degrades honestly (naming the tool + how to
get it) when absent. All output is UNTRUSTED data coming from a live, possibly hostile target --
treat it as such. The browser surface uses a locally launched Chromium (Playwright) and is bounded
by a timeout. Design parity with REA's device/browser/dynamic surfaces (morluto/rea, MIT)."""
from __future__ import annotations

_RUNTIME_LIMIT = ("superficie RUNTIME: habla con un objetivo EN VIVO (no es analisis estatico); "
                  "salida NO confiable; solo para objetivos autorizados")


def _adb_argv(serial, *rest):
    base = ["adb"]
    if serial:
        base += ["-s", serial]
    return base + list(rest)


def adb_devices(timeout: int = 20) -> dict:
    """Connected Android devices (adb devices -l). Caller-supplied adb."""
    from .callertools import run_caller_tool
    r = run_caller_tool(["adb", "devices", "-l"], timeout)
    if not r.get("ok"):
        return r
    devices = []
    for line in (r["stdout"] or "").splitlines()[1:]:
        line = line.strip()
        if not line or "\t" in line and line.endswith("offline"):
            pass
        parts = line.split()
        if len(parts) >= 2 and parts[1] in ("device", "offline", "unauthorized", "recovery"):
            devices.append({"serial": parts[0], "state": parts[1],
                            "info": " ".join(parts[2:])[:120]})
    return {"ok": True, "available": True, "tool": "adb", "devices": devices,
            "limitations": [_RUNTIME_LIMIT]}


def adb_packages(serial: str = None, third_party: bool = True, timeout: int = 30) -> dict:
    """Installed packages on a device (adb shell pm list packages). `third_party` adds -3."""
    from .callertools import run_caller_tool
    argv = _adb_argv(serial, "shell", "pm", "list", "packages")
    if third_party:
        argv.append("-3")
    r = run_caller_tool(argv, timeout)
    if not r.get("ok"):
        return r
    pkgs = sorted(ln.strip()[8:] for ln in (r["stdout"] or "").splitlines()
                  if ln.startswith("package:"))
    return {"ok": True, "available": True, "tool": "adb", "packages": pkgs,
            "package_count": len(pkgs), "third_party_only": third_party,
            "limitations": [_RUNTIME_LIMIT]}


def adb_processes(serial: str = None, timeout: int = 30) -> dict:
    """Running processes on a device (adb shell ps -A)."""
    from .callertools import run_caller_tool
    r = run_caller_tool(_adb_argv(serial, "shell", "ps", "-A"), timeout)
    if not r.get("ok"):
        return r
    lines = (r["stdout"] or "").splitlines()
    return {"ok": True, "available": True, "tool": "adb",
            "process_lines": lines[:400], "process_count": max(0, len(lines) - 1),
            "limitations": [_RUNTIME_LIMIT]}


def adb_logcat(serial: str = None, lines: int = 200, timeout: int = 30) -> dict:
    """A bounded dump of the device log (adb logcat -d -t N). Never streams."""
    from .callertools import run_caller_tool
    n = max(1, min(int(lines), 5000))
    r = run_caller_tool(_adb_argv(serial, "logcat", "-d", "-t", str(n)), timeout)
    if not r.get("ok"):
        return r
    return {"ok": True, "available": True, "tool": "adb",
            "log": (r["stdout"] or "")[-20000:], "requested_lines": n,
            "limitations": [_RUNTIME_LIMIT, "volcado unico (-d), no streaming"]}


def adb_getprop(serial: str = None, timeout: int = 20) -> dict:
    """Device fingerprint and key build properties (adb shell getprop)."""
    from .callertools import run_caller_tool
    r = run_caller_tool(_adb_argv(serial, "shell", "getprop"), timeout)
    if not r.get("ok"):
        return r
    props = {}
    for ln in (r["stdout"] or "").splitlines():
        # getprop lines look like: [ro.build.version.release]: [13]
        if ln.startswith("[") and "]: [" in ln:
            k, v = ln[1:].split("]: [", 1)
            props[k] = v.rstrip("]")
    notable = {k: props[k] for k in (
        "ro.product.model", "ro.product.manufacturer", "ro.build.version.release",
        "ro.build.version.sdk", "ro.build.fingerprint", "ro.boot.verifiedbootstate",
        "ro.debuggable", "ro.secure") if k in props}
    return {"ok": True, "available": True, "tool": "adb", "notable": notable,
            "property_count": len(props), "limitations": [_RUNTIME_LIMIT]}


def adb_apk_path(package: str, serial: str = None, timeout: int = 20) -> dict:
    """Locate a package's APK(s) on the device (adb shell pm path <pkg>). The returned device paths
    can be `adb pull`ed and then fed to binoracle's STATIC apk reader -- the dynamic->static bridge."""
    from .callertools import run_caller_tool
    if not package or "/" in package or " " in package:
        return {"ok": False, "available": True, "tool": "adb", "note": "nombre de paquete invalido"}
    r = run_caller_tool(_adb_argv(serial, "shell", "pm", "path", package), timeout)
    if not r.get("ok"):
        return r
    paths = [ln.strip()[8:] for ln in (r["stdout"] or "").splitlines() if ln.startswith("package:")]
    return {"ok": True, "available": True, "tool": "adb", "package": package, "apk_paths": paths,
            "limitations": [_RUNTIME_LIMIT,
                            "haz `adb pull <ruta>` y analizalo con `binoracle apk` / `caller-tool jadx` (estatico)"]}


def frida_devices(timeout: int = 20) -> dict:
    """Devices visible to Frida (frida-ls-devices): local, usb, remote."""
    from .callertools import run_caller_tool
    r = run_caller_tool(["frida-ls-devices"], timeout)
    if not r.get("ok"):
        return r
    return {"ok": True, "available": True, "tool": "frida-ls-devices",
            "output": (r["stdout"] or "")[:4000], "limitations": [_RUNTIME_LIMIT]}


def frida_processes(timeout: int = 20) -> dict:
    """Processes visible to Frida (frida-ps). Caller-supplied frida-tools. Enumeration only --
    this does NOT attach to or instrument any process."""
    from .callertools import run_caller_tool
    r = run_caller_tool(["frida-ps"], timeout)
    if not r.get("ok"):
        return r
    procs = []
    for ln in (r["stdout"] or "").splitlines()[1:]:
        parts = ln.split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            procs.append({"pid": int(parts[0]), "name": parts[1].strip()})
    return {"ok": True, "available": True, "tool": "frida-ps", "processes": procs[:500],
            "process_count": len(procs),
            "limitations": [_RUNTIME_LIMIT, "solo enumeracion; no se inyecta ni instrumenta nada"]}


def browser_observe(url: str, timeout_s: int = 20, screenshot: str = None,
                    secret_scan: bool = True) -> dict:
    """Observe a web page in a locally launched headless Chromium (Playwright). Captures, passively:
    final URL, title, loaded scripts (and their inline bodies), every network request AND its
    response (status + content-type), console messages, page metrics (forms/links/iframes), the set
    of cookies and localStorage keys set, and an optional screenshot saved to `screenshot`. With
    secret_scan it runs binoracle's IOC/secret heuristics over inline scripts and JSON/text
    responses bodies it can read. Loads a LIVE page -- authorized targets only; the preinstalled
    Chromium is used (no download). Nothing is submitted or clicked."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        return {"ok": False, "available": False, "tool": "playwright",
                "note": f"Playwright no disponible: {e}. pip install playwright"}
    requests, responses, console, scripts, inline_bodies = [], [], [], [], []
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            try:
                page = browser.new_context().new_page()
                page.on("request", lambda req: requests.append(
                    {"method": req.method, "url": req.url[:300], "type": req.resource_type}))
                page.on("response", lambda res: responses.append(
                    {"status": res.status, "url": res.url[:200],
                     "type": (res.headers or {}).get("content-type", "")[:60]}))
                page.on("console", lambda msg: console.append(
                    {"type": msg.type, "text": msg.text[:300]}))
                page.goto(url, wait_until="load", timeout=timeout_s * 1000)
                final_url, title = page.url, page.title()
                for s in page.query_selector_all("script"):
                    src = s.get_attribute("src")
                    if src:
                        scripts.append({"src": src[:300]})
                    else:
                        body = (s.inner_text() or "")[:20000]
                        scripts.append({"inline": True})
                        if body.strip():
                            inline_bodies.append(body)
                metrics = {
                    "forms": len(page.query_selector_all("form")),
                    "links": len(page.query_selector_all("a[href]")),
                    "iframes": len(page.query_selector_all("iframe")),
                    "inputs": len(page.query_selector_all("input")),
                }
                try:
                    storage_keys = page.evaluate(
                        "() => { try { return Object.keys(localStorage); } catch(e){ return []; } }") or []
                except Exception:
                    storage_keys = []
                try:
                    cookies = [c.get("name") for c in page.context.cookies()]
                except Exception:
                    cookies = []
                if screenshot:
                    try:
                        page.screenshot(path=screenshot, full_page=True)
                    except Exception:
                        screenshot = None
            finally:
                browser.close()
    except Exception as e:
        return {"ok": False, "available": True, "tool": "playwright",
                "note": f"fallo al observar la pagina: {e}"}
    hosts, statuses = {}, {}
    from urllib.parse import urlsplit
    for rq in requests:
        h = urlsplit(rq["url"]).netloc
        if h:
            hosts[h] = hosts.get(h, 0) + 1
    for rs in responses:
        statuses[str(rs["status"])] = statuses.get(str(rs["status"]), 0) + 1
    secrets = []
    if secret_scan and inline_bodies:
        try:
            from .iocscan import _PATTERNS, _redact
            seen = set()
            for body in inline_bodies:
                for name, rx, gate in _PATTERNS:
                    if name in ("ipv4", "email"):
                        continue
                    m = rx.search(body)
                    if m:
                        val = m.group(1) if (gate and m.groups()) else m.group(0)
                        key = (name, val)
                        if val and key not in seen:
                            seen.add(key)
                            secrets.append({"kind": name, "evidence": _redact(val)})
        except Exception:
            pass
    return {"ok": True, "available": True, "tool": "playwright", "final_url": final_url,
            "title": title, "script_count": len(scripts),
            "scripts": [s for s in scripts if s.get("src")][:60],
            "inline_scripts": sum(1 for s in scripts if s.get("inline")),
            "request_count": len(requests), "requests": requests[:80],
            "response_count": len(responses), "statuses": statuses,
            "console": console[:40], "metrics": metrics,
            "cookies": cookies[:40], "storage_keys": storage_keys[:40],
            "hosts": hosts, "screenshot": screenshot, "secrets": secrets[:30],
            "limitations": [_RUNTIME_LIMIT, "observacion pasiva: no se envian formularios ni se "
                            "interactua; red real alcanzada por el navegador; secretos por heuristica"]}


def render_dynamic(kind: str, r: dict) -> str:
    out = [f"## Analisis dinamico (runtime): {kind}\n"]
    if not r.get("ok"):
        return "\n".join(out + [f"- No disponible: {r.get('note','')}"])
    if kind == "adb-devices":
        devs = r.get("devices") or []
        out.append(f"- dispositivos: {len(devs)}")
        for d in devs:
            out.append(f"  - {d['serial']} [{d['state']}] {d.get('info','')}")
    elif kind == "adb-packages":
        out.append(f"- paquetes{' (3rd-party)' if r.get('third_party_only') else ''}: {r.get('package_count')}")
        for p in (r.get("packages") or [])[:80]:
            out.append(f"  - {p}")
    elif kind == "adb-processes":
        out.append(f"- procesos: {r.get('process_count')}")
        for ln in (r.get("process_lines") or [])[:60]:
            out.append(f"  {ln}")
    elif kind == "adb-logcat":
        out.append(f"- logcat (ultimas {r.get('requested_lines')} lineas):\n```\n{r.get('log','')[:4000]}\n```")
    elif kind == "adb-getprop":
        out.append(f"- propiedades: {r.get('property_count')}")
        for k, v in (r.get("notable") or {}).items():
            out.append(f"  - {k}: {v}")
    elif kind == "adb-apk-path":
        out.append(f"- paquete: {r.get('package')}")
        for p in (r.get("apk_paths") or []):
            out.append(f"  - {p}")
    elif kind == "frida-devices":
        out.append("```\n" + (r.get("output", "") or "") + "\n```")
    elif kind == "frida-ps":
        out.append(f"- procesos visibles a Frida: {r.get('process_count')}")
        for p in (r.get("processes") or [])[:60]:
            out.append(f"  - {p['pid']}  {p['name']}")
    elif kind == "browser":
        out.append(f"- URL final: {r.get('final_url')}")
        out.append(f"- titulo: {r.get('title')}")
        m = r.get("metrics") or {}
        if m:
            out.append(f"- DOM: {m.get('forms')} forms, {m.get('inputs')} inputs, "
                       f"{m.get('links')} links, {m.get('iframes')} iframes")
        out.append(f"- scripts: {r.get('script_count')} ({r.get('inline_scripts')} inline)")
        for s in (r.get("scripts") or [])[:30]:
            out.append(f"  - {s.get('src')}")
        hosts = r.get("hosts") or {}
        if hosts:
            out.append("- hosts contactados: " + ", ".join(f"{h}({n})" for h, n in
                                                            sorted(hosts.items(), key=lambda kv: -kv[1])[:15]))
        out.append(f"- peticiones: {r.get('request_count')}  |  respuestas: {r.get('response_count')}  |  "
                   f"codigos: " + ", ".join(f"{s}x{n}" for s, n in sorted((r.get('statuses') or {}).items())))
        if r.get("cookies"):
            out.append(f"- cookies: {', '.join(r['cookies'][:20])}")
        if r.get("storage_keys"):
            out.append(f"- localStorage: {', '.join(r['storage_keys'][:20])}")
        con = r.get("console") or []
        if con:
            out.append(f"- consola ({len(con)}): " + "; ".join(f"[{c['type']}] {c['text'][:60]}" for c in con[:8]))
        sec = r.get("secrets") or []
        if sec:
            out.append(f"\n### Secretos en scripts inline (heuristica): {len(sec)}")
            for s in sec[:20]:
                out.append(f"- **{s['kind']}**: `{s['evidence']}`")
        if r.get("screenshot"):
            out.append(f"- captura de pantalla: {r['screenshot']}")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
