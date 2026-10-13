"""Static HAR (HTTP Archive) reader: requests, responses and exposed secrets.

Parses a saved `.har` capture (JSON) with no network and nothing executed: the request/response
inventory (method, URL, status, mime, size), the hosts contacted, and -- most useful for app RE --
secrets exposed in URLs, headers or bodies (Authorization/Bearer, api_key/token/password params,
JWTs, AWS-style keys). Secret flags are heuristic and reported as such. Built-in json only. Design
adapted from REA's saved-capture tooling (morluto/rea, MIT); re-implemented in Python."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

_SECRET_PATTERNS = [
    ("authorization-header", re.compile(r"^authorization$", re.I), None),
    ("bearer-token", None, re.compile(r"bearer\s+[A-Za-z0-9._\-]{8,}", re.I)),
    ("jwt", None, re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}")),
    ("api-key-param", None, re.compile(r"(?:api[_\-]?key|apikey|access[_\-]?token|token|secret|"
                                       r"password|passwd|pwd)=[^&\s\"']{4,}", re.I)),
    ("aws-access-key", None, re.compile(r"AKIA[0-9A-Z]{16}")),
    ("slack-token", None, re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("google-api-key", None, re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
]


def _redact(s: str) -> str:
    s = s if len(s) <= 80 else s[:77] + "..."
    return s


def _scan_secrets(where: str, text: str, out: list):
    if not text:
        return
    for name, _keyre, valre in _SECRET_PATTERNS:
        if valre is None:
            continue
        m = valre.search(text)
        if m:
            out.append({"kind": name, "where": where, "evidence": _redact(m.group(0))})


def inspect_har(path: str, max_entries: int = 500) -> dict:
    """Parse a HAR capture. Returns {ok, is_har, entries, hosts, methods, status_codes, secrets}."""
    import json
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            doc = json.load(f)
    except Exception as e:
        return {"ok": True, "is_har": False, "note": f"no es JSON HAR valido: {e}"}
    log = doc.get("log") if isinstance(doc, dict) else None
    if not isinstance(log, dict) or "entries" not in log:
        return {"ok": True, "is_har": False, "note": "sin 'log.entries' (no es un HAR)"}
    entries_in = log.get("entries") or []
    entries, hosts, methods, status_codes, secrets = [], {}, {}, {}, []
    for e in entries_in[:max_entries]:
        req = e.get("request") or {}
        resp = e.get("response") or {}
        url = req.get("url") or ""
        method = req.get("method") or "?"
        status = resp.get("status")
        content = resp.get("content") or {}
        mime = content.get("mimeType") or ""
        host = urlsplit(url).netloc
        if host:
            hosts[host] = hosts.get(host, 0) + 1
        methods[method] = methods.get(method, 0) + 1
        if status is not None:
            status_codes[str(status)] = status_codes.get(str(status), 0) + 1
        entries.append({"method": method, "url": _redact(url), "status": status,
                        "mime": mime, "size": content.get("size")})
        # secret scan: URL (query), headers, request body
        _scan_secrets(f"url {method}", url, secrets)
        for h in (req.get("headers") or []):
            hn = (h.get("name") or "")
            hv = (h.get("value") or "")
            if hn.lower() == "authorization" and hv:
                secrets.append({"kind": "authorization-header", "where": "request header",
                                "evidence": _redact(hv)})
            else:
                _scan_secrets(f"request header {hn}", hv, secrets)
        pd = req.get("postData") or {}
        _scan_secrets("request body", pd.get("text") or "", secrets)
    # dedup secrets
    seen = set()
    uniq = []
    for s in secrets:
        k = (s["kind"], s["evidence"])
        if k not in seen:
            seen.add(k)
            uniq.append(s)
    return {"ok": True, "is_har": True, "entry_count": len(entries_in), "shown": len(entries),
            "entries": entries, "hosts": hosts, "methods": methods, "status_codes": status_codes,
            "secrets": uniq,
            "limitations": ["deteccion de secretos por heuristica (regex); solo request URL/headers/"
                            "body; no se descifra TLS ni se siguen redirecciones"]}


def render_har(r: dict) -> str:
    out = ["## Inspeccion de captura HAR (estatica)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    if not r.get("is_har"):
        return "\n".join(out + ["- No es un HAR: " + r.get("note", "")])
    out.append(f"- peticiones: {r.get('entry_count')} (mostrando {r.get('shown')})")
    hosts = r.get("hosts") or {}
    if hosts:
        top = sorted(hosts.items(), key=lambda kv: -kv[1])[:15]
        out.append("- hosts: " + ", ".join(f"{h}({n})" for h, n in top))
    if r.get("methods"):
        out.append("- metodos: " + ", ".join(f"{m}x{n}" for m, n in r["methods"].items()))
    if r.get("status_codes"):
        out.append("- codigos: " + ", ".join(f"{s}x{n}" for s, n in sorted(r["status_codes"].items())))
    sec = r.get("secrets") or []
    if sec:
        out.append(f"\n### Secretos expuestos (heuristica): {len(sec)}")
        for s in sec[:40]:
            out.append(f"- **{s['kind']}** en {s['where']}: `{s['evidence']}`")
    else:
        out.append("\n- sin secretos detectados por la heuristica")
    out.append(f"\n### Peticiones ({r.get('shown')})")
    for e in (r.get("entries") or [])[:40]:
        out.append(f"- {e['method']} [{e.get('status')}] {e['mime']}  {e['url']}")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
