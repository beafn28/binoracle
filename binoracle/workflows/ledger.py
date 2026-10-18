"""Evidence ledger: the residual-unknown lifecycle + obligation-gated resolution + sealed bundles.

This is binoracle's "grounded reconstruction with obligations" workflow, matching REA's unknown /
evidence tools (morluto/rea, MIT). The idea: reverse engineering is only honest when every open
question is tracked and only closed when backed by evidence that meets a stated obligation.

* An **unknown** is an open question about the target: `question`, `severity`, `domain`, and the
  obligation it must meet to be resolved -- `required_authority` (how strong the evidence source
  must be) and `required_confidence` (how strongly it must be established), plus `recommended_probes`
  (which binoracle tools would settle it). It carries a `revision` for optimistic concurrency.
* **Evidence** is a recorded observation with its own `authority` and `confidence`, a source tool,
  and a canonical content digest, so it cannot be silently altered.
* `verify_unknown_resolution` closes an unknown ONLY when it has a resolution, at least one
  supporting evidence that meets BOTH its required authority and confidence, and no contradicting
  evidence. Otherwise it stays open and the ledger says exactly which obligation is unmet.
* `export/import/get_evidence_bundle` serialize the whole ledger to a JSON bundle sealed with a
  sha256 digest over its canonical form, so a bundle round-trips verifiably.

Pure Python standard library; the ledger persists to a JSON file (default `.binoracle_ledger.json`
in the working directory, or a caller-supplied path). Nothing is executed here."""
from __future__ import annotations

import hashlib
import json
import os
import time

_DEFAULT_PATH = ".binoracle_ledger.json"

# Obligation ladders: a stronger source / firmer establishment ranks higher. Supporting evidence
# must rank at or above the unknown's required level on BOTH ladders to discharge the obligation.
_AUTHORITY = ["asserted", "static-only", "controlled-replay", "instrumented", "live"]
_CONFIDENCE = ["asserted", "observed", "reproduced", "verified"]
_SEVERITY = ("info", "low", "medium", "high", "critical")
_STATUS = ("open", "investigating", "resolved", "wont-fix")


def _canon(obj) -> bytes:
    """Canonical JSON bytes (sorted keys, no whitespace) for stable digests."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(obj) -> str:
    return hashlib.sha256(_canon(obj)).hexdigest()


def _load(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        if isinstance(doc, dict) and "unknowns" in doc and "evidence" in doc:
            return doc
    except Exception:
        pass
    return {"version": 1, "unknowns": {}, "evidence": {}}


def _save(path: str, doc: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def _rank(ladder: list, value: str) -> int:
    try:
        return ladder.index(value)
    except ValueError:
        return -1


def record_unknown(question: str, severity: str = "medium", domain: str = "general",
                   required_authority: str = "static-only", required_confidence: str = "observed",
                   recommended_probes=None, ledger: str = None) -> dict:
    """Record a new residual unknown. Returns the created record (status 'open', revision 1)."""
    path = ledger or _DEFAULT_PATH
    doc = _load(path)
    if severity not in _SEVERITY:
        return {"ok": False, "note": f"severity invalida: {severity} (usa {', '.join(_SEVERITY)})"}
    if _rank(_AUTHORITY, required_authority) < 0:
        return {"ok": False, "note": f"required_authority invalida (usa {', '.join(_AUTHORITY)})"}
    if _rank(_CONFIDENCE, required_confidence) < 0:
        return {"ok": False, "note": f"required_confidence invalida (usa {', '.join(_CONFIDENCE)})"}
    body = {
        "question": question, "severity": severity, "domain": domain,
        "required_authority": required_authority, "required_confidence": required_confidence,
        "recommended_probes": list(recommended_probes or []),
        "status": "open", "supporting_evidence_ids": [], "contradicting_evidence_ids": [],
        "resolution": None, "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    uid = "unk_" + _digest({"q": question, "d": domain, "t": body["created"], "n": len(doc["unknowns"])})[:32]
    body["id"] = uid
    body["revision"] = 1
    doc["unknowns"][uid] = body
    _save(path, doc)
    return {"ok": True, "unknown": body, "ledger": path}


def add_evidence(summary: str, kind: str = "observation", source: str = "binoracle",
                 authority: str = "static-only", confidence: str = "observed",
                 data=None, ledger: str = None) -> dict:
    """Record a piece of evidence with its authority/confidence and a sealed content digest."""
    path = ledger or _DEFAULT_PATH
    doc = _load(path)
    if _rank(_AUTHORITY, authority) < 0 or _rank(_CONFIDENCE, confidence) < 0:
        return {"ok": False, "note": "authority/confidence invalidas"}
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    body = {"summary": summary, "kind": kind, "source": source, "authority": authority,
            "confidence": confidence, "data": data, "created": created}
    eid = "ev_" + _digest(body)[:32]
    body["id"] = eid
    body["content_digest"] = _digest({k: body[k] for k in ("summary", "kind", "source",
                                                            "authority", "confidence", "data")})
    doc["evidence"][eid] = body
    _save(path, doc)
    return {"ok": True, "evidence": body, "ledger": path}


def update_unknown(unknown_id: str, expected_revision: int = None, status: str = None,
                   severity: str = None, supporting_evidence_ids=None,
                   contradicting_evidence_ids=None, resolution: str = None,
                   recommended_probes=None, ledger: str = None) -> dict:
    """Update an unknown with optimistic concurrency (expected_revision must match). Bumps revision."""
    path = ledger or _DEFAULT_PATH
    doc = _load(path)
    unk = doc["unknowns"].get(unknown_id)
    if not unk:
        return {"ok": False, "note": f"unknown no encontrado: {unknown_id}"}
    if expected_revision is not None and expected_revision != unk["revision"]:
        return {"ok": False, "note": f"conflicto de revision: esperado {expected_revision}, "
                                     f"actual {unk['revision']}"}
    if status is not None:
        if status not in _STATUS:
            return {"ok": False, "note": f"status invalido (usa {', '.join(_STATUS)})"}
        unk["status"] = status
    if severity is not None:
        if severity not in _SEVERITY:
            return {"ok": False, "note": f"severity invalida (usa {', '.join(_SEVERITY)})"}
        unk["severity"] = severity
    if supporting_evidence_ids is not None:
        unk["supporting_evidence_ids"] = list(supporting_evidence_ids)
    if contradicting_evidence_ids is not None:
        unk["contradicting_evidence_ids"] = list(contradicting_evidence_ids)
    if resolution is not None:
        unk["resolution"] = resolution
    if recommended_probes is not None:
        unk["recommended_probes"] = list(recommended_probes)
    unk["revision"] += 1
    _save(path, doc)
    return {"ok": True, "unknown": unk, "ledger": path}


def list_unknowns(offset: int = 0, limit: int = 50, ledger: str = None) -> dict:
    """List residual unknowns (most recent first), with a one-line obligation/status summary."""
    path = ledger or _DEFAULT_PATH
    doc = _load(path)
    items = sorted(doc["unknowns"].values(), key=lambda u: u.get("created", ""), reverse=True)
    window = items[offset:offset + limit]
    open_n = sum(1 for u in items if u["status"] in ("open", "investigating"))
    return {"ok": True, "total": len(items), "open": open_n, "unknowns": window, "ledger": path}


def verify_unknown_resolution(unknown_id: str, ledger: str = None) -> dict:
    """Close an unknown ONLY if it meets its obligation: a resolution, >=1 supporting evidence at or
    above required authority AND confidence, and no contradicting evidence. Otherwise report the
    unmet obligation and leave it open."""
    path = ledger or _DEFAULT_PATH
    doc = _load(path)
    unk = doc["unknowns"].get(unknown_id)
    if not unk:
        return {"ok": False, "note": f"unknown no encontrado: {unknown_id}"}
    reasons = []
    if not unk.get("resolution"):
        reasons.append("sin resolucion declarada")
    contradicting = [doc["evidence"].get(e) for e in unk.get("contradicting_evidence_ids", [])]
    contradicting = [e for e in contradicting if e]
    if contradicting:
        reasons.append(f"{len(contradicting)} evidencia(s) contradictoria(s)")
    req_a = _rank(_AUTHORITY, unk["required_authority"])
    req_c = _rank(_CONFIDENCE, unk["required_confidence"])
    supporting = [doc["evidence"].get(e) for e in unk.get("supporting_evidence_ids", [])]
    supporting = [e for e in supporting if e]
    meeting = [e for e in supporting
               if _rank(_AUTHORITY, e.get("authority", "")) >= req_a
               and _rank(_CONFIDENCE, e.get("confidence", "")) >= req_c]
    if not meeting:
        reasons.append(f"ninguna evidencia alcanza la obligacion "
                       f"(authority>={unk['required_authority']}, confidence>={unk['required_confidence']}; "
                       f"{len(supporting)} de apoyo)")
    verified = not reasons
    if verified:
        unk["status"] = "resolved"
        unk["revision"] += 1
        _save(path, doc)
    return {"ok": True, "unknown_id": unknown_id, "verified": verified,
            "unmet_obligations": reasons, "supporting_meeting": [e["id"] for e in meeting],
            "status": unk["status"], "ledger": path,
            "note": ("obligacion cumplida: unknown resuelto" if verified
                     else "obligacion NO cumplida: " + "; ".join(reasons))}


def export_evidence_bundle(out_path: str, ledger: str = None) -> dict:
    """Serialize the whole ledger into a JSON bundle sealed with a sha256 digest over its canonical
    form (so any later tampering is detectable on import)."""
    path = ledger or _DEFAULT_PATH
    doc = _load(path)
    payload = {"version": doc.get("version", 1),
               "exported": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "unknowns": doc["unknowns"], "evidence": doc["evidence"]}
    bundle = {"payload": payload, "digest": "sha256:" + _digest(payload)}
    _save(out_path, bundle)
    return {"ok": True, "bundle_path": out_path, "digest": bundle["digest"],
            "unknown_count": len(doc["unknowns"]), "evidence_count": len(doc["evidence"])}


def import_evidence_bundle(bundle_path: str, ledger: str = None, merge: bool = True) -> dict:
    """Load a sealed bundle, verify its digest, and import it into the ledger (merge or replace)."""
    path = ledger or _DEFAULT_PATH
    try:
        with open(bundle_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        payload = bundle["payload"]
        stated = bundle.get("digest", "")
    except Exception as e:
        return {"ok": False, "note": f"no se pudo leer el bundle: {e}"}
    recomputed = "sha256:" + _digest(payload)
    if stated != recomputed:
        return {"ok": False, "note": f"digest invalido: el bundle fue alterado "
                                     f"(declarado {stated}, recalculado {recomputed})"}
    doc = _load(path) if merge else {"version": 1, "unknowns": {}, "evidence": {}}
    doc["unknowns"].update(payload.get("unknowns", {}))
    doc["evidence"].update(payload.get("evidence", {}))
    _save(path, doc)
    return {"ok": True, "ledger": path, "merged": merge, "digest_ok": True,
            "unknown_count": len(doc["unknowns"]), "evidence_count": len(doc["evidence"])}


def get_evidence_bundle(ledger: str = None) -> dict:
    """Return the current ledger as an (unsealed) bundle view, with its canonical digest."""
    path = ledger or _DEFAULT_PATH
    doc = _load(path)
    payload = {"version": doc.get("version", 1), "unknowns": doc["unknowns"], "evidence": doc["evidence"]}
    return {"ok": True, "ledger": path, "digest": "sha256:" + _digest(payload),
            "unknown_count": len(doc["unknowns"]), "evidence_count": len(doc["evidence"]),
            "payload": payload}


def render_ledger(r: dict) -> str:
    out = ["## Evidence ledger (unknowns + obligaciones)\n"]
    if not r.get("ok"):
        return "\n".join(out + [f"- Error: {r.get('note','')}"])
    if "unknowns" in r and isinstance(r.get("unknowns"), list):
        out.append(f"- total: {r.get('total')} | abiertos: {r.get('open')}")
        for u in r["unknowns"]:
            out.append(f"\n### `{u['id']}` [{u['status']}] sev={u['severity']} ({u['domain']})")
            out.append(f"- {u['question']}")
            out.append(f"- obligacion: authority≥{u['required_authority']}, "
                       f"confidence≥{u['required_confidence']} | rev {u['revision']}")
            if u.get("recommended_probes"):
                probes = ", ".join(p.get("operation", str(p)) if isinstance(p, dict) else str(p)
                                   for p in u["recommended_probes"])
                out.append(f"- sondas sugeridas: {probes}")
        return "\n".join(out)
    if "verified" in r:
        out.append(f"- unknown `{r['unknown_id']}` -> **{'RESUELTO' if r['verified'] else 'SIGUE ABIERTO'}**")
        out.append(f"- {r.get('note','')}")
        return "\n".join(out)
    if "bundle_path" in r:
        out.append(f"- bundle exportado: `{r['bundle_path']}`")
        out.append(f"- sello: `{r['digest']}` | unknowns={r['unknown_count']} evidencias={r['evidence_count']}")
        return "\n".join(out)
    if "unknown" in r:
        u = r["unknown"]
        out.append(f"- `{u['id']}` [{u['status']}] rev {u['revision']} — {u['question']}")
        return "\n".join(out)
    if "evidence" in r:
        e = r["evidence"]
        out.append(f"- evidencia `{e['id']}` ({e['kind']}, authority={e['authority']}, "
                   f"confidence={e['confidence']}) sello `{e['content_digest'][:16]}…`")
        return "\n".join(out)
    if "digest" in r:
        out.append(f"- ledger `{r.get('ledger')}` sello `{r['digest']}` "
                   f"(unknowns={r['unknown_count']}, evidencias={r['evidence_count']})")
        return "\n".join(out)
    return "\n".join(out + [f"- {r}"])
