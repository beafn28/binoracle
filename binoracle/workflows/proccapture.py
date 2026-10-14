"""Process-scenario capture + comparison (RUNTIME; authorized targets only).

Runs a target process once under a bounded timeout and records its OBSERVABLE behaviour -- argv,
exit status, wall-time bucket, and normalized stdout/stderr -- then lets two captures be diffed to
surface changed behaviour between builds/versions/inputs. Matches REA's `capture_process_scenario`
and `compare_process_captures` (morluto/rea, MIT).

This lives in the RUNTIME family, deliberately separate from the static grounding core: it EXECUTES
the caller's target, so it is for AUTHORIZED targets only and its captured output is untrusted data.
Output is NORMALIZED (addresses, PIDs, timestamps, temp paths collapsed to placeholders) so two runs
of the same deterministic program compare equal and a real behavioural change stands out. A content
digest is taken over the normalized form so captures round-trip and tampering is visible."""
from __future__ import annotations

import difflib
import hashlib
import json
import re
import subprocess
import time

_NORMALIZERS = (
    (re.compile(rb"0x[0-9a-fA-F]+"), b"0xADDR"),
    (re.compile(rb"\b[0-9a-fA-F]{12,}\b"), b"HEX"),
    (re.compile(rb"\bpid[= ]\d+", re.I), b"pid=PID"),
    (re.compile(rb"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b"), b"TIMESTAMP"),
    (re.compile(rb"/tmp/[^\s\"']+"), b"/tmp/PATH"),
    (re.compile(rb"\b\d{10,}\b"), b"NUM"),
)


def _normalize(data: bytes) -> str:
    out = data
    for rx, repl in _NORMALIZERS:
        out = rx.sub(repl, out)
    return out.decode("utf-8", "replace")


def _duration_bucket(sec: float) -> str:
    if sec < 0.1:
        return "<100ms"
    if sec < 1:
        return "<1s"
    if sec < 5:
        return "<5s"
    if sec < 30:
        return "<30s"
    return ">=30s"


def capture_process(argv, stdin_data: bytes = b"", timeout: int = 20, out_path: str = None) -> dict:
    """Run `argv` once (authorized target), capture normalized stdout/stderr, exit status and a
    wall-time bucket, and seal a digest over the normalized form. Optionally persist to out_path."""
    if not argv or not isinstance(argv, (list, tuple)):
        return {"ok": False, "tool": "process_capture", "note": "argv vacio o invalido"}
    argv = [str(a) for a in argv]
    started = time.time()
    try:
        p = subprocess.run(argv, input=stdin_data, capture_output=True, timeout=timeout)
        timed_out = False
        code = p.returncode
        raw_out, raw_err = p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        timed_out = True
        code = None
        raw_out = e.stdout or b""
        raw_err = e.stderr or b""
    except FileNotFoundError:
        return {"ok": False, "tool": "process_capture", "note": f"ejecutable no encontrado: {argv[0]}"}
    except Exception as e:
        return {"ok": False, "tool": "process_capture", "note": f"fallo al ejecutar: {e}"}
    elapsed = time.time() - started
    nout, nerr = _normalize(raw_out), _normalize(raw_err)
    scenario = {
        "argv": argv, "exit_code": code, "timed_out": timed_out,
        "duration_bucket": _duration_bucket(elapsed),
        "stdout_normalized": nout, "stderr_normalized": nerr,
        "captured": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    seal = {k: scenario[k] for k in ("argv", "exit_code", "timed_out",
                                     "stdout_normalized", "stderr_normalized")}
    scenario["digest"] = "sha256:" + hashlib.sha256(
        json.dumps(seal, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    res = {"ok": True, "tool": "process_capture", "scenario": scenario,
           "limitations": ["EJECUTA el objetivo (solo objetivos AUTORIZADOS); salida no confiable",
                           "salida normalizada (direcciones/PIDs/timestamps colapsados) para comparar"]}
    if out_path:
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(scenario, f, ensure_ascii=False, indent=2)
            res["capture_path"] = out_path
        except Exception as e:
            res["note"] = f"no se pudo guardar la captura: {e}"
    return res


def _load_capture(ref) -> dict:
    if isinstance(ref, dict):
        return ref.get("scenario", ref)
    with open(ref, "r", encoding="utf-8") as f:
        return json.load(f)


def compare_captures(a, b) -> dict:
    """Diff two process captures (paths or dicts): exit-code / timeout change, duration bucket, and
    a unified diff of the normalized stdout & stderr. `identical` is true iff the sealed digests match."""
    try:
        ca, cb = _load_capture(a), _load_capture(b)
    except Exception as e:
        return {"ok": False, "tool": "process_compare", "note": f"no se pudo leer una captura: {e}"}
    identical = ca.get("digest") and ca.get("digest") == cb.get("digest")

    def _diff(x: str, y: str, label: str):
        dl = list(difflib.unified_diff(x.splitlines(), y.splitlines(),
                                       fromfile=f"a/{label}", tofile=f"b/{label}", lineterm=""))
        return dl[:400]

    changes = []
    if ca.get("exit_code") != cb.get("exit_code"):
        changes.append(f"exit_code: {ca.get('exit_code')} -> {cb.get('exit_code')}")
    if ca.get("timed_out") != cb.get("timed_out"):
        changes.append(f"timed_out: {ca.get('timed_out')} -> {cb.get('timed_out')}")
    if ca.get("duration_bucket") != cb.get("duration_bucket"):
        changes.append(f"duration: {ca.get('duration_bucket')} -> {cb.get('duration_bucket')}")
    out_diff = _diff(ca.get("stdout_normalized", ""), cb.get("stdout_normalized", ""), "stdout")
    err_diff = _diff(ca.get("stderr_normalized", ""), cb.get("stderr_normalized", ""), "stderr")
    return {"ok": True, "tool": "process_compare", "identical": bool(identical),
            "behavior_changes": changes, "stdout_diff": out_diff, "stderr_diff": err_diff,
            "limitations": ["comparacion sobre salida normalizada; diferencias de entorno no "
                            "deterministas pueden quedar fuera del alcance del normalizador"]}


def render_capture(r: dict) -> str:
    out = ["## Captura de escenario de proceso (runtime, autorizado)\n"]
    if not r.get("ok"):
        return "\n".join(out + [f"- No disponible: {r.get('note','')}"])
    s = r["scenario"]
    out.append(f"- argv: `{' '.join(s['argv'])}`")
    out.append(f"- exit: {s['exit_code']}" + (" (timeout)" if s["timed_out"] else "")
               + f" | duracion: {s['duration_bucket']}")
    out.append(f"- sello: `{s['digest']}`")
    if s.get("stdout_normalized"):
        out.append("\n### stdout (normalizado)\n```\n" + s["stdout_normalized"][:2000] + "\n```")
    if r.get("capture_path"):
        out.append(f"\n- guardada en `{r['capture_path']}`")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)


def render_compare(r: dict) -> str:
    out = ["## Comparacion de capturas de proceso\n"]
    if not r.get("ok"):
        return "\n".join(out + [f"- No disponible: {r.get('note','')}"])
    out.append(f"- identicas: **{'SI' if r.get('identical') else 'no'}**")
    for c in r.get("behavior_changes", []):
        out.append(f"- cambio: {c}")
    if r.get("stdout_diff"):
        out.append("\n### diff stdout\n```diff\n" + "\n".join(r["stdout_diff"][:120]) + "\n```")
    if r.get("stderr_diff"):
        out.append("\n### diff stderr\n```diff\n" + "\n".join(r["stderr_diff"][:60]) + "\n```")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
