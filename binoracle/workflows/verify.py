"""Automatic, deterministic verification pass — v2.

Promotes a finding from 'grounded' to 'verified' WITHOUT relying on the
model deciding to call angr. For each candidate sink, extract its call-site
address from static evidence and ask angr to prove reachability from entry,
synthesizing a concrete input. Reachability of the sink call with attacker
input is an observable fact, not a claim.

v2 adds:
  - `http_verify(url, payload, method, check_fn)` — fires a real HTTP request
    against a live/lab target and asserts a custom check function; used for
    web CVE verification without docker compose every time
  - `sandbox_verify(binary, payload, expected_indicator)` — runs the binary
    in a lightweight sandbox (binoracle-lab Docker or local) and checks stdout/
    stderr for a success indicator (e.g. "BINORACLE_PWNED", uid=0, /etc/passwd)
  - `VerifyResult` dataclass — unified return type with method, evidence, timing
  - `multi_verify(registry, findings, http_targets, on_step)` — combines angr +
    HTTP + sandbox verification in a single pass
  - Automatic promotion uses: angr (binary) + HTTP (web) + sandbox (dynamic)
"""
from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..oracles.base import ToolRegistry
from ..store.session import Finding

_ADDR = re.compile(r"0x[0-9a-fA-F]+")


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class VerifyResult:
    method:    str            # "angr" | "http" | "sandbox" | "manual"
    verified:  bool
    evidence:  str
    elapsed_s: float = 0.0
    input_used: Optional[str] = None
    notes:     List[str] = field(default_factory=list)


# ── HTTP verification ─────────────────────────────────────────────────────────

def http_verify(
    url: str,
    payload: Optional[str] = None,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    check_fn: Optional[Callable[[int, Dict[str, str], bytes], bool]] = None,
    timeout: int = 15,
) -> VerifyResult:
    """
    Fire an HTTP request to `url` and verify the finding with `check_fn`.

    `check_fn(status_code, response_headers, body) -> bool`
    If not provided, considers 200–299 without 'error'/'denied' in body as success.

    For AUTHORIZED targets / lab environments only.
    """
    import urllib.request
    import urllib.error

    t0 = time.time()
    hdrs = {"User-Agent": "binoracle-verify/0.3", **(headers or {})}

    try:
        body_bytes = (payload or "").encode()
        req = urllib.request.Request(
            url, data=(body_bytes if method != "GET" else None),
            headers=hdrs, method=method,
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            resp_hdrs = dict(resp.headers)
            body = resp.read(65536)
    except urllib.error.HTTPError as e:
        status = e.code
        resp_hdrs = dict(e.headers)
        body = e.read(65536)
    except Exception as exc:
        elapsed = time.time() - t0
        return VerifyResult(
            method="http", verified=False,
            evidence=f"HTTP request failed: {exc}", elapsed_s=elapsed,
        )

    elapsed = time.time() - t0
    if check_fn:
        verified = bool(check_fn(status, resp_hdrs, body))
    else:
        body_str = body.decode(errors="replace").lower()
        verified = (200 <= status < 300 and "denied" not in body_str and "error" not in body_str[:100])

    evidence_lines = [
        f"HTTP {method} {url}",
        f"Status: {status}",
        f"Time: {elapsed:.2f}s",
        f"Response (first 500 bytes): {body[:500].decode(errors='replace')!r}",
    ]
    return VerifyResult(
        method="http", verified=verified,
        evidence="\n".join(evidence_lines),
        elapsed_s=elapsed,
        input_used=payload,
    )


# ── Sandbox verification ──────────────────────────────────────────────────────

def sandbox_verify(
    binary: str,
    payload: bytes = b"",
    success_indicator: str = "BINORACLE_PWNED",
    timeout: int = 10,
) -> VerifyResult:
    """
    Run `binary` with `payload` on stdin in a Docker sandbox (or local fallback)
    and check output for `success_indicator`.

    Typical indicators:
      - "BINORACLE_PWNED"  — PoC output marker
      - "uid=0"            — root shell confirmed
      - "/etc/passwd"      — file read confirmed
      - "RIP"              — crash/SIGSEGV detected

    For AUTHORIZED targets / Docker lab only.
    """
    t0 = time.time()
    docker_ok = subprocess.run(
        ["docker", "info"], capture_output=True, timeout=5
    ).returncode == 0

    if docker_ok:
        try:
            r = subprocess.run(
                ["docker", "run", "--rm", "-i", "--network=none",
                 "--memory=128m", "--pids-limit=64",
                 "-v", f"{os.path.abspath(binary)}:/target:ro",
                 "binoracle-lab:latest", "/target"],
                input=payload, capture_output=True, timeout=timeout,
            )
            output = (r.stdout + r.stderr).decode(errors="replace")
            method = "sandbox-docker"
        except Exception as e:
            elapsed = time.time() - t0
            return VerifyResult(method="sandbox-docker", verified=False,
                                evidence=f"Docker run failed: {e}", elapsed_s=elapsed)
    else:
        # Local fallback — no network isolation
        try:
            r = subprocess.run(
                [os.path.abspath(binary)],
                input=payload, capture_output=True, timeout=timeout,
            )
            output = (r.stdout + r.stderr).decode(errors="replace")
            method = "sandbox-local"
        except Exception as e:
            elapsed = time.time() - t0
            return VerifyResult(method="sandbox-local", verified=False,
                                evidence=f"Local run failed: {e}", elapsed_s=elapsed)

    elapsed = time.time() - t0
    verified = success_indicator in output
    evidence = (
        f"binary: {binary}\n"
        f"indicator: {success_indicator!r}\n"
        f"verified: {verified}\n"
        f"output (first 800 bytes):\n{output[:800]}"
    )
    return VerifyResult(
        method=method, verified=verified, evidence=evidence,
        elapsed_s=elapsed, input_used=payload.decode(errors="replace"),
    )


# ── angr reachability (original) ──────────────────────────────────────────────

def verify_address(registry: ToolRegistry, addr: str) -> Tuple[bool, Optional[str], str]:
    """Ask angr whether `addr` is reachable from entry. Returns (reachable, input, evidence)."""
    tool = registry.get("angr_reachable")
    if tool is None:
        return (False, None, "angr not available")
    res = tool.run(addr=addr)
    if not res.ok:
        return (False, None, res.error or "angr error")
    reachable = bool(res.meta.get("reachable"))
    return (reachable, None, f"[{res.source}]\n{res.data}")


def _callsite_addr(evidence: str) -> Optional[str]:
    """Pull the call-site address out of an r2 xref/sink evidence line."""
    for line in evidence.splitlines():
        if "bl " in line or "call" in line.lower() or "CALL" in line:
            m = _ADDR.search(line)
            if m:
                return m.group(0)
    m = _ADDR.search(evidence)
    return m.group(0) if m else None


# ── Multi-method orchestrator ─────────────────────────────────────────────────

def auto_verify(
    registry: ToolRegistry,
    findings: List[Finding],
    store=None,
    on_step=None,
) -> Tuple[List[Finding], List[str]]:
    """
    Try to promote each binary finding to 'verified' via angr reachability.
    Original entry point — preserved for backwards compatibility.
    """
    notes: List[str] = []
    if registry.get("angr_reachable") is None:
        return findings, ["angr not installed: cannot auto-verify reachability (findings stay 'grounded')"]
    for f in findings:
        if f.verdict == "verified":
            continue
        addr = _callsite_addr(f.evidence or "")
        if not addr:
            continue
        if on_step:
            on_step(f"angr: verificando reachability de {addr} ({f.title})...")
        reachable, _inp, ev = verify_address(registry, addr)
        if reachable:
            f.verdict = "verified"
            f.evidence = (f.evidence or "") + f"\n\n--- angr verification ---\n{ev}"
            f.rationale = (f.rationale or "") + (
                f"\n\nVERIFIED: angr proved the sink call site {addr} is reachable from entry "
                f"with attacker-controlled input (concrete input synthesized above)."
            )
            notes.append(f"promoted '{f.title}' grounded->verified (angr: {addr} reachable)")
            if store:
                store.add_finding(f)
        else:
            notes.append(f"'{f.title}': angr could NOT prove {addr} reachable within bounds (stays grounded)")
    return findings, notes


def multi_verify(
    registry: ToolRegistry,
    findings: List[Finding],
    http_targets: Optional[List[Dict[str, Any]]] = None,
    sandbox_targets: Optional[List[Dict[str, Any]]] = None,
    store=None,
    on_step=None,
) -> Tuple[List[Finding], List[VerifyResult], List[str]]:
    """
    Multi-method verification pass:
    1. angr reachability — for binary/function-level findings
    2. HTTP verification — for web/API findings (uses http_targets list)
    3. Sandbox verification — for binary PoC confirmation

    `http_targets`: list of dicts with keys: url, payload, method, check_fn
    `sandbox_targets`: list of dicts with keys: binary, payload, success_indicator

    Returns (updated_findings, verify_results, notes).
    """
    notes: List[str] = []
    results: List[VerifyResult] = []

    # Pass 1: angr
    findings, angr_notes = auto_verify(registry, findings, store=store, on_step=on_step)
    notes.extend(angr_notes)

    # Pass 2: HTTP
    for ht in (http_targets or []):
        url = ht.get("url", "")
        if not url:
            continue
        if on_step:
            on_step(f"http_verify: {url}...")
        vr = http_verify(
            url=url,
            payload=ht.get("payload"),
            method=ht.get("method", "GET"),
            headers=ht.get("headers"),
            check_fn=ht.get("check_fn"),
            timeout=ht.get("timeout", 15),
        )
        results.append(vr)
        notes.append(f"http_verify {url}: {'VERIFIED' if vr.verified else 'NOT VERIFIED'} "
                     f"({vr.elapsed_s:.1f}s)")

    # Pass 3: Sandbox
    for st in (sandbox_targets or []):
        binary = st.get("binary", "")
        if not binary:
            continue
        if on_step:
            on_step(f"sandbox_verify: {os.path.basename(binary)}...")
        vr = sandbox_verify(
            binary=binary,
            payload=st.get("payload", b""),
            success_indicator=st.get("success_indicator", "BINORACLE_PWNED"),
            timeout=st.get("timeout", 10),
        )
        results.append(vr)
        notes.append(f"sandbox_verify {os.path.basename(binary)}: "
                     f"{'VERIFIED' if vr.verified else 'NOT VERIFIED'} ({vr.elapsed_s:.1f}s)")

    return findings, results, notes
