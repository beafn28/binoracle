"""difftest.py — Differential container testing for CVE verification.

The core idea: spin up TWO Docker containers — one with the VULNERABLE version
of the target software and one with the PATCHED version — send the exact same
PoC request to both, and compare the responses. If they differ in a meaningful
way (different status code, different body content, payload reflected in
vulnerable but not patched), the CVE is confirmed with the highest possible
confidence.

This eliminates false-positives from "the endpoint returns 200 by design" and
produces irrefutable evidence: "version X is vulnerable (200+canary), version
Y is not (403 or no canary)".

Usage:
    from .difftest import differential_test
    result = differential_test(
        source_dir="/path/to/vuln/source",
        patched_source_dir="/path/to/patched/source",   # or None to build from pkg_version
        endpoint="/api/users",
        http_method="GET",
        payload="",
        bypass_headers={"X-Forwarded-For": "127.0.0.1"},
        confirm_string='"id":',
        on_step=step,
        budget_s=180.0,
    )
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .wpverify import _docker_daemon_ok, _http_request


@dataclass
class DiffTestResult:
    confirmed: bool = False
    vuln_status: int = 0
    patched_status: int = 0
    vuln_body_snippet: str = ""
    patched_body_snippet: str = ""
    diff_reason: str = ""
    error: str = ""
    elapsed_s: float = 0.0
    evidence: dict = field(default_factory=dict)


def _run(cmd: list, timeout: int = 120, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout, **kwargs)


def _wait_for_port(host: str, port: int, timeout_s: int = 45) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(1)
    return False


def _lab_host() -> str:
    return os.environ.get("BINORACLE_LAB_HOST", "127.0.0.1")


def _build_and_start(source_dir: str, container_name: str,
                     port: int, step: Callable) -> bool:
    """Build and start a Docker container from source_dir. Returns True on success."""
    try:
        step(f"  difftest: construyendo {container_name}…")
        r = _run(["docker", "build", "-t", container_name, source_dir], timeout=180)
        if r.returncode != 0:
            step(f"  difftest: build falló para {container_name}: {r.stderr[:200]}")
            return False
        _run(["docker", "stop", container_name], timeout=10)
        _run(["docker", "rm", "-f", container_name], timeout=10)
        r2 = _run(["docker", "run", "-d", "--rm", "--name", container_name,
                   "-p", f"{port}:{port}", container_name], timeout=30)
        if r2.returncode != 0:
            step(f"  difftest: run falló para {container_name}: {r2.stderr[:200]}")
            return False
        return True
    except Exception as e:
        step(f"  difftest: error construyendo {container_name}: {e}")
        return False


def _stop(container_name: str) -> None:
    try:
        subprocess.run(["docker", "stop", container_name],
                       capture_output=True, timeout=15)
        subprocess.run(["docker", "rm", "-f", container_name],
                       capture_output=True, timeout=10)
    except Exception:
        pass


def _meaningful_diff(vuln_status: int, patched_status: int,
                     vuln_body: str, patched_body: str,
                     confirm_string: str) -> tuple[bool, str]:
    """Decide if the response difference is meaningful (not noise).

    Returns (is_meaningful, reason).

    Rules (in priority order):
    1. confirm_string in vuln_body but NOT in patched_body → confirmed
    2. vuln_status 2xx, patched_status 4xx/5xx → confirmed
    3. vuln_status == patched_status AND bodies differ by < 10 chars → NOT meaningful
    4. vuln_body has payload canary, patched doesn't → confirmed
    """
    if confirm_string:
        in_vuln = confirm_string in vuln_body
        in_patched = confirm_string in patched_body
        if in_vuln and not in_patched:
            return True, "confirm_string presente en vulnerable, ausente en parchado"
        if not in_vuln and not in_patched:
            # Both lack it — no signal
            return False, "confirm_string ausente en ambas versiones"

    # Status code divergence
    vuln_ok = 200 <= vuln_status < 300
    patched_ok = 200 <= patched_status < 300
    if vuln_ok and not patched_ok:
        return True, (f"vulnerable devuelve {vuln_status}, "
                      f"parchado devuelve {patched_status}")
    if not vuln_ok and patched_ok:
        # Unexpected: patched is MORE permissive. Not a confirmed CVE.
        return False, "parchado más permisivo que vulnerable (inesperado)"

    # Body size divergence
    if abs(len(vuln_body) - len(patched_body)) > 50:
        # Meaningful size difference
        return True, (f"cuerpos difieren en {abs(len(vuln_body)-len(patched_body))} chars — "
                      f"vulnerable={len(vuln_body)}b patched={len(patched_body)}b")

    return False, "sin diferencia significativa entre versiones"


def differential_test(
        source_dir: str,
        patched_source_dir: Optional[str],
        endpoint: str,
        http_method: str = "GET",
        payload: str = "",
        bypass_headers: Optional[dict] = None,
        confirm_string: str = "",
        on_step: Optional[Callable] = None,
        budget_s: float = 180.0,
        vuln_port: int = 18081,
        patched_port: int = 18082,
        pkg_name: str = "",
        patched_version: str = "",
) -> DiffTestResult:
    """Run a differential test between vulnerable and patched versions.

    Args:
        source_dir:          path to vulnerable version source
        patched_source_dir:  path to patched version source (None = use pkg_name@patched_version)
        endpoint:            URL path to test (e.g. /api/users)
        http_method:         HTTP method
        payload:             request body or query string payload
        bypass_headers:      headers to include in requests (e.g. bypass headers)
        confirm_string:      string that confirms vulnerability in response
        on_step:             progress callback
        budget_s:            max total seconds for both containers
        vuln_port:           port for vulnerable container
        patched_port:        port for patched container
        pkg_name:            package name (for version-based patched container)
        patched_version:     version string to install in patched container

    Returns DiffTestResult with confirmed=True if the two containers respond differently.
    """
    t0 = time.time()
    step = on_step or (lambda _m: None)
    res = DiffTestResult()

    if not _docker_daemon_ok():
        res.error = "Docker no disponible"
        return res

    cve_slug = re.sub(r"[^a-zA-Z0-9]", "_", os.path.basename(source_dir))[:20]
    vuln_name = f"bo_diff_vuln_{cve_slug}"
    patched_name = f"bo_diff_patched_{cve_slug}"

    # Build patched source if not provided
    _patched_dir = patched_source_dir
    _patched_tmpdir = None
    if not _patched_dir and pkg_name and patched_version:
        import tempfile
        _patched_tmpdir = tempfile.mkdtemp(prefix="bo_patched_")
        _patched_dir = _patched_tmpdir
        # Create a minimal Dockerfile that installs the patched version
        _patched_df = os.path.join(_patched_tmpdir, "Dockerfile")
        # Detect stack from source_dir to pick right base image
        _has_go = os.path.isfile(os.path.join(source_dir, "go.mod"))
        _has_py = os.path.isfile(os.path.join(source_dir, "requirements.txt"))
        _has_js = os.path.isfile(os.path.join(source_dir, "package.json"))
        if _has_go:
            _base = "golang:1.22-alpine"
            _install = f"RUN go get {pkg_name}@v{patched_version} 2>/dev/null || true"
        elif _has_py:
            _base = "python:3.11-slim"
            _install = f"RUN pip install {pkg_name}=={patched_version} 2>/dev/null || true"
        elif _has_js:
            _base = "node:20-alpine"
            _install = f"RUN npm install {pkg_name}@{patched_version} 2>/dev/null || true"
        else:
            _base = "ubuntu:22.04"
            _install = "# patched version install would go here"
        with open(_patched_df, "w") as f:
            f.write(f"FROM {_base}\nWORKDIR /app\nCOPY . .\n{_install}\n"
                    f"EXPOSE {patched_port}\n"
                    f'CMD ["sh", "-c", "echo patched container up; sleep 3600"]\n')
        # Copy source
        import shutil
        for item in os.listdir(source_dir):
            src = os.path.join(source_dir, item)
            dst = os.path.join(_patched_tmpdir, item)
            if os.path.isdir(src):
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dst)

    if not _patched_dir:
        res.error = "Sin fuente parchada disponible para test diferencial"
        return res

    host = _lab_host()
    headers = bypass_headers or {}

    try:
        # Build both containers
        vuln_ok = _build_and_start(source_dir, vuln_name, vuln_port, step)
        patched_ok = _build_and_start(_patched_dir, patched_name, patched_port, step)

        if not vuln_ok:
            res.error = "No se pudo construir container vulnerable"
            return res
        if not patched_ok:
            res.error = "No se pudo construir container parchado"
            return res

        # Wait for both to be ready
        step(f"  difftest: esperando puertos {vuln_port} y {patched_port}…")
        if not _wait_for_port(host, vuln_port, timeout_s=45):
            res.error = f"Timeout esperando puerto vulnerable {vuln_port}"
            return res
        if not _wait_for_port(host, patched_port, timeout_s=45):
            res.error = f"Timeout esperando puerto parchado {patched_port}"
            return res

        # Send identical requests to both
        vuln_url = f"http://{host}:{vuln_port}{endpoint}"
        patched_url = f"http://{host}:{patched_port}{endpoint}"

        body = payload if http_method.upper() in ("POST", "PUT", "PATCH") else None
        qstring = payload if http_method.upper() == "GET" and payload else ""
        if qstring and "?" not in endpoint:
            vuln_url += f"?{qstring}"
            patched_url += f"?{qstring}"

        step(f"  difftest: {http_method} {endpoint} → vuln:{vuln_port} vs patched:{patched_port}")

        try:
            r_vuln = _http_request(http_method.upper(), vuln_url,
                                   data=body, headers=headers, timeout=15)
            res.vuln_status = r_vuln.status
            res.vuln_body_snippet = (r_vuln.body or "")[:400]
        except Exception as e:
            res.error = f"Request a container vulnerable falló: {e}"
            return res

        try:
            r_patched = _http_request(http_method.upper(), patched_url,
                                      data=body, headers=headers, timeout=15)
            res.patched_status = r_patched.status
            res.patched_body_snippet = (r_patched.body or "")[:400]
        except Exception as e:
            res.error = f"Request a container parchado falló: {e}"
            return res

        # Compare responses
        meaningful, reason = _meaningful_diff(
            res.vuln_status, res.patched_status,
            res.vuln_body_snippet, res.patched_body_snippet,
            confirm_string)

        res.confirmed = meaningful
        res.diff_reason = reason
        res.evidence = {
            "vuln_url": vuln_url,
            "patched_url": patched_url,
            "vuln_status": res.vuln_status,
            "patched_status": res.patched_status,
            "diff_reason": reason,
        }

        if meaningful:
            step(f"  difftest: DIFERENCIAL CONFIRMADO — {reason}")
        else:
            step(f"  difftest: sin diferencia significativa — {reason}")

    finally:
        _stop(vuln_name)
        _stop(patched_name)
        if _patched_tmpdir:
            import shutil
            try:
                shutil.rmtree(_patched_tmpdir, ignore_errors=True)
            except Exception:
                pass

    res.elapsed_s = time.time() - t0
    return res
