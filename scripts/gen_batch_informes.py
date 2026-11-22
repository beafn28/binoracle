#!/usr/bin/env python3
"""
Genera _informe_pdf.html (mismo template que gen_informe_pdf.py) para CVEs del batch.
Uso:
  python3 scripts/gen_batch_informes.py                    # todos los batch JSONs
  python3 scripts/gen_batch_informes.py CVE-2025-57633    # solo ese
"""
import json, os, sys, tempfile, shutil

BATCH_DIR = os.path.join(os.path.dirname(__file__), "..", "binoracle_batch_reports")
OUT       = os.path.expanduser("~/Downloads/binoracle_reports")
SCRIPT    = os.path.join(os.path.dirname(__file__), "gen_informe_pdf.py")

# Auto-screenshot generator
_this_dir = os.path.dirname(os.path.abspath(__file__))
if _this_dir not in sys.path:
    sys.path.insert(0, _this_dir)
try:
    from gen_screenshots import auto_gen_screenshots as _auto_screenshots
except ImportError:
    _auto_screenshots = None

os.makedirs(OUT, exist_ok=True)

cve_filter = set(a.upper() for a in sys.argv[1:]) if len(sys.argv) > 1 else None

# ── 1. Cargar funciones de gen_informe_pdf.py sin ejecutar su bucle final ────
_src = open(SCRIPT).read()
# Elimina el bucle de generacion al final (lo ejecutaremos nosotros con nuestros datos)
_src_no_loop = _src.split("# ── GENERATE")[0]
_ns = {"__name__": "__main__"}
exec(compile(_src_no_loop, SCRIPT, "exec"), _ns)

build_informe = _ns["build_informe"]

def _build_logs_from_ae(ae):
    """Convert attempt_evidence fields to [{t, msg}] log entries for the report."""
    logs = []
    t = 0.0

    # Setup phase
    setup_cmd = ae.get("setup_cmd", "")
    if setup_cmd:
        logs.append({"t": t, "msg": f"[SETUP] {setup_cmd[:300]}"})
        t += 1.0
        setup_stderr = ae.get("setup_stderr_recorte", "")
        if setup_stderr:
            for line in setup_stderr.strip().split("\n")[:12]:
                if line.strip():
                    logs.append({"t": t, "msg": line.strip()})
                    t += 0.1
        rc = ae.get("setup_returncode")
        if rc is not None:
            logs.append({"t": t, "msg": f"[SETUP] exit={rc}"})
            t += 0.5

    # CLI argv phase
    argv = ae.get("argv")
    if argv:
        cmd_str = " ".join(str(a) for a in argv)
        logs.append({"t": t, "msg": f"[RUN] {cmd_str[:350]}"})
        t += 0.5
        run_stdout = ae.get("run_stdout_recorte", "")
        if run_stdout:
            for line in run_stdout.strip().split("\n")[:15]:
                if line.strip():
                    logs.append({"t": t, "msg": line.strip()})
                    t += 0.1
        rc2 = ae.get("run_returncode")
        if rc2 is not None:
            logs.append({"t": t, "msg": f"[RUN] exit={rc2}"})
            t += 0.3
        canary = ae.get("canary_name", "")
        presente = ae.get("canario_presente", False)
        if canary:
            icon = "CONFIRMADO" if presente else "NO ENCONTRADO"
            logs.append({"t": t, "msg": f"[CANARY] {canary} → {icon}"})
            t += 0.2

    # Binary crash phase (poc_cmd / crash_output_recorte from binaryverify.py)
    poc_cmd = ae.get("poc_cmd", "")
    if poc_cmd and not ae.get("argv"):
        docker_img = ae.get("docker_image", "")
        if docker_img:
            logs.append({"t": t, "msg": f"[DOCKER] imagen={docker_img}"})
            t += 0.3
        logs.append({"t": t, "msg": f"[POC] {poc_cmd[:300]}"})
        t += 0.5
        crash_out = ae.get("crash_output_recorte", "")
        if crash_out:
            for line in crash_out.strip().split("\n")[:8]:
                if line.strip():
                    logs.append({"t": t, "msg": line.strip()})
                    t += 0.1
        exit_code = ae.get("exit_code")
        if exit_code is not None:
            logs.append({"t": t, "msg": f"[EXIT] code={exit_code}"})
            t += 0.2
        return logs

    # DoS phase (técnica dos / dos-pipeline)
    tecnica = ae.get("tecnica", "")
    if tecnica in ("dos", "dos-pipeline", "websocket"):
        endpoint = ae.get("endpoint", "")
        resp = ae.get("respuesta_cuerpo_recorte", "")
        sc = ae.get("status_code")
        logs.append({"t": t, "msg": "[DOCKER] servidor efímero iniciado (Docker --network none)"})
        t += 0.5
        if endpoint:
            logs.append({"t": t, "msg": f"[TARGET] endpoint={endpoint}"})
            t += 0.3
        if tecnica == "dos-pipeline":
            logs.append({"t": t, "msg": "[ATAQUE] HTTP pipeline + TCP RST injection → forzando ECONNRESET"})
            t += 0.4
        elif tecnica in ("dos", "websocket"):
            logs.append({"t": t, "msg": "[ATAQUE] WebSocket upgrade → frame sin máscara (MASK=0, RFC 6455 §5.1)"})
            t += 0.4
        if sc:
            logs.append({"t": t, "msg": f"[HTTP] status upgrade={sc}"})
            t += 0.2
        if resp:
            logs.append({"t": t, "msg": f"[CRASH] {resp[:300]}"})
            t += 0.3
        logs.append({"t": t, "msg": "[RESULTADO] servidor crasheó → DoS CONFIRMADO"})
        return logs

    # HTTP phase (web CVEs)
    endpoint = ae.get("endpoint", "")
    metodo = ae.get("metodo", "")
    is_cli_marker = metodo == "CLI" or (endpoint and "CLI" in endpoint)
    if endpoint and metodo and not is_cli_marker:
        base = ae.get("base_url", "")
        contenedor = ae.get("contenedor", "")
        if contenedor:
            logs.append({"t": t, "msg": f"[DOCKER] contenedor={contenedor}"})
            t += 0.3
        if base:
            logs.append({"t": t, "msg": f"[TARGET] {base}{endpoint}"})
            t += 0.3
        payload = ae.get("payload_ganador", "")
        param = ae.get("parametro_ganador", "")
        if payload:
            logs.append({"t": t, "msg": f"[PAYLOAD] {param}={payload[:200]}"})
            t += 0.3
        resp = ae.get("respuesta_cuerpo_recorte", "")
        if resp:
            logs.append({"t": t, "msg": f"[RESP] {resp[:300]}"})
            t += 0.2
        sc = ae.get("status_code")
        if sc:
            logs.append({"t": t, "msg": f"[HTTP] status={sc}"})
            t += 0.2
        canary_s = ae.get("canary_secret", "")
        if canary_s:
            logs.append({"t": t, "msg": f"[CANARY] {canary_s} → PRESENTE"})
            t += 0.2
    elif is_cli_marker and not argv:
        payload = ae.get("payload_ganador", "")
        resp = ae.get("respuesta_cuerpo_recorte", "")
        canary = ae.get("canary_name", "")
        presente = ae.get("canario_presente", False)
        logs.append({"t": t, "msg": "[DOCKER] sandbox npm isolado (--network none)"})
        t += 0.5
        if endpoint:
            logs.append({"t": t, "msg": f"[CMD] {endpoint}"})
            t += 0.3
        if payload:
            logs.append({"t": t, "msg": f"[PAYLOAD] --cmd {payload[:200]}"})
            t += 0.4
        if resp:
            logs.append({"t": t, "msg": f"[RESP] {resp[:300]}"})
            t += 0.3
        if canary:
            icon = "CONFIRMADO" if presente else "NO ENCONTRADO"
            logs.append({"t": t, "msg": f"[CANARY] {canary} → {icon}"})
            t += 0.2
        if presente:
            logs.append({"t": t, "msg": "[RESULTADO] command injection CONFIRMADO vía parámetro CLI"})

    return logs

# ── 2. Procesar cada batch JSON ───────────────────────────────────────────────
batch_dir = os.path.realpath(BATCH_DIR)
files = sorted(f for f in os.listdir(batch_dir) if f.endswith(".json"))
processed = 0

for fname in files:
    cve_id = fname[:-5]
    if cve_filter and cve_id not in cve_filter:
        continue

    with open(os.path.join(batch_dir, fname)) as f:
        batch = json.load(f)

    llm = batch.get("llm_notes") or {}
    ae  = batch.get("attempt_evidence") or {}
    sg  = batch.get("source_grounding") or {}
    verified = bool(batch.get("verified"))

    # ── verified_evidence: mapeo desde attempt_evidence ──────────────────────
    params = llm.get("parameters") or []
    if isinstance(params, dict):
        params = list(params.keys())
    first_param = params[0] if params else ""

    ve = {
        "endpoint":                ae.get("endpoint") or llm.get("endpoint", ""),
        "metodo":                  (ae.get("metodo") or llm.get("http_method", "POST")).upper(),
        "sqli_param":              ae.get("parametro_ganador") or ae.get("ssti_param") or first_param,
        "path_param":              ae.get("parametro_ganador") or first_param,
        "payload_ganador":         ae.get("payload_ganador") or "",
        "canary_path":             ae.get("canary_path") or "",
        "canary_secret":           ae.get("canary_secret") or "",
        "respuesta_cuerpo_recorte": ae.get("respuesta_cuerpo_recorte") or "",
        "respuesta_control_recorte": ae.get("respuesta_control_recorte") or "",
        "status_code_respuesta":   str(ae.get("status_code") or "200"),
        "screenshots":             ae.get("screenshots") or [],
        "tecnica":                 ae.get("tecnica") or batch.get("vuln_class") or "",
        "ssti_param":              ae.get("ssti_param") or first_param,
        "login_bajo_privilegio":   ae.get("login_bajo_privilegio") or "",
        "marker":                  ae.get("marker") or "",
    }

    # grounding source info
    grounded_fns = sg.get("found", {})
    grounded_note = ""
    if grounded_fns:
        fn_list = []
        for fn_name, locs in list(grounded_fns.items())[:3]:
            loc = locs[0] if isinstance(locs, list) and locs else ""
            fn_list.append(f"`{fn_name}` ({loc})" if loc else f"`{fn_name}`")
        grounded_note = "Funciones confirmadas en codigo real: " + ", ".join(fn_list) + "."

    # For HUECO (not dynamically verified), use the LLM-developed PoC script as the report
    developed_script = batch.get("developed_script") or ""
    markdown_report = ""
    if developed_script and not verified:
        # Wrap the script so it renders properly in the informe
        markdown_report = (
            f"# PoC desarrollado por binoracle (sin verificacion dinamica)\n\n"
            f"Este CVE es un **HUECO** — no existe exploit publico previo. El script siguiente "
            f"fue generado por el motor a partir del analisis del codigo fuente real.\n\n"
            f"```bash\n{developed_script.strip()}\n```\n\n"
            f"{grounded_note}"
        )

    logs = _build_logs_from_ae(ae) if verified else []

    r = {
        "cvss_score":       batch.get("cvss_score"),
        "cvss_severity":    batch.get("cvss_severity"),
        "cvss_vector":      batch.get("cvss_vector"),
        "description":      batch.get("description"),
        "vuln_class":       batch.get("vuln_class"),
        "published":        batch.get("published") or "2026",
        "poc_source":       batch.get("poc_source_used") or "",
        "verified":         verified,
        "affected_version": llm.get("affected_version") or "(ver NVD)",
        "markdown_report":  markdown_report,
        "logs":             logs,
        "evidence":         {"screenshots": ae.get("screenshots") or []},
        "verified_evidence": ve,
        "detail":           grounded_note,
    }

    # Use stored screenshots; auto-generate if none and Pillow available
    _stored_shots = ae.get("screenshots") or []
    if len(_stored_shots) < 2 and verified and _auto_screenshots:
        _stored_shots = _auto_screenshots(cve_id, r, ve)
    html = build_informe(cve_id, r, ve, _stored_shots, logs)
    dest = os.path.join(OUT, f"{cve_id}_informe_pdf.html")
    with open(dest, "w", encoding="utf-8") as f:
        f.write(html)

    shots = len([s for s in (ae.get("screenshots") or [])
                 if (isinstance(s, dict) and s.get("png_b64"))
                 or (isinstance(s, list) and len(s) > 1 and s[1])])
    status = "VERIFICADO" if verified else "HUECO"
    print(f"[OK] {cve_id} ({status}) — {shots} capturas -> {os.path.basename(dest)}")
    processed += 1

print(f"\n{processed} informes generados en {OUT}/")
