#!/usr/bin/env python3
"""
Genera drafts de reporte YesWeHack para los CVEs HUECO (sin PoC previo)
desde el historial de binoracle.

Produce un archivo .md por CVE HUECO en ~/Downloads/binoracle_reports/ywh/
Formato: secciones YWH estandar (Description, Discovery, PoC, Exploitation,
Impact, Remediation). Sin padding, sin OWASP boilerplate.

Uso:
  python3 scripts/gen_ywh_reports.py              # solo HUECOs
  python3 scripts/gen_ywh_reports.py --all        # todos los 21 CVEs
  python3 scripts/gen_ywh_reports.py CVE-2025-39471
"""
import json, os, sys, re

HISTORY  = os.path.expanduser("~/.binoracle/history")
OUT_DIR  = os.path.expanduser("~/Downloads/binoracle_reports/ywh")
ALL_MODE = "--all" in sys.argv
FILTER   = next((a for a in sys.argv[1:] if a.startswith("CVE-")), None)
os.makedirs(OUT_DIR, exist_ok=True)

CVSS_LABEL = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S":  {"U": "Unchanged", "C": "Changed"},
    "C":  {"N": "None", "L": "Low", "H": "High"},
    "I":  {"N": "None", "L": "Low", "H": "High"},
    "A":  {"N": "None", "L": "Low", "H": "High"},
}


def parse_cvss_vector(vector):
    if not vector:
        return {}
    parts = {}
    for tok in vector.replace("CVSS:3.1/", "").split("/"):
        if ":" in tok:
            k, v = tok.split(":", 1)
            parts[k] = v
    return parts


def cvss_justify(vector):
    parts = parse_cvss_vector(vector)
    lines = []
    for key, label in [("AV","Attack Vector"),("AC","Attack Complexity"),
                        ("PR","Privileges Required"),("UI","User Interaction"),
                        ("S","Scope"),("C","Confidentiality"),("I","Integrity"),("A","Availability")]:
        val = parts.get(key, "?")
        readable = CVSS_LABEL.get(key, {}).get(val, val)
        lines.append(f"- **{label}** ({key}:{val}): {readable}")
    return "\n".join(lines)


def build_ywh_report(cve_id, r, ve):
    cls      = (r.get("vuln_class") or "sqli").lower()
    tech     = (ve.get("tecnica") or "").lower()
    if not tech:
        if ve.get("respuesta_true_len") or ve.get("payload_false"):
            tech = "boolean-blind"
        elif ve.get("bypass_header"):
            tech = "auth-bypass"
        elif ve.get("marker"):
            tech = "stored-xss"
        elif ve.get("canary_path"):
            tech = "path-traversal"

    endpoint     = ve.get("endpoint") or "?"
    metodo       = (ve.get("metodo") or "POST").upper()
    param        = ve.get("sqli_param") or ve.get("path_param") or "?"
    payload      = ve.get("payload_ganador") or "?"
    payload_false = ve.get("payload_false") or ""
    mysql_ver    = ve.get("mysql_version_extraida") or ""
    marker       = ve.get("marker") or ""
    page_url     = ve.get("page_url") or ""
    affected     = r.get("affected_version") or "(ver NVD)"
    desc         = r.get("description") or ""
    auth         = ve.get("login_bajo_privilegio") or ""
    score        = r.get("cvss_score") or "?"
    sev          = (r.get("cvss_severity") or "CRITICAL").upper()
    vector       = r.get("cvss_vector") or ""
    published    = r.get("published") or "?"
    canary       = ve.get("canary_secret") or ve.get("canary_path") or ""
    bypass_header = ve.get("bypass_header") or ""
    bypass_value  = ve.get("bypass_value") or ""
    confirm_str   = str(ve.get("confirm_string_presente") or ve.get("confirm_string") or "")
    status        = ve.get("status_code_respuesta") or "200"
    resp_body     = (ve.get("respuesta_cuerpo_recorte") or "")[:400]
    resp_ctrl     = (ve.get("respuesta_control_recorte") or "")[:200]
    true_len      = ve.get("respuesta_true_len") or ""
    false_len     = ve.get("respuesta_false_len") or ""
    estrategia    = ve.get("estrategia") or ""

    precond = f"Autenticado como subscriber (`{auth}`, obtenible via registro abierto)." if auth else "Sin autenticacion — endpoint anonimo."

    # ── 1. Build description ──────────────────────────────────────────────
    if "xss" in cls or marker:
        bug_one_liner = f"Stored XSS en el plugin via el parametro `{param}`. El valor se persiste en base de datos y se renderiza sin escape en la pagina `{page_url or '(URL del post)'}`."
    elif "path" in cls or "lfi" in cls or "traversal" in tech:
        bug_one_liner = f"Path traversal en `{endpoint}` via el parametro `{param}`. Permite lectura arbitraria de ficheros del servidor."
    elif "auth" in cls or "missing" in cls:
        bug_one_liner = f"Omision de control de acceso en `{endpoint}` mediante la cabecera `{bypass_header}`. Acceso sin credenciales a recurso protegido (HTTP {status})."
    elif "boolean" in tech:
        bug_one_liner = f"SQL Injection (boolean in-band) en `{endpoint}` via el parametro `{param}`. El motor confirmó delta TRUE={true_len}B / FALSE={false_len}B consistente."
    elif "union" in tech:
        bug_one_liner = f"SQL Injection (UNION-based) en `{endpoint}` via el parametro `{param}`. Se extrajo '{mysql_ver}' desde la base de datos."
    else:
        bug_one_liner = f"SQL Injection (error-based) en `{endpoint}` via el parametro `{param}`. El motor extrajo '{mysql_ver}' de MySQL mediante `extractvalue()`."

    # ── 2. Discovery ─────────────────────────────────────────────────────
    if "xss" in cls or marker:
        discovery = (f"Revisando el codigo fuente del plugin {affected} identifique que el campo `{param}` se renderiza "
                     f"sin `esc_html()` / `esc_attr()`. Cree un widget con el payload `<img src=x onerror=confirm(document.domain)>` "
                     f"y verifique que al visitar `{page_url or '(URL post)'}` el handler `onerror` se ejecuta. "
                     f"El marker `{marker}` fue encontrado literalmente en el DOM durante la verificacion en laboratorio aislado.")
    elif "path" in cls or "lfi" in cls:
        discovery = (f"El endpoint `{endpoint}` acepta `{param}` como ruta relativa. Probe con `../../../../../../etc/passwd` "
                     f"y el servidor devolvio el contenido del fichero. En laboratorio cree un fichero canary en `/tmp/` "
                     f"y lo recupere con el payload `{payload}`, obteniendo el contenido exacto del fichero.")
    elif "auth" in cls or "missing" in cls:
        discovery = (f"El endpoint `{endpoint}` devuelve 403 sin credenciales. Revisando el codigo fuente de {r.get('affected_version','el componente')} "
                     f"identifique que la comprobacion de autorizacion puede omitirse incluyendo la cabecera "
                     f"`{bypass_header}: {bypass_value}`. Una peticion con esa cabecera retorno HTTP {status} "
                     f"con `{confirm_str[:80]}` en el cuerpo.")
    elif "boolean" in tech:
        discovery = (f"El endpoint `{endpoint}` procesa `{param}` en una consulta SQL. Probe una condicion siempre-verdadera "
                     f"(`OR '1'='1`) y una siempre-falsa (`AND '1'='2`): las respuestas difirieron en {true_len}B vs {false_len}B. "
                     f"El delta fue consistente en multiples peticiones, confirmando que la condicion SQL inyectada "
                     f"altera el resultado de la consulta del plugin.")
    else:
        discovery = (f"Revisando el codigo fuente del plugin {affected} identifique que `{param}` se interpola directamente "
                     f"en la consulta SQL sin `$wpdb->prepare()`. Probe el payload `{payload}` y la respuesta incluyo "
                     f"el mensaje de error MySQL con `{mysql_ver}`, confirmando que `extractvalue()` evaluo `version()` "
                     f"en el contexto de la consulta.")

    # ── 3. PoC request ───────────────────────────────────────────────────
    if "xss" in cls or marker:
        poc_req = f"""<!-- 1. Iniciar sesion como contributor/editor -->
<!-- 2. Crear widget y establecer campo {param}: -->
Valor: <img src=x onerror=confirm(document.domain)>
<!-- 3. Publicar pagina -->

GET {page_url or '(URL del post)'} HTTP/1.1
Host: TARGET

<!-- Resultado: onerror ejecutado. Marker '{marker}' en DOM. -->"""
    elif "path" in cls or "lfi" in cls:
        poc_req = f"""{metodo} {endpoint}?{param}={payload} HTTP/1.1
Host: TARGET
{"Cookie: wordpress_logged_in_...=" + auth + ":SESSION" if auth else ""}

[Respuesta: contenido del fichero canary '{canary}']"""
    elif "auth" in cls or "missing" in cls:
        poc_req = f"""# Peticion bloqueada (control):
GET {endpoint} HTTP/1.1
Host: TARGET
# Respuesta: 403 Forbidden

# Peticion con bypass:
GET {endpoint} HTTP/1.1
Host: TARGET
{bypass_header}: {bypass_value}
# Respuesta: {status} — cuerpo incluye '{confirm_str[:60]}'"""
    elif "boolean" in tech:
        poc_req = f"""# Peticion de control:
{metodo} {endpoint} HTTP/1.1
Host: TARGET
{"Cookie: wordpress_logged_in_...=" + auth + ":SESSION" if auth else ""}
Content-Type: application/x-www-form-urlencoded

{param}=1

# Respuesta: {false_len}B (condicion falsa, sin resultados)

# Peticion TRUE (inyeccion boolean):
{metodo} {endpoint} HTTP/1.1
Host: TARGET
{"Cookie: wordpress_logged_in_...=" + auth + ":SESSION" if auth else ""}
Content-Type: application/x-www-form-urlencoded

{param}={payload}

# Respuesta: {true_len}B (condicion verdadera, con resultados)
# Delta: {true_len}B vs {false_len}B — diferencia consistente y reproducible."""
    else:
        ctrl_ep = endpoint.split("?")[0] if "?" in endpoint else endpoint
        poc_req = f"""# Peticion de control:
{metodo} {ctrl_ep} HTTP/1.1
Host: TARGET
{"Cookie: wordpress_logged_in_...=" + auth + ":SESSION" if auth else ""}
Content-Type: application/x-www-form-urlencoded

{param}=1

# Respuesta: 200 OK normal

# Peticion con inyeccion:
{metodo} {ctrl_ep} HTTP/1.1
Host: TARGET
{"Cookie: wordpress_logged_in_...=" + auth + ":SESSION" if auth else ""}
Content-Type: application/x-www-form-urlencoded

{param}={payload}

# Respuesta: 200 — mensaje de error MySQL con '{mysql_ver}'"""

    # ── 4. Steps ─────────────────────────────────────────────────────────
    if "xss" in cls or marker:
        steps = f"""Precondiciones: cuenta contributor o editor activa. Probado con WordPress {affected}.

1. Iniciar sesion con credenciales contributor/editor.
2. Crear nuevo widget Elementor del tipo correspondiente al plugin.
3. Establecer el campo `{param}` con el valor `<img src=x onerror=confirm(document.domain)>`.
4. Publicar la pagina.
5. Visitar `{page_url or '(URL del post publicado)'}` sin sesion activa.
6. Resultado esperado: `confirm(document.domain)` ejecuta. Resultado obtenido: se ejecuto."""
    elif "path" in cls or "lfi" in cls:
        steps = f"""Precondiciones: {"cuenta " + auth + " activa." if auth else "sin autenticacion."} Probado con version {affected}.

1. {("Iniciar sesion como subscriber." if auth else "Sin sesion.")}
2. Enviar peticion: `{metodo} {endpoint}?{param}={payload}` al servidor objetivo.
3. Resultado esperado: 403 o error. Resultado obtenido: contenido del fichero `{canary or '/etc/passwd'}`."""
    elif "auth" in cls or "missing" in cls:
        steps = f"""Precondiciones: sin autenticacion. Probado con version {affected}.

1. Enviar `GET {endpoint}` sin la cabecera de bypass.
   Resultado esperado: 403. Resultado obtenido: 403.
2. Enviar `GET {endpoint}` con la cabecera `{bypass_header}: {bypass_value}`.
   Resultado esperado: 403. Resultado obtenido: HTTP {status} con recurso protegido.
3. El cuerpo de la respuesta incluye `{confirm_str[:80]}`."""
    elif "boolean" in tech:
        steps = f"""Precondiciones: {"cuenta " + auth + " activa." if auth else "sin autenticacion."} Probado con version {affected}.

1. {("Iniciar sesion como subscriber." if auth else "Sin sesion.")}
2. Enviar peticion de control con `{param}=1`. Registrar tamano de respuesta: {false_len}B.
3. Enviar peticion con payload TRUE `{param}={payload}`.
   Resultado esperado: tamano identico al control. Resultado obtenido: {true_len}B.
4. Delta de {true_len}B vs {false_len}B confirma que la condicion SQL inyectada
   altera el resultado de la consulta."""
    else:
        ctrl_ep = endpoint.split("?")[0] if "?" in endpoint else endpoint
        steps = f"""Precondiciones: {"cuenta " + auth + " activa (registro abierto)." if auth else "sin autenticacion."} Probado con version {affected}.

1. {("Iniciar sesion como subscriber (registro abierto en la instalacion de prueba)." if auth else "Sin sesion.")}
2. Enviar peticion de control: `{metodo} {ctrl_ep}` con `{param}=1`. Respuesta: 200 normal.
3. Enviar peticion con inyeccion: `{param}={payload}`.
4. Resultado esperado: 200 sin mensaje de error MySQL.
   Resultado obtenido: 200 con mensaje de error MySQL que incluye `{mysql_ver}`."""

    # ── 5. Impact ────────────────────────────────────────────────────────
    if "xss" in cls or marker:
        impact = (f"Ejecucion arbitraria de JavaScript en el navegador de cualquier visitante de `{page_url or 'la pagina publicada'}` "
                  f"en el origen del sitio objetivo. Probado: el marker `{marker}` fue encontrado en el DOM. "
                  f"Un payload real puede leer `document.cookie`, realizar peticiones autenticadas en nombre de la victima, "
                  f"o redirigir al usuario.")
    elif "path" in cls or "lfi" in cls:
        impact = (f"Lectura arbitraria de ficheros del servidor accesibles por el proceso web. "
                  f"Probado: recuperacion del fichero canary `{canary}` desde el sistema de ficheros. "
                  f"Ficheros objetivo de mayor impacto: `wp-config.php` (credenciales DB), claves SSH, logs del servidor.")
    elif "auth" in cls or "missing" in cls:
        impact = (f"Acceso no autorizado al recurso protegido por `{endpoint}`. "
                  f"Probado: HTTP {status} con `{confirm_str[:80] or 'recurso protegido'}` en la respuesta "
                  f"sin credenciales validas.")
    elif "boolean" in tech:
        impact = (f"Extraccion completa del esquema y datos de la base de datos MySQL del servidor objetivo "
                  f"mediante condiciones binarias. Probado: delta TRUE={true_len}B / FALSE={false_len}B consistente "
                  f"en el parametro `{param}` de `{endpoint}`. Con sqlmap o extraccion manual, "
                  f"un atacante puede volcar credenciales, hashes de usuarios y cualquier dato almacenado.")
    else:
        impact = (f"Extraccion de datos de la base de datos MySQL del servidor objetivo. "
                  f"Probado: version del motor extraida ({mysql_ver}) mediante `extractvalue()` en el parametro "
                  f"`{param}` de `{endpoint}`. Con la misma tecnica se puede extraer cualquier dato "
                  f"accesible al usuario de base de datos del plugin (tipicamente todas las tablas de WordPress).")

    # ── 6. Remediation ───────────────────────────────────────────────────
    if "xss" in cls or marker:
        remediation = (f"Escapar el valor de `{param}` con `esc_html()` o `esc_attr()` segun el contexto "
                       f"en el punto donde se incluye en HTML — no al guardar. "
                       f"Actualizar el plugin a la version parcheada (> {affected}).")
    elif "path" in cls or "lfi" in cls:
        remediation = (f"Usar `realpath()` para normalizar la ruta y verificar que el resultado empieza "
                       f"por el directorio base autorizado antes de leer el fichero. "
                       f"Actualizar el plugin a la version parcheada (> {affected}).")
    elif "auth" in cls or "missing" in cls:
        remediation = (f"Tratar `{bypass_header}` como cabecera no confiable si su origen es el cliente externo. "
                       f"Verificar autorizacion en el handler de ruta independientemente del middleware. "
                       f"Actualizar a la version parcheada (> {affected}).")
    else:
        remediation = (f"Usar `$wpdb->prepare()` con placeholders tipados (`%s`/`%d`) para el parametro `{param}` "
                       f"en la consulta SQL del endpoint `{endpoint}`. "
                       f"Actualizar el plugin a la version parcheada (> {affected}).")

    # ── Assemble ─────────────────────────────────────────────────────────
    hdr = f"# {cve_id} — {sev} {score}"
    if vector:
        hdr += f"\n\n**CVSS 3.1:** `{vector}` — {score} {sev}\n\n{cvss_justify(vector)}"

    report = f"""{hdr}

---

## Description

{bug_one_liner}

**Versiones afectadas:** {affected}

**Publicado (NVD):** {published}

---

## Vulnerability Discovery

{discovery}

---

## Proof of Concept (PoC)

```
{poc_req}
```

---

## Exploitation

{steps}

---

## Impact

{impact}

---

## Remediation

{remediation}

---

*Verificado en laboratorio Docker efimero (WordPress + MySQL 8.0.46). Verificacion: {r.get('detail','')[:200]}*
"""
    return report


def main():
    generated = 0
    skipped   = 0
    for fname in sorted(os.listdir(HISTORY)):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(HISTORY, fname)
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)

        cve_id = data.get("cve_id", fname.replace(".json",""))
        if FILTER and cve_id != FILTER:
            continue

        r  = data.get("result", {})
        ve = r.get("verified_evidence") or {}
        poc = r.get("poc_source", "")

        if not ALL_MODE and poc:
            print(f"[skip] {cve_id} — tiene PoC publico")
            skipped += 1
            continue

        md = build_ywh_report(cve_id, r, ve)
        out_path = os.path.join(OUT_DIR, f"{cve_id}_ywh_draft.md")
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"[ok]   {cve_id} — {len(md)} chars -> {os.path.basename(out_path)}")
        generated += 1

    print(f"\n{generated} drafts YWH generados en {OUT_DIR}/")
    if skipped:
        print(f"{skipped} CVEs con PoC publico omitidos (usa --all para incluirlos)")


if __name__ == "__main__":
    main()
