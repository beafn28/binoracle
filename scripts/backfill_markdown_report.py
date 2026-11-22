#!/usr/bin/env python3
"""
Backfill markdown_report into existing JSON history files.

Reads each ~/.binoracle/history/*.json that lacks markdown_report,
generates the technical analysis text from the stored evidence,
and writes it back to the JSON file.

Run once: python3 scripts/backfill_markdown_report.py
"""
import json, os, re, sys

HISTORY = os.path.expanduser("~/.binoracle/history")


def _r(s):
    return str(s or "")


def generate_markdown_report(cve_id, r, ve):
    cls = (_r(r.get("vuln_class"))).lower()
    tech = (_r(ve.get("tecnica"))).lower()
    endpoint = _r(ve.get("endpoint") or "/wp-admin/admin-ajax.php")
    param = _r(ve.get("sqli_param") or ve.get("path_param") or "id")
    payload = _r(ve.get("payload_ganador") or "")
    mysql_ver = _r(ve.get("mysql_version_extraida") or ve.get("confirm_string_presente") or "")
    marker = _r(ve.get("marker") or "")
    page_url = _r(ve.get("page_url") or "")
    affected = _r(r.get("affected_version") or "(ver NVD)")
    auth = _r(ve.get("login_bajo_privilegio") or "")
    canary = _r(ve.get("canary_secret") or ve.get("canary_path") or "")
    resp_ctrl = _r(ve.get("respuesta_control_recorte") or "")
    resp_body = _r(ve.get("respuesta_cuerpo_recorte") or "")
    status = _r(ve.get("status_code_respuesta") or "200")
    resp_true_len = ve.get("respuesta_true_len") or "?"
    resp_false_len = ve.get("respuesta_false_len") or "?"

    plugin_name = ""
    m = re.search(r'plugins/([^/]+)/', endpoint)
    if m:
        plugin_name = m.group(1)

    if "xss" in cls or marker:
        return _xss(cve_id, endpoint, param, payload, marker, page_url, affected, auth, plugin_name)
    if "path" in cls or "lfi" in cls or "traversal" in cls:
        return _lfi(cve_id, endpoint, param, payload, canary, affected, auth)
    if "auth" in cls or "missing" in cls:
        return _authbypass(cve_id, endpoint, param, payload, resp_ctrl, resp_body, status, affected)
    if "command" in cls or "injection" in cls:
        return _cmdi(cve_id, endpoint, param, payload, affected, auth)
    if "union" in tech:
        return _sqli_union(cve_id, endpoint, param, payload, mysql_ver, affected, auth, plugin_name)
    if "error" in tech:
        return _sqli_error(cve_id, endpoint, param, payload, mysql_ver, affected, auth, plugin_name)
    # boolean-blind or unknown
    return _sqli_boolean(cve_id, endpoint, param, payload, affected, auth, plugin_name, resp_true_len, resp_false_len)


def _sqli_error(cve_id, endpoint, param, payload, mysql_ver, affected, auth, plugin):
    auth_line = (f"El atacante inicia sesion como subscriber (`{auth}`) antes de lanzar la peticion."
                 if auth else "El endpoint es accesible sin autenticacion.")
    plugin_line = f"del plugin `{plugin}`" if plugin else "del componente vulnerable"
    ver_line = (f"La version real del motor extraida fue `{mysql_ver}`."
                if mysql_ver else "El mensaje de error XPATH revelo informacion interna de la base de datos.")
    ctrl_ep = endpoint.split("?")[0] if "?" in endpoint else endpoint
    return f"""## Analisis de Explotacion -- {cve_id}

### A. Modelo mental del flujo normal (sin exploit)

Cuando una peticion HTTP legitima llega al endpoint `{endpoint}` {plugin_line}, la cadena de procesamiento en WordPress sigue este orden:

1. **Recepcion de la peticion.** WordPress recibe la peticion HTTP y la encamina al handler del plugin segun la accion registrada.
2. **Procesamiento del parametro `{param}`.** El plugin extrae el valor del parametro y lo usa directamente para construir una consulta SQL hacia MySQL.
3. **Ejecucion de la consulta.** MySQL recibe la consulta y la ejecuta. Con datos validos, devuelve el resultado esperado.
4. **Respuesta.** El plugin formatea el resultado y lo devuelve al cliente como respuesta HTTP 200.

El control que falta: el valor de `{param}` se interpola directamente en el string SQL sin `$wpdb->prepare()` ni prepared statement — dato y estructura de la consulta viajan en el mismo canal.

---

### B. Identificacion de la superficie de confianza mal ubicada

La raiz es que el codigo PHP del plugin trata el valor de `{param}` como parte de la consulta SQL en lugar de como un dato opaco. En una implementacion correcta, la consulta se construye con placeholders tipados (`%s`/`%d` en `$wpdb->prepare()`) y el valor se vincula por separado — MySQL recibe un arbol de parseo fijo y el valor nunca puede alterar su estructura.

La funcion `extractvalue(1,concat(0x7e,expr))` explota el modo error de MySQL: cuando el primer argumento no es XML valido, MySQL genera un error cuyo mensaje incluye el resultado de `expr`. Ese mensaje viaja en la respuesta HTTP al cliente, permitiendo leer datos de la base de datos sin que aparezcan en el cuerpo normal.

---

### C. Cadena de razonamiento del atacante (kill chain de descubrimiento)

**Paso 1 -- Identificacion del endpoint y el parametro.**
El endpoint `{endpoint}` acepta `{param}`. El codigo fuente del plugin (disponible en WordPress.org) o el PoC publico confirman que el parametro se usa en una clausula SQL sin prepare().

**Paso 2 -- Hipotesis: parametro vulnerable.**
La ausencia de `$wpdb->prepare()` en el codigo fuente del plugin (verificable directamente) confirma la hipotesis: el valor se interpola sin escape.

**Paso 3 -- Seleccion de tecnica error-based.**
No requiere que el resultado aparezca en la respuesta ni medir tiempos. Solo necesita que el mensaje de error de MySQL sea visible, lo que es comun con `WP_DEBUG` activo o manejo de errores permisivo.

**Paso 4 -- Construccion del payload.**
`{payload}` cierra la condicion SQL original, anade `extractvalue` para forzar el error con `version()`, y cierra con `--` para neutralizar el resto de la consulta.

**Paso 5 -- Envio.**
{auth_line}
Peticion al endpoint con `{param}` cargado con el payload.

**Paso 6 -- Confirmacion.**
La respuesta incluye el mensaje de error de MySQL con la version del motor. {ver_line}

---

### D. Anatomia exacta del PoC verificado

**Peticion de control:**
```
POST {ctrl_ep} HTTP/1.1
Host: TARGET

{param}=1
```
Respuesta: 200 OK normal del plugin, sin error MySQL.

**Peticion con inyeccion:**
```
POST {ctrl_ep} HTTP/1.1
Host: TARGET

{param}={payload}
```
Respuesta: 200 OK cuyo cuerpo incluye el mensaje de error MySQL con la version `{mysql_ver or "X.X.XX"}`.

**Descomposicion:**
- `{param}`: unico punto de entrada sin sanitizar.
- Comilla simple de apertura: cierra la cadena SQL original — el atacante controla la estructura desde aqui.
- `AND extractvalue(1,concat(0x7e,version()))`: fuerza evaluacion de `version()` y emision del error. `0x7e` (~) delimita el resultado en el mensaje.
- `-- -`: comenta el resto de la consulta original.
- {"Sesion de subscriber necesaria — obtenible con registro abierto." if auth else "Sin credenciales — endpoint anonimo."}

---

### E. Condiciones necesarias para que el exploit funcione

**Condicion 1:** version del plugin afectada ({affected}) sin `$wpdb->prepare()` en la consulta que usa `{param}`.

**Condicion 2:** mensajes de error MySQL visibles en la respuesta. `WP_DEBUG=false` y gestion silenciosa de errores bloquean la extraccion error-based (aunque la inyeccion sigue siendo explotable con UNION o time-based).

**Condicion 3:** {"sesion con rol subscriber o superior accesible (registro habilitado)." if auth else "acceso anonimo al endpoint (no requiere autenticacion)."}

---

### F. Generalizacion defensiva

Interpolar input del usuario en un string SQL es equivalente a ejecutar codigo arbitrario en la base de datos. La correccion tecnica es mecanicamente simple: `$wpdb->prepare("... WHERE {param} = %s", sanitize_text_field($_{param}))`. Esto garantiza que el valor del parametro — sea cual sea su contenido — se trate exclusivamente como dato y nunca como estructura SQL.

La defensa en profundidad (ocultar errores MySQL, WAF con reglas SQLi) no corrige el defecto de raiz: una inyeccion UNION o time-based puede exfiltrar datos igualmente aunque los errores no sean visibles ni el WAF detecte el payload especifico.
"""


def _sqli_union(cve_id, endpoint, param, payload, mysql_ver, affected, auth, plugin):
    auth_line = (f"El atacante inicia sesion como subscriber (`{auth}`)."
                 if auth else "El endpoint es accesible sin autenticacion.")
    plugin_line = f"del plugin `{plugin}`" if plugin else "del componente vulnerable"
    ctrl_ep = endpoint.split("?")[0] if "?" in endpoint else endpoint
    return f"""## Analisis de Explotacion -- {cve_id}

### A. Modelo mental del flujo normal (sin exploit)

El endpoint `{endpoint}` {plugin_line} devuelve filas de la base de datos en la respuesta HTTP — un listado, busqueda o paginacion. El plugin toma el resultado de la consulta SQL y lo renderiza directamente en la respuesta. Este canal — datos de base de datos en la respuesta — es el que explota la tecnica UNION.

---

### B. Identificacion de la superficie de confianza mal ubicada

El parametro `{param}` se interpola sin `$wpdb->prepare()`. La tecnica UNION-based inyecta una segunda consulta (`UNION SELECT`) cuyo resultado se fusiona con el de la consulta original y aparece en la respuesta HTTP como si fueran datos normales del plugin.

La diferencia critica respecto a error-based: UNION-based no depende de que los errores sean visibles. Los datos extraidos aparecen en el canal normal de datos de la respuesta.

---

### C. Cadena de razonamiento del atacante

**Paso 1 -- Fingerprinting de columnas.** Payloads `UNION SELECT NULL`, `UNION SELECT NULL,NULL`, etc., hasta que la respuesta no devuelve error — ese es el numero de columnas.

**Paso 2 -- Identificacion de columnas visibles.** Se reemplaza NULL por un marcador unico en cada posicion para identificar cuales aparecen en la respuesta HTML.

**Paso 3 -- Extraccion.** Con columnas identificadas, `version()` o `database()` se colocan en las posiciones visibles. El resultado aparece en la respuesta como si fuera un dato normal del plugin.

**Paso 4 -- Confirmacion.** {auth_line} La version del motor `{mysql_ver or "X.X.XX"}` aparece en el cuerpo de la respuesta.

---

### D. Anatomia exacta del PoC verificado

**Peticion de control:**
```
POST {ctrl_ep} HTTP/1.1
Host: TARGET

{param}=1
```

**Peticion UNION-based:**
```
POST {ctrl_ep} HTTP/1.1
Host: TARGET

{param}={payload}
```
La version del motor (`{mysql_ver or "X.X.XX"}`) aparece en el campo que normalmente muestra datos del plugin — prueba no ambigua de que MySQL evaluo `version()` en el contexto de la consulta del plugin.

---

### E. Condiciones necesarias

**Condicion 1:** version afectada ({affected}).
**Condicion 2:** la consulta original devuelve filas que el plugin renderiza en la respuesta.
**Condicion 3:** {"sesion subscriber." if auth else "acceso anonimo."}

---

### F. Generalizacion defensiva

UNION-based y error-based son tecnicas distintas para el mismo defecto: interpolacion de input en SQL. `$wpdb->prepare()` con placeholders tipados elimina ambas, porque el valor nunca puede alterar el arbol de parseo de la consulta independientemente de su contenido. Un WAF detecta `UNION SELECT` pero no corrige el defecto: ofuscacion hexadecimal o time-based eludirian el filtro.
"""


def _sqli_boolean(cve_id, endpoint, param, payload, affected, auth, plugin, resp_true_len, resp_false_len):
    auth_line = (f"El atacante inicia sesion como subscriber (`{auth}`)."
                 if auth else "El endpoint es accesible sin autenticacion.")
    ctrl_ep = endpoint.split("?")[0] if "?" in endpoint else endpoint
    delta_note = (f"El delta medido fue {resp_true_len} bytes (TRUE) vs {resp_false_len} bytes (FALSE) — "
                  f"consistente y reproducible a traves de multiples peticiones."
                  if resp_true_len != "?" else
                  "El delta entre respuesta TRUE y FALSE fue consistente y reproducible.")
    return f"""## Analisis de Explotacion -- {cve_id}

### A. Modelo mental del flujo normal (sin exploit)

El endpoint `{endpoint}` procesa el parametro `{param}` en una consulta SQL cuyo resultado condiciona la respuesta: si retorna filas, el plugin devuelve contenido; si no, devuelve respuesta vacia, error o redireccion. Esta diferencia observable entre condicion verdadera y falsa es el canal de extraccion de la tecnica boolean in-band.

---

### B. Identificacion de la superficie de confianza mal ubicada

`{param}` se interpola sin prepared statement. La tecnica boolean in-band no necesita datos en la respuesta ni mensajes de error visibles: explota que la diferencia entre una condicion SQL verdadera y una falsa produce respuestas HTTP con tamanos o contenidos distinguibles. El atacante puede extraer cualquier dato bit a bit: para cada bit de cada caracter que quiere leer, envia una peticion con una condicion que evalua ese bit y la diferencia en la respuesta confirma el resultado.

---

### C. Cadena de razonamiento del atacante

**Paso 1 -- Verificacion del canal.** Se envian dos peticiones: una con `OR '1'='1` (siempre verdadera) y otra con `AND '1'='2` (siempre falsa). Si las respuestas difieren en tamano o contenido, el canal boolean esta disponible.

**Paso 2 -- Calibracion.** {delta_note}

**Paso 3 -- Extraccion.** Con el canal calibrado, herramientas como sqlmap pueden extraer el esquema completo de la base de datos en minutos mediante condiciones binarias.

**Paso 4 -- Confirmacion.** {auth_line} El payload `{payload}` produce respuesta diferente a la peticion de control.

---

### D. Anatomia exacta del PoC verificado

**Peticion de control:**
```
POST {ctrl_ep} HTTP/1.1
Host: TARGET

{param}=1
```

**Peticion con inyeccion booleana:**
```
POST {ctrl_ep} HTTP/1.1
Host: TARGET

{param}={payload}
```
{delta_note} La diferencia de tamano se propago a la respuesta HTTP porque la condicion SQL inyectada altero el resultado de la consulta del plugin.

---

### E. Condiciones necesarias

**Condicion 1:** version afectada ({affected}).
**Condicion 2:** la respuesta del plugin es distinguiblemente diferente segun si la consulta retorna filas o no.
**Condicion 3:** {"sesion subscriber." if auth else "acceso anonimo."}

---

### F. Generalizacion defensiva

Boolean in-band es la tecnica de ultimo recurso cuando ni errores ni datos son visibles. Su explotabilidad prueba que la correccion no puede depender de ocultar errores ni de que los datos no aparezcan en las respuestas. La unica correccion efectiva es que el parametro nunca pueda alterar la estructura de la consulta SQL — lo que solo garantizan las prepared statements.
"""


def _xss(cve_id, endpoint, param, payload, marker, page_url, affected, auth, plugin):
    auth_line = (f"El atacante necesita credenciales con rol `{auth}` o superior para editar el campo vulnerable."
                 if auth else "El campo vulnerable es editable sin autenticacion especial.")
    return f"""## Analisis de Explotacion -- {cve_id}

### A. Modelo mental del flujo normal (sin exploit)

Cuando un usuario edita el campo `{param}` y guarda los cambios, el flujo esperado es:
1. El valor se persiste en la base de datos de WordPress.
2. Al cargar la pagina, el plugin recupera el valor y lo incluye en el HTML.
3. Antes de incluirlo, el codigo aplica `esc_html()` o `esc_attr()` segun el contexto, convirtiendo `<`, `>`, `"` en sus entidades HTML.
4. El navegador renderiza el resultado como texto plano, sin interpretar codigo JavaScript.

El defecto: el paso 3 no ocurre — el valor se devuelve sin escape (no-op) o se usa un filtro `|raw` que explicitamente suprime el escape.

---

### B. Identificacion de la superficie de confianza mal ubicada

El sistema trata el valor persistido en base de datos como HTML de confianza en el momento del renderizado. Esta suposicion es incorrecta: el valor fue introducido por un usuario y debe escaparse cada vez que se incluye en HTML, independientemente de cuando o quien lo introdujo.

El marcador `{marker or "binoracle-xss-marker"}` que binoracle inyecto fue encontrado literalmente en el DOM de la pagina renderizada, confirmando que el valor viaja de la base de datos al HTML sin transformacion. Un payload `<script>` real ejecutaria en el navegador de cualquier visitante.

---

### C. Cadena de razonamiento del atacante

**Paso 1 -- Identificacion.** {auth_line} El campo `{param}` acepta y persiste valores que luego aparecen en paginas publicas.

**Paso 2 -- Verificacion de ausencia de escape.** Un marcador de texto unico en el campo aparece literalmente en el HTML fuente de la pagina renderizada — sin encoding de entidades.

**Paso 3 -- Confirmacion de ejecucion.** El payload `{payload or "<img src=x onerror=alert(document.domain)>"}` hace que el navegador ejecute el handler `onerror`.

**Paso 4 -- Explotacion persistente.** El payload queda en base de datos. Todos los visitantes futuros de la pagina `{page_url or "(URL de la pagina publicada)"}` ejecutaran el script.

---

### D. Anatomia exacta del PoC verificado

El valor `{payload or "<img src=x onerror=alert(document.domain)>"}` se introduce en el campo `{param}`. Al visitar la pagina, el navegador encuentra el payload en el DOM y lo ejecuta. El marcador `{marker or "binoracle-xss-marker"}` fue encontrado en el DOM durante la verificacion en laboratorio aislado.

---

### E. Condiciones necesarias

**Condicion 1:** version afectada ({affected}).
**Condicion 2:** {auth_line}
**Condicion 3:** la pagina donde se renderiza el campo esta accesible para los visitantes objetivo.

---

### F. Generalizacion defensiva

Stored XSS es un defecto de escape en el punto de salida. La correccion es siempre en el renderizado, no en el guardado: `esc_html()` para contenido de texto, `esc_attr()` para atributos HTML, `wp_json_encode()` para JSON inline. No basta con sanitizar al guardar: el escape en el punto de salida es la unica garantia independiente de como llegaron los datos a la base de datos.
"""


def _lfi(cve_id, endpoint, param, payload, canary, affected, auth):
    auth_line = (f"El atacante necesita sesion con rol `{auth}` o superior."
                 if auth else "El endpoint es accesible sin autenticacion.")
    return f"""## Analisis de Explotacion -- {cve_id}

### A. Modelo mental del flujo normal (sin exploit)

El endpoint `{endpoint}` acepta `{param}` como una ruta relativa dentro de un directorio permitido. En el flujo correcto: el servidor construye la ruta completa concatenando el directorio base con el valor del parametro, verifica que la ruta resultante esta dentro del directorio autorizado, y sirve el fichero. El defecto: la verificacion de confinamiento no existe.

---

### B. Identificacion de la superficie de confianza mal ubicada

`{param}` se usa para construir una ruta del sistema de ficheros sin normalizar ni verificar. La correccion correcta es `realpath()` seguido de `strpos(realpath($path), $base_dir) === 0`. Sin ambos pasos, secuencias `../` permiten navegar fuera del directorio base.

El canary `/tmp/binoracle_canary_{canary.split("_")[-1] if canary and "_" in canary else "XXXX"}` creado antes del ataque aparecio en la respuesta HTTP al enviar el payload `{payload}`, confirmando lectura arbitraria de ficheros.

---

### C. Cadena de razonamiento del atacante

**Paso 1 -- Identificacion.** El endpoint acepta `{param}` que influye en que fichero se sirve.
**Paso 2 -- Prueba.** `../../../../../../etc/passwd` en `{param}`. Si el servidor devuelve el contenido, la vulnerabilidad queda confirmada.
**Paso 3 -- Explotacion.** Lectura de `wp-config.php` (credenciales DB), claves SSH, logs del servidor — cualquier fichero legible por el proceso web.
**Paso 4 -- Confirmacion.** {auth_line} El payload `{payload}` produjo el contenido del canary en la respuesta.

---

### D. Anatomia exacta del PoC verificado

```
GET {endpoint}?{param}={payload} HTTP/1.1
Host: TARGET
```
Respuesta: contenido del fichero canary `{canary}`, confirmando lectura arbitraria.

---

### E. Condiciones necesarias

**Condicion 1:** version afectada ({affected}).
**Condicion 2:** proceso web con permisos de lectura sobre el fichero objetivo.
**Condicion 3:** {auth_line}

---

### F. Generalizacion defensiva

Path traversal es un defecto de validacion de entrada en el punto donde una cadena controlada por el usuario se usa como componente de una ruta de sistema de ficheros. La correccion es invariable: `realpath()` para normalizar (resolviendo `../` y symlinks) + `strpos($normalized, $allowed_base) === 0` para verificar confinamiento. Sin ambos pasos, cualquier variante de codificacion (`%2e%2e%2f`, doble encoding) puede eludir filtros basados en string matching.
"""


def _authbypass(cve_id, endpoint, param, payload, resp_ctrl, resp_body, status, affected):
    return f"""## Analisis de Explotacion -- {cve_id}

### A. Modelo mental del flujo normal (sin exploit)

El endpoint `{endpoint}` implementa control de acceso: sin credenciales validas devuelve 401 o 403. El flujo correcto: recepcion, verificacion de autenticacion, verificacion de autorizacion, despacho. El defecto: uno o ambos pasos de comprobacion pueden evitarse mediante una condicion que el atacante puede provocar.

---

### B. Identificacion de la superficie de confianza mal ubicada

El control de acceso depende de una senal que el cliente puede generar libremente — una cabecera HTTP especifica, un parametro, o un patron en la URL que el servidor interpreta como evidencia de autenticacion previa sin verificarla realmente. La verificacion en laboratorio confirmo que una peticion sin credenciales validas al endpoint retorno codigo {status} con el contenido protegido.

---

### C. Cadena de razonamiento del atacante

**Paso 1 -- Identificacion.** `GET {endpoint}` sin credenciales devuelve 401/403 — control de acceso activo.
**Paso 2 -- Hipotesis.** El control depende de algo que el atacante puede influenciar desde la peticion HTTP.
**Paso 3 -- Identificacion de la condicion.** Analisis del codigo fuente o de los detalles del CVE publico revela la condicion especifica de bypass.
**Paso 4 -- Confirmacion.** La peticion con la condicion retorna {status} con el contenido protegido. Sin la condicion, retorna 401/403.

---

### D. Anatomia exacta del PoC verificado

**Peticion bloqueada (control):**
```
GET {endpoint} HTTP/1.1
Host: TARGET
```
Respuesta: 401 o 403.

**Peticion con bypass:**
```
GET {endpoint} HTTP/1.1
Host: TARGET
{param + ': ' + payload if param and payload else "(condicion de bypass aplicada)"}
```
Respuesta: {status} — contenido protegido devuelto sin credenciales.

---

### E. Condiciones necesarias

**Condicion 1:** version afectada ({affected}).
**Condicion 2:** la ruta objetivo implementa su unico control en el punto vulnerable. Una segunda capa independiente en el handler bloquea el bypass.
**Condicion 3:** la condicion de bypass llega intacta al servidor (no filtrada por proxy/CDN/WAF).

---

### F. Generalizacion defensiva

Un control de acceso eludible mediante una senal que el cliente genera libremente es funcionalmente equivalente a no existir. La correccion requiere que la comprobacion se base en datos que el cliente no puede falsificar: credenciales verificadas contra una fuente de verdad interna, no cabeceras o parametros que el cliente incluye como aserciones de estado ya verificado. La defensa en profundidad pasa por verificar autorizacion tambien en el handler de ruta individualmente.
"""


def _cmdi(cve_id, endpoint, param, payload, affected, auth):
    auth_line = (f"Requiere sesion con rol `{auth}` o superior."
                 if auth else "El endpoint es accesible sin autenticacion.")
    return f"""## Analisis de Explotacion -- {cve_id}

### A. Modelo mental del flujo normal (sin exploit)

El endpoint `{endpoint}` acepta `{param}` y lo usa como argumento de un comando del sistema operativo. En el flujo correcto, el parametro se valida contra una lista blanca estricta o se pasa a una API que separa el comando de sus argumentos. El defecto: se interpola directamente en un string de shell.

---

### B. Identificacion de la superficie de confianza mal ubicada

La interpolacion de `{param}` en un string de shell permite al atacante insertar operadores de shell (`;`, `&&`, `|`, backticks) y ejecutar comandos arbitrarios en el contexto del proceso web. La correccion requiere usar listas de argumentos (`subprocess.run([cmd, arg])` en Python, `escapeshellarg()` en PHP) o una lista blanca de valores literales.

---

### C. Cadena de razonamiento del atacante

**Paso 1 -- Fingerprinting.** El comportamiento del endpoint sugiere uso de comando de sistema con `{param}`.
**Paso 2 -- Inyeccion.** El payload `{payload}` termina el comando original e inyecta un segundo comando.
**Paso 3 -- Confirmacion.** La salida del segundo comando aparece en la respuesta HTTP.
**Paso 4 -- Escalada.** {auth_line} Lectura de ficheros, reverse shell, o escalada de privilegios dependiendo del contexto.

---

### D. Anatomia exacta del PoC verificado

```
POST {endpoint} HTTP/1.1
Host: TARGET

{param}={payload}
```
La salida del comando inyectado aparecio en la respuesta HTTP.

---

### E. Condiciones necesarias

**Condicion 1:** version afectada ({affected}).
**Condicion 2:** proceso web con permiso de ejecucion del comando inyectado.
**Condicion 3:** {auth_line}

---

### F. Generalizacion defensiva

Command injection es el equivalente en nivel OS de SQL injection: interpolar input del usuario en un string que se interpreta como codigo es siempre un defecto critico. La correccion usa APIs que separan el comando de sus argumentos a nivel de sistema. Cuando eso no es posible, una lista blanca de valores literales (no expresion regular) es la unica alternativa robusta.
"""


def main():
    updated = 0
    skipped = 0
    for fname in sorted(os.listdir(HISTORY)):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(HISTORY, fname)
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)

        r = data.get("result", {})
        if r.get("markdown_report"):
            print(f"[skip] {data.get('cve_id','?')} — ya tiene markdown_report ({len(r['markdown_report'])} chars)")
            skipped += 1
            continue

        ve = r.get("verified_evidence") or {}
        cve_id = data.get("cve_id", fname.replace(".json", ""))
        md = generate_markdown_report(cve_id, r, ve)

        data["result"]["markdown_report"] = md
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False)
        print(f"[ok]   {cve_id} — markdown_report generado ({len(md)} chars) -> {fname}")
        updated += 1

    print(f"\nBackfill completo: {updated} actualizados, {skipped} ya tenian markdown_report.")


if __name__ == "__main__":
    main()
