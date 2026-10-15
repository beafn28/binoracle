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
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, List, Optional

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


@dataclass
class Investigation:
    cve_id: str
    description: str = ""
    lookup_ok: bool = False
    lookup_note: str = ""     # por que lookup_ok es False: formato invalido, red/rate-limit...
    is_gap: bool = False
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


_RESEARCH_SYS = (
    "Eres un investigador de explotacion para objetivos AUTORIZADOS (pentest/CTF/research). Analizas "
    "una vulnerabilidad y propones un plan tecnico. Responde SOLO con JSON valido con las claves: "
    "vuln_class (memoria: stack-overflow, heap-overflow, uaf, double-free, format-string, oob-write, "
    "oob-read, integer-overflow, type-confusion; WEB/APP: missing-authorization, idor, auth-bypass, "
    "sqli, xss, ssrf, command-injection, rce, path-traversal, file-upload, deserialization, xxe, "
    "ssti, csrf, open-redirect; u otra), primitive (que concede), target_binary (binario/componente "
    "a obtener, o el plugin/paquete), source_url (si lo sabes: repo git o zip del codigo vulnerable; "
    "para plugins WordPress deja el slug), affected_version (version afectada, p.ej. '5.1.8'), "
    "vulnerable_functions (lista de funciones/metodos citados, p.ej. update_user), trigger (como se "
    "alcanza: stdin/argumento/fichero/peticion HTTP...), http_method (GET/POST si es web), endpoint "
    "(ruta/accion si es web, p.ej. /wp-admin/admin-ajax.php?action=...), parameters (lista de "
    "parametros relevantes), auth_required (true/false/rol minimo), strategy (una frase), steps "
    "(lista de pasos concretos). Se tecnico y breve; deja vacio lo que no sepas."
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


def _apply_wpverify_result(inv, wr, es: bool) -> None:
    """Vuelca un WpVerifyResult (ver workflows/wpverify.py) en la investigacion -- mismo volcado
    que los bloques de missing-authorization/idor/path-traversal/command-injection/sqli/ssrf
    repetian literal; centralizado aqui para las clases que se fueron anadiendo despues (xss,
    ssti, xxe, open-redirect, file-upload, csrf) sin repetir el mismo bloque de 15 lineas otra vez
    por cada una."""
    inv.dynamic_verify = {"attempted": True, "available": wr.available, "ok": wr.ok,
                          "verified": wr.verified, "detail": wr.detail, "logs": wr.logs}
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
                trimmed = "\n".join(body.splitlines()[-15:])
                inv.blockers.append(f"{head}:\n```\n{trimmed}\n```")


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
    """Clona el PRIMER repo de GitHub de `exploit_refs` (el PoC YA PUBLICADO por su autor, no uno
    que desarrollemos nosotros -- viene de cvelookup.fetch_cve()/search_github_poc()) y devuelve el
    contenido concatenado de sus ficheros de texto (scripts/README), acotado en numero de ficheros
    y bytes. Confirmado en vivo (CVE-2024-1071): cuando "ya tiene exploit publico" solo se usaba
    para decidir si desarrollar uno desde cero, nunca para leer el que YA EXISTE -- el autor del
    PoC ya resolvio como dispararlo de verdad (endpoint exacto, payload exacto, precondiciones que
    documenta), informacion que una hipotesis generada solo desde el resumen de la CVE no tiene.
    None si no hay ningun ref de GitHub, git no esta disponible, o el clone falla -- best-effort,
    nunca lanza (exploit-db no se clona por git; su PoC, cuando lo haya, llega via el texto crudo
    que ya devuelve search_searchsploit si 'searchsploit' esta instalado, no por aqui)."""
    step = on_step or (lambda _m: None)
    github_refs = [r for r in (exploit_refs or []) if getattr(r, "source", "") == "github"]
    if not github_refs:
        return None
    from .websource import fetch_git_source
    for ref in github_refs[:2]:    # como mucho 2 repos, evita tardar mucho si el primero no sirve
        step(f"clonando el PoC publico real ({ref.url})...")
        fr = fetch_git_source(ref.url, timeout=timeout)
        if not fr.ok or not fr.local_path:
            continue
        chunks = []
        total = 0
        count = 0
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
                    with open(fp, "r", encoding="utf-8", errors="replace") as f:
                        text = f.read(_POC_MAX_BYTES_PER_FILE)
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
    return None


_EXTRACT_POC_SYS = (
    "Eres un investigador de explotacion para objetivos AUTORIZADOS (pentest/CTF/research). Te doy "
    "el contenido de un repositorio PUBLICO de GitHub que es el PoC REAL ya publicado para una CVE "
    "(codigo/scripts/README) -- no una descripcion de terceros, es el exploit real tal cual lo "
    "publico su autor. Tu trabajo es leerlo y extraer los datos EXACTOS que usa para explotar la "
    "vulnerabilidad, en vez de adivinar desde el resumen de la CVE. Responde SOLO con JSON valido "
    "con las claves: source_url (si el PoC dice que plugin/paquete exacto y version usa -- para "
    "WordPress deja el slug si lo ves), affected_version (copia los numeros de version TAL CUAL "
    "aparecen en el texto, con todos sus puntos -- '2.1.3' nunca '213', '2.8.2' nunca '282'; si el "
    "PoC da un rango copia el limite SUPERIOR con sus puntos), http_method (GET o POST), endpoint (ruta "
    "o accion AJAX exacta que el PoC golpea), parameters (lista de nombres EXACTOS de parametro que "
    "el PoC manda), payload_example (el valor de payload EXACTO que el PoC usa para el parametro "
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
]


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
    for pattern in _PLUGIN_NAME_PATTERNS:
        m = pattern.search(description)
        if m:
            name = m.group(1).strip().rstrip(".")
            slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
            if slug and len(slug) >= 3:
                return slug
    return None


_VERSION_PATTERN = re.compile(r"^[0-9]+(?:[.\-][0-9A-Za-z]+)*$")
_VNUM = r"([0-9]+(?:\.[0-9]+){0,4})"
# casuistica real de frases de rango de NVD/Patchstack (revisado a fondo, no solo el patron
# 'through X' que confirmo CVE-2024-27956) -- en todas, la version que importa para descargar
# el zip vulnerable es la del extremo SUPERIOR del rango, la mas reciente aun afectada:
#   - "from n/a through 3.92.0" / "2.1.3 to 2.8.2" (confirmados en vivo, los dos)
#   - "before 1.26" / "prior to 1.26" (NVD clasico)
#   - "up to 1.26" / "up to and including 1.26" (otra fraseologia comun)
#   - "<= 1.26" / "< 1.26" (notas terse)
#   - "1.0 - 2.0" / "1.0 – 2.0" / "1.0 — 2.0" (rango con guion/en-dash/em-dash, con o sin
#     espacios a los lados -- confirmado en vivo un PoC real transcribiendolo SIN espacios,
#     "2.1.3-2.8.2". No se confunde con un unico token tipo '1.0-beta1' porque ahi 'beta1' no
#     es un VNUM valido (no son solo digitos/puntos), asi que esa alternativa simplemente no
#     hace match y cae al chequeo de "ya es una version valida" de mas abajo)
_THROUGH_VERSION_RE = re.compile(
    rf"(?:through|to|before|prior\s+to|up\s+to(?:\s+and\s+including)?|<=?)\s+{_VNUM}"
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
    if not m and _VERSION_PATTERN.match(raw):
        return raw
    if m:
        # grupo 1: las frases con palabra clave (through/to/before/...). grupo 3: el extremo
        # SUPERIOR del rango con guion (grupo 2 es el inferior, nunca el que interesa aqui).
        return m.group(1) or m.group(3)
    return ""


def _run_web_investigation(inv: "Investigation", lang: str, step, llm=None) -> None:
    """Rama WEB/APP de investigate_cve: descarga el codigo real si se puede, fundamenta la hipotesis
    del LLM contra el (grep de las funciones citadas) y desarrolla el PoC HTTP/HTML. Muta `inv` in
    place.

    `inv.verified` solo se pone a True en UN caso concreto, y por una prueba real: la clase es
    missing-authorization/idor, el codigo se descargo como plugin de WordPress, y hay Docker con
    daemon disponible -> wpverify.py levanta un WordPress+MySQL efimero, instala el plugin de
    verdad, inicia sesion como un usuario de bajo privilegio, envia la peticion, y confirma con un
    SEGUNDO login (con la password que la peticion fijo) que la cuenta objetivo quedo tomada. Fuera
    de ese caso (otra clase, sin Docker, sin plugin de WordPress...) nunca se marca verificado aqui:
    hace falta correr el PoC contra el objetivo autorizado real."""
    es = lang == "es"
    from .websource import fetch_source, grep_vulnerable_functions
    from .webexploit import build_http_poc

    notes = inv.llm_notes or {}
    source = (notes.get("source_url") or "").strip()
    version_raw = (notes.get("affected_version") or "").strip()
    version = _clean_affected_version(version_raw)
    if version_raw and not version:
        step((f"'{version_raw}' no tiene pinta de version real (parece texto libre de la "
             f"descripcion) y no se pudo extraer ninguna -- se sigue sin version concreta" )
             if es else
             (f"'{version_raw}' doesn't look like a real version (looks like free text from "
             f"the description) and none could be extracted -- continuing without a specific "
             f"version"))
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

    if source:
        step(f"intentando obtener el codigo real ({source})..." if es else
             f"attempting to fetch the real source ({source})...")
        fr = fetch_source(source, version=version, on_step=step,
                         cms_hint=(notes.get("cms") or "").strip().lower())
        inv.source_fetch = {"ok": fr.ok, "kind": fr.kind, "source": fr.source,
                            "resolved_version": fr.resolved_version,
                            "local_path": fr.local_path, "note": fr.note,
                            "source_guessed_from_description": guessed_source}
        if fr.ok:
            step(f"codigo obtenido ({fr.kind}, version {fr.resolved_version or '?'})" if es else
                 f"source fetched ({fr.kind}, version {fr.resolved_version or '?'})")
            # calculado AQUI (no solo mas abajo, donde lo usa el despacho de verificacion
            # dinamica) porque el refinamiento determinista de endpoint/parametros TAMBIEN
            # necesita saber de que CMS es: Drupal (routing.yml) y Joomla ($input->getXxx()) se
            # leen distinto que WordPress (add_action/register_rest_route).
            plugin_dir = fr.plugin_dir or (fr.source if fr.kind in ("wordpress-plugin", "drupal-module") else "")
            is_drupal = fr.kind == "drupal-module" or (
                fr.kind in ("local-zip", "zip-url") and _looks_like_drupal_module(fr.local_path, plugin_dir))
            is_joomla = (not is_drupal) and fr.kind in ("local-zip", "zip-url") and _looks_like_joomla_extension(
                fr.local_path, plugin_dir)
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
                        pass_param_hint=pass_p or "", on_step=step)
                    _apply_wpverify_result(inv, wr, es)
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
                        pass_param_hint=pass_p or "", on_step=step)
                    _apply_wpverify_result(inv, wr, es)
            elif (not is_drupal and not is_joomla and fr.kind in ("wordpress-plugin", "local-zip", "zip-url") and plugin_dir
                    and inv.vuln_class in ("missing-authorization", "idor") and notes.get("endpoint")):
                # el mecanismo exacto de account-takeover no es siempre el mismo (ver wpverify.py):
                # unos plugins te dejan CAMBIAR la password/email de otro usuario (confirmable con
                # un segundo login), otros te dejan CONVERTIRTE DIRECTAMENTE en su sesion sin tocar
                # ninguna credencial (p.ej. CVE-2024-43982 en Login As Users). No se le pide al
                # analista que lo sepa de antemano: se deriva de la FORMA de los parametros que la
                # hipotesis del LLM (o los hints) ya trae -- si hay un parametro de email/password,
                # es el primer caso; si solo hay un ID objetivo, el segundo.
                from .wpverify import (verify_wordpress_account_takeover,
                                       verify_wordpress_direct_login_as, _pick_param,
                                       _ID_HINTS, _EMAIL_HINTS, _PASS_HINTS)
                params = notes.get("parameters") or []
                # preferir el mapeo de rol que el LLM extrajo LEYENDO el codigo real (mas fiable
                # que adivinar por el nombre del parametro); cae a la heuristica por nombre si no
                # hay refinamiento (sin LLM, o el refinamiento no incluyo esa clave).
                id_p = notes.get("id_param") or _pick_param(params, _ID_HINTS)
                email_p = notes.get("email_param") or _pick_param(params, _EMAIL_HINTS)
                pass_p = notes.get("pass_param") or _pick_param(params, _PASS_HINTS)
                wr = None
                if email_p or pass_p:
                    step(("intentando verificacion DINAMICA -- patron de cambio de credencial "
                         "(WordPress+MySQL efimero en Docker)..." if es else
                         "attempting DYNAMIC verification -- credential-change pattern "
                         "(ephemeral WordPress+MySQL in Docker)..."))
                    wr = verify_wordpress_account_takeover(
                        fr.local_path, plugin_dir, notes.get("endpoint"),
                        notes.get("http_method") or "POST", params,
                        id_param_hint=id_p or "", email_param_hint=email_p or "",
                        pass_param_hint=pass_p or "", on_step=step)
                elif id_p:
                    step(("intentando verificacion DINAMICA -- patron de login-as directo "
                         "(WordPress+MySQL efimero en Docker)..." if es else
                         "attempting DYNAMIC verification -- direct login-as pattern "
                         "(ephemeral WordPress+MySQL in Docker)..."))
                    wr = verify_wordpress_direct_login_as(
                        fr.local_path, plugin_dir, notes.get("endpoint"),
                        notes.get("http_method") or "GET", params,
                        id_param_hint=id_p or "", on_step=step)
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
                    path_param_hint=path_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                    path_param_hint=path_p or "", on_step=step)
                inv.dynamic_verify = {"attempted": True, "available": wr.available,
                                      "ok": wr.ok, "verified": wr.verified, "detail": wr.detail,
                                      "logs": wr.logs}
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
            # docker-compose.yml.
            elif (not plugin_dir and fr.local_path and
                  inv.vuln_class == "path-traversal" and notes.get("endpoint")):
                from .genericverify import verify_generic_path_traversal, _pick_param
                from .wpverify import _PATH_HINTS
                params = notes.get("parameters") or []
                path_p = notes.get("path_param") or _pick_param(params, _PATH_HINTS)
                step(("intentando verificacion DINAMICA GENERICA -- fichero canario, el objetivo "
                     "se construye desde su propio Dockerfile/compose..." if es else
                     "attempting GENERIC DYNAMIC verification -- canary file, the target is "
                     "built from its own Dockerfile/compose..."))
                wr = verify_generic_path_traversal(
                    fr.local_path, notes.get("endpoint"), notes.get("http_method") or "GET",
                    params, path_param_hint=path_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                    cmd_param_hint=cmd_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                    cmd_param_hint=cmd_p or "", on_step=step)
                inv.dynamic_verify = {"attempted": True, "available": wr.available,
                                      "ok": wr.ok, "verified": wr.verified, "detail": wr.detail,
                                      "logs": wr.logs}
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
                    params, cmd_param_hint=cmd_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                    sqli_param_hint=sqli_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
            # mismo laboratorio efimero, para SQLi: UNION-based (extrae version() real de la
            # base de datos) con fallback a boolean-blind diferencial -- ver verify_wordpress_sqli.
            elif (not is_drupal and not is_joomla and fr.kind in ("wordpress-plugin", "local-zip", "zip-url") and plugin_dir
                  and inv.vuln_class in ("sqli", "sql-injection") and notes.get("endpoint")):
                from .wpverify import verify_wordpress_sqli, _pick_param, _SQLI_HINTS
                params = notes.get("parameters") or []
                sqli_p = notes.get("sqli_param") or _pick_param(params, _SQLI_HINTS)
                step(("intentando verificacion DINAMICA -- UNION-based/boolean-blind "
                     "(WordPress+MySQL efimero en Docker)..." if es else
                     "attempting DYNAMIC verification -- UNION-based/boolean-blind "
                     "(ephemeral WordPress+MySQL in Docker)..."))
                wr = verify_wordpress_sqli(
                    fr.local_path, plugin_dir, notes.get("endpoint"),
                    notes.get("http_method") or "GET", params,
                    sqli_param_hint=sqli_p or "", on_step=step,
                    setup_wp_options=notes.get("setup_options") or [])
                inv.dynamic_verify = {"attempted": True, "available": wr.available,
                                      "ok": wr.ok, "verified": wr.verified, "detail": wr.detail,
                                      "logs": wr.logs}
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
                wr = verify_generic_sqli_blind(
                    fr.local_path, notes.get("endpoint"), notes.get("http_method") or "GET",
                    params, sqli_param_hint=sqli_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                                        url_param_hint=url_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                    url_param_hint=url_p or "", on_step=step)
                inv.dynamic_verify = {"attempted": True, "available": wr.available,
                                      "ok": wr.ok, "verified": wr.verified, "detail": wr.detail,
                                      "logs": wr.logs}
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
                    params, url_param_hint=url_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                                       xss_param_hint=xss_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                                          xss_param_hint=xss_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                    params, xss_param_hint=xss_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                                        ssti_param_hint=ssti_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                                           ssti_param_hint=ssti_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
            # "cualquier entorno": fallback generico de SSTI (ver genericverify.py).
            elif (not plugin_dir and fr.local_path and
                  inv.vuln_class == "ssti" and notes.get("endpoint")):
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
                    params, ssti_param_hint=ssti_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                                       xml_param_hint=xml_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                                          xml_param_hint=xml_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                    params, xml_param_hint=xml_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                                                 redirect_param_hint=redir_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                                                    redirect_param_hint=redir_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                    params, redirect_param_hint=redir_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                                               file_param_hint=file_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                                                  file_param_hint=file_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                                        pass_param_hint=pass_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                                           pass_param_hint=pass_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                    serial_param_hint=serial_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                    serial_param_hint=serial_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                    serial_param_hint=serial_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                    serial_param_hint=serial_p or "", on_step=step)
                _apply_wpverify_result(inv, wr, es)
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
                    budget_s: float = 300.0, hints: Optional[dict] = None) -> Investigation:
    """Investiga una CVE con el LLM y prueba lo que se pueda. No lanza.

    `hints` deja al analista aportar lo que YA SABE de la CVE (igual que un exploit developer real:
    la hipotesis del LLM es un punto de partida, no la unica fuente) y pisa lo que proponga el LLM en
    esas claves exactas: source_url (slug de WordPress.org o URL git), affected_version, endpoint,
    http_method, parameters (lista), vulnerable_functions (lista). Util cuando ya tienes el aviso
    oficial delante y no quieres depender de que el modelo adivine el slug/endpoint correctos."""
    import os
    from ..config import load_config
    from ..llm import make_backend
    from .cvelookup import fetch_cve
    from .cveplan import classify_cve, classify_binary, plan, plan_for_binary, is_web_class

    step = on_step or (lambda _m: None)
    es = lang == "es"
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

    # 2b) hechos conocidos del analista: PISAN la hipotesis del LLM en esas claves (el analista
    # que tiene el aviso oficial delante sabe el slug/endpoint reales mejor que una adivinanza).
    if hints:
        given = {k: v for k, v in hints.items() if v}
        if given:
            inv.llm_notes = {**inv.llm_notes, **given}
            step(("hechos del analista aplicados: " if es else "analyst-supplied facts applied: ")
                 + ", ".join(f"{k}={v}" for k, v in given.items()))

    # 3) clasifica + desarrolla la plantilla (grounded, deterministico)
    inv.vuln_class = (classify_cve(inv.description) or
                      classify_cve(inv.llm_notes.get("vuln_class", "")) or "")
    has_bin = bool(binary and os.path.exists(binary))

    if is_web_class(inv.vuln_class):
        # Clase WEB/APP (missing-authorization, IDOR, SQLi, RCE...): no hay binario que explotar con
        # pwntools, el "exploit" es una peticion HTTP. En vez de forzar el camino de memoria, esto:
        #   1) intenta DESCARGAR el codigo real (plugin de WordPress.org o repo git) y confirmar por
        #      grep que las funciones citadas por el LLM existen de verdad (evidencia GROUNDED),
        #   2) desarrolla el PoC HTTP (o la pagina para CSRF) a partir de la hipotesis del LLM.
        # Nunca se marca 'verificado' aqui: eso exige lanzar el PoC contra un objetivo autorizado real.
        _run_web_investigation(inv, lang=lang, step=step, llm=(llm if llm_on else None))
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
        pl, err = plan_with_budget(binary, hint, lang, True, budget_s)
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
        pl = plan(inv.description or inv.cve_id, {}, cve=inv.cve_id, lang=lang)
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
    return inv


def render_investigation(inv: Investigation, lang: str = "es", embed_images: bool = True) -> str:
    """`embed_images=False` sustituye cada captura por un aviso corto en vez del PNG en base64
    completo -- para la salida de TERMINAL, que no puede pintar imagenes y donde el base64
    (decenas de KB por captura) es solo ruido ilegible. render_investigation_page() (el export
    HTML, que SI las pinta) sigue llamando con embed_images=True (el valor por defecto)."""
    es = lang == "es"
    out = ["## " + ("Investigacion de explotacion" if es else "Exploitation investigation")
           + f": {inv.cve_id}"]
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
        out.append(f"\n### " + ("Impacto" if es else "Impact"))
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
            out.append("\n### " + ("Evidencia real de la ejecucion (laboratorio efimero)" if es else
                                   "Real evidence from the run (ephemeral lab)"))
            out.append(("_Datos reales de la peticion que SE EJECUTO y SE CONFIRMO de verdad contra "
                        "el WordPress desechable de arriba -- no una plantilla. El laboratorio ya "
                        "esta destruido: estas credenciales no abren nada, se muestran como prueba "
                        "de que el flujo corrio de verdad, no que se simulo._" if es else
                        "_Real data from the request that WAS ACTUALLY SENT and CONFIRMED against "
                        "the throwaway WordPress above -- not a template. The lab is already torn "
                        "down: these credentials unlock nothing, shown as proof the flow really "
                        "ran, not that it was simulated._"))
            rows = [
                (("Usuario de bajo privilegio" if es else "Low-privilege user"),
                 f"`{ev.get('login_bajo_privilegio')}` / `{ev.get('login_bajo_privilegio_password')}`"),
                (("Admin objetivo (laboratorio)" if es else "Target admin (lab)"),
                 f"`{ev.get('admin_user')}` (id={ev.get('admin_id')})"),
                (("Parametros (rol -> nombre real)" if es else "Parameters (role -> real name)"),
                 ", ".join(f"{role}={name}" for role, name in
                          (("id", ev.get("id_param")), ("email", ev.get("email_param")),
                           ("password", ev.get("pass_param"))) if name)),
                (("Peticion enviada" if es else "Request sent"),
                 f"`{ev.get('metodo')} {ev.get('endpoint')}`"),
                (("Payload real" if es else "Real payload"), f"`{ev.get('payload_enviado')}`"),
                (("Codigo de respuesta" if es else "Response status"),
                 str(ev.get("status_code_respuesta"))),
            ]
            if ev.get("password_nueva_confirmada"):
                rows.append((("Password fijada y CONFIRMADA por segundo login" if es else
                             "Password set and CONFIRMED by second login"),
                            f"`{ev['password_nueva_confirmada']}`"))
            if ev.get("email_nuevo_confirmado"):
                rows.append((("Email fijado y CONFIRMADO leyendo el usuario" if es else
                             "Email set and CONFIRMED by reading the user"),
                            f"`{ev['email_nuevo_confirmado']}` (leido: `{ev.get('email_leido_tras_ataque')}`)"))
            for label, value in rows:
                if value and value not in ("None", "`None`"):
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
    if inv.blockers:
        out.append("\n### " + ("Bloqueos para el exploit real" if es else "Blockers for a real exploit"))
        out += [f"- {b}" for b in inv.blockers]
    if inv.developed_script:
        if inv.poc_kind == "http":
            title = "PoC desarrollado (HTTP / requests)" if es else "Developed PoC (HTTP / requests)"
            fence = "python"
        elif inv.poc_kind == "html":
            title = "PoC desarrollado (CSRF, pagina HTML)" if es else "Developed PoC (CSRF, HTML page)"
            fence = "html"
        else:
            title = "Exploit desarrollado (pwntools)" if es else "Developed exploit (pwntools)"
            fence = "python"
        out.append(f"\n### {title}\n```{fence}\n" + inv.developed_script + "\n```")
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
    on_event: Optional[Callable[[dict], None]] = None,
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
                                  budget_s=budget_s, hints=hints_by_cve.get(cve_id))
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
