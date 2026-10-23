"""Android (APK) audit — grounded, no native exploitation.

The native `audit` loop (ROP/ret2libc/format-string against an ELF) makes no sense for an APK: an
Android app's attack surface lives in its DEX/Java and its manifest, not in process memory. This
module is what `run_audit` redirects to when the target is an APK. It is GROUNDED and STATIC:

  1. facts from inspect_apk (framework, ABIs, signing, native libs),
  2. the decoded AndroidManifest (apktool): exported components, debuggable/backup/cleartext flags,
  3. the decompiled Java (jadx): a deterministic scan for well-known insecure patterns
     (hardcoded secrets, SQL built by concatenation, insecure WebView, world-readable storage,
     weak crypto, trust-all TLS, insecure logging...).

Findings are `grounded` (a static pattern matched in decompiled code / the manifest), never
`verified` (there is no runtime shell here). It degrades honestly: if jadx/apktool are absent the
code/manifest layer is skipped with a stated limitation, and inspect_apk still reports.
Everything the decompiler/apktool produce is untrusted data derived from the uploaded APK.
"""
from __future__ import annotations

import os
import re

# (regex, titulo, severidad, recomendacion, owasp, cwe). Patrones deterministas sobre el Java
# decompilado. owasp/cwe: IDs reales de OWASP MASVS v2/MASWE (mas.owasp.org/MASVS/controls,
# confirmado en vivo -- ver ROADMAP.md) y CWE (cwe.mitre.org, confirmados uno a uno, nunca
# inventados); "" cuando ningun CWE existente encaja con suficiente precision, mejor dejarlo
# vacio que forzar uno equivocado.
_PATTERNS = [
    (re.compile(r'(?i)(password|passwd|pwd|secret|api[_-]?key|apikey|token|auth)\s*=\s*"[^"]{3,}"'),
     "Credencial/secreto hardcodeado en codigo", "high",
     "No embebas secretos en el APK (es trivial de extraer); usa el Keystore/servidor y rota lo filtrado.",
     "MASWE-0004", "CWE-798"),
    (re.compile(r'rawQuery\s*\([^;]*\+|execSQL\s*\([^;]*\+|db\.(query|update|delete)\s*\([^;]*\+'),
     "SQL construido por concatenacion (SQL injection)", "high",
     "Usa consultas parametrizadas (selectionArgs / placeholders '?'), nunca concatenes entrada.",
     "MASWE-0050", "CWE-89"),
    (re.compile(r'addJavascriptInterface\s*\('),
     "WebView.addJavascriptInterface (puente JS->Java)", "high",
     "Evitalo o restringe a @JavascriptInterface con minSdk>=17 y contenido de confianza.",
     "MASWE-0033", "CWE-749"),
    (re.compile(r'setJavaScriptEnabled\s*\(\s*true\s*\)'),
     "WebView con JavaScript habilitado", "medium",
     "Habilita JS solo si es imprescindible; no cargues contenido/urls no confiables.",
     "MASWE-0035", ""),
    (re.compile(r'setAllowFileAccess\s*\(\s*true\s*\)|setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)'),
     "WebView con acceso a file:// amplio", "high",
     "Deshabilita file access / universal access from file URLs salvo necesidad real.",
     "MASWE-0034", ""),
    (re.compile(r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|MODE_WORLD_WRITABLE'),
     "Almacenamiento world-readable/writeable", "high",
     "Usa MODE_PRIVATE; otros apps pueden leer/escribir esos ficheros.",
     "MASWE-0002", "CWE-276"),
    (re.compile(r'getExternalStorage|getExternalFilesDir|Environment\.getExternalStoragePublicDirectory'),
     "Datos en almacenamiento externo", "medium",
     "El almacenamiento externo es legible por otras apps; no guardes ahi datos sensibles.",
     "MASWE-0002", "CWE-922"),
    (re.compile(r'"DES"|"DESede"|/ECB/|"RC4"|Cipher\.getInstance\(\s*"AES"\s*\)'),
     "Criptografia debil (DES/ECB/RC4/AES modo por defecto)", "medium",
     "Usa AES/GCM (o AES/CBC con IV aleatorio y HMAC); nunca ECB ni DES/RC4.",
     "MASWE-0007", "CWE-327"),
    (re.compile(r'MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"\s*\)'),
     "Hash debil (MD5/SHA-1)", "low",
     "Para integridad/firmas usa SHA-256+; para contrasenas, bcrypt/scrypt/Argon2.",
     "MASWE-0008", "CWE-328"),
    (re.compile(r'IvParameterSpec\s*\(\s*(?:"|new byte\[\]\s*\{|[A-Za-z_]+\.getBytes)'),
     "IV/clave criptografica estatica (posible)", "medium",
     "Genera IV aleatorio por mensaje; no reutilices IV/claves fijas en codigo.",
     "MASWE-0012", "CWE-329"),
    (re.compile(r'checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|ALLOW_ALL_HOSTNAME_VERIFIER|'
                r'return\s+true;\s*//?\s*verify|X509TrustManager\(\s*\)\s*\{'),
     "TLS inseguro: trust-all / hostname verifier permisivo", "high",
     "No desactives la validacion de certificados; usa el TrustManager por defecto y pinning si procede.",
     "MASWE-0027", "CWE-295"),
    (re.compile(r'Log\.[dviwe]\s*\('),
     "Logging (posible fuga de datos sensibles)", "low",
     "No registres secretos/PII; retira los Log de depuracion en release (ProGuard/R8).",
     "MASWE-0005", "CWE-532"),
    (re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\('),
     "Ejecucion de comandos del sistema", "medium",
     "Evita exec con entrada del usuario; valida/escapa y prefiere APIs nativas.",
     "MASWE-0050", "CWE-78"),
    (re.compile(r'loadUrl\s*\(\s*"http://'),
     "Carga de URL por HTTP en claro", "medium",
     "Usa HTTPS; el trafico en claro es interceptable/manipulable.",
     "MASWE-0026", "CWE-319"),
]

_MAX_PER_CAT = 8       # evidencias por categoria
_MAX_FILES = 6000      # ficheros java a escanear (cota dura)
_MAX_BYTES = 400000    # por fichero


def _manifest_findings(apk: str, Finding):
    """Hallazgos del AndroidManifest decodificado (apktool): flags peligrosos + componentes
    exportados. Devuelve (findings, meta_dict, limitation_or_None)."""
    out = []
    try:
        from .androidmanifest import _apktool_decode, parse_manifest_xml
    except Exception:
        return out, {}, "modulo de manifest no disponible"
    d, err = _apktool_decode(apk)
    if not d:
        return out, {}, f"manifest no decodificado ({err}); instala apktool"
    mpath = os.path.join(d, "AndroidManifest.xml")
    try:
        with open(mpath, "r", encoding="utf-8", errors="replace") as f:
            xml = f.read()
    except Exception as e:
        return out, {}, f"sin AndroidManifest: {e}"
    m = parse_manifest_xml(xml)
    meta = {"package": m.get("package"), "permissions": m.get("permissions", []),
            "components": m.get("components", [])}
    # flags de la etiqueta <application>. owasp/cwe: ver el comentario sobre _PATTERNS mas
    # arriba -- mismos IDs reales de MASVS v2/MASWE y CWE, confirmados uno a uno.
    flags = [
        (r'android:debuggable\s*=\s*"true"', "application android:debuggable=true", "high",
         "Nunca publiques con debuggable=true: permite depurar y extraer datos del proceso.",
         "MASWE-0063", "CWE-489"),
        (r'android:allowBackup\s*=\s*"true"', "application android:allowBackup=true", "medium",
         "Desactiva allowBackup o excluye datos sensibles: adb backup puede exfiltrarlos.",
         "MASWE-0006", "CWE-530"),
        (r'android:usesCleartextTraffic\s*=\s*"true"', "usesCleartextTraffic=true (HTTP en claro)", "medium",
         "Prohibe trafico en claro (network_security_config / usesCleartextTraffic=false).",
         "MASWE-0026", "CWE-319"),
    ]
    for rx, title, sev, rec, owasp, cwe in flags:
        if re.search(rx, xml):
            out.append(Finding(title=title, severity=sev, verdict="grounded",
                               evidence=f"AndroidManifest.xml: coincide /{rx}/",
                               location="AndroidManifest.xml", recommendation=rec,
                               rationale="Bandera insegura declarada en el manifest (apktool).",
                               owasp=owasp, cwe=cwe))
    # componentes exportados (superficie de ataque entre apps)
    exported = [c for c in m.get("components", []) if c.get("exported")]
    if exported:
        ev = "\n".join(f"- {c['type']} {c['name']}"
                       + (f"  (actions: {', '.join(c['actions'])})" if c.get("actions") else "")
                       for c in exported[:20])
        out.append(Finding(
            title=f"{len(exported)} componente(s) exportado(s) (alcanzables por otras apps)",
            severity="medium", verdict="grounded", evidence=ev, location="AndroidManifest.xml",
            rationale="Componentes con exported=true (o con intent-filter) son invocables por "
                      "cualquier app; cada uno es superficie de ataque (intents, provider URIs).",
            recommendation="Marca exported=false lo que no deba ser publico; protege el resto con "
                           "permisos de firma y valida/filtra los intents y las URIs de los providers.",
            owasp="MASWE-0018", cwe="CWE-926"))
    return out, meta, None


def _scan_java(root: str, Finding):
    """Escaneo determinista del Java decompilado. Devuelve lista de Finding (una por categoria)."""
    try:
        from .androidquery import _iter_java, _classname
    except Exception:
        return []
    hits = {}   # idx_patron -> [(clase, linea, texto)]
    nfiles = 0
    for jpath in _iter_java(root):
        nfiles += 1
        if nfiles > _MAX_FILES:
            break
        try:
            with open(jpath, "r", encoding="utf-8", errors="replace") as f:
                code = f.read(_MAX_BYTES)
        except Exception:
            continue
        cls = _classname(root, jpath)
        for i, (rx, *_rest) in enumerate(_PATTERNS):
            if len(hits.get(i, [])) >= _MAX_PER_CAT:
                continue
            for mobj in rx.finditer(code):
                line_no = code.count("\n", 0, mobj.start()) + 1
                line = code.splitlines()[line_no - 1].strip() if line_no else mobj.group(0)
                hits.setdefault(i, []).append((cls, line_no, line[:200]))
                if len(hits[i]) >= _MAX_PER_CAT:
                    break
    out = []
    for i, matches in sorted(hits.items()):
        rx, title, sev, rec, owasp, cwe = _PATTERNS[i]
        ev = "\n".join(f"- {c}:{ln}: {txt}" for c, ln, txt in matches)
        out.append(Finding(title=title, severity=sev, verdict="grounded", evidence=ev,
                           location=matches[0][0] if matches else "",
                           rationale="Patron inseguro encontrado en el Java decompilado (jadx). "
                                     "Estatico/heuristico: confirma la explotabilidad en contexto.",
                           recommendation=rec, owasp=owasp, cwe=cwe))
    return out


# MASVS-RESILIENCE (mas.owasp.org/MASVS/controls, confirmado en vivo): a diferencia de
# _PATTERNS (una vulnerabilidad SI el patron esta presente), aqui el hallazgo es la AUSENCIA de
# una tecnica de defensa conocida en TODO el arbol decompilado -- un unico escaneo, no por
# fichero. Son heuristicas de hardening (firmas de APIs/strings publicas y bien documentadas:
# RootBeer, paquetes de root conocidos, Debug.isDebuggerConnected, Build.FINGERPRINT=generic,
# TracerPid/Frida/Xposed), no una prueba formal de que la proteccion no existe -- codigo nativo
# (JNI) o una implementacion fuertemente ofuscada/renombrada escaparian a este escaneo sobre
# Java decompilado; se indica siempre en el limitation del hallazgo. cwe: deliberadamente vacio
# en los 4 -- CWE-693 "Protection Mechanism Failure" seria el unico pillar remotamente
# relacionado, pero MITRE lo marca "Vulnerability Mapping: DISCOURAGED" (confirmado via
# WebSearch), asi que no se fuerza.
_RESILIENCE_CHECKS = [
    ("MASWE-0051", "Deteccion de root/jailbreak no implementada",
     [r'RootBeer', r'\bisRooted\b', r'checkRootMethod|checkForRoot',
      r'/system/bin/su|/system/xbin/su|/sbin/su|/system/app/Superuser\.apk',
      r'com\.noshufou\.android\.su|com\.koushikdutta\.superuser|eu\.chainfire\.supersu|'
      r'com\.topjohnwu\.magisk|com\.devadvance\.rootcloak',
      r'Build\.TAGS[^;]{0,40}test-keys'],
     "Ningun indicador conocido de deteccion de root (libreria RootBeer, rutas de binario su, "
     "paquetes de apps de root conocidas, Build.TAGS=test-keys) aparece en el Java decompilado.",
     "Anade una capa de deteccion de root (p.ej. RootBeer) como señal adicional de riesgo, no "
     "como unico control -- es evadible y no sustituye la validacion del lado del servidor."),
    ("MASWE-0064", "Deteccion de depurador no implementada",
     [r'Debug\.isDebuggerConnected\s*\(\)', r'ApplicationInfo\.FLAG_DEBUGGABLE',
      r'Debug\.waitingForDebugger\s*\(\)'],
     "Ningun indicador conocido de deteccion de depurador (Debug.isDebuggerConnected, "
     "FLAG_DEBUGGABLE, Debug.waitingForDebugger) aparece en el Java decompilado.",
     "Comprueba Debug.isDebuggerConnected()/FLAG_DEBUGGABLE en rutas sensibles; combinalo con "
     "deteccion nativa (TracerPid) ya que esta via es trivial de parchear/evitar."),
    ("MASWE-0053", "Deteccion de emulador/dispositivo virtual no implementada",
     [r'Build\.FINGERPRINT[^;]{0,40}generic', r'Build\.HARDWARE[^;]{0,40}(goldfish|ranchu)',
      r'Build\.PRODUCT[^;]{0,40}sdk', r'Build\.MODEL[^;]{0,40}(sdk|Emulator|Android SDK)',
      r'\bisEmulator\b'],
     "Ningun indicador conocido de deteccion de emulador (Build.FINGERPRINT/HARDWARE/PRODUCT/"
     "MODEL tipicos de AVD/goldfish/ranchu) aparece en el Java decompilado.",
     "Si la app maneja datos sensibles, anade deteccion de emulador como señal adicional de "
     "riesgo (no como bloqueo absoluto: falsos positivos en dispositivos reales clonados)."),
    ("MASWE-0065", "Deteccion de herramientas de analisis dinamico no implementada",
     [r'frida-server|frida_server', r'\bXposed\b|de\.robv\.android\.xposed', r'TracerPid',
      r'\bobjection\b', r'LSPosed'],
     "Ningun indicador conocido de deteccion de Frida/Xposed/LSPosed/objection (strings del "
     "proceso Frida, paquete Xposed, campo TracerPid) aparece en el Java decompilado.",
     "Anade deteccion de frameworks de hooking (TracerPid, puertos/sockets de Frida, Xposed "
     "cargado) junto con otras capas -- cualquier deteccion client-side es evadible por un "
     "atacante con control del dispositivo."),
]


def _resilience_findings(root: str, Finding):
    """Un unico escaneo del arbol decompilado para las 4 categorias MASVS-RESILIENCE de arriba.
    Devuelve (findings, nclasses) -- un Finding 'Not Implemented' por categoria ausente."""
    try:
        from .androidquery import _iter_java
    except Exception:
        return [], 0
    compiled = [(owasp, title, [re.compile(rx) for rx in rxs], rationale, rec)
                for owasp, title, rxs, rationale, rec in _RESILIENCE_CHECKS]
    found = [False] * len(compiled)
    nfiles = 0
    for jpath in _iter_java(root):
        nfiles += 1
        if nfiles > _MAX_FILES:
            break
        if all(found):
            break
        try:
            with open(jpath, "r", encoding="utf-8", errors="replace") as f:
                code = f.read(_MAX_BYTES)
        except Exception:
            continue
        for i, (_owasp, _title, rxs, _rat, _rec) in enumerate(compiled):
            if found[i]:
                continue
            if any(rx.search(code) for rx in rxs):
                found[i] = True
    out = []
    for i, (owasp, title, _rxs, rationale, rec) in enumerate(compiled):
        if found[i]:
            continue
        out.append(Finding(title=title, severity="info", verdict="grounded",
                           evidence=f"escaneados {nfiles} fichero(s) .java; sin coincidencias.",
                           location="", rationale=rationale, recommendation=rec,
                           owasp=owasp, cwe=""))
    return out, nfiles


def run_android_audit(apk: str, llm=None, config=None, store=None, on_step=None):
    """Auditoria Android fundamentada. Devuelve un AgentResult (como el audit nativo) para que la
    web/CLI lo rendericen igual. No ejecuta la app; no popea nada: los veredictos son 'grounded'."""
    from ..agent.loop import AgentResult
    from ..agent.grounding import GroundingLedger
    from ..store.session import Finding

    def emit(i, msg):
        if not on_step:
            return
        try:
            on_step(i, {"action": "tool", "tool": msg, "args": {}})
        except TypeError:
            try:
                on_step(msg)
            except Exception:
                pass

    findings = []
    limits = ["auditoria ANDROID estatica: lee el APK, no ejecuta la app; los hallazgos son "
              "'grounded' (patron en manifest/Java decompilado), no 'verified' por ejecucion.",
              "el Java decompilado por jadx es una reconstruccion; valida la explotabilidad en contexto."]
    step = 0

    emit(step := step + 1, "recon del APK (inspect_apk)")
    try:
        from .apkinspect import inspect_apk
        facts = inspect_apk(apk)
    except Exception as e:
        facts = {"ok": False, "note": str(e)}

    emit(step := step + 1, "AndroidManifest (apktool): flags y componentes exportados")
    mf, meta, mlim = _manifest_findings(apk, Finding)
    findings += mf
    if mlim:
        limits.append(mlim)

    emit(step := step + 1, "decompilando DEX -> Java (jadx) y escaneando patrones inseguros")
    try:
        from .androidquery import _decompile
        root, reason = _decompile(apk)
    except Exception as e:
        root, reason = "", str(e)
    if root:
        findings += _scan_java(root, Finding)
        emit(step := step + 1, "MASVS-RESILIENCE: deteccion de root/depurador/emulador/herramientas de analisis")
        rfindings, _nclasses = _resilience_findings(root, Finding)
        findings += rfindings
        if rfindings:
            limits.append("las ausencias MASVS-RESILIENCE son heuristicas sobre Java decompilado: "
                           "una proteccion solo en codigo nativo (JNI) o fuertemente ofuscada/"
                           "renombrada no se detectaria y aparece aqui como falso 'no implementada'.")
    else:
        limits.append(f"escaneo de codigo omitido (jadx no disponible: {reason}); instala jadx.")

    # ---- resumen (answer markdown) ----
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: sev_rank.get(f.severity, 5))
    pkg = (meta or {}).get("package") or (facts.get("package") if isinstance(facts, dict) else "") or "?"
    fw = facts.get("framework") if isinstance(facts, dict) else ""
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    head = [f"# Auditoria Android — {os.path.basename(apk)}",
            f"- paquete: **{pkg}**" + (f"  ·  framework: **{fw}**" if fw else ""),
            "- hallazgos: " + (", ".join(f"{n} {s}" for s, n in sorted(counts.items(),
                                 key=lambda kv: sev_rank.get(kv[0], 9))) or "ninguno") + "\n"]
    for f in findings[:40]:
        head.append(f"### [{f.severity.upper()}] {f.title}")
        if f.location:
            head.append(f"_en: {f.location}_")
        if f.evidence:
            head.append("```\n" + f.evidence[:1200] + "\n```")
        if f.recommendation:
            head.append(f"**Recomendacion:** {f.recommendation}\n")
    head.append("\n---\n_" + "_\n_".join(limits) + "_")
    answer = "\n".join(head)

    # persistir hallazgos si hay store
    try:
        if store is not None:
            for f in findings:
                store.add_finding(f)
    except Exception:
        pass

    return AgentResult(answer=answer, findings=findings, ledger=GroundingLedger(),
                       steps=step, stopped_reason="android-audit")
