#!/usr/bin/env python3
"""
Generates rich markdown_report for each CVE using the binoracle LLM,
then saves it back to the JSON history file.

Run: python3 scripts/generate_llm_reports.py [--force] [CVE-XXXX-XXXXX]

--force  regenerates even CVEs that already have a long markdown_report (>5000 chars)
"""
import json, os, sys, re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HISTORY = os.path.expanduser("~/.binoracle/history")
FORCE   = "--force" in sys.argv
FILTER  = next((a for a in sys.argv[1:] if a.startswith("CVE-")), None)

SYSTEM = """Eres un investigador de seguridad experto que redacta análisis técnicos de vulnerabilidades
confirmadas en laboratorio Docker aislado. Tu tarea es redactar la sección «Informe Completo»
de un informe binoracle para una CVE específica.

Reglas absolutas:
- Escribe en español.
- NO uses emojis, no uses ★☆☀☾ ni ningún símbolo decorativo.
- NO hagas padding, boilerplate ni introducciones genéricas de OWASP.
- Solo afirma lo que se puede deducir directamente de los datos del laboratorio. Nada teórico.
- Usa `backticks` para código, payloads, cabeceras, nombres de función y nombres de fichero.
- Cuando menciones algo inferido (no observado directamente), añade *(inferencia lógica basada en X)*.
- Estructura obligatoria: secciones A, B, C, D, E, F con encabezados ### exactos como se indican.
- Cada sección mínimo 3 párrafos densos. Total mínimo 2500 palabras.
"""

PROMPT_TMPL = """Redacta el análisis técnico completo para {cve_id}.

## Datos del laboratorio

**Clase de vulnerabilidad:** {vuln_class}
**Técnica de explotación:** {tecnica}
**Endpoint:** `{endpoint}`
**Parámetro vulnerable:** `{param}`
**Payload ganador:** `{payload}`
**Resultado extraído:** {result_data}
**Auth requerida:** {auth}
**Versión afectada:** {affected}
**Descripción NVD:** {description}
**Estrategia del motor:** {estrategia}
**Respuesta control (recorte):** `{resp_ctrl}`
**Respuesta exploit (recorte):** `{resp_body}`
**Detail del motor:** {detail}
{extra_fields}

## Estructura requerida (usa EXACTAMENTE estos encabezados)

### A. Modelo mental del flujo normal (sin exploit)

Explica paso a paso (lista numerada) cómo funciona el endpoint en condiciones normales —
desde la petición HTTP hasta la respuesta — y dónde reside el control de seguridad
que el exploit va a romper. Sé específico con el nombre del endpoint, el parámetro
y el mecanismo interno del framework/plugin.

### B. Identificación de la superficie de confianza mal ubicada

Explica con precisión el defecto arquitectónico: qué asunción incorrecta hace el código,
por qué esa asunción es incorrecta, y cómo la técnica de explotación (`{tecnica}`)
explota exactamente esa brecha. Incluye el razonamiento técnico detallado de la función
o mecanismo de ataque (extractvalue, UNION SELECT, bypass de cabecera, path traversal, etc.).

### C. Cadena de razonamiento del atacante (kill chain de descubrimiento)

Pasos numerados (Paso 1 — Paso N) describiendo la secuencia lógica exacta
que un investigador seguiría para descubrir y confirmar este exploit desde cero.
Cada paso: observación → hipótesis → acción → confirmación. Marca con *(Confirmado por
observación directa del laboratorio.)* o *(Inferencia lógica basada en X.)* según corresponda.

### D. Anatomía exacta del PoC verificado

Bloque de código con la petición de control y la petición exploit (HTTP crudo).
Descomposición campo a campo de cada elemento del payload: qué hace cada parte,
por qué funciona, qué pasaría si se omite. Explica por qué el resultado observado
(`{result_data}`) es prueba no ambigua de la explotación (descarta explicaciones alternativas).

### E. Condiciones necesarias para que el exploit funcione (y cuándo NO funciona)

Lista cada condición (versión, configuración, permisos, visibilidad de errores, red)
con su explicación causal: por qué sin esa condición el exploit falla o se degrada.
Incluye al menos una condición en que el exploit NO funciona aunque la vulnerabilidad exista.

### F. Generalización defensiva

Extrae el principio de diseño de seguridad que viola este CVE, formulado con precisión
lógica. Explica por qué las mitigaciones superficiales (ocultar errores, WAF básico)
no corrigen el defecto de raíz. Termina con la corrección técnica concreta y por qué
es la única que garantiza eliminar la clase completa de ataque.
"""

def build_prompt(cve_id, r, ve):
    cls      = r.get("vuln_class","sqli")
    tecnica  = ve.get("tecnica","") or ("boolean-blind" if ve.get("respuesta_true_len") else cls)
    endpoint = ve.get("endpoint","?")
    param    = ve.get("sqli_param") or ve.get("path_param") or "?"
    payload  = ve.get("payload_ganador","?")
    affected = r.get("affected_version","?")
    desc     = r.get("description","")
    auth     = ve.get("login_bajo_privilegio","") or "no (anonimo)"
    estrategia = ve.get("estrategia","")
    resp_ctrl  = ve.get("respuesta_control_recorte","")[:300]
    resp_body  = ve.get("respuesta_cuerpo_recorte","")[:300]
    detail     = r.get("detail","")[:400]

    # Result data: what was extracted
    if ve.get("mysql_version_extraida"):
        result_data = f"version MySQL extraida: `{ve['mysql_version_extraida']}`"
    elif ve.get("confirm_string_presente"):
        result_data = f"string de confirmacion presente: `{ve['confirm_string_presente']}`"
    elif ve.get("marker"):
        result_data = f"marker XSS encontrado en DOM: `{ve['marker']}`"
    elif ve.get("canary_secret"):
        result_data = f"canary leido del filesystem: `{ve['canary_secret'][:60]}`"
    elif ve.get("respuesta_true_len"):
        result_data = (f"delta boolean: TRUE={ve['respuesta_true_len']} bytes, "
                       f"FALSE={ve['respuesta_false_len']} bytes — diferencia consistente")
    elif ve.get("status_con_bypass"):
        result_data = (f"bypass: status sin bypass={ve.get('status_sin_bypass','403')}, "
                       f"con bypass={ve['status_con_bypass']} — recurso protegido accesible")
    else:
        result_data = "(ver evidencia del laboratorio)"

    # Extra fields specific to some CVE types
    extra = []
    if ve.get("bypass_header"):
        extra.append(f"**Cabecera de bypass:** `{ve['bypass_header']}: {ve.get('bypass_value','')}`")
    if ve.get("bypass_value"):
        extra.append(f"**Valor de bypass:** `{ve['bypass_value']}`")
    if ve.get("canary_path"):
        extra.append(f"**Ruta canary:** `{ve['canary_path']}`")
    if ve.get("page_url"):
        extra.append(f"**URL de la pagina XSS:** `{ve['page_url']}`")
    if ve.get("marker"):
        extra.append(f"**Marker XSS:** `{ve['marker']}`")
    if ve.get("widget_type"):
        extra.append(f"**Tipo de widget:** `{ve['widget_type']}`")
    if ve.get("stack_detectado"):
        extra.append(f"**Stack detectado:** `{ve['stack_detectado']}`")
    if ve.get("intentos"):
        n = len(ve["intentos"]) if isinstance(ve["intentos"], list) else "?"
        extra.append(f"**Intentos de verificacion:** {n}")
    extra_str = "\n".join(extra) if extra else "(sin campos extra)"

    return PROMPT_TMPL.format(
        cve_id=cve_id, vuln_class=cls, tecnica=tecnica,
        endpoint=endpoint, param=param, payload=payload,
        result_data=result_data, auth=auth, affected=affected,
        description=desc[:500], estrategia=estrategia[:300],
        resp_ctrl=resp_ctrl, resp_body=resp_body, detail=detail,
        extra_fields=extra_str,
    )

def main():
    from binoracle.config import load_config
    from binoracle.llm import make_backend, Message
    cfg = load_config()
    llm = make_backend(cfg)
    if not llm.available():
        print("LLM no disponible. Verifica la configuracion del motor.", file=sys.stderr)
        sys.exit(1)

    files = sorted(os.listdir(HISTORY))
    updated = skipped = errors = 0

    for fname in files:
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
        existing = r.get("markdown_report","")

        # Skip if already has a rich LLM-generated report (>5000 chars) unless --force
        if existing and len(existing) > 5000 and not FORCE:
            print(f"[skip] {cve_id} — ya tiene informe LLM ({len(existing)} chars)")
            skipped += 1
            continue

        print(f"[llm]  {cve_id} — generando...", end="", flush=True)
        try:
            prompt = build_prompt(cve_id, r, ve)
            msgs = [
                Message(role="system", content=SYSTEM),
                Message(role="user", content=prompt),
            ]
            md = llm.chat(msgs)
        except Exception as e:
            print(f" ERROR: {e}")
            errors += 1
            continue

        data["result"]["markdown_report"] = md
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False)
        print(f" ok ({len(md)} chars)")
        updated += 1

    print(f"\nCompletado: {updated} generados por LLM, {skipped} ya tenian informe, {errors} errores.")
    if updated:
        print("Regenera los HTML con: python3 scripts/gen_informe_pdf.py")

if __name__ == "__main__":
    main()
