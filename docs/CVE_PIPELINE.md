# Pipeline CVE — Cómo funciona binoracle de extremo a extremo

Este documento describe la arquitectura interna del pipeline CVE de binoracle: desde la consulta a
NVD hasta el informe HTML final, pasando por la hipótesis del LLM, el laboratorio Docker efímero y
la verificación dinámica con evidencia real.

---

## Visión general

```
┌──────────────────────────────────────────────────────────────────┐
│                         binoracle cve <CVE-ID>                   │
└───────────────────────────────┬──────────────────────────────────┘
                                │
         ┌──────────────────────▼──────────────────────┐
         │  FASE 1 — Consulta NVD                      │
         │  NVD API v2  +  GitHub PoC  +  Exploit-DB   │
         │  → descripción, CVSS, versión afectada,     │
         │    código fuente del PoC público (si existe) │
         └──────────────────────┬──────────────────────┘
                                │
         ┌──────────────────────▼──────────────────────┐
         │  FASE 2 — Hipótesis LLM                     │
         │  Qwen 2.5 Coder 7B (Ollama local)           │
         │  → vuln_class, endpoint, http_method,       │
         │    affected_version, vulnerable_functions,  │
         │    steps, strategy (JSON estructurado)      │
         └──────────────────────┬──────────────────────┘
                                │
         ┌──────────────────────▼──────────────────────┐
         │  FASE 3 — Scaffolding del laboratorio       │
         │  Detecta stack (httpd / pip+aiohttp / npm)  │
         │  Genera Dockerfile con versión vulnerable   │
         │  Planta fichero canario + secreto aleatorio  │
         └──────────────────────┬──────────────────────┘
                                │
         ┌──────────────────────▼──────────────────────┐
         │  FASE 4 — Verificación dinámica             │
         │  Levanta el contenedor Docker efímero       │
         │  Lanza payloads (URL-encoded variants)      │
         │  Busca el secreto en la respuesta           │
         │  → VERIFICADO  ó  NO CONFIRMADO             │
         └──────────────────────┬──────────────────────┘
                                │
         ┌──────────────────────▼──────────────────────┐
         │  FASE 5 — Informe HTML                      │
         │  CVSS pill · tarjeta de explotación         │
         │  Timeline · análisis técnico · PoC          │
         │  Capturas Playwright (si disponible)        │
         └─────────────────────────────────────────────┘
```

Todo ocurre **en local**: el LLM corre en Ollama, los laboratorios en Docker efímero, nada sale
del host.

---

## Fase 1 — Consulta NVD

### Qué se obtiene

binoracle consulta la **NVD API v2** (`https://services.nvd.nist.gov/rest/json/cves/2.0`) y
extrae:

| Campo          | Descripción                                           |
|----------------|-------------------------------------------------------|
| `description`  | Texto libre de la vulnerabilidad (en inglés)          |
| `cvss_score`   | Puntuación CVSS v3.1 (o v2 si v3 no existe)           |
| `cvss_severity`| LOW / MEDIUM / HIGH / CRITICAL                        |
| `cvss_vector`  | Vector CVSS completo (AV:N/AC:L/…)                    |
| `published`    | Fecha de publicación ISO 8601                         |
| `cpe_versions` | Lista de versiones CPE afectadas                      |

### Validación del CVE

Si el ID no tiene el formato `CVE-YYYY-NNNNN`, la investigación para aquí con
`lookup_ok=False` y un mensaje claro. Si NVD devuelve 404 o sin resultados, se registra
`lookup_note` con el motivo y se sigue con la información disponible (PoC de GitHub, etc.).

### Fuentes secundarias

Además de NVD, el agente busca código de explotación en:

- **GitHub** — busca repositorios con el CVE-ID en el nombre/descripción, descarga el PoC
  cuando es un fichero Python/Ruby/Bash o un Dockerfile usable.
- **Exploit-DB** — consulta el mirror público cuando GitHub no arroja resultados.

El campo `poc_source_used` del resultado registra la URL exacta del PoC realmente leído, o
queda vacío cuando el PoC era solo un advisory en texto.

---

## Fase 2 — Hipótesis LLM

### Qué recibe el modelo

El LLM recibe un único prompt en dos partes:

1. **System prompt** — define el rol (investigador de explotación para objetivos autorizados),
   el formato de respuesta (JSON estricto) y los campos esperados.
2. **User prompt** — el CVE-ID y la descripción textual extraída de NVD, más el fragmento de
   código del PoC cuando se pudo descargar.

```
CVE: CVE-2021-41773
Descripción: A flaw was found in a change made to path normalization in Apache HTTP Server
2.4.49. An attacker could use a path traversal attack to map URLs to files outside the
directories configured by Alias-like directives...

Analiza la vulnerabilidad y da el plan en JSON con las claves indicadas.
```

### Qué extrae el modelo

La respuesta es siempre JSON (modo `json_mode=True`). Los campos relevantes son:

| Campo                 | Ejemplo para CVE-2021-41773           |
|-----------------------|---------------------------------------|
| `vuln_class`          | `path-traversal`                      |
| `endpoint`            | `/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd` |
| `http_method`         | `GET`                                 |
| `affected_version`    | `2.4.49`                              |
| `vulnerable_functions`| `["ap_normalize_path"]`               |
| `steps`               | lista de pasos de explotación         |
| `strategy`            | una frase de estrategia               |
| `auth_required`       | `false`                               |
| `parameters`          | lista de parámetros relevantes        |

### Por qué es autónomo

El LLM trabaja **sin hints del analista** por defecto: solo ve la descripción pública de la CVE y
el código del PoC cuando existe. Esto simula el flujo real de un investigador que parte de cero.
Se pueden pasar hints opcionales (`--source`, `--endpoint`, `--method`) para anclar la hipótesis
cuando ya se sabe algo del objetivo, pero no son obligatorios.

La hipótesis es exactamente eso: una hipótesis fundamentada en texto, no un hecho probado. El
criterio de verdad es la verificación dinámica (Fase 4), no el razonamiento del modelo.

---

## Fase 3 — Scaffolding del laboratorio

### Detección del stack

Una vez que el LLM propone `affected_version` y `source_url`, el agente intenta construir un
laboratorio. La lógica de detección sigue este orden:

1. **Dockerfile/docker-compose del propio PoC** — si el código descargado trae un
   `Dockerfile` o `docker-compose.yml`, se usa directamente.
2. **Detección automática por ficheros** — si no hay Dockerfile, el agente mira:
   - `requirements.txt` / `setup.py` / `pyproject.toml` → stack **Python** (imagen `python:3.11-slim`)
   - `package.json` → stack **Node.js** (imagen `node:18-slim`)
   - `composer.json` / `*.php` → stack **PHP** (imagen `php:8.1-apache`)
   - Patrón `httpd` / `apache` en el nombre del componente → imagen `httpd:<version>`
3. **Dockerfile mínimo generado** — si ninguno de los anteriores aplica, el agente genera
   un Dockerfile mínimo para el stack detectado.

### Versión vulnerable vs. parcheada

El agente ancla el Dockerfile a la **versión vulnerable exacta**:

```dockerfile
FROM httpd:2.4.49
```

Si el LLM devuelve la versión parcheada en lugar de la vulnerable (error conocido),
el agente la corrige automáticamente y emite un mensaje `[CORR]` en el terminal:

```
[CORR] corrigiendo version: '2.4.50' es la version PARCHEADA; usando 2.4.49
```

### Secreto canario

Antes de levantar el contenedor, el agente genera un token aleatorio de 32 bytes y lo planta
en un fichero dentro del contenedor en una ruta fuera del webroot:

```
/binoracle_secret_<token_corto>.txt  → contenido: <token_completo>
```

Este secreto actúa como **oráculo binario**: si aparece en la respuesta HTTP, la vulnerabilidad
está confirmada de forma independiente al razonamiento del modelo.

---

## Fase 4 — Verificación dinámica

### Arranque del laboratorio

El agente ejecuta `docker compose up --build -d` en un directorio temporal aislado con red propia
(`binoracle_net_<id>`). Espera a que el servicio responda con un 200 antes de lanzar payloads
(timeout configurable, por defecto 60 s).

### Variantes de payload

Para cada clase de vulnerabilidad, el agente prueba múltiples variantes del payload:

- **URL encoding simple** — `../../../etc/passwd`
- **Double encoding** — `%2e%2e%2f%2e%2e%2f`
- **UTF-8 overlong** — `%c0%af` (bypass clásico de Apache)
- **Null byte** — `%00` al final
- **Combinaciones** de las anteriores

La base de conocimiento de payloads vive en `binoracle/workflows/payload_kb.py` y cubre:

| Clase                | Payloads típicos                                   |
|---------------------|----------------------------------------------------|
| `path-traversal`    | `../`, `%2e%2e%2f`, `..%2f`, doble encoding       |
| `command-injection` | `; id`, `\| id`, `$(id)`, `\`id\``                |
| `sqli`              | `' OR 1=1--`, `UNION SELECT`, time-based          |
| `ssti`              | `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`                |
| `xss`               | `<script>alert(1)</script>`, event handlers       |
| `ssrf`              | `http://169.254.169.254/`, `file:///etc/passwd`   |

### Criterio de verificación

El resultado es **VERIFICADO** si y solo si:

1. El secreto canario aparece textualmente en la respuesta HTTP, **o**
2. Para command-injection, se encuentra la salida del comando canario (`uid=`, nombre de host)
   en la respuesta.

Nunca se considera verificado por código de estado HTTP, por similitud de respuesta, ni por
el razonamiento del LLM. El campo `verified_evidence` recoge la evidencia real:

```json
{
  "payload_ganador": "/.%2e/.%2e/.%2e/.%2e/etc/passwd",
  "tiempo_1_ganador_s": 0.12,
  "tiempo_2_ganador_s": 0.11,
  "contenedor": "binoracle_httpd_abc123",
  "endpoint": "/cgi-bin/",
  "estrategia": "path-traversal via double-encoding"
}
```

Si ningún payload devuelve el secreto, el resultado es **NO CONFIRMADO** y el campo `blockers`
registra por qué (contenedor no arrancó, timeout, endpoint no encontrado, etc.).

---

## Fase 5 — Informe HTML

El informe HTML se genera con `binoracle cve <CVE-ID> --html informe.html`. Contiene:

### Secciones principales

| Sección              | Contenido                                                    |
|----------------------|--------------------------------------------------------------|
| **Cabecera**         | CVE-ID, CVSS pill con color por severidad, fecha            |
| **Tarjeta de explotación** | Clase de vulnerabilidad, impacto en una frase, endpoint, payload ganador |
| **Timeline**         | Pasos de la explotación numerados con timestamps            |
| **Análisis técnico** | Descripción NVD + hipótesis del LLM + funciones vulnerables |
| **Verificación**     | Estado VERIFICADO / NO CONFIRMADO con evidencia JSON        |
| **Galería de capturas** | Capturas Playwright con leyenda (si disponibles)         |
| **PoC descargable**  | Script Python/Bash generado, con botón de descarga          |
| **Mitigación**       | Recomendaciones concretas y accionables por clase de vuln   |

### Capturas de pantalla (Playwright)

Las capturas requieren tener Playwright instalado:

```bash
pip install playwright
playwright install chromium
```

Si Playwright no está disponible, el informe sigue siendo completo: las capturas se sustituyen
por la evidencia inline (payload, respuesta, timestamps). El flag `--open-report` abre el
informe en el navegador al terminar.

---

## Clases de vulnerabilidad soportadas

| Clase                  | Severidad típica | Impacto principal                                     |
|------------------------|-----------------|-------------------------------------------------------|
| `path-traversal`       | ALTO            | Lectura de ficheros arbitrarios fuera del webroot     |
| `command-injection`    | CRÍTICO         | Ejecución de comandos OS con privilegios del proceso  |
| `sqli`                 | CRÍTICO         | Lectura/escritura arbitraria de la base de datos      |
| `ssti`                 | CRÍTICO         | Inyección en motor de plantillas → RCE habitual       |
| `xss`                  | MEDIO           | JavaScript arbitrario en el navegador de otros usuarios |
| `ssrf`                 | ALTO            | Peticiones desde el servidor a servicios internos     |
| `missing-authorization`| CRÍTICO         | Toma de control de cuentas sin privilegio             |
| `idor`                 | ALTO            | Acceso a recursos de otros usuarios por ID            |
| `auth-bypass`          | CRÍTICO         | Saltarse autenticación sin credenciales válidas       |
| `rce`                  | CRÍTICO         | Ejecución remota de código arbitrario                 |
| `file-upload`          | CRÍTICO         | Subida de webshell → control del servidor             |
| `deserialization`      | CRÍTICO         | Deserialización controlada → RCE                      |
| `xxe`                  | ALTO            | Lectura de ficheros + SSRF via entidades XML          |
| `open-redirect`        | BAJO            | Apoyo en campañas de phishing                         |
| `csrf`                 | MEDIO           | Acción no deseada en nombre del usuario logueado      |

---

## Caché de investigaciones

Para no repetir desde cero pasos que no cambian (consultar NVD, leer el PoC, descargar código),
binoracle guarda el resultado en:

```
~/.cache/binoracle/investigations/<CVE-ID>.json
```

La caché se lee automáticamente en la siguiente invocación del mismo CVE-ID. Para forzar una
investigación fresca (por ejemplo, después de actualizar binoracle):

```bash
binoracle cve CVE-2021-41773 --no-cache
```

La ubicación del directorio de caché se puede cambiar con la variable de entorno
`BINORACLE_CACHE_DIR`.

---

## Límites y advertencias

- binoracle es una herramienta de investigación. Los laboratorios Docker solo se levantan
  contra contenedores locales efímeros que tú aprovisionas. No usar contra sistemas sin
  autorización explícita.
- El LLM local (Qwen 2.5 Coder 7B con 7B parámetros) comete errores: puede proponer versiones
  parcheadas en lugar de vulnerables, endpoints incorrectos, o clases de vulnerabilidad
  equivocadas. El pipeline corrige automáticamente los errores más comunes, pero la hipótesis
  siempre debe revisarse cuando el resultado es NO CONFIRMADO.
- La verificación dinámica requiere Linux x86-64 (nativo, WSL2 o VM). En macOS/Windows nativos
  la hipótesis LLM funciona pero no se puede verificar.

---

## Referencias

- [CVE_QUICKSTART.md](CVE_QUICKSTART.md) — primera ejecución en 5 minutos
- [CVE_REFERENCE.md](CVE_REFERENCE.md) — referencia completa de flags y variables de entorno
- [CVE_TROUBLESHOOTING.md](CVE_TROUBLESHOOTING.md) — solución de problemas comunes
- [ENGINE.md](ENGINE.md) — internals del motor (pipeline de binarios)
