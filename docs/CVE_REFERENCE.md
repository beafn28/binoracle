# CVE Reference — Referencia completa de comandos y configuración

---

## Comandos

### `binoracle cve`

Ejecuta una investigación completa para un único CVE-ID.

```
binoracle cve <CVE-ID> [opciones]
```

**Argumentos posicionales:**

| Argumento | Descripción                           |
|-----------|---------------------------------------|
| `CVE-ID`  | Identificador de la vulnerabilidad, formato `CVE-YYYY-NNNNN` (obligatorio) |

**Opciones:**

| Opción                   | Descripción                                                    | Por defecto |
|--------------------------|----------------------------------------------------------------|-------------|
| `--html <fichero>`        | Escribe el informe HTML completo en `<fichero>`               | (ninguno)   |
| `--no-cache`              | Ignora la caché de investigaciones anteriores y repite desde cero | usa caché |
| `--lang es\|en`           | Idioma del informe HTML (`es` = español, `en` = inglés)       | `es`        |
| `--open-report`           | Abre el informe HTML en el navegador al terminar              | no abre     |
| `--budget <segundos>`     | Tiempo máximo en segundos para toda la investigación          | `600`       |
| `--source <url>`          | URL del repositorio o zip del código fuente vulnerable (hint) | (auto)      |
| `--endpoint <ruta>`       | Endpoint HTTP conocido (hint para el LLM)                     | (auto)      |
| `--method GET\|POST`      | Método HTTP conocido (hint para el LLM)                       | (auto)      |
| `--vuln-class <clase>`    | Clase de vulnerabilidad conocida (hint para el LLM)           | (auto)      |

**Ejemplos:**

```bash
# Investigación básica, solo terminal
binoracle cve CVE-2021-41773

# Con informe HTML y apertura automática
binoracle cve CVE-2021-41773 --html informe.html --open-report

# Forzar reinvestigación ignorando caché
binoracle cve CVE-2021-41773 --no-cache

# Informe en inglés
binoracle cve CVE-2021-41773 --html report.html --lang en

# Con hints para anclar la hipótesis del LLM
binoracle cve CVE-2024-23334 \
    --source https://github.com/aio-libs/aiohttp \
    --endpoint /static/ \
    --vuln-class path-traversal \
    --html informe.html
```

---

### `binoracle cve-batch`

Ejecuta investigaciones para múltiples CVE-IDs en secuencia (o en paralelo con `--workers`).

```
binoracle cve-batch <CVE-ID-1> <CVE-ID-2> ... [opciones]
```

**Argumentos posicionales:**

| Argumento         | Descripción                                                |
|-------------------|------------------------------------------------------------|
| `CVE-ID-1 ...`    | Uno o más CVE-IDs separados por espacios (obligatorio)    |

**Opciones:**

| Opción              | Descripción                                                       | Por defecto |
|---------------------|-------------------------------------------------------------------|-------------|
| `--html-dir <dir>`  | Directorio donde escribir los informes HTML (uno por CVE)        | (ninguno)   |
| `--workers N`       | Número de investigaciones en paralelo                            | `1`         |
| `--no-cache`        | Ignora la caché para todos los CVEs del lote                     | usa caché   |
| `--lang es\|en`     | Idioma de todos los informes HTML                                | `es`        |

**Ejemplos:**

```bash
# Lote secuencial
binoracle cve-batch CVE-2021-41773 CVE-2024-23334

# Lote paralelo con informes HTML
binoracle cve-batch CVE-2021-41773 CVE-2024-23334 CVE-2025-27516 \
    --html-dir ./informes/ \
    --workers 3

# Reinvestigar todo el lote desde cero
binoracle cve-batch CVE-2021-41773 CVE-2024-23334 --no-cache
```

Los informes HTML se nombran `<CVE-ID>.html` dentro del directorio especificado.

---

## Variables de entorno

### Backend LLM

| Variable               | Descripción                                                       | Ejemplo                                 |
|------------------------|-------------------------------------------------------------------|-----------------------------------------|
| `BINORACLE_BACKEND`    | Proveedor del backend LLM: `openai` (compatible) o `anthropic`   | `openai`                                |
| `BINORACLE_BASE_URL`   | URL base de la API del backend                                    | `http://127.0.0.1:11434/v1`             |
| `BINORACLE_MODEL`      | Nombre del modelo a usar                                          | `qwen2.5-coder:7b`                      |
| `BINORACLE_API_KEY`    | Clave de API (para Ollama local, cualquier valor no vacío)        | `sk-...` o `ollama`                     |

**Configuración recomendada para Ollama local:**

```bash
export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=http://127.0.0.1:11434/v1
export BINORACLE_MODEL=qwen2.5-coder:7b
export BINORACLE_API_KEY=ollama
```

**Configuración para OpenAI (nube):**

```bash
export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=https://api.openai.com/v1
export BINORACLE_MODEL=gpt-4o
export BINORACLE_API_KEY=sk-proj-...
```

**Configuración para Anthropic (nube):**

```bash
export BINORACLE_BACKEND=anthropic
export BINORACLE_MODEL=claude-3-5-sonnet-20241022
export BINORACLE_API_KEY=sk-ant-...
```

> **Nota.** binoracle es local por diseño: el modelo recomendado es `qwen2.5-coder:7b` sobre
> Ollama, que corre 100% en tu máquina. Los proveedores externos (OpenAI/Anthropic) son
> compatibles pero envían datos fuera del host.

### Caché

| Variable               | Descripción                                              | Por defecto              |
|------------------------|----------------------------------------------------------|--------------------------|
| `BINORACLE_CACHE_DIR`  | Directorio de caché de investigaciones                  | `~/.cache/binoracle`     |
| `BINORACLE_NO_CACHE`   | Si vale `1`, desactiva la caché completamente           | `0` (caché activa)       |

### Modelos recomendados por caso de uso

| Modelo                   | Proveedor | RAM necesaria | Calidad hipótesis | Velocidad |
|--------------------------|-----------|---------------|-------------------|-----------|
| `qwen2.5-coder:7b`       | Ollama    | ~6 GB         | Buena             | Rápida    |
| `qwen2.5-coder:14b`      | Ollama    | ~11 GB        | Muy buena         | Media     |
| `qwen2.5-coder:32b`      | Ollama    | ~22 GB        | Excelente         | Lenta     |
| `gpt-4o`                 | OpenAI    | (nube)        | Excelente         | Rápida    |
| `claude-3-5-sonnet-...`  | Anthropic | (nube)        | Excelente         | Rápida    |

---

## Formato de salida en terminal

### Niveles de mensaje

| Nivel     | Icono | Color    | Significado                                      |
|-----------|-------|----------|--------------------------------------------------|
| `INFO`    | `ℹ`   | Azul     | Progreso normal                                  |
| `OK`      | `✓`   | Verde    | Paso completado con éxito                        |
| `WARN`    | `⚠`   | Amarillo | Advertencia no fatal                             |
| `ERROR`   | `✖`   | Rojo     | Error recuperable                                |
| `CORR`    | —     | Amarillo | Corrección automática (versión parcheada, etc.)  |

### Paneles especiales

El terminal muestra paneles destacados para los eventos más importantes:

**Panel de hipótesis** (cuando el LLM propone una clase):
```
  ╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌
  » Clase:  PATH-TRAVERSAL
  ╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌
```

**Panel de objetivo arriba** (cuando el laboratorio está listo):
```
  ┌──────────────────────────────────────────────────────┐
  │  URL:        http://127.0.0.1:35421                  │
  │  Contenedor: binoracle_httpd_abc123                  │
  └──────────────────────────────────────────────────────┘
```

**Banner VERIFICADO** (cuando el secreto canario aparece en la respuesta):
```
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ★  VERIFICADO: el secreto plantado apareció en la respuesta
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Estructura del objeto `Investigation`

El resultado interno de cada investigación es un dataclass con estos campos principales:

| Campo                | Tipo     | Descripción                                              |
|----------------------|----------|----------------------------------------------------------|
| `cve_id`             | `str`    | CVE-ID normalizado en mayúsculas                        |
| `description`        | `str`    | Descripción de NVD                                      |
| `lookup_ok`          | `bool`   | True si NVD devolvió datos                              |
| `cvss_score`         | `float`  | Puntuación CVSS (None si no consta)                     |
| `cvss_severity`      | `str`    | LOW / MEDIUM / HIGH / CRITICAL                          |
| `vuln_class`         | `str`    | Clase de vulnerabilidad (hipótesis LLM)                 |
| `llm_notes`          | `dict`   | Hipótesis completa del LLM (JSON)                       |
| `verified`           | `bool`   | True si se confirmó con evidencia real                  |
| `verified_evidence`  | `dict`   | Payload ganador, tiempos, contenedor, endpoint          |
| `blockers`           | `list`   | Razones por las que no se verificó (si aplica)          |
| `poc_source_used`    | `str`    | URL del PoC público leído (vacío si ninguno)            |

Este objeto se guarda en caché como JSON en `~/.cache/binoracle/investigations/<CVE-ID>.json`.

---

## Véase también

- [CVE_QUICKSTART.md](CVE_QUICKSTART.md) — primera ejecución paso a paso
- [CVE_PIPELINE.md](CVE_PIPELINE.md) — arquitectura interna del pipeline
- [CVE_TROUBLESHOOTING.md](CVE_TROUBLESHOOTING.md) — solución de problemas
