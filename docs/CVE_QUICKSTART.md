# CVE Quickstart — De cero a VERIFICADO en 5 minutos

Este tutorial lleva desde la instalación limpia hasta un resultado `VERIFICADO` usando
**CVE-2021-41773** (path-traversal en Apache HTTP Server 2.4.49), una de las CVEs más
documentadas y un buen banco de pruebas para el pipeline.

---

## Requisitos previos

| Requisito         | Versión mínima | Notas                                                  |
|-------------------|---------------|--------------------------------------------------------|
| Python            | 3.10          | `python3 --version`                                    |
| Docker            | 20.10         | Debe estar corriendo: `docker ps`                      |
| Ollama            | 0.1.x         | LLM local: `ollama --version`                          |
| Playwright        | opcional      | Solo para capturas de pantalla en el informe HTML      |

> **Plataforma.** La verificación dinámica requiere Linux x86-64 (nativo, WSL2 o VM). En macOS
> o Windows nativos el pipeline corre hasta la hipótesis LLM pero no puede levantar el lab.

---

## Paso 1 — Instalar binoracle

```bash
pip install binoracle
```

Comprueba que el comando está disponible:

```bash
binoracle --version
```

---

## Paso 2 — Instalar y configurar Ollama

```bash
# Instalar Ollama (Linux)
curl -fsSL https://ollama.com/install.sh | sh

# Descargar el modelo recomendado (~4.7 GB)
ollama pull qwen2.5-coder:7b

# Verificar que el servidor está corriendo
curl http://127.0.0.1:11434/api/tags
```

---

## Paso 3 — Variables de entorno

Configura binoracle para usar Ollama como backend LLM. Añade esto a tu `.bashrc` / `.zshrc`
o exclúyelo antes de cada sesión:

```bash
export BINORACLE_BACKEND=openai          # Ollama expone la API compatible con OpenAI
export BINORACLE_BASE_URL=http://127.0.0.1:11434/v1
export BINORACLE_MODEL=qwen2.5-coder:7b
export BINORACLE_API_KEY=ollama          # cualquier valor no vacío; Ollama no valida la clave
```

Verifica que binoracle ve el backend:

```bash
binoracle doctor
```

La salida debe mostrar el backend LLM como disponible y Docker como listo.

---

## Paso 4 (opcional) — Instalar Playwright para capturas

Las capturas de pantalla en el informe HTML son opcionales. Si las quieres:

```bash
pip install playwright
playwright install chromium
```

Sin Playwright el informe sigue siendo completo; las capturas se sustituyen por evidencia
inline (payload, respuesta, timestamps).

---

## Paso 5 — Primera ejecución

```bash
binoracle cve CVE-2021-41773 --html informe.html
```

El terminal muestra el progreso en tiempo real, organizado por fases:

```
╔══════════════════════════════════════════════════════════════════╗
║  ◈ BINORACLE  ·  CVE-2021-41773  ·  investigación autónoma
╚══════════════════════════════════════════════════════════════════╝

── 🔍  Consulta NVD ──────────────────────────────────────────────
     0.8s  [INFO] CVE-2021-41773 encontrada en NVD (CVSS 7.5 HIGH)
     1.2s  [INFO] descripción: A flaw was found in a change made to path normalization...

── 🧠  Hipótesis LLM ─────────────────────────────────────────────
     3.1s  [INFO] hipotesis del LLM: clase=path-traversal, disparador=GET /cgi-bin/

  ╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌
  » Clase:  PATH-TRAVERSAL
  ╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌

── 🏗️  Scaffolding del lab ───────────────────────────────────────
     5.4s  [INFO] scaffolded minimal path-traversal lab at /tmp/... (vuln_class=path-traversal, pin=2.4.49)
          pin: 2.4.49  ·  clase: path-traversal

── 🚀  Verificación dinámica ─────────────────────────────────────
    12.3s  [INFO] objetivo arriba: http://127.0.0.1:35421 (contenedor 'binoracle_httpd_abc123')

  ┌──────────────────────────────────────────────────────┐
  │  URL:        http://127.0.0.1:35421                  │
  │  Contenedor: binoracle_httpd_abc123                  │
  └──────────────────────────────────────────────────────┘

    14.1s  [INFO] probando payload: /.%2e/.%2e/.%2e/.%2e/etc/passwd

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ★  VERIFICADO: el secreto plantado apareció en la respuesta
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

╔══════════════════════════════════════════════════════════════════╗
║                     ★  VERIFICADO                               ║
╚══════════════════════════════════════════════════════════════════╝

  Contenedor:       binoracle_httpd_abc123
  Endpoint:         /cgi-bin/
  Payload ganador:  /.%2e/.%2e/.%2e/.%2e/etc/passwd
  Tiempo 1: 0.12s  Tiempo 2: 0.11s  Baseline: 0.08s
  Estrategia:       path-traversal via double-encoding

  Tiempo total: 18.3s
  CVSS 7.5 HIGH · clase: path-traversal · PoC: http
```

---

## Qué significa cada parte del output

### Recuadro inicial

```
╔══════════════════════════════════════════════════════════════════╗
║  ◈ BINORACLE  ·  CVE-2021-41773  ·  investigación autónoma
╚══════════════════════════════════════════════════════════════════╝
```

Confirma el CVE-ID y que el modo es autónomo (sin hints del analista).

### Fases numeradas

Cada bloque `── Nombre de Fase ──` separa las fases del pipeline. Los timestamps a la izquierda
(`0.8s`, `3.1s`, …) son tiempos transcurridos desde el inicio.

### Panel de hipótesis

```
» Clase:  PATH-TRAVERSAL
```

La clase de vulnerabilidad que el LLM dedujo. Orienta los payloads que se van a probar.

### Panel de objetivo arriba

```
┌──────────────────────────────────────────────────────┐
│  URL:        http://127.0.0.1:35421                  │
│  Contenedor: binoracle_httpd_abc123                  │
└──────────────────────────────────────────────────────┘
```

El laboratorio Docker está listo y binoracle empieza a disparar payloads.

### Banner VERIFICADO

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
★  VERIFICADO: el secreto plantado apareció en la respuesta
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

El secreto canario plantado en el contenedor apareció en la respuesta HTTP. La vulnerabilidad
está confirmada de forma independiente al LLM.

### Recuadro final con evidencia

Muestra el payload que funcionó, el contenedor, los tiempos de respuesta y la estrategia.
`Tiempo 1` y `Tiempo 2` son dos repeticiones del payload ganador para confirmar reproducibilidad.

---

## Paso 6 — Leer el informe HTML

```bash
# Abrir el informe en el navegador
xdg-open informe.html        # Linux
open informe.html            # macOS

# O pasar --open-report para que binoracle lo abra automáticamente
binoracle cve CVE-2021-41773 --html informe.html --open-report
```

El informe contiene: cabecera con CVSS pill, tarjeta de explotación, timeline de pasos,
análisis técnico, evidencia de verificación, galería de capturas (si Playwright está
instalado) y el PoC descargable.

---

## Siguiente CVE de prueba

Una vez que el primer CVE funciona, prueba con uno más reciente:

```bash
# CVE-2024-23334 — aiohttp path-traversal (Python)
binoracle cve CVE-2024-23334 --html informe-aiohttp.html
```

Este CVE usa un stack Python con `aiohttp`, lo que ejercita la detección automática de stack
(en lugar de Apache/httpd).

---

## Siguientes pasos

- [CVE_PIPELINE.md](CVE_PIPELINE.md) — cómo funciona el pipeline en detalle
- [CVE_REFERENCE.md](CVE_REFERENCE.md) — todos los flags y opciones
- [CVE_TROUBLESHOOTING.md](CVE_TROUBLESHOOTING.md) — qué hacer cuando el resultado es NO CONFIRMADO
