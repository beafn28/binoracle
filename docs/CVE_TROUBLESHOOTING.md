# CVE Troubleshooting — Solución de problemas comunes

---

## El resultado es "NO CONFIRMADO" cuando debería ser VERIFICADO

Este es el caso más habitual. Hay varias causas posibles:

### Docker no está corriendo

**Síntoma:** El pipeline llega a la fase de scaffolding y se detiene, o aparece un error como:
```
Cannot connect to the Docker daemon at unix:///var/run/docker.sock
```

**Solución:**
```bash
# Linux con systemd
sudo systemctl start docker
sudo systemctl enable docker   # para que arranque automáticamente

# Verificar
docker ps
```

Si usas Docker Desktop en Linux, ábrelo antes de lanzar binoracle.

---

### El LLM propone la versión parcheada en lugar de la vulnerable

**Síntoma:** El terminal muestra:
```
[CORR] corrigiendo version: '2.4.50' es la version PARCHEADA; usando 2.4.49
```

Este mensaje indica que el agente **ya corrigió** el problema automáticamente. No es un error
fatal: continúa con la versión correcta. Si el mensaje no aparece pero el laboratorio arranca
con la versión parcheada, puedes forzar la versión con `--source`:

```bash
binoracle cve CVE-2021-41773 --source https://archive.apache.org/dist/httpd/httpd-2.4.49.tar.gz
```

---

### El LLM propone como `source_url` algo que no es un Dockerfile

**Síntoma:** El agente intenta usar una URL como fuente del laboratorio pero el contenido no
es un Dockerfile (es un advisory, una página web, un fichero Python suelto…).

**Comportamiento:** El pipeline detecta este caso automáticamente y descarta la `source_url`
no válida, pasando a la detección automática de stack. Se muestra un mensaje `[WARN]` en el
terminal pero la investigación continúa.

**Acción si persiste:** Proporciona tú mismo la URL correcta:

```bash
binoracle cve CVE-2024-23334 --source https://github.com/aio-libs/aiohttp/archive/v3.9.1.zip
```

---

### Error en captura de pantalla que interrumpe la verificación

**Síntoma (antes de la versión actual):** La captura Playwright fallaba con una excepción no
capturada que abortaba el proceso de verificación.

**Estado actual:** Corregido. Los errores de Playwright se capturan y la verificación continúa
sin capturas. Si ves un error de este tipo en la versión actual, actualiza binoracle:

```bash
pip install --upgrade binoracle
```

---

### El endpoint propuesto no existe en el contenedor

**Síntoma:** Todos los payloads devuelven 404 o el contenedor responde pero no con el recurso
esperado. Los `blockers` en el resultado final muestran algo como:
```
endpoint /cgi-bin/ devuelve 404 en todos los intentos
```

**Diagnóstico:** La hipótesis del LLM puede haber errado en el endpoint. Proporciona el
endpoint correcto (lo encontrarás en el advisory oficial o en el PoC público):

```bash
binoracle cve CVE-2021-41773 --endpoint "/cgi-bin/" --method GET
```

---

## "no se pudo descargar ningún PoC"

**Síntoma:** El terminal muestra que la búsqueda de PoC en GitHub/Exploit-DB no devolvió
código usable.

**Explicación:** Es el comportamiento esperado cuando el PoC publicado es un advisory en texto,
un post de blog o una descripción sin código ejecutable. El agente lo registra en el log pero
continúa: trabaja solo con la descripción de NVD para generar la hipótesis LLM.

**Consecuencia:** La hipótesis del LLM es menos precisa porque no tiene código de referencia.
El resultado puede ser NO CONFIRMADO si el LLM no deduce el endpoint o los parámetros exactos.

**Solución alternativa:** Si conoces el endpoint real (del advisory oficial), pásalo como hint:

```bash
binoracle cve CVE-XXXX-XXXXX --endpoint "/ruta/real" --method POST
```

---

## Playwright devuelve `None` o no genera capturas

**Síntoma:** El informe HTML no tiene capturas, o el terminal muestra:
```
[WARN] playwright no disponible; capturas desactivadas
```

**Causa:** Playwright no está instalado, o el navegador Chromium no está descargado.

**Solución:**
```bash
pip install playwright
playwright install chromium

# Verificar instalación
python3 -c "from playwright.sync_api import sync_playwright; print('OK')"
```

Si la instalación falla por restricciones del entorno (contenedor, CI/CD…), el informe HTML
sigue siendo completo: las capturas se sustituyen por evidencia inline (payload exacto,
fragmento de respuesta HTTP, timestamps). No es obligatorio tener Playwright.

---

## Advertencia `pkg_resources is deprecated`

**Síntoma:** Al ejecutar cualquier comando de binoracle aparece:
```
DeprecationWarning: pkg_resources is deprecated as an API. Use importlib.resources instead.
```

**Explicación:** Advertencia inofensiva de `setuptools` en versiones recientes de Python.
No afecta al funcionamiento de binoracle.

**Para silenciarla:**
```bash
# Opción 1: ignorar warnings de deprecación
python3 -W ignore::DeprecationWarning -m binoracle cve CVE-2021-41773

# Opción 2: bajar a una versión de setuptools sin el warning
pip install "setuptools<81"
```

---

## El LLM tarda más de 60 segundos en responder

**Síntoma:** La fase "Hipótesis LLM" tarda mucho y el terminal queda quieto durante más de
un minuto.

**Causas frecuentes y soluciones:**

| Causa                          | Diagnóstico                              | Solución                                      |
|-------------------------------|------------------------------------------|-----------------------------------------------|
| Modelo demasiado grande para la RAM | `ollama ps` muestra swap alto          | Usar `qwen2.5-coder:7b` en lugar de 14b/32b   |
| CPU sin GPU disponible         | `ollama ps` muestra `100% CPU`          | Ver nota sobre GPU más abajo                  |
| Ollama no está corriendo       | `curl http://127.0.0.1:11434/api/tags` falla | `ollama serve &`                           |
| Modelo no descargado           | `ollama list` no muestra el modelo      | `ollama pull qwen2.5-coder:7b`               |

**Acelerar con GPU:**

Ollama detecta automáticamente NVIDIA/AMD/Metal. Verifica que la GPU se está usando:

```bash
# NVIDIA
nvidia-smi   # muestra procesos ollama si usa GPU
ollama ps    # muestra "100% GPU" si está acelerado

# Si no detecta GPU automáticamente
export CUDA_VISIBLE_DEVICES=0
ollama serve
```

Con `qwen2.5-coder:7b` en una GPU de 8 GB la hipótesis tarda típicamente 3-10 segundos.
En CPU pura puede llegar a 90 segundos con un procesador de 8 núcleos.

---

## El laboratorio Docker tarda mucho en arrancar

**Síntoma:** La fase de verificación dinámica queda esperando más de 30 segundos con:
```
[INFO] esperando a que el laboratorio esté disponible...
```

**Causas:**

- **Primera vez con esa imagen:** Docker está descargando la imagen base (p.ej. `httpd:2.4.49`,
  `python:3.11-slim`). Esperar a que termine; las ejecuciones siguientes usarán la caché de Docker.
- **Build lento de imagen personalizada:** El PoC trae un Dockerfile con muchas dependencias.
  Normal en la primera ejecución.
- **Contenedor que no responde en el puerto esperado:** El servicio puede arrancar en un puerto
  distinto. Revisar los logs del contenedor:
  ```bash
  docker logs $(docker ps -q --filter "name=binoracle_")
  ```

---

## `binoracle doctor` muestra el backend LLM como no disponible

**Síntoma:**
```
backend LLM: NO DISPONIBLE
```

**Pasos de diagnóstico:**

```bash
# ¿Está Ollama corriendo?
curl http://127.0.0.1:11434/api/tags

# ¿Están las variables de entorno configuradas?
echo $BINORACLE_BACKEND
echo $BINORACLE_BASE_URL
echo $BINORACLE_MODEL

# Si usas un fichero .env, cárgalo
source .env && binoracle doctor
```

Si `BINORACLE_BACKEND` está vacío, binoracle no sabe a qué backend conectar. Configura las
tres variables (`BACKEND`, `BASE_URL`, `MODEL`) antes de ejecutar.

---

## El informe HTML está vacío o sin estilo

**Síntoma:** El fichero `.html` generado tiene el contenido del informe pero sin CSS/estilo,
o el fichero existe pero está vacío.

**Causa:** Error al escribir el fichero (permisos, disco lleno) o excepción durante el
renderizado.

**Diagnóstico:**
```bash
# Verificar que el fichero tiene contenido
wc -c informe.html

# Intentar con una ruta alternativa
binoracle cve CVE-2021-41773 --html /tmp/informe_test.html
```

Si el problema persiste, lanza el comando con el modo de log verboso:
```bash
BINORACLE_LOG_LEVEL=DEBUG binoracle cve CVE-2021-41773 --html informe.html 2>&1 | tee debug.log
```

---

## Véase también

- [CVE_QUICKSTART.md](CVE_QUICKSTART.md) — primera ejecución paso a paso
- [CVE_PIPELINE.md](CVE_PIPELINE.md) — cómo funciona el pipeline en detalle
- [CVE_REFERENCE.md](CVE_REFERENCE.md) — todos los flags y variables de entorno
