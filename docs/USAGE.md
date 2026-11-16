# binoracle — Guía de uso (levantar en local y analizar)

Guía práctica para poner binoracle en marcha y analizar artefactos (APK, ELF, Mach-O, .NET, JS…),
por CLI, servidor MCP o la UI web.

> **Plataforma.** El núcleo estático (lectores) corre en cualquier sitio. La **verificación de
> exploits por ejecución** necesita **Linux x86-64** (nativo, WSL2, o una VM/cloud x86-64). En
> Windows nativo o macOS nativo tendrás solo la mitad estática. Ver "Plataformas" al final.

---

## 0. Opción más fácil: Docker (recomendada en Mac / Windows)

Trae Linux x86-64 dentro, así que funcionan **tanto los lectores como la verificación de exploits**
sin instalar nada en tu máquina más que Docker.

```bash
git clone <tu-repo> binoracle && cd binoracle
make docker                      # = docker compose build + up -d  (web en http://127.0.0.1:8080)
# equivalente sin make:
docker compose up --build
# atajos: make docker-logs | make docker-shell | make docker-down
```

Analizar **tus** ficheros: déjalos en `./targets/` y en la app (web o CLI) usa la ruta
`/targets/<fichero>`:

```bash
# copia tu APK a ./targets/ y:
docker compose run --rm binoracle binoracle apk /targets/tu-app.apk
# verificar exploits dentro del contenedor:
docker compose exec binoracle pytest tests/test_smoke.py -v
```

> En **Mac M1** Docker ejecuta la imagen como `linux/amd64` por emulación (más lento pero funcional
> para los exploits x86). Si solo quieres lectura estática, puedes quitar `platform: linux/amd64` del
> `docker-compose.yml` y correrá nativo arm64. El bloque `cap_add`/`security_opt` del compose es
> **solo** para la verificación de exploits por ejecución (objetivos AUTORIZADOS/CTF); si no lo
> necesitas, bórralo.

---

## 1. Instalación nativa (alternativa)

```bash
cd binoracle
pip install -e .            # deja el comando `binoracle` en el PATH
# opcional, para más capacidades:
make install-tools          # radare2, pwntools, one_gadget, ...
sudo apt install -y jadx apktool   # análisis Android a nivel clase/método y recursos
```

Comprueba que está instalado:

```bash
binoracle --help
binoracle doctor            # estado de backend LLM, herramientas externas y RAG
```

---

## 2. Construir el corpus de práctica (opcional, para los exploits)

```bash
bash samples/build.sh       # compila ret2win, srop, heap (hof/hos/hoe/botcake/largebin/stash/hoc/
                            # unsafeunlink/fastbindup/homind/iofile), etc. en samples/bin/
```

---

## 3. Analizar un artefacto por CLI

El front-end "reversea cualquier cosa": pásale un fichero y lo identifica y enruta.

```bash
binoracle identify  ruta/al/fichero      # detecta el formato y aplica el lector adecuado
```

### Android (APK)
```bash
binoracle apk            tu-app.apk       # manifest, DEX, ABIs, frameworks (Flutter/RN/…), firma, snapshots
binoracle apk-manifest   tu-app.apk       # (apktool) AndroidManifest decodificado + permisos
binoracle apk-decompile  tu-app.apk       # (jadx) DEX -> Java, resumen de clases
```
Ejemplo de salida real sobre un APK Flutter:
```
formato detectado: apk
framework detectado: Flutter
ABIs nativas: arm64-v8a  ->  libapp.so, libflutter.so
engine libflutter.so: build-id … | Dart VM 3.4.1 (stable) | backend Impeller | API Vulkan
flutter_assets: AssetManifest, fuentes[Roboto], version.json{com.demo.app 1.2.3+45}
firma v1 (JAR): META-INF/CERT.RSA
```

### Otros formatos
```bash
binoracle elf      bin            binoracle macho   app         binoracle pe      x.exe
binoracle dotnet   x.dll          binoracle go      bin         binoracle wasm    mod.wasm
binoracle sqlite   db             binoracle evm     code.bin    binoracle js      bundle/
binoracle plist    Info.plist     binoracle asar    app.asar    binoracle har     capture.har
binoracle java     app.jar        binoracle secrets dir/
```

### Triage / cadenas / arsenal (nativo)
```bash
binoracle triage    bin            # hechos fundamentados: arch, NX/PIE/canary/RELRO, símbolos, superficie
binoracle analyze   bin            # chain-analyzer: cadenas candidatas (ret2win/libc/srop/heap/…)
binoracle arsenal   bin            # arsenal ROP: mejor gadget por registro, syscall, pivot, one_gadget
binoracle gadgets   bin            # gadgets ROP clasificados
```

---

## 4. Verificar exploits por ejecución (Linux x86-64)

La verificación "verified = shell real" vive en los tests y en los flujos `autopwn`/`audit`:

```bash
pytest tests/test_smoke.py -v                    # toda la suite (auto-salta lo que no aplica)
pytest tests/test_smoke.py -k fastbindup -v      # una familia concreta
pytest tests/test_smoke.py -k heap_families_as_verified -v   # el grafo de cadenas de heap

binoracle autopwn samples/bin/ret2win            # intenta combinaciones y verifica en sandbox
binoracle audit   samples/bin/heapexp            # auditoría + explotación autónoma (con LLM local)
```

Probar una familia a mano (devuelve `verified: true` + direcciones reales si popea shell):
```bash
python3 -c "from binoracle.workflows.autofastbindup import autofastbindup; \
import json; print(json.dumps(autofastbindup('samples/bin/fastbindup'), default=str, indent=2))"
```

---

## 5. Servidor MCP (para Claude / Cursor / cualquier cliente MCP)

```bash
binoracle mcp               # habla JSON-RPC por stdio; expone ~104 herramientas
```
Conéctalo a tu cliente MCP y pídele, por ejemplo:
*"analiza tu-app.apk con inspect_apk e inspect_flutter"*, o
*"verifica fastbin-dup en samples/bin/fastbindup"* (→ llama a `autofastbindup`).

---

## 6. UI web local

```bash
binoracle serve                               # abre en el navegador (http://127.0.0.1:8080 por defecto)
binoracle serve --host 127.0.0.1 --port 8777 --no-open   # sin abrir navegador, puerto fijo
```
Arrastra/sube el fichero en la UI y lanza los comandos (`identify`, `apk`, `triage`, `analyze`, …).
La UI usa la API `POST /api/run` con `{"command": "...", "binary": "...", "options": {}}`:

```bash
curl -s -X POST http://127.0.0.1:8777/api/run -H 'Content-Type: application/json' \
     -d '{"command":"apk","binary":"/ruta/tu.apk","options":{}}'
```

> Si trabajas en una VM/cloud y abres el servidor ahí, reenvía el puerto para verlo en tu navegador:
> `ssh -L 8777:127.0.0.1:8777 usuario@maquina` y entra a `http://127.0.0.1:8777`.

---

## 7. Lo mínimo para verlo funcionando (30 s, Linux x86-64)

```bash
pip install -e . && bash samples/build.sh && \
  pytest tests/test_smoke.py -k "fastbindup or unsafeunlink or hoc or homind or iofile" -v
```

---

## 8. Sitio de documentación estático (tutorial guiado incluido)

```bash
pip install -e ".[docs]"
python3 docs/build_site.py
# abre docs/site/index.html en tu navegador
```

Genera un sitio HTML estático (sin servidor, sin JS) a partir de `docs/TUTORIAL.md` (un recorrido
guiado, paso a paso, por el corpus de `samples/` -- de `triage` a un exploit verificado), más
`USAGE.md`, `ENGINE.md` y `ROADMAP.md`. `docs/site/` no se versiona (es un artefacto generado);
reconstrúyelo cuando cambie cualquier `.md` fuente.

---

## 9. Pipeline CVE — investigación autónoma de vulnerabilidades web

binoracle incluye un segundo pipeline, independiente del análisis de binarios, que toma un
CVE-ID y ejecuta una investigación completa de forma autónoma: consulta NVD, genera una
hipótesis de explotación con el LLM local, levanta un laboratorio Docker efímero con la
versión vulnerable y verifica la vulnerabilidad con evidencia real.

```bash
# Investigación básica (resultado en terminal)
binoracle cve CVE-2021-41773

# Con informe HTML
binoracle cve CVE-2021-41773 --html informe.html --open-report

# Lote de CVEs con informes paralelos
binoracle cve-batch CVE-2021-41773 CVE-2024-23334 --html-dir ./informes/ --workers 2
```

Configuración mínima (Ollama local recomendado):

```bash
export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=http://127.0.0.1:11434/v1
export BINORACLE_MODEL=qwen2.5-coder:7b
export BINORACLE_API_KEY=ollama
```

Documentación completa del pipeline CVE:

| Documento | Contenido |
|---|---|
| [CVE_QUICKSTART.md](CVE_QUICKSTART.md) | Primera ejecución paso a paso, de cero a VERIFICADO |
| [CVE_PIPELINE.md](CVE_PIPELINE.md) | Arquitectura interna: NVD → LLM → Docker → verificación → HTML |
| [CVE_REFERENCE.md](CVE_REFERENCE.md) | Todos los flags, opciones y variables de entorno |
| [CVE_TROUBLESHOOTING.md](CVE_TROUBLESHOOTING.md) | Qué hacer cuando el resultado es NO CONFIRMADO |

---

## Plataformas soportadas

| Plataforma | Núcleo estático (lectores) | Verificación de exploits por ejecución |
|---|---|---|
| **Linux x86-64** (referencia) | ✅ | ✅ todo (x86-64/x86-32) |
| **Windows + WSL2** (x86-64) | ✅ | ✅ igual que Linux |
| **Mac M1 + VM Linux ARM64** | ✅ | ⚠️ nativo solo aarch64; x86 por emulación (más lento/menos fiable) |
| **Windows / macOS nativos** | ✅ | ❌ (sin ELF/`/proc`/glibc/`unshare`) |

binoracle es **local y offline**: nada sale del host. Moverlo entre máquinas es `git clone` +
`pip install -e .` + `bash samples/build.sh`; lo único que importa para los exploits es que debajo
haya un **kernel Linux**.
