<div align="center">

<img src="assets/logo.svg" alt="binoracle" width="120" height="120">

# binoracle

**Investigación autónoma de exploits CVE y reversing binario — 100% local**

[![PyPI](https://img.shields.io/pypi/v/binoracle?color=blue&label=PyPI)](https://pypi.org/project/binoracle/)
[![Python](https://img.shields.io/badge/python-%3E%3D3.10-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](../LICENSE)
[![Docs](https://img.shields.io/badge/docs-gh--pages-blueviolet)](https://beafn28.github.io/binoracle/)

[English](../README.md) · [Español](README.es.md) · [Docs](https://beafn28.github.io/binoracle/) · [Arquitectura](assets/architecture.svg) · [Tutorial](TUTORIAL.md)

</div>

---

> **AVISO LEGAL** — binoracle es una herramienta de investigación y educación.
> Todos los laboratorios CVE se ejecutan contra contenedores Docker que tú creas localmente.
> Nunca la uses contra sistemas que no sean tuyos o para los que no tengas permiso escrito explícito.

---

## ¿Qué es binoracle?

binoracle es un asistente de investigación de seguridad **totalmente local y offline-first** con dos motores principales:

| Motor | Qué hace |
|-------|----------|
| **Motor CVE** | Obtiene un CVE de NVD, lo envía a un LLM local (Qwen 2.5 Coder 7B via Ollama) que genera hipótesis de exploit de forma autónoma sin pistas externas, provisiona un laboratorio Docker Compose efímero, ejecuta el proof-of-concept, captura screenshots Playwright en cada paso de verificación y emite un informe HTML estructurado. |
| **Motor RE Binario** | Análisis estático y dinámico de artefactos ELF, PE, Mach-O, APK, WASM, Go, Rust, .NET, JS, EVM y SQLite. Cubre generación de exploits (stack, heap, format string, SROP), síntesis de cadenas ROP, decompilación con múltiples backends y evaluación de protecciones. Todas las operaciones son locales. |

Ningún dato sale del host. El LLM corre via la API OpenAI-compatible de Ollama en `localhost:11434`. Los laboratorios Docker se destruyen tras cada ejecución. Los informes se escriben en disco.

---

## Inicio rápido

```bash
# Instalar
pip install binoracle

# Instalar Ollama y descargar el modelo (Linux / macOS)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder:7b

# Configurar el backend LLM
export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=http://127.0.0.1:11434/v1
export BINORACLE_MODEL=qwen2.5-coder:7b

# Ejecutar el motor CVE
binoracle cve CVE-2025-27516

# Análisis estático de un binario
binoracle triage ./binario_objetivo

# Cadena de exploit completa
binoracle pwn ./binario_vulnerable
```

---

## Motor CVE

El motor es completamente autónomo: el LLM local recibe únicamente la descripción NVD sin pistas del analista. Todas las hipótesis de exploit se generan a partir de esa descripción.

![Flujo del motor CVE](assets/cve-flow.svg)

### Clases de vulnerabilidad soportadas

| Clase | Scaffolders | PoC automático |
|-------|------------|----------------|
| SSTI (Jinja2, Twig, Smarty) | pip / gem | sí |
| SQLi (GET / POST / JSON / header) | pip / gem / php / maven | sí |
| Path traversal / LFI | pip / gem / npm / httpd | sí |
| RCE / inyección de comandos | pip / gem / npm | sí |
| XSS (reflected / stored) | pip / npm | sí |
| SSRF | pip / npm | sí |
| XXE | java / maven | sí |
| Deserialización | java / gem (Marshal) | sí |
| Auth bypass / IDOR | pip / gem / npm | sí |
| Subida de ficheros / webshell | pip | sí |
| Open redirect | pip / gem / npm | sí |
| CSRF | pip / gem | sí |
| Plugins WordPress (100+) | WP Docker | sí |
| Extensiones Joomla | Joomla Docker | sí |
| Módulos Drupal | Drupal Docker | sí |
| Apache httpd | httpd Docker | sí |
| Java / Maven (Spring, Struts, Log4j) | maven | sí |
| Paquetes PHP Composer | php | sí |
| npm / Node.js / Next.js | npm | sí |
| Ruby gems (Rails, Rack, Sinatra) | gem | sí |

```bash
# CVE individual
binoracle cve CVE-2025-27516

# Lote, paralelizado
binoracle cve-batch CVE-2025-27516 CVE-2024-23334 CVE-2025-59681

# Idioma del informe
binoracle cve CVE-2025-27516 --lang en
```

---

## Motor de Reversing Binario

```bash
binoracle pwn ./binario
```

### Familias de exploit

| Familia | Técnicas |
|---------|----------|
| Stack | ret2win, ret2libc, ret2plt, ret2csu, SROP (x86-64 / x86-32 / aarch64), stack pivot, cadenas ROP |
| Heap | tcache dup, fastbin dup, UAF, double-free, House-of-Force, House-of-Spirit, House-of-Orange, House-of-Mind, large-bin attack, unsafe-unlink, Botcake |
| Format string | escritura arbitraria %n, GOT overwrite, canary leak, PIE leak |
| Bajo nivel | shellcode (NX off), bad-char scrubbing, exploit IO_FILE, DL-resolve, GOT hijack |
| Canary | leak + reuse, fork brute-force |
| PIE | partial overwrite, leak chain |

### Comandos de análisis estático

```bash
binoracle triage ./binario        # protecciones, símbolos, imports, secciones
binoracle decompile ./binario     # multi-backend: Ghidra, radare2, angr, pwndbg
binoracle rop ./binario           # búsqueda de gadgets ROP + síntesis de cadenas
binoracle chain ./binario         # generación de cadena de exploit completa
binoracle hardening ./binario     # NX, PIE, RELRO, canary, Fortify, CFI, shadow stack
```

### Formatos soportados

| Formato | Backends de análisis |
|---------|---------------------|
| ELF (x86-64 / x86 / ARM / MIPS / RISC-V) | radare2, pyelftools, pwntools, angr, pwndbg |
| PE / PE+ (Windows) | pefile, LIEF, radare2 |
| Mach-O (macOS / iOS) | LIEF, radare2 |
| APK / DEX (Android) | apktool, jadx, androguard |
| Ensamblados .NET | dnlib, ILSpy |
| JavaScript / TypeScript | esprima, acorn |
| Binarios Go | go-dis stub, symbol recovery |
| Binarios Rust | LIEF + symbol demangling |
| Módulos WASM | wabt, binaryen |
| Bases de datos SQLite | sqlite3 schema + data dump |
| Bytecode EVM | pyevmasm |

---

## Servidor MCP

binoracle expone su conjunto completo de capacidades como herramientas MCP, permitiendo integración con Claude Desktop, Cursor, Zed y otros clientes compatibles con MCP.

```bash
binoracle mcp-server
```

```json
// claude_desktop_config.json
{
  "mcpServers": {
    "binoracle": {
      "command": "binoracle",
      "args": ["mcp-server"]
    }
  }
}
```

---

## Arquitectura

![Arquitectura binoracle](assets/architecture.svg)

---

## Informes

Cada investigación produce un informe HTML con:

- Resumen ejecutivo con puntuación CVSS y clasificación de severidad
- Hipótesis del LLM con la cadena de razonamiento completa
- Configuración del scaffold del laboratorio y especificación Docker Compose
- Screenshots Playwright en cada paso de verificación
- Código PoC completo (curl, Python, pwntools)
- Recomendaciones de remediación con orientación específica

---

## Comparación con REA

| Funcionalidad | binoracle | REA |
|--------------|-----------|-----|
| LLM local via Ollama | sí | no |
| CVE → laboratorio Docker → PoC verificado | sí | no |
| Screenshots Playwright como evidencia | sí | no |
| Labs WordPress / Joomla / Drupal | sí | no |
| ret2win / ret2libc / SROP | sí | sí |
| Ataques heap (tcache / fastbin / UAF / House-of-X) | sí | sí |
| Explotación format string | sí | sí |
| Síntesis de cadenas ROP | sí | sí |
| Servidor MCP (~100 herramientas) | sí | no |
| Corpus de práctica (40+ binarios) | sí | sí |
| APK / .NET / WASM / EVM | sí | parcial |
| 100% offline | sí | parcial |

---

## Instalación

```bash
pip install binoracle
```

**Desde el código fuente:**

```bash
git clone https://github.com/beafn28/binoracle
cd binoracle
pip install -e ".[all]"
```

**Conjuntos de dependencias opcionales:**

```bash
pip install binoracle[pwn]         # pwntools + ROPgadget
pip install binoracle[symbolic]    # ejecución simbólica angr
pip install binoracle[screenshots] # screenshots Playwright en informes CVE
pip install binoracle[all]         # todo lo anterior
```

---

## Configuración

```bash
# LLM local via Ollama (recomendado)
export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=http://127.0.0.1:11434/v1
export BINORACLE_MODEL=qwen2.5-coder:7b

# Idioma del informe (por defecto: es)
export BINORACLE_LANG=es
```

---

## Corpus de práctica

```bash
# Compilar el corpus (requiere Docker o gcc)
samples/build.sh

# Seguir el tutorial
binoracle triage samples/bin/ret2win
binoracle pwn samples/bin/ret2libc
# Ver docs/TUTORIAL.md para el recorrido completo
```

---

## Licencia

MIT © 2024–2025 Beatriz Fresno Naumova

---

<div align="center">

**binoracle — herramienta autónoma de investigación de seguridad**

[Docs](https://beafn28.github.io/binoracle/) · [Issues](https://github.com/beafn28/binoracle/issues)

</div>
