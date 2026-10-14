# binoracle — documento maestro (todo, en un sitio)

Referencia única y completa de binoracle: qué es, qué sabe leer, qué sabe explotar (y cómo lo
**verifica de verdad**), todas sus herramientas, la CLI, la suite de tests, las plataformas y cómo
arrancarlo. Si solo quieres levantarlo, ve a [`docs/USAGE.md`](USAGE.md); si quieres el detalle
interno del motor, a [`docs/ENGINE.md`](ENGINE.md). Este fichero es el índice que lo ata todo.

> **Regla de oro (grounding).** binoracle no marca nada como `verified` sin haber **popeado una
> shell real** en un sandbox. Todo informe lleva evidencia y, cuando algo no se puede comprobar,
> **degrada con honestidad** (`NOT_VERIFIED` / `NOT_APPLICABLE` + `limitations`), nunca finge.
> Es **local y offline**: nada sale del host. Los lectores estáticos **nunca ejecutan** el objetivo;
> la ejecución vive en módulos de runtime separados y en sandbox. Todo dato subido/externo es
> **no confiable**.

---

## 1. Qué es binoracle

Una herramienta de ingeniería inversa + desarrollo de exploits **fundamentada en oráculos**
(oracle-grounded): combina lectores estáticos deterministas con un motor de explotación
**verificado por ejecución**. El objetivo del proyecto es **igualar y superar a REA** (morluto/rea)
y, además, tener el motor de exploits reproducible más amplio posible en x86-64 / x86-32 (y
aarch64 donde el entorno lo permite).

Tres planos, bien separados:

1. **Lectores estáticos** — identifican el formato y extraen hechos sin ejecutar nada.
2. **Análisis / arsenal** — chain-analyzer, gadgets ROP, primitivas, superficie de ataque.
3. **Motor de exploits** — reproduce cada familia en un binario y **confirma con shell real**.

Encima, una capa de **paridad REA** (consulta nativa con estado, reconstrucción .NET/Android/JS) y
tres interfaces: **CLI**, **servidor MCP** (~100 herramientas) y **UI web**.

---

## 2. Lectores estáticos (reversea "cualquier cosa")

`binoracle identify <fichero>` detecta el formato y enruta al lector adecuado. Formatos cubiertos:

| Área | Formatos / lectores |
|---|---|
| **Nativo** | ELF, Mach-O, PE/COFF, Go, WebAssembly (`.wasm` → WAT), core dumps |
| **Móvil** | APK (manifest, DEX/ABIs/firma), AndroidManifest (apktool), DEX→Java (jadx) |
| **Flutter/Dart** | snapshot AOT (`f5f5dcdc`, hash, features), engine `libflutter.so`, `flutter_assets`, `AssetManifest.bin` (StandardMessageCodec) |
| **Managed** | .NET/CLI (metadata `#~`, tablas ECMA-335, tokens, CIL) |
| **Web / JS** | bundles JS, source recovery, imports de módulos, `.asar` (Electron), HAR, descubrimiento WebMCP |
| **Datos / otros** | SQLite, EVM bytecode, `.jar`/`.class`, plist (bin/xml), firmware, escaneo de secretos/IOCs |

---

## 3. Motor de exploits (familias y estado de verificación)

Cada familia tiene su sample en `samples/src/*.c` (compilado por `samples/build.sh`) y un flujo
`autoX` que intenta la técnica y marca `verified: true` **solo si popea shell**. Cuando la glibc
moderna bloquea la técnica original, se reproduce in-binary; algunas se comprueban sobre glibc 2.39
real. Las que requieren una plataforma ausente (p.ej. aarch64 sin toolchain/qemu) **degradan con
honestidad**, nunca dan un falso positivo.

### Stack / ROP / control de flujo
| Familia | Módulo | Notas |
|---|---|---|
| ret2win | `autopwn` / chain | desvío directo a `win()` |
| ret2libc | `autolibc` | fuga libc + `system("/bin/sh")` |
| ret2csu | `autocsu` | `__libc_csu_init` para rellenar argumentos |
| SROP x86-64 | `autosrop` | `sigreturn` frame → `execve` |
| SROP aarch64 | `autosrop_aarch64` | rt_sigreturn=139, execve=221; degrada si no hay aarch64 |
| ret2dlresolve x64 | `autodlresolve` | `Elf64_Rela` forjada |
| ret2dlresolve 32-bit | `autodlresolve` | `Elf32_Rel`, cdecl, offset 76 |
| format string (GOT) | `autofmt` | sobrescribe GOT, confirma con `uid=` |
| canary leak/bypass | `autocanary` | fuga + reconstrucción |
| PIE defeat | `autopie` | fuga de base + rebase |
| stack pivot | `autopivot` | pivot a área controlada |
| one_gadget | `autolibc` (`og_only`) | barrido de restricciones; usa la gema `one_gadget` si está |
| shellcode | `shellcode` | NX off / RWX |

### Heap (glibc)
| Familia | Módulo |
|---|---|
| tcache poison / dup | `autotcachedup` |
| use-after-free | `autouaf` |
| write-what-where | `autowow` |
| house of force | `autohof` |
| house of spirit | `autohos` |
| house of einherjar | `autohoe` |
| house of botcake | `autobotcake` |
| largebin attack | `autolargebin` |
| tcache stashing unlink | `autostash` |
| house of corrosion | `autohoc` |
| unsafe unlink | `autounsafeunlink` |
| fastbin dup | `autofastbindup` |
| House of Mind | `autohomind` |
| IO_FILE / FSOP | `autoiofile` |

Todas las familias de heap están **integradas en el chain-analyzer**: `analyze_chains` emite una
`ExploitChain` por familia aplicable (detectada vía símbolos del ELF) y `_verify_chain` la despacha
al verificador `autoX` correspondiente, de modo que el grafo de cadenas refleja lo que de verdad
popea shell.

### Orquestación
`autopwn` (combina y verifica en sandbox), `audit` (auditoría + explotación autónoma con LLM local),
`autopoc`, `autofuzz`, `regress` (regresión), más primitivas, CSU/pivot/arsenal ROP.

---

## 4. Paridad REA (igualar y superar)

| Categoría | Capacidades | Módulos |
|---|---|---|
| **A. Estático nativo a nivel función** | analyze_function, call-graph, xrefs, address↔name, call-path, inspect_native_api, binary_overview, trace_feature; **sesión nativa con estado** (open/inspect/session/close/list) | `nativequery`, `nativesession`, `nativeconnect` (ida/hopper), `jebconnect` |
| **B. Reconstrucción managed** | metadata → **grafo de tipos por token**, call-graph CIL, comparación de miembros, verificación de frontera managed/nativo | `managedquery`, `dotnetgraph`, `dotnetinspect` |
| **C. Android** | clase/método, paquete, búsqueda de clases, refs, **grafo de app móvil**, recursos | `androidquery`, `androidmanifest`, `apkinspect` |
| **D. JS / web** | recover sources, analyze bundle, trace imports, descubrir herramientas WebMCP | `jsinspect` |
| **E. Orquestación / cross-cutting** | correlate estático↔runtime, find_changed_behavior, trace_feature, captura de procesos, evidence bundles, ledger | `proccapture`, `ledger`, `correlate` (en `nativequery`/MCP) |

---

## 5. Interfaces

### CLI
Subcomandos disponibles (`binoracle <cmd> --help`):

```
doctor cveplan triage hunt ask chat report primitives gadgets arsenal cyclic
exploit-skeleton explain diff verify view rop shellcode fuzz fmtstring analyze
serve mcp go core elf wasm sqlite evm har java secrets asar plist dotnet macho
apk pe jeb js dynamic caller-tool identify autopoc autopwn audit regress tools
rag kb learn heap train dataset autofuzz fetch investigate
```

### Servidor MCP
`binoracle mcp` — JSON-RPC por stdio, **~100 herramientas** para clientes MCP (Claude, Cursor…):
inspección (`inspect_apk`, `inspect_flutter`, `inspect_dotnet_assembly`, `inspect_elf`…),
exploits (`autopwn`, `analyze_chains`, `one_gadget`, `rop_arsenal`…), consulta nativa
(`analyze_function`, `get_call_graph`, `open_binary`…), managed/android/js, dinámico
(`dynamic_frida`, `dynamic_adb`, `dynamic_browser`) y evidencia (`record_evidence`,
`export_evidence_bundle`).

### UI web
`binoracle serve` (por defecto `http://127.0.0.1:8080`). API: `POST /api/run` con
`{"command","binary","options"}`. Enruta identify/apk/elf/macho/pe/go/wasm/sqlite/evm/dotnet/js/
plist/asar/har/java/flutter/firmware/secrets + triage/analyze/arsenal.

---

## 6. Verificación y tests

Suite offline en `tests/` (auto-salta lo que no aplica a la plataforma):

| Fichero | Qué cubre |
|---|---|
| `test_smoke.py` | lectores + todas las familias de exploits + grafo de cadenas de heap |
| `test_tools_and_config.py` | herramientas MCP, CLI, config, routing |
| `test_autoheap.py` | familias de heap aisladas |
| `test_sandbox.py` | el `run_driver` / sandbox |
| `test_rag.py`, `test_trainer.py` | RAG local y dataset/trainer |

Ejecutar todo: `pytest tests/ -v`. Una familia: `pytest tests/test_smoke.py -k fastbindup -v`.

---

## 7. Plataformas

| Plataforma | Lectores estáticos | Verificación de exploits (ejecución) |
|---|---|---|
| **Linux x86-64** (referencia) | ✅ | ✅ todo (x86-64 / x86-32) |
| **Windows + WSL2** (x86-64) | ✅ | ✅ igual que Linux |
| **Mac M1 + Docker `linux/amd64`** | ✅ | ✅ x86 por emulación (más lento) |
| **Mac M1 nativo / VM ARM64** | ✅ | ⚠️ solo aarch64 nativo |
| **Windows / macOS nativos** | ✅ | ❌ (sin ELF/`/proc`/glibc/`unshare`) |

Lo único imprescindible para los exploits es un **kernel Linux** debajo. Por eso la vía recomendada
en Mac/Windows es **Docker** (ver `docs/USAGE.md`).

---

## 8. Arranque rápido

```bash
# Docker (recomendado en Mac/Windows): trae Linux x86-64 dentro
docker compose up --build            # web en http://127.0.0.1:8080
cp tu-app.apk targets/ && docker compose run --rm binoracle binoracle apk /targets/tu-app.apk

# Nativo (Linux x86-64)
pip install -e . && bash samples/build.sh
pytest tests/test_smoke.py -v
binoracle serve
```

Detalle completo de instalación, análisis de APK, verificación de exploits, MCP y web:
**[`docs/USAGE.md`](USAGE.md)**. Interior del motor: **[`docs/ENGINE.md`](ENGINE.md)**.
