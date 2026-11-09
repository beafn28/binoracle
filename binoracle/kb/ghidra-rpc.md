# Ghidra headless / RPC para reversing automatizado (cheat sheet)

Conducir Ghidra por linea de comandos (o desde un agente LLM) en vez de la GUI: un demonio
carga el binario UNA vez, lo mantiene "caliente" (sin re-analisis por comando) y expone
decompiler, disasm, xrefs, tipos, parcheo y diffing devolviendo JSON estructurado. Es la via
para reversing reproducible y scriptable. Referencia: ghidra-rpc (PyGhidra + JVM de Ghidra 11+).
Complementa [[methodology]] y [[patch-diff]].

## Sesion: demonio caliente
```bash
export GHIDRA_INSTALL_DIR=/opt/ghidra_12.0
# arranca el demonio headless en background (vuelve cuando el socket responde):
ghidra-rpc start --project /tmp/work.gpr --headless --detach
export GHIDRA_RPC_PROJECT=/tmp/work.gpr
ghidra-rpc load /usr/bin/ls            # importa + auto-analiza; devuelve la clave (p.ej. /ls-a1b2c3)
ghidra-rpc list-instances              # demonios vivos (pid, project, mode)
ghidra-rpc list-binaries               # se reengancha a la sesion existente
```
Claves de diseno: el binario se analiza una sola vez y queda en memoria; CADA comando persiste
sus cambios al proyecto .gpr, asi que renombres/comentarios/tipos/parcheos siguen visibles al
abrir el proyecto en la GUI. Endpoint y ficheros de sesion se derivan de un hash de la ruta del
.gpr (un socket por proyecto, sin colisiones). En CI/sandbox, `GHIDRA_RPC_STATE_DIR` redirige
sesiones y registro global a un dir propio.

## Mapa de capacidades (que puedes pedirle)
| Area | Comandos tipicos |
|------|------------------|
| Entender codigo | `decompile` (pseudo-C), `disassemble`, `cfg`, P-code |
| Navegar | `xrefs-to` / `xrefs-from`, `strings`, `functions`, `imports`, `exports`, `search` (bytes/patrones) |
| Anotar | `rename-function`, `rename-symbol`, `set-comment`, bookmarks, tags |
| Recuperar tipos | definir struct/union/enum, retipar variables, fijar firma de funcion |
| Parchear | ensamblar instrucciones (SLEIGH), escribir bytes crudos, override de flow |
| Diff de builds | `version-track` (correladores exact-bytes/instr/symbol/ref/BSim), match por BSim |

## Reconocimiento base
```bash
ghidra-rpc metadata ls                 # arch, bits, formato, compilador
ghidra-rpc imports ls                  # dependencias/capacidades (imports peligrosos)
ghidra-rpc exports ls                  # relevante en .so/.dll
ghidra-rpc strings ls "error" --limit 20
ghidra-rpc functions ls --limit 100 --offset 0   # paginar: la respuesta trae total y count
ghidra-rpc decompile ls main --timeout 120       # empieza por main y trabaja hacia afuera
```
Tip de grafo: `xrefs-from <func> --no-stack` quita las referencias `Stack[-0x..]` y deja solo
callees reales. Tip de flujo: renombra SEGUN avanzas; renombrar una funcion mejora al instante
el decompilado de todos sus llamadores (propagacion), no lo dejes para el final.

## Flujo: auditoria de binario
```bash
ghidra-rpc load ./bin && ghidra-rpc metadata bin && ghidra-rpc imports bin
# barre strings con varios terminos: http, error, password, key, "/"
for t in http error password key /; do ghidra-rpc strings bin "$t" --limit 20; done
ghidra-rpc functions bin               # entry points, funciones nombradas, utilidades muy xref-eadas
ghidra-rpc decompile bin main          # ancla y expande por callees
```

## Flujo: investigacion de vulnerabilidades
Imports de alto riesgo (busca sus call sites y traza hacia atras hasta la fuente de entrada):

| Funcion | Riesgo |
|---------|--------|
| strcpy, strcat, gets | overflow de buffer (sin bound check) |
| sprintf, vsprintf | overflow (salida sin bound) |
| scanf/sscanf con %s | overflow (lectura de string ilimitada) |
| memcpy, memmove | overflow si el tamano es controlado por el usuario |
| system, popen, exec* | inyeccion de comando si el arg toca input |
| malloc | integer overflow si la expresion de tamano hace wrap |
| free | UAF / double-free si la gestion del puntero falla |

```bash
ghidra-rpc xrefs-to bin strcpy                     # 1) call sites del import peligroso
ghidra-rpc decompile bin <caller> --timeout 120    # 2) decompila el llamador
ghidra-rpc xrefs-to bin <caller> --no-stack        # 3) traza atras hasta recv/read/fgets/argv
ghidra-rpc set-comment bin 0x401234 \
  --comment "VULN: strcpy con datos de recv() sin validar" --type pre   # 4) anota el hallazgo
ghidra-rpc rename-function bin FUN_00401100 handle_user_input_UNSAFE
```
Idea: el bug es explotable solo si la cadena de llamadas conecta el sink (strcpy...) con una
fuente de datos externa (recv/read/argv). Ver [[integer-bugs]] y [[uaf-typeconfusion]].

## Flujo: analisis de parche (diff de versiones)
```bash
ghidra-rpc load ./bin_v1 && ghidra-rpc load ./bin_v2 && ghidra-rpc list-binaries
# Auto Version Tracking: corre varios correladores y marca lo que cambio
ghidra-rpc version-track bin_v1 bin_v2 --changed-only        # solo pares con similarity < 1.0
ghidra-rpc version-track bin_v1 bin_v2 --min-similarity 0.5  # filtra matches de baja confianza
```
La salida trae `matched` (pares con score; <1.0 = cambio), `unmatched_source` (posibles
eliminadas en v1), `unmatched_destination` (posibles anadidas en v2) y `summary` (cobertura:
changed/identical/total). Para 1-day/n-day: mira primero los `matched` con menor similarity y
decompila ambos lados para localizar el chequeo anadido. Ver [[patch-diff]].

## Flujo: APK / DEX (Android)
Ghidra trae soporte nativo de APK/DEX (procesador Dalvik + loaders Android APK/DEX/CDEX), sin
instalar extension. El decompilado sale como pseudo-Java y `decompile`/`functions`/`strings`/
`xrefs-*` funcionan igual que en nativo. Todo programa cargado reporta arch=Dalvik, bits=32.
```bash
ghidra-rpc load ./app.apk              # dex unico: carga directa
ghidra-rpc metadata app.apk            # confirma arch=Dalvik
```
Cuidado multi-dex: `load app.apk` importa SOLO el `classes.dex` primario; `classes2.dex`,
`classes3.dex`... se descartan en silencio. Para la app entera, extrae cada dex del APK (es un
ZIP) y carga cada uno como programa aparte:
```bash
unzip -l app.apk | grep '\.dex$'                    # lista los dex
mkdir -p /tmp/app-dex && cd /tmp/app-dex
unzip -o /ruta/app.apk 'classes*.dex'               # extrae todos
for d in classes*.dex; do ghidra-rpc load "/tmp/app-dex/$d"; done
```
Ver [[android-native]] para la parte nativa (.so/JNI) del mismo APK.

## Cuando usarlo
- Reversing repetible/scriptable o dirigido por un agente (JSON estructurado, no clicks).
- Binarios grandes donde re-analizar por comando seria inviable (el demonio queda caliente).
- Diffing de parches a escala (version tracking + BSim) y triaje de imports peligrosos.
- APK/DEX y nativo con el mismo juego de comandos.
Alternativas segun tarea: r2/rizin para scripting ligero ([[radare2]] si existe), IDA+idapython
para GUI interactiva. Ghidra headless brilla en decompilado + version tracking gratis y offline.
