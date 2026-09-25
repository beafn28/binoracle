# Ghidra MCP para reversing dirigido por agente (cheat sheet)

Servidor que expone el decompilador y el motor de analisis de Ghidra por HTTP para que un agente
LLM (o binoracle) lo conduzca sin la GUI: el plugin GhidraMCP abre endpoints en
`127.0.0.1:8089` y devuelve JSON estructurado (pseudo-C, xrefs, P-code, grafos, tipos, emulacion).
Complementa [[ghidra-rpc]], [[reversing-workflow]] y [[methodology]]. binoracle lo usa como fuente
de decompilacion PREFERENTE cuando el servidor esta arriba, con fallback a r2 (`pdg`/`pdc`).

## Cuando usarlo
- El pseudo-C de Ghidra suele ser mas legible y correcto que `pdg`/`pdc` de r2 en binarios grandes,
  C++ con vtables, o con tipos/estructuras recuperados.
- Analisis de flujo de datos por P-code, grafo de llamadas, y emulacion de P-code de una funcion
  sin ejecutarla (util para resolver constantes/comprobaciones sin sandbox).
- Requiere Ghidra ABIERTO con el plugin y el binario cargado (el servidor solo vive con el programa
  cargado). Version del plugin y de Ghidra deben casar (extensiones sensibles a version).

## Endpoints clave (lectura, para entender el binario)
| Objetivo | Endpoint |
|----------|----------|
| Decompilar una funcion (o varias) | `/decompile_function?address=<nombre|0xADDR>&timeout=60` (o `functions=a,b,c`) |
| Desensamblar | `/disassemble_function` |
| Localizar/navegar | `/get_function_by_address`, `/get_function_count`, `/search_functions` |
| Referencias cruzadas | `/get_bulk_xrefs`, `/get_function_callers`, `/get_function_callees` |
| Grafos y flujo | `/get_function_call_graph`, `/analyze_control_flow`, `/analyze_dataflow`, `/get_function_pcode` |
| Variables y firma | `/get_function_variables`, `/get_function_signature`, `/get_function_labels` |
| Saltos | `/get_function_jump_targets` |
| Salud/conexion | `/check_connection` (comprobar antes de usar; 200 = servidor vivo con programa cargado) |

Las peticiones son GET con query params (o POST JSON si hay cuerpo). La respuesta es JSON: el
pseudo-C viene en un campo tipo `decompilation`/`code`. Direcciones: `0x<hex>`; en programas con
varios espacios, prefijo `espacio:0xADDR` (p.ej. `mem:0x1000`).

## Escritura (anotar; util para documentar, no para el analisis inicial)
Renombrar (`/rename_function`, componentes), tipos y estructuras (`/create_struct`, `/apply_data_type`,
`/create_enum`), comentarios en lote (`/batch_set_comments`), tags. Cambios atomicos y por lotes
(reduce llamadas API). Convenciones (PascalCase con verbo, notacion hungara por tipo) se aplican en
la capa de herramienta (auto-fix / warn / reject) para salida consistente entre sesiones.

## Capacidades avanzadas
- Emulacion de P-code de una funcion (`/emulate_function`): entender convencion de llamada y
  resolver valores sin ejecutar el binario.
- Debugger en vivo integrado y analisis de flujo de datos por grafo de P-code.
- Transferencia de documentacion entre versiones del binario por hash SHA-256 de funcion
  (`/get_function_hash`, `/get_bulk_function_hashes`, `find_similar_functions`): documentar una vez,
  propagar a otras builds. Encaja con [[patch-diff]] para bindiffing.

## Integracion en binoracle
- Oraculo cliente opcional (`oracles/ghidra.py`): `available()` sondea `/check_connection`;
  `decompile_function(name)` trae el pseudo-C. Config con `BINORACLE_GHIDRA_URL`
  (default `http://127.0.0.1:8089`).
- La decompilacion aumentada (`decompile_explain`) usa Ghidra si esta disponible y cae a r2 si no,
  marcando el engine (`ghidra` vs `pdg`/`pdc`/`pdf`) en el informe. Todo grounded: el pseudo-C es la
  salida real del decompilador; el LLM solo lo anota, no inventa.

## Setup del servidor (fuera de binoracle)
1. Instalar Ghidra (version que case con el plugin) y construir/instalar la extension GhidraMCP.
2. Abrir Ghidra (GUI o headless) con el binario importado y auto-analizado.
3. Activar el servidor del plugin (escucha en 8089). Comprobar con `/check_connection`.
Si el 8089 no responde: el plugin no esta instalado/activo, hay desajuste de version, o no hay
binario cargado. binoracle sigue funcionando por fallback a r2 mientras tanto.
