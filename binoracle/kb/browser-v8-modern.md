# V8 moderno: pipeline JIT, sandbox y escape (cheat sheet)

El exploit de V8 de hoy no acaba en addrof/fakeobj: el **V8 sandbox** (pointer compression)
te encierra en una jaula de 4 GB, y aun te falta salir del sandbox del renderer al proceso
browser. Aqui va el flujo moderno de punta a punta. Amplia [[browser-v8]] con lo de 2023+.
Taxonomia sintetizada de yaklang/hack-skills (browser-exploitation-v8).

## Pipeline de compilacion (donde nacen los bugs)
`Ignition` (interprete + profiler) -> `Sparkplug` (baseline, >=9.1) -> `Maglev` (mid-tier,
>=10.2) -> `TurboFan` (JIT optimizador con ASUNCIONES especulativas). El bug tipico vive en
TurboFan/Maglev: una suposicion de tipo/rango que deja de ser cierta -> **type confusion** o
**bounds-check elimination**. Estructuras clave: **Map** (hidden class: forma del objeto,
element kinds), **JSArray** (map + elements ptr + length), **ArrayBuffer** (`backing_store`),
**WasmInstanceObject** (apunta a las paginas de codigo JIT).

## De la confusion de tipos a R/W (addrof/fakeobj)
- **addrof(obj)**: confunde `PACKED_ELEMENTS` <-> `PACKED_DOUBLE_ELEMENTS` -> lees la referencia
  del objeto como bits de un `double` -> te da su direccion (comprimida).
- **fakeobj(addr)**: escribe un `double` (una direccion cruda) en un array de doubles y lo lees
  como referencia -> forjas un objeto en una direccion controlada.
- **arb R/W**: con addrof+fakeobj forjas un `Float64Array` con el `backing_store` apuntando donde
  quieras -> lectura/escritura arbitraria... DENTRO de la jaula.
- Alternativa a las element-kinds: un typer bug / OOB por rango mal analizado da OOB directo.

## El V8 sandbox (pointer compression, >=11.x)
- **Cage**: region de 4 GB que contiene el heap, los backing stores de ArrayBuffer y la memoria
  WASM. Todos los HeapObject se referencian con **offsets de 32 bits** desde la base de la cage.
- Consecuencia: tu "arb R/W" con addrof/fakeobj es R/W SOLO dentro de la cage. No puedes leer
  memoria absoluta del proceso aun teniendo la primitiva.
- **External Pointer Table (EPT)**: los punteros que SI salen de la jaula (a recursos externos)
  viven en una tabla indexada. Corromper una entrada de la EPT (o el indice de un objeto) es la
  via tipica para conseguir un puntero NO comprimido -> **escape de la cage**.
- Otras vias de escape de la cage: sobrescribir el puntero de codigo de WASM, o un bug de Mojo.

## Ejecucion de codigo: WASM y W^X
1. Crea un modulo WebAssembly -> V8 lo compila JIT a una pagina de codigo.
2. `addrof` sobre el `WasmInstanceObject` -> sigue punteros hasta la pagina de codigo JIT.
3. Escribe tus bytes en esa pagina y llama a una funcion exportada -> ejecucion.
- Cuidado **W^X**: Chrome moderno pone las paginas de codigo RW->RX tras compilar. Necesitas una
  ventana de escritura (durante la compilacion) o **JIT spray** / envenenar la jump table de WASM.

## Escape del sandbox del renderer (renderer -> browser) via Mojo
Tener RCE en el renderer NO es root: el renderer esta en un sandbox de proceso. **Mojo** es la
capa de IPC de Chrome entre procesos. Cadena tipica:
1. RCE en el renderer via el bug de V8 (arb R/W + WASM).
2. Un segundo bug (UAF/type-confusion) en un handler de interfaz **Mojo**.
3. Comprometes el proceso **browser** (mas privilegiado) -> acceso al sistema.
Los full-chain reales encadenan: bug de V8 -> escape de cage -> escape de renderer (Mojo) ->
a veces LPE de kernel para salir del sandbox del SO.

## Notas de explotacion
- Fija la version exacta de Chrome/V8: los offsets de Map, los element kinds y el layout de la
  cage cambian entre versiones; un exploit es muy sensible a la build.
- Depura con un `d8` (la shell de V8) de la MISMA version: `--allow-natives-syntax` te da
  `%DebugPrint(obj)` (imprime Map y direccion) y `%SystemBreak()`.
- Verifica cada primitiva por separado (addrof con `%DebugPrint`, R/W leyendo un valor conocido)
  antes de encadenar; el exploit de V8 se construye primitiva a primitiva.

Fuente de la taxonomia: yaklang/hack-skills (skills/browser-exploitation-v8). Sintetizado como
guia; para PoCs por CVE ver colecciones como Escapingbug/awesome-browser-exploit. Ver [[browser-v8]].
