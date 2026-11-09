# Técnica: JavaScript ofuscado que despacha dinámicamente a WebAssembly

## Patrón a reconocer

Un reto web/wasm tiene JavaScript fuertemente ofuscado (literales hexadecimales, tabla de
nombres de propiedades indirecta vía un diccionario, strings codificadas) que en algún punto
hace algo como `window[NOMBRE_RESUELTO](argumentos)`, donde `NOMBRE_RESUELTO` es el resultado
de deofuscar una cadena. Intentar deofuscar el JS COMPLETO a mano es lento; normalmente basta
identificar ESE nombre concreto.

## Por qué importa

Cuando el reto embebe un módulo WebAssembly (`.wasm`) junto al JS, es muy común que el nombre
resuelto sea el de una función EXPORTADA del propio WASM, expuesta en `window` por el runtime
de Emscripten (p.ej. via `cwrap`/`ccall` o una exportación directa). Si es así, no hace falta
terminar de deofuscar todo el JS: basta identificar QUÉ exporta el `.wasm` (ver
`binoracle wasm <archivo>` para la lista de exports) y llamar esa función WASM DIRECTAMENTE,
evitando ejecutar el script ofuscado (que puede ser deliberadamente hostil o simplemente
innecesario de ejecutar).

## Cómo aplicarlo

1. Identifica el/los nombres de función que el JS ofuscado intenta resolver dinámicamente
   (buscar patrones `window[...]`, `obj[...]`, tablas de métodos indirectas).
2. Inspecciona el módulo `.wasm` acompañante (`binoracle wasm archivo.wasm`) y compara sus
   exports contra los candidatos deofuscados -- si alguno coincide (o es muy similar: Emscripten
   suele anteponer/cambiar prefijos como `_` o envolver con `cwrap`), esa es la función real.
3. Ejecuta el WASM directamente con un runtime nativo (Node.js `WebAssembly.instantiate`, o
   Python `wasmtime`) en vez de cargar el script ofuscado completo -- más seguro (no ejecuta
   código JS no confiable) y más rápido que terminar de deofuscar todo.
4. Si la función espera un string, revisa cómo Emscripten pasa strings (vía el heap lineal de
   memoria del módulo: hay que escribir los bytes en memoria y pasar el puntero, no un string
   JS directo) -- `cwrap` con el tipo `"string"` en los argumentos se encarga de esto
   automáticamente si se puede invocar a través de él.

## Caso real confirmado (CTF "flagle", DiceCTF 2022)

Un bloque de un reto tipo "Wordle" cargaba un `.wasm` y llamaba `window[GUESS](...)` desde JS
fuertemente ofuscado (`javascript-obfuscator`, literales hex, tabla de métodos indirecta).
Deofuscar hasta identificar que `GUESS` resolvía al nombre de una función real de Emscripten
(`cwrap`) permitió confirmar la hipótesis ejecutando el WASM real directamente con la API
nativa de un runtime (sin cargar el script sospechoso), obteniendo el valor esperado sin
depender de ejecutar el JS ofuscado completo.
