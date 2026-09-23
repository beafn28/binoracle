# Browser / V8 exploitation (cheat sheet)

Explotacion de motores JS (V8 de Chrome/Node). El bug suele ser type confusion / OOB en
arrays y se convierte en dos primitivas base: addrof y fakeobj, luego read/write arbitrario.

## Representacion en V8
- JSObjects almacenan punteros comprimidos (pointer compression: 32 bits bajos + heap base).
- Los float/double arrays guardan valores de 64 bits REALES (sin comprimir) -> ideales para
  leer/escribir punteros crudos.
- SMI (Small Integer): enteros pequenos van etiquetados (shift). Los doubles se guardan tal cual.
- Un JSArray y sus Elements estan separados (tipico ~0x30); Elements a index[0] ~0x10.
- El "map" (Hidden Class) describe el tipo/estructura del objeto; cambiarlo o confundir el
  ElementsKind (PACKED_DOUBLE vs PACKED) hace que V8 reinterprete los datos (float como puntero
  o al reves): esa es la confusion de tipos.

## Encoding de doubles <-> bits
```
function ftoi(f){ buf.setFloat64(0,f); return buf.getBigUint64(0); }
function itof(i){ buf.setBigUint64(0,i); return buf.getFloat64(0); }
var buf = new DataView(new ArrayBuffer(8));
```

## addrof(obj)  (leak de la direccion de un objeto)
1. Guarda `obj` en un array de objetos (o en un slot cuyo tipo puedas confundir).
2. Con la OOB/confusion, lee ese slot como un float/double.
3. ftoi(ese double) = puntero (comprimido) del objeto -> su direccion.

## fakeobj(addr)  (tratar una direccion como objeto)
1. Escribe itof(addr) en un slot que V8 tratara como objeto.
2. Al leerlo como objeto, V8 acepta el puntero forjado sin validarlo -> objeto en direccion
   controlada.

## Arbitrary read/write
- Monta un fake Float64Array/JSArrayBuffer en memoria controlada: pon un map valido de
  Float64Array y un `elements`/`backing_store` apuntando al target.
- fakeobj(direccion_de_ese_fake) -> leer/escribir su [0] lee/escribe en target.
- Patron clasico "OOB -> addrof/fakeobj -> fake typed array -> arb rw".

## RCE final
- Versiones viejas: sobrescribir el codigo JIT (RWX) de una funcion optimizada con shellcode.
- WebAssembly: instanciar un modulo WASM crea una pagina RWX; sobrescribe su codigo con
  shellcode y llama a la funcion exportada. Ruta favorita en CTF.
- Con arb rw + un leak de una direccion de codigo, saltar a shellcode escrito en la pagina WASM.

## Mitigaciones modernas (importante)
- Pointer compression: fakeobj queda limitado al heap de V8 (cage de 4GB), no a todo el espacio.
- V8 heap sandbox (external pointer table, sandboxed pointers): aisla el heap y hace OBSOLETA la
  tecnica clasica en versiones actuales; hoy se persiguen bugs que ESCAPEN del sandbox
  (corromper structs/tablas fuera del cage, o el JIT).
- CFI/BTI en el binario del navegador.
- Estas notas aplican sobre todo a retos CTF con versiones fijadas de V8 (d8) sin sandbox.

## Flujo CTF tipico (d8)
1. Te dan un diff/parche que introduce la OOB (p.ej. un metodo que no valida length).
2. Compilas d8 con el parche (o te lo dan). Reproduces la OOB en JS.
3. Construyes addrof/fakeobj a partir de la OOB.
4. Fake typed array -> arb read/write.
5. WASM RWX -> escribes shellcode -> lo llamas. Depuras con gdb sobre d8 (`job`, `x/...`).
- Fuentes: ir0nstone oob-v8, faith *CTF oob-v8, Project Zero.
