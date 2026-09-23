# Browser / V8 exploitation (cheat sheet)

Explotacion de motores JS (V8 de Chrome/Node). El bug suele ser type confusion / OOB en
arrays y se convierte en dos primitivas base: addrof y fakeobj, luego read/write arbitrario.

## Representacion en V8
- JSObjects almacenan punteros comprimidos (pointer compression: 32 bits bajos + heap base).
- Los float/double arrays guardan valores de 64 bits REALES (sin comprimir) -> ideales para
  leer/escribir punteros crudos.
- Un JSArray y sus Elements estan separados (tipico ~0x30); Elements a index[0] ~0x10.
- El "map" describe el tipo del objeto; cambiarlo (OOB write) hace que V8 reinterprete los
  datos (float como puntero o al reves): esa es la confusion de tipos.

## addrof(obj)  (leak de la direccion de un objeto)
1. Guarda `obj` en un array de objetos.
2. Con un OOB read desde un float array adyacente, lee ese elemento como valor de 64 bits.
3. Ese valor es el puntero (comprimido) del objeto -> tienes su direccion.

## fakeobj(addr)  (tratar una direccion como objeto)
1. Escribe `addr` en un array de objetos via OOB write desde el float array.
2. Devuelve ese elemento como si fuera un objeto legitimo: V8 acepta el puntero forjado sin
   validarlo.

## Arbitrary read/write
- Monta un fake Float64Array en memoria controlada: elem[0] = map valido de Float64Array,
  elem[1] = puntero "elements"/backing_store apuntando al target.
- Al acceder al fake array, V8 desreferencia tu backing_store -> lees/escribes donde quieras.
- RCE final: sobrescribir el codigo JIT de una funcion (RWX en versiones viejas) con
  shellcode, o usar WebAssembly (paginas RWX) para saltar a shellcode.

## Mitigaciones modernas (importante)
- Pointer compression: fakeobj queda limitado al heap de V8 (no direcciones arbitrarias de
  todo el espacio).
- V8 heap sandbox: aisla el heap y hace OBSOLETA esta tecnica clasica en versiones actuales;
  hoy se persiguen bugs que escapen del sandbox (corromper structs fuera del cage).
- Estas notas aplican sobre todo a retos CTF con versiones fijadas de V8 (d8) sin sandbox.

## Flujo CTF tipico (d8)
Compilas d8 con el parche vulnerable, reproduces la OOB en JS, construyes addrof/fakeobj,
luego arb rw, luego RWX (WASM) + shellcode. Depuras con gdb sobre d8.
