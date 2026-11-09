# House of Orange (cheat sheet)

Tecnica de heap pensada para binarios donde NO hay `free()` disponible (o no da ventaja): abusa
del `top chunk` (el chunk al final del heap, del que malloc() recorta cuando ninguna otra lista
tiene un chunk que sirva) para forzar su liberacion indirecta y encadenar hacia una corrupcion de
la estructura `_IO_FILE` de stdout (unsorted bin attack + FSOP).

## Paso 1: reducir el top chunk
Si haces un malloc() mas grande que el tamano actual del top chunk, glibc lo extiende con
`sbrk`/`mmap` -- pero si PRIMERO reduces el campo `size` del top chunk (via un overflow del
chunk anterior que llega hasta ahi), una peticion algo mayor que ese size reducido hace que
glibc trate el top chunk como si estuviera libre y lo meta en el UNSORTED BIN, en vez de
extenderlo. Asi consigues un chunk "libre" en el unsorted bin sin haber llamado a free() nunca.

## Paso 2: unsorted bin attack
Con el (antiguo) top chunk ahora en el unsorted bin, su `bk` apunta a una zona que controlas si
fabricaste el chunk falso con cuidado. La siguiente vez que se procesa el unsorted bin (por
ejemplo, otro malloc), glibc escribe `main_arena` (o un puntero interno) en `bk->fd`+offset --
un primitivo de escritura de un puntero de libc en una direccion elegida, util para apuntar hacia
la estructura de `stdout`.

## Paso 3: FSOP (File Stream Oriented Programming) sobre stdout
Con esa escritura, se fabrica una `_IO_FILE_plus` de `stdout` falsa cuyos punteros de vtable
apuntan a codigo controlado (o a `system`), de forma que la SIGUIENTE operacion sobre stdout
(un simple `printf`/`exit`, que internamente hace flush) dispara la ejecucion. Esta ultima parte
es la misma familia de tecnica que House of Apple/Cat en glibc moderna (ver [[io-file]] y
[[modern-heap]] para el detalle de la estructura `_IO_FILE` y sus comprobaciones actuales).

## Requisitos
- Un overflow que llegue a modificar el `size` del top chunk (heap overflow lineal tipico).
- Poder disparar al menos una o dos llamadas malloc() adicionales tras la corrupcion.
- Sin necesidad de `free()` en absoluto: por eso es la tecnica de referencia cuando el reto solo
  da `malloc`/`edit`/`print`, sin opcion de liberar memoria.

## Ver tambien
[[io-file]] (estructura FILE y sus comprobaciones), [[heap]] (unsorted bin, vision general),
[[modern-heap]] (variantes FSOP en glibc reciente).
