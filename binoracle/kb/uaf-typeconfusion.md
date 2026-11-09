# Use-after-free, type confusion y vtable hijack (cheat sheet)

Bugs de objetos: usar memoria liberada o tratar un objeto como un tipo distinto. Muy comunes
en programas C++ con objetos y punteros a funcion (vtables) y en menus de heap de CTF.

## Use-after-free (UAF)
Se libera un objeto pero un puntero sigue apuntando a el (dangling). Si reasignas ese hueco con
datos controlados (MISMO tamano -> mismo tcache bin), controlas el "objeto".
- Patron: crear(obj); free(obj); crear(otro_del_mismo_size) con tu payload; usar(obj->campo).
- Si el objeto tiene un puntero a funcion / vtable, controlarlo da RIP al invocar un metodo.
- Un UAF de LECTURA (usar tras free sin reescribir) puede filtrar punteros de heap/libc que
  quedaron en fd/bk del chunk liberado.
- En glibc, un UAF sobre un chunk en tcache = poder editar su fd = tcache poisoning ([[heap]]).

Ejemplo (menu tipico add/free/edit/show):
```
add(0, 0x20)          # chunk A
free(0)               # A -> tcache, fd/bk apuntan a arena/A
show(0)               # UAF read: leak de heap/libc
edit(0, p64(target))  # UAF write: envenena fd de A
add(1, 0x20)          # saca A
add(2, 0x20)          # devuelve 'target' -> arbitrary alloc
```

## Double-free
Liberar dos veces el mismo chunk -> corrompe la lista del bin. tcache detecta algunos con el
"key" (glibc 2.29+); se evade liberando OTRO chunk en medio (free A; free B; free A) o usando
fastbin. Resultado: dos punteros a la misma zona (overlap) o alloc arbitrario. Ver [[heap]].

## Type confusion
El programa cree que un objeto es del tipo A pero es del tipo B (union mal usada, cast
invalido, deserializacion, indice de tipo controlado). Los campos se interpretan mal:
- un entero controlado se usa como puntero -> arb read/write.
- un puntero se expone como entero -> infoleak.
Es la base de la explotacion de motores (V8: confusion de ElementsKind, ver [[browser-v8]]) y
de muchos parsers/deserializadores.

## vtable hijack (C++)
Un objeto C++ con metodos virtuales guarda al inicio un puntero a su vtable (vptr). Si
sobrescribes el objeto (overflow/UAF) con un vptr falso que apunta a una vtable controlada, al
invocar un metodo virtual `call [vptr + idx*8]` saltas donde quieras.
- Monta una fake vtable en memoria conocida con la direccion de system/one_gadget en el slot
  del metodo que se llamara, y pon el objeto->vptr apuntando a ella.
- Si controlas rdi (this = el propio objeto), pon "/bin/sh" al inicio del objeto y system en el
  slot -> system(this) = system("/bin/sh").

## Deteccion (estatica y dinamica)
- sinks: free(p) seguido de uso de p; ausencia de `p = NULL` tras free; punteros compartidos.
- objetos con function pointers / vtables + una primitiva de escritura sobre ellos:
  r2_vtables / r2_indirect localizan los `call [reg+off]` de dispatch virtual.
- dinamico: ASan (heap-use-after-free, double-free) y valgrind lo delatan al instante.
- binoracle: try_heap confirma double-free/corrupcion por el abort de glibc.

## Explotacion (resumen del flujo)
1. Consigue el UAF/confusion y su tamano exacto de objeto.
2. Groom del heap para reclamar el hueco de forma fiable ([[heap-grooming]]).
3. Reclama con un objeto controlado (o con datos crudos si el menu tiene edit).
4. Convierte a arb read/write o a control de un puntero a funcion/vtable.
5. Leak (libc/heap) -> objetivo final (system, one_gadget, FSOP, exit-handlers).
