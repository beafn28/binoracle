# Use-after-free, type confusion y vtable hijack (cheat sheet)

Bugs de objetos: usar memoria liberada o tratar un objeto como un tipo distinto. Muy comunes
en programas C++ con objetos y punteros a funcion (vtables).

## Use-after-free (UAF)
- Se libera un objeto pero un puntero sigue apuntando a el (dangling). Si reasignas ese hueco
  con datos controlados (mismo tamano -> mismo tcache bin), controlas el "objeto".
- Si el objeto tiene un puntero a funcion / vtable, controlarlo da RIP al llamar un metodo.
- Patron: free(obj); malloc(same_size) con tu payload; trigger obj->method().
- En heap glibc, UAF tambien habilita tcache poisoning ([[heap]]).

## Double-free
- Liberar dos veces el mismo chunk -> corrompe la lista del bin. tcache detecta algunos con
  el "key" (glibc 2.29+), pero se evade liberando otro chunk en medio o con el tamano justo.
- Resultado: dos punteros a la misma zona (overlap) o alloc arbitrario.

## Type confusion
- El programa cree que un objeto es del tipo A pero es del tipo B (union mal usada, cast
  invalido, deserializacion). Los campos se interpretan mal -> un entero controlado se usa
  como puntero, o viceversa -> lectura/escritura o llamada arbitraria.
- Tipico en motores (JS/V8) y parsers.

## vtable hijack (C++)
- Un objeto C++ con metodos virtuales guarda un puntero a su vtable al inicio. Si sobrescribes
  el objeto (overflow/UAF) con un vptr falso que apunta a una vtable controlada, al invocar un
  metodo virtual saltas donde quieras.
- Analisis estatico: buscar `call [reg+off]` tras cargar un vptr (dispatch virtual); r2
  r2_vtables / r2_indirect ayudan a localizarlos.

## Deteccion
- sinks: free() seguido de uso del mismo puntero; ausencia de `ptr = NULL` tras free.
- objetos con function pointers / vtables + una primitiva de escritura sobre ellos.
- valgrind / ASAN delatan UAF y double-free en dinamico.
