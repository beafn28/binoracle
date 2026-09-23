# Exit handlers y estructuras de terminacion (cheat sheet)

Rutas de RCE que se disparan cuando el programa TERMINA (return de main, exit(), o al recibir
una senal). Muy usadas cuando no hay hooks (glibc >= 2.34) pero SI hay escritura arbitraria.

## __run_exit_handlers / __exit_funcs
`exit()` llama a `__run_exit_handlers`, que recorre la lista `__exit_funcs` (registrada por
atexit/on_exit y con `_dl_fini` por defecto). Cada entrada tiene un puntero a funcion.
- Requisito: el programa debe salir por return de main o exit() (no _exit/abort directos).
- Si controlas la lista (arb write sobre __exit_funcs o sobre una entry) puedes registrar tu
  funcion (p.ej. system) con su argumento.

## Pointer mangling / pointer guard
Los punteros de exit handlers estan CIFRADOS: `enc = rol(ptr ^ guard, 0x11)` (rotate-left 17;
al descifrar, ror 0x11 y xor guard). El `guard` esta en el TLS (`fs:0x30`).
- Para forjar una entry valida necesitas el pointer_guard.
- Truco leakless: `_dl_fini` YA esta registrado y su valor cifrado esta ahi; si conoces
  `_dl_fini` (misma libc/ld) puedes recuperar el guard:
  `guard = ror(enc_dl_fini, 0x11) ^ _dl_fini`  y con el cifrar tu propio puntero.

## .fini_array / _dl_fini
`_dl_fini` ejecuta el array `.fini_array` de cada objeto cargado. Con escritura sobre una
entrada de `.fini_array` (No/Partial RELRO -> a veces escribible) o forjando una tabla
fini_array falsa que _dl_fini recorra, consigues ejecucion al salir.

## atexit / __cxa_atexit
Destructores de C++ registrados con __cxa_atexit se guardan en la misma estructura de exit
funcs (con dso_handle). Mismo mangling; misma ruta de explotacion.

## TLS / structs relacionadas
- tls_dtor_list: destructores de variables thread_local; punteros mangled con el mismo guard.
- __call_tls_dtors los ejecuta al salir del hilo.

## Cuando usarlo
Tienes arb write pero Full RELRO (no GOT) y glibc sin hooks. Objetivos: __exit_funcs,
.fini_array, tls_dtor_list. Combina con un leak de libc/ld o con la tecnica leakless del guard.
Relacionado: FSOP ([[modern-heap]]) es la otra gran ruta "al salir/al hacer IO".
