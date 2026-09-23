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
