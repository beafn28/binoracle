# Mitigaciones de explotacion (cheat sheet)

Resumen de las defensas y como se sortean. Comprueba cuales estan activas con checksec/
rabin2 -I antes de planear; la dificultad y la ruta dependen de la combinacion.

## NX (No-eXecute / DEP / W^X)
La pila y el heap no son ejecutables (W^X). Impide shellcode en la pila.
Bypass: ROP / ret2libc / ret2syscall (reutilizar codigo existente), o mprotect(RWX)+shellcode.

## Stack canary (stack protector / /GS)
Valor aleatorio entre buffers y saved RIP (`fs:0x28`); si cambia al retornar ->
__stack_chk_fail (abort). El byte bajo es 0x00.
Bypass: fugar el canary y reponerlo; overwrite que no pase por el canary; brute-force byte a
byte en fork servers; funcion sin canary. Detalle en [[canary-bypass]].

## PIE / PIC (ASLR del binario)
El binario carga en base aleatoria; codigo/GOT dependen de la base.
Bypass: fugar una direccion de .text -> pie_base = leak - offset; partial overwrite de los 12
bits bajos (fijos) para saltos cercanos. Detalle en [[pie]].

## ASLR (libc, heap, pila)
libc/heap/pila en base aleatoria (independiente de PIE).
Bypass: fugar una direccion de libc (ret2plt puts(puts@got), %s/%p en format-string) ->
libc_base = leak - libc.sym[funcion]. Ver [[ret2libc]].

## RELRO
- Partial: .got.plt (lazy) aun escribible -> GOT overwrite y ret2dlresolve posibles.
- Full (bind now): toda la GOT de solo lectura -> NO GOT overwrite ni ret2dlresolve; ve por
  hooks (glibc<2.34), FSOP/_IO_FILE, exit handlers, o un retaddr en la pila. Ver [[got-plt]].

## FORTIFY_SOURCE (_chk)
Reemplaza memcpy/strcpy/sprintf/printf/read por *_chk que validan tamanos/formato en compilacion
cuando el tamano es conocido. Reduce overflows clasicos y bloquea %n en format-string cuando el
formato esta en memoria de solo lectura (__printf_chk). No protege tamanos desconocidos en runtime.

## CET / IBT / Shadow Stack (Intel CET)
- Shadow Stack: copia protegida de las return addresses; un ROP que altere el retaddr se detecta
  al retornar. Rompe el ROP clasico donde este activo (kernels/hardware recientes).
- IBT (Indirect Branch Tracking): los saltos indirectos deben caer en un `endbr64` -> limita
  gadgets JOP/COP. Equivalente a BTI en ARM y CFG en Windows.

## CFI / CFG / BTI
Control Flow Integrity: valida que las llamadas indirectas van a destinos legitimos. CFG
(Windows), BTI (ARMv8.5), clang CFI. Fuerza a usar destinos validos o bugs que evadan la
comprobacion.

## Seccomp
Sandbox de syscalls (no es memoria): bloquea execve etc. Bypass: ORW, openat/execveat,
x32/retf-32bit. Ver [[syscalls-seccomp]].

## Heap hardening (glibc)
tcache key (2.29), safe-linking (2.32), hooks eliminados (2.34), vtable check en FILE. Ver
[[heap]] y [[modern-heap]].

## Regla de severidad
La severidad depende del IMPACTO REAL verificado, no de la etiqueta. Un overflow con
NX+PIE+canary+FullRELRO+CET es mucho mas dificil (a menudo no explotable sin un leak potente)
que uno sin mitigaciones. binoracle solo marca "verified" lo que prueba un oraculo/ejecucion.
