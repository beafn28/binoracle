# Mitigaciones de explotacion (cheat sheet)

## NX (No-eXecute / DEP / W^X)
La pila y el heap no son ejecutables. Impide shellcode en la pila. Bypass: ROP / ret2libc /
ret2syscall (reutilizar codigo existente).

## Stack canary (stack protector)
Valor aleatorio entre buffers y saved RIP; si cambia al retornar -> __stack_chk_fail (abort).
Bypass: fugar el canary (format-string, OOB read) y reponerlo en el payload; o overwrite que
no pase por el canary; brute-force byte a byte en fork servers.

## PIE / PIC (ASLR del binario)
El binario carga en base aleatoria; las direcciones de codigo/GOT dependen de la base.
Bypass: fugar una direccion de codigo del propio binario -> pie_base = leak - offset conocido.
Partial overwrite de los 12 bits bajos (no aleatorizados) para saltos cercanos.

## ASLR (libc)
libc en base aleatoria. Bypass: fugar una direccion de libc (puts@GOT via puts, %s en
format-string, ret2plt puts(puts@got)) -> libc_base = leak - libc.sym[funcion].

## RELRO
Partial: GOT parcialmente protegido, .got.plt aun escribible (GOT overwrite posible).
Full: GOT de solo lectura tras el arranque (bind now) -> no GOT overwrite; usar hooks (viejo)
o FSOP / __malloc_hook (glibc<2.34) / apuntar a otra estructura.

## FORTIFY_SOURCE (_chk)
Reemplaza memcpy/strcpy/sprintf/printf por versiones *_chk que validan tamanos/formato.
Reduce overflows clasicos y %n en format-string con formato en memoria de solo lectura.

## Reglas
- La severidad depende del impacto real verificado, no de la etiqueta. Un overflow con NX+PIE
  +canary+FullRELRO es mucho mas dificil que sin mitigaciones.
