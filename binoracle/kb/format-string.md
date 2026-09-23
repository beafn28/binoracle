# Format-string (cheat sheet)

printf(user) sin formato -> el usuario controla el formato. Primitivas: leer (%p/%s) y
escribir (%n) memoria arbitraria.

## Encontrar el offset
Enviar "AAAAAAAA.%p.%p.%p..." y ver en que indice N aparece 0x4141414141414141 -> tu input
esta en el argumento N. Alternativa: "%N$p".

## Leak
`%N$p` lee el argumento N (fugar libc/canary/PIE de la pila). `%N$s` desreferencia (leer una
cadena en una direccion controlada).

## Escritura (GOT overwrite -> shell)
Sobrescribir printf@GOT (o exit@GOT, o un puntero llamado despues) con system. Luego si el
binario hace printf(buf) con buf="/bin/sh", se ejecuta system("/bin/sh").
pwntools automatiza los %n: `fmtstr_payload(offset, {got_addr: system})`.
IMPORTANTE: escribe solo los bytes necesarios; no rellenes con ceros o corromperas las GOT
adyacentes.

## PIE
Resolver la base (leak) y escribir en got_addr = pie_base + got_offset.

## FORTIFY
_chk bloquea %n si el formato esta en memoria de solo lectura (%n en formato writable ok).
