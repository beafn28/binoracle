# Format-string (cheat sheet)

printf(user) sin formato de control -> el usuario controla la cadena de formato. Primitivas:
leer memoria (%p/%s) y escribir memoria arbitraria (%n). Es a la vez infoleak y arb-write.

## Cuando aplica
El binario pasa input del usuario como PRIMER argumento de una funcion printf-family
(printf/fprintf/sprintf/snprintf/vprintf/syslog) sin un "%s" fijo. En el desensamblado:
`lea rdi, [buf]` seguido de `call printf` (rdi = tu buffer, no una cadena constante).

## Encontrar el offset (donde cae tu input)
Envia un marcador + specifiers y mira en que indice N reaparece:
```
%p.%p.%p.%p.%p.%p.%p.%p        # cuenta hasta ver 0x... de tu zona
AAAAAAAA.%6$p                  # si imprime 0x4141414141414141, tu input esta en el arg 6
```
En x86-64 los 5 primeros args van en registros (rsi,rdx,rcx,r8,r9); el 6º en adelante en la
pila. El offset a "tu buffer" suele ser 6 + desplazamiento.

## Leak (lectura)
- `%N$p`  imprime el valor N de la pila -> fuga canary (acaba en 0x..00), libc (una direccion
  __libc_start_main+off en la pila), o PIE (una direccion de .text).
- `%N$s`  desreferencia: imprime la cadena apuntada por el valor N (leer memoria arbitraria si
  controlas ese valor colocando la direccion en tu propio input).
- Reconoce lo fugado: canary termina en 00 y es aleatorio; libc/PIE tienen rangos tipicos.

## Escritura con %n (arb write)
`%n` escribe en la direccion apuntada por el argumento el NUMERO de bytes impresos hasta ahi.
Variantes: %hhn (1 byte), %hn (2 bytes), %n (4). Escribes por trozos para no imprimir millones
de caracteres:
```
from pwn import *
payload = fmtstr_payload(offset, {elf.got['printf']: libc.sym['system']}, write_size='short')
```
- write_size 'short' (%hn de 2 en 2) suele ser lo mas fiable.
- IMPORTANTE: fmtstr_payload escribe solo los bytes necesarios; a mano, ordena las escrituras
  de menor a mayor conteo y usa %hhn para no pisar GOT adyacentes.

## GOT overwrite -> shell (patron tipico)
1. Fuga libc (%N$p sobre una direccion de libc en la pila) -> libc.address.
2. Sobrescribe printf@GOT (o exit@GOT, o __stack_chk_fail@GOT, o un puntero llamado despues)
   con system.
3. Si el binario luego hace printf(buf) con buf que empieza por "/bin/sh", se ejecuta
   system("/bin/sh"). O sobrescribe exit@GOT y deja que el programa llame exit.
Con Full RELRO no hay GOT escribible: apunta a __malloc_hook (glibc<2.34), a un retaddr en la
pila, o usa FSOP/exit-handlers ([[exit-handlers]], [[io-file]]).

## PIE
Resuelve la base con un leak (%N$p de una direccion de .text) y escribe en
got_addr = pie_base + got_offset. Sin leak no sabes donde escribir.

## Objetivos alternativos de escritura
- return address en la pila (si controlas su direccion): redirige el flujo a un one_gadget.
- un puntero a funcion de la aplicacion llamado despues.
- loop: si printf(buf) se ejecuta en bucle, puedes leakear y luego escribir en pasadas
  distintas (fuga primero, arb-write despues).

## FORTIFY_SOURCE (_chk)
Con _FORTIFY_SOURCE, printf pasa a __printf_chk, que PROHIBE %n cuando la cadena de formato
esta en memoria de solo lectura y exige argumentos posicionales en orden. Si tu formato esta
en memoria escribible (pila/heap) el %n aun puede funcionar; si no, solo te queda el leak.

## Gotchas
- La longitud del padding para %n depende de cuantos bytes ya imprimio el propio formato:
  fmtstr_payload lo calcula por ti; a mano, cuenta con cuidado.
- 32 vs 64 bit: en 32-bit los args estan directamente en la pila (offset mas simple).
- Evita bytes nulos en las direcciones dentro del formato (cortan la cadena): colocalos al final.
