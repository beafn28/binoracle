# PIE, ASLR y leaks (cheat sheet)

PIE (Position Independent Executable): el binario se carga en una base ALEATORIA cada
ejecucion. Las paginas se alinean a 0x1000, asi que los 12 bits BAJOS de cualquier direccion
son fijos (los conoces del binario en disco); solo la parte alta se aleatoriza. ASLR hace lo
mismo con libc, heap y pila. Sin un leak no sabes donde esta nada.

## Que aleatoriza que
- PIE: la base del propio binario (.text/.got/.data). Necesitas un leak de UNA direccion de
  .text (o de la GOT) del binario.
- ASLR libc: la base de libc. Necesitas un leak de UNA direccion de libc (ver [[ret2libc]]).
- Son INDEPENDIENTES: fugar libc no te da la base PIE y viceversa.

## Resolver la base
```
pie_base = leaked_code_addr - known_offset
```
known_offset = la direccion del simbolo/gadget EN EL ELF EN DISCO (readelf -s, nm, objdump).
Luego cualquier direccion = pie_base + offset_del_simbolo.

## Fuentes de leak (PIE)
- format-string: `%N$p` sobre un valor de la pila que apunte a .text (una saved return address
  del propio binario suele estar en la pila; identifica el rango 0x55.../0x56...).
- uninitialized read / overflow que deje visible una direccion de codigo al imprimir.
- un puntero a funcion del binario guardado en una estructura que puedas leer.
- OJO: `puts(puts@GOT)` (ret2plt) revela LIBC, no PIE. Para PIE necesitas una direccion de
  .text del propio binario.

## Partial overwrite (sin leak)
Los 12 bits bajos NO cambian con ASLR. Sobrescribe solo 1-2 bytes de un puntero de retorno del
binario para saltar a una direccion CERCANA (misma pagina) sin conocer la base. Si el destino
esta a mas de 0x1000, hay que adivinar 1 nibble (4 bits) -> 1/16 de exito por intento (util con
fork/reintentos). Escribe con %hhn (1 byte) o %hn (2 bytes).

## Con fork server
Como con el canary, si hay fork la base PIE es la misma entre hijos -> brute-force byte a byte
de los bytes altos, o partial overwrite fiable.

## PoC deterministico (solo local)
Con ASLR desactivado (setarch -R, personality ADDR_NO_RANDOMIZE, o `echo 0 >
/proc/sys/kernel/randomize_va_space`), la base PIE tipica de Linux x86-64 es 0x555555554000 y
libc/pila quedan fijas. Util para reproducir un PoC en sandbox; NUNCA asumas esto en el target
real (ahi hay ASLR).

## Flujo tipico
1. Fuga una direccion de .text -> resuelve pie_base -> ya conoces win/gadgets/GOT del binario.
2. Si ademas necesitas libc: fuga una direccion de libc (ret2plt puts, o %N$p de una direccion
   de libc en la pila) -> resuelve libc.address.
3. Construye el exploit con las direcciones ya resueltas.
