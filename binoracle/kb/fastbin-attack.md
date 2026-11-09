# Fastbin attack (cheat sheet)

Ataque clasico de heap contra los fastbins de glibc: chunks pequenos (hasta 0x80 en la mayoria de
builds) que se gestionan como listas simplemente enlazadas LIFO, con comprobaciones minimas. Es
el precursor directo del tcache poisoning actual ([[heap]]), y sigue aplicando en binarios/glibc
donde el tcache esta deshabilitado o el tamano objetivo cae fuera de su rango.

## Mecanica base
Cada fastbin es una lista singly-linked por `fd`. malloc() de ese tamano saca la CABEZA de la
lista sin validar que el puntero `fd` apunte a algo razonable (en glibc pre-parcheo). Un
use-after-free o un overflow que sobrescriba el `fd` de un chunk ya en el fastbin te deja elegir
la siguiente direccion que malloc() va a devolver.

```
a = malloc(0x40); free(a)          # fastbin[0x50]: a
# UAF: escribe fd de 'a' = TARGET - offset_datos
malloc(0x40)                       # devuelve 'a' de nuevo
malloc(0x40)                       # devuelve TARGET  -> control total del contenido
```

## Double-free en fastbin
La comprobacion clasica es "double free or corruption (fasttop)": glibc compara el chunk que
vas a liberar con la CABEZA actual del bin y rechaza el free si coinciden. Se evade liberando un
chunk DISTINTO entre medias (`free(a); free(b); free(a)`), de forma que cuando el segundo
free(a) llega, la cabeza ya no es 'a'. Con tcache (2.29+) hay ademas una comprobacion de `key`
por chunk que complica esto mas (ver [[heap]]).

## Requisitos del chunk falso / objetivo
El tamano leido en el campo `size` de la direccion objetivo (target - offset del campo size)
debe coincidir con el bin del que estas tirando (o pasar `malloc_consolidate`/comprobaciones
laxas segun version). Muchos writeups usan una region con datos controlados (p.ej. un buffer del
propio programa) donde puedas fabricar ese `size` falso antes de apuntar fd ahi.

## Por que sigue siendo relevante con tcache
tcache se prueba PRIMERO (LIFO, 7 chunks por bin, casi sin comprobaciones) pero solo cubre hasta
cierto tamano y cuenta maximo 7 entradas por bin; al agotarlo, las liberaciones siguientes caen
en el fastbin normal. Para tamanos grandes o cuando el reto vacia el tcache explicitamente, el
fastbin attack clasico vuelve a ser el camino.

## Deteccion (aborts de glibc)
"double free or corruption (fasttop)", "invalid fastbin entry (free)" (tamano de chunk
inconsistente con el bin), "malloc(): memory corruption (fast)".

## Ver tambien
[[heap]] (tcache, tabla general de tecnicas), [[unlink-exploitation]] (el otro ataque clasico
pre-tcache), [[heap-grooming]] (preparar el layout antes de disparar).
