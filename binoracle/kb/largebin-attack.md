# Largebin attack (cheat sheet)

Ataque de heap que abusa de los punteros auxiliares `fd_nextsize`/`bk_nextsize` de los large
chunks (los que ya no caben en small/tcache/fastbin) para conseguir una escritura arbitraria de
un puntero grande (normalmente la direccion de otro chunk) sobre una posicion controlada por el
atacante. Mas complejo de montar que un fastbin/tcache attack, pero sigue siendo viable en glibc
moderna porque estos campos reciben MUCHAS menos comprobaciones que fd/bk normales.

## Por que existen fd_nextsize/bk_nextsize
Los large bins mantienen los chunks ordenados por tamano. Para no recorrer chunk a chunk buscando
el primer tamano distinto, cada chunk de tamano "cabeza de grupo" (el primero de su tamano en el
bin) enlaza directamente con el siguiente/anterior TAMANO distinto via estos dos punteros
extra -- son una optimizacion de busqueda, no metadatos de contabilidad como fd/bk.

## Mecanica del ataque
Cuando un chunk nuevo entra en el large bin y hay que insertarlo en la posicion correcta, glibc
escribe a traves de `fd_nextsize`/`bk_nextsize` del chunk vecino sin validarlos tanto como fd/bk.
Si controlas esos campos de un chunk ya en el bin (via overflow o UAF), el proceso de insercion
te da una escritura estilo unlink: `victim->fd_nextsize->bk_nextsize = victim` (o variantes segun
la version), con `victim` bajo tu control -> escribes una direccion elegida en un offset elegido.

## Variantes conocidas
- **Largebin attack "clasico"**: corromper fd_nextsize de un chunk existente en el bin para que,
  al insertar el siguiente chunk del mismo tamano, se escriba donde quieras.
- **Version que evita el chequeo de tamano**: preparar DOS chunks del mismo tamano exacto en el
  bin (glibc entonces no toca fd_nextsize/bk_nextsize del chunk insertado, solo su fd/bk
  normales) para colarse en la lista sin disparar la validacion mas estricta que se anadio en
  glibc recientes sobre los punteros nextsize.

## Requisitos
1. Al menos un chunk grande (large bin) ya libre y en el bin, con fd_nextsize/bk_nextsize
   sobre-escribibles (via un chunk adyacente con overflow, o UAF).
2. Provocar la insercion de un chunk NUEVO del mismo tamano (o de un tamano que dispare la
   comparacion) para que el proceso de insercion ejecute la escritura corrompida.
3. Idealmente, un leak de heap/libc previo para calcular offsets objetivo con precision.

## Deteccion
"malloc(): unsorted double linked list corrupted" y variantes especificas de large bin
("malloc(): corrupted unsorted chunks", segun version) cuando la comprobacion de consistencia
falla al recorrer el bin.

## Ver tambien
[[heap]] (vision general), [[unlink-exploitation]] (mismo principio, aplicado a la lista
doblemente enlazada normal en vez de a nextsize).
