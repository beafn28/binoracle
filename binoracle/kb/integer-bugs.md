# Integer bugs y off-by-one (cheat sheet)

Bugs que no son overflow de buffer directo pero habilitan uno o corrompen el heap.

## Integer overflow / wraparound
- `int` que envuelve: p.ej. `len + 1` con len=INT_MAX -> negativo/0; un `malloc(len*size)`
  puede envolver y reservar poco, luego se escribe mucho -> heap overflow.
- Comprobacion firmada vs uso sin signo: `if (len > MAX)` con len firmado; un len negativo
  pasa el check y luego `memcpy(dst, src, (size_t)len)` copia enorme.

## Signedness (firmado/sin signo)
- leer un tamano como `int` y usarlo como `size_t`: -1 -> 0xffffffffffffffff.
- indices negativos: `arr[idx]` con idx firmado controlado -> OOB read/write antes del buffer.

## Off-by-one
- bucle `<=` en vez de `<`: escribe 1 byte de mas. En stack puede pisar el LSB del saved RBP;
  en heap, el LSB del `size` del siguiente chunk (poison null byte -> House of Einherjar).
- null byte off-by-one: escribir un 0x00 extra que apaga el bit PREV_INUSE o reduce un size.

## Truncamiento
- guardar un valor de 64 bits en 32/16/8 bits: se pierden bytes altos; util para forzar
  tamanos pequenos o colisiones.

## Como detectarlos
- revisa toda aritmetica sobre tamanos/indices que venga de input: mult, suma, resta, cast.
- sinks: malloc/calloc/realloc/memcpy/read con un tamano calculado.
- en el binario: comparaciones `movsx`/`cdqe` (extension de signo) cerca de un tamano de
  input suelen delatar signedness.

## Explotacion
El integer bug rara vez es el final: suele DAR el overflow (stack o heap) que luego explotas
con las tecnicas normales ([[heap]], [[ret2libc]], [[rop]]).
