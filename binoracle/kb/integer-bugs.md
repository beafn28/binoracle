# Integer bugs y off-by-one (cheat sheet)

Bugs de aritmetica entera que no son overflow de buffer directo pero HABILITAN uno o corrompen
el heap. Casi nunca son el final: dan la primitiva (overflow/OOB) que luego explotas normal.

## Integer overflow / wraparound
Un entero supera su rango y "envuelve".
```
int n = read_int();          // atacante controla n
char *p = malloc(n * 8);     // n=0x20000001 -> n*8 envuelve a 8 en 32-bit -> reserva minima
for (i=0;i<n;i++) p[i]=...   // escribe muchisimo -> heap overflow
```
- `len + 1` con len=INT_MAX -> INT_MIN/negativo.
- `a * b` de tamanos controlados que envuelve -> malloc pequeno + copia grande.

## Signedness (firmado vs sin signo)
El clasico: se valida como firmado y se usa como sin signo.
```
int len = read_int();                 // firmado
if (len > BUFSIZE) return;            // -1 pasa el check (es < BUFSIZE)
memcpy(dst, src, (size_t)len);        // (size_t)-1 = 0xffff...ff -> copia gigante
```
- indices negativos: `arr[idx]` con idx firmado controlado -> OOB read/write ANTES del buffer
  (util para tocar metadatos/punteros previos).

## Off-by-one
Escribir 1 byte de mas (bucle `<=` en vez de `<`, o un NUL terminador que se pasa 1).
- en stack: pisa el LSB del saved RBP -> al hacer leave/ret puede desviar rsp (stack pivot
  parcial / off-by-one RBP).
- en heap: pisa el LSB del `size` del siguiente chunk. El "poison null byte" (un 0x00 de mas)
  apaga PREV_INUSE o encoge un size -> consolidacion falsa -> overlap (House of Einherjar).

## Truncamiento
Guardar un valor de 64/32 bits en un tipo mas pequeno (short/char): se pierden bytes altos.
Util para forzar tamanos pequenos, colisiones de indice, o saltarse comprobaciones que miran
solo la parte baja.

## Como detectarlos (estatico)
- toda aritmetica sobre tamanos/indices que venga de input: mult, suma, resta, cast, shift.
- sinks: malloc/calloc/realloc/memcpy/memmove/read/alloca con un tamano CALCULADO.
- en el binario: `movsx`/`movsxd`/`cdqe` (extension de signo) cerca de un tamano de input
  delatan signedness; `imul` sin comprobar overflow; comparaciones `jl/jg` (con signo) donde se
  esperaria `jb/ja` (sin signo).
- calloc valida overflow de n*size internamente; malloc(n*size) NO.

## Explotacion
Convierte el integer bug en su primitiva real y sigue el flujo correspondiente:
- overflow de heap -> [[heap]] / [[modern-heap]].
- overflow de stack -> [[rop]] / [[ret2libc]].
- OOB index R/W -> leak + arb write directo (a veces sin ni tocar el heap).
