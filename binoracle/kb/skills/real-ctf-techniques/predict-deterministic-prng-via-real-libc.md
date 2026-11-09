# Técnica: predecir un PRNG determinista llamando a la libc REAL, no reimplementándolo a mano

## Patrón a reconocer

Un binario llama `srand(N)` con una semilla FIJA (literal en el código, no derivada de
`time()`), y luego `rand()` repetidamente (p.ej. una IA que juega contra ti, o un generador de
retos). Como la semilla es fija, toda la secuencia de `rand()` es 100% determinista y
predecible SIN ejecutar el binario.

## Por qué importa

Reimplementar el algoritmo exacto de `rand()`/`random()` de glibc a mano (el generador
`TYPE_3`, un generador lineal aditivo con tablas de realimentación) es tedioso y propenso a
errores sutiles de índice. Pero el binario normalmente fue compilado contra la MISMA libc que
está instalada en el sistema de análisis (o una compatible) -- no hace falta reimplementar
nada: se puede invocar la función real.

## Cómo aplicarlo

1. Identifica la semilla fija (`srand(N)` en el disassembly, N es un literal) y en qué orden
   exacto se llama `rand()` (cada cuántas rondas, módulo qué valor: `rand() % 4`, etc.).
2. En Python, usa `ctypes.CDLL(None)` (o `ctypes.CDLL("libc.so.6")` en Linux) para llamar a
   `srand`/`rand` de la libc REAL del sistema:

       import ctypes
       libc = ctypes.CDLL(None)
       libc.srand(1337)
       secuencia = [libc.rand() % 4 for _ in range(24)]

3. Esto reproduce EXACTAMENTE la misma secuencia que el binario objetivo generará, con cero
   riesgo de una reimplementación incorrecta -- el algoritmo TYPE_3 de glibc lleva décadas
   estable en su ABI, así que esto funciona de forma fiable entre versiones.
4. Si el binario fue compilado contra una libc distinta (musl, una version de Windows CRT,
   etc.), el algoritmo difiere -- confirma primero con `file`/`ldd`/los imports qué libc usa
   el binario, y usa la *misma* para la llamada via ctypes (p.ej. cargar esa .so/.dll concreta
   en vez de la del sistema de analisis, si estan disponibles).

## Caso real confirmado (CTF "Punch-Out!")

Un binario ELF x86-64 con `srand(1337)` fijo; una IA llama `rand() % 4` cada ronda durante 24
rondas (fallar una tirada = derrota instantánea). Replicar el `rand()` real de glibc vía
`ctypes` en vez de reimplementarlo dio la secuencia exacta `123322100333030310222003`,
verificada carácter a carácter -- sin necesidad de ejecutar el binario original ni adivinar
los detalles internos del algoritmo.
