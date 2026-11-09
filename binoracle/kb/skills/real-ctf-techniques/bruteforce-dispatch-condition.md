# Técnica: fuerza bruta propia sobre una condición de dispatch, en vez de confiar en un valor dado

## Patrón a reconocer

Un binario selecciona QUÉ función ejecutar (de varias candidatas, vía tabla de punteros a
función o una cadena de `if`/`switch`) según una condición booleana calculada a partir del
input del usuario -- p.ej. `(seed[0]|seed[1]) & (seed[2]|seed[3]) == 0x49`. Un writeup o
solución externa puede dar UN valor concreto que satisface la condición (una "semilla mágica"),
pero eso no prueba que se entendió el mecanismo -- podría ser casualidad o copiado.

## Por qué importa

Cuando el espacio de entradas es pequeño (unos pocos bytes imprimibles), es perfectamente
viable y MÁS RIGUROSO hacer fuerza bruta propia sobre la condición exacta derivada del
disassembly, en vez de solo confirmar que un valor dado funciona. Esto además revela la
ESTRUCTURA real del problema: cuántas soluciones válidas existen, si la "solución conocida" es
la única o una de muchas, y permite encontrar soluciones más simples.

## Cómo aplicarlo

1. Deriva la condición EXACTA del disassembly (qué operación bitwise, qué comparación, sobre
   qué bytes del input).
2. Si el espacio de entradas válidas es pequeño (ASCII imprimible en pocas posiciones, por
   ejemplo 4 bytes x 95 valores imprimibles = ~81 millones, trivial para un script), itera
   TODAS las combinaciones y cuenta cuántas satisfacen la condición exacta.
3. Compara: si un valor "conocido" (de un writeup, o una pista) está entre las soluciones
   encontradas, confirma que el mecanismo se entendió correctamente -- Y que probablemente hay
   MUCHAS otras soluciones válidas (lo cual es señal de que la condición no es demasiado
   restrictiva, consistente con un reto bien diseñado).
4. Si el valor conocido NO aparece entre las soluciones de tu fuerza bruta, la condición que
   derivaste del disassembly está mal -- revisa el mecanismo antes de asumir que es un dato
   externo irrecuperable.

## Caso real confirmado (CTF "Function-Pointer-Fun", HackPackCTF 2021)

Dispatch de 5 funciones vía puntero a función, seleccionado por
`(seed[0]|seed[1]) & (seed[2]|seed[3]) == 0x49`. En vez de solo confirmar la semilla de un
writeup (`i0@I`), fuerza bruta propia sobre las 4 posiciones (restringidas a ASCII imprimible)
encontró 413307 semillas válidas de forma independiente -- incluyendo una más simple (`" I@I"`)
-- confirmando que el dispatch era resoluble sin el writeup. (El bloqueo real que quedó en ese
reto era un dato externo genuino -- un `fopen("flag","r")` sobre un archivo que no existía en
ningún sitio del entorno -- no un fallo del mecanismo de dispatch, que quedó completamente
resuelto.)
