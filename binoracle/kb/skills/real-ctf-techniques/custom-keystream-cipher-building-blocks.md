# Técnica: catálogo de bloques comunes en cifrados "a medida" de tablas de strings en CTFs

## Patrón a reconocer

Muchos retos de reversing NO usan un cifrado estándar (AES/RC4) para ocultar sus strings --
usan un cifrado CASERO, simple pero distinto cada vez, aplicado byte a byte sobre una tabla de
strings cifradas. Reconocer la FAMILIA del cifrado desde el disassembly es más rápido que
intentar fuerza bruta.

## Variantes reales confirmadas en esta sesión (todas distintas, todas resueltas)

1. **XOR simple byte-a-byte** con una clave fija o derivada del índice
   (`plano[i] = cifrado[i] XOR key`). La más simple; buscar un `xor` en un bucle sobre un
   buffer, sin más estado.

2. **XOR alternante por paridad del índice**: la clave usada depende de si `i` es par o impar
   (dos claves distintas, una para posiciones pares y otra para impares). Señal: dos ramas
   condicionales dentro del bucle de descifrado, una activada por `i & 1`.

3. **Desplazamiento (shift cipher) con byte CON SIGNO**: la resta/suma de desplazamiento se
   hace sobre un `signed char`/`int8_t`, no un byte sin signo -- el resultado puede dar
   negativo y hay que tratarlo con aritmética modular de 256 explícita (`((v % 256) + 256) %
   256`), no asumir que siempre es positivo. Un error de signo aquí produce caracteres
   incorrectos solo para un SUBCONJUNTO de posiciones, lo que puede parecer "casi funciona".

4. **Keystream evolutivo polinomial por índice**: la clave de cada posición se deriva de la
   anterior con una fórmula tipo `key_siguiente = (byte_cifrado XOR key_actual) * key_actual +
   indice * CONST` (todo módulo 2^32 o 2^64 -- aritmética de registro, no de precisión
   arbitraria). Cada string de una tabla puede arrancar con una semilla distinta (p.ej.
   `key_inicial = indice_de_la_string`). Señal: el bucle de descifrado actualiza una variable
   de estado con una multiplicación Y una suma, no solo un XOR.

5. **Red Feistel propia** con función F simple (AND+XOR con una constante) y subclaves
   generadas por un PRNG reconocible (p.ej. PCG32: multiplicador `0x5851f42d4c957f2d` es su
   firma). Suele no intercambiar las dos mitades en la ÚLTIMA ronda (patrón estándar de
   Feistel). Ver la nota separada sobre verificar contra un vector de prueba embebido antes de
   confiar en la reconstrucción.

## Cómo aplicarlo

- Antes de asumir XOR simple, mira el bucle de descifrado COMPLETO: ¿hay una condición sobre el
  índice (par/impar)? ¿La clave cambia entre iteraciones, o es constante? ¿Hay una
  multiplicación además de XOR?
- Si el primer intento produce texto "casi legible" pero con caracteres sueltos mal (en
  posiciones específicas, no aleatorias), sospecha de un error de signo (variante 3) antes de
  descartar el algoritmo entero.
- Para la variante 4 (keystream evolutivo), extrae la tabla de offsets/semillas y el blob
  cifrado completo, y reimplementa el autómata exacto en Python con aritmética modular
  explícita del tamaño de registro correcto (32 o 64 bits).

## Casos reales confirmados esta sesión

- `rocca-pia` (dvCTF 2021): variante 2, XOR alternante por paridad.
- `stings` (ImaginaryCTF 2021): variante 3, shift cipher con byte con signo.
- `jailbreak` (Angstrom 2021): variante 4 -- tabla de 29 strings, cada una con su propio
  keystream evolutivo (`key_siguiente = (cifrado XOR key) * key + indice*17 mod 2^32`),
  arrancando con `key = indice_de_la_string`. Descifradas las 29 strings completas, revelando
  contenido (ramas trampa, un backdoor de victoria instantánea) que ningún writeup documentaba.
- `FeistyCrypt` (UMDCTF 2021): variante 5, red Feistel de 256 rondas con subclaves PCG32.
