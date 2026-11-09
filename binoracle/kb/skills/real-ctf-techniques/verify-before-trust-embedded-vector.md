# Técnica: verificar un algoritmo reconstruido contra un vector de prueba embebido antes de confiar en él

## Patrón a reconocer

Muchos retos de reversing imprimen o comparan un valor de ejemplo ANTES de pedir el input real
(p.ej. `printf("test: %s -> %s\n", "baseball", encrypt("baseball"))`, o una comparación contra
un string fijo embebido en `.rodata`). Ese vector de prueba es ORO: permite confirmar que la
reconstrucción del algoritmo (hecha a mano leyendo el disassembly, o con una herramienta como
`angr_call_function`) es EXACTAMENTE correcta ANTES de aplicarla al ciphertext/flag real.

## Por qué importa

Reconstruir un algoritmo (XOR con keystream evolutivo, red Feistel, PRNG propio, etc.) leyendo
disassembly a mano es propenso a errores sutiles (un signo, un orden de operandos, un offset de
índice). Aplicar la reconstrucción DIRECTAMENTE al ciphertext real sin verificar primero puede
producir basura que parece "casi correcta" y llevar a conclusiones falsas. El vector de prueba
embebido (si existe) es la forma más barata y fiable de detectar el error ANTES de perder tiempo
analizando una salida incorrecta.

## Cómo aplicarlo

1. Antes de descifrar el ciphertext real, busca en el binario (strings, constantes, o el propio
   flujo de `main`) un ejemplo de entrada/salida ya calculado por el programa mismo.
2. Reconstruye el algoritmo (a mano, o llamando la función real con `angr_call_function` sobre
   el ejemplo conocido en vez de reimplementarlo).
3. Compara: ¿tu reconstrucción produce EXACTAMENTE la misma salida que el programa, para esa
   misma entrada de ejemplo? Si no coincide byte a byte, el algoritmo reconstruido está mal --
   NO sigas adelante con el ciphertext real todavía.
4. Para operaciones invertibles (cifrado simétrico, Feistel, XOR), haz también un roundtrip:
   `decrypt(encrypt(x)) == x`. Si falla, la inversión (no solo el cifrado) tiene un error.
5. Solo una vez el vector de prueba Y el roundtrip coinciden exactamente, aplica el algoritmo
   al ciphertext/flag real.

## Caso real confirmado (CTF "FeistyCrypt")

Una red Feistel de 256 rondas con subclaves generadas por un PRNG PCG32 de semilla fija. El
binario imprime `encrypt("baseball")` como ejemplo. Verificar la reconstrucción contra ese
vector exacto (`70 09 36 2d 3a 75 45 7c`) ANTES de tocar el ciphertext real, más un roundtrip
`decrypt(encrypt(x))==x`, confirmó que la reconstrucción (función F = AND+XOR, sin intercambio
en la última ronda) era exacta -- evitando confiar en una inversión potencialmente mal derivada.
