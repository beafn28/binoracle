# PIE y leaks (cheat sheet)

PIE: el binario carga en base aleatoria (paginas de 0x1000; los 12 bits bajos fijos).

## Resolver la base
pie_base = leaked_code_addr - known_offset. El offset es la direccion del simbolo en el ELF
(readelf/nm). Cualquier funcion, GOT, o direccion de retorno del propio binario sirve.

## Fuentes de leak
- format-string: %N$p sobre un valor de la pila que apunte al binario.
- overflow que deje una direccion de codigo visible al imprimir (uninitialized read).
- ret2plt puts(some_got) revela libc, no PIE; para PIE necesitas una direccion de .text.

## Partial overwrite
Los 12 bits bajos no cambian con ASLR -> sobrescribe solo 1-2 bytes de un puntero de retorno
para saltar a una direccion cercana sin conocer la base (1 nibble de brute-force: 1/16).

## En autopoc/PoC deterministico
Con ASLR desactivado (setarch -R / personality), la base PIE tipica de Linux x86-64 es
0x555555554000; util para PoCs reproducibles en sandbox, NO para el target real.
