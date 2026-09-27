# Heap: matriz de tecnicas por version de glibc (cheat sheet)

Que tecnica de heap sigue viva en cada glibc es lo primero que decide la ruta: una casa que
funciona en 2.27 puede estar parcheada en 2.31. Antes de elegir, mira la version del reto
(`strings libc.so.6 | grep -i "glibc"` o `./libc.so.6` la imprime) y cruza con esta tabla.
Sintetizado de la matriz de shellphish/how2heap (referencia autoritativa que verifica cada
tecnica contra la libc de Ubuntu). Complementa [[heap]], [[modern-heap]] y [[heap-grooming]].

## Timeline de mitigaciones (que cambia y cuando)
- **2.26**: nace tcache (7 chunks por tamano, LIFO, sin apenas checks al principio) -> tcache
  poisoning trivial. Muchas casas "clasicas" pierden fuerza porque el free va a tcache.
- **2.29**: checks de consistencia fuertes: unsorted_bin `bk`/`fd` validados -> caen
  unsorted_bin_attack, house_of_force, house_of_orange (clasico), house_of_storm, roman.
- **2.31**: tcache gana `key` (doble-free detectado) y `count` -> el double-free directo muere;
  hay que hacer tcache stashing / botcake para saltar el key.
- **2.32**: safe-linking: los `fd` de tcache/fastbin van cifrados `ptr ^ (addr >> 12)` -> para
  envenenar necesitas conocer la direccion del chunk (leak del heap) y aplicar el mangle.
- **2.34**: se ELIMINAN los hooks (`__malloc_hook`, `__free_hook`, `__realloc_hook`) -> ya no
  hay hook que sobrescribir; se pasa a FSOP / exit-handlers ([[io-file]], [[exit-handlers]]).
- **2.35+**: mas hardening de tcache/fastbin; parches puntuales que rompen o ajustan casas
  concretas (fastbin_dup y house_of_mind parcheadas antes de 2.43; large_bin_attack antes de 2.42).

## Matriz de tecnicas (viva / parcheada)
| Tecnica | Ventana util | Notas |
|---------|--------------|-------|
| tcache poisoning | >= 2.26 (vigente) | base moderna; con safe-linking (>=2.32) necesita leak de heap |
| tcache dup (double-free directo) | 2.26-2.28 | muere en 2.31 con el `key` |
| tcache stashing unlink | >= 2.26 (vigente) | escribe un puntero en un sitio semi-controlado |
| house_of_botcake | >= 2.26 (vigente) | double-free saltando el tcache key (via unsorted) |
| fastbin_dup / into_stack | hasta ~2.42 | parcheada antes de 2.43; revisa checks de fastbin |
| fastbin_reverse_into_tcache | 2.26-2.42 | mueve de fastbin a tcache para reusar |
| unsafe_unlink | vigente | necesita puntero a si mismo (chunk que apunta a su ptr) |
| house_of_spirit | vigente | forja un chunk falso y lo libera |
| poison_null_byte | vigente | off-by-one NUL -> solapamiento (ver [[integer-bugs]]) |
| house_of_einherjar | vigente | off-by-one en prev_size + PREV_INUSE -> consolidacion falsa |
| house_of_lore | vigente | smallbin `bk` -> alloc en zona controlada |
| large_bin_attack | hasta ~2.42 | escribe un valor grande en un objetivo (no arbitrario) |
| unsorted_bin_attack | <= 2.28 | muere en 2.29 (checks de unsorted) |
| house_of_force | <= 2.28 | muere en 2.29 (check del top size) |
| house_of_orange (clasico) | <= 2.25 | parcheada en 2.26; su idea vive en FSOP moderno |
| house_of_storm / roman / gods | <= 2.28 / <= 2.26 | recetas viejas, casi todas parcheadas |
| house_of_water | >= 2.36 | moderna, usa unsorted + tcache |
| house_of_tangerine | >= 2.26 (vigente) | tcache count + unsorted |
| sysmalloc_int_free | >= 2.39 | abusa del camino de sysmalloc |
| tcache_metadata_poisoning / hijacking | >= 2.26 / >= 2.42 | pisa metadatos de tcache_perthread_struct |
| tcache_relative_write | 2.30-2.41 | escritura relativa via tcache |

## Como elegir segun el target
1. **Saca la version** de la libc del reto (imprimela o `identify` con [[got-plt]] tools /
   libc-database). Sin eso, planificas a ciegas.
2. **glibc < 2.29**: tienes el menu viejo abierto (unsorted_bin_attack, house_of_force,
   fastbin dup facil). Rapido y fiable.
3. **2.31-2.33**: tcache con key + safe-linking. Ruta tipica: leak de heap -> tcache poisoning
   con `fd` cifrado; double-free via botcake/stashing (no directo). Hooks aun existen (<2.34).
4. **>= 2.34**: sin hooks. Consigue arb write y ve por FSOP ([[io-file]], House of Apple 2) o
   exit-handlers ([[exit-handlers]]); el heap solo te da la primitiva, no el RCE final.
5. **Verifica en un debugger** (pwndbg `vis_heap_chunks`) que el layout es el que crees antes de
   disparar; la matriz dice si la tecnica es POSIBLE, no que tu groom sea correcto ([[heap-grooming]]).

Fuente de la matriz: shellphish/how2heap (github.com/shellphish/how2heap), que mantiene cada
tecnica verificada por version de Ubuntu/glibc. Aqui va sintetizada como guia de decision; para
el PoC concreto de cada casa, ver los cheat sheets [[modern-heap]] y [[heap]].
