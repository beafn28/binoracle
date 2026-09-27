# Heap moderno: House-of-* y FSOP (cheat sheet)

Tecnicas de heap para glibc reciente (2.32+), donde tcache tiene safe-linking y los hooks
(__malloc_hook/__free_hook) fueron eliminados en 2.34.

## Ataques a bins (recordatorio rapido)
- fastbin dup / tcache poisoning: double-free/UAF para envenenar fd y obtener alloc arbitrario
  (con safe-linking necesitas heap leak; ver [[heap]]).
- unsorted bin leak: un chunk en unsorted bin tiene fd/bk apuntando a main_arena -> leak de
  libc al imprimirlo (UAF read).
- tcache stashing unlink: abusar del stashing de smallbin a tcache para escribir un puntero
  controlado (requiere control de bk de un smallbin).
- large bin attack: escribir una direccion de libc/heap en un target via bk_nextsize
  (util para preparar otras primitivas, no da RCE por si solo).

## Sin hooks (glibc >= 2.34): FSOP
Ya no hay __free_hook/__malloc_hook. La ruta moderna es corromper structs FILE (_IO_FILE) y
disparar la cadena de vtables al hacer fwrite/fread/exit/fflush (FSOP = File Stream Oriented
Programming).
- glibc valida que la vtable este dentro de __libc_IO_vtables (_IO_vtable_check). Una vtable
  en el heap falla ese check.

## House of Apple 2 (bypass del vtable check, glibc 2.35+)
Usa los streams de caracteres anchos (_wide_data): el puntero externo se valida, pero el
_wide_vtable anidado NO. Cadena tipica:
`fwrite -> _IO_wfile_xsputn -> _IO_wfile_overflow -> _IO_wdoallocbuf ->
call [fp->_wide_data->_wide_vtable + 0x68] -> system("sh")`.
- Requisitos: colocar una fake vtable/_wide_data en una direccion conocida y tener escritura
  arbitraria o lectura arbitraria dentro de libc.

## Otras "houses" modernas (cuando aplican)
- House of Emma: secuestra `_IO_cookie_jumps` + pointer guard (necesita leak del guard/TLS).
- House of Water / leakless: cadenas que evitan necesitar un leak previo montando primitivas
  con unsorted/large bin + tcache.
- House of Force: overwrite del top chunk size (solo glibc < 2.29).
- House of Spirit / Einherjar / Botcake: fake chunks, off-by-one prev_size, overlap tcache.

## Como elegir
1. Que version de glibc? (define que esta mitigado). 2. Que primitiva tienes (UAF, overflow,
double-free, arb write)? 3. Tienes leak de libc/heap? 4. Elige la house que encaje con esas
condiciones; valida con how2heap para esa version.
