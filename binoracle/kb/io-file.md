# FILE / _IO_FILE a fondo y FSOP (cheat sheet)

La struct FILE (_IO_FILE_plus) guarda flags, buffers y una vtable de punteros a funcion. Toda
operacion de IO (fwrite/fread/fclose/fflush/puts/printf con buffer) pasa por esa vtable ->
corromperla da control. Complementa [[modern-heap]].

## Campos clave de _IO_FILE
- _flags (offset 0): bits de estado (magic 0xFBAD0000 | flags). Manipularlo cambia el
  comportamiento de lectura/escritura del stream.
- _IO_read_ptr/base/end, _IO_write_ptr/base/end (buffers).
- _chain: siguiente FILE (lista _IO_list_all).
- _fileno: fd. _lock: puntero al lock. vtable (al final, _IO_jump_t).
- _wide_data: datos de streams de caracteres anchos (clave en House of Apple 2).

## Leak via _IO_2_1_stdout_
Trucar los flags y punteros de stdout para que el proximo output filtre memoria:
- set `_flags = 0xfbad1800` (o 0xfbad1887) y pon `_IO_write_base` apuntando "mas atras" (p.ej.
  a una direccion de libc en la propia struct) y `_IO_write_end` mas lejos -> al hacer flush,
  glibc escribe TODO ese rango a stdout -> leak enorme de libc/heap.
- Muy usado tras un overlap de tcache con `_IO_2_1_stdout_`.

## FSOP: disparar la vtable
Al hacer fwrite/fflush/exit(->_IO_flush_all_lockp), glibc recorre _IO_list_all y llama
`vtable->__overflow(fp)` etc. Si controlas fp y su vtable, controlas rip.
- Mitigacion moderna: `_IO_vtable_check` exige que la vtable este dentro de __libc_IO_vtables.
  Una vtable en heap falla.

## Bypass del vtable check (glibc 2.24+ / 2.35+)
- House of Orange (viejo): abusa de _IO_list_all + fake FILE con vtable a system (pre-check).
- House of Apple 2 (2.35+): via _wide_data->_wide_vtable (el anidado NO se valida). Cadena:
  `_IO_wfile_xsputn -> _IO_wfile_overflow -> _IO_wdoallocbuf -> call [_wide_data->_wide_vtable
  + 0x68]` con system/one_gadget.
- House of Cat: usa _IO_wfile_jumps + _wide_data para saltar a un gadget controlado (similar
  filosofia, otra cadena; util cuando controlas rdx).
- House of Kiwi: abusa de __malloc_assert -> _IO_flush_all para forzar la cadena FSOP incluso
  sin exit explicito.
- House of Banana: corrompe _dl_fini / rtld_global (_IO/link_map) para RCE al salir.

## Requisitos generales
- fake FILE en memoria conocida (heap con leak), o overwrite de un FILE real.
- leak de libc (para vtable/system) salvo variantes leakless.
- que el programa haga IO o salga (para disparar la cadena).
