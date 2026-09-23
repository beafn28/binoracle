# Heap exploitation glibc (cheat sheet)

Asignador ptmalloc2. El heap se organiza en chunks; los libres se guardan en bins.

## tcache (glibc >= 2.26)
Lista LIFO por tamano (64 entradas/bin). fd del chunk libre apunta al siguiente.
- tcache poisoning: UAF/double-free para escribir fd de un chunk en tcache -> la siguiente
  asignacion de ese tamano devuelve la direccion elegida (arbitrary alloc).
- Safe-linking (glibc >= 2.32): fd = ptr ^ (chunk_addr >> 12). Necesitas un leak del heap
  para "desofuscar": target_ptr = fd_leido ^ (pos >> 12). Al envenenar: fd = (pos>>12) ^ target.
- tcache count check (glibc >= 2.29): detecta algunos double-free en el mismo bin (key field).

## Objetivos tipicos
- __free_hook / __malloc_hook (glibc < 2.34): escribir system y liberar/alloc con "/bin/sh".
- glibc >= 2.34: hooks eliminados -> FSOP (_IO_FILE, _IO_str_jumps / wide vtable check),
  __exit_funcs, apuntar a la GOT de ld, o house-of-* modernas.

## Tecnicas House-of-*
- House of Force (top chunk size overwrite; pre-2.29).
- House of Spirit (fake fastbin/tcache chunk en area controlada).
- House of Einherjar (off-by-one prev_size -> consolidacion hacia atras).
- House of Botcake (tcache/unsortedbin overlap para UAF fuerte).
- Unsortedbin attack (escribir main_arena en un target; pre-2.33 mayormente).

## Deteccion (sin shell)
Un double-free / corrupcion se confirma por abort de glibc: "free(): double free detected in
tcache 2", "malloc(): unsorted double linked list corrupted", "corrupted top size".

## Herramientas
gdb + pwndbg/gef: `heap`, `bins`, `tcachebins`, `vis_heap_chunks`. pwntools para el driver.
