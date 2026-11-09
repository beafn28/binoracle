# Heap exploitation glibc (cheat sheet)

Asignador ptmalloc2. La memoria dinamica se organiza en chunks; los libres se guardan en bins
(listas por tamano). La mayoria de bugs de heap se explotan corrompiendo los metadatos de esos
chunks/bins para conseguir un alloc arbitrario o un overlap.

## Anatomia de un chunk
```
prev_size (si el anterior esta libre) | size (bits bajos: PREV_INUSE, IS_MMAPPED, NON_MAIN)
fd | bk        <- solo cuando esta LIBRE (en uso, aqui empiezan los datos del usuario)
```
El puntero que te da malloc apunta a `fd` (chunk+0x10). size incluye la cabecera y se alinea a
0x10; el bit 0 (PREV_INUSE) indica si el chunk anterior esta en uso.

## Bins
- tcache (2.26+): 64 bins por tamano (hasta 0x410), LIFO, 7 chunks por bin. Rapido y con pocas
  comprobaciones -> el objetivo favorito.
- fastbins: chunks pequenos, LIFO, singly-linked.
- unsorted / small / large: chunks mayores; unsorted es paso intermedio y da leaks.

## tcache poisoning (la tecnica base)
UAF o double-free para controlar el `fd` de un chunk en tcache. La siguiente asignacion de ese
tamano te devuelve el chunk siguiente = la direccion que pusiste -> arbitrary alloc.
```
a = malloc(0x20); b = malloc(0x20)
free(a); free(b)              # tcache: b -> a
# UAF: sobrescribe fd de b con TARGET (desofuscado si safe-linking)
malloc(0x20)                  # devuelve b
malloc(0x20)                  # devuelve TARGET  -> escribe donde quieras
```

## Safe-linking (glibc >= 2.32)
El fd de tcache/fastbin va ofuscado: `fd = (pos >> 12) ^ ptr`, con pos = direccion del chunk.
Necesitas un LEAK del heap para operar:
- desofuscar un fd leido: `real = fd_leido ^ (pos >> 12)`.
- al envenenar hacia TARGET: `fd = (pos >> 12) ^ TARGET`.
Ademas el chunk resultante debe estar alineado a 0x10 (comprobacion de 2.32+).

## Protecciones a tener en cuenta
- tcache key (2.29+): cada chunk liberado marca un `key`; un double-free directo en el mismo
  bin se detecta. Evasion: libera otro chunk en medio, o usa fastbin, o corrompe el key.
- tcache count: se valida el contador del bin.
- glibc >= 2.34: __malloc_hook / __free_hook / __realloc_hook ELIMINADOS.

## Objetivos (donde escribir para RCE)
- glibc < 2.34: __free_hook = system, luego free(chunk_con_"/bin/sh"); o __malloc_hook =
  one_gadget.
- glibc >= 2.34: FSOP via _IO_FILE / _wide_data (House of Apple/Cat), __exit_funcs
  ([[exit-handlers]]), o la GOT del loader. Ver [[io-file]] y [[modern-heap]].
- tambien: un retaddr en la pila (si el alloc arbitrario cae ahi), o un puntero a funcion de la app.

## Leaks de heap y libc
- unsorted bin: un chunk grande liberado tiene fd/bk apuntando a main_arena (en libc). Leelo
  (UAF read) -> libc.address. 
- heap leak: fd de un chunk en tcache (o cualquier puntero de heap impreso) da la base del heap,
  necesaria para safe-linking.

## Tecnicas House-of-* (segun version)
- House of Force (top chunk size overwrite; pre-2.29).
- House of Spirit (fake fastbin/tcache chunk en area controlada).
- House of Einherjar (off-by-one/null-byte en prev_size -> consolidacion hacia atras -> overlap).
- House of Botcake (tcache + unsorted overlap -> UAF fuerte, evade tcache key).
- Unsortedbin attack (escribir main_arena en un target; util para preparar, pre-2.33).
- Modernas (2.35+): House of Apple/Cat/Kiwi/Banana ([[modern-heap]]).

## Deteccion (confirmar sin shell)
glibc aborta con mensajes reconocibles: "free(): double free detected in tcache 2",
"malloc(): unsorted double linked list corrupted", "corrupted top size",
"free(): invalid pointer". binoracle usa estos aborts para verificar corrupcion por ejecucion.

## Grooming (fiabilidad)
Vaciar/llenar el bin del tamano objetivo y colocar los chunks contiguos antes de disparar el
bug ([[heap-grooming]]).

## Herramientas
gdb + pwndbg/gef: `heap`, `bins`, `tcachebins`, `fastbins`, `vis_heap_chunks`, `heap-analysis`.
how2heap para PoC por version. pwntools para el driver (menu de alloc/free/edit/view).
