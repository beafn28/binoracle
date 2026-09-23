# GOT / PLT y lazy binding (cheat sheet)

Como un ELF dinamico resuelve funciones de libc en runtime, y por que eso es un objetivo de
explotacion. Base de GOT overwrite y de ret2dlresolve ([[advanced-rop]]).

## PLT y GOT
- PLT (.plt): trampolin por funcion importada. `call puts@plt` salta a una entrada PLT.
- GOT (.got.plt): tabla de punteros que la PLT lee. Antes de resolver, la GOT apunta de vuelta
  a la PLT (para forzar la resolucion la primera vez); despues, al codigo real en libc.

## Lazy binding (resolucion perezosa)
1. Primera llamada a `func@plt`: la GOT aun apunta a PLT+6 -> empuja el indice de reloc y salta
   a PLT[0].
2. PLT[0] llama a `_dl_runtime_resolve(link_map, reloc_index)`.
3. El resolver: coge la reloc de JMPREL (.rela.plt) en `JMPREL + index`, saca el simbolo de
   SYMTAB (.dynsym) via el campo r_info, y el NOMBRE de STRTAB (.dynstr). Busca la direccion
   real y la ESCRIBE en la GOT.
4. Siguientes llamadas: la GOT ya tiene la direccion -> salto directo, sin resolver.

## GOT overwrite (RCE primitive)
Si tienes escritura (format-string %n, overflow de un puntero, arb write) y la GOT es
escribible (No/Partial RELRO): sobrescribe la entrada de una funcion que se llamara despues
(printf, exit, __stack_chk_fail...) con system/one_gadget.
- Ejemplo clasico: printf@GOT -> system, y luego printf(buf) con buf="/bin/sh" ejecuta system.
- Tambien GOTs INTERNAS de la propia libc (algunas funciones de libc se llaman entre si via su
  GOT) pueden ser objetivo cuando el binario tiene Full RELRO pero la libc no.

## ret2dlresolve (sin leak)
Abusa del paso 3: das un `reloc_index` enorme para que la reloc caiga en memoria que controlas,
y forjas Elf64_Rela + Elf64_Sym + el nombre en STRTAB apuntando a "system". _dl_runtime_resolve
resuelve y llama tu funcion. Requiere GOT escribible (no Full RELRO) y lazy binding activo.

## RELRO (la defensa)
- Partial RELRO: .got (datos) de solo lectura, pero .got.plt (lazy) sigue escribible -> GOT
  overwrite y ret2dlresolve posibles.
- Full RELRO: bind now (todo resuelto al arranque) + toda la GOT de solo lectura -> no GOT
  overwrite, no ret2dlresolve. Hay que ir por FSOP/exit-handlers/hooks.
- Comprueba con checksec antes de planear.
