# ret2win (cheat sheet)

Patron: overflow de stack + una funcion "regalo" (win/shell/backdoor) que ya hace lo que
quieres (system("/bin/sh"), imprime la flag, abre y lee un fichero). No necesita leak si el
binario es no-PIE. Es el reto de introduccion al control de flujo.

## Cuando aplica
- Overflow de stack (gets, read con tamano grande, scanf %s, strcpy) sobre un buffer local.
- Existe una funcion que no se llama por el flujo normal y hace algo util (win/shell/flag).
  Localizala con `r2 afl`, imports (system), o cadenas ("/bin/sh", "flag").

## Pasos
1. Offset del buffer al saved RIP:
```
cyclic 200            # genera el patron
# envia, deja que crashee, en gdb: mira el valor de RIP/lo que hay en rsp
cyclic -l 0x6161616c  # -> offset exacto
```
   Tipico: tamano_buffer + 8 (saved rbp). No lo asumas, mide.
2. payload = b"A"*offset + p64(win).
3. Alineacion (movaps): si win llama a system/printf y crashea DENTRO con SIGSEGV, anade un
   gadget `ret` antes de win para realinear rsp a 16:
   payload = b"A"*offset + p64(ret_gadget) + p64(win).

## Saltar al cuerpo, no al prologo
A veces conviene saltar unas instrucciones DESPUES del prologo de win (evitar `push rbp` que
desalinea, o saltar un `strcmp` que valida). Usa win+offset en vez de win.

## PIE
win = pie_base + win_offset. Con PIE necesitas fugar una direccion de .text primero
(uninitialized read, format-string) y sumar el offset del simbolo. Con ASLR off en pruebas la
base tipica es 0x555555554000 (solo para PoC local, no para el target).

## Funcion win con argumentos
Si win es en realidad `system` o `execve` que espera un argumento (p.ej. una funcion que hace
system(cmd) con cmd controlable, o quieres win("cat flag")), necesitas cargar rdi con un gadget
`pop rdi; ret` antes -> ya es medio ROP. Ver [[rop]].

## Capturar la evidencia
Si win da shell, envia despues por stdin `cat flag*; id` para probar RCE real. Si win imprime
la flag, leela de la salida. Un PoC serio termina con la flag o `uid=...`, no solo "win reached".

## pwntools
```
from pwn import *
elf = context.binary = ELF('./chall')
io = process(elf.path)                 # o remote(host, port)
off = 40
rop = ROP(elf); RET = rop.find_gadget(['ret'])[0]
io.sendlineafter(b'? ', flat({off: [RET, elf.sym.win]}))
io.interactive()                       # o: io.sendline(b'cat flag*'); print(io.recvall())
```

## Gotchas
- gets ignora \n pero corta en EOF; read no filtra: elige el vector segun la funcion.
- bytes nulos: si el vector es strcpy/scanf, un 0x00 en la direccion de win corta el payload
  (raro en no-PIE, donde win suele ser 0x4011xx sin nulos intermedios).
- si "win reached" pero no hay shell/flag: puede faltar alineacion, o win pide un argumento.
