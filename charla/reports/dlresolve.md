## Auto-explotacion de `samples/bin/dlresolve`

> EXPLOIT VERIFICADO: se ejecuto un exploit (ret2dlresolve) en sandbox y se consiguio el objetivo.

### Contexto del binario (defensas detectadas)

- arquitectura: **x86 64-bit**
- mitigaciones: **NX ON · PIE off · canary off**
- funcion gift `win()`: **no**
- sinks peligrosos: read
- **por que la tecnica elegida**: dinamico no-PIE sin win()/system ni leak -> se forjan las estructuras del resolver dinamico para llamar a system('/bin/sh') SIN fuga de libc

- hallazgos verificados: 1

### Combinaciones probadas

| tecnica | resultado | detalle |
|---|---|---|
| srop | posible | SROP: no verificado (native) (sin pop rax/syscall/'/bin/sh' o timing) |
| rop-chain | no | no se pudo construir cadena automatica (sin /bin/sh o gadgets suficientes; ret2libc dinamico necesita libc/leak) |
| ret2libc | posible | ret2libc/one_gadget: no verificado (native) (sin leak/gadget aplicable o timing) |
| mprotect-shellcode | posible | mprotect()+shellcode: no verificado (native) (sin mprotect()/buffer fijo conocido, gadgets insuficientes para rdi/rsi/rdx, o forma de entrada distinta) |
| leak-chain | posible | infoleak chaining: no verificado (native) (sin table/<fn>_leak/callback conocidos, sin libc dinamica, o timing) |
| ret2dlresolve | FUNCIONA | VERIFIED off=72 align=ret data=0x404e00 bits=64 |

### Traza
```
[recon] arch=x86 64-bit  NX=true  PIE=false  canary=false
[recon] sinks: read
[recon] gadget 'pop rdi': si
[verify] hallazgos verificados por angr: 1
[combo] ret2win: no hay funcion gift -> se omite
[combo] SROP: sigreturn -> execve('/bin/sh') (sandbox)...
[combo] SROP -> no verificado
[combo] cadena ROP: intentando construir...
[combo] cadena ROP -> no automatica
[combo] ret2libc con leak (fuga libc -> system, sandbox)...
[combo] ret2libc -> no aplicable/verificable
[combo] mprotect()+shellcode: ROP a mprotect() sobre un buffer fijo -> shellcode real...
[combo] mprotect()+shellcode -> no aplicable/verificable
[combo] infoleak chaining: OOB read -> libc_base -> write-what-where -> shell...
[combo] infoleak chaining -> no aplicable/verificable
[combo] ret2dlresolve: shell sin leak forjando el resolver dinamico (sandbox)...
[combo] ret2dlresolve -> SHELL VERIFICADA
[fin] combinaciones probadas: srop, rop-chain, ret2libc, mprotect-shellcode, leak-chain, ret2dlresolve
```

Todo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).