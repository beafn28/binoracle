## Auto-explotacion de `samples/bin/staticrop`

### Contexto del binario (defensas detectadas)

- arquitectura: **x86 64-bit**
- mitigaciones: **NX ON · PIE off · canary ON**
- funcion gift `win()`: **no**
- sinks peligrosos: read

- hallazgos verificados: 0

### Combinaciones probadas

| tecnica | resultado | detalle |
|---|---|---|
| srop | posible | SROP: no verificado (native) (sin pop rax/syscall/'/bin/sh' o timing) |
| rop-chain | posible | execve (pwntools, '/bin/sh' staged a .bss) (construida) |
| ret2libc | posible | ret2libc/one_gadget: no verificado (native) (sin leak/gadget aplicable o timing) |
| mprotect-shellcode | posible | mprotect()+shellcode: no verificado (native) (sin mprotect()/buffer fijo conocido, gadgets insuficientes para rdi/rsi/rdx, o forma de entrada distinta) |
| leak-chain | posible | infoleak chaining: no verificado (native) (sin table/<fn>_leak/callback conocidos, sin libc dinamica, o timing) |
| tcache-dup | posible | no verificado (native): menu no reconocido, ninguna GOT alineada, o el double-free no aplica asi |
| ret2dlresolve | posible | ret2dlresolve: no verificado (native) (no aplicable, sin gadgets, o resolver endurecido en glibc >= 2.35) |

### Traza
```
[recon] arch=x86 64-bit  NX=true  PIE=false  canary=true
[recon] sinks: read
[recon] gadget 'pop rdi': si
[verify] hallazgos verificados por angr: 0
[combo] ret2win: no hay funcion gift -> se omite
[combo] SROP: sigreturn -> execve('/bin/sh') (sandbox)...
[combo] SROP -> no verificado
[combo] cadena ROP: intentando construir...
[combo] cadena ROP -> construida
[combo] ret2libc con leak (fuga libc -> system, sandbox)...
[combo] ret2libc -> no aplicable/verificable
[combo] mprotect()+shellcode: ROP a mprotect() sobre un buffer fijo -> shellcode real...
[combo] mprotect()+shellcode -> no aplicable/verificable
[combo] infoleak chaining: OOB read -> libc_base -> write-what-where -> shell...
[combo] infoleak chaining -> no aplicable/verificable
[combo] tcache-dup: tcache dup -> GOT=system (sandbox)...
[combo] tcache-dup -> no verificado
[combo] ret2dlresolve: shell sin leak forjando el resolver dinamico (sandbox)...
[combo] ret2dlresolve -> no verificado
[fin] combinaciones probadas: srop, rop-chain, ret2libc, mprotect-shellcode, leak-chain, tcache-dup, ret2dlresolve
```

Todo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).