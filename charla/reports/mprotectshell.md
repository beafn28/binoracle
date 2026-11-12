## Auto-explotacion de `samples/bin/mprotectshell`

> EXPLOIT VERIFICADO: se ejecuto un exploit (mprotect-shellcode) en sandbox y se consiguio el objetivo.

### Contexto del binario (defensas detectadas)

- arquitectura: **x86 64-bit**
- mitigaciones: **NX ON · PIE off · canary ON**
- funcion gift `win()`: **no**
- sinks peligrosos: read
- **por que la tecnica elegida**: NX activo, gadgets insuficientes para un execve/ret2libc completo -> ROP solo hasta mprotect() sobre un buffer fijo (RWX) y salto a shellcode real

- hallazgos verificados: 0

### Combinaciones probadas

| tecnica | resultado | detalle |
|---|---|---|
| srop | posible | SROP: no verificado (native) (sin pop rax/syscall/'/bin/sh' o timing) |
| rop-chain | posible | execve (pwntools, '/bin/sh' staged a .bss) (construida) |
| ret2libc | posible | ret2libc/one_gadget: no verificado (native) (sin leak/gadget aplicable o timing) |
| mprotect-shellcode | FUNCIONA | VERIFIED off=64 extra_pad=8 mprotect=0x411cd0 stage=0x4ad000 |
| tcache-dup | posible | no verificado (native): menu no reconocido, ninguna GOT alineada, o el double-free no aplica asi |

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
[combo] mprotect()+shellcode -> SHELL VERIFICADA
[combo] tcache-dup: tcache dup -> GOT=system (sandbox)...
[combo] tcache-dup -> no verificado
[fin] combinaciones probadas: srop, rop-chain, ret2libc, mprotect-shellcode, tcache-dup
```

Todo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).