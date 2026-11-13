## Auto-explotacion de `samples/bin/leakchain`

> EXPLOIT VERIFICADO: se ejecuto un exploit (leak-chain) en sandbox y se consiguio el objetivo.

### Contexto del binario (defensas detectadas)

- arquitectura: **x86 64-bit**
- mitigaciones: **NX ON · PIE off · canary off**
- funcion gift `win()`: **no**
- sinks peligrosos: printf
- **por que la tecnica elegida**: sin win()/system directo -> un mismo bug indexable usado como leak (libc_base) y como escritura (hijack de puntero), encadenados en una sola ejecucion

- hallazgos verificados: 1

### Combinaciones probadas

| tecnica | resultado | detalle |
|---|---|---|
| srop | posible | SROP: no verificado (native) (sin pop rax/syscall/'/bin/sh' o timing) |
| rop-chain | no | no se pudo construir cadena automatica (sin /bin/sh o gadgets suficientes; ret2libc dinamico necesita libc/leak) |
| ret2libc | posible | ret2libc/one_gadget: no verificado (native) (sin leak/gadget aplicable o timing) |
| mprotect-shellcode | posible | mprotect()+shellcode: no verificado (native) (sin mprotect()/buffer fijo conocido, gadgets insuficientes para rdi/rsi/rdx, o forma de entrada distinta) |
| leak-chain | FUNCIONA | VERIFIED leak_fn=printf leaked=0x7ffff7c60100 libc_base=0x7ffff7c00000 system=0x7ffff7c58750 idx_leak=-6 idx_cb=16 |
| format-string | posible | format-string: no verificado (native) (no aplica printf(user) en bucle o timing) |

### Traza
```
[recon] arch=x86 64-bit  NX=true  PIE=false  canary=false
[recon] sinks: printf
[recon] gadget 'pop rdi': no
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
[combo] infoleak chaining -> SHELL VERIFICADA
[combo] format-string: intentando GOT overwrite -> shell (sandbox)...
[combo] format-string -> no verificable (requiere printf en bucle)
[fin] combinaciones probadas: srop, rop-chain, ret2libc, mprotect-shellcode, leak-chain, format-string
```

Todo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).