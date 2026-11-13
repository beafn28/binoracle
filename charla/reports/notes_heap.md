## Auto-explotacion de `samples/bin/notes_heap`

> EXPLOIT VERIFICADO: se ejecuto un exploit (tcache-dup) en sandbox y se consiguio el objetivo.

### Contexto del binario (defensas detectadas)

- arquitectura: **x86 64-bit**
- mitigaciones: **NX ON · PIE off · canary off**
- funcion gift `win()`: **no**
- sinks peligrosos: read, printf
- **por que la tecnica elegida**: primitiva de heap (UAF/tcache) -> secuestro de puntero/GOT a win()/system

- hallazgos verificados: 2

### Combinaciones probadas

| tecnica | resultado | detalle |
|---|---|---|
| srop | posible | SROP: no verificado (native) (sin pop rax/syscall/'/bin/sh' o timing) |
| rop-chain | no | no se pudo construir cadena automatica (sin /bin/sh o gadgets suficientes; ret2libc dinamico necesita libc/leak) |
| ret2libc | posible | ret2libc/one_gadget: no verificado (native) (sin leak/gadget aplicable o timing) |
| mprotect-shellcode | posible | mprotect()+shellcode: no verificado (native) (sin mprotect()/buffer fijo conocido, gadgets insuficientes para rdi/rsi/rdx, o forma de entrada distinta) |
| leak-chain | posible | infoleak chaining: no verificado (native) (sin table/<fn>_leak/callback conocidos, sin libc dinamica, o timing) |
| format-string | posible | format-string: no verificado (native) (no aplica printf(user) en bucle o timing) |
| heap-corruption | posible | no se disparo corrupcion con las entradas de prueba |
| tcache-dup | FUNCIONA | VERIFIED got=free(0x404000) system=0x155555258750 |

### Traza
```
[recon] arch=x86 64-bit  NX=true  PIE=false  canary=false
[recon] sinks: read, printf
[recon] gadget 'pop rdi': no
[verify] hallazgos verificados por angr: 2
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
[combo] format-string: intentando GOT overwrite -> shell (sandbox)...
[combo] format-string -> no verificable (requiere printf en bucle)
[combo] heap: confirmando corrupcion (double-free/overflow) en sandbox...
[combo] heap -> no disparada con entradas de prueba
[combo] tcache-dup: tcache dup -> GOT=system (sandbox)...
[combo] tcache-dup -> SHELL VERIFICADA
[fin] combinaciones probadas: srop, rop-chain, ret2libc, mprotect-shellcode, leak-chain, format-string, heap-corruption, tcache-dup
```

Todo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).