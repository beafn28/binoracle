## Auto-explotacion de `samples/bin/hoc`

> EXPLOIT VERIFICADO: se ejecuto un exploit (house-of-corrosion) en sandbox y se consiguio el objetivo.

### Contexto del binario (defensas detectadas)

- arquitectura: **x86 64-bit**
- mitigaciones: **NX ON · PIE off · canary off**
- funcion gift `win()`: **si**
- sinks peligrosos: system, read
- **por que la tecnica elegida**: global_max_fast corrompido -> un free() grande se trata como fastbin con indice sin cota -> escritura en una direccion elegida

- hallazgos verificados: 1

### Combinaciones probadas

| tecnica | resultado | detalle |
|---|---|---|
| ret2win | no | offset=24 win=0x401156 |
| ret2csu | posible | ret2csu: no verificado (native) (sin gadgets csu / puntero de funcion / timing) |
| rop-chain | no | no se pudo construir cadena automatica (sin /bin/sh o gadgets suficientes; ret2libc dinamico necesita libc/leak) |
| ret2libc | posible | ret2libc/one_gadget: no verificado (native) (sin leak/gadget aplicable o timing) |
| mprotect-shellcode | posible | mprotect()+shellcode: no verificado (native) (sin mprotect()/buffer fijo conocido, gadgets insuficientes para rdi/rsi/rdx, o forma de entrada distinta) |
| leak-chain | posible | infoleak chaining: no verificado (native) (sin table/<fn>_leak/callback conocidos, sin libc dinamica, o timing) |
| heap-shell | no | no aplicable: no se detecto un menu new/free/edit/show en el binario |
| fastbin-dup | posible | fastbin-dup: no verificado (native) (sin la forma de practica o timing) |
| house-of-corrosion | FUNCIONA | VERIFIED idx=16386 S=0x40040 heap=0x404060 hook=0x428060 win=0x401156 |

### Traza
```
[recon] arch=x86 64-bit  NX=true  PIE=false  canary=false
[recon] sinks: system, read
[recon] gadget 'pop rdi': no
[verify] hallazgos verificados por angr: 1
[combo] ret2win: construyendo y verificando en sandbox...
[combo] ret2win -> construido, no verificado
[combo] ret2csu: gadgets universales de __libc_csu_init (sandbox)...
[combo] ret2csu -> no verificado
[combo] cadena ROP: intentando construir...
[combo] cadena ROP -> no automatica
[combo] ret2libc con leak (fuga libc -> system, sandbox)...
[combo] ret2libc -> no aplicable/verificable
[combo] mprotect()+shellcode: ROP a mprotect() sobre un buffer fijo -> shellcode real...
[combo] mprotect()+shellcode -> no aplicable/verificable
[combo] infoleak chaining: OOB read -> libc_base -> write-what-where -> shell...
[combo] infoleak chaining -> no aplicable/verificable
[combo] heap-shell: tcache poison -> free@GOT=win (sandbox)...
[combo] heap-shell -> no verificado
[combo] fastbin-dup: doble-free A,B,A (pre-safe-linking) -> fd envenenado (sandbox)...
[combo] fastbin-dup -> no verificado
[combo] house-of-corrosion: global_max_fast corrompido -> indice de fastbin sin cota (sandbox)...
[combo] house-of-corrosion -> SHELL VERIFICADA
[fin] combinaciones probadas: ret2win, ret2csu, rop-chain, ret2libc, mprotect-shellcode, leak-chain, heap-shell, fastbin-dup, house-of-corrosion
```

Todo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).