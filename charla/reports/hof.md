## Auto-explotacion de `samples/bin/hof`

> EXPLOIT VERIFICADO: se ejecuto un exploit (house-of-force) en sandbox y se consiguio el objetivo.

### Contexto del binario (defensas detectadas)

- arquitectura: **x86 64-bit**
- mitigaciones: **NX ON · PIE off · canary off**
- funcion gift `win()`: **si**
- sinks peligrosos: system, read
- **por que la tecnica elegida**: asignador con el carve de top-chunk pre-2.29 -> top-chunk corrompido a un tamano enorme desplaza `top` a una direccion elegida

- hallazgos verificados: 1

### Combinaciones probadas

| tecnica | resultado | detalle |
|---|---|---|
| ret2win | no | offset=32 win=0x401166 |
| ret2csu | posible | ret2csu: no verificado (native) (sin gadgets csu / puntero de funcion / timing) |
| rop-chain | no | no se pudo construir cadena automatica (sin /bin/sh o gadgets suficientes; ret2libc dinamico necesita libc/leak) |
| ret2libc | posible | ret2libc/one_gadget: no verificado (native) (sin leak/gadget aplicable o timing) |
| mprotect-shellcode | posible | mprotect()+shellcode: no verificado (native) (sin mprotect()/buffer fijo conocido, gadgets insuficientes para rdi/rsi/rdx, o forma de entrada distinta) |
| leak-chain | posible | infoleak chaining: no verificado (native) (sin table/<fn>_leak/callback conocidos, sin libc dinamica, o timing) |
| house-of-force | FUNCIONA | VERIFIED need_a=0x30 heap=0x404060 handler=0x404040 win=0x401166 |
| house-of-spirit | posible | house-of-spirit: no verificado (native) (sin la forma HoS o timing) |
| house-of-einherjar | posible | house-of-einherjar: no verificado (native) (sin la forma HoE o timing) |

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
[combo] house-of-force: top-chunk pre-2.29 -> top arbitrario -> hijack (sandbox)...
[combo] house-of-force -> SHELL VERIFICADA
[combo] house-of-spirit: chunk falso en tcache -> hijack (sandbox)...
[combo] house-of-spirit -> no verificado
[combo] house-of-einherjar: consolidacion hacia atras -> hijack (sandbox)...
[combo] house-of-einherjar -> no verificado
[fin] combinaciones probadas: ret2win, ret2csu, rop-chain, ret2libc, mprotect-shellcode, leak-chain, house-of-force, house-of-spirit, house-of-einherjar
```

Todo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).