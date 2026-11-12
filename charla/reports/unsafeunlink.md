## Auto-explotacion de `samples/bin/unsafeunlink`

> EXPLOIT VERIFICADO: se ejecuto un exploit (unsafe-unlink) en sandbox y se consiguio el objetivo.

### Contexto del binario (defensas detectadas)

- arquitectura: **x86 64-bit**
- mitigaciones: **NX ON · PIE off · canary off**
- funcion gift `win()`: **si**
- sinks peligrosos: system, read
- **por que la tecnica elegida**: fd/bk forjados satisfacen el chequeo >=2.3.4 (FD->bk==P && BK->fd==P) -> unlink() deja un puntero apuntando cerca de si mismo

- hallazgos verificados: 1

### Combinaciones probadas

| tecnica | resultado | detalle |
|---|---|---|
| ret2win | no | offset=16 win=0x401166 |
| ret2csu | posible | ret2csu: no verificado (native) (sin gadgets csu / puntero de funcion / timing) |
| rop-chain | no | no se pudo construir cadena automatica (sin /bin/sh o gadgets suficientes; ret2libc dinamico necesita libc/leak) |
| ret2libc | posible | ret2libc/one_gadget: no verificado (native) (sin leak/gadget aplicable o timing) |
| mprotect-shellcode | posible | mprotect()+shellcode: no verificado (native) (sin mprotect()/buffer fijo conocido, gadgets insuficientes para rdi/rsi/rdx, o forma de entrada distinta) |
| leak-chain | posible | infoleak chaining: no verificado (native) (sin table/<fn>_leak/callback conocidos, sin libc dinamica, o timing) |
| house-of-force | posible | house-of-force: no verificado (native) (sin la forma HoF o glibc >=2.29 lo mitiga) |
| house-of-spirit | posible | house-of-spirit: no verificado (native) (sin la forma HoS o timing) |
| house-of-einherjar | posible | house-of-einherjar: no verificado (native) (sin la forma HoE o timing) |
| unsafe-unlink | FUNCIONA | VERIFIED chunkptr=0x408050 handler=0x408060 win=0x401166 |

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
[combo] house-of-force -> no verificado
[combo] house-of-spirit: chunk falso en tcache -> hijack (sandbox)...
[combo] house-of-spirit -> no verificado
[combo] house-of-einherjar: consolidacion hacia atras -> hijack (sandbox)...
[combo] house-of-einherjar -> no verificado
[combo] unsafe-unlink: bypass del chequeo 2.3.4+ -> ptr cerca de si mismo (sandbox)...
[combo] unsafe-unlink -> SHELL VERIFICADA
[fin] combinaciones probadas: ret2win, ret2csu, rop-chain, ret2libc, mprotect-shellcode, leak-chain, house-of-force, house-of-spirit, house-of-einherjar, unsafe-unlink
```

Todo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).