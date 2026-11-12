## Auto-explotacion de `samples/bin/botcake`

> EXPLOIT VERIFICADO: se ejecuto un exploit (house-of-botcake) en sandbox y se consiguio el objetivo.

### Contexto del binario (defensas detectadas)

- arquitectura: **x86 64-bit**
- mitigaciones: **NX ON · PIE off · canary off**
- funcion gift `win()`: **si**
- sinks peligrosos: system, read
- **por que la tecnica elegida**: doble-free A,A enrutado por la unsorted bin -> esquiva el chequeo de key del tcache -> chunks solapados

- hallazgos verificados: 1

### Combinaciones probadas

| tecnica | resultado | detalle |
|---|---|---|
| ret2win | no | offset=44 win=0x401176 |
| ret2csu | posible | ret2csu: no verificado (native) (sin gadgets csu / puntero de funcion / timing) |
| rop-chain | no | no se pudo construir cadena automatica (sin /bin/sh o gadgets suficientes; ret2libc dinamico necesita libc/leak) |
| ret2libc | posible | ret2libc/one_gadget: no verificado (native) (sin leak/gadget aplicable o timing) |
| mprotect-shellcode | posible | mprotect()+shellcode: no verificado (native) (sin mprotect()/buffer fijo conocido, gadgets insuficientes para rdi/rsi/rdx, o forma de entrada distinta) |
| leak-chain | posible | infoleak chaining: no verificado (native) (sin table/<fn>_leak/callback conocidos, sin libc dinamica, o timing) |
| heap-corruption | posible | no se disparo corrupcion con las entradas de prueba |
| heap-shell | no | no aplicable: no se detecto un menu new/free/edit/show en el binario |
| uaf-funcptr | posible | no verificado (native): menu no reconocido, tamano de chunk distinto, o UAF no explotable asi |
| house-of-spirit | posible | house-of-spirit: no verificado (native) (sin la forma HoS o timing) |
| house-of-botcake | FUNCIONA | VERIFIED a=0x405aa0 handler=0x404170 win=0x401176 |

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
[combo] heap: confirmando corrupcion (double-free/overflow) en sandbox...
[combo] heap -> no disparada con entradas de prueba
[combo] heap-shell: tcache poison -> free@GOT=win (sandbox)...
[combo] heap-shell -> no verificado
[combo] uaf-funcptr: UAF reuso de chunk -> funcptr=win (sandbox)...
[combo] uaf-funcptr -> no verificado
[combo] house-of-spirit: chunk falso en tcache -> hijack (sandbox)...
[combo] house-of-spirit -> no verificado
[combo] house-of-botcake: doble-free via unsorted -> tcache poison (sandbox)...
[combo] house-of-botcake -> SHELL VERIFICADA
[fin] combinaciones probadas: ret2win, ret2csu, rop-chain, ret2libc, mprotect-shellcode, leak-chain, heap-corruption, heap-shell, uaf-funcptr, house-of-spirit, house-of-botcake
```

Todo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).