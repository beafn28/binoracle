## Auto-explotacion de `samples/bin/uaf`

> EXPLOIT VERIFICADO: se ejecuto un exploit (uaf-funcptr) en sandbox y se consiguio el objetivo.

### Contexto del binario (defensas detectadas)

- arquitectura: **x86 64-bit**
- mitigaciones: **NX ON · PIE off · canary off**
- funcion gift `win()`: **si**
- sinks peligrosos: system, memcpy, read, printf
- **por que la tecnica elegida**: primitiva de heap (UAF/tcache) -> secuestro de puntero/GOT a win()/system

- hallazgos verificados: 3

### Combinaciones probadas

| tecnica | resultado | detalle |
|---|---|---|
| ret2win | no | offset=88 win=0x4011dc |
| ret2csu | posible | ret2csu: no verificado (native) (sin gadgets csu / puntero de funcion / timing) |
| rop-chain | no | no se pudo construir cadena automatica (sin /bin/sh o gadgets suficientes; ret2libc dinamico necesita libc/leak) |
| ret2libc | posible | ret2libc/one_gadget: no verificado (native) (sin leak/gadget aplicable o timing) |
| mprotect-shellcode | posible | mprotect()+shellcode: no verificado (native) (sin mprotect()/buffer fijo conocido, gadgets insuficientes para rdi/rsi/rdx, o forma de entrada distinta) |
| leak-chain | posible | infoleak chaining: no verificado (native) (sin table/<fn>_leak/callback conocidos, sin libc dinamica, o timing) |
| format-string | posible | format-string: no verificado (native) (no aplica printf(user) en bucle o timing) |
| heap-corruption | posible | no se disparo corrupcion con las entradas de prueba |
| heap-shell | no | no aplicable: no se detecto un menu new/free/edit/show en el binario |
| uaf-funcptr | FUNCIONA | VERIFIED win=0x4011dc size=16 opts={'new': 1, 'free': 2, 'trigger': 3, 'write': 4} |

### Traza
```
[recon] arch=x86 64-bit  NX=true  PIE=false  canary=false
[recon] sinks: system, memcpy, read, printf
[recon] gadget 'pop rdi': no
[verify] hallazgos verificados por angr: 3
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
[combo] format-string: intentando GOT overwrite -> shell (sandbox)...
[combo] format-string -> no verificable (requiere printf en bucle)
[combo] heap: confirmando corrupcion (double-free/overflow) en sandbox...
[combo] heap -> no disparada con entradas de prueba
[combo] heap-shell: tcache poison -> free@GOT=win (sandbox)...
[combo] heap-shell -> no verificado
[combo] uaf-funcptr: UAF reuso de chunk -> funcptr=win (sandbox)...
[combo] uaf-funcptr -> SHELL VERIFICADA
[fin] combinaciones probadas: ret2win, ret2csu, rop-chain, ret2libc, mprotect-shellcode, leak-chain, format-string, heap-corruption, heap-shell, uaf-funcptr
```

Todo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).