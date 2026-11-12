## Auto-explotacion de `samples/bin/canleak`

> EXPLOIT VERIFICADO: se ejecuto un exploit (canary-bypass) en sandbox y se consiguio el objetivo.

### Contexto del binario (defensas detectadas)

- arquitectura: **x86 64-bit**
- mitigaciones: **NX ON · PIE off · canary ON**
- funcion gift `win()`: **si**
- sinks peligrosos: system, read, printf
- **por que la tecnica elegida**: canary ACTIVO + win() + buffer impreso -> fuga del canary, reescritura y overflow a win()

- hallazgos verificados: 2

### Combinaciones probadas

| tecnica | resultado | detalle |
|---|---|---|
| ret2csu | posible | ret2csu: no verificado (native) (sin gadgets csu / puntero de funcion / timing) |
| rop-chain | no | no se pudo construir cadena automatica (sin /bin/sh o gadgets suficientes; ret2libc dinamico necesita libc/leak) |
| ret2libc | posible | ret2libc/one_gadget: no verificado (native) (sin leak/gadget aplicable o timing) |
| mprotect-shellcode | posible | mprotect()+shellcode: no verificado (native) (sin mprotect()/buffer fijo conocido, gadgets insuficientes para rdi/rsi/rdx, o forma de entrada distinta) |
| leak-chain | posible | infoleak chaining: no verificado (native) (sin table/<fn>_leak/callback conocidos, sin libc dinamica, o timing) |
| format-string | posible | format-string: no verificado (native) (no aplica printf(user) en bucle o timing) |
| canary-bypass | FUNCIONA | VERIFIED bufsz=72 rbpgap=8 align=ret canary=0x62e9ce843e390100 win=0x401176 |

### Traza
```
[recon] arch=x86 64-bit  NX=true  PIE=false  canary=true
[recon] sinks: system, read, printf
[recon] gadget 'pop rdi': no
[verify] hallazgos verificados por angr: 2
[combo] ret2win: canary activo -> el overflow lineal se omite, se usa el bypass por fuga (combo canary)
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
[combo] canary: fuga del canary + overflow a win (sandbox)...
[combo] canary -> SHELL VERIFICADA
[fin] combinaciones probadas: ret2csu, rop-chain, ret2libc, mprotect-shellcode, leak-chain, format-string, canary-bypass
```

Todo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).