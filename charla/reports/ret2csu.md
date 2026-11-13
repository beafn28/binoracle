## Auto-explotacion de `samples/bin/ret2csu`

> EXPLOIT VERIFICADO: se ejecuto un exploit (ret2csu) en sandbox y se consiguio el objetivo.

### Contexto del binario (defensas detectadas)

- arquitectura: **x86 64-bit**
- mitigaciones: **NX ON · PIE off · canary off**
- funcion gift `win()`: **si**
- sinks peligrosos: system, read
- **por que la tecnica elegida**: sin pop rsi/pop rdx propios -> los dos gadgets universales de __libc_csu_init fijan rdi/rsi/rdx y hacen una llamada indirecta

- hallazgos verificados: 1

### Combinaciones probadas

| tecnica | resultado | detalle |
|---|---|---|
| ret2win | no | offset=72 win=0x401146 |
| ret2csu | FUNCIONA | VERIFIED mode=win off=72 align=1 g1=0x40118a g2=0x401195 fnptr=0x404028 |
| house-of-spirit | posible | house-of-spirit: no verificado (native) (sin la forma HoS o timing) |
| tcache-stash | posible | tcache stashing: no verificado (native) (sin la forma de practica o timing) |

### Traza
```
[recon] arch=x86 64-bit  NX=true  PIE=false  canary=false
[recon] sinks: system, read
[recon] gadget 'pop rdi': si
[verify] hallazgos verificados por angr: 1
[combo] ret2win: construyendo y verificando en sandbox...
[combo] ret2win -> construido, no verificado
[combo] ret2csu: gadgets universales de __libc_csu_init (sandbox)...
[combo] ret2csu -> SHELL VERIFICADA
[combo] house-of-spirit: chunk falso en tcache -> hijack (sandbox)...
[combo] house-of-spirit -> no verificado
[combo] tcache-stash: stash de smallbin->tcache -> chunk falso stashed (sandbox)...
[combo] tcache-stash -> no verificado
[fin] combinaciones probadas: ret2win, ret2csu, house-of-spirit, tcache-stash
```

Todo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).