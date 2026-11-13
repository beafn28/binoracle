## Auto-explotacion de `samples/bin/ret2libc`

> EXPLOIT VERIFICADO: se ejecuto un exploit (ret2libc) en sandbox y se consiguio el objetivo.

### Contexto del binario (defensas detectadas)

- arquitectura: **x86 64-bit**
- mitigaciones: **NX ON · PIE off · canary off**
- funcion gift `win()`: **no**
- sinks peligrosos: read, printf
- **por que la tecnica elegida**: sin win(): fuga de libc (puts@GOT) -> base -> system('/bin/sh')

- hallazgos verificados: 2

### Combinaciones probadas

| tecnica | resultado | detalle |
|---|---|---|
| srop | posible | SROP: no verificado (native) (sin pop rax/syscall/'/bin/sh' o timing) |
| rop-chain | no | no se pudo construir cadena automatica (sin /bin/sh o gadgets suficientes; ret2libc dinamico necesita libc/leak) |
| ret2libc | FUNCIONA | VERIFIED off=88 leak=0x7ffff7c87cc0 base=0x7ffff7c00000 system=0x7ffff7c58750 |
| format-string | posible | format-string: no verificado (native) (no aplica printf(user) en bucle o timing) |

### Traza
```
[recon] arch=x86 64-bit  NX=true  PIE=false  canary=false
[recon] sinks: read, printf
[recon] gadget 'pop rdi': si
[verify] hallazgos verificados por angr: 2
[combo] ret2win: no hay funcion gift -> se omite
[combo] SROP: sigreturn -> execve('/bin/sh') (sandbox)...
[combo] SROP -> no verificado
[combo] cadena ROP: intentando construir...
[combo] cadena ROP -> no automatica
[combo] ret2libc con leak (fuga libc -> system, sandbox)...
[combo] ret2libc -> SHELL VERIFICADA
[combo] format-string: intentando GOT overwrite -> shell (sandbox)...
[combo] format-string -> no verificable (requiere printf en bucle)
[fin] combinaciones probadas: srop, rop-chain, ret2libc, format-string
```

Todo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).