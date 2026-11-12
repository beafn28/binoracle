## Auto-explotacion de `samples/bin/srop`

> EXPLOIT VERIFICADO: se ejecuto un exploit (srop) en sandbox y se consiguio el objetivo.

### Contexto del binario (defensas detectadas)

- arquitectura: **x86 64-bit**
- mitigaciones: **NX ON · PIE off · canary ON**
- funcion gift `win()`: **no**
- sinks peligrosos: read
- **por que la tecnica elegida**: binario pobre en gadgets con gadget syscall + '/bin/sh' -> SROP: un rt_sigreturn restaura TODOS los registros desde un frame forjado y ejecuta execve('/bin/sh')

- hallazgos verificados: 0

### Combinaciones probadas

| tecnica | resultado | detalle |
|---|---|---|
| srop | FUNCIONA | VERIFIED off=72 rax_gadget=0x41905b syscall=0x4017e9 binsh=0x4aa0d0 |
| tcache-dup | posible | no verificado (native): menu no reconocido, ninguna GOT alineada, o el double-free no aplica asi |

### Traza
```
[recon] arch=x86 64-bit  NX=true  PIE=false  canary=true
[recon] sinks: read
[recon] gadget 'pop rdi': si
[verify] hallazgos verificados por angr: 0
[combo] ret2win: no hay funcion gift -> se omite
[combo] SROP: sigreturn -> execve('/bin/sh') (sandbox)...
[combo] SROP -> SHELL VERIFICADA
[combo] tcache-dup: tcache dup -> GOT=system (sandbox)...
[combo] tcache-dup -> no verificado
[fin] combinaciones probadas: srop, tcache-dup
```

Todo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).