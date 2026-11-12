## Auto-explotacion de `samples/bin/csuexec`

> EXPLOIT VERIFICADO: se ejecuto un exploit (srop) en sandbox y se consiguio el objetivo.

### Contexto del binario (defensas detectadas)

- arquitectura: **x86 64-bit**
- mitigaciones: **NX ON · PIE off · canary off**
- funcion gift `win()`: **no**
- sinks peligrosos: read
- **por que la tecnica elegida**: binario pobre en gadgets con gadget syscall + '/bin/sh' -> SROP: un rt_sigreturn restaura TODOS los registros desde un frame forjado y ejecuta execve('/bin/sh')

- hallazgos verificados: 1

### Combinaciones probadas

| tecnica | resultado | detalle |
|---|---|---|
| srop | FUNCIONA | VERIFIED off=72 rax_gadget=0x401156 syscall=0x401158 binsh=0x404020 |

### Traza
```
[recon] arch=x86 64-bit  NX=true  PIE=false  canary=false
[recon] sinks: read
[recon] gadget 'pop rdi': si
[verify] hallazgos verificados por angr: 1
[combo] ret2win: no hay funcion gift -> se omite
[combo] SROP: sigreturn -> execve('/bin/sh') (sandbox)...
[combo] SROP -> SHELL VERIFICADA
[fin] combinaciones probadas: srop
```

Todo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).