## Auto-explotacion de `samples/bin/ropme_pie`

> EXPLOIT VERIFICADO: se ejecuto un exploit (rop-chain) en sandbox y se consiguio el objetivo.

### Contexto del binario (defensas detectadas)

- arquitectura: **x86 64-bit**
- mitigaciones: **NX ON · PIE ON · canary ON**
- funcion gift `win()`: **no**
- sinks peligrosos: read, printf
- **por que la tecnica elegida**: sin win()/system directo -> cadena ROP execve por syscall (PIE: base resuelta en sandbox)

- hallazgos verificados: 0

### Combinaciones probadas

| tecnica | resultado | detalle |
|---|---|---|
| rop-chain | FUNCIONA |  -> SHELL verificada |
| format-string | posible | format-string: no verificado (native) (no aplica printf(user) en bucle o timing) |
| tcache-dup | posible | no verificado (native): menu no reconocido, ninguna GOT alineada, o el double-free no aplica asi |

### Traza
```
[recon] arch=x86 64-bit  NX=true  PIE=true  canary=true
[recon] sinks: read, printf
[recon] gadget 'pop rdi': si
[verify] hallazgos verificados por angr: 0
[combo] ret2win: no hay funcion gift -> se omite
[combo] cadena ROP: intentando construir... (PIE)
[combo] cadena ROP -> SHELL VERIFICADA
[combo] format-string: intentando GOT overwrite -> shell (sandbox)...
[combo] format-string -> no verificable (requiere printf en bucle)
[combo] tcache-dup: tcache dup -> GOT=system (sandbox)...
[combo] tcache-dup -> no verificado
[fin] combinaciones probadas: rop-chain, format-string, tcache-dup
```

Todo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).