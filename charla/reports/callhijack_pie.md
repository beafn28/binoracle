## Auto-explotacion de `samples/bin/callhijack_pie`

> EXPLOIT VERIFICADO: se ejecuto un exploit (ret2win) en sandbox y se consiguio el objetivo.

### Contexto del binario (defensas detectadas)

- arquitectura: **x86 64-bit**
- mitigaciones: **NX ON · PIE ON · canary off**
- funcion gift `win()`: **si**
- sinks peligrosos: system, gets, printf
- **por que la tecnica elegida**: win() presente con PIE -> se resuelve la base en sandbox

- hallazgos verificados: 2

### Combinaciones probadas

| tecnica | resultado | detalle |
|---|---|---|
| ret2win | FUNCIONA | VERIFIED off=72 base=0x555555554000 win=0x555555555179 |
| format-string | posible | format-string: no verificado (native) (no aplica printf(user) en bucle o timing) |

### Traza
```
[recon] arch=x86 64-bit  NX=true  PIE=true  canary=false
[recon] sinks: system, gets, printf
[recon] gadget 'pop rdi': no
[verify] hallazgos verificados por angr: 2
[combo] ret2win: construyendo y verificando en sandbox... (PIE)
[combo] ret2win (PIE) -> FUNCIONA (verificado)
[combo] format-string: intentando GOT overwrite -> shell (sandbox)...
[combo] format-string -> no verificable (requiere printf en bucle)
[fin] combinaciones probadas: ret2win, format-string
```

Todo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).