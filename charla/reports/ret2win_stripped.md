## Auto-explotacion de `samples/bin/ret2win.stripped`

> EXPLOIT VERIFICADO: se ejecuto un exploit (ret2win) en sandbox y se consiguio el objetivo.

### Contexto del binario (defensas detectadas)

- arquitectura: **x86 64-bit**
- mitigaciones: **NX ON · PIE off · canary off**
- funcion gift `win()`: **si**
- sinks peligrosos: system, gets, printf
- **por que la tecnica elegida**: win() presente sin canary -> retorno directo a win() (direccion fija)

- hallazgos verificados: 3

### Combinaciones probadas

| tecnica | resultado | detalle |
|---|---|---|
| ret2win | FUNCIONA | offset=72 win=0x401176 |
| format-string | posible | format-string: no verificado (native) (no aplica printf(user) en bucle o timing) |

### Traza
```
[recon] arch=x86 64-bit  NX=true  PIE=false  canary=false
[recon] sinks: system, gets, printf
[recon] gadget 'pop rdi': no
[verify] hallazgos verificados por angr: 3
[combo] ret2win: construyendo y verificando en sandbox...
[combo] ret2win -> FUNCIONA (verificado)
[combo] format-string: intentando GOT overwrite -> shell (sandbox)...
[combo] format-string -> no verificable (requiere printf en bucle)
[fin] combinaciones probadas: ret2win, format-string
```

Todo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).