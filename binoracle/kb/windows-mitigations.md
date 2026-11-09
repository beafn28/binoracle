# Windows: mitigaciones de explotacion y bypasses (cheat sheet)

Antes de un exploit en Windows, identifica que mitigaciones tiene el binario/proceso
(`dumpbin /headers`, `Get-ProcessMitigation`, o mira las flags de CFG/CET en el PE) y el kernel
(VBS/HVCI on?). Aqui va el mapa mitigacion -> que para -> como se saltea, user y kernel.
Sintetizado de nccgroup/exploit_mitigations. Complementa [[windows-exploit]] y [[pe-dll]].

## User-mode
| Mitigacion | Que impide | Bypass tipico |
|------------|-----------|---------------|
| **DEP** | ejecutar codigo en paginas de datos (stack/heap) | **ROP** para llamar VirtualProtect/VirtualAlloc y marcar RX; luego saltar al shellcode |
| **ASLR** | direcciones fijas de modulos | **info leak** de una direccion (un puntero filtrado, un modulo sin /DYNAMICBASE); brute force en 32-bit |
| **High-Entropy ASLR** | ASLR reforzado en 64-bit | necesitas leak si o si; no hay brute practico |
| **CFG** | call/jmp indirectos a destinos no validos | punteros de funcion NO protegidos (JIT, callbacks), type confusion, o retornos (CFG no cubre `ret` -> ROP sigue viable sin CET) |
| **XFG** | CFG por hash del prototipo de la funcion | predecir/colisionar el hash del tipo; usar un gadget con la misma firma |
| **CET Shadow Stack** | ROP (protege direcciones de retorno) | data-only / JOP; solo en CPUs recientes; combinar con bugs que no toquen `ret` |
| **ACG** | asignar codigo dinamico (VirtualAlloc RWX) | **code reuse** (ROP/gadgets ya presentes); no puedes meter shellcode nuevo, reusa el existente |
| **CIG** | cargar codigo sin firmar | **BYOVD**/DLL firmada pero vulnerable; secuestro de una libreria firmada |
| **SEHOP** | pisar el handler de SEH | heap spray + cadena SEH valida; o rutas que no dependan de SEH |
| **LFH / heap cookies** | layout de heap predecible + metadatos | groom del LFH, info leak de la cookie, corrupcion de metadatos con leak |
| **No-Child-Process** | crear subprocesos | actua dentro de un proceso ya existente (inyeccion), no lances hijos |

## Kernel-mode
| Mitigacion | Que impide | Bypass tipico |
|------------|-----------|---------------|
| **kASLR** | base de ntoskrnl/drivers fija | **info leak** de kernel (NtQuerySystemInformation con Medium IL, un driver que filtre punteros) |
| **SMEP** | ejecutar paginas de USER en modo kernel | **ROP en kernel** (pivot + gadgets) o data-only; ajusta el payload para no ejecutar user directo |
| **kCFG** | call indirectos de kernel invalidos | solo se aplica con **Hyper-V/VBS activo**; sin VBS, no estorba; con el, mismas debilidades que CFG |
| **HVCI / VBS** | cargar codigo de kernel sin firmar (integridad por hipervisor) | **BYOVD**: trae un driver FIRMADO pero vulnerable y explotalo (no puedes cargar el tuyo sin firma) |
| **KDP** | corromper estructuras de datos de kernel de solo-lectura | ataca estructuras NO protegidas por KDP; o data-only sobre lo escribible |

## Objetivos y primitivas tipicas (kernel LPE)
- **Token stealing**: copia el `Token` de un proceso SYSTEM (PID 4) al `EPROCESS` del tuyo ->
  SYSTEM. La cadena clasica de Windows (equivalente a commit_creds en Linux).
- **_EX_FAST_REF / previous mode**: manipular `PreviousMode` del thread para R/W de kernel.
- **Arbitrary R/W** via un driver vulnerable (IOCTL) -> escala a token stealing.
- **BYOVD** (Bring Your Own Vulnerable Driver): la via estandar frente a HVCI/CIG hoy.

## Flujo de decision
1. **PE del target**: mira CFG/CET/ACG/CIG activos (`dumpbin`, PE flags). Sin CET -> ROP libre.
2. **DEP siempre**: monta ROP para VirtualProtect. **ASLR**: consigue un leak primero.
3. **ACG/CIG**: olvida meter shellcode nuevo -> todo por reuso de codigo firmado.
4. **Kernel**: VBS/HVCI on -> ve por **BYOVD** (driver firmado vulnerable) + token stealing.
5. **Verifica en una VM** de la MISMA build (los offsets de EPROCESS/Token cambian por version).

Fuente de la taxonomia: nccgroup/exploit_mitigations (windows_mitigations.md). Sintetizado como
mapa de decision; para PoCs por CVE ver colecciones como FULLSHADE/WindowsExploitationResources.
Ver [[windows-exploit]] y [[pe-dll]].
