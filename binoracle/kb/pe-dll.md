# PE / DLL: estructura y analisis (cheat sheet)

Formato de ejecutables y librerias de Windows (Portable Executable). Una .exe y una .dll usan
el MISMO formato PE; la DLL solo tiene el flag IMAGE_FILE_DLL y exporta funciones. binoracle
analiza PE/DLL con radare2 y angr (recon, imports/exports, disasm, gadgets); la ejecucion de
PoC en sandbox es solo ELF Linux.

## Estructura PE
- DOS header (MZ) + DOS stub -> e_lfanew apunta al PE header.
- PE signature "PE\0\0" + COFF File Header (Machine, NumberOfSections, Characteristics).
- Optional Header: ImageBase (base preferida), AddressOfEntryPoint (RVA), SectionAlignment,
  Subsystem (GUI/CUI), DllCharacteristics (aqui viven NX/ASLR/CFG/SEH flags), DataDirectory[].
- Secciones: .text (codigo), .data/.rdata, .idata (imports), .edata (exports), .reloc, .rsrc,
  .tls, .pdata (unwind x64).
- RVA (Relative Virtual Address): offset desde ImageBase. VA = ImageBase + RVA. Para mapear a
  offset de fichero se usa la tabla de secciones (RVA->raw).

## DllCharacteristics (el "checksec" de PE)
- DYNAMIC_BASE (0x40) = ASLR.  NX_COMPAT (0x100) = DEP/NX.
- GUARD_CF (0x4000) = Control Flow Guard (CFG).  NO_SEH (0x400) = sin SEH.
- HIGH_ENTROPY_VA (0x20) = ASLR de 64 bits.  FORCE_INTEGRITY = firma requerida.
- radare2: `rabin2 -I file.dll` los muestra (nx, canary, pic/aslr...).

## Imports (IAT) y Exports (EAT)
- IAT (Import Address Table, .idata): tabla de punteros a funciones de otras DLLs (kernel32,
  ntdll...). El loader la rellena en carga. Analoga a la GOT de ELF. Un hook/overwrite de la
  IAT redirige llamadas.
- Import por nombre o por ordinal (numero). `rabin2 -i file.dll` lista imports.
- EAT (Export Address Table, .edata): funciones que la DLL expone. Por nombre u ordinal.
  `rabin2 -E file.dll` lista exports. Forwarders: un export puede reenviar a otra DLL
  ("NTDLL.RtlAlloc").

## TLS callbacks (ejecucion temprana / anti-debug)
La DataDirectory TLS (.tls) puede tener AddressOfCallBacks: funciones que se ejecutan ANTES
del entry point, en cada attach/detach de hilo. Se usan para anti-debug (detectar debugger al
arrancar) y como truco de packers. Al reversear, revisa SIEMPRE los TLS callbacks, no solo el
entry point. r2: busca la seccion .tls / `rabin2 -H`.

## Relocaciones (.reloc)
Si la DLL no carga en su ImageBase preferida (ASLR o colision), el loader aplica las
relocaciones de .reloc a los punteros absolutos. Con ASLR off, la base es predecible.

## Ejecucion de una DLL
Una DLL no corre sola: la carga un proceso host.
- rundll32.exe file.dll,ExportName    (llama a un export con firma de rundll)
- LoadLibrary + GetProcAddress desde un loader propio.
- regsvr32 file.dll (llama DllRegisterServer, para COM).
- DllMain se ejecuta en LoadLibrary/attach: cuidado, corre codigo al cargar.

## Superficie de ataque tipica (DLL)
- DLL hijacking / search order: si una app carga "foo.dll" sin ruta absoluta, Windows la busca
  por orden (dir de la app, System32, PATH...). Colocar una foo.dll maliciosa antes en el orden
  = ejecucion en el contexto de la app. Ver tambien "phantom DLL" (DLL que la app busca pero no
  existe) y "DLL proxying" (tu DLL reenvia los exports legitimos y anade codigo en DllMain).
- Vulnerabilidades de memoria dentro de un export: overflow/UAF/format-string igual que en ELF,
  pero explotadas contra el proceso host (WinDbg + mona), no ejecutando la DLL suelta.
- Unsafe imports: llamadas a system/WinExec/CreateProcess/LoadLibrary con datos controlados.

## Analisis con herramientas
- radare2 / rizin: `aa`, `afl`, `pdf`, `ii`(imports), `iE`(exports), `iH`(headers). Detecta PE
  automaticamente.
- rabin2: -I (info+mitigaciones), -i (imports), -E (exports), -H (headers), -z (strings).
- PE-bear / CFF Explorer / PEview: inspeccion visual de headers/secciones/IAT/EAT.
- dumpbin /imports /exports /headers (MSVC).  Detect It Easy (DIE) para packers/compilador.
- Ghidra / IDA: decompilacion; angr carga PE via CLE para simbolico.

## En binoracle
`Auditar` sobre una .dll/.exe: r2 hace el recon (imports/exports/funciones/disasm/gadgets/
sinks con fallback IAT), angr prueba alcanzabilidad. La verificacion por EJECUCION de PoC no
aplica a PE (sandbox es ELF Linux x86-64): el exploit se montaria contra el proceso host.
Ver tambien [[windows-exploit]] para SEH/DEP/ROP en Windows.
