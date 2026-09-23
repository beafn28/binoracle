# Referencias externas (fuentes autoritativas)

Enlaces a material de referencia sobre reversing y explotacion de binarios. binoracle NO
copia su contenido: estos cheat sheets son sintesis propia; aqui apuntamos a las fuentes
originales para profundizar. Consulta siempre la version mas reciente (glibc/mitigaciones
cambian con el tiempo).

## Notas y libros de tecnica
- ir0nstone / Binary Exploitation Notes — ROP, format string, heap/tcache, safe-linking,
  one_gadget, GOT overwrite: https://ir0nstone.gitbook.io/notes
- Practical CTF (J. Woltjer) — ret2libc, stack, heap, workflow con pwntools:
  https://book.jorianwoltjer.com/binary-exploitation
- Nightmare (guyinatuxedo) — curso por retos reales de CTF, stack->heap->kernel:
  https://guyinatuxedo.github.io
- CTF101 pwn — introduccion a overflow, ROP, format string:
  https://ctf101.org/binary-exploitation/overview/

## ROP avanzado y bypasses
- ir0nstone SROP: https://ir0nstone.gitbook.io/notes/binexp/stack/syscalls/sigreturn-oriented-programming-srop
- ir0nstone ret2csu: https://ir0nstone.gitbook.io/notes/binexp/stack/ret2csu
- ir0nstone stack pivoting: https://ir0nstone.gitbook.io/notes/binexp/stack/stack-pivoting
- Practical CTF ret2dlresolve: https://book.jorianwoltjer.com/binary-exploitation/return-oriented-programming-rop/ret2dlresolve
- HackTricks (protecciones y bypasses): https://hacktricks.wiki/en/binary-exploitation/
- n132 Guide of Seccomp in CTF: https://n132.github.io/2022/07/03/Guide-of-Seccomp-in-CTF.html
- pwnable.tw orw (ORW clasico): reto de referencia para open/read/write shellcode.

## Heap glibc y FSOP
- how2heap (shellphish) — PoC ejecutables de cada tecnica house-of-* y bins, por version de
  glibc: https://github.com/shellphish/how2heap
- angry-FSROP (kylebot) — bypass del vtable check en structs FILE:
  https://blog.kylebot.net/2022/10/22/angry-FSROP/
- House of Apple 2 (writeup) — FSOP via _wide_data en glibc 2.35+:
  https://ian.nl/blog/htb-love-letter-house-of-apple-fsop
- Deep Dive into FSOP (Niftic): https://niftic.ca/posts/fsop/
- AngelBoy - Play with FILE Structure (fundacional):
  https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique
- 0x434b - Overview of glibc heap exploitation:
  https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/

## GOT / PLT / dynamic linking
- MaskRay - All about the PLT: https://maskray.me/blog/2021-09-19-all-about-procedure-linkage-table
- syst3mfailure - ret2dl_resolve x64: https://syst3mfailure.io/ret2dl_resolve/
- 4xura - Hijack libc internal GOT/PLT as RCE:
  https://4xura.com/binex/pwn-got-hijack-libcs-internal-got-plt-as-rce-primitives/

## Kernel pwn
- CTF Wiki (kernel): https://ctf-wiki.mahaloz.re/pwn/linux/kernel/
- lkmidas — Learning Linux Kernel Exploitation (serie):
  https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/
- lkmidas — modprobe_path:
  https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/
- n132 — Introduction of Kernel Pwn (stack):
  https://n132.github.io/2022/05/16/Introduction-of-Kernel-Pwn-Stack.html
- HeapLAB / max kamper — tcache, fastbin, unsorted, hooks (curso):
  referencia frecuente en la comunidad (buscar "HeapLAB").
- glibc source (malloc/malloc.c) — la verdad ultima del asignador:
  https://elixir.bootlin.com/glibc/latest/source/malloc/malloc.c

## Browser / V8
- ir0nstone browser exploitation (oob-v8):
  https://ir0nstone.gitbook.io/notes/binexp/browser-exploitation/ctf-2019-oob-v8/the-challenge
- addrof/fakeobj explicados (TrustFoundry):
  https://trustfoundry.net/2025/03/28/browser-exploitation-basics-explaining-the-addrof-and-fakeobj-primitives/
- faith - *CTF oob-v8 en profundidad: https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/

## Windows exploit dev
- cranelab exploit-development: https://github.com/cranelab/exploit-development
- CyberArk - Modern Windows memory corruption (stack):
  https://www.cyberark.com/resources/threat-research-blog/a-modern-exploration-of-windows-memory-corruption-exploits-part-i-stack-overflows
- mona.py (Corelan) para ROP/SEH en Immunity/WinDbg.

## ARM / MIPS
- CTF Wiki arm_rop: https://ctf-wiki.mahaloz.re/pwn/linux/arm/arm_rop/
- CTF Recipes AArch64 calling convention: https://www.ctfrecipes.com/pwn/architectures/aarch64/calling-convention
- HackTricks ret2syscall arm64: https://hacktricks.wiki/en/binary-exploitation/rop-return-oriented-programing/rop-syscall-execv/ret2syscall-arm64.html
- easy-linux-pwn (xairy, multi-arch): https://github.com/xairy/easy-linux-pwn

## Anti-debug / reversing
- yo-yo-yo-jbo anti_debugging_intro: https://github.com/yo-yo-yo-jbo/anti_debugging_intro
- UPX: https://upx.github.io  (upx -d para desempaquetar)

## Exit handlers / race / macOS
- Abusing exit handlers + pointer mangling (binholic):
  https://m101.github.io/binholic/2017/05/20/notes-on-abusing-exit-handlers.html
- nobodyisnobody - code execution on last libc (exit funcs, FSOP):
  https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc
- HackTricks WWW2Exec atexit:
  https://hacktricks.wiki/en/binary-exploitation/arbitrary-write-2-exec/www2exec-atexit.html
- userfaultfd + setxattr heap spray (ETenal):
  https://etenal.me/archives/1336
- Will's Root - userfaultfd race kernel UAF:
  https://www.willsroot.io/2020/10/cuctf-2020-hotrod-kernel-writeup.html
- HackTricks iOS exploiting: https://hacktricks.wiki/en/binary-exploitation/ios-exploiting/index.html
- Anatomy of a Mach-O (PAC/code signing):
  https://oliviagallucci.com/the-anatomy-of-a-mach-o-structure-code-signing-and-pac/

## Practica
- pwn.college — curso estructurado (ASU), desde asm hasta kernel:
  https://pwn.college
- ROP Emporium — retos centrados solo en ROP, por arquitectura:
  https://ropemporium.com
- pwnable.kr / pwnable.tw — retos clasicos de pwn.
- picoCTF — retos introductorios.

## Tablas y utilidades de referencia
- syscall table x86-64 (Chromium/Ryan Chapman):
  https://filippo.io/linux-syscall-table/  y  https://syscall.sh
- libc database (identificar libc por offsets filtrados): https://libc.rip  y
  https://github.com/niklasb/libc-database
- pwninit (parchear binario con su libc/loader): https://github.com/io12/pwninit
- pwntools docs (ELF, ROP, fmtstr_payload, shellcraft, cyclic):
  https://docs.pwntools.com
- GTFOBins (binarios SUID/sudo para escalada, util tras conseguir ejecucion):
  https://gtfobins.github.io

## Notas de version (glibc) que afectan a la explotacion
- 2.26: aparece tcache.
- 2.29: tcache key check (mitiga algunos double-free en el mismo bin).
- 2.32: safe-linking (fd = (pos>>12) ^ ptr) en tcache/fastbins; necesita heap leak.
- 2.34: eliminados __malloc_hook / __free_hook / __realloc_hook -> usar FSOP / otras rutas.
- 2.35+: cambios en _IO_FILE vtable checks; FSOP moderno (House of Apple, etc.).
