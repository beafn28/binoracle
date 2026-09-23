# Referencias externas (biblioteca de fuentes)

Material de referencia sobre reversing y explotacion de binarios. Los cheat sheets de binoracle
son sintesis propia; esta pagina apunta a las fuentes originales para profundizar. Las tecnicas
de heap/FSOP/mitigaciones dependen de la version de glibc/kernel: verifica siempre contra la
version del objetivo.

## Fundamentos y papers clasicos
- Aleph One - "Smashing the Stack for Fun and Profit" (Phrack 49): el paper fundacional del
  stack overflow. http://phrack.org/issues/49/14.html
- Nergal - "The advanced return-into-lib(c) exploits" (Phrack 58): ret2libc encadenado.
  http://phrack.org/issues/58/4.html
- Solar Designer - return-to-libc original (Bugtraq 1997).
- "Once upon a free()" (Phrack 57): explotacion de heap clasica (unlink).
  http://phrack.org/issues/57/9.html
- blackngel - "Malloc Des-Maleficarum" (Phrack 66): houses clasicas del heap.
  http://phrack.org/issues/66/10.html
- System V AMD64 ABI (convencion de llamada, stack layout): https://gitlab.com/x86-psABIs/x86-64-ABI
- Felix Cloutier - x86/x64 instruction reference: https://www.felixcloutier.com/x86/
- Eli Bendersky - "How dynamic linking works" / PIC & PLT:
  https://eli.thegreenplace.net/2011/11/03/position-independent-code-pic-in-shared-libraries/

## Cursos, notas y wargames
- ir0nstone / Binary Exploitation Notes (referencia moderna completa): https://ir0nstone.gitbook.io/notes
- Practical CTF (J. Woltjer): https://book.jorianwoltjer.com/binary-exploitation
- Nightmare (guyinatuxedo) - curso por retos reales, stack->heap->kernel: https://guyinatuxedo.github.io
- pwn.college (ASU) - curso estructurado, asm a kernel: https://pwn.college
- RPISEC - Modern Binary Exploitation (MBE), material universitario:
  https://github.com/RPISEC/MBE
- OpenSecurityTraining2 - clases de arquitectura, ELF, exploitation: https://ost2.fyi
- LiveOverflow - Binary Exploitation / pwn (video):
  https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN
- CTF101 pwn (intro): https://ctf101.org/binary-exploitation/overview/
- CTF Wiki (EN): https://ctf-wiki.mahaloz.re/pwn/
- HackTricks - Binary Exploitation (protecciones y bypasses): https://hacktricks.wiki/en/binary-exploitation/
- Exploit Education (Phoenix/Nebula, VMs practicas): https://exploit.education
- OverTheWire (Narnia, Behemoth): https://overthewire.org/wargames/
- ROP Emporium (solo ROP, multi-arch): https://ropemporium.com
- pwnable.kr / pwnable.tw / pwnable.xyz - retos clasicos de pwn.
- picoCTF - retos introductorios: https://picoctf.org
- Agregadores: Tzaoh/pwning (https://github.com/Tzaoh/pwning) y alex-bellon/cybersecurity-resources.

## Stack: ROP, ret2libc, SROP, ret2csu, pivot, ret2dlresolve
- ir0nstone SROP: https://ir0nstone.gitbook.io/notes/binexp/stack/syscalls/sigreturn-oriented-programming-srop
- ir0nstone ret2csu: https://ir0nstone.gitbook.io/notes/binexp/stack/ret2csu
- ir0nstone stack pivoting: https://ir0nstone.gitbook.io/notes/binexp/stack/stack-pivoting
- Practical CTF ret2dlresolve: https://book.jorianwoltjer.com/binary-exploitation/return-oriented-programming-rop/ret2dlresolve
- syst3mfailure - ret2dl_resolve x64: https://syst3mfailure.io/ret2dl_resolve/
- HackTricks ret2csu / SROP / ret2dlresolve: https://hacktricks.wiki/en/binary-exploitation/rop-return-oriented-programing/

## Format string
- ir0nstone format string: https://ir0nstone.gitbook.io/notes/binexp/stack/format-string
- HackTricks format strings: https://hacktricks.wiki/en/binary-exploitation/format-strings/

## Heap glibc, houses y FSOP
- how2heap (shellphish) - PoC ejecutables por version de glibc: https://github.com/shellphish/how2heap
- glibc source (malloc/malloc.c), la verdad ultima: https://elixir.bootlin.com/glibc/latest/source/malloc/malloc.c
- sploitfun - understanding glibc malloc: https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/
- Azeria / Dhaval Kapil - heap exploitation: https://heap-exploitation.dhavalkapil.com
- 0x434b - Overview of glibc heap exploitation: https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/
- HeapLAB (Max Kamper) - curso de heap (tcache/fastbin/unsorted/hooks).
- AngelBoy - Play with FILE Structure (FSOP fundacional):
  https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique
- angry-FSROP (kylebot) - bypass del vtable check: https://blog.kylebot.net/2022/10/22/angry-FSROP/
- House of Apple 2 (writeup, glibc 2.35+): https://ian.nl/blog/htb-love-letter-house-of-apple-fsop
- Deep Dive into FSOP (Niftic): https://niftic.ca/posts/fsop/
- nobodyisnobody - code execution on last libc: https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc

## GOT/PLT, dynamic linking y exit handlers
- MaskRay - All about the PLT: https://maskray.me/blog/2021-09-19-all-about-procedure-linkage-table
- 4xura - Hijack libc internal GOT/PLT as RCE: https://4xura.com/binex/pwn-got-hijack-libcs-internal-got-plt-as-rce-primitives/
- binholic - Abusing exit handlers + pointer mangling: https://m101.github.io/binholic/2017/05/20/notes-on-abusing-exit-handlers.html
- HackTricks WWW2Exec (atexit/GOT): https://hacktricks.wiki/en/binary-exploitation/arbitrary-write-2-exec/

## Kernel (Linux)
- CTF Wiki (kernel): https://ctf-wiki.mahaloz.re/pwn/linux/kernel/
- lkmidas - Learning Linux Kernel Exploitation (serie): https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/
- lkmidas - modprobe_path: https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/
- n132 - Introduction of Kernel Pwn (stack): https://n132.github.io/2022/05/16/Introduction-of-Kernel-Pwn-Stack.html
- pawnyable (kernel + browser, muy completo): https://pawnyable.cafe/
- Andrey Konovalov (a13xp0p0v) - kernel exploitation writeups/CVEs: https://a13xp0p0v.github.io
- Will's Root - userfaultfd race + kernel UAF: https://www.willsroot.io/2020/10/cuctf-2020-hotrod-kernel-writeup.html
- ETenal - userfaultfd + setxattr heap spray: https://etenal.me/archives/1336
- Google kernelCTF (PoCs reales): https://github.com/google/security-research/tree/master/pocs/linux/kernelctf

## Browser / JS engines (V8)
- ir0nstone browser exploitation (oob-v8): https://ir0nstone.gitbook.io/notes/binexp/browser-exploitation/ctf-2019-oob-v8/the-challenge
- addrof/fakeobj (TrustFoundry): https://trustfoundry.net/2025/03/28/browser-exploitation-basics-explaining-the-addrof-and-fakeobj-primitives/
- faith - *CTF oob-v8 en profundidad: https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/
- Google Project Zero (research de navegadores): https://googleprojectzero.blogspot.com

## Windows
- Corelan - Exploit writing tutorials (stack, SEH, egghunter, ROP): https://www.corelan.be/index.php/articles/
- FuzzySecurity - Windows exploit dev: https://fuzzysecurity.com/tutorials.html
- CyberArk - Modern Windows memory corruption: https://www.cyberark.com/resources/threat-research-blog/a-modern-exploration-of-windows-memory-corruption-exploits-part-i-stack-overflows
- connormcgarr - Windows exploitation notes: https://connormcgarr.github.io
- mona.py (Corelan) para ROP/SEH en Immunity/WinDbg.

## ARM / AArch64 / MIPS
- Azeria Labs - ARM assembly & exploitation: https://azeria-labs.com
- CTF Wiki arm_rop: https://ctf-wiki.mahaloz.re/pwn/linux/arm/arm_rop/
- CTF Recipes AArch64 calling convention: https://www.ctfrecipes.com/pwn/architectures/aarch64/calling-convention
- HackTricks ret2syscall arm64: https://hacktricks.wiki/en/binary-exploitation/rop-return-oriented-programing/rop-syscall-execv/ret2syscall-arm64.html
- easy-linux-pwn (xairy, multi-arch): https://github.com/xairy/easy-linux-pwn

## macOS / iOS
- HackTricks iOS exploiting: https://hacktricks.wiki/en/binary-exploitation/ios-exploiting/index.html
- Anatomy of a Mach-O (PAC/code signing): https://oliviagallucci.com/the-anatomy-of-a-mach-o-structure-code-signing-and-pac/
- Project Zero (research iOS/PAC): https://googleprojectzero.blogspot.com

## Anti-debug, reversing y packers
- yo-yo-yo-jbo - anti_debugging_intro: https://github.com/yo-yo-yo-jbo/anti_debugging_intro
- Ghidra: https://ghidra-sre.org  |  angr docs: https://docs.angr.io
- UPX (upx -d): https://upx.github.io

## Herramientas
- pwntools (ELF, ROP, fmtstr_payload, shellcraft, cyclic): https://docs.pwntools.com
- pwndbg: https://github.com/pwndbg/pwndbg  |  GEF: https://github.com/hugsy/gef
- ROPgadget: https://github.com/JonathanSalwan/ROPgadget  |  ropper: https://github.com/sashs/ropper
- one_gadget: https://github.com/david942j/one_gadget  |  seccomp-tools: https://github.com/david942j/seccomp-tools
- pwninit: https://github.com/io12/pwninit  |  patchelf: https://github.com/NixOS/patchelf
- libc-database: https://github.com/niklasb/libc-database  |  libc.rip (busqueda online): https://libc.rip
- radare2: https://github.com/radareorg/radare2  |  angr: https://github.com/angr/angr
- GTFOBins (escalada tras ejecucion): https://gtfobins.github.io

## Tablas y ABIs
- syscall table x86-64: https://filippo.io/linux-syscall-table/  y  https://syscall.sh
- x86-64 psABI: https://gitlab.com/x86-psABIs/x86-64-ABI
- ELF spec / man elf(5): https://man7.org/linux/man-pages/man5/elf.5.html

## Notas de version (glibc) que afectan a la explotacion
- 2.26: aparece tcache.
- 2.29: tcache key check (mitiga algunos double-free en el mismo bin); House of Force muere.
- 2.32: safe-linking (fd = (pos>>12) ^ ptr) en tcache/fastbins; necesita heap leak.
- 2.34: eliminados __malloc_hook / __free_hook / __realloc_hook -> FSOP / exit handlers.
- 2.35+: cambios en _IO_FILE vtable checks; FSOP moderno (House of Apple/Cat/Kiwi/Banana).
