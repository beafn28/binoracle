# Summary of Reverse Engineering Resources

> Selected from multiple awesome lists, sorted by practicality. AI can refer to these resources for methodology and tool guidance in reverse analysis.

---

## Comprehensive Resource Library

| Project | Stars | Coverage | Link |
|---------|-------|----------|------|
| **awesome-reversing** (tylerha97) | 3k+ | Reversing tools/books/courses/exercises | https://github.com/tylerha97/awesome-reversing |
| **awesome-reverse-engineering** (alphaSeclab) | 4k+ | 3500+ tools + 2300 articles, cross-platform | https://github.com/alphaSeclab/awesome-reverse-engineering |
| **Reverse-Engineering** (mytechnotalent) | 10k+ | Free tutorials: x86/x64/ARM/AVR/RISC-V | https://github.com/mytechnotalent/Reverse-Engineering |
| **awesome-malware-analysis** (rshipp) | 12k+ | Malware analysis tools/resources | https://github.com/rshipp/awesome-malware-analysis |
| **reversingBits** | — | Reversing/binary analysis cheat sheet collection | https://github.com/mohitmishra786/reversingBits |
| **awesome-arm-exploitation** | — | ARM exploitation resources (videos/articles/books) | https://github.com/HenryHoggard/awesome-arm-exploitation |
| **Binary-Analysis-Automation** | — | Automated binary analysis (ML/scripts/static/dynamic) | https://github.com/user1342/Awesome-Binary-Analysis-Automation |

---

## ELF / Linux Reversing Specialization

| Resource | Description | Link |
|----------|-------------|------|
| **libelfmaster** | Secure ELF parsing library (forensics/malware reconstruction) | https://github.com/elfmaster/libelfmaster |
| **ELF Specification** | Official ELF format documentation | https://refspecs.linuxfoundation.org/elf/elf.pdf |
| **Linux Internals** | /proc file system, memory layout, syscalls | https://0xax.gitbooks.io/linux-insides/ |
| **Compiler Explorer** | Online view of C/C++/Rust/Go code compiled to assembly | https://godbolt.org/ |

---

## ARM / AArch64 Specialization

| Resource | Description | Link |
|----------|-------------|------|
| **ARM Official Architecture Manual** | Complete instruction set reference | https://developer.arm.com/documentation |
| **Azeria Labs** | ARM assembly/exploitation tutorials (best introduction) | https://azeria-labs.com/writing-arm-assembly-part-1/ |
| **ARM64 syscall table** | Linux AArch64 system call numbers | https://arm64.syscall.sh/ |
| **QEMU User Mode Simulation** | Analyze ARM binaries without real hardware | `qemu-aarch64 -strace ./binary` |

---

## Malware Analysis

| Resource | Description | Link |
|----------|-------------|------|
| **YARA** | Malware signature matching rules | https://github.com/VirusTotal/yara |
| **Volatility 3** | Memory forensics framework | https://github.com/volatilityfoundation/volatility3 |
| **FLOSS** | Automated extraction of obfuscated strings | https://github.com/mandiant/flare-floss |
| **Detect It Easy (DiE)** | File type/shell/compiler identification | https://github.com/horsicq/Detect-It-Easy |
| **PE-bear** | PE file analyzer | https://github.com/hasherezade/pe-bear |
| **Capa** | Automated recognition of binary capabilities (network/file/cryptography etc.) | https://github.com/mandiant/capa |
| **Unpacker** | General de-packer framework | https://github.com/malwaretech/UnpackerFramework |

---

## Dynamic Analysis / Sandbox

| Resource | Description | Link |
|----------|-------------|------|
| **Frida** | Cross-platform dynamic instrumentation | https://frida.re/ |
| **strace** | Linux system call tracing | Built-in |
| **ltrace** | Library function call tracing | Built-in |
| **QEMU** | User-mode/system-mode emulation | https://www.qemu.org/ |
| **Unicorn** | CPU simulation framework (programmable) | https://www.unicorn-engine.org/ |
| **Qiling** | Advanced binary simulation framework | https://qiling.io/ |
| **angr** | Symbolic execution + binary analysis | https://angr.io/ |
| **Triton** | Dynamic binary analysis framework | https://triton-library.github.io/ |

---

## Deobfuscation / Unpacking

| Resource | Description | Link |
|----------|-------------|------|
| **UPX** | Most common packer, `upx -d` unpacks | https://upx.github.io/ |
| **unipacker** | Universal PE unpacker | https://github.com/unipacker/unipacker |
| **de4dot** | .NET deobfuscation | https://github.com/de4dot/de4dot |
| **JADX** | Android DEX deobfuscation | https://github.com/skylot/jadx |
| **JEB** | Commercial Android/ARM decompiler | https://www.pnfsoftware.com/ |
| **Miasm** | Reverse engineering framework (IR/symbolic execution/deobfuscation) | https://github.com/cea-sec/miasm |
| **OLLVM Deobfuscation** | Control flow flattening/false control flow mitigation | Using angr/Triton symbolic execution to recover |

---

## Online Analysis Platforms

| Platform | Description | Link |
|----------|-------------|------|
| **VirusTotal** | Multi-engine scan + behavioral analysis | https://www.virustotal.com/ |
| **Joe Sandbox** | Automated malware analysis | https://www.joesandbox.com/ |
| **ANY.RUN** | Interactive online sandbox | https://any.run/ |
| **Hybrid Analysis** | Free malware analysis | https://www.hybrid-analysis.com/ |
| **Compiler Explorer** | See compiler output | https://godbolt.org/ |
| **Dogbolt** | Multi-decompiler comparison (IDA/Ghidra/Binary Ninja) | https://dogbolt.org/ |

---

## Learning Path

### Beginner (0-3 months)

1. [Reverse Engineering for Beginners](https://beginners.re/) — Free e-book
2. [Azeria Labs ARM Tutorial](https://azeria-labs.com/) — ARM assembly basics
3. [Nightmare](https://guyinatuxedo.github.io/) — CTF reverse/pwn tutorial
4. [crackmes.one](https://crackmes.one/) — Reverse engineering exercises

### Intermediate (3-12 months)

1. [Practical Binary Analysis](https://practicalbinaryanalysis.com/) — Practical binary analysis
2. [The IDA Pro Book](https://nostarch.com/idapro2.htm) — Deep IDA usage
3. [Malware Unicorn RE101](https://malwareunicorn.org/workshops/re101.html) — Malware reverse engineering
4. [pwnable.kr](http://pwnable.kr/) / [pwnable.tw](https://pwnable.tw/) — Pwn exercises

### Advanced

1. [Modern Binary Exploitation](https://github.com/RPISEC/MBE) — RPI course
2. [How to Hack Like a Ghost](https://nostarch.com/how-hack-ghost) — Advanced penetration testing
3. [Windows Internals](https://docs.microsoft.com/en-us/sysinternals/) — Windows kernel
4. Practical: Analyzing real malware samples (MalwareBazaar)

## Cheat Sheet

| Cheat Sheet | Link |
|-------------|------|
| x86/x64 Instruction Reference | https://www.felixcloutier.com/x86/ |
| ARM64 Instruction Reference | https://developer.arm.com/documentation/ddi0602/latest |
| Linux syscall table (x64) | https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/ |
| Linux syscall table (ARM64) | https://arm64.syscall.sh/ |
| GDB Cheat Sheet | https://darkdust.net/files/GDB%20Cheat%20Sheet.pdf |
| radare2 Cheat Sheet | This package `radare2/references/cheatsheet.md` |
| IDA Shortcuts | https://hex-rays.com/products/ida/support/freefiles/IDA_Pro_Shortcuts.pdf |
| Ghidra Shortcuts | Ghidra built-in Help → Keyboard Shortcuts |