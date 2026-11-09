# Kernel Driver Reverse Engineering Reference

> Cover Windows/Linux kernel driver reverse engineering, Rootkit analysis, C/C++ binary mode recognition.

---

## Windows Driver Reverse Engineering

### Driver Types

| Type | Features | Analysis Focus |
|------|----------|----------------|
| WDM (Windows Driver Model) | Older drivers, manual IRP management | DriverEntry → Device Creation → Dispatch Routines |
| KMDF (Kernel Mode Driver Framework) | Modern framework, event-driven | EvtDriverDeviceAdd → Queue → I/O Callbacks |
| WDF (Windows Driver Foundation) | KMDF + UMDF combined | Look for WdfDriverCreate calls |
| Minifilter | File system filter driver | FltRegisterFilter → Pre/Post Callbacks |

### WDM Driver Analysis Workflow

```text
1. Find DriverEntry (entry point)
   - IDA automatically identifies it, or search for IoCreateDevice / IoCreateSymbolicLink

2. Find device name and symbolic link
   - IoCreateDevice → DeviceName (e.g., \Device\MyDriver)
   - IoCreateSymbolicLink → SymLink (e.g., \DosDevices\MyDriver)

3. Find Dispatch routines
   - DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl
   - This is the entry point for user mode through DeviceIoControl

4. Analyze IOCTL handling
   - switch(IoControlCode) distributes different functions
   - IOCTL encoding: CTL_CODE(DeviceType, Function, Method, Access)
   - Method: METHOD_BUFFERED / METHOD_IN_DIRECT / METHOD_OUT_DIRECT / METHOD_NEITHER

5. Find vulnerabilities
   - Unvalidated length of user-controlled buffer → Overflow
   - METHOD_NEITHER directly uses user pointers → Arbitrary read/write
   - Unchecked IOCTL permissions → Non-privileged users can call
```

### IOCTL Encoding Parsing

```python
# Parse IOCTL code
def decode_ioctl(code):
    device_type = (code >> 16) & 0xFFFF
    access = (code >> 14) & 0x3
    function = (code >> 2) & 0xFFF
    method = code & 0x3
    
    methods = {0: "BUFFERED", 1: "IN_DIRECT", 2: "OUT_DIRECT", 3: "NEITHER"}
    access_types = {0: "ANY", 1: "READ", 2: "WRITE", 3: "READ|WRITE"}
    
    return f"DevType=0x{device_type:X} Func=0x{function:X} Method={methods[method]} Access={access_types[access]}"

# Example
decode_ioctl(0x80002034)
# DevType=0x8000 Func=0x80D Method=BUFFERED Access=ANY
```

### IDA Plugins

| Plugin | Purpose | Link |
|--------|---------|------|
| **Driver Buddy Reloaded** | Automatically identifies IOCTL, Dispatch, device names | https://github.com/VoidSec/DriverBuddyReloaded |
| **WinDbg + IDA** | Kernel debugging + static analysis combined | Built-in |
| **FLIRT/Lumina** | Identifies WDK library functions | Built-in in IDA |

### Reference Articles

- [Windows Drivers RE Methodology (VoidSec)](https://voidsec.com/windows-drivers-reverse-engineering-methodology/) — Comprehensive WDM driver reverse engineering methodology
- [Driver Reversing 101](https://eversinc33.com/posts/driver-reversing.html) — Comparison of WDM vs KMDF
- [Methodology of Reversing Vulnerable Killer Drivers](https://whiteknightlabs.com/2025/10/28/methodology-of-reversing-vulnerable-killer-drivers/) — Analysis of vulnerable driver reversing

## Linux Kernel Module Reverse Engineering

### LKM (Loadable Kernel Module) Structure

```text
Key functions:
- init_module / module_init → Executed when the module is loaded
- cleanup_module / module_exit → Executed when the module is unloaded

Key structures:
- struct file_operations → Character device operations like open/read/write/ioctl
- struct net_device_ops → Network device operations
- struct block_device_operations → Block device operations
```

### Analysis Process

```text
1. Confirm it's a kernel module
   file module.ko → "ELF 64-bit ... relocatable" (note: relocatable, not executable)

2. Find init/exit functions
   readelf -s module.ko | grep -E "init_module|cleanup_module"
   or in the .modinfo section for module information

3. Find file_operations structure
   Search for register_chrdev / cdev_add / misc_register
   → Find the fops structure → Locate ioctl/read/write handler functions

4. Analyze ioctl handling
   unlocked_ioctl / compat_ioctl functions
   → switch(cmd) dispatching

5. Find Rootkit behavior
   - Modify sys_call_table → syscall hook
   - Modify /proc file system → Hide processes/files
   - Register netfilter hook → Hide network connections
   - Modify VFS layer → Hide files
```

### Common Techniques of Rootkits

| Technique | Feature | Detection Method |
|-----------|---------|------------------|
| syscall table hook | Modify `sys_call_table` entries | Compare the memory table with the vmlinux on disk |
| VFS hook | Modify `file_operations` function pointers | Check if fops pointers point outside the kernel code segment |
| Netfilter hook | `nf_register_net_hook` | Traverse the netfilter hook linked list |
| kprobe/ftrace hook | Register kprobe or ftrace callbacks | Check the ftrace registration list |
| eBPF rootkit | Load malicious BPF programs | `bpftool prog list` |
| DKOM | Directly modify kernel objects (process chains) | Traverse the task_struct linked list and compare with /proc |

### Tools

| Tool | Purpose |
|------|---------|
| `crash` | Kernel dump analysis |
| `volatility3` | Memory forensics (Linux profile) |
| `dmesg` / `journalctl` | Kernel logs |
| `lsmod` / `/proc/modules` | List of loaded modules |
| `modinfo` | Module metadata |
| `strace` | System call tracing (user-space perspective) |

## C/C++ Reverse Engineering Techniques

### Common Patterns in C Language

| Source Code Pattern | Disassembly Feature |
|---------------------|-----------------------|
| `if-else`             | `cmp` + `jcc` (conditional jump) |
| `switch-case`         | Jump table (`jmp [rax*8 + table]`) or consecutive `cmp` |
| `for` loop            | `cmp` + `jl/jle` + loop body + `inc/add` + `jmp` back |
| `while` loop          | Condition check at the top of the loop |
| `do-while` loop       | Condition check at the bottom of the loop |
| Function pointer call   | `call rax` or `call [reg+offset]` |
| `struct` access         | `[reg+fixed offset]` (e.g., `[rdi+0x10]`) |
| `malloc` + use          | `call malloc` → return value stored in register → subsequent use of that register + offset |
| String comparison       | `call strcmp` or `repe cmpsb` |

### Unique Patterns in C++

| Source Code Pattern | Disassembly Feature |
|---------------------|-----------------------|
| **Virtual function call** | `mov rax, [rcx]` (fetch vtable) → `call [rax+offset]` (call virtual function) |
| **Constructor**       | Memory allocation → write vtable pointer → initialize members |
| **Destructor**        | Clean up members → may call `operator delete` |
| **this pointer**      | First parameter (rcx/rdi) is object pointer |
| **Inheritance**       | Vtable contains parent class virtual functions + subclass overrides |
| **Multiple inheritance** | Object has multiple vtable pointers (offsets different) |
| **RTTI**              | `type_info` pointer before vtable |
| **Exception handling** | `__cxa_throw` / `_CxxThrowException` |
| **STL containers**    | `std::vector`: `{begin, end, capacity}` three-pointer structure |
| **std::string**       | Small string optimization (SSO): short strings inlined, long strings heap-allocated |

### Vtable Reverse Engineering Methods

```text
1. Find vtable
   - Search for consecutive function pointer arrays (.rodata or .rdata segment)
   - Constructor writes vtable pointer to [rcx] (`mov [rcx], offset vtable`)

2. Determine class hierarchy
   - -8 offset before vtable is usually RTTI pointer (if not stripped)
   - Multiple vtables sharing first few entries → inheritance relationship

3. Annotate virtual functions
   - vtable[0] is typically destructor (or deleting destructor)
   - Subsequent by offset: vtable[1] = func1, vtable[2] = func2...

4. IDA operations
   - Create struct at vtable address (each field is a function pointer)
   - Add comments to `call [rax+offset]` indicating the virtual function called
```

### Structure Recovery

```text
Method 1: Infer from access pattern
  mov eax, [rdi+0x00]  → field_0: int/ptr (4/8 bytes)
  mov ecx, [rdi+0x08]  → field_8: int/ptr
  movss xmm0, [rdi+0x10] → field_10: float

Method 2: Infer from sizeof
  call malloc(0x30) → structure size 0x30 (48 bytes)
  
Method 3: Infer from constructor
  Constructor initializes all fields → field types and offsets are clear

Method 4: Use IDA's "Create struct" feature
  Select access pattern → Edit → Struct → Create struct from selection
```

---

## Common Compiler Features

| Compiler | Identification Feature |
|----------|------------------------|
| MSVC     | `_security_cookie` check, `__fastcall` calling convention, Rich Header |
| GCC      | `__stack_chk_fail`, `-fstack-protector`, `.note.GNU-stack` |
| Clang/LLVM | Similar to GCC but with different optimization modes, `__asan_*` (if sanitizer is enabled) |
| MinGW    | GCC features + Windows API calls |
| AOSP Clang | Android-specific `__android_log_print`, PGO markers |

### Optimization Level Identification

| Optimization Level | Feature |
|--------------------|---------|
| -O0                | Large number of redundant movs, variables on stack, functions not inlined |
| -O1                | Basic optimizations, some variables in registers |
| -O2                | Loop unrolling, function inlining, tail call optimization |
| -O3 / -Os          | Aggressive inlining, vectorization (SIMD), difficult-to-read code |
| PGO                | Hot path optimization, cold code separated to `.text.cold` |
| LTO                | Cross-module inlining, global dead code elimination |

---

## Kernel Debugging Environment

### Windows

```text
Debugger: WinDbg Preview
Connection method: Network debugging (recommended) or Serial port

Target machine setup:
bcdedit /debug on
bcdedit /dbgsettings net hostip:192.168.x.x port:50000

Debugging machine connection:
WinDbg → File → Attach to Kernel → Net → Port:50000 Key:xxx

Common commands:
!analyze -v          # Automatically analyze crash
lm                   # List loaded modules
!drvobj \Driver\xxx  # View driver object
dt nt!_DRIVER_OBJECT # Display structure
bp module!function   # Set breakpoint
```

### Linux

```text
Debugger: GDB + QEMU or kgdb

QEMU kernel debugging:
qemu-system-x86_64 -kernel bzImage -s -S ...
gdb vmlinux -ex "target remote :1234"

Common commands:
info threads         # Kernel threads
lx-symbols           # Load kernel symbols (requires scripts/gdb/)
p init_task          # View init process
lx-dmesg             # Kernel logs
```

---

## Agent Action Anchors (Issue #65 U–AV)

Align with `references/nonpe-format-cookbook.md` §5 (short table, do not replace the previous workflow):

| ID | Action | Evidence |
|----|------|----------|
| AG | `DriverEntry` short → scan non-empty slots in `MajorFunction`, prioritize DEVICE_CONTROL/CREATE | `E-driver-irp-handlers` |
| AH | Establish IOCTL control code → handler table with METHOD_* | `E-driver-ioctl` |
| AI | Suspect BYOVD: compare against public vulnerable driver list; name/hash/signature with call intent; **do not write exploit steps** | `E-driver-byovd` |

## Reference Resources

| Resource | Description | Link |
|----------|-------------|------|
| VoidSec Driver Reversing Methodology | Comprehensive analysis flow for Windows WDM drivers | https://voidsec.com/windows-drivers-reverse-engineering-methodology/ |
| Elastic Rootkit Series | Classification and detection of Linux rootkits | https://security-labs.elastic.co/security-labs/linux-rootkits-1-hooked-on-linux |
| Driver Buddy Reloaded | IDA driver analysis plugin | https://github.com/VoidSec/DriverBuddyReloaded |
| LOLDrivers | List of known vulnerable drivers | https://www.loldrivers.io/ |
| Windows Driver Samples | Official Microsoft driver samples | https://github.com/microsoft/Windows-driver-samples |
| Linux Kernel Module Programming | Tutorial on kernel module development | https://sysprog21.github.io/lkmpg/ |
| Trail of Bits - Devirtualizing C++ | vtable reversing method | https://blog.trailofbits.com/2017/02/13/devirtualizing-c-with-binary-ninja/ |