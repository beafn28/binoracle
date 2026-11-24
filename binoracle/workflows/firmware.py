"""Firmware analysis — UEFI modules, embedded Linux images, raw flash dumps.

Supported targets:
  - UEFI PE32+ modules (.efi) and firmware volumes (.fd, .rom, .bin)
  - Linux-based firmware images (SquashFS/JFFS2 rootfs, uImage/zImage kernels)
  - Raw flash dumps (SPI NOR, NAND) with auto-format detection

Analysis pipeline:
  1. Identify format (UEFI magic, uImage header, squashfs, JFFS2, ELF, PE32+, raw)
  2. Extract filesystem / volume contents (binwalk, unsquashfs, jefferson, uefi-firmware-parser)
  3. Enumerate attack surface:
     - UEFI: SMM handlers, protocols, PEI modules, DXE drivers, NVRAM variables
     - Embedded Linux: busybox applets, telnetd/sshd/httpd, SUID binaries, hardcoded creds
  4. Static analysis of extracted ELF/PE binaries (binoracle existing pipeline)
  5. Produce a structured firmware report

External tools used (graceful fallback if absent):
  - binwalk          : extraction + entropy analysis
  - unsquashfs       : SquashFS extraction
  - jefferson        : JFFS2 extraction
  - uefi-firmware-parser (uefi_firmware Python package) : UEFI volumes

SOLO USO AUTORIZADO — solo firmware de dispositivos de tu propiedad o para los que
tienes autorización escrita.
"""
from __future__ import annotations

import re
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple


# ---------------------------------------------------------------------------
# Constants / magic bytes
# ---------------------------------------------------------------------------

_MAGIC = {
    "uefi_fd":    (b"\x01\xba",),                            # partial match; real check below
    "squashfs":   (b"sqsh", b"hsqs", b"shsq", b"qshs"),      # LE/BE variants
    "jffs2":      (b"\x85\x19", b"\x19\x85"),
    "elf":        (b"\x7fELF",),
    "pe32":       (b"MZ",),
    "uimage":     (b"\x27\x05\x19\x56",),                    # IH_MAGIC
    "gzip":       (b"\x1f\x8b",),
    "lzma":       (b"\xfd7zXZ\x00",),                        # XZ
    "lzma_old":   (b"\x5d\x00\x00",),                        # LZMA legacy
    "cramfs":     (b"\x28\xcd\x3d\x45", b"\x45\x3d\xcd\x28"),
    "ext2":       (b"\x53\xef",),                             # at offset 0x438
    "yaffs":      (b"\x03\x00\x00\x00",),
    "zip":        (b"PK\x03\x04",),
    "7zip":       (b"\x37\x7a\xbc\xaf\x27\x1c",),
    "android_sparse": (b"\x3a\xff\x26\xed",),
    "android_boot": (b"ANDROID!",),
    "dtb":        (b"\xd0\x0d\xfe\xed",),
}

_UEFI_VOLUME_MAGIC = b"_FVH"           # offset 0x28 in EFI_FIRMWARE_VOLUME_HEADER
_UEFI_MODULE_MAGIC = b"MZ"             # PE32+ EFI modules start with MZ


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class FirmwareFinding:
    severity: str     # critical | high | medium | low | info
    category: str     # hardcoded_cred | suid_binary | debug_interface | uefi_smi |
                      # insecure_service | kernel_config | nvram_exposure | other
    description: str
    path: str = ""
    detail: str = ""


@dataclass
class FirmwareInfo:
    path: str
    size: int = 0
    fmt: str = "unknown"           # uefi_fd | squashfs | jffs2 | uimage | elf | pe32 | raw
    arch: str = ""                 # x86 | x86_64 | arm | arm64 | mips | ppc
    endian: str = ""               # little | big
    # UEFI-specific
    uefi_modules: List[str] = field(default_factory=list)
    uefi_protocols: List[str] = field(default_factory=list)
    smi_handlers: List[str] = field(default_factory=list)
    # Embedded Linux-specific
    kernel_version: str = ""
    busybox_version: str = ""
    filesystem_type: str = ""
    suid_binaries: List[str] = field(default_factory=list)
    world_writable: List[str] = field(default_factory=list)
    hardcoded_creds: List[Tuple[str, str]] = field(default_factory=list)  # (file, match)
    services: List[str] = field(default_factory=list)
    # General
    findings: List[FirmwareFinding] = field(default_factory=list)
    extracted_to: str = ""
    binwalk_output: str = ""
    note: str = ""
    ok: bool = False


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def _read_header(path: str, size: int = 512) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(size)
    except Exception:
        return b""


def detect_format(path: str) -> Tuple[str, str, str]:
    """Return (fmt, arch, endian) by inspecting magic bytes."""
    hdr = _read_header(path, 1024)
    if not hdr:
        return "unknown", "", ""

    # UEFI firmware volume
    if _UEFI_VOLUME_MAGIC in hdr:
        return "uefi_fd", "x86_64", "little"

    # EFI PE32+ module
    if hdr[:2] == b"MZ":
        # check for UEFI subsystem in PE optional header
        try:
            pe_off = struct.unpack_from("<I", hdr, 0x3c)[0]
            sig = hdr[pe_off:pe_off+4] if pe_off + 4 <= len(hdr) else b""
            if sig == b"PE\x00\x00":
                machine = struct.unpack_from("<H", hdr, pe_off + 4)[0] if pe_off + 6 <= len(hdr) else 0
                subsystem_off = pe_off + 0x5c
                subsystem = struct.unpack_from("<H", hdr, subsystem_off)[0] if subsystem_off + 2 <= len(hdr) else 0
                if subsystem in (0x0b, 0x0c, 0x0d):  # EFI app/boot/runtime
                    arch = {0x8664: "x86_64", 0x014c: "x86", 0xaa64: "arm64",
                            0x01c2: "arm", 0x0200: "ia64"}.get(machine, "x86_64")
                    return "uefi_module", arch, "little"
        except Exception:
            pass
        return "pe32", "x86", "little"

    # ELF
    if hdr[:4] == b"\x7fELF":
        _ei_class = hdr[4] if len(hdr) > 4 else 0
        ei_data = hdr[5] if len(hdr) > 5 else 0
        e_machine = struct.unpack_from("<H" if ei_data == 1 else ">H", hdr, 0x12)[0] if len(hdr) > 0x14 else 0
        arch_map = {0x28: "arm", 0xb7: "arm64", 0x03: "x86", 0x3e: "x86_64",
                    0x08: "mips", 0x14: "ppc", 0x15: "ppc64", 0xf3: "riscv"}
        arch = arch_map.get(e_machine, f"elf_{e_machine:#x}")
        endian = "little" if ei_data == 1 else "big"
        return "elf", arch, endian

    # uImage
    if hdr[:4] == _MAGIC["uimage"][0]:
        arch_byte = hdr[11] if len(hdr) > 11 else 0
        arch_map = {2: "arm", 3: "x86", 4: "ia64", 5: "mips", 6: "ppc",
                    7: "s390", 8: "sh", 11: "arm64", 23: "riscv"}
        arch = arch_map.get(arch_byte, f"uimage_{arch_byte}")
        return "uimage", arch, "big"

    # SquashFS
    for m in _MAGIC["squashfs"]:
        if hdr[:4] == m:
            endian = "little" if m in (b"sqsh", b"shsq") else "big"
            return "squashfs", "", endian

    # JFFS2
    for m in _MAGIC["jffs2"]:
        if hdr[:2] == m:
            endian = "little" if m == b"\x85\x19" else "big"
            return "jffs2", "", endian

    # gzip / xz / lzma
    if hdr[:2] == b"\x1f\x8b":
        return "gzip", "", ""
    if hdr[:6] == b"\xfd7zXZ\x00":
        return "xz", "", ""

    # Android boot image
    if hdr[:8] == b"ANDROID!":
        return "android_boot", "arm", "little"

    # Device tree blob
    if hdr[:4] == b"\xd0\x0d\xfe\xed":
        return "dtb", "", "big"

    return "raw", "", ""


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def _run(cmd: List[str], cwd: str = ".", timeout: int = 120) -> Tuple[bool, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return r.returncode == 0, (r.stdout + r.stderr)[:8192]
    except FileNotFoundError:
        return False, f"tool not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, f"timeout after {timeout}s"
    except Exception as e:
        return False, str(e)


def _binwalk_extract(path: str, out_dir: str) -> Tuple[bool, str]:
    ok, out = _run(["binwalk", "--extract", "--directory", out_dir,
                    "--run-as=root", "--matryoshka", path], timeout=180)
    if not ok and "run-as" in out:
        ok, out = _run(["binwalk", "--extract", "--directory", out_dir,
                        "--matryoshka", path], timeout=180)
    return ok, out


def _unsquashfs(path: str, out_dir: str) -> Tuple[bool, str]:
    return _run(["unsquashfs", "-d", out_dir, "-f", path], timeout=120)


def _jefferson_extract(path: str, out_dir: str) -> Tuple[bool, str]:
    return _run(["jefferson", "-d", out_dir, path], timeout=120)


def _try_uefi_parser(path: str) -> Tuple[List[str], List[str], List[str]]:
    """Return (modules, protocols, smi_handlers) via uefi_firmware Python package."""
    modules: List[str] = []
    protocols: List[str] = []
    smi_handlers: List[str] = []
    try:
        import uefi_firmware
        with open(path, "rb") as f:
            data = f.read()
        parser = uefi_firmware.AutoParser(data)
        fw = parser.parse()
        if fw is None:
            return modules, protocols, smi_handlers
        for obj in fw.iterate_objects():
            name = getattr(obj, "name", "") or ""
            guid = str(getattr(obj, "guid", "") or "")
            typ = type(obj).__name__
            if name:
                modules.append(f"{name} [{typ}]")
            if "SMM" in name.upper() or "SMI" in name.upper():
                smi_handlers.append(name or guid)
        return modules[:64], protocols[:64], smi_handlers[:32]
    except ImportError:
        return modules, protocols, smi_handlers
    except Exception:
        return modules, protocols, smi_handlers


# ---------------------------------------------------------------------------
# Static analysis of extracted rootfs
# ---------------------------------------------------------------------------

_CRED_PATTERNS = [
    (re.compile(rb'(?:password|passwd|pass|pwd)\s*[=:]\s*["\']?([A-Za-z0-9!@#$%^&*]{4,32})', re.IGNORECASE), "hardcoded_password"),
    (re.compile(rb'(?:username|user|login)\s*[=:]\s*["\']?(admin|root|administrator|guest)', re.IGNORECASE), "default_username"),
    (re.compile(rb'(?:secret|api[_-]?key|token)\s*[=:]\s*["\']?([A-Za-z0-9+/=]{8,64})', re.IGNORECASE), "hardcoded_secret"),
    (re.compile(rb'[A-Za-z0-9+/]{40,}={0,2}', re.IGNORECASE), "base64_blob"),
]

_INTERESTING_BINS = {
    "busybox", "telnetd", "ftpd", "httpd", "lighttpd", "nginx", "dropbear",
    "sshd", "openssl", "wget", "curl", "nc", "ncat", "nmap", "tcpdump",
    "gdb", "strace", "ltrace", "python", "python3", "perl", "lua",
    "php", "node", "sh", "bash",
}


def _scan_rootfs(rootfs: str, info: FirmwareInfo):
    """Walk extracted rootfs and populate info.findings."""
    base = Path(rootfs)
    if not base.exists():
        return

    # kernel version string
    for vmlinuz in base.rglob("vmlinuz*"):
        try:
            data = vmlinuz.read_bytes()[:65536]
            m = re.search(rb"Linux version (\d+\.\d+\.\d+[^\x00]*)", data)
            if m:
                info.kernel_version = m.group(1).decode("latin-1", "replace")[:80]
                break
        except Exception:
            pass

    # busybox version
    for bb in base.rglob("busybox"):
        try:
            data = bb.read_bytes()[:65536]
            m = re.search(rb"BusyBox v([0-9.]+)", data)
            if m:
                info.busybox_version = m.group(1).decode()
                break
        except Exception:
            pass

    # services
    for svc in _INTERESTING_BINS:
        for p in base.rglob(svc):
            info.services.append(str(p.relative_to(base)))

    # SUID binaries and world-writable files
    for p in base.rglob("*"):
        if not p.is_file():
            continue
        try:
            mode = p.stat().st_mode
            if mode & 0o4000:  # SUID
                rel = str(p.relative_to(base))
                info.suid_binaries.append(rel)
                info.findings.append(FirmwareFinding(
                    severity="high", category="suid_binary",
                    description=f"SUID binary: {rel}", path=rel,
                ))
            if mode & 0o002:  # world-writable
                rel = str(p.relative_to(base))
                info.world_writable.append(rel)
        except Exception:
            pass

    # Hardcoded credentials in text/config files
    cred_hits = 0
    for p in base.rglob("*"):
        if not p.is_file() or p.stat().st_size > 512 * 1024:
            continue
        # skip large binaries — scan only text-ish files and known configs
        try:
            suffix = p.suffix.lower()
            if suffix in (".png", ".jpg", ".gif", ".ico", ".ttf", ".woff",
                          ".mp3", ".mp4", ".bin", ".ko", ".so", ".a"):
                continue
            data = p.read_bytes()[:16384]
            for pat, label in _CRED_PATTERNS:
                for m in pat.finditer(data):
                    val = m.group(1).decode("latin-1", "replace") if m.lastindex else ""
                    if val in ("", "password", "PASSWORD", "null", "none", "true", "false"):
                        continue
                    rel = str(p.relative_to(base))
                    info.hardcoded_creds.append((rel, f"{label}: {val[:32]}"))
                    if cred_hits < 32:
                        info.findings.append(FirmwareFinding(
                            severity="critical", category="hardcoded_cred",
                            description=f"Potential hardcoded credential in {rel}",
                            path=rel, detail=f"{label}: {val[:32]}",
                        ))
                    cred_hits += 1
                    if cred_hits >= 128:
                        break
                if cred_hits >= 128:
                    break
        except Exception:
            pass

    # Debug interfaces
    for p in base.rglob("*"):
        rel = str(p.relative_to(base))
        if any(x in rel for x in ("telnetd", "debug", "uart", "serial", "jtag")):
            info.findings.append(FirmwareFinding(
                severity="medium", category="debug_interface",
                description=f"Potential debug interface: {rel}", path=rel,
            ))

    # /etc/passwd and /etc/shadow — check for password hashes or empty passwords
    for fname in ("etc/passwd", "etc/shadow"):
        fp = base / fname
        if fp.exists():
            try:
                lines = fp.read_text(errors="replace").splitlines()
                for line in lines:
                    parts = line.split(":")
                    if len(parts) >= 2 and parts[1] in ("", "x", "*"):
                        continue
                    if len(parts) >= 2 and parts[1] and parts[1] not in ("!", "!!"):
                        info.findings.append(FirmwareFinding(
                            severity="high", category="hardcoded_cred",
                            description=f"Password hash in {fname} for user '{parts[0]}'",
                            path=fname, detail=f"hash prefix: {parts[1][:20]}",
                        ))
            except Exception:
                pass

    # Kernel config
    for kconf in base.rglob("config*"):
        if "kernel" in str(kconf).lower() or kconf.name.startswith("config-"):
            try:
                cfg = kconf.read_text(errors="replace")[:8192]
                dangerous = [
                    ("CONFIG_DEVMEM=y", "Direct /dev/mem access enabled"),
                    ("CONFIG_STRICT_DEVMEM is not set", "Strict /dev/mem disabled"),
                    ("CONFIG_KALLSYMS_ALL=y", "Full kernel symbol table exposed"),
                    ("CONFIG_DEBUG_KERNEL=y", "Kernel debug enabled"),
                    ("CONFIG_KGDB=y", "Kernel GDB stub enabled"),
                ]
                for opt, msg in dangerous:
                    if opt in cfg:
                        info.findings.append(FirmwareFinding(
                            severity="medium", category="kernel_config",
                            description=msg, path=str(kconf.relative_to(base)),
                        ))
            except Exception:
                pass

    info.suid_binaries = info.suid_binaries[:64]
    info.world_writable = info.world_writable[:32]
    info.hardcoded_creds = info.hardcoded_creds[:32]
    info.services = list(dict.fromkeys(info.services))[:32]


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze_firmware(path: str, out_dir: str = "") -> FirmwareInfo:
    """Analyze a firmware image. Returns a populated FirmwareInfo.

    Args:
        path:    Path to the firmware file (EFI, .fd, .rom, rootfs image, etc.)
        out_dir: Where to extract the firmware. Uses a temp dir if empty.
    """
    p = Path(path)
    info = FirmwareInfo(path=path)
    if not p.exists():
        info.note = f"file not found: {path}"
        return info

    info.size = p.stat().st_size
    info.fmt, info.arch, info.endian = detect_format(path)

    use_tmp = not out_dir
    if use_tmp:
        out_dir = tempfile.mkdtemp(prefix="binoracle_fw_")
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    info.extracted_to = out_dir

    # --- UEFI firmware volume ---
    if info.fmt in ("uefi_fd", "uefi_module"):
        mods, protos, smis = _try_uefi_parser(path)
        info.uefi_modules = mods
        info.uefi_protocols = protos
        info.smi_handlers = smis
        if smis:
            for s in smis:
                info.findings.append(FirmwareFinding(
                    severity="high", category="uefi_smi",
                    description=f"SMM handler detected: {s}",
                ))
        # Try binwalk extraction for deeper look
        ok, bw = _binwalk_extract(path, out_dir)
        info.binwalk_output = bw[:4096]
        if ok:
            _scan_rootfs(out_dir, info)

    # --- SquashFS ---
    elif info.fmt == "squashfs":
        sqfs_out = str(Path(out_dir) / "squashfs-root")
        ok, out = _unsquashfs(path, sqfs_out)
        if not ok:
            ok, out = _binwalk_extract(path, out_dir)
            info.binwalk_output = out[:4096]
        info.filesystem_type = "squashfs"
        _scan_rootfs(sqfs_out if Path(sqfs_out).exists() else out_dir, info)

    # --- JFFS2 ---
    elif info.fmt == "jffs2":
        jffs_out = str(Path(out_dir) / "jffs2-root")
        ok, out = _jefferson_extract(path, jffs_out)
        if not ok:
            ok, out = _binwalk_extract(path, out_dir)
            info.binwalk_output = out[:4096]
        info.filesystem_type = "jffs2"
        _scan_rootfs(jffs_out if Path(jffs_out).exists() else out_dir, info)

    # --- uImage / gzip / generic compressed ---
    elif info.fmt in ("uimage", "gzip", "xz", "raw", "android_boot"):
        ok, out = _binwalk_extract(path, out_dir)
        info.binwalk_output = out[:4096]
        # find extracted rootfs
        for sub in sorted(Path(out_dir).rglob("squashfs-root")):
            _scan_rootfs(str(sub), info)
            break
        for sub in sorted(Path(out_dir).rglob("jffs2-root")):
            _scan_rootfs(str(sub), info)
            break
        if not info.services:
            _scan_rootfs(out_dir, info)

    # --- Bare ELF / PE (single binary) ---
    elif info.fmt in ("elf", "pe32"):
        # just record it; full static analysis handled by other binoracle tools
        info.findings.append(FirmwareFinding(
            severity="info", category="other",
            description=f"Single {info.fmt.upper()} binary — use binoracle analyze for deeper analysis.",
            path=path,
        ))

    info.ok = True
    info.note = (f"{info.fmt} | {info.arch or '?'} | {info.endian or '?'}-endian | "
                 f"{info.size // 1024} KiB")
    return info


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_BADGE = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def render_firmware(info: FirmwareInfo) -> str:
    out = ["## Firmware analysis report\n"]

    out.append(f"**File:** `{info.path}`  ")
    out.append(f"**Format:** {info.fmt}  |  **Arch:** {info.arch or '?'}  "
               f"|  **Endian:** {info.endian or '?'}  |  **Size:** {info.size // 1024} KiB\n")

    if info.note and not info.ok:
        out.append(f"_{info.note}_\n")
        return "\n".join(out)

    # Executive summary table
    sev_counts = {}
    for f in info.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    if sev_counts:
        out.append("### Findings summary\n")
        out.append("| Severity | Count |")
        out.append("|----------|------:|")
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev in sev_counts:
                out.append(f"| {_SEV_BADGE[sev]} {sev.capitalize()} | {sev_counts[sev]} |")
        out.append("")

    # UEFI section
    if info.uefi_modules or info.smi_handlers:
        out.append("### UEFI modules\n")
        if info.smi_handlers:
            out.append(f"**SMM/SMI handlers ({len(info.smi_handlers)}):** "
                       + ", ".join(f"`{s}`" for s in info.smi_handlers[:10]))
            out.append("")
        if info.uefi_modules:
            out.append(f"**Modules ({min(len(info.uefi_modules), 20)} shown):**")
            for m in info.uefi_modules[:20]:
                out.append(f"  - `{m}`")
            out.append("")

    # Embedded Linux section
    if info.kernel_version or info.busybox_version or info.services:
        out.append("### Embedded Linux\n")
        if info.kernel_version:
            out.append(f"**Kernel:** `{info.kernel_version}`")
        if info.busybox_version:
            out.append(f"**BusyBox:** v{info.busybox_version}")
        if info.filesystem_type:
            out.append(f"**Filesystem:** {info.filesystem_type}")
        if info.services:
            out.append(f"**Services/binaries found:** {', '.join(f'`{s}`' for s in info.services[:16])}")
        out.append("")

    if info.suid_binaries:
        out.append(f"**SUID binaries ({len(info.suid_binaries)}):** "
                   + ", ".join(f"`{s}`" for s in info.suid_binaries[:10]))
        out.append("")

    if info.hardcoded_creds:
        out.append(f"**Potential hardcoded credentials ({len(info.hardcoded_creds)}):**")
        for path, detail in info.hardcoded_creds[:8]:
            out.append(f"  - `{path}`: {detail}")
        out.append("")

    # Findings detail
    if info.findings:
        out.append("### Findings\n")
        sorted_findings = sorted(info.findings, key=lambda f: _SEV_ORDER.get(f.severity, 5))
        out.append("| Sev | Category | Description |")
        out.append("|-----|----------|-------------|")
        for f in sorted_findings[:40]:
            badge = _SEV_BADGE.get(f.severity, "⚪")
            desc = f.description[:80]
            out.append(f"| {badge} | {f.category} | {desc} |")
        if len(info.findings) > 40:
            out.append(f"| … | | +{len(info.findings)-40} more findings |")
        out.append("")

    if info.extracted_to:
        out.append(f"**Extracted to:** `{info.extracted_to}`")

    out.append("\n_SOLO USO AUTORIZADO — solo firmware de dispositivos propios "
               "o con permiso escrito._")
    return "\n".join(out)
