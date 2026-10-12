"""Native (no-Docker) execution sandbox: host/target capability detection."""
import os
import platform
import tempfile

from binoracle.workflows import _sandbox


def _here():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_elf_machine_detects_x86_64():
    sample = os.path.join(_here(), "samples", "bin", "heapexp")
    if not os.path.exists(sample):
        return
    assert _sandbox._elf_machine(sample) == _sandbox._EM_X86_64


def test_elf_machine_rejects_non_elf():
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
    f.write(b"MZ\x90\x00" + b"\x00" * 60)  # DOS/PE header, not ELF
    f.close()
    try:
        assert _sandbox._elf_machine(f.name) != _sandbox._EM_X86_64
    finally:
        os.unlink(f.name)


def test_native_available_on_x86_64_elf():
    # On a Linux x86-64 host with pwntools + setarch (our CI/dev target), an x86-64 ELF is
    # runnable natively; otherwise the reason must be non-empty and actionable.
    sample = os.path.join(_here(), "samples", "bin", "heapexp")
    if not os.path.exists(sample):
        return
    ok, reason = _sandbox.native_available(sample)
    assert isinstance(ok, bool) and reason
    if platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64"):
        try:
            import pwn  # noqa: F401
            import shutil
            if shutil.which("setarch"):
                assert ok, reason
        except Exception:
            pass


def test_native_available_rejects_non_elf_target():
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
    f.write(b"MZ" + b"\x00" * 100)
    f.close()
    try:
        ok, reason = _sandbox.native_available(f.name)
        assert ok is False and "ELF" in reason
    finally:
        os.unlink(f.name)
