"""binoracle: local, oracle-grounded LLM copilot for binary RE and exploitation."""

# Run pwntools headless (no terminal control) when the exploit workflows import it. pwntools
# resets its OWN logger level to a very low value on import, so the WARNING-level noise it emits
# (e.g. "Could not populate PLT: Cannot allocate 1GB memory to run Unicorn Engine" when its
# optional Unicorn PLT emulation can't allocate -- cosmetic, analysis falls back to cached
# gadgets) can only be silenced by pinning the level AFTER `from pwn import ...`. Two call sites
# genuinely exist: (1) HOST-PROCESS imports -- rop.py/shellcode.py/fmtstring.py/autopoc.py build
# a chain or PoC snippet directly in this process and call `_quiet_pwn()` right after their own
# `from pwn import`; (2) driver SCRIPTS (separate `from pwn import ...` strings that run as their
# own subprocess in the sandbox) quiet themselves inline via `context.log_level = "error"`
# instead, since `_quiet_pwn()` can't run inside a process it was never imported into. A prior
# "unused import" cleanup pass nearly deleted this function entirely, having only grepped for
# TOP-LEVEL (column-0) `from pwn import` and missing the four indented, in-`try:` host-process
# call sites above -- caught by actually running `autopwn` against a real sample and seeing it
# fail with `cannot import name '_quiet_pwn'`, not by static analysis. PWNLIB_NOTERM is set here
# unconditionally: env vars set in this process are inherited by every driver subprocess too.
import os as _os

_os.environ.setdefault("PWNLIB_NOTERM", "1")

__version__ = "0.1.0"


def _quiet_pwn() -> None:
    """Pin pwntools' logger to ERROR. Call right AFTER `from pwn import ...` in a HOST-PROCESS
    import (pwntools sets its own logger level on import, so this must run after). Keeps
    cosmetic Unicorn/PLT warnings out of grounded reports without hiding real errors."""
    import logging as _logging
    _logging.getLogger("pwnlib").setLevel(_logging.ERROR)


def _quiet_angr() -> None:
    """Pin angr/cle/pyvex's loggers to ERROR. angr (unlike pwntools) IS imported directly into
    this process by oracles/symbolic_angr.py, oracles/concolic.py and workflows/autopoc.py --
    call this right after `import angr` in any module that does so, so a new one can't forget
    and let angr's own INFO-level analysis chatter leak into a grounded report."""
    import logging as _logging
    _logging.getLogger("angr").setLevel(_logging.ERROR)
    _logging.getLogger("cle").setLevel(_logging.ERROR)
    _logging.getLogger("pyvex").setLevel(_logging.ERROR)
