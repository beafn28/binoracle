"""binoracle: local, oracle-grounded LLM copilot for binary RE and exploitation."""

# Run pwntools headless (no terminal control). pwntools is never imported into THIS process --
# every exploit workflow builds a driver script (a separate `from pwn import ...` string) that
# runs as its own subprocess, in the sandbox or standalone, and quiets pwntools' own WARNING-level
# noise (e.g. "Could not populate PLT: Cannot allocate 1GB memory to run Unicorn Engine" when its
# optional Unicorn PLT emulation can't allocate -- cosmetic, analysis falls back to cached
# gadgets) itself, inline, via `context.log_level = "error"` right after its own `from pwn
# import`. PWNLIB_NOTERM is the one setting that DOES need to be set here: env vars set in this
# process are inherited by every driver subprocess it spawns.
import os as _os

_os.environ.setdefault("PWNLIB_NOTERM", "1")

__version__ = "0.1.0"


def _quiet_angr() -> None:
    """Pin angr/cle/pyvex's loggers to ERROR. angr (unlike pwntools) IS imported directly into
    this process by oracles/symbolic_angr.py, oracles/concolic.py and workflows/autopoc.py --
    call this right after `import angr` in any module that does so, so a new one can't forget
    and let angr's own INFO-level analysis chatter leak into a grounded report."""
    import logging as _logging
    _logging.getLogger("angr").setLevel(_logging.ERROR)
    _logging.getLogger("cle").setLevel(_logging.ERROR)
    _logging.getLogger("pyvex").setLevel(_logging.ERROR)
