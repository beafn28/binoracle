"""binoracle: local, oracle-grounded LLM copilot for binary RE and exploitation."""

# Run pwntools headless (no terminal control) when the exploit workflows import it. pwntools
# resets its OWN logger level to a very low value on import, so the WARNING-level noise it
# emits (e.g. "Could not populate PLT: Cannot allocate 1GB memory to run Unicorn Engine" when
# its optional Unicorn PLT emulation cannot allocate -- cosmetic, analysis falls back to
# cached gadgets) can only be silenced by pinning the level AFTER `from pwn import ...`; each
# exploit workflow does that via `_quiet_pwn()` right after importing pwn.
import os as _os

_os.environ.setdefault("PWNLIB_NOTERM", "1")

__version__ = "0.1.0"


def _quiet_pwn() -> None:
    """Pin pwntools' logger to ERROR. Call right AFTER `from pwn import ...` (pwntools sets its
    own logger level on import, so this must run after). Keeps cosmetic Unicorn/PLT warnings
    out of grounded reports without hiding real errors."""
    import logging as _logging
    _logging.getLogger("pwnlib").setLevel(_logging.ERROR)
