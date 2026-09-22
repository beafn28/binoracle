"""Oracle registry assembly."""
from .base import Oracle, Tool, ToolParam, ToolResult, ToolRegistry
from .elf_meta import ElfMetaOracle
from .static_r2 import R2Oracle
from .symbolic_angr import AngrOracle
from .dynamic_dbg import DebuggerOracle
from .exploit_helpers import ExploitHelperOracle


def build_registry(binary: str, enable_dynamic: bool = False) -> ToolRegistry:
    """Assemble all oracles for a target binary.

    Dynamic (debugger) execution is opt-in because it actually runs the target."""
    oracles = [
        ElfMetaOracle(binary),
        R2Oracle(binary),
        AngrOracle(binary),
        ExploitHelperOracle(binary),
    ]
    if enable_dynamic:
        oracles.append(DebuggerOracle(binary))
    return ToolRegistry(oracles)
