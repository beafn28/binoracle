"""Oracle registry assembly."""
from .base import Oracle as Oracle, Tool as Tool, ToolParam as ToolParam, ToolResult as ToolResult, ToolRegistry
from .elf_meta import ElfMetaOracle
from .static_r2 import R2Oracle
from .symbolic_angr import AngrOracle
from .dynamic_dbg import DebuggerOracle
from .heap_dynamic import HeapDynamicOracle
from .frida_dynamic import FridaDynamicOracle
from .concolic import ConcolicOracle
from .exploit_helpers import ExploitHelperOracle
from .exploit_actions import ExploitActionsOracle
from .ghidra import GhidraOracle
from .decai import DecaiOracle
from .capstone_fallback import CapstoneOracle
from .pe_meta import PeMetaOracle
from .rop_chain import RopChainOracle
from .windows_kernel import WindowsKernelOracle


def build_registry(binary: str, enable_dynamic: bool = False, enable_exploit: bool = False,
                   winver: str | None = None) -> ToolRegistry:
    """Assemble all oracles for a target binary.

    Dynamic (debugger) execution is opt-in because it actually runs the target."""
    oracles = [
        ElfMetaOracle(binary),
        PeMetaOracle(binary),
        R2Oracle(binary),
        RopChainOracle(binary),
        CapstoneOracle(binary),  # only registers itself when radare2 is unavailable
        AngrOracle(binary),
        ExploitHelperOracle(binary),
        GhidraOracle(binary),   # solo se registra si hay un servidor GhidraMCP arriba
        DecaiOracle(binary),    # solo se registra si decai esta instalado y hay LLM listo
        WindowsKernelOracle(winver=winver),
    ]
    if enable_dynamic:
        oracles.append(DebuggerOracle(binary))
        oracles.append(HeapDynamicOracle(binary))
        oracles.append(FridaDynamicOracle(binary))
        oracles.append(ConcolicOracle(binary))
    if enable_exploit:
        oracles.append(ExploitActionsOracle(binary))
    return ToolRegistry(oracles)
