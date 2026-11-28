"""The inventory of record: typed scanner evidence resolved into agents, instances and tools."""
from quin_scanner.inventory.evidence import NO_INSTRUCTIONS, AgentSite, InstructionsRef, ToolSite
from quin_scanner.inventory.resolver import Inventory
from quin_scanner.inventory.resolver import fallback as fallback_inventory
from quin_scanner.inventory.resolver import resolve as resolve_inventory

__all__ = [
    "NO_INSTRUCTIONS",
    "AgentSite",
    "InstructionsRef",
    "Inventory",
    "ToolSite",
    "fallback_inventory",
    "resolve_inventory",
]
