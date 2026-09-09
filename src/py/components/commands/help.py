from typing import Any, Dict

def helpThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    from components.commands import COMMAND_REGISTRY
    listing = [
        {"name": cmd.name, "usage": cmd.usage, "description": cmd.description}
        for cmd in COMMAND_REGISTRY
    ]
    return {"success": True, "commands": listing}
