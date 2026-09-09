from typing import Any, Dict
import sys
import os
import pkgutil
import importlib
from utils.logger import bridgeLog
from utils.safety import safeCall

def reloadThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    bridgeLog("remote reload triggered via reload component")
    try:
        import utils.safety
        import utils.logger
        import utils.ports
        import utils.dumpInfo
        import utils.sigEngine
        import components.decompiler
        import components.commands

        importlib.reload(utils.safety)
        importlib.reload(utils.logger)
        importlib.reload(utils.ports)
        importlib.reload(utils.dumpInfo)
        importlib.reload(utils.sigEngine)
        utils.sigEngine._SEG_CACHE.refresh()
        importlib.reload(components.decompiler)

        # dynamically discover and reload all command components
        if hasattr(components.commands, "__path__"):
            for _, modName, _ in pkgutil.iter_modules(components.commands.__path__):
                try:
                    fullName = f"components.commands.{modName}"
                    m = sys.modules.get(fullName)
                    if m:
                        importlib.reload(m)
                    else:
                        importlib.import_module(fullName)
                except Exception:
                    pass

        importlib.reload(components.commands)

        import components.server
        importlib.reload(components.server)

        # refresh registry cache
        components.commands.COMMANDS_BY_NAME = components.commands.getCommandsByName()

        return {
            "success": True,
            "status": "reloaded",
            "version": "1.0.0",
            "commands": list(components.commands.COMMANDS_BY_NAME.keys())
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
