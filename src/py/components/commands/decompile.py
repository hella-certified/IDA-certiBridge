from typing import Any, Dict
from utils.logger import bridgeLog
import components.decompiler

def decompileThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    target = params.get("ea") or params.get("addr") or params.get("address") or params.get("symbol")
    if not target:
        return {"success": False, "error": "missing ea or symbol parameter"}

    bridgeLog(f"decompilation requested for: {target}")
    dirty = params.get("dirty") == "1" or params.get("force") == "1"
    res = components.decompiler.decompileFunction(target, dirty=dirty)
    if params.get("raw") == "1" or params.get("plain") == "1" or params.get("format") == "raw":
        res["isRaw"] = True
    return res
