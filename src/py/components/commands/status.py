from typing import Any, Dict
from utils.dumpInfo import getDumpInfo

def statusThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    port = getattr(plugin, "boundPort", 0) if plugin else 0
    info = getDumpInfo(port)
    return {
        "success": True,
        "status": "online",
        "version": "1.0.0",
        "dump": info
    }
