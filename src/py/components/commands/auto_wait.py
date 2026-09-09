import time
from typing import Any, Dict
import ida_auto

from utils.safety import safeCastFloat

def autoWaitThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    timeout = safeCastFloat(params.get("timeout"), fallback=30.0)
    startTime = time.time()

    if ida_auto.auto_is_ok():
        return {
            "success": True,
            "status": "idle",
            "analyzing": False,
            "elapsed_sec": 0.0,
            "message": "auto-analysis is idle/complete"
        }

    while not ida_auto.auto_is_ok():
        elapsed = time.time() - startTime
        if elapsed >= timeout:
            return {
                "success": False,
                "status": "busy",
                "analyzing": True,
                "elapsed_sec": round(elapsed, 3),
                "error": f"auto-analysis still running after {timeout:.0f}s"
            }
        time.sleep(0.2)

    return {
        "success": True,
        "status": "idle",
        "analyzing": False,
        "elapsed_sec": round(time.time() - startTime, 3),
        "message": "auto-analysis completed"
    }
