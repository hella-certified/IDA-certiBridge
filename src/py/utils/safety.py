from typing import Any, Callable, Dict, Optional
import json
import traceback

def safeCall(fn: Callable, *args, fallback: Any = None, **kwargs) -> Any:
    try:
        return fn(*args, **kwargs)
    except Exception:
        return fallback

def safeCastInt(val: Any, fallback: int = 0) -> int:
    try:
        return int(val) if val is not None else fallback
    except (ValueError, TypeError):
        return fallback

def safeCastStr(val: Any, fallback: str = "") -> str:
    try:
        return str(val) if val is not None else fallback
    except Exception:
        return fallback

def safeCastFloat(val: Any, fallback: float = 0.0) -> float:
    try:
        return float(val) if val is not None else fallback
    except (ValueError, TypeError):
        return fallback

def safeJsonLoads(val: Any, fallback: Any = None) -> Any:
    try:
        return json.loads(val) if isinstance(val, (str, bytes, bytearray)) else fallback
    except Exception:
        return fallback

def safeJsonDumps(val: Any, fallback: str = "{}") -> str:
    try:
        return json.dumps(val, ensure_ascii=False)
    except Exception:
        return fallback

import threading
import ida_kernwin

def safeExecute(action: str, fn: Callable, *args, **kwargs) -> Dict[str, Any]:
    try:
        if threading.current_thread() is not threading.main_thread():
            box = {}
            def syncTarget():
                try:
                    box["res"] = fn(*args, **kwargs)
                except Exception as e:
                    box["exc"] = e
                return 1
            ida_kernwin.execute_sync(syncTarget, ida_kernwin.MFF_WRITE)
            if "exc" in box:
                raise box["exc"]
            res = box.get("res")
        else:
            res = fn(*args, **kwargs)
        return res if isinstance(res, dict) else {"success": True, "result": res}
    except Exception as e:
        from utils.logger import bridgeLog
        safeCall(bridgeLog, f"safe execution failure in '{action}': {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        }
