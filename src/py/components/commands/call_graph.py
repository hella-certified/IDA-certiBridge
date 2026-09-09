from typing import Any, Dict, List
import ida_funcs
import ida_idaapi
import idautils
import idc

import components.decompiler
from utils.safety import safeCall, safeCastInt, safeCastStr

def resolveTargetEa(raw):
    ea = components.decompiler.parseAddress(raw)
    if ea is None and isinstance(raw, str):
        ea = components.decompiler.findFunctionByName(raw)
    return ea

def isThunkOrRuntime(func) -> bool:
    if not func:
        return False
    if (func.flags & ida_funcs.FUNC_THUNK) != 0:
        return True
    name = idc.get_func_name(func.start_ea)
    if name.startswith("__") or name.startswith("j_") or name.startswith("sub_thunk"):
        return True
    return False

def callersThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    target = params.get("ea") or params.get("addr") or params.get("address")
    if not target:
        return {"success": False, "error": "missing ea parameter"}

    ea = resolveTargetEa(target)
    if ea is None or ea == ida_idaapi.BADADDR:
        return {"success": False, "error": f"could not resolve address for '{target}'"}

    limit = safeCastInt(params.get("limit"), fallback=100)
    userOnly = params.get("user_only") != "0" and params.get("user_only") != "false"

    func = ida_funcs.get_func(ea)
    targetStart = func.start_ea if func else ea

    callers: List[Dict[str, Any]] = []
    seen = set()

    for ref in idautils.CodeRefsTo(targetStart, 0):
        callerFunc = ida_funcs.get_func(ref)
        if not callerFunc:
            continue
        if userOnly and isThunkOrRuntime(callerFunc):
            continue

        cStart = callerFunc.start_ea
        if cStart in seen:
            continue
        seen.add(cStart)

        cName = idc.get_func_name(cStart) or f"sub_{hex(cStart)[2:]}"
        callers.append(
            {
                "caller_ea": hex(ref),
                "func_ea": hex(cStart),
                "func_name": cName
            }
        )
        if len(callers) >= limit:
            break

    return {
        "success": True,
        "ea": hex(targetStart),
        "callerCount": len(callers),
        "callers": callers
    }

def calleesThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    target = params.get("ea") or params.get("addr") or params.get("address")
    if not target:
        return {"success": False, "error": "missing ea parameter"}

    ea = resolveTargetEa(target)
    if ea is None or ea == ida_idaapi.BADADDR:
        return {"success": False, "error": f"could not resolve address for '{target}'"}

    limit = safeCastInt(params.get("limit"), fallback=100)
    userOnly = params.get("user_only") != "0" and params.get("user_only") != "false"

    func = ida_funcs.get_func(ea)
    if not func:
        return {"success": False, "error": f"no function found at {hex(ea)}"}

    callees: List[Dict[str, Any]] = []
    seen = set()

    for item in idautils.FuncItems(func.start_ea):
        for ref in idautils.CodeRefsFrom(item, 0):
            targetFunc = ida_funcs.get_func(ref)
            if not targetFunc:
                continue
            if userOnly and isThunkOrRuntime(targetFunc):
                continue

            tStart = targetFunc.start_ea
            if tStart == func.start_ea or tStart in seen:
                continue
            seen.add(tStart)

            tName = idc.get_func_name(tStart) or f"sub_{hex(tStart)[2:]}"
            callees.append(
                {
                    "call_site": hex(item),
                    "func_ea": hex(tStart),
                    "func_name": tName
                }
            )
            if len(callees) >= limit:
                break
        if len(callees) >= limit:
            break

    return {
        "success": True,
        "ea": hex(func.start_ea),
        "calleeCount": len(callees),
        "callees": callees
    }
