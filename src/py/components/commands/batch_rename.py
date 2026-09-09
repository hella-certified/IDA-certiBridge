from typing import Any, Dict, List
import ida_name
import ida_funcs
import idc

from utils.logger import bridgeLog
from utils.safety import safeCastStr
import components.decompiler
from components.commands.rename import allowColonInNames

def batchRenameThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    items = params.get("items") or params.get("renames") or params.get("list")
    if not items or not isinstance(items, list):
        return {"success": False, "error": "missing or invalid items list"}

    results: List[Dict[str, Any]] = []
    renamedCount = 0

    for item in items:
        if not isinstance(item, dict):
            continue
        rawEa = item.get("ea") or item.get("addr") or item.get("address")
        newName = safeCastStr(item.get("name") or item.get("new_name") or item.get("newName")).strip()
        if not rawEa or not newName:
            results.append({"success": False, "error": "missing ea or name", "item": item})
            continue

        ea = components.decompiler.parseAddress(rawEa)
        if ea is None and isinstance(rawEa, str):
            ea = components.decompiler.findFunctionByName(rawEa)

        if ea is None:
            results.append({"success": False, "error": f"could not resolve address '{rawEa}'", "name": newName})
            continue

        func = ida_funcs.get_func(ea)
        targetEa = func.start_ea if func else ea
        oldName = idc.get_func_name(targetEa) or idc.get_name(targetEa)

        if ":" in newName:
            allowColonInNames()

        ok = ida_name.set_name(targetEa, newName, ida_name.SN_NOWARN)
        if not ok:
            ok = ida_name.set_name(targetEa, newName, ida_name.SN_NOWARN | ida_name.SN_FORCE)
        if not ok:
            ok = ida_name.set_name(targetEa, newName, ida_name.SN_NOWARN | ida_name.SN_NOCHECK)

        if ok:
            assigned = idc.get_func_name(targetEa) or idc.get_name(targetEa) or newName
            renamedCount += 1
            results.append({"success": True, "ea": hex(targetEa), "oldName": oldName, "newName": assigned})
        else:
            results.append({"success": False, "ea": hex(targetEa), "error": f"failed to set name '{newName}'"})

    if renamedCount > 0:
        components.decompiler.clearFunctionCache()
        bridgeLog(f"batch renamed {renamedCount}/{len(items)} symbols")

    return {
        "success": True,
        "total": len(items),
        "renamed": renamedCount,
        "results": results
    }
