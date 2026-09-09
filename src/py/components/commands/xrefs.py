from typing import Any, Dict, List
import idautils
import idc
import ida_funcs
import ida_idaapi

from utils.safety import safeCall, safeCastInt, safeCastStr
import components.decompiler

def xrefsThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    target = params.get("ea") or params.get("addr") or params.get("address") or params.get("name")
    if not target:
        return {"success": False, "error": "missing ea or name parameter"}

    ea = components.decompiler.parseAddress(target)
    if ea is None and isinstance(target, str):
        ea = components.decompiler.findFunctionByName(target)

    if ea is None or ea == ida_idaapi.BADADDR:
        return {"success": False, "error": f"could not resolve address for '{target}'"}

    limit = safeCastInt(params.get("limit"), fallback=100)
    limit = min(max(1, limit), 500)

    results: List[Dict[str, Any]] = []
    for x in idautils.XrefsTo(ea):
        if len(results) >= limit:
            break
        fn = safeCastStr(idc.get_func_name(x.frm) or idc.get_name(x.frm))
        funcObj = ida_funcs.get_func(x.frm)
        fnEa = hex(funcObj.start_ea) if funcObj else hex(x.frm)
        results.append({
            "frm": hex(x.frm),
            "func_ea": fnEa,
            "func_name": fn or f"sub_{fnEa[2:]}",
            "is_code": bool(x.iscode),
            "type": int(x.type)
        })

    return {
        "success": True,
        "ea": hex(ea),
        "count": len(results),
        "results": results
    }
