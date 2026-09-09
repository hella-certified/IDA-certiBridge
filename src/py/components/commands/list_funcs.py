from typing import Any, Dict, List
import ida_funcs
import idautils
import idc

from utils.safety import safeCall, safeCastInt, safeCastStr

def listFuncsThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    query = safeCastStr(params.get("query") or params.get("q") or params.get("filter")).strip().lower()
    limit = safeCastInt(params.get("limit"), fallback=50)
    offset = safeCastInt(params.get("offset"), fallback=0)
    unnamedOnly = params.get("unnamed_only") == "1" or params.get("unnamed_only") == "true"

    limit = min(max(1, limit), 500)
    results: List[Dict[str, Any]] = []
    matchedTotal = 0

    for ea in idautils.Functions():
        name = safeCastStr(idc.get_func_name(ea) or idc.get_name(ea))
        isUnnamed = name.startswith("sub_") or name.startswith("loc_") or name.startswith("nullsub_")

        if unnamedOnly and not isUnnamed:
            continue

        if query and query not in name.lower():
            continue

        matchedTotal += 1
        if matchedTotal <= offset:
            continue

        if len(results) < limit:
            fn = ida_funcs.get_func(ea)
            fnSize = fn.size() if fn else 0
            results.append({
                "ea": hex(ea),
                "name": name,
                "size": fnSize,
                "is_unnamed": isUnnamed
            })

    return {
        "success": True,
        "query": query,
        "total_matched": matchedTotal,
        "returned": len(results),
        "offset": offset,
        "limit": limit,
        "results": results
    }
