from typing import Any, Dict, List
import ida_typeinf
import idautils

from utils.safety import safeCall, safeCastInt, safeCastStr

def listStructsThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    query = safeCastStr(params.get("query") or params.get("q") or params.get("filter")).strip().lower()
    limit = safeCastInt(params.get("limit"), fallback=50)
    offset = safeCastInt(params.get("offset"), fallback=0)

    limit = min(max(1, limit), 500)
    results: List[Dict[str, Any]] = []
    matchedTotal = 0

    try:
        ordLimit = safeCall(ida_typeinf.get_ordinal_limit, fallback=0)
        for ordIdx in range(1, ordLimit):
            tif = ida_typeinf.tinfo_t()
            if not tif.get_numbered_type(None, ordIdx):
                continue

            name = safeCastStr(tif.get_type_name())
            if not name:
                continue

            if query and query not in name.lower():
                continue

            matchedTotal += 1
            if matchedTotal <= offset:
                continue

            if len(results) < limit:
                size = safeCall(tif.get_size, fallback=0)
                results.append({
                    "name": name,
                    "ordinal": ordIdx,
                    "size": size,
                    "is_struct": bool(tif.is_struct()),
                    "is_union": bool(tif.is_union()),
                    "is_enum": bool(tif.is_enum())
                })
    except Exception:
        pass

    # fallback to idautils.Structs() if ordinal iteration returned empty
    if not results and not matchedTotal:
        try:
            for sTuple in idautils.Structs():
                sName = safeCastStr(sTuple[2]) if len(sTuple) > 2 else ""
                if not sName:
                    continue

                if query and query not in sName.lower():
                    continue

                matchedTotal += 1
                if matchedTotal <= offset:
                    continue

                if len(results) < limit:
                    results.append({
                        "name": sName,
                        "ordinal": sTuple[0] if len(sTuple) > 0 else 0,
                        "size": 0,
                        "is_struct": True
                    })
        except Exception:
            pass

    return {
        "success": True,
        "query": query,
        "total_matched": matchedTotal,
        "returned": len(results),
        "offset": offset,
        "limit": limit,
        "results": results
    }
