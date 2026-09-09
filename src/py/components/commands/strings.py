import time
from typing import Any, Dict, List
import ida_bytes
import ida_segment
import ida_idaapi
import ida_funcs
import ida_strlist
import idautils
import idc

from utils.safety import safeCall, safeCastInt, safeCastStr, safeCastFloat

def safeBinSearch(startEa, endEa, pattern: bytes, mask: bytes = b"", step: int = ida_bytes.BIN_SEARCH_FORWARD):
    try:
        return ida_bytes.bin_search(startEa, endEa, pattern, mask, len(pattern), step)
    except Exception:
        return ida_idaapi.BADADDR

def searchStringsThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    query = params.get("query") or params.get("q") or params.get("str") or ""
    cleanQuery = safeCastStr(query).strip()
    isWildcard = not cleanQuery or cleanQuery == "*"
    lowerQuery = cleanQuery.lower()

    limit = safeCastInt(params.get("limit"), fallback=50)
    wantXrefs = params.get("xrefs") != "0" and params.get("xrefs") != "false"
    maxXrefs = safeCastInt(params.get("max_xrefs"), fallback=20)
    maxDuration = safeCastFloat(params.get("max_duration"), fallback=25.0)

    results: List[Dict[str, Any]] = []
    startTime = time.time()
    isPartial = False

    try:
        qty = ida_strlist.get_strlist_qty()
        if qty == 0:
            ida_strlist.build_strlist()
            qty = ida_strlist.get_strlist_qty()

        si = ida_strlist.string_info_t()
        for i in range(qty):
            if len(results) >= limit:
                break
            if i % 250 == 0 and time.time() - startTime > maxDuration:
                isPartial = True
                break
            if ida_strlist.get_strlist_item(si, i):
                raw = ida_bytes.get_strlit_contents(si.ea, si.length, si.type)
                if raw:
                    val = raw.decode("utf-8", errors="replace")
                    if isWildcard or lowerQuery in val.lower():
                        xrefs = []
                        if wantXrefs:
                            try:
                                for idx, x in enumerate(idautils.XrefsTo(si.ea)):
                                    if idx >= maxXrefs:
                                        break
                                    fn = idc.get_func_name(x.frm)
                                    funcObj = ida_funcs.get_func(x.frm)
                                    fnEa = hex(funcObj.start_ea) if funcObj else hex(x.frm)
                                    xrefs.append({
                                        "caller_ea": hex(x.frm),
                                        "func_name": fn or f"sub_{fnEa[2:]}",
                                        "func_ea": fnEa
                                    })
                            except Exception:
                                pass

                        results.append({
                            "ea": hex(si.ea),
                            "string": val,
                            "length": si.length,
                            "xrefs": xrefs
                        })
    except Exception:
        pass

    if not results and not isWildcard and not isPartial:
        queryBytes = cleanQuery.encode("utf-8")
        try:
            seg = ida_segment.get_first_seg()
            while seg and len(results) < limit:
                if time.time() - startTime > maxDuration:
                    isPartial = True
                    break
                segStart = seg.start_ea
                segEnd = seg.end_ea
                cur = segStart
                while cur < segEnd and len(results) < limit:
                    if time.time() - startTime > maxDuration:
                        isPartial = True
                        break
                    found = safeBinSearch(cur, segEnd, queryBytes)
                    if found == ida_idaapi.BADADDR or found == 0:
                        break

                    strVal = idc.get_strlit_contents(found)
                    text = strVal.decode("utf-8", errors="replace") if strVal else cleanQuery

                    xrefs = []
                    if wantXrefs:
                        try:
                            for idx, x in enumerate(idautils.XrefsTo(found)):
                                if idx >= maxXrefs:
                                    break
                                fn = idc.get_func_name(x.frm)
                                funcObj = ida_funcs.get_func(x.frm)
                                fnEa = hex(funcObj.start_ea) if funcObj else hex(x.frm)
                                xrefs.append({
                                    "caller_ea": hex(x.frm),
                                    "func_name": fn or f"sub_{fnEa[2:]}",
                                    "func_ea": fnEa
                                })
                        except Exception:
                            pass

                    results.append({
                        "ea": hex(found),
                        "string": text,
                        "length": len(queryBytes),
                        "xrefs": xrefs
                    })
                    cur = found + max(1, len(queryBytes))

                seg = ida_segment.get_next_seg(segStart)
        except Exception:
            pass

    return {
        "success": True,
        "query": cleanQuery,
        "count": len(results),
        "results": results,
        "partial": isPartial,
        "elapsed_sec": round(time.time() - startTime, 3)
    }
