from typing import Any, Dict, List
import ida_bytes
import ida_ida
import ida_idaapi
import ida_nalt
import ida_name
import ida_funcs
import ida_segment
import idc

from utils.safety import safeCall, safeCastInt, safeCastStr

def isCodeAddress(ea: int) -> bool:
    if not ea or ea == ida_idaapi.BADADDR:
        return False
    seg = ida_segment.getseg(ea)
    if not seg:
        return False
    return (seg.perm & ida_segment.SEGPERM_EXEC) != 0 or ida_funcs.get_func(ea) is not None

def findVtablesThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    segName = params.get("seg") or ".rdata"
    query = safeCastStr(params.get("query") or params.get("name") or params.get("filter")).strip().lower()
    minMethods = safeCastInt(params.get("min_methods"), fallback=3)
    limit = safeCastInt(params.get("limit"), fallback=50)

    is64 = ida_ida.inf_is_64bit()
    ptrSize = 8 if is64 else 4
    readPtr = ida_bytes.get_qword if is64 else ida_bytes.get_dword
    imageBase = ida_nalt.get_imagebase()

    targetSeg = ida_segment.get_segm_by_name(segName)
    if not targetSeg:
        targetSeg = ida_segment.get_first_seg()
        while targetSeg:
            curName = ida_segment.get_segm_name(targetSeg)
            if segName.lower() in curName.lower():
                break
            targetSeg = ida_segment.get_next_seg(targetSeg.start_ea)

    if not targetSeg:
        return {"success": False, "error": f"segment '{segName}' not found"}

    vtables: List[Dict[str, Any]] = []
    curr = targetSeg.start_ea
    endEa = targetSeg.end_ea

    while curr < endEa and len(vtables) < limit:
        firstPtr = readPtr(curr)
        if isCodeAddress(firstPtr):
            consecutive = 1
            probe = curr + ptrSize
            while probe < endEa:
                nextPtr = readPtr(probe)
                if isCodeAddress(nextPtr):
                    consecutive += 1
                    probe += ptrSize
                else:
                    break

            if consecutive >= minMethods:
                sym = idc.get_name(curr) or f"vtbl_{hex(curr)[2:]}"
                demangled = ida_name.demangle_name(sym, ida_name.MNG_SHORT_FORM) or sym
                className = ""

                colEa = readPtr(curr - ptrSize)
                if colEa and colEa != ida_idaapi.BADADDR and colEa > imageBase:
                    typeDescRva = ida_bytes.get_dword(colEa + 12)
                    typeDescEa = (imageBase + typeDescRva) if is64 else typeDescRva
                    nameEa = typeDescEa + (16 if is64 else 8)
                    strBytes = ida_bytes.get_strlit_contents(nameEa, 128, ida_nalt.STRTYPE_C)
                    if strBytes:
                        rawMangled = strBytes.decode("utf-8", errors="replace")
                        className = ida_name.demangle_name(rawMangled, ida_name.MNG_SHORT_FORM) or rawMangled

                if query:
                    targetText = f"{sym} {demangled} {className}".lower()
                    if query not in targetText:
                        curr = probe + ptrSize
                        continue

                vtables.append(
                    {
                        "ea": hex(curr),
                        "name": sym,
                        "demangled": demangled,
                        "className": className,
                        "methodCount": consecutive,
                        "firstMethod": hex(firstPtr)
                    }
                )
                curr = probe + ptrSize
                continue

        curr += ptrSize

    return {
        "success": True,
        "segment": segName,
        "query": query,
        "count": len(vtables),
        "vtables": vtables
    }
