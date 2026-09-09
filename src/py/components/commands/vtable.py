from typing import Any, Dict, List
import ida_bytes
import ida_ida
import ida_idaapi
import ida_name
import ida_funcs
import ida_segment
import idc

import components.decompiler
from utils.safety import safeCall, safeCastInt, safeCastStr

def resolveTargetEa(raw):
    ea = components.decompiler.parseAddress(raw)
    if ea is None and isinstance(raw, str):
        ea = components.decompiler.findFunctionByName(raw)
    return ea

def isCodeAddress(ea: int) -> bool:
    if not ea or ea == ida_idaapi.BADADDR:
        return False
    seg = ida_segment.getseg(ea)
    if not seg:
        return False
    return (seg.perm & ida_segment.SEGPERM_EXEC) != 0 or ida_funcs.get_func(ea) is not None

def vtableInspectThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    target = params.get("ea") or params.get("addr") or params.get("address")
    if not target:
        return {"success": False, "error": "missing ea parameter"}

    ea = resolveTargetEa(target)
    if ea is None or ea == ida_idaapi.BADADDR:
        return {"success": False, "error": f"could not resolve address for '{target}'"}

    maxCount = safeCastInt(params.get("count"), fallback=64)
    is64 = ida_ida.inf_is_64bit()
    ptrSize = 8 if is64 else 4
    readPtr = ida_bytes.get_qword if is64 else ida_bytes.get_dword

    customName = params.get("name") or idc.get_name(ea) or f"Vtbl_{hex(ea)[2:]}"
    cleanName = customName.replace("::", "_").replace(" ", "_")

    methods: List[Dict[str, Any]] = []
    cDeclLines: List[str] = [f"struct {cleanName}", "{"]

    for idx in range(maxCount):
        slotEa = ea + (idx * ptrSize)
        funcEa = readPtr(slotEa)

        if not isCodeAddress(funcEa):
            break

        funcName = idc.get_func_name(funcEa) or idc.get_name(funcEa) or f"sub_{hex(funcEa)[2:]}"
        demangled = ida_name.demangle_name(funcName, ida_name.MNG_SHORT_FORM) or funcName

        methods.append(
            {
                "index": idx,
                "slot_ea": hex(slotEa),
                "func_ea": hex(funcEa),
                "name": funcName,
                "demangled": demangled
            }
        )
        cDeclLines.append(f"    void* (__fastcall* method_{idx}_{funcName})(void* thisPtr);")

    cDeclLines.append("};")
    cDecl = "\n".join(cDeclLines)

    return {
        "success": True,
        "ea": hex(ea),
        "name": cleanName,
        "methodCount": len(methods),
        "methods": methods,
        "c_decl": cDecl
    }
