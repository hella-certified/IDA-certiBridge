from typing import Any, Dict
import ida_name
import ida_funcs
import ida_hexrays
import ida_idaapi
import idc

from utils.logger import bridgeLog
import components.decompiler

def resolveTargetEa(raw):
    ea = components.decompiler.parseAddress(raw)
    if ea is None and isinstance(raw, str):
        ea = components.decompiler.findFunctionByName(raw)
    return ea

def allowColonInNames():
    try:
        for char in [":", "<", ">", "~"]:
            cp = ord(char)
            for kind in [getattr(ida_name, "UCDR_NAME", 1), getattr(ida_name, "VNT_IDENT", 0)]:
                try:
                    ida_name.set_cp_validity(cp, kind, True)
                except Exception:
                    try:
                        ida_name.set_cp_validity(kind, cp, cp + 1, True)
                    except Exception:
                        pass
    except Exception:
        pass

def renameFuncThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    target = params.get("ea") or params.get("addr") or params.get("address") or params.get("old_name")
    newName = params.get("name") or params.get("new_name")

    if not target or not newName:
        return {"success": False, "error": "missing ea or new name"}

    ea = resolveTargetEa(target)
    if ea is None or ea == ida_idaapi.BADADDR:
        return {"success": False, "error": f"could not resolve address for '{target}'"}

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
    if not ok:
        return {"success": False, "error": f"failed to rename {hex(targetEa)} to '{newName}'"}

    assignedName = idc.get_func_name(targetEa) or idc.get_name(targetEa) or newName
    bridgeLog(f"renamed function {hex(targetEa)}: '{oldName}' -> '{assignedName}'")
    return {
        "success": True,
        "ea": hex(targetEa),
        "oldName": oldName,
        "newName": assignedName
    }

def renameVarThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    target = params.get("ea") or params.get("addr") or params.get("address") or params.get("func")
    oldVar = params.get("old_name") or params.get("var") or params.get("old")
    newVar = params.get("new_name") or params.get("name") or params.get("new")

    if not target or not oldVar or not newVar:
        return {"success": False, "error": "missing function ea, old variable name, or new variable name"}

    if not ida_hexrays.init_hexrays_plugin():
        return {"success": False, "error": "hex-rays decompiler unavailable"}

    ea = resolveTargetEa(target)
    if ea is None or ea == ida_idaapi.BADADDR:
        return {"success": False, "error": f"could not resolve function for '{target}'"}

    func = ida_funcs.get_func(ea)
    targetEa = func.start_ea if func else ea

    cfunc = ida_hexrays.decompile(targetEa)
    if not cfunc:
        return {"success": False, "error": f"failed to decompile function at {hex(targetEa)}"}

    targetLvar = None
    oldStr = str(oldVar).strip()
    isIdx = oldStr.isdigit()
    idxVal = int(oldStr) if isIdx else -1

    for idx, lvar in enumerate(cfunc.lvars):
        if (isIdx and idx == idxVal) or lvar.name == oldStr:
            targetLvar = lvar
            break

    if not targetLvar:
        available = [l.name for l in cfunc.lvars if l.name]
        return {"success": False, "error": f"variable '{oldVar}' not found", "availableVars": available}

    resolvedOld = targetLvar.name
    renamed = ida_hexrays.rename_lvar(cfunc.entry_ea, resolvedOld, newVar)
    if not renamed:
        return {"success": False, "error": f"hex-rays failed to rename lvar '{resolvedOld}' to '{newVar}'"}

    cfunc.save_user_labels()
    bridgeLog(f"renamed lvar in {hex(targetEa)}: '{resolvedOld}' -> '{newVar}'")
    return {
        "success": True,
        "ea": hex(targetEa),
        "oldVar": resolvedOld,
        "newVar": newVar
    }

def renameParamThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    target = params.get("ea") or params.get("addr") or params.get("address")
    paramIdent = params.get("param") or params.get("old_name") or params.get("index")
    newName = params.get("name") or params.get("new_name")

    if not target or paramIdent is None or not newName:
        return {"success": False, "error": "missing ea, param identifier, or new name"}

    if not ida_hexrays.init_hexrays_plugin():
        return {"success": False, "error": "hex-rays decompiler unavailable"}

    ea = resolveTargetEa(target)
    if ea is None or ea == ida_idaapi.BADADDR:
        return {"success": False, "error": f"could not resolve function for '{target}'"}

    func = ida_funcs.get_func(ea)
    targetEa = func.start_ea if func else ea

    cfunc = ida_hexrays.decompile(targetEa)
    if not cfunc:
        return {"success": False, "error": f"failed to decompile function at {hex(targetEa)}"}

    argVars = [l for l in cfunc.lvars if l.is_arg_var]
    targetArg = None
    pStr = str(paramIdent).strip()

    if pStr.isdigit():
        pIdx = int(pStr)
        if 0 <= pIdx < len(argVars):
            targetArg = argVars[pIdx]
    else:
        for a in argVars:
            if a.name == pStr:
                targetArg = a
                break

    if not targetArg:
        availArgs = [a.name for a in argVars]
        return {"success": False, "error": f"parameter '{paramIdent}' not found", "availableParams": availArgs}

    oldName = targetArg.name
    renamed = ida_hexrays.rename_lvar(cfunc.entry_ea, oldName, newName)
    if not renamed:
        return {"success": False, "error": f"hex-rays failed to rename param '{oldName}' to '{newName}'"}

    cfunc.save_user_labels()
    bridgeLog(f"renamed param in {hex(targetEa)}: '{oldName}' -> '{newName}'")
    return {
        "success": True,
        "ea": hex(targetEa),
        "oldParam": oldName,
        "newParam": newName
    }
