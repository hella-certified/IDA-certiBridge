import ida_hexrays
import ida_lines
import ida_funcs
import ida_idaapi
import ida_name
import idautils
import idc

def parseAddress(raw):
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        clean = raw.strip()
        if clean.startswith(("0x", "0X")):
            try:
                return int(clean, 16)
            except ValueError:
                return None
        if clean.isdigit() or (clean.startswith("-") and clean[1:].isdigit()):
            try:
                return int(clean)
            except ValueError:
                return None
    return None

_FUNC_NAME_CACHE = {}

def clearFunctionCache():
    global _FUNC_NAME_CACHE
    _FUNC_NAME_CACHE.clear()

def buildFunctionCache():
    global _FUNC_NAME_CACHE
    cache = {}
    shortDn = idc.get_inf_attr(idc.INF_SHORT_DN)
    for fEa in idautils.Functions():
        fnName = idc.get_func_name(fEa)
        if not fnName:
            continue
        fnLower = fnName.lower()
        cache[fnLower] = fEa
        if "::" in fnLower:
            cache[fnLower.split("::")[-1]] = fEa
        demangled = idc.demangle_name(fnName, shortDn)
        if demangled:
            dLower = demangled.lower()
            cache[dLower] = fEa
            if "::" in dLower:
                cache[dLower.split("::")[-1]] = fEa
    _FUNC_NAME_CACHE = cache

def findFunctionByName(name: str):
    clean = name.strip()
    if "(" in clean:
        parts = clean.split("(")[0].strip().split()
        if parts:
            clean = parts[-1].strip("*& ")

    ea = idc.get_name_ea_simple(clean)
    if ea != ida_idaapi.BADADDR and ea != 0:
        return ea

    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, clean)
    if ea != ida_idaapi.BADADDR and ea != 0:
        return ea

    lower = clean.lower()
    global _FUNC_NAME_CACHE
    if not _FUNC_NAME_CACHE:
        buildFunctionCache()

    return _FUNC_NAME_CACHE.get(lower)

def decompileFunction(rawInput, dirty: bool = False) -> dict:
    if not ida_hexrays.init_hexrays_plugin():
        return {"success": False, "error": "hex-rays decompiler unavailable"}

    try:
        normEa = parseAddress(rawInput)
        if normEa is None and isinstance(rawInput, str):
            normEa = findFunctionByName(rawInput)

        if normEa is None or normEa == ida_idaapi.BADADDR:
            return {"success": False, "error": f"could not resolve address or symbol for '{rawInput}'"}

        func = ida_funcs.get_func(normEa)
        targetEa = func.start_ea if func else normEa

        if dirty:
            ida_hexrays.mark_cfunc_dirty(targetEa)

        cfunc = ida_hexrays.decompile(targetEa)
        if not cfunc:
            return {"success": False, "error": f"failed to decompile function at {hex(targetEa)}"}

        lines = [ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()]
        return {
            "success": True,
            "ea": hex(targetEa),
            "code": "\n".join(lines)
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
