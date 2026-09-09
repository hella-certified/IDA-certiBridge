from typing import Any, Dict
import urllib.request
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_typeinf
import idc

from utils.logger import bridgeLog
from utils.safety import safeCastInt, safeCastStr, safeJsonLoads
import components.decompiler

def applyPrototype(ea: int, proto: str) -> bool:
    cleanProto = proto.strip().rstrip(";") + ";"
    try:
        tinfo = ida_typeinf.tinfo_t()
        parseFlags = getattr(ida_typeinf, "PT_SIL", 0x0001)
        res = ida_typeinf.parse_decl(tinfo, None, cleanProto, parseFlags)
        if res is not None and tinfo.is_func():
            ok = ida_typeinf.apply_tinfo(ea, tinfo, ida_typeinf.TINFO_DEFINITE)
            if ok and ida_hexrays.init_hexrays_plugin():
                ida_hexrays.mark_cfunc_dirty(ea)
            return bool(ok)
    except Exception:
        pass

    try:
        import re
        fnType = re.sub(r"(\b\w+\s*\([^)]*\))", lambda m: m.group(0)[m.group(0).find("("):], cleanProto, count=1)
        ok = idc.SetType(ea, fnType)
        if ok and ida_hexrays.init_hexrays_plugin():
            ida_hexrays.mark_cfunc_dirty(ea)
        return bool(ok)
    except Exception:
        pass
    return False

def fetchRemotePrototype(fromPort: int, query: str) -> str:
    url = f"http://127.0.0.1:{fromPort}/api/decompile?ea={urllib.parse.quote(query)}&raw=1"
    req = urllib.request.Request(url, headers={"Connection": "close"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        code = resp.read().decode("utf-8", errors="replace")
        lines = [line.strip() for line in code.splitlines() if line.strip() and not line.strip().startswith("//")]
        if not lines:
            return ""
        headerParts = []
        for line in lines:
            headerParts.append(line)
            if ")" in line:
                break
        return " ".join(headerParts)

def copyProtoThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    target = params.get("ea") or params.get("addr") or params.get("address") or params.get("name")
    fromPort = safeCastInt(params.get("from_port") or params.get("fromPort") or params.get("port") or params.get("remote_port") or params.get("remotePort"), fallback=0)
    source = params.get("source") or params.get("from_ea") or params.get("from_name") or target
    explicitProto = params.get("proto") or params.get("decl") or params.get("type")

    if not target:
        return {"success": False, "error": "missing target ea or name"}

    ea = components.decompiler.parseAddress(target)
    if ea is None and isinstance(target, str):
        ea = components.decompiler.findFunctionByName(target)

    if ea is None or ea == ida_idaapi.BADADDR:
        return {"success": False, "error": f"could not resolve function for '{target}'"}

    func = ida_funcs.get_func(ea)
    targetEa = func.start_ea if func else ea
    oldProto = idc.get_type(targetEa) or ""

    protoToApply = explicitProto
    if not protoToApply and fromPort > 0 and source:
        try:
            protoToApply = fetchRemotePrototype(fromPort, str(source))
        except Exception as e:
            return {"success": False, "error": f"failed to fetch prototype from port {fromPort}: {safeCastStr(e)}"}

    if not protoToApply:
        return {"success": False, "error": "no prototype provided or resolved"}

    ok = applyPrototype(targetEa, protoToApply)
    if not ok:
        return {"success": False, "error": f"failed to apply prototype '{protoToApply}' to {hex(targetEa)}"}

    newProto = idc.get_type(targetEa) or protoToApply
    bridgeLog(f"applied prototype to {hex(targetEa)}: '{protoToApply}'")
    return {
        "success": True,
        "ea": hex(targetEa),
        "oldPrototype": oldProto,
        "appliedPrototype": newProto
    }
