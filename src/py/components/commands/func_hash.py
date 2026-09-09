import ida_funcs
import ida_bytes
import ida_idaapi
import idc
from typing import Any, Dict
import components.decompiler
from utils.logger import bridgeLog
import utils.tlshEngine as tlshEngine
from utils.normalizer import normalizeFunctionBytes

def resolveTargetEa(raw):
    ea = components.decompiler.parseAddress(raw)
    if ea is None and isinstance(raw, str):
        ea = components.decompiler.findFunctionByName(raw)
    return ea

def hashFunctionBytes(func, mode="normalized"):
    startEa = func.start_ea
    endEa = func.end_ea
    if mode == "normalized":
        normalized = normalizeFunctionBytes(startEa, endEa)
        if normalized:
            return tlshEngine.hashBuffer(normalized)
    rawBytes = ida_bytes.get_bytes(startEa, endEa - startEa)
    if rawBytes:
        return tlshEngine.hashBuffer(rawBytes)
    return ""

def funcHashThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    target = params.get("ea") or params.get("addr") or params.get("address") or params.get("name") or params.get("target")
    if not target:
        return {"success": False, "error": "missing ea or name parameter"}

    mode = params.get("mode") or "normalized"
    if mode not in ("raw", "normalized"):
        mode = "normalized"

    ea = resolveTargetEa(str(target))
    if ea is None or ea == ida_idaapi.BADADDR:
        return {"success": False, "error": f"invalid address or symbol: {target}"}

    func = ida_funcs.get_func(ea)
    if not func:
        return {"success": False, "error": f"no function at {hex(ea)}"}

    startEa = func.start_ea
    size = func.end_ea - startEa

    h = hashFunctionBytes(func, mode=mode)
    if not h:
        return {"success": False, "error": "failed to compute tlsh hash (insufficient entropy or dll error)"}

    funcName = idc.get_func_name(startEa)
    return {
        "success": True,
        "ea": hex(startEa),
        "name": funcName,
        "size": size,
        "mode": mode,
        "tlsh": h,
    }

def funcDiffThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    target1 = params.get("target1") or params.get("ea1") or params.get("h1") or params.get("hash1")
    target2 = params.get("target2") or params.get("ea2") or params.get("h2") or params.get("hash2")
    if not target1 or not target2:
        return {"success": False, "error": "missing target1/ea1 and target2/ea2 parameters"}

    mode = params.get("mode") or "normalized"
    if mode not in ("raw", "normalized"):
        mode = "normalized"

    def resolveHash(val: str) -> str:
        s = val.strip()
        if s.startswith("T1") and len(s) >= 70:
            return s
        ea = resolveTargetEa(s)
        if ea is not None and ea != ida_idaapi.BADADDR:
            f = ida_funcs.get_func(ea)
            if f:
                return hashFunctionBytes(f, mode=mode)
        return ""

    h1 = resolveHash(str(target1))
    h2 = resolveHash(str(target2))

    if not h1:
        return {"success": False, "error": f"could not resolve hash for: {target1}"}
    if not h2:
        return {"success": False, "error": f"could not resolve hash for: {target2}"}

    diff = tlshEngine.compareHashes(h1, h2)
    verdict = "identical"
    if diff == 0:
        verdict = "identical"
    elif diff <= 30:
        verdict = "patch variant (very close)"
    elif diff <= 70:
        verdict = "similar"
    else:
        verdict = "different"

    return {
        "success": True,
        "target1": str(target1),
        "target2": str(target2),
        "hash1": h1,
        "hash2": h2,
        "mode": mode,
        "distance": diff,
        "verdict": verdict,
    }
