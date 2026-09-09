from typing import Any, Dict, List
import urllib.request
import urllib.parse
import collections
import ida_funcs
import ida_bytes
import ida_idaapi
import idautils
import idc

from utils.safety import safeCastInt, safeCastStr, safeJsonLoads
import components.decompiler

def extractFunctionStrings(funcEa: int) -> List[str]:
    func = ida_funcs.get_func(funcEa)
    if not func:
        return []

    strings = []
    seen = set()
    for itemEa in idautils.FuncItems(func.start_ea):
        for dataRef in idautils.DataRefsFrom(itemEa):
            strType = idc.get_str_type(dataRef)
            if strType is not None and strType != ida_idaapi.BADADDR:
                rawStr = idc.get_strlit_contents(dataRef)
                if rawStr:
                    try:
                        clean = rawStr.decode("utf-8", errors="ignore").strip()
                        if len(clean) >= 4 and clean not in seen:
                            seen.add(clean)
                            strings.append(clean)
                    except Exception:
                        pass
    return strings

def matchXrefsThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    target = params.get("ea") or params.get("addr") or params.get("address") or params.get("name")
    fromPort = safeCastInt(params.get("from_port") or params.get("fromPort") or params.get("port") or params.get("remote_port") or params.get("remotePort"), fallback=0)

    if not target:
        return {"success": False, "error": "missing ea or name parameter"}

    ea = components.decompiler.parseAddress(target)
    if ea is None and isinstance(target, str):
        ea = components.decompiler.findFunctionByName(target)

    if ea is None or ea == ida_idaapi.BADADDR:
        return {"success": False, "error": f"could not resolve address for '{target}'"}

    func = ida_funcs.get_func(ea)
    targetEa = func.start_ea if func else ea
    funcName = idc.get_func_name(targetEa) or idc.get_name(targetEa)

    localStrings = extractFunctionStrings(targetEa)

    if fromPort == 0:
        return {
            "success": True,
            "ea": hex(targetEa),
            "funcName": funcName,
            "stringsFound": len(localStrings),
            "strings": localStrings
        }

    candidateScores = collections.defaultdict(lambda: {"func_name": "", "func_ea": "", "matched_strings": []})
    for s in localStrings[:20]:
        queryUrl = f"http://127.0.0.1:{fromPort}/api/search_strings?query={urllib.parse.quote(s)}"
        try:
            req = urllib.request.Request(queryUrl, headers={"Connection": "close"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = safeJsonLoads(resp.read().decode("utf-8", errors="replace"))
                if isinstance(data, dict) and data.get("success"):
                    for result in data.get("results", []):
                        for xref in result.get("xrefs", []):
                            fnEa = xref.get("func_ea")
                            fnName = xref.get("func_name")
                            if fnEa and fnName and not fnName.startswith("sub_"):
                                entry = candidateScores[fnEa]
                                entry["func_name"] = fnName
                                entry["func_ea"] = fnEa
                                if s not in entry["matched_strings"]:
                                    entry["matched_strings"].append(s)
        except Exception:
            continue

    rankedCandidates = sorted(
        candidateScores.values(),
        key=lambda c: len(c["matched_strings"]),
        reverse=True
    )

    return {
        "success": True,
        "ea": hex(targetEa),
        "funcName": funcName,
        "stringsChecked": min(len(localStrings), 20),
        "totalStrings": len(localStrings),
        "matchesCount": len(rankedCandidates),
        "matches": rankedCandidates[:10]
    }
