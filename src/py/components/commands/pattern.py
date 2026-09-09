from typing import Any, Dict, List
import struct
import ida_bytes
import ida_funcs
import idc

from utils.safety import safeCall, safeCastInt, safeCastStr
from utils.sigEngine import scanPattern

def parsePatternTokens(patStr: str) -> List[str]:
    tokens: List[str] = []
    clean = patStr.strip()

    if "\\x" in clean:
        parts = clean.split("\\x")
        for p in parts:
            if not p:
                continue
            hexVal = p[:2]
            tokens.append(hexVal.upper())
        return tokens

    parts = clean.replace(",", " ").split()
    for p in parts:
        token = p.strip()
        if token in ("?", "??"):
            tokens.append("?")
        else:
            if token.startswith("0x") or token.startswith("0X"):
                token = token[2:]
            tokens.append(token.upper().zfill(2))
    return tokens

def findPatternThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    rawPattern = params.get("pattern") or params.get("sig") or params.get("query")
    if not rawPattern:
        return {"success": False, "error": "missing pattern parameter"}

    limit = safeCastInt(params.get("limit"), fallback=50)
    ripOffset = safeCastInt(params.get("rip_offset"), fallback=-1)
    insnLen = safeCastInt(params.get("insn_len"), fallback=-1)

    tokens = parsePatternTokens(safeCastStr(rawPattern))
    if not tokens:
        return {"success": False, "error": "invalid pattern syntax"}

    matchedAddresses = scanPattern(tokens, limit=limit)
    matches: List[Dict[str, Any]] = []

    for matchEa in matchedAddresses:
        fn = idc.get_func_name(matchEa)
        funcObj = ida_funcs.get_func(matchEa)
        fnEa = hex(funcObj.start_ea) if funcObj else hex(matchEa)

        item: Dict[str, Any] = {
            "ea": hex(matchEa),
            "func_name": fn or f"sub_{fnEa[2:]}",
            "func_ea": fnEa,
            "offset_in_func": (matchEa - funcObj.start_ea) if funcObj else 0
        }

        if ripOffset >= 0 and insnLen > 0:
            dispBytes = ida_bytes.get_bytes(matchEa + ripOffset, 4)
            if dispBytes and len(dispBytes) == 4:
                disp32 = struct.unpack("<i", dispBytes)[0]
                resolvedTarget = matchEa + insnLen + disp32
                targetName = idc.get_func_name(resolvedTarget) or idc.get_name(resolvedTarget) or hex(resolvedTarget)
                item["rip_target"] = hex(resolvedTarget)
                item["rip_target_name"] = targetName
                item["disp32"] = disp32

        matches.append(item)

    return {
        "success": True,
        "pattern": " ".join(tokens),
        "matchCount": len(matches),
        "matches": matches
    }
