from typing import Any, Dict, List, Optional
import struct
import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_segment
import ida_ua
import idautils
import idc

import components.decompiler
from utils.safety import safeCall, safeCastInt, safeCastStr
from utils.sigEngine import (
    countPatternMatches,
    detectRipOperand,
    formatSignature,
    getSegmentCache
)

def resolveTargetEa(raw):
    ea = components.decompiler.parseAddress(raw)
    if ea is None and isinstance(raw, str):
        ea = components.decompiler.findFunctionByName(raw)
    return ea

def buildInsnTokens(ea: int, insnLen: int, insn, rawBytes: bytes, ripInfo: Optional[Dict[str, Any]]) -> List[str]:
    tokens: List[str] = []
    ripStart = ripInfo["rip_offset"] if ripInfo else -1
    ripEnd = (ripStart + ripInfo["disp_len"]) if ripInfo else -1

    for idx, b in enumerate(rawBytes):
        if ripStart != -1 and ripStart <= idx < ripEnd:
            tokens.append("?")
        else:
            tokens.append(f"{b:02X}")

    return tokens

def generateDirectSignature(startEa: int, maxLen: int, allowCrossFunction: bool = False) -> Optional[Dict[str, Any]]:
    tokens: List[str] = []
    cur = startEa
    insn = ida_ua.insn_t()
    firstRipInfo: Optional[Dict[str, Any]] = None

    func = ida_funcs.get_func(startEa)
    endLimit = 0xFFFFFFFFFFFFFFFF if (allowCrossFunction or not func) else func.end_ea

    while len(tokens) < maxLen:
        if cur >= endLimit and not allowCrossFunction:
            break

        insnLen = ida_ua.decode_insn(insn, cur)
        if insnLen <= 0:
            if allowCrossFunction:
                b = ida_bytes.get_byte(cur)
                tokens.append(f"{b:02X}")
                cur += 1
                continue
            break

        rawBytes = ida_bytes.get_bytes(cur, insnLen)
        if not rawBytes:
            break

        ripInfo = detectRipOperand(cur, insn, rawBytes)
        if ripInfo and not firstRipInfo:
            firstRipInfo = ripInfo

        insnTokens = buildInsnTokens(cur, insnLen, insn, rawBytes, ripInfo)
        tokens.extend(insnTokens)

        if len(tokens) >= 8:
            matchCount = countPatternMatches(tokens, maxMatches=2)
            if matchCount == 1:
                formats = formatSignature(tokens)
                return {
                    "mode": "direct",
                    "ea": hex(startEa),
                    "length": len(tokens),
                    "isUnique": True,
                    "rip": firstRipInfo,
                    "formats": formats
                }

        cur += insnLen

    if tokens:
        formats = formatSignature(tokens)
        return {
            "mode": "direct",
            "ea": hex(startEa),
            "length": len(tokens),
            "isUnique": countPatternMatches(tokens, maxMatches=2) == 1,
            "rip": firstRipInfo,
            "formats": formats
        }
    return None

def generateDeepSignature(funcStart: int, maxLen: int) -> Optional[Dict[str, Any]]:
    func = ida_funcs.get_func(funcStart)
    if not func:
        return None

    cur = func.start_ea
    insn = ida_ua.insn_t()
    insnAddresses: List[int] = []

    while cur < func.end_ea and len(insnAddresses) < 120:
        insnAddresses.append(cur)
        insnLen = ida_ua.decode_insn(insn, cur)
        if insnLen <= 0:
            break
        cur += insnLen

    for startIdx in range(1, len(insnAddresses)):
        subStart = insnAddresses[startIdx]
        res = generateDirectSignature(subStart, maxLen, allowCrossFunction=False)
        if res and res.get("isUnique"):
            res["mode"] = "deep"
            res["func_entry"] = hex(func.start_ea)
            res["offset_from_entry"] = subStart - func.start_ea
            return res

    return None

def getPrecedingHeads(startEa: int, count: int = 3) -> List[int]:
    heads: List[int] = []
    cur = startEa
    for _ in range(count):
        prev = idc.prev_head(cur)
        if prev == idc.BADADDR or prev == cur or (cur - prev) > 16:
            break
        heads.insert(0, prev)
        cur = prev
    return heads

def generateXrefSignature(targetEa: int, maxLen: int) -> Optional[Dict[str, Any]]:
    func = ida_funcs.get_func(targetEa)
    resolveEa = func.start_ea if func else targetEa

    callRefs = []
    for ref in idautils.CodeRefsTo(resolveEa, 0):
        callRefs.append(ref)
        if len(callRefs) >= 50:
            break

    # pass 1: try windowed context preceding call site
    for callSite in callRefs:
        precedingHeads = getPrecedingHeads(callSite, count=3)
        for anchorEa in precedingHeads:
            callOffset = callSite - anchorEa
            res = generateDirectSignature(anchorEa, maxLen + callOffset, allowCrossFunction=True)
            if res and res.get("isUnique"):
                res["mode"] = "xref_context"
                res["call_site"] = hex(callSite)
                res["resolved_target"] = hex(resolveEa)
                res["anchor_ea"] = hex(anchorEa)
                res["call_offset"] = callOffset

                insn = ida_ua.insn_t()
                insnLen = ida_ua.decode_insn(insn, callSite)
                rawBytes = ida_bytes.get_bytes(callSite, insnLen)
                ripInfo = detectRipOperand(callSite, insn, rawBytes) if rawBytes else None

                if ripInfo:
                    res["rip"] = ripInfo
                return res

    # pass 2: try direct call site
    for callSite in callRefs:
        insn = ida_ua.insn_t()
        insnLen = ida_ua.decode_insn(insn, callSite)
        if insnLen <= 0:
            continue

        rawBytes = ida_bytes.get_bytes(callSite, insnLen)
        if not rawBytes:
            continue

        ripInfo = detectRipOperand(callSite, insn, rawBytes)
        res = generateDirectSignature(callSite, maxLen, allowCrossFunction=True)
        if res and res.get("isUnique"):
            res["mode"] = "xref_direct"
            res["call_site"] = hex(callSite)
            res["resolved_target"] = hex(resolveEa)
            if ripInfo:
                res["rip"] = ripInfo
            return res

    return None

def generateBoundarySignature(targetEa: int, maxLen: int) -> Optional[Dict[str, Any]]:
    # cross function boundary into following instructions / padding
    res = generateDirectSignature(targetEa, maxLen, allowCrossFunction=True)
    if res and res.get("isUnique"):
        res["mode"] = "boundary_extension"
        return res

    # try preceding anchor navigation (up to 24 bytes before target)
    cur = targetEa
    for dist in range(1, 4):
        prev = idc.prev_head(cur)
        if prev == idc.BADADDR or prev >= cur:
            break
        offsetFromAnchor = targetEa - prev
        ancRes = generateDirectSignature(prev, maxLen + offsetFromAnchor, allowCrossFunction=True)
        if ancRes and ancRes.get("isUnique"):
            ancRes["mode"] = "preceding_anchor"
            ancRes["anchor_ea"] = hex(prev)
            ancRes["target_ea"] = hex(targetEa)
            ancRes["offset_from_anchor"] = offsetFromAnchor
            return ancRes
        cur = prev

    return None

def generateDataRefSignature(targetEa: int, maxLen: int) -> Optional[Dict[str, Any]]:
    is64 = ida_ida.inf_is_64bit()
    ptrSize = 8 if is64 else 4

    for dref in idautils.DataRefsTo(targetEa):
        seg = ida_segment.getseg(dref)
        if not seg:
            continue

        # check if in data/rdata segment (e.g. vtable slot)
        segName = ida_segment.get_segm_name(seg).lower()
        if "data" in segName:
            # build signature from surrounding table pointers
            tableStart = max(seg.start_ea, dref - (ptrSize * 2))
            tableBytes = ida_bytes.get_bytes(tableStart, ptrSize * 4)
            if tableBytes:
                tokens = []
                for idx, b in enumerate(tableBytes):
                    tokens.append(f"{b:02X}")

                if len(tokens) >= 16:
                    matchCount = countPatternMatches(tokens, maxMatches=2)
                    if matchCount == 1:
                        formats = formatSignature(tokens)
                        offsetInTable = dref - tableStart
                        return {
                            "mode": "vtable_data_ref",
                            "table_ea": hex(tableStart),
                            "slot_ea": hex(dref),
                            "target_ea": hex(targetEa),
                            "offset_in_table": offsetInTable,
                            "length": len(tokens),
                            "isUnique": True,
                            "formats": formats
                        }

    return None

def makeSigThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    target = params.get("ea") or params.get("addr") or params.get("address")
    if not target:
        return {"success": False, "error": "missing ea parameter"}

    ea = resolveTargetEa(target)
    if ea is None or ea == ida_idaapi.BADADDR:
        return {"success": False, "error": f"could not resolve address for '{target}'"}

    maxLen = safeCastInt(params.get("max_len"), fallback=96)
    mode = safeCastStr(params.get("mode") or "auto").lower()

    func = ida_funcs.get_func(ea)
    funcName = idc.get_func_name(func.start_ea if func else ea) or idc.get_name(ea)

    getSegmentCache()

    result = None

    # strategy 1: direct
    if mode in ("direct", "auto"):
        result = generateDirectSignature(ea, maxLen, allowCrossFunction=False)

    # strategy 2: deep within function
    if (not result or not result.get("isUnique")) and mode in ("deep", "auto"):
        deepRes = generateDeepSignature(ea, maxLen)
        if deepRes and deepRes.get("isUnique"):
            result = deepRes

    # strategy 3: xref / caller context with rip call resolution
    if (not result or not result.get("isUnique")) and mode in ("xref", "auto"):
        xrefRes = generateXrefSignature(ea, maxLen)
        if xrefRes and xrefRes.get("isUnique"):
            result = xrefRes

    # strategy 4: data references (vtables / pointer arrays)
    if (not result or not result.get("isUnique")) and mode in ("data", "auto"):
        dataRes = generateDataRefSignature(ea, maxLen)
        if dataRes and dataRes.get("isUnique"):
            result = dataRes

    # strategy 5: boundary extension / preceding anchor navigation (for tiny/stub functions)
    if (not result or not result.get("isUnique")) and mode in ("boundary", "anchor", "auto"):
        bndRes = generateBoundarySignature(ea, maxLen)
        if bndRes and bndRes.get("isUnique"):
            result = bndRes

    if not result:
        return {"success": False, "error": f"could not generate unique signature for {hex(ea)}"}

    result["success"] = True
    result["func_name"] = funcName
    result["pattern"] = result["formats"]["ida"]
    result["x64dbg"] = result["formats"]["x64dbg"]
    result["mask"] = result["formats"]["mask"]
    result["code"] = result["formats"]["code"]
    result["c_decl"] = result["formats"]["c_decl"]

    return result
