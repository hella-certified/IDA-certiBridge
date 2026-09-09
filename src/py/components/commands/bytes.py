from typing import Any, Dict, List, Optional
import ida_bytes
import ida_ida
import ida_idaapi
import ida_lines
import idautils
import idc

import components.decompiler
from utils.safety import safeCall, safeCastInt, safeCastStr

def resolveTargetEa(raw):
    ea = components.decompiler.parseAddress(raw)
    if ea is None and isinstance(raw, str):
        ea = components.decompiler.findFunctionByName(raw)
    return ea

def getBytesThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    target = params.get("ea") or params.get("addr") or params.get("address")
    if not target:
        return {"success": False, "error": "missing ea parameter"}

    ea = resolveTargetEa(target)
    if ea is None or ea == ida_idaapi.BADADDR:
        return {"success": False, "error": f"could not resolve address for '{target}'"}

    size = safeCastInt(params.get("size"), fallback=32)
    raw = ida_bytes.get_bytes(ea, size)
    if not raw:
        return {"success": False, "error": f"failed to read {size} bytes at {hex(ea)}"}

    hexStr = " ".join(f"{b:02X}" for b in raw)

    return {
        "success": True,
        "ea": hex(ea),
        "size": len(raw),
        "hex": hexStr,
        "bytes": list(raw)
    }

def tryAssembleInstructions(ea: int, text: str) -> Optional[bytearray]:
    lines = [l.strip() for l in text.replace(";", "\n").splitlines() if l.strip()]
    if not lines:
        return None

    is64 = ida_ida.inf_is_64bit()
    assembled = bytearray()
    curEa = ea

    for line in lines:
        codeBytes = None
        try:
            import ida_idp
            res = ida_idp.assemble(curEa, curEa, curEa, False if is64 else True, line)
            if isinstance(res, tuple) and len(res) == 2 and res[0]:
                codeBytes = res[1]
            elif isinstance(res, (bytes, bytearray)):
                codeBytes = res
        except Exception:
            pass

        if not codeBytes:
            try:
                res = idc.assemble_loc(curEa, line)
                if isinstance(res, (bytes, bytearray)):
                    codeBytes = res
            except Exception:
                pass

        if not codeBytes:
            return None

        assembled.extend(codeBytes)
        curEa += len(codeBytes)

    return assembled

def patchBytesThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    target = params.get("ea") or params.get("addr") or params.get("address")
    patchData = params.get("bytes") or params.get("data") or params.get("hex") or params.get("asm")

    if not target or not patchData:
        return {"success": False, "error": "missing ea or patch data"}

    ea = resolveTargetEa(target)
    if ea is None or ea == ida_idaapi.BADADDR:
        return {"success": False, "error": f"could not resolve address for '{target}'"}

    targetSize = safeCastInt(params.get("target_size") or params.get("size"), fallback=0)

    rawStr = str(patchData).strip()
    tokens = rawStr.replace(",", " ").split()
    patchBytes = bytearray()
    hexParseFailed = False
    wasAssembled = False

    for token in tokens:
        clean = token.strip()
        if clean.startswith("0x") or clean.startswith("0X"):
            clean = clean[2:]
        try:
            val = int(clean, 16)
            patchBytes.append(val & 0xFF)
        except ValueError:
            hexParseFailed = True
            break

    if hexParseFailed or not patchBytes:
        asmRes = tryAssembleInstructions(ea, rawStr)
        if asmRes:
            patchBytes = asmRes
            wasAssembled = True
        else:
            return {"success": False, "error": f"could not parse as hex bytes or assemble instructions: '{rawStr}'"}

    assembledLen = len(patchBytes)

    # length safety for assembled mnemonics
    if wasAssembled and targetSize > 0:
        if assembledLen > targetSize:
            return {
                "success": False,
                "error": f"assembled {assembledLen} bytes exceeds target region of {targetSize} bytes (would clobber next instruction)",
                "assembledLength": assembledLen,
                "targetLength": targetSize,
                "assembledHex": " ".join(f"{b:02X}" for b in patchBytes)
            }
        if assembledLen < targetSize:
            nopCount = targetSize - assembledLen
            nopStartEa = ea + assembledLen
            nopEndEa = ea + targetSize
            xrefsIntoNops = []
            for checkEa in range(nopStartEa, nopEndEa):
                for xref in idautils.XrefsTo(checkEa):
                    xrefsIntoNops.append({"target": hex(checkEa), "from": hex(xref.frm), "type": xref.type})
            if xrefsIntoNops:
                forceIt = params.get("force") == "1" or params.get("force") == "true"
                if not forceIt:
                    return {
                        "success": False,
                        "error": f"xrefs found pointing into NOP-pad region ({hex(nopStartEa)}-{hex(nopEndEa)}), use force=1 to override",
                        "assembledLength": assembledLen,
                        "targetLength": targetSize,
                        "xrefsIntoNopRegion": xrefsIntoNops[:10]
                    }
            patchBytes.extend(b"\x90" * nopCount)

    origBytes = ida_bytes.get_bytes(ea, len(patchBytes))
    origHex = " ".join(f"{b:02X}" for b in origBytes) if origBytes else ""

    ok = ida_bytes.patch_bytes(ea, bytes(patchBytes))
    if not ok:
        return {"success": False, "error": f"failed to patch {len(patchBytes)} bytes at {hex(ea)}"}

    result = {
        "success": True,
        "ea": hex(ea),
        "patchedLength": len(patchBytes),
        "originalHex": origHex,
        "patchedHex": " ".join(f"{b:02X}" for b in patchBytes)
    }

    if wasAssembled:
        result["assembledLength"] = assembledLen
        if targetSize > 0:
            result["targetLength"] = targetSize
            if assembledLen < targetSize:
                result["nopPadded"] = targetSize - assembledLen

    return result
