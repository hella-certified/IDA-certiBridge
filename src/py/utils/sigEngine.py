import re
import struct
from typing import Any, Dict, List, Optional, Tuple
import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_nalt
import ida_segment
import ida_ua
import idautils
import idc

from utils.safety import safeCall, safeCastInt, safeCastStr

class SegmentCache:
    def __init__(self):
        self.segments: List[Dict[str, Any]] = []
        self.lastIdb: str = ""

    def refresh(self):
        curIdb = idc.get_root_filename() or ""
        self.segments.clear()
        self.lastIdb = curIdb

        seg = ida_segment.get_first_seg()
        while seg:
            isCode = (seg.perm & ida_segment.SEGPERM_EXEC) != 0
            isReadable = (seg.perm & ida_segment.SEGPERM_READ) != 0
            segName = ida_segment.get_segm_name(seg)
            segStart = seg.start_ea
            segSize = seg.end_ea - seg.start_ea
            if (isCode or isReadable) and 0 < segSize < 512 * 1024 * 1024:
                raw = ida_bytes.get_bytes(segStart, segSize)
                if raw:
                    self.segments.append(
                        {
                            "name": segName,
                            "start_ea": segStart,
                            "end_ea": seg.end_ea,
                            "size": segSize,
                            "data": bytes(raw)
                        }
                    )

            seg = ida_segment.get_next_seg(seg.start_ea)

_SEG_CACHE = SegmentCache()

def getSegmentCache() -> SegmentCache:
    if not _SEG_CACHE.segments or _SEG_CACHE.lastIdb != (idc.get_root_filename() or ""):
        _SEG_CACHE.refresh()
    return _SEG_CACHE

def patternToRegex(patTokens: List[str]) -> Optional[re.Pattern]:
    regexParts = []
    for token in patTokens:
        clean = token.strip().upper()
        if clean in ("?", "??"):
            regexParts.append(b".")
        else:
            try:
                val = int(clean, 16)
                regexParts.append(re.escape(bytes([val & 0xFF])))
            except ValueError:
                return None
    try:
        return re.compile(b"".join(regexParts), re.DOTALL)
    except Exception:
        return None

def countPatternMatches(patTokens: List[str], maxMatches: int = 2) -> int:
    compiled = patternToRegex(patTokens)
    if not compiled:
        return 0

    cache = getSegmentCache()
    totalMatches = 0

    for seg in cache.segments:
        data = seg["data"]
        pos = 0
        while pos < len(data):
            m = compiled.search(data, pos)
            if not m:
                break
            totalMatches += 1
            if totalMatches >= maxMatches:
                return totalMatches
            pos = m.start() + 1

    return totalMatches

def scanPattern(patTokens: List[str], limit: int = 50) -> List[int]:
    compiled = patternToRegex(patTokens)
    if not compiled:
        return []

    cache = getSegmentCache()
    results: List[int] = []

    for seg in cache.segments:
        data = seg["data"]
        baseEa = seg["start_ea"]
        pos = 0
        while pos < len(data) and len(results) < limit:
            m = compiled.search(data, pos)
            if not m:
                break
            matchEa = baseEa + m.start()
            results.append(matchEa)
            pos = m.start() + 1

    return results

def detectRipOperand(ea: int, insn, rawBytes: bytes) -> Optional[Dict[str, Any]]:
    is64 = ida_ida.inf_is_64bit()
    if not is64 or not rawBytes:
        return None

    insnLen = len(rawBytes)
    mnem = insn.get_canon_mnem()

    # direct call or jmp relative (e8 / e9 xx xx xx xx)
    if mnem in ("call", "jmp") and insnLen == 5 and rawBytes[0] in (0xE8, 0xE9):
        disp32 = struct.unpack("<i", rawBytes[1:5])[0]
        targetEa = ea + insnLen + disp32
        return {
            "rip_offset": 1,
            "disp_len": 4,
            "insn_len": 5,
            "disp32": disp32,
            "target_ea": targetEa,
            "type": "rel_branch"
        }

    # indirect call or jmp (ff 15 xx xx xx xx)
    if mnem in ("call", "jmp") and insnLen == 6 and rawBytes[0] == 0xFF and rawBytes[1] in (0x15, 0x25):
        disp32 = struct.unpack("<i", rawBytes[2:6])[0]
        targetEa = ea + insnLen + disp32
        return {
            "rip_offset": 2,
            "disp_len": 4,
            "insn_len": 6,
            "disp32": disp32,
            "target_ea": targetEa,
            "type": "rip_indirect"
        }

    # check operands for memory displacement
    for opIdx in range(min(len(insn.ops), 4)):
        op = insn.ops[opIdx]
        if op.type == ida_ua.o_void:
            break

        if op.type in (ida_ua.o_mem, ida_ua.o_displ):
            # rip relative displacement typically occupies 4 bytes ending at insnLen or before imm
            immLen = 0
            for otherOp in insn.ops:
                if otherOp.type == ida_ua.o_imm:
                    immLen = otherOp.dtype
                    if immLen <= 0 or immLen > 4:
                        immLen = 1

            dispOffset = insnLen - 4 - immLen
            if 0 < dispOffset < insnLen - 3:
                dispBytes = rawBytes[dispOffset:dispOffset + 4]
                if len(dispBytes) == 4:
                    disp32 = struct.unpack("<i", dispBytes)[0]
                    targetEa = ea + insnLen + disp32
                    return {
                        "rip_offset": dispOffset,
                        "disp_len": 4,
                        "insn_len": insnLen,
                        "disp32": disp32,
                        "target_ea": targetEa,
                        "type": "rip_mem"
                    }

    return None

def formatSignature(tokens: List[str]) -> Dict[str, str]:
    idaStr = " ".join(tokens)
    x64Str = " ".join("??" if t == "?" else t for t in tokens)

    byteList = []
    maskChars = []
    for t in tokens:
        if t in ("?", "??"):
            byteList.append(0)
            maskChars.append("?")
        else:
            byteList.append(int(t, 16))
            maskChars.append("x")

    codeStr = "".join(f"\\x{b:02X}" for b in byteList)
    maskStr = "".join(maskChars)

    cArray = "{ " + ", ".join(f"0x{b:02X}" for b in byteList) + " }"
    cDef = f"const uint8_t sig[] = {cArray};\nconst char mask[] = \"{maskStr}\";"

    return {
        "ida": idaStr,
        "x64dbg": x64Str,
        "code": codeStr,
        "mask": maskStr,
        "c_decl": cDef
    }
