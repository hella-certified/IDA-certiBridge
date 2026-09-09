import re
import struct
from typing import Any, Dict, List
import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_name
import ida_nalt
import ida_segment
import idc

import components.decompiler
from utils.safety import safeCall, safeCastInt, safeCastStr
from utils.sigEngine import getSegmentCache

def resolveTargetEa(raw):
    ea = components.decompiler.parseAddress(raw)
    if ea is None and isinstance(raw, str):
        ea = components.decompiler.findFunctionByName(raw)
    return ea

def rttiInspectThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    target = params.get("ea") or params.get("addr") or params.get("address")
    if not target:
        return {"success": False, "error": "missing ea parameter"}

    ea = resolveTargetEa(target)
    if ea is None or ea == ida_idaapi.BADADDR:
        return {"success": False, "error": f"could not resolve address for '{target}'"}

    is64 = ida_ida.inf_is_64bit()
    imageBase = ida_nalt.get_imagebase()

    colEa = 0
    if is64:
        colPtr = ida_bytes.get_qword(ea - 8)
        if colPtr and colPtr != ida_idaapi.BADADDR and colPtr > imageBase:
            colEa = colPtr
        else:
            colEa = ea
    else:
        colPtr = ida_bytes.get_dword(ea - 4)
        if colPtr and colPtr != ida_idaapi.BADADDR:
            colEa = colPtr
        else:
            colEa = ea

    signature = ida_bytes.get_dword(colEa)
    offset = ida_bytes.get_dword(colEa + 4)
    cdOffset = ida_bytes.get_dword(colEa + 8)

    typeDescRva = ida_bytes.get_dword(colEa + 12)
    typeDescEa = (imageBase + typeDescRva) if is64 else typeDescRva

    classDescRva = ida_bytes.get_dword(colEa + 16)
    classDescEa = (imageBase + classDescRva) if is64 else classDescRva

    rawMangled = ""
    demangled = ""
    nameEa = typeDescEa + (16 if is64 else 8)
    strBytes = ida_bytes.get_strlit_contents(nameEa, 256, ida_nalt.STRTYPE_C)
    if strBytes:
        rawMangled = strBytes.decode("utf-8", errors="replace")
        demangled = ida_name.demangle_name(rawMangled, ida_name.MNG_SHORT_FORM) or rawMangled

    baseClasses: List[str] = []
    if classDescEa and classDescEa != imageBase:
        numBaseClasses = ida_bytes.get_dword(classDescEa + 8)
        baseArrayRva = ida_bytes.get_dword(classDescEa + 12)
        baseArrayEa = (imageBase + baseArrayRva) if is64 else baseArrayRva

        for i in range(min(numBaseClasses, 16)):
            baseDescRva = ida_bytes.get_dword(baseArrayEa + (i * 4))
            baseDescEa = (imageBase + baseDescRva) if is64 else baseDescRva
            baseTypeRva = ida_bytes.get_dword(baseDescEa)
            baseTypeEa = (imageBase + baseTypeRva) if is64 else baseTypeRva
            bNameEa = baseTypeEa + (16 if is64 else 8)
            bStr = ida_bytes.get_strlit_contents(bNameEa, 256, ida_nalt.STRTYPE_C)
            if bStr:
                bMangled = bStr.decode("utf-8", errors="replace")
                bDemangled = ida_name.demangle_name(bMangled, ida_name.MNG_SHORT_FORM) or bMangled
                baseClasses.append(bDemangled)

    return {
        "success": True,
        "ea": hex(ea),
        "col_ea": hex(colEa),
        "className": demangled or rawMangled or "unknown",
        "mangledName": rawMangled,
        "offset": offset,
        "cdOffset": cdOffset,
        "baseClasses": baseClasses
    }

def findClassThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    query = params.get("name") or params.get("class") or params.get("query") or ""
    cleanQuery = safeCastStr(query).strip()
    if not cleanQuery:
        return {"success": False, "error": "missing class name parameter"}

    limit = safeCastInt(params.get("limit"), fallback=10)
    methodCount = safeCastInt(params.get("methods"), fallback=32)

    is64 = ida_ida.inf_is_64bit()
    imageBase = ida_nalt.get_imagebase()
    segCache = getSegmentCache()

    # compile regex for type descriptor name: .?AV<query>...@@ or .?AU<query>...@@
    escQuery = re.escape(cleanQuery.encode("utf-8"))
    typePat = re.compile(rb"\.\?[AU]V?[^\x00]*?" + escQuery + rb"[^\x00]*?@@", re.IGNORECASE)

    foundTypeDescs = []
    seenTypeEa = set()

    for seg in segCache.segments:
        data = seg["data"]
        startEa = seg["start_ea"]
        for m in typePat.finditer(data):
            nameEa = startEa + m.start()
            typeDescEa = nameEa - (16 if is64 else 8)
            if typeDescEa not in seenTypeEa and typeDescEa >= imageBase:
                seenTypeEa.add(typeDescEa)
                rawMangled = m.group(0).decode("utf-8", errors="replace")
                demangled = ida_name.demangle_name(rawMangled, ida_name.MNG_SHORT_FORM) or rawMangled
                foundTypeDescs.append({
                    "ea": typeDescEa,
                    "name_ea": nameEa,
                    "mangled": rawMangled,
                    "demangled": demangled
                })
            if len(foundTypeDescs) >= limit * 2:
                break

    results: List[Dict[str, Any]] = []

    for td in foundTypeDescs:
        typeDescEa = td["ea"]
        rva = (typeDescEa - imageBase) if is64 else typeDescEa
        rvaBytes = struct.pack("<I", rva & 0xFFFFFFFF)

        # search for RTTICompleteObjectLocator referencing this TypeDescriptor
        colList: List[int] = []
        for seg in segCache.segments:
            data = seg["data"]
            startEa = seg["start_ea"]
            pos = 0
            while True:
                idx = data.find(rvaBytes, pos)
                if idx == -1:
                    break
                matchEa = startEa + idx
                # in MSVC x64, pTypeDescriptor is at offset +12 of COL
                colCandidate = matchEa - 12
                sig = ida_bytes.get_dword(colCandidate)
                if sig == 1:
                    colList.append(colCandidate)
                pos = idx + 4

        # find vtables pointing to each COL (vtable[-1] == colEa)
        for colEa in colList:
            colBytes = struct.pack("<Q" if is64 else "<I", colEa)
            for seg in segCache.segments:
                data = seg["data"]
                startEa = seg["start_ea"]
                pos = 0
                while True:
                    idx = data.find(colBytes, pos)
                    if idx == -1:
                        break
                    vptrEa = startEa + idx
                    vtableEa = vptrEa + (8 if is64 else 4)

                    methods = []
                    for mi in range(methodCount):
                        mEa = ida_bytes.get_qword(vtableEa + mi * 8) if is64 else ida_bytes.get_dword(vtableEa + mi * 4)
                        if not mEa or mEa == ida_idaapi.BADADDR:
                            break
                        mSeg = ida_segment.getseg(mEa)
                        if not mSeg or (mSeg.perm & ida_segment.SEGPERM_EXEC) == 0:
                            break
                        mFunc = ida_funcs.get_func(mEa)
                        fnName = idc.get_func_name(mEa) or f"sub_{hex(mEa)[2:]}"
                        methods.append({
                            "index": mi,
                            "ea": hex(mEa),
                            "name": fnName,
                            "size": (mFunc.end_ea - mFunc.start_ea) if mFunc else 0
                        })

                    # parse base classes from COL
                    baseClasses: List[str] = []
                    classDescRva = ida_bytes.get_dword(colEa + 16)
                    classDescEa = (imageBase + classDescRva) if is64 else classDescRva
                    if classDescEa and classDescEa != imageBase:
                        numBase = ida_bytes.get_dword(classDescEa + 8)
                        baseArrayRva = ida_bytes.get_dword(classDescEa + 12)
                        baseArrayEa = (imageBase + baseArrayRva) if is64 else baseArrayRva
                        for bi in range(min(numBase, 16)):
                            baseDescRva = ida_bytes.get_dword(baseArrayEa + (bi * 4))
                            baseDescEa = (imageBase + baseDescRva) if is64 else baseDescRva
                            baseTypeRva = ida_bytes.get_dword(baseDescEa)
                            baseTypeEa = (imageBase + baseTypeRva) if is64 else baseTypeRva
                            bNameEa = baseTypeEa + (16 if is64 else 8)
                            bStr = ida_bytes.get_strlit_contents(bNameEa, 256, ida_nalt.STRTYPE_C)
                            if bStr:
                                bMangled = bStr.decode("utf-8", errors="replace")
                                bDemangled = ida_name.demangle_name(bMangled, ida_name.MNG_SHORT_FORM) or bMangled
                                baseClasses.append(bDemangled)

                    results.append({
                        "className": td["demangled"],
                        "mangledName": td["mangled"],
                        "typeDescriptorEa": hex(typeDescEa),
                        "colEa": hex(colEa),
                        "vtableEa": hex(vtableEa),
                        "methodCount": len(methods),
                        "baseClasses": baseClasses,
                        "methods": methods
                    })

                    if len(results) >= limit:
                        break
                    pos = idx + 8

                if len(results) >= limit:
                    break

            if len(results) >= limit:
                break

    return {
        "success": True,
        "query": cleanQuery,
        "count": len(results),
        "classes": results
    }
