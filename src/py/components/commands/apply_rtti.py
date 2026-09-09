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
import ida_typeinf
import idc

import components.decompiler
from components.commands.rename import allowColonInNames
from utils.logger import bridgeLog
from utils.safety import safeCastInt, safeCastStr
from utils.sigEngine import getSegmentCache

def resolveTargetEa(raw):
    ea = components.decompiler.parseAddress(raw)
    if ea is None and isinstance(raw, str):
        ea = components.decompiler.findFunctionByName(raw)
    return ea

def safeSetName(ea, name):
    if ":" in name:
        allowColonInNames()
    ok = ida_name.set_name(ea, name, ida_name.SN_NOWARN)
    if not ok:
        ok = ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_FORCE)
    if not ok:
        ok = ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK)
    return ok

def sanitizeClassName(raw):
    cleaned = raw.strip()
    cleaned = re.sub(r"^\.?\?[AU]V?", "", cleaned)
    cleaned = re.sub(r"@@$", "", cleaned)
    cleaned = cleaned.replace("::", "_")
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", cleaned)
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    return cleaned or "UnknownClass"

def createVtableStruct(className, methods, is64, dryRun=False):
    structName = f"{className}_vtbl"
    ptrType = "void*" if is64 else "void*"
    lines = [f"struct {structName} {{"]
    for m in methods:
        fieldName = m.get("vfuncName", f"vfunc{m['index']}")
        fieldName = re.sub(r"[^a-zA-Z0-9_]", "_", fieldName)
        lines.append(f"    {ptrType} {fieldName};")
    lines.append("};")
    cDecl = "\n".join(lines)

    if dryRun:
        return {"structName": structName, "c_decl": cDecl, "applied": False}

    try:
        tif = ida_typeinf.tinfo_t()
        cleanDecl = cDecl if cDecl.endswith(";") else f"{cDecl};"
        parsedName = None
        try:
            parsedName = ida_typeinf.parse_decl(tif, None, cleanDecl, ida_typeinf.PT_SIL)
        except Exception:
            pass
        nameToUse = parsedName or structName
        if nameToUse:
            try:
                tif.set_named_type(ida_typeinf.get_idati(), nameToUse, ida_typeinf.NTF_REPLACE)
            except Exception:
                pass
            try:
                idc.import_type(-1, nameToUse)
            except Exception:
                pass
        size = 0
        try:
            size = tif.get_size() or 0
        except Exception:
            pass
        bridgeLog(f"rtti apply: created struct '{structName}' ({size} bytes)")
        return {"structName": structName, "c_decl": cDecl, "applied": True, "size": size}
    except Exception as e:
        return {"structName": structName, "c_decl": cDecl, "applied": False, "error": str(e)}

def applyRttiThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    query = params.get("name") or params.get("class") or params.get("query") or ""
    cleanQuery = safeCastStr(query).strip()
    if not cleanQuery:
        return {"success": False, "error": "missing class name parameter"}

    limit = safeCastInt(params.get("limit"), fallback=10)
    methodCount = safeCastInt(params.get("methods"), fallback=32)
    dryRun = params.get("dry_run") == "1" or params.get("dry_run") == "true"
    createStructs = params.get("no_struct") != "1" and params.get("no_struct") != "true"

    is64 = ida_ida.inf_is_64bit()
    imageBase = ida_nalt.get_imagebase()
    ptrSize = 8 if is64 else 4
    readPtr = ida_bytes.get_qword if is64 else ida_bytes.get_dword
    segCache = getSegmentCache()

    escQuery = re.escape(cleanQuery.encode("utf-8"))
    typePat = re.compile(rb"\.?\?[AU]V?[^\x00]*?" + escQuery + rb"[^\x00]*?@@", re.IGNORECASE)

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

    applied: List[Dict[str, Any]] = []
    totalRenamed = 0
    totalVtables = 0
    totalStructs = 0

    for td in foundTypeDescs:
        typeDescEa = td["ea"]
        rva = (typeDescEa - imageBase) if is64 else typeDescEa
        rvaBytes = struct.pack("<I", rva & 0xFFFFFFFF)
        className = sanitizeClassName(td["demangled"])

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
                colCandidate = matchEa - 12
                sig = ida_bytes.get_dword(colCandidate)
                if sig == 1:
                    colList.append(colCandidate)
                pos = idx + 4

        vtableIdx = 0
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
                    vtableEa = vptrEa + ptrSize

                    vtableSuffix = f"_{vtableIdx}" if vtableIdx > 0 else ""
                    vtableName = f"{className}{vtableSuffix}_vtbl"
                    renames: List[Dict[str, str]] = []
                    structMethods: List[Dict[str, Any]] = []

                    if not dryRun:
                        oldVtblName = idc.get_name(vtableEa) or ""
                        if safeSetName(vtableEa, vtableName):
                            renames.append({"ea": hex(vtableEa), "old": oldVtblName, "new": vtableName, "type": "vtable"})
                            bridgeLog(f"rtti apply: named vtable {hex(vtableEa)} -> '{vtableName}'")
                    else:
                        renames.append({"ea": hex(vtableEa), "old": idc.get_name(vtableEa) or "", "new": vtableName, "type": "vtable"})

                    for mi in range(methodCount):
                        mEa = readPtr(vtableEa + mi * ptrSize)
                        if not mEa or mEa == ida_idaapi.BADADDR:
                            break
                        mSeg = ida_segment.getseg(mEa)
                        if not mSeg or (mSeg.perm & ida_segment.SEGPERM_EXEC) == 0:
                            break

                        currentName = idc.get_func_name(mEa) or idc.get_name(mEa) or ""
                        isUnnamed = currentName.startswith("sub_") or currentName.startswith("nullsub_") or not currentName

                        vfuncName = f"{className}::vfunc{mi}"
                        structMethods.append({"index": mi, "ea": hex(mEa), "vfuncName": f"vfunc{mi}", "currentName": currentName})

                        if not isUnnamed:
                            continue

                        if not dryRun:
                            if safeSetName(mEa, vfuncName):
                                renames.append({"ea": hex(mEa), "old": currentName, "new": vfuncName, "type": "vfunc"})
                                bridgeLog(f"rtti apply: named {hex(mEa)} -> '{vfuncName}'")
                        else:
                            renames.append({"ea": hex(mEa), "old": currentName, "new": vfuncName, "type": "vfunc"})

                    structResult = None
                    if createStructs and structMethods:
                        structResult = createVtableStruct(
                            f"{className}{vtableSuffix}",
                            structMethods,
                            is64,
                            dryRun=dryRun
                        )
                        if structResult and structResult.get("applied"):
                            totalStructs += 1

                    totalVtables += 1
                    totalRenamed += len(renames)

                    entry = {
                        "className": td["demangled"],
                        "sanitized": className,
                        "vtableEa": hex(vtableEa),
                        "methodCount": len(structMethods),
                        "renames": renames
                    }
                    if structResult:
                        entry["struct"] = structResult

                    applied.append(entry)

                    vtableIdx += 1
                    if len(applied) >= limit:
                        break
                    pos = idx + ptrSize

                if len(applied) >= limit:
                    break
            if len(applied) >= limit:
                break

    return {
        "success": True,
        "query": cleanQuery,
        "dryRun": dryRun,
        "vtablesProcessed": totalVtables,
        "totalRenamed": totalRenamed,
        "structsCreated": totalStructs,
        "classes": applied
    }
