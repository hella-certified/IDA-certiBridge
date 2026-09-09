from typing import Any, Dict
import urllib.request
import urllib.parse
import ida_typeinf
try:
    import ida_struct
except ImportError:
    ida_struct = None
import ida_hexrays
import ida_funcs
import ida_idaapi
import idc

from utils.logger import bridgeLog
from utils.safety import safeCall, safeCastInt, safeCastStr, safeJsonLoads
import components.decompiler

def getStructThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    name = params.get("name") or params.get("struct")
    if not name:
        return {"success": False, "error": "missing struct name parameter"}

    cleanName = safeCastStr(name).strip()
    cleanName = cleanName[7:].strip() if cleanName.startswith("struct ") else cleanName

    try:
        tif = ida_typeinf.tinfo_t()
        found = False
        try:
            found = tif.get_named_type(None, cleanName)
        except Exception:
            pass

        if not found:
            try:
                found = tif.get_named_type(ida_typeinf.get_idati(), cleanName)
            except Exception:
                pass

        members = []
        cDecl = ""
        size = 0

        if found:
            size = safeCall(tif.get_size, fallback=0)
            cDecl = safeCastStr(safeCall(tif.dstr, fallback=""))

            try:
                udt = ida_typeinf.udt_type_data_t()
                if hasattr(tif, "get_udt_details") and tif.get_udt_details(udt):
                    for m in udt:
                        mType = m.type.dstr() if hasattr(m.type, "dstr") else str(m.type)
                        members.append({
                            "name": m.name,
                            "offset": m.offset // 8,
                            "size": m.size // 8,
                            "type": mType
                        })
            except Exception:
                pass

            if (not cDecl or "{" not in cDecl) and members:
                lines = [f"struct {cleanName} {{"]
                for idx, m in enumerate(members):
                    mName = m["name"] if m["name"] else f"base_{idx}"
                    lines.append(f"    {m['type']} {mName}; // offset: {hex(m['offset'])}")
                lines.append("};")
                cDecl = "\n".join(lines)
    except Exception:
        pass

    if not cDecl and ida_struct:
        sid = safeCall(ida_struct.get_struc_id, cleanName, fallback=ida_idaapi.BADADDR)
        if sid != ida_idaapi.BADADDR and sid != 0:
            s = safeCall(ida_struct.get_struc, sid)
            if s:
                size = safeCall(ida_struct.get_struc_size, s, fallback=0)
                offset = 0
                while offset < size:
                    m = safeCall(ida_struct.get_member, s, offset)
                    if m:
                        mName = safeCall(ida_struct.get_member_name, m.id) or f"field_{hex(offset)[2:]}"
                        mSize = safeCastInt(safeCall(ida_struct.get_member_size, m), fallback=1)
                        members.append({
                            "name": mName,
                            "offset": offset,
                            "size": mSize,
                            "type": "char" if mSize == 1 else f"char[{mSize}]"
                        })
                        offset += max(1, mSize)
                    else:
                        offset += 1

                lines = [f"struct {cleanName} {{"]
                for mem in members:
                    lines.append(f"    {mem['type']} {mem['name']}; // offset: {hex(mem['offset'])}")
                lines.append("};")
                cDecl = "\n".join(lines)

    if not cDecl:
        return {"success": False, "error": f"struct '{cleanName}' not found in local types or structures"}

    return {
        "success": True,
        "name": cleanName,
        "size": size,
        "c_decl": cDecl,
        "members": members
    }

def createStructThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    decl = params.get("decl") or params.get("c_decl")
    structName = params.get("name")

    if not decl and not structName:
        return {"success": False, "error": "missing c_decl or struct name parameter"}

    if decl:
        cleanDecl = safeCastStr(decl).strip()
        cleanDecl = cleanDecl if cleanDecl.endswith(";") else f"{cleanDecl};"

        tif = ida_typeinf.tinfo_t()
        parsedName = safeCall(ida_typeinf.parse_decl, tif, None, cleanDecl, ida_typeinf.PT_SIL)
        nameToUse = parsedName or structName

        # store in idati
        if nameToUse:
            safeCall(tif.set_named_type, ida_typeinf.get_idati(), nameToUse, ida_typeinf.NTF_REPLACE)

        # import to structures view if possible
        if nameToUse:
            safeCall(idc.import_type, -1, nameToUse)

        size = safeCall(tif.get_size, fallback=0)
        bridgeLog(f"created/updated struct '{nameToUse}' ({size} bytes)")
        return {
            "success": True,
            "name": nameToUse,
            "size": size,
            "c_decl": cleanDecl
        }

    return {"success": False, "error": "invalid declaration"}

def copyStructThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    name = params.get("name") or params.get("struct")
    fromPort = safeCastInt(params.get("from_port"), fallback=13382)

    if not name:
        return {"success": False, "error": "missing struct name to copy"}

    cleanName = safeCastStr(name).strip()
    cleanName = cleanName[7:].strip() if cleanName.startswith("struct ") else cleanName

    url = f"http://127.0.0.1:{fromPort}/api/get_struct?name={urllib.parse.quote(cleanName)}"
    bridgeLog(f"requesting struct '{cleanName}' from port {fromPort}...")

    try:
        req = urllib.request.urlopen(url, timeout=120.0)
        data = safeJsonLoads(req.read().decode("utf-8"), fallback={})
    except Exception as e:
        return {"success": False, "error": f"failed to query struct from port {fromPort}: {safeCastStr(e)}"}

    if not data.get("success") or not data.get("c_decl"):
        return {"success": False, "error": f"source port {fromPort} did not return a valid c_decl: {data.get('error')}"}

    cDecl = data["c_decl"]
    created = createStructThunk(plugin, {"decl": cDecl, "name": cleanName})
    if not created.get("success"):
        return created

    bridgeLog(f"successfully copied struct '{cleanName}' from port {fromPort} into current session")
    return {
        "success": True,
        "name": cleanName,
        "fromPort": fromPort,
        "size": created.get("size"),
        "c_decl": cDecl
    }

def setTypeThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    target = params.get("ea") or params.get("addr") or params.get("address") or params.get("func")
    varName = params.get("var") or params.get("name") or params.get("param")
    typeStr = params.get("type")

    if not target or not varName or not typeStr:
        return {"success": False, "error": "missing func ea, var name, or type string"}

    if not ida_hexrays.init_hexrays_plugin():
        return {"success": False, "error": "hex-rays decompiler unavailable"}

    ea = components.decompiler.parseAddress(target)
    if ea is None and isinstance(target, str):
        ea = components.decompiler.findFunctionByName(target)

    if ea is None or ea == ida_idaapi.BADADDR:
        return {"success": False, "error": f"could not resolve function for '{target}'"}

    func = ida_funcs.get_func(ea)
    targetEa = func.start_ea if func else ea

    cfunc = safeCall(ida_hexrays.decompile, targetEa)
    if not cfunc:
        return {"success": False, "error": f"failed to decompile function at {hex(targetEa)}"}

    tif = ida_typeinf.tinfo_t()
    declString = f"{typeStr} dummy;"
    parsed = safeCall(ida_typeinf.parse_decl, tif, None, declString, ida_typeinf.PT_SIL)
    if not parsed:
        return {"success": False, "error": f"failed to parse type declaration '{typeStr}'"}

    targetLvar = None
    vStr = safeCastStr(varName).strip()
    isIdx = vStr.isdigit()
    vIdx = safeCastInt(vStr, fallback=-1) if isIdx else -1

    for idx, l in enumerate(cfunc.lvars):
        if (isIdx and idx == vIdx) or l.name == vStr:
            targetLvar = l
            break

    if not targetLvar:
        available = [l.name for l in cfunc.lvars if l.name]
        return {"success": False, "error": f"variable '{varName}' not found in function", "availableVars": available}

    try:
        class LvarTypeModifier(ida_hexrays.user_lvar_modifier_t):
            def __init__(self, targetName: str, newType: ida_typeinf.tinfo_t):
                super().__init__()
                self.targetName = targetName
                self.newType = newType

            def modify_lvars(self, lvars):
                for one in lvars.lvvec:
                    if one.name == self.targetName:
                        one.type = self.newType
                        return True
                return False

        mod = LvarTypeModifier(targetLvar.name, tif)
        safeCall(ida_hexrays.modify_user_lvars, cfunc.entry_ea, mod)
        safeCall(targetLvar.set_final_lvar_type, tif)
        safeCall(targetLvar.set_lvar_type, tif)
        safeCall(cfunc.save_user_labels)
        bridgeLog(f"applied type '{typeStr}' to '{targetLvar.name}' in {hex(targetEa)}")
        return {
            "success": True,
            "ea": hex(targetEa),
            "var": targetLvar.name,
            "type": typeStr
        }
    except Exception as e:
        return {"success": False, "error": f"failed to apply type: {safeCastStr(e)}"}
