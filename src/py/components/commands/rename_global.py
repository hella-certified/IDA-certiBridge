from typing import Any, Dict
import ida_name
import ida_idaapi
import idc

from utils.logger import bridgeLog
from utils.safety import safeCastStr
import components.decompiler
from components.commands.rename import allowColonInNames

def renameGlobalThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    target = params.get("ea") or params.get("addr") or params.get("address") or params.get("old_name")
    newName = safeCastStr(params.get("name") or params.get("new_name") or params.get("newName")).strip()

    if not target or not newName:
        return {"success": False, "error": "missing ea or new name"}

    ea = components.decompiler.parseAddress(target)
    if ea is None and isinstance(target, str):
        ea = idc.get_name_ea_simple(target)

    if ea is None or ea == ida_idaapi.BADADDR:
        return {"success": False, "error": f"could not resolve address for '{target}'"}

    oldName = idc.get_name(ea)

    if ":" in newName:
        allowColonInNames()

    ok = ida_name.set_name(ea, newName, ida_name.SN_NOWARN)
    if not ok:
        ok = ida_name.set_name(ea, newName, ida_name.SN_NOWARN | ida_name.SN_FORCE)
    if not ok:
        ok = ida_name.set_name(ea, newName, ida_name.SN_NOWARN | ida_name.SN_NOCHECK)
    if not ok:
        return {"success": False, "error": f"failed to rename global at {hex(ea)} to '{newName}'"}

    assignedName = idc.get_name(ea) or newName
    bridgeLog(f"renamed global {hex(ea)}: '{oldName}' -> '{assignedName}'")
    return {
        "success": True,
        "ea": hex(ea),
        "oldName": oldName,
        "newName": assignedName
    }
