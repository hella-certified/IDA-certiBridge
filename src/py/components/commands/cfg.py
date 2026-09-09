from typing import Any, Dict, List
import ida_funcs
import ida_gdl
import ida_idaapi
import idc

import components.decompiler
from utils.safety import safeCall, safeCastInt, safeCastStr

def resolveTargetEa(raw):
    ea = components.decompiler.parseAddress(raw)
    if ea is None and isinstance(raw, str):
        ea = components.decompiler.findFunctionByName(raw)
    return ea

def cfgThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    target = params.get("ea") or params.get("addr") or params.get("address")
    if not target:
        return {"success": False, "error": "missing ea parameter"}

    ea = resolveTargetEa(target)
    if ea is None or ea == ida_idaapi.BADADDR:
        return {"success": False, "error": f"could not resolve address for '{target}'"}

    func = ida_funcs.get_func(ea)
    if not func:
        return {"success": False, "error": f"no function found at {hex(ea)}"}

    flowchart = ida_gdl.FlowChart(func)
    blocks: List[Dict[str, Any]] = []
    mermaidLines: List[str] = ["graph TD"]

    for block in flowchart:
        succs = [hex(succ.start_ea) for succ in block.succs()]
        preds = [hex(pred.start_ea) for pred in block.preds()]
        bId = hex(block.start_ea)

        blocks.append(
            {
                "id": block.id,
                "start_ea": bId,
                "end_ea": hex(block.end_ea),
                "successors": succs,
                "predecessors": preds
            }
        )

        for s in succs:
            mermaidLines.append(f"    node_{bId[2:]} --> node_{s[2:]}")

    funcName = idc.get_func_name(func.start_ea) or f"sub_{hex(func.start_ea)[2:]}"
    mermaidDiagram = "\n".join(mermaidLines)

    return {
        "success": True,
        "ea": hex(func.start_ea),
        "name": funcName,
        "blockCount": len(blocks),
        "blocks": blocks,
        "mermaid": mermaidDiagram
    }
