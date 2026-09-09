import json
import os
import time
from typing import Any, Dict, List
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_name
import ida_nalt
import idautils
import idc

from components.commands.func_hash import hashFunctionBytes
from components.commands.rename import allowColonInNames
from utils.logger import bridgeLog
from utils.safety import safeCastInt, safeCastStr
import utils.tlshEngine as tlshEngine

def hashAllThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    limit = safeCastInt(params.get("limit"), fallback=0)
    minSize = safeCastInt(params.get("min_size"), fallback=0)
    mode = params.get("mode") or "normalized"
    if mode not in ("raw", "normalized"):
        mode = "normalized"
    outPath = safeCastStr(params.get("output") or params.get("out") or params.get("path")).strip()
    startTime = time.time()

    entries: List[Dict[str, Any]] = []
    skipped = 0
    failed = 0

    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if not func:
            continue

        size = func.end_ea - func.start_ea
        if minSize > 0 and size < minSize:
            skipped += 1
            continue

        h = hashFunctionBytes(func, mode=mode)
        name = idc.get_func_name(func.start_ea) or ""

        entry = {
            "ea": hex(func.start_ea),
            "name": name,
            "size": size,
        }
        if h:
            entry["tlsh"] = h
        else:
            entry["tlsh"] = None
            failed += 1

        entries.append(entry)
        if limit > 0 and len(entries) >= limit:
            break

    imageBase = ida_nalt.get_imagebase()
    result = {
        "imageBase": hex(imageBase),
        "binary": idc.get_input_file_path() or "",
        "mode": mode,
        "timestamp": int(time.time()),
        "count": len(entries),
        "skipped": skipped,
        "hashFailed": failed,
        "elapsed_sec": round(time.time() - startTime, 3),
        "functions": entries,
    }

    if outPath:
        try:
            os.makedirs(os.path.dirname(outPath) or ".", exist_ok=True)
            with open(outPath, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            result["savedTo"] = outPath
            bridgeLog(f"hash_all: exported {len(entries)} hashes ({mode}) to '{outPath}'")
        except Exception as e:
            result["saveError"] = str(e)

    return {"success": True, **result}

def safeSetName(ea, name):
    if ":" in name:
        allowColonInNames()
    ok = ida_name.set_name(ea, name, ida_name.SN_NOWARN)
    if not ok:
        ok = ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_FORCE)
    if not ok:
        ok = ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK)
    return ok

def matchFuncsThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    dbPath = safeCastStr(params.get("db") or params.get("path") or params.get("file")).strip()
    maxDist = safeCastInt(params.get("max_distance") or params.get("threshold"), fallback=100)
    limit = safeCastInt(params.get("limit"), fallback=50)
    mode = params.get("mode") or "normalized"
    if mode not in ("raw", "normalized"):
        mode = "normalized"
    applyNames = params.get("apply") == "1" or params.get("apply") == "true"
    applyThreshold = safeCastInt(params.get("apply_threshold"), fallback=30)

    if not dbPath or not os.path.isfile(dbPath):
        return {"success": False, "error": f"hash database not found: '{dbPath}'"}

    try:
        with open(dbPath, "r", encoding="utf-8") as f:
            refDb = json.load(f)
    except Exception as e:
        return {"success": False, "error": f"failed to load hash database: {e}"}

    refFuncs = refDb.get("functions", [])
    refHashes = [(r["ea"], r.get("name", ""), r["tlsh"], r.get("size", 0)) for r in refFuncs if r.get("tlsh")]
    if not refHashes:
        return {"success": False, "error": "reference database has no valid TLSH hashes"}

    matches: List[Dict[str, Any]] = []
    scanned = 0

    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if not func:
            continue

        size = func.end_ea - func.start_ea
        localHash = hashFunctionBytes(func, mode=mode)
        if not localHash:
            continue

        scanned += 1
        bestDist = 999999
        bestRef = None

        for refEa, refName, refHash, refSize in refHashes:
            if refSize > 0 and size > 0:
                ratio = max(size, refSize) / max(min(size, refSize), 1)
                if ratio > 3.0:
                    continue
            dist = tlshEngine.compareHashes(localHash, refHash)
            if dist < 0:
                continue
            if dist < bestDist:
                bestDist = dist
                bestRef = (refEa, refName, refHash, refSize)

        if bestRef and bestDist <= maxDist:
            localName = idc.get_func_name(func.start_ea) or ""
            verdict = "identical" if bestDist == 0 else ("patch variant" if bestDist <= 30 else ("similar" if bestDist <= 70 else "weak match"))
            matches.append({
                "localEa": hex(func.start_ea),
                "localName": localName,
                "localSize": size,
                "refEa": bestRef[0],
                "refName": bestRef[1],
                "refSize": bestRef[3],
                "distance": bestDist,
                "verdict": verdict,
            })

        if limit > 0 and len(matches) >= limit:
            break

    matches.sort(key=lambda m: m["distance"])

    renamedCount = 0
    renameResults: List[Dict[str, Any]] = []

    if applyNames:
        for m in matches:
            if m["distance"] > applyThreshold:
                continue
            refName = m["refName"]
            if not refName or refName.startswith("sub_") or refName.startswith("nullsub_"):
                continue
            localName = m["localName"]
            if not localName.startswith("sub_") and not localName.startswith("nullsub_"):
                continue
            localEa = int(m["localEa"], 16)
            if safeSetName(localEa, refName):
                renamedCount += 1
                renameResults.append({"ea": m["localEa"], "old": localName, "new": refName, "distance": m["distance"]})
                bridgeLog(f"match_funcs apply: {m['localEa']} '{localName}' -> '{refName}' (dist={m['distance']})")

    result = {
        "success": True,
        "refDatabase": dbPath,
        "refCount": len(refHashes),
        "mode": mode,
        "scannedFunctions": scanned,
        "matchCount": len(matches),
        "maxDistance": maxDist,
        "matches": matches
    }

    if applyNames:
        result["applied"] = True
        result["applyThreshold"] = applyThreshold
        result["renamedCount"] = renamedCount
        result["renames"] = renameResults

    return result
