import os
import json
import socket
import urllib.request
import ida_nalt
import ida_loader
import ida_ida
import ida_hexrays
import ida_auto
import idc

CORE_DAEMON_PORT = 13371

def getDumpInfo(port: int = 0) -> dict:
    idbPath = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
    filename = idc.get_root_filename() or os.path.basename(ida_nalt.get_input_file_path() or "")
    if not filename or filename == "unknown":
        if idbPath:
            filename = os.path.basename(idbPath).replace(".i64", "").replace(".idb", "")
        else:
            filename = "unknown"
    imageBase = hex(ida_nalt.get_imagebase())
    arch = "x86_64" if ida_ida.inf_is_64bit() else "x86"
    rawMd5 = ida_nalt.retrieve_input_file_md5()
    md5 = rawMd5.hex() if isinstance(rawMd5, (bytes, bytearray)) else ""
    hexRays = bool(ida_hexrays.init_hexrays_plugin())

    return {
        "id": f"dump_{port}",
        "filename": filename,
        "idbPath": idbPath,
        "architecture": arch,
        "imageBase": imageBase,
        "md5": md5,
        "hexRaysAvailable": hexRays,
        "analysisStatus": "completed" if ida_auto.auto_is_ok() else "analyzing",
        "port": port
    }

def notifyCoreDaemon(info: dict, action: str = "register", pluginDir: str = ""):
    try:
        url = f"http://127.0.0.1:{CORE_DAEMON_PORT}/api/dump/{action}"
        payload = json.dumps(info).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=1.0):
            pass
    except Exception:
        writeFallbackDiary(info, action, pluginDir)

def findDiaryLocations(info: dict, pluginDir: str = "") -> list:
    locations = []
    if pluginDir:
        locations.append(os.path.abspath(pluginDir))
        parent = os.path.dirname(os.path.abspath(pluginDir))
        if os.path.basename(parent).lower() == "plugins" or os.path.basename(os.path.abspath(pluginDir)).lower() == "plugins":
            locations.append(parent)
    if info.get("idbPath"):
        idbDir = os.path.dirname(info["idbPath"])
        if os.path.isdir(idbDir):
            locations.append(idbDir)
    seen = set()
    result = []
    for loc in locations:
        norm = os.path.normpath(loc)
        if norm not in seen and os.path.isdir(norm):
            seen.add(norm)
            result.append(norm)
    return result

def isPortResponsive(port: int) -> bool:
    if not port:
        return False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.05)
        return s.connect_ex(("127.0.0.1", port)) == 0

def writeFallbackDiary(info: dict, action: str = "register", pluginDir: str = ""):
    dirs = findDiaryLocations(info, pluginDir)
    port = info.get("port") or 0
    dumpKey = info.get("id") or f"dump_{port}"

    for d in dirs:
        jsonPath = os.path.join(d, "diary.json")
        mdPath = os.path.join(d, "DIARY.md")

        dumps = {}
        if os.path.isfile(jsonPath):
            try:
                with open(jsonPath, "r", encoding="utf-8") as f:
                    dumps = json.load(f)
            except Exception:
                dumps = {}

        if action == "register" and info.get("filename") and info.get("filename") != "None":
            dumps[dumpKey] = info
        elif action == "unregister":
            dumps.pop(dumpKey, None)

        # prune inactive dumps
        activeDumps = {}
        for k, v in dumps.items():
            p = v.get("port") or 0
            if (p == port and action == "register") or isPortResponsive(p):
                activeDumps[k] = v

        try:
            with open(jsonPath, "w", encoding="utf-8") as f:
                json.dump(activeDumps, f, indent=2)
        except Exception:
            pass

        rows = []
        for v in activeDumps.values():
            fn = v.get("filename") or "unknown"
            p = v.get("port") or ""
            ib = v.get("imageBase") or ""
            arch = v.get("architecture") or ""
            hr = "Active" if v.get("hexRaysAvailable") else "Unavailable"
            st = v.get("analysisStatus") or "ready"
            db = v.get("idbPath") or ""
            rows.append(f"| **{fn}** | `{p}` | `{ib}` | {arch} | {hr} | {st} | `{db}` |")

        tableContent = "\n".join(rows) if rows else "| *No active dumps registered* | | | | | | |"

        content = (
            "# IDA Pro Binary Diary\n\n"
            "Live registry of loaded binary dumps and active IDA sessions.\n\n"
            "| Target / File | Port | Image Base | Arch | Hex-Rays | Status | Database Path |\n"
            "|---|---|---|---|---|---|---|\n"
            f"{tableContent}\n"
        )

        try:
            with open(mdPath, "w", encoding="utf-8") as f:
                f.write(content)
            break
        except Exception:
            continue
