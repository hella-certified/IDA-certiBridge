#!/usr/bin/env python3
import json
import os
import socket
import sys
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Union

DEFAULT_HOST = "127.0.0.1"
DEFAULT_BASE_PORT = 13371
DEFAULT_MAX_PORT = 13390
DEFAULT_TIMEOUT_FAST = 30.0
DEFAULT_TIMEOUT_HEAVY = 180.0

HEAVY_ENDPOINTS = {
    "decompile",
    "strings",
    "search_strings",
    "find_vtables",
    "find",
    "find_pattern",
    "make_sig",
    "cfg",
    "callers",
    "callees",
    "list_funcs",
    "match_xrefs",
    "find_class",
    "class",
    "hash_all",
    "match_funcs",
    "apply_rtti",
}

def findActivePort(host: str = DEFAULT_HOST, preferred: Optional[int] = None) -> int:
    if preferred and isPortOpen(host, preferred):
        return preferred

    for p in range(DEFAULT_BASE_PORT, DEFAULT_MAX_PORT + 1):
        if isPortOpen(host, p):
            return p

    candidates = [
        "diary.json",
        "DIARY.md",
        os.path.join(os.path.dirname(__file__), "diary.json"),
        os.path.join(os.path.dirname(__file__), "DIARY.md"),
    ]

    cfgPath = os.path.join(os.path.dirname(__file__), "config.toml")
    if os.path.isfile(cfgPath):
        try:
            with open(cfgPath, "r", encoding="utf-8") as f:
                for line in f:
                    cleanLine = line.strip()
                    if cleanLine.startswith("pluginsPath"):
                        val = cleanLine.split("=", 1)[1].strip().strip('"').strip("'")
                        candidates.append(os.path.join(val, "certibridge", "diary.json"))
                        candidates.append(os.path.join(val, "certibridge", "DIARY.md"))
                    elif cleanLine.startswith("portablePath"):
                        val = cleanLine.split("=", 1)[1].strip().strip('"').strip("'")
                        candidates.append(os.path.join(val, "plugins", "certibridge", "diary.json"))
                        candidates.append(os.path.join(val, "plugins", "certibridge", "DIARY.md"))
        except Exception:
            pass

    idaUsr = os.environ.get("IDAUSR")
    if idaUsr:
        for part in idaUsr.split(os.pathsep):
            candidates.append(os.path.join(part, "plugins", "certibridge", "diary.json"))
            candidates.append(os.path.join(part, "plugins", "certibridge", "DIARY.md"))

    appData = os.environ.get("APPDATA")
    if appData:
        candidates.append(os.path.join(appData, "Hex-Rays", "IDA Pro", "plugins", "certibridge", "diary.json"))
        candidates.append(os.path.join(appData, "Hex-Rays", "IDA Pro", "plugins", "certibridge", "DIARY.md"))

    for path in candidates:
        if os.path.isfile(path):
            try:
                if path.endswith(".json"):
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    for k, v in data.items():
                        p = v.get("port")
                        if p and isPortOpen(host, int(p)):
                            return int(p)
                elif path.endswith(".md"):
                    with open(path, "r", encoding="utf-8") as f:
                        content = f.read()
                    import re
                    ports = re.findall(r"`(133[7-9]\d)`", content)
                    for p in ports:
                        if isPortOpen(host, int(p)):
                            return int(p)
            except Exception:
                pass

    return 13381

def isPortOpen(host: str, port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.04)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False

class BridgeClient:
    def __init__(self, port: Optional[int] = None, host: str = DEFAULT_HOST, defaultTimeout: Optional[float] = None):
        self.host = host
        self.port = port or findActivePort(host)
        self.defaultTimeout = defaultTimeout

    def request(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        raw: bool = False,
        post: bool = False,
        timeout: Optional[float] = None,
    ) -> Union[Dict[str, Any], str]:
        cleanEndpoint = endpoint.lstrip("/")
        baseName = cleanEndpoint.replace("api/", "")
        if not cleanEndpoint.startswith("api/"):
            cleanEndpoint = f"api/{cleanEndpoint}"

        reqTimeout = timeout
        if reqTimeout is None:
            if self.defaultTimeout is not None:
                reqTimeout = self.defaultTimeout
            elif baseName in HEAVY_ENDPOINTS:
                reqTimeout = DEFAULT_TIMEOUT_HEAVY
            else:
                reqTimeout = DEFAULT_TIMEOUT_FAST

        url = f"http://{self.host}:{self.port}/{cleanEndpoint}"
        queryDict = dict(params) if params else {}

        if raw:
            queryDict["raw"] = "1"

        if post:
            dataBytes = json.dumps(queryDict).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=dataBytes,
                headers={"Content-Type": "application/json"}
            )
        else:
            if queryDict:
                url = f"{url}?{urllib.parse.urlencode(queryDict)}"
            req = urllib.request.Request(url)

        try:
            with urllib.request.urlopen(req, timeout=reqTimeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                if raw:
                    return body
                try:
                    return json.loads(body)
                except Exception:
                    return {"success": True, "raw": body}
        except (socket.timeout, TimeoutError):
            errMsg = f"request to '{cleanEndpoint}' timed out after {reqTimeout:.0f}s (IDA Pro is still running or busy analyzing). Retry or increase timeout with '--timeout <sec>'."
            if raw:
                return f"// error: {errMsg}"
        except urllib.error.HTTPError as e:
            errBody = e.read().decode("utf-8", errors="replace")
            try:
                return json.loads(errBody)
            except Exception:
                return {"success": False, "error": f"HTTP {e.code}: {errBody}"}
        except urllib.error.URLError as e:
            if isinstance(getattr(e, "reason", None), socket.timeout) or "timed out" in str(e).lower():
                errMsg = f"request to '{cleanEndpoint}' timed out after {reqTimeout:.0f}s (IDA Pro is still running or busy analyzing). Retry or increase timeout with '--timeout <sec>'."
                if raw:
                    return f"// error: {errMsg}"
                return {"success": False, "error": errMsg, "timeout": True, "ea": queryDict.get("ea")}
            return {"success": False, "error": f"connection failed: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def status(self, timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("status", timeout=timeout)

    def decompile(self, target: str, raw: bool = False, dirty: bool = False, timeout: Optional[float] = None) -> Union[Dict[str, Any], str]:
        params = {"ea": str(target)}
        if dirty:
            params["dirty"] = "1"
        return self.request("decompile", params, raw=raw, timeout=timeout)

    def sig(self, target: str, mode: str = "auto", maxLen: int = 96, timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("make_sig", {"ea": str(target), "mode": mode, "max_len": maxLen}, timeout=timeout)

    def find(self, pattern: str, ripOffset: int = -1, insnLen: int = -1, limit: int = 50, timeout: Optional[float] = None) -> Dict[str, Any]:
        p: Dict[str, Any] = {"pattern": pattern, "limit": limit}
        if ripOffset >= 0:
            p["rip_offset"] = ripOffset
        if insnLen > 0:
            p["insn_len"] = insnLen
        return self.request("find_pattern", p, timeout=timeout)

    def listFuncs(self, query: str = "", limit: int = 50, timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("list_funcs", {"query": query, "limit": limit}, timeout=timeout)

    def vtable(self, ea: str, count: int = 32, raw: bool = False, timeout: Optional[float] = None) -> Union[Dict[str, Any], str]:
        return self.request("vtable", {"ea": str(ea), "count": count}, raw=raw, timeout=timeout)

    def findVtables(self, query: str = "", seg: str = ".rdata", minMethods: int = 3, limit: int = 50, timeout: Optional[float] = None) -> Dict[str, Any]:
        p: Dict[str, Any] = {"seg": seg, "min_methods": minMethods, "limit": limit}
        if query:
            p["query"] = query
        return self.request("find_vtables", p, timeout=timeout)

    def rtti(self, ea: str, timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("rtti", {"ea": str(ea)}, timeout=timeout)

    def callers(self, ea: str, limit: int = 50, userOnly: bool = True, timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("callers", {"ea": str(ea), "limit": limit, "user_only": "1" if userOnly else "0"}, timeout=timeout)

    def callees(self, ea: str, limit: int = 50, userOnly: bool = True, timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("callees", {"ea": str(ea), "limit": limit, "user_only": "1" if userOnly else "0"}, timeout=timeout)

    def cfg(self, ea: str, formatType: str = "mermaid", timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("cfg", {"ea": str(ea), "format": formatType}, timeout=timeout)

    def bytes(self, ea: str, size: int = 32, timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("get_bytes", {"ea": str(ea), "size": size}, timeout=timeout)

    def patch(self, ea: str, patchBytes: str, timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("patch_bytes", {"ea": str(ea), "bytes": patchBytes}, post=True, timeout=timeout)

    def rename(self, ea: str, newName: str, timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("rename_func", {"ea": str(ea), "name": newName}, timeout=timeout)

    def renameVar(self, funcEa: str, oldVar: str, newVar: str, timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("rename_var", {"ea": str(funcEa), "old_name": oldVar, "new_name": newVar}, timeout=timeout)

    def struct(self, name: str, raw: bool = False, timeout: Optional[float] = None) -> Union[Dict[str, Any], str]:
        return self.request("get_struct", {"name": name}, raw=raw, timeout=timeout)

    def strings(self, query: str = "", limit: int = 50, xrefs: bool = True, timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("search_strings", {"query": query, "limit": limit, "xrefs": "1" if xrefs else "0"}, timeout=timeout)

    def reload(self, timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("reload", timeout=timeout)

    def logs(self, count: int = 100, timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("logs", {"count": count}, timeout=timeout)

    def findClass(self, name: str, limit: int = 10, methods: int = 32, timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("find_class", {"name": name, "limit": limit, "methods": methods}, timeout=timeout)

    def autoWait(self, timeout: float = 30.0) -> Dict[str, Any]:
        return self.request("auto_wait", {"timeout": timeout}, timeout=timeout + 5.0)

    def funcHash(self, target: str, timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("func_hash", {"ea": target}, timeout=timeout)

    def funcDiff(self, target1: str, target2: str, timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("func_diff", {"target1": target1, "target2": target2}, timeout=timeout)

    def hashAll(self, output: str = "", minSize: int = 0, limit: int = 0, timeout: Optional[float] = None) -> Dict[str, Any]:
        p: Dict[str, Any] = {}
        if output:
            p["output"] = output
        if minSize > 0:
            p["min_size"] = minSize
        if limit > 0:
            p["limit"] = limit
        return self.request("hash_all", p, timeout=timeout)

    def matchFuncs(self, dbPath: str, maxDistance: int = 100, limit: int = 50, apply: bool = False, applyThreshold: int = 30, timeout: Optional[float] = None) -> Dict[str, Any]:
        p: Dict[str, Any] = {"db": dbPath, "max_distance": maxDistance, "limit": limit}
        if apply:
            p["apply"] = "1"
            p["apply_threshold"] = applyThreshold
        return self.request("match_funcs", p, timeout=timeout)

    def applyRtti(self, name: str, limit: int = 10, methods: int = 32, dryRun: bool = False, timeout: Optional[float] = None) -> Dict[str, Any]:
        p: Dict[str, Any] = {"name": name, "limit": limit, "methods": methods}
        if dryRun:
            p["dry_run"] = "1"
        return self.request("apply_rtti", p, timeout=timeout)

    def call(self, command: str, timeout: Optional[float] = None, **kwargs) -> Any:
        return self.request(command, kwargs, timeout=timeout)

_DEFAULT_CLIENT: Optional[BridgeClient] = None

def getClient(timeout: Optional[float] = None) -> BridgeClient:
    global _DEFAULT_CLIENT
    if _DEFAULT_CLIENT is None:
        _DEFAULT_CLIENT = BridgeClient(defaultTimeout=timeout)
    elif timeout is not None:
        _DEFAULT_CLIENT.defaultTimeout = timeout
    return _DEFAULT_CLIENT

def status(timeout: Optional[float] = None):
    return getClient(timeout=timeout).status()

def decompile(target: str, raw: bool = False, dirty: bool = False, timeout: Optional[float] = None):
    return getClient(timeout=timeout).decompile(target, raw=raw, dirty=dirty, timeout=timeout)

def sig(target: str, mode: str = "auto", maxLen: int = 96, timeout: Optional[float] = None):
    return getClient(timeout=timeout).sig(target, mode=mode, maxLen=maxLen, timeout=timeout)

def find(pattern: str, ripOffset: int = -1, insnLen: int = -1, limit: int = 50, timeout: Optional[float] = None):
    return getClient(timeout=timeout).find(pattern, ripOffset=ripOffset, insnLen=insnLen, limit=limit, timeout=timeout)

def listFuncs(query: str = "", limit: int = 50, timeout: Optional[float] = None):
    return getClient(timeout=timeout).listFuncs(query=query, limit=limit, timeout=timeout)

def vtable(ea: str, count: int = 32, raw: bool = False, timeout: Optional[float] = None):
    return getClient(timeout=timeout).vtable(ea, count=count, raw=raw, timeout=timeout)

def findVtables(seg: str = ".rdata", minMethods: int = 3, limit: int = 50, timeout: Optional[float] = None):
    return getClient(timeout=timeout).findVtables(seg=seg, minMethods=minMethods, limit=limit, timeout=timeout)

def rtti(ea: str, timeout: Optional[float] = None):
    return getClient(timeout=timeout).rtti(ea, timeout=timeout)

def findClass(name: str, limit: int = 10, methods: int = 32, timeout: Optional[float] = None):
    return getClient(timeout=timeout).findClass(name, limit=limit, methods=methods, timeout=timeout)

def autoWait(timeout: float = 30.0):
    return getClient().autoWait(timeout=timeout)

def funcHash(target: str, timeout: Optional[float] = None):
    return getClient(timeout=timeout).funcHash(target, timeout=timeout)

def funcDiff(target1: str, target2: str, timeout: Optional[float] = None):
    return getClient(timeout=timeout).funcDiff(target1, target2, timeout=timeout)

def hashAll(output: str = "", minSize: int = 0, limit: int = 0, timeout: Optional[float] = None):
    return getClient(timeout=timeout).hashAll(output=output, minSize=minSize, limit=limit, timeout=timeout)

def matchFuncs(dbPath: str, maxDistance: int = 100, limit: int = 50, apply: bool = False, applyThreshold: int = 30, timeout: Optional[float] = None):
    return getClient(timeout=timeout).matchFuncs(dbPath, maxDistance=maxDistance, limit=limit, apply=apply, applyThreshold=applyThreshold, timeout=timeout)

def applyRtti(name: str, limit: int = 10, methods: int = 32, dryRun: bool = False, timeout: Optional[float] = None):
    return getClient(timeout=timeout).applyRtti(name, limit=limit, methods=methods, dryRun=dryRun, timeout=timeout)

def callers(ea: str, limit: int = 50, userOnly: bool = True, timeout: Optional[float] = None):
    return getClient(timeout=timeout).callers(ea, limit=limit, userOnly=userOnly, timeout=timeout)

def callees(ea: str, limit: int = 50, userOnly: bool = True, timeout: Optional[float] = None):
    return getClient(timeout=timeout).callees(ea, limit=limit, userOnly=userOnly, timeout=timeout)

def cfg(ea: str, formatType: str = "mermaid", timeout: Optional[float] = None):
    return getClient(timeout=timeout).cfg(ea, formatType=formatType, timeout=timeout)

def bytes(ea: str, size: int = 32, timeout: Optional[float] = None):
    return getClient(timeout=timeout).bytes(ea, size=size, timeout=timeout)

def patch(ea: str, patchBytes: str, timeout: Optional[float] = None):
    return getClient(timeout=timeout).patch(ea, patchBytes=patchBytes, timeout=timeout)

def rename(ea: str, newName: str, timeout: Optional[float] = None):
    return getClient(timeout=timeout).rename(ea, newName=newName, timeout=timeout)

def struct(name: str, raw: bool = False, timeout: Optional[float] = None):
    return getClient(timeout=timeout).struct(name, raw=raw, timeout=timeout)

def strings(query: str = "", limit: int = 50, timeout: Optional[float] = None):
    return getClient(timeout=timeout).strings(query=query, limit=limit, timeout=timeout)

def reload(timeout: Optional[float] = None):
    return getClient(timeout=timeout).reload(timeout=timeout)

def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        print("Usage: python cb.py <command> [args] [--raw] [--port N] [--timeout SEC]")
        print("\nCommands:")
        print("  status                          Show active dump, base, hexrays status")
        print("  decompile <ea|name> [--raw]     Decompile function (cached by default, --dirty to force)")
        print("  sig <ea|name> [mode=auto]       Generate unique signature")
        print("  find <pattern> [ripOff] [len]   Scan memory for wildcard pattern")
        print("  list_funcs [query] [limit=50]   List / search functions")
        print("  vtable <ea> [count=32] [--raw]  Inspect vtable & generate struct")
        print("  find_vtables [seg=.rdata]       Scan for candidate vtables")
        print("  class <name> [limit=10]         Find class RTTI, vtable, methods & base classes")
        print("  rtti <ea>                       Parse MSVC 64-bit RTTI")
        print("  auto_wait [--timeout SEC]       Wait for IDA auto-analysis to finish")
        print("  callers <ea> [limit=50]         List calling functions")
        print("  callees <ea> [limit=50]         List called subroutines")
        print("  cfg <ea> [format=mermaid|json]  Extract control flow graph")
        print("  bytes <ea> [size=32]            Read raw memory bytes & hex")
        print("  patch <ea> <bytes>              Patch bytes in database")
        print("  rename <ea> <name>              Rename function")
        print("  struct <name> [--raw]           Inspect struct declaration")
        print("  strings [query] [limit=50]      Search / generate strings & xrefs")
        print("  reload                          Hot reload plugin mid-session")
        print("  hash <ea|name>                  Compute TLSH fuzzy function hash")
        print("  diff <ea1|hash1> <ea2|hash2>    Compare two functions by TLSH distance")
        print("  hash_all [output=path.json]      Hash all functions & export corpus")
        print("  match_funcs <db.json> [max=100]  Match functions against a hash corpus")
        print("  apply_rtti <class> [--dry-run]   Auto-name vtable & vfuncs from RTTI")
        print("  call <endpoint> [k=v ...]       Call any arbitrary API endpoint")
        print("\nOptions:")
        print("  --raw                           Return pure text/C pseudocode without JSON wrapper")
        print("  --timeout <sec>, -t <sec>       Custom request timeout in seconds (default: 30s light, 180s heavy)")
        print("  --port <port>                   Directly specify IDA bridge instance port")
        return

    port = None
    raw = False
    customTimeout = None
    customLimit = None
    cleanArgs: List[str] = []

    idx = 0
    while idx < len(args):
        a = args[idx]
        if a == "--raw":
            raw = True
        elif a == "--port" and idx + 1 < len(args):
            port = int(args[idx + 1])
            idx += 1
        elif (a == "--timeout" or a == "-t") and idx + 1 < len(args):
            try:
                customTimeout = float(args[idx + 1])
            except ValueError:
                pass
            idx += 1
        elif (a == "--limit" or a == "-l") and idx + 1 < len(args):
            try:
                customLimit = int(args[idx + 1])
            except ValueError:
                pass
            idx += 1
        else:
            cleanArgs.append(a)
        idx += 1

    cmd = cleanArgs[0].lower() if cleanArgs else "status"
    subArgs = cleanArgs[1:]

    client = BridgeClient(port=port, defaultTimeout=customTimeout)

    res: Any = None
    if cmd == "status":
        res = client.status()
    elif cmd in ("decompile", "dec"):
        target = subArgs[0] if subArgs else "WinMain"
        dirty = "--dirty" in subArgs or "--force" in subArgs
        res = client.decompile(target, raw=raw, dirty=dirty)
    elif cmd in ("sig", "make_sig"):
        target = subArgs[0] if subArgs else "WinMain"
        mode = subArgs[1] if len(subArgs) > 1 else "auto"
        res = client.sig(target, mode=mode)
    elif cmd in ("find", "find_pattern"):
        pat = subArgs[0] if subArgs else ""
        ripOff = int(subArgs[1]) if len(subArgs) > 1 else -1
        insnLen = int(subArgs[2]) if len(subArgs) > 2 else -1
        res = client.find(pat, ripOffset=ripOff, insnLen=insnLen)
    elif cmd in ("list_funcs", "funcs"):
        q = subArgs[0] if subArgs else ""
        lim = customLimit if customLimit is not None else (int(subArgs[1]) if len(subArgs) > 1 else 50)
        res = client.listFuncs(query=q, limit=lim)
    elif cmd == "vtable":
        ea = subArgs[0] if subArgs else ""
        count = customLimit if customLimit is not None else (int(subArgs[1]) if len(subArgs) > 1 else 32)
        res = client.vtable(ea, count=count, raw=raw)
    elif cmd == "find_vtables":
        query = ""
        seg = ".rdata"
        if subArgs:
            if subArgs[0].startswith("."):
                seg = subArgs[0]
                if len(subArgs) > 1:
                    query = subArgs[1]
            else:
                query = subArgs[0]
                if len(subArgs) > 1:
                    seg = subArgs[1]
        lim = customLimit if customLimit is not None else 50
        res = client.findVtables(query=query, seg=seg, limit=lim)
    elif cmd in ("find_class", "class"):
        name = subArgs[0] if subArgs else "Camera"
        lim = customLimit if customLimit is not None else 10
        methods = int(subArgs[1]) if len(subArgs) > 1 and subArgs[1].isdigit() else 32
        applyFlag = "--apply" in subArgs
        if applyFlag:
            dryRun = "--dry-run" in subArgs or "--dry_run" in subArgs
            res = client.applyRtti(name, limit=lim, methods=methods, dryRun=dryRun)
        else:
            res = client.findClass(name, limit=lim, methods=methods)
    elif cmd in ("auto_wait", "wait_analysis", "wait"):
        to = customTimeout if customTimeout is not None else 30.0
        res = client.autoWait(timeout=to)
    elif cmd in ("func_hash", "hash"):
        target = subArgs[0] if subArgs else ""
        res = client.funcHash(target)
    elif cmd in ("func_diff", "diff"):
        t1 = subArgs[0] if subArgs else ""
        t2 = subArgs[1] if len(subArgs) > 1 else ""
        res = client.funcDiff(t1, t2)
    elif cmd in ("hash_all",):
        outPath = ""
        minSz = 0
        for sa in subArgs:
            if sa.startswith("output=") or sa.startswith("out="):
                outPath = sa.split("=", 1)[1]
            elif sa.startswith("min_size="):
                minSz = int(sa.split("=", 1)[1])
        lim = customLimit if customLimit is not None else 0
        res = client.hashAll(output=outPath, minSize=minSz, limit=lim)
    elif cmd in ("match_funcs", "match"):
        dbFile = subArgs[0] if subArgs else ""
        maxDist = 100
        applyFlag = "--apply" in subArgs
        applyThresh = 30
        for sa in subArgs[1:]:
            if sa.startswith("max=") or sa.startswith("max_distance="):
                maxDist = int(sa.split("=", 1)[1])
            elif sa.startswith("threshold=") or sa.startswith("apply_threshold="):
                applyThresh = int(sa.split("=", 1)[1])
        lim = customLimit if customLimit is not None else 50
        res = client.matchFuncs(dbFile, maxDistance=maxDist, limit=lim, apply=applyFlag, applyThreshold=applyThresh)
    elif cmd in ("apply_rtti",):
        name = subArgs[0] if subArgs else ""
        lim = customLimit if customLimit is not None else 10
        methods = 32
        dryRun = "--dry-run" in subArgs or "--dry_run" in subArgs
        for sa in subArgs[1:]:
            if sa.isdigit():
                methods = int(sa)
        res = client.applyRtti(name, limit=lim, methods=methods, dryRun=dryRun)
    elif cmd == "rtti":
        ea = subArgs[0] if subArgs else ""
        res = client.rtti(ea)
    elif cmd == "callers":
        ea = subArgs[0] if subArgs else ""
        lim = customLimit if customLimit is not None else 50
        res = client.callers(ea, limit=lim)
    elif cmd == "callees":
        ea = subArgs[0] if subArgs else ""
        lim = customLimit if customLimit is not None else 50
        res = client.callees(ea, limit=lim)
    elif cmd == "cfg":
        ea = subArgs[0] if subArgs else ""
        fmt = subArgs[1] if len(subArgs) > 1 else "mermaid"
        res = client.cfg(ea, formatType=fmt)
    elif cmd == "bytes":
        ea = subArgs[0] if subArgs else ""
        size = customLimit if customLimit is not None else (int(subArgs[1]) if len(subArgs) > 1 else 32)
        res = client.bytes(ea, size=size)
    elif cmd == "patch":
        ea = subArgs[0] if subArgs else ""
        patchData = " ".join(subArgs[1:])
        res = client.patch(ea, patchData)
    elif cmd in ("rename", "rename_func"):
        ea = subArgs[0] if subArgs else ""
        name = subArgs[1] if len(subArgs) > 1 else ""
        res = client.rename(ea, name)
    elif cmd == "struct":
        name = subArgs[0] if subArgs else ""
        res = client.struct(name, raw=raw)
    elif cmd in ("strings", "str"):
        q = " ".join(subArgs) if subArgs else ""
        lim = customLimit if customLimit is not None else 50
        res = client.strings(q, limit=lim)
    elif cmd == "reload":
        res = client.reload()
    elif cmd == "logs":
        res = client.logs()
    elif cmd == "call":
        endpoint = subArgs[0] if subArgs else "status"
        kvParams = {}
        for item in subArgs[1:]:
            if "=" in item:
                k, v = item.split("=", 1)
                kvParams[k] = v
        res = client.call(endpoint, **kvParams)
    else:
        kvParams = {}
        for item in subArgs:
            if "=" in item:
                k, v = item.split("=", 1)
                kvParams[k] = v
        res = client.call(cmd, **kvParams)

    if raw and isinstance(res, str):
        print(res)
    elif isinstance(res, dict) or isinstance(res, list):
        print(json.dumps(res, indent=2))
    else:
        print(res)

if __name__ == "__main__":
    main()
