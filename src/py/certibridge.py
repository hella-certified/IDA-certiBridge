import os
import sys
import importlib

pluginDir = os.path.dirname(os.path.abspath(__file__))
for p in [pluginDir, os.path.join(pluginDir, "certibridge")]:
    if os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)

import ida_idaapi
import ida_kernwin
import ida_idp
import idc

from utils.logger import bridgeLog
from utils.ports import findFreePort
from utils.dumpInfo import getDumpInfo, notifyCoreDaemon
from components.server import BridgeRequestHandler, CertiBridgeServer
from components.commands import executeCommand, COMMAND_REGISTRY
def getActiveDumpName() -> str:
    import ida_nalt
    return idc.get_root_filename() or os.path.basename(ida_nalt.get_input_file_path() or "unknown")

_activeCertibridgePlugin = None

class CertiBridgePlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX
    comment = "IDA-certiBridge Plugin"
    help = "IDA-certiBridge Pro Decompiler & Session Bridge"
    wanted_name = "certibridge"
    wanted_hotkey = "Ctrl-Shift-R"

    def __init__(self):
        super().__init__()
        self.httpd = None
        self.timer = None
        self.boundPort = 0
        self.idbHooks = None
        self.currentDumpName = "unknown"
        self.tickCounter = 0

    def init(self):
        global _activeCertibridgePlugin

        if _activeCertibridgePlugin is not None and _activeCertibridgePlugin is not self:
            bridgeLog("active instance detected; restarting with new changes...")
            try:
                _activeCertibridgePlugin.stopServer()
            except Exception:
                pass
            _activeCertibridgePlugin = None

        self.startServer()
        _activeCertibridgePlugin = self
        return ida_idaapi.PLUGIN_KEEP

    def startServer(self):
        self.boundPort = findFreePort()
        self.httpd = CertiBridgeServer(("127.0.0.1", self.boundPort), BridgeRequestHandler)
        self.httpd.boundPort = self.boundPort
        self.httpd.plugin = self
        self.httpd.timeout = 0.001
        self.currentDumpName = getActiveDumpName()
        self.tickCounter = 0

        def timerTick():
            if self.httpd:
                try:
                    self.httpd.handle_request()
                except Exception:
                    pass

            self.tickCounter += 1
            if self.tickCounter >= 20:
                self.tickCounter = 0
                curName = getActiveDumpName()
                if curName != "unknown" and curName != self.currentDumpName:
                    self.currentDumpName = curName
                    info = getDumpInfo(self.boundPort)
                    notifyCoreDaemon(info, "register", pluginDir)
                    bridgeLog(f"binary detected: '{curName}' (image base: {info.get('imageBase')}, arch: {info.get('architecture')}) - registered on port {self.boundPort}")

            return 25

        self.timer = ida_kernwin.register_timer(25, timerTick)

        class IDBHooks(ida_idp.IDB_Hooks):
            def auto_empty_finally(self):
                curName = getActiveDumpName()
                self.plugin.currentDumpName = curName
                info = getDumpInfo(self.plugin.boundPort)
                notifyCoreDaemon(info, "register", pluginDir)
                bridgeLog(f"auto-analysis complete for '{curName}'")
                return 0

            def savebase(self):
                curName = getActiveDumpName()
                if curName != "unknown" and curName != self.plugin.currentDumpName:
                    self.plugin.currentDumpName = curName
                    info = getDumpInfo(self.plugin.boundPort)
                    notifyCoreDaemon(info, "register", pluginDir)
                return 0

        self.idbHooks = IDBHooks()
        self.idbHooks.plugin = self
        self.idbHooks.hook()

        fn = getActiveDumpName()
        self.currentDumpName = fn
        if fn != "unknown":
            info = getDumpInfo(self.boundPort)
            notifyCoreDaemon(info, "register", pluginDir)
            bridgeLog(f"online at http://127.0.0.1:{self.boundPort} for '{fn}' (hotkey: Ctrl-Shift-R)")
        else:
            bridgeLog(f"online at http://127.0.0.1:{self.boundPort} - waiting for IDB/exe to open... (hotkey: Ctrl-Shift-R)")

    def stopServer(self):
        global _activeCertibridgePlugin
        fn = getActiveDumpName()
        if self.boundPort:
            notifyCoreDaemon({"port": self.boundPort, "id": f"dump_{self.boundPort}"}, "unregister", pluginDir)
        if self.timer:
            try:
                ida_kernwin.unregister_timer(self.timer)
            except Exception:
                pass
            self.timer = None
        if self.httpd:
            try:
                self.httpd.server_close()
            except Exception:
                pass
            self.httpd = None
        if self.idbHooks:
            try:
                self.idbHooks.unhook()
            except Exception:
                pass
            self.idbHooks = None
        if _activeCertibridgePlugin is self:
            _activeCertibridgePlugin = None
        bridgeLog(f"session unloaded for '{fn}'")

    def run(self, arg):
        fn = getActiveDumpName()
        bridgeLog(f"manual reload requested mid-session for '{fn}'...")
        self.stopServer()
        for modName in list(sys.modules.keys()):
            if modName.startswith("components.") or modName.startswith("utils."):
                try:
                    importlib.reload(sys.modules[modName])
                except Exception:
                    pass
        self.startServer()

    def term(self):
        self.stopServer()

def renameFunc(ea, name: str):
    return executeCommand("rename_func", plugin=_activeCertibridgePlugin, ea=ea, name=name)

def renameVar(ea, oldVar: str, newVar: str):
    return executeCommand("rename_var", plugin=_activeCertibridgePlugin, ea=ea, old_name=oldVar, new_name=newVar)

def renameParam(ea, param, name: str):
    return executeCommand("rename_param", plugin=_activeCertibridgePlugin, ea=ea, param=param, name=name)

def batchRename(items: list):
    return executeCommand("batch_rename", plugin=_activeCertibridgePlugin, items=items)

def renameGlobal(ea, name: str):
    return executeCommand("rename_global", plugin=_activeCertibridgePlugin, ea=ea, name=name)

def copyProto(ea, fromPort: int = 13382, source=None, proto: str = None):
    return executeCommand("copy_proto", plugin=_activeCertibridgePlugin, ea=ea, from_port=fromPort, source=source, proto=proto)

def matchXrefs(ea, fromPort: int = 13382):
    return executeCommand("match_xrefs", plugin=_activeCertibridgePlugin, ea=ea, from_port=fromPort)

def getStruct(name: str):
    return executeCommand("get_struct", plugin=_activeCertibridgePlugin, name=name)

def createStruct(decl: str):
    return executeCommand("create_struct", plugin=_activeCertibridgePlugin, decl=decl)

def copyStruct(name: str, fromPort: int = 13382):
    return executeCommand("copy_struct", plugin=_activeCertibridgePlugin, name=name, from_port=fromPort)

def setType(ea, var: str, typeStr: str):
    return executeCommand("set_type", plugin=_activeCertibridgePlugin, ea=ea, var=var, type=typeStr)

def searchStrings(query: str, limit: int = 50, xrefs: bool = True):
    return executeCommand("search_strings", plugin=_activeCertibridgePlugin, query=query, limit=limit, xrefs="1" if xrefs else "0")

def decompile(ea, raw: bool = False):
    return executeCommand("decompile", plugin=_activeCertibridgePlugin, ea=ea, raw="1" if raw else "0")

def reload():
    if _activeCertibridgePlugin:
        _activeCertibridgePlugin.run(0)
    return {"status": "reloaded"}

def logs(count: int = 100):
    return executeCommand("logs", plugin=_activeCertibridgePlugin, count=count)

def status():
    return executeCommand("status", plugin=_activeCertibridgePlugin)

def diary():
    return executeCommand("diary", plugin=_activeCertibridgePlugin)

def help():
    return executeCommand("help", plugin=_activeCertibridgePlugin)

def vtable(ea, count: int = 32):
    return executeCommand("vtable", plugin=_activeCertibridgePlugin, ea=ea, count=count)

def findVtables(seg: str = ".rdata", minMethods: int = 3, limit: int = 50):
    return executeCommand("find_vtables", plugin=_activeCertibridgePlugin, seg=seg, min_methods=minMethods, limit=limit)

def rtti(ea):
    return executeCommand("rtti", plugin=_activeCertibridgePlugin, ea=ea)

def findPattern(pattern: str, limit: int = 50):
    return executeCommand("find_pattern", plugin=_activeCertibridgePlugin, pattern=pattern, limit=limit)

def makeSig(ea, maxLen: int = 64, unique: bool = True):
    return executeCommand("make_sig", plugin=_activeCertibridgePlugin, ea=ea, max_len=maxLen, unique="1" if unique else "0")

def getBytes(ea, size: int = 32):
    return executeCommand("get_bytes", plugin=_activeCertibridgePlugin, ea=ea, size=size)

def patchBytes(ea, patchData):
    return executeCommand("patch_bytes", plugin=_activeCertibridgePlugin, ea=ea, bytes=patchData)

def callers(ea, limit: int = 100, userOnly: bool = True):
    return executeCommand("callers", plugin=_activeCertibridgePlugin, ea=ea, limit=limit, user_only="1" if userOnly else "0")

def callees(ea, limit: int = 100, userOnly: bool = True):
    return executeCommand("callees", plugin=_activeCertibridgePlugin, ea=ea, limit=limit, user_only="1" if userOnly else "0")

def cfg(ea, format: str = "mermaid"):
    return executeCommand("cfg", plugin=_activeCertibridgePlugin, ea=ea, format=format)

def PLUGIN_ENTRY():
    return CertiBridgePlugin()
