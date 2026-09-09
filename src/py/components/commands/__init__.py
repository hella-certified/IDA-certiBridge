import sys
import importlib
from typing import Callable, Any, Dict, List, Optional
from utils.safety import safeExecute, safeCall, safeCastStr

class CommandDef:
    def __init__(self, name: str, usage: str, description: str, modName: str, funcName: str):
        self.name = name
        self.usage = usage
        self.description = description
        self.modName = modName
        self.funcName = funcName

    @property
    def thunk(self):
        mod = sys.modules.get(self.modName)
        if not mod:
            mod = importlib.import_module(self.modName)
        return getattr(mod, self.funcName)

COMMAND_REGISTRY: List[CommandDef] = [
    CommandDef("status", "status", "Get binary dump metadata, imagebase, and bridge status", "components.commands.status", "statusThunk"),
    CommandDef("decompile", "decompile <ea|name|proto> [raw=1]", "Decompile function with clean raw C pseudocode output", "components.commands.decompile", "decompileThunk"),
    CommandDef("rename_func", "rename_func <ea|old_name> <new_name>", "Rename a function in IDA", "components.commands.rename", "renameFuncThunk"),
    CommandDef("rename_var", "rename_var <func_ea> <old_var|idx> <new_var>", "Rename local variable in Hex-Rays pseudocode", "components.commands.rename", "renameVarThunk"),
    CommandDef("rename_param", "rename_param <func_ea> <param_idx|old_name> <new_name>", "Rename parameter in Hex-Rays pseudocode", "components.commands.rename", "renameParamThunk"),
    CommandDef("get_struct", "get_struct <struct_name>", "Get C struct declaration, size, and member offsets", "components.commands.structs", "getStructThunk"),
    CommandDef("create_struct", "create_struct <c_decl>", "Create or update C struct in local type library", "components.commands.structs", "createStructThunk"),
    CommandDef("copy_struct", "copy_struct <struct_name> [from_port=13382]", "Copy struct declaration from remote IDA session / PDB", "components.commands.structs", "copyStructThunk"),
    CommandDef("set_type", "set_type <func_ea> <var_name> <type_decl>", "Apply struct pointer or custom type to local variable or parameter", "components.commands.structs", "setTypeThunk"),
    CommandDef("list_funcs", "list_funcs [query=str] [unnamed_only=1] [limit=50]", "List and search functions by name, address, or unassigned status", "components.commands.list_funcs", "listFuncsThunk"),
    CommandDef("list_structs", "list_structs [query=str] [limit=50]", "List and search structures and type libraries by name", "components.commands.list_structs", "listStructsThunk"),
    CommandDef("xrefs", "xrefs <ea|name> [limit=100]", "Retrieve code and data references to an address or function", "components.commands.xrefs", "xrefsThunk"),
    CommandDef("search_strings", "search_strings <query> [limit=50] [xrefs=1]", "Fast non-blocking SIMD string and xref search", "components.commands.strings", "searchStringsThunk"),
    CommandDef("batch_rename", "batch_rename <items=[{ea, name}, ...]>", "Batch rename functions or global variables in a single call", "components.commands.batch_rename", "batchRenameThunk"),
    CommandDef("rename_global", "rename_global <ea|old_name> <new_name>", "Rename a global variable or label in IDA", "components.commands.rename_global", "renameGlobalThunk"),
    CommandDef("set_name", "set_name <ea|old_name> <new_name>", "Set name for any address in IDA", "components.commands.rename_global", "renameGlobalThunk"),
    CommandDef("copy_proto", "copy_proto <ea|name> [from_port=13382] [source=sym] [proto=decl]", "Synchronize or apply C function prototype", "components.commands.copy_proto", "copyProtoThunk"),
    CommandDef("match_xrefs", "match_xrefs <ea|name> [from_port=13382]", "Match function against reference binary using referenced strings and xrefs", "components.commands.match_xrefs", "matchXrefsThunk"),
    CommandDef("vtable", "vtable <ea|name> [count=32]", "Inspect virtual method table, resolve methods, and generate C++ struct", "components.commands.vtable", "vtableInspectThunk"),
    CommandDef("vtable_inspect", "vtable_inspect <ea|name> [count=32]", "Alias for vtable inspection", "components.commands.vtable", "vtableInspectThunk"),
    CommandDef("find_vtables", "find_vtables [seg=.rdata] [min_methods=3] [limit=50]", "Scan data segments for candidate virtual tables", "components.commands.find_vtables", "findVtablesThunk"),
    CommandDef("rtti", "rtti <ea>", "Inspect MSVC 64-bit RTTI to recover class name and inheritance", "components.commands.rtti", "rttiInspectThunk"),
    CommandDef("rtti_inspect", "rtti_inspect <ea>", "Alias for rtti inspection", "components.commands.rtti", "rttiInspectThunk"),
    CommandDef("find_class", "find_class <class_name> [limit=10] [methods=32]", "Find class by name using MSVC RTTI, resolve CompleteObjectLocator, vtable, base classes, and virtual methods", "components.commands.rtti", "findClassThunk"),
    CommandDef("class", "class <class_name> [limit=10] [methods=32]", "Alias for find_class", "components.commands.rtti", "findClassThunk"),
    CommandDef("auto_wait", "auto_wait [timeout=30]", "Wait for IDA background auto-analysis to finish before issuing commands", "components.commands.auto_wait", "autoWaitThunk"),
    CommandDef("find_pattern", "find_pattern <pattern> [limit=50]", "Scan memory segments for IDA wildcard byte pattern", "components.commands.pattern", "findPatternThunk"),
    CommandDef("make_sig", "make_sig <ea|name> [max_len=64]", "Generate minimal unique IDA wildcard signature pattern", "components.commands.make_sig", "makeSigThunk"),
    CommandDef("get_bytes", "get_bytes <ea|name> [size=32]", "Read raw bytes and hex dump from address", "components.commands.bytes", "getBytesThunk"),
    CommandDef("patch_bytes", "patch_bytes <ea|name> <bytes>", "Apply safe patch bytes to address in IDA database", "components.commands.bytes", "patchBytesThunk"),
    CommandDef("callers", "callers <ea|name> [limit=100] [user_only=1]", "Retrieve callers of function with runtime thunk filtering", "components.commands.call_graph", "callersThunk"),
    CommandDef("callees", "callees <ea|name> [limit=100] [user_only=1]", "Retrieve callees called by function with runtime thunk filtering", "components.commands.call_graph", "calleesThunk"),
    CommandDef("cfg", "cfg <ea|name> [format=json|mermaid]", "Extract basic block control flow graph and Mermaid diagram", "components.commands.cfg", "cfgThunk"),
    CommandDef("diary", "diary", "View active binary dumps registered in the AI diary", "components.commands.diary", "diaryThunk"),
    CommandDef("logs", "logs [count=100]", "Retrieve recent plugin and server log entries", "components.commands.logs", "logsThunk"),
    CommandDef("reload", "reload", "Hot reload all plugin components without restarting IDA", "components.commands.reload", "reloadThunk"),
    CommandDef("func_hash", "func_hash <ea|name>", "Compute 70-char TLSH fuzzy similarity digest for function bytes", "components.commands.func_hash", "funcHashThunk"),
    CommandDef("func_diff", "func_diff <ea1|hash1> <ea2|hash2>", "Compare two functions or TLSH digests to compute fuzzy distance and patch similarity", "components.commands.func_hash", "funcDiffThunk"),
    CommandDef("hash_all", "hash_all [output=path.json] [min_size=0] [limit=0]", "Compute TLSH hash for all functions and export corpus to JSON file", "components.commands.corpus", "hashAllThunk"),
    CommandDef("match_funcs", "match_funcs <db=path.json> [max_distance=100] [limit=50]", "Match local functions against a TLSH hash corpus database by nearest-neighbor distance", "components.commands.corpus", "matchFuncsThunk"),
    CommandDef("apply_rtti", "apply_rtti <class_name> [limit=10] [methods=32] [dry_run=1]", "Auto-rename vtable globals and unnamed virtual methods using RTTI class discovery", "components.commands.apply_rtti", "applyRttiThunk"),
    CommandDef("help", "help", "List all available certiBridge commands and their usages", "components.commands.help", "helpThunk"),
]

def getCommandsByName() -> Dict[str, CommandDef]:
    return {cmd.name: cmd for cmd in COMMAND_REGISTRY}

COMMANDS_BY_NAME: Dict[str, CommandDef] = getCommandsByName()

def executeCommand(commandTarget: str, /, plugin=None, params: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
    cmdMap = getCommandsByName()
    cmd = cmdMap.get(commandTarget)
    if not cmd:
        return {"success": False, "error": f"unknown command: {commandTarget}", "available": list(cmdMap.keys())}

    mergedParams: Dict[str, Any] = dict(params) if isinstance(params, dict) else {}
    if kwargs:
        mergedParams.update(kwargs)

    return safeExecute(commandTarget, cmd.thunk, plugin, mergedParams)
