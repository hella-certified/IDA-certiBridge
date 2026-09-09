import os
import datetime
import ida_loader

_recentLogs = []

def bridgeLog(msg: str):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{ts}] [certiBridge] {msg}"
    print(formatted)
    _recentLogs.append(formatted)
    if len(_recentLogs) > 200:
        _recentLogs.pop(0)
    try:
        logPaths = [os.path.join(os.getcwd(), "bridge.log")]
        idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if idb:
            logPaths.insert(0, os.path.join(os.path.dirname(idb), "bridge.log"))
        for lp in logPaths:
            with open(lp, "a", encoding="utf-8") as f:
                f.write(formatted + "\n")
            break
    except Exception:
        pass

def getRecentLogs(count: int = 100) -> str:
    return "\n".join(_recentLogs[-count:] if count > 0 else _recentLogs)
