from typing import Any, Dict
from utils.logger import getRecentLogs

def logsThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    count = int(params.get("count", 100)) if str(params.get("count", "")).isdigit() else 100
    logs = getRecentLogs(count)
    return {"success": True, "logs": logs}
