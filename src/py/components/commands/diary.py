import os
import json
from typing import Any, Dict
from utils.dumpInfo import getDumpInfo, findDiaryLocations, writeFallbackDiary

def diaryThunk(plugin, params: Dict[str, Any]) -> Dict[str, Any]:
    port = getattr(plugin, "boundPort", 0) if plugin else 0
    info = getDumpInfo(port)
    if info.get("filename") and info.get("filename") != "None":
        writeFallbackDiary(info, "register")

    locations = findDiaryLocations(info)
    dumps = {}
    for loc in locations:
        jsonPath = os.path.join(loc, "diary.json")
        if os.path.isfile(jsonPath):
            try:
                with open(jsonPath, "r", encoding="utf-8") as f:
                    dumps = json.load(f)
                    break
            except Exception:
                pass
    return {"success": True, "dumps": dumps}
