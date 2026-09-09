import ctypes
import os

tlshLib = None

def initTlsh() -> bool:
    global tlshLib
    if tlshLib is not None:
        return True

    searchDirs = [
        os.path.dirname(os.path.abspath(__file__)),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "build", "Release")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "build", "Release")),
    ]

    dllPath = None
    for candidate in searchDirs:
        p = os.path.join(candidate, "certibridge_tlsh.dll")
        if os.path.isfile(p):
            dllPath = p
            break

    if not dllPath:
        return False

    try:
        lib = ctypes.CDLL(dllPath)
        lib.tlshHashBytes.argtypes = [ctypes.c_char_p, ctypes.c_uint, ctypes.c_char_p, ctypes.c_uint]
        lib.tlshHashBytes.restype = ctypes.c_int
        lib.tlshCompare.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.tlshCompare.restype = ctypes.c_int
        tlshLib = lib
        return True
    except Exception:
        return False

def hashBuffer(data: bytes) -> str:
    if not initTlsh():
        return ""

    buf = ctypes.create_string_buffer(128)
    res = tlshLib.tlshHashBytes(data, len(data), buf, 128)
    if res != 0:
        return ""

    return buf.value.decode("utf-8")

def compareHashes(hash1: str, hash2: str) -> int:
    if not initTlsh():
        return -1

    h1 = hash1.strip().encode("utf-8")
    h2 = hash2.strip().encode("utf-8")
    return int(tlshLib.tlshCompare(h1, h2))
