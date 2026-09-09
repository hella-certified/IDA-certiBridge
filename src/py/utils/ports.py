import socket

DEFAULT_BASE_PORT = 13381

def isPortInUse(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.05)
        if s.connect_ex(("127.0.0.1", port)) == 0:
            return True

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            except OSError:
                pass
        try:
            s.bind(("127.0.0.1", port))
            return False
        except OSError:
            return True

def findFreePort(startPort: int = DEFAULT_BASE_PORT, maxPort: int = 13399) -> int:
    for p in range(startPort, maxPort + 1):
        if not isPortInUse(p):
            return p
    return startPort
