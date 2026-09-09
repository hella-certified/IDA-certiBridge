import socket
from socketserver import ThreadingMixIn
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import ida_auto
import components.commands
from components.commands import executeCommand, COMMANDS_BY_NAME
from utils.logger import bridgeLog
from utils.safety import safeCall, safeCastInt, safeCastStr, safeJsonLoads, safeJsonDumps

HEAVY_COMMANDS = {
    "decompile", "strings", "search_strings", "find_vtables", "find_pattern",
    "make_sig", "cfg", "callers", "callees", "list_funcs", "match_xrefs",
    "find_class", "class", "hash_all", "match_funcs", "apply_rtti",
}

class CertiBridgeServer(HTTPServer):
    allow_reuse_address = True

    def get_request(self):
        sock, addr = super().get_request()
        safeCall(sock.settimeout, 300.0)
        return sock, addr

    def handle_error(self, request, client_address):
        safeCall(bridgeLog, f"connection closed by {client_address}")

class BridgeRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def handle(self):
        try:
            super().handle()
        except Exception as e:
            safeCall(bridgeLog, f"request error: {safeCastStr(e)}")

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionResetError, BrokenPipeError, TimeoutError):
            pass
        except Exception as e:
            safeCall(bridgeLog, f"http processing error: {safeCastStr(e)}")

    def do_GET(self):
        parsed = urlparse(self.path)
        params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}
        self.dispatchRequest(parsed.path, params)

    def do_POST(self):
        parsed = urlparse(self.path)
        params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}

        contentLen = safeCastInt(self.headers.get("Content-Length", 0))
        if contentLen > 0:
            body = self.rfile.read(contentLen).decode("utf-8", errors="replace")
            jsonBody = safeJsonLoads(body)
            if isinstance(jsonBody, dict):
                params.update(jsonBody)
            else:
                params["body"] = body

        self.dispatchRequest(parsed.path, params)

    def dispatchRequest(self, path: str, params: dict):
        try:
            plugin = getattr(self.server, "plugin", None)
            cleanPath = path.rstrip("/")

            cmdName = cleanPath[5:] if cleanPath.startswith("/api/") else cleanPath.lstrip("/")
            if cmdName in ("commands", "help"):
                cmdName = "help"

            cmdMap = components.commands.getCommandsByName()
            if cmdName not in cmdMap:
                self.sendJsonResponse({"error": "endpoint not found", "cmd": cmdName, "available": list(cmdMap.keys())}, status=404)
                return

            if cmdName in HEAVY_COMMANDS and not ida_auto.auto_is_ok():
                payload = {
                    "success": False,
                    "error": "auto-analysis still running, retry after analysis completes",
                    "analyzing": True,
                    "retry_after_ms": 2000,
                }
                try:
                    data = safeJsonDumps(payload).encode("utf-8")
                    self.send_response(503)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Retry-After", "2")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(data)
                except Exception:
                    pass
                return

            res = executeCommand(cmdName, plugin=plugin, params=params)
            isRaw = params.get("raw") == "1" or params.get("plain") == "1" or params.get("format") == "raw"

            if cmdName == "decompile" and isRaw:
                if res.get("success"):
                    self.sendRawText(safeCastStr(res.get("code", "")))
                else:
                    self.sendRawText(f"// error: {safeCastStr(res.get('error'))}", status=400)
                return

            if cmdName == "logs" and (isRaw or path == "/api/logs"):
                if "logs" in res and isRaw:
                    self.sendRawText(safeCastStr(res["logs"]))
                    return

            if cmdName == "get_struct" and isRaw:
                if res.get("success"):
                    self.sendRawText(safeCastStr(res.get("c_decl", "")))
                else:
                    self.sendRawText(f"// error: {safeCastStr(res.get('error'))}", status=400)
                return

            self.sendJsonResponse(res, status=200)
        except Exception as e:
            self.sendJsonResponse({"success": False, "error": f"server error: {safeCastStr(e)}"}, status=500)

    def sendJsonResponse(self, payload: dict, status: int = 200):
        try:
            data = safeJsonDumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            pass

    def sendRawText(self, text: str, status: int = 200):
        try:
            data = safeCastStr(text).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            pass
