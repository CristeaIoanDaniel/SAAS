import json
import ssl
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import security
MAX_BODY = 1_000_000
MAX_SKEW = 60
class Handler(BaseHTTPRequestHandler):
    def _reply(self, code):
        self.send_response(code)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0 or length > MAX_BODY:
            return self._reply(413)
        body = self.rfile.read(length)
        ts = self.headers.get("X-IDS-Timestamp", "")
        sig = self.headers.get("X-IDS-Signature", "")
        if not ts.isdigit() or abs(time.time() - int(ts)) > MAX_SKEW:
            return self._reply(401)
        if not security.verify(ts.encode() + b"." + body, sig):
            return self._reply(401)
        with open("received_alerts.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(json.loads(body)) + "\n")
        print("[collector] verified alert:", json.loads(body).get("type"), json.loads(body).get("src", ""))
        self._reply(200)

    def log_message(self, *args):
        pass
if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8443), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain("cert.pem", "key.pem")
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print("[collector] listening on https://127.0.0.1:8443/alert")
    server.serve_forever()