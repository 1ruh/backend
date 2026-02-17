import json
import os
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib import parse, request, error


LEAKCHECK_API_KEY = "4344cd645b6e6cc2559c1a92017d9bfa12e4e4b1"


class LeakcheckHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = parse.urlparse(self.path)
        if parsed.path != "/leakcheck":
            self._send_json(404, {"success": False, "error": "not_found"})
            return

        params = parse.parse_qs(parsed.query)
        query = (params.get("q") or [""])[0].strip()
        q_type = (params.get("type") or ["username"])[0].strip() or "username"

        if not query:
            self._send_json(400, {"success": False, "error": "missing_query"})
            return

        url = f"https://leakcheck.io/api/v2/query/{query}?type={q_type}"

        req = request.Request(
            url,
            headers={
                "Accept": "application/json",
                "X-API-Key": LEAKCHECK_API_KEY,
                "User-Agent": "python-requests/2.x exi-backend",
            },
            method="GET",
        )

        try:
            resp = request.urlopen(req, timeout=15)
            body_bytes = resp.read()
            status = resp.getcode() or 200
        except error.HTTPError as e:
            body_bytes = e.read()
            status = e.code or 500
        except Exception as e:
            self._send_json(
                502,
                {
                    "success": False,
                    "error": "backend_error",
                    "detail": str(e),
                },
            )
            return

        body_text = body_bytes.decode("utf-8", errors="replace")
        try:
            data = json.loads(body_text)
        except Exception:
            self._send_json(
                status,
                {
                    "success": False,
                    "error": "upstream_non_json",
                    "status": status,
                    "body": body_text[:400],
                },
            )
            return

        self._send_json(status, data)


def run(host=None, port=None):
    if host is None:
        host = os.environ.get("HOST", "0.0.0.0")
    if port is None:
        port = int(os.environ.get("PORT", "8080"))
    server = HTTPServer((host, port), LeakcheckHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"EXI backend listening on http://{host}:{port}")
    try:
        thread.join()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    run()
