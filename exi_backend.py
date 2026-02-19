import json
import os
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib import parse, request, error


LEAKCHECK_API_KEY = "4344cd645b6e6cc2559c1a92017d9bfa12e4e4b1"
SNUSBASE_API_KEY_SECONDARY = "sby0b7crta98od7efbb8zr70788n2h"
SNUSBASE_API_URL = "https://api.snusbase.com/data/search"

STEALER_KEYWORDS = [
    "stealer", "stealerlogs", "logs", "logz", 
    "grabber", "clipper", "redline", "raccoon", "brute-logs"
]

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
        
        if parsed.path == "/leakcheck":
            self.handle_leakcheck(parsed)
        elif parsed.path == "/snusbase":
            self.handle_snusbase(parsed)
        elif parsed.path == "/search":
            self.handle_combined(parsed)
        else:
            self._send_json(404, {"success": False, "error": "not_found"})

    def is_stealer(self, source_name):
        if not source_name: return False
        source_name = source_name.lower()
        return any(k in source_name for k in STEALER_KEYWORDS)

    def get_leakcheck_data(self, query, q_type):
        # Do not use LeakCheck for password searches
        if q_type == "password":
            return []

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
            resp = request.urlopen(req, timeout=10)
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            results = data.get("result", []) if data.get("success") else []
            
            # Filter for stealer logs in LeakCheck results
            filtered = []
            for r in results:
                # Check source names in LeakCheck (usually list of sources)
                sources = r.get("sources", [])
                # If sources is a list of strings
                is_stealer_log = False
                for src in sources:
                    if self.is_stealer(src):
                        is_stealer_log = True
                        break
                
                # Also check 'source' object if structure differs
                if not is_stealer_log and "source" in r:
                    src_obj = r["source"]
                    if isinstance(src_obj, dict) and self.is_stealer(src_obj.get("name")):
                        is_stealer_log = True

                if is_stealer_log:
                    # Map origin/source to 'url' for UI compatibility
                    # Try to find specific origin URL/domain first
                    origin = r.get("url") or r.get("domain") or r.get("site") or ""
                    
                    if not origin:
                        # Fallback to source name
                        if "source" in r and isinstance(r["source"], dict):
                            origin = r["source"].get("name", "")
                        elif sources:
                             # Use the first source name found if available
                            origin = sources[0] if sources else ""
                    
                    r["url"] = origin
                    filtered.append(r)
            
            return filtered
        except Exception as e:
            print(f"LeakCheck error: {e}")
            return []

    def get_snusbase_data(self, query, q_type):
        sb_type = "email" if "@" in query else "username"
        if q_type == "email": sb_type = "email"
        elif q_type == "username": sb_type = "username"
        elif q_type == "password": sb_type = "password"

        body = {
            "terms": [query],
            "types": [sb_type],
            "wildcard": False
        }
        
        req = request.Request(
            SNUSBASE_API_URL,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Auth": SNUSBASE_API_KEY_SECONDARY,
                "User-Agent": "python-requests/2.x exi-backend",
            },
            method="POST",
        )

        try:
            resp = request.urlopen(req, timeout=10)
            sb_data = json.loads(resp.read().decode("utf-8", errors="replace"))
            
            results = []
            if "results" in sb_data and isinstance(sb_data["results"], dict):
                for term, entries in sb_data["results"].items():
                    # Check if database name (term) indicates a stealer log
                    if not self.is_stealer(term):
                        continue

                    for entry in entries:
                        # Extract URL/Origin if available
                        origin_url = entry.get("url") or entry.get("site") or entry.get("origin") or entry.get("domain") or entry.get("_domain") or ""
                        
                        results.append({
                            "line": f"{entry.get('username','')}:{entry.get('password','')}",
                            "source": {"name": term}, # Use the database name as source
                            "username": entry.get("username", ""),
                            "email": entry.get("email", ""),
                            "password": entry.get("password", ""),
                            "url": origin_url # Include the URL
                        })
            return results
        except Exception as e:
            print(f"Snusbase error: {e}")
            return []

    def handle_combined(self, parsed):
        params = parse.parse_qs(parsed.query)
        query = (params.get("q") or [""])[0].strip()
        q_type = (params.get("type") or ["username"])[0].strip() or "username"

        if not query:
            self._send_json(400, {"success": False, "error": "missing_query"})
            return

        # Fetch from both in parallel threads to be faster, or sequential for simplicity
        # Sequential is safer for now to avoid complexity
        lc_results = self.get_leakcheck_data(query, q_type)
        sb_results = self.get_snusbase_data(query, q_type)
        
        combined = lc_results + sb_results
        
        self._send_json(200, {
            "success": True,
            "result": combined,
            "meta": {
                "leakcheck_count": len(lc_results),
                "snusbase_count": len(sb_results)
            }
        })

    def handle_leakcheck(self, parsed):
        params = parse.parse_qs(parsed.query)
        query = (params.get("q") or [""])[0].strip()
        q_type = (params.get("type") or ["username"])[0].strip() or "username"

        if not query:
            self._send_json(400, {"success": False, "error": "missing_query"})
            return

        results = self.get_leakcheck_data(query, q_type)
        self._send_json(200, {"success": True, "result": results})

    def handle_snusbase(self, parsed):
        params = parse.parse_qs(parsed.query)
        query = (params.get("q") or [""])[0].strip()
        q_type = (params.get("type") or ["username"])[0].strip() or "username"

        if not query:
            self._send_json(400, {"success": False, "error": "missing_query"})
            return

        results = self.get_snusbase_data(query, q_type)
        self._send_json(200, {"success": True, "result": results})


def run(host=None, port=None):
    if host is None:
        host = os.environ.get("HOST", "0.0.0.0")
    if port is None:
        port = int(os.environ.get("PORT", "5000"))
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
