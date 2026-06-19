# examples/demo_playbook/mock_siem_simple.py
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import requests
import os

PLAYBOOK_URL = os.getenv("PLAYBOOK_SERVICE_URL",
                         "http://127.0.0.1:8002/ingest")


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8')
        try:
            payload = json.loads(body)
        except Exception:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"invalid json")
            return

        print("Mock SIEM received alert:", json.dumps(payload))
        try:
            resp = requests.post(PLAYBOOK_URL, json=payload, timeout=5)
            resp_json = resp.json() if resp.content else {
                "status": "no-content"}
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(
                {"forwarded": True, "playbook_response": resp_json}).encode())
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())


def run(host="127.0.0.1", port=8001):
    server = HTTPServer((host, port), Handler)
    print(f"Mock SIEM running on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down mock SIEM")
        server.server_close()


if __name__ == "__main__":
    run()
