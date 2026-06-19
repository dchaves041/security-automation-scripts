from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import time
from store_sqlite import init_db, get_ticket, save_ticket

init_db()


def enrich_alert(alert):
    enriched = alert.copy()
    enriched["enrichment"] = {
        "ip_reputation": "malicious" if "suspicious" in alert.get("title", "").lower() else "unknown",
        "user_last_login": "2026-05-01T12:00:00Z"
    }
    return enriched


def create_ticket(enriched):
    ticket = {
        "ticket_id": f"TICKET-{int(time.time())}",
        "summary": f"Auto ticket for {enriched.get('user', 'unknown')} - {enriched.get('title')}"
    }
    print("Created ticket:", ticket)
    return ticket


def get_or_create_ticket(alert_id, enriched):
    existing = get_ticket(alert_id)
    if existing:
        print(f"Idempotency hit for alert_id={alert_id}")
        return existing
    ticket = create_ticket(enriched)
    save_ticket(alert_id, ticket)
    return ticket


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/ingest":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")
            return

        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8')

        try:
            alert = json.loads(body)
        except:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"invalid json")
            return

        enriched = enrich_alert(alert)

        if enriched["enrichment"]["ip_reputation"] == "malicious":
            result = {"action": "blocked_ip", "details": {
                "ip": alert.get("ip", "n/a")}}
        else:
            alert_id = alert.get("id") or alert.get("title")
            ticket = get_or_create_ticket(alert_id, enriched)
            result = {"action": "ticket_created", "ticket": ticket}

        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps(
            {"status": "ok", "result": result}).encode())


def run(host="127.0.0.1", port=8002):
    server = HTTPServer((host, port), Handler)
    print(f"Playbook service running on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
