# examples/playbook_service/test_app.py
import os
from fastapi.testclient import TestClient
from store_sqlite import init_db, get_ticket
from app import app, enrich_alert

DB_FILE = os.path.join(os.path.dirname(__file__), "playbook_store.db")


def setup_function():
    # limpiar DB antes de cada test
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    init_db()


def test_ingest_idempotency():
    client = TestClient(app)
    payload = {
        "id": "test-456",
        "title": "Normal login",
        "description": "Test",
        "user": "alice@example.com",
        "ip": "1.2.3.4"
    }

    r1 = client.post("/ingest", json=payload)
    assert r1.status_code == 200
    body1 = r1.json()
    assert body1["status"] == "ok"
    ticket1 = body1["result"]["ticket"]
    assert "ticket_id" in ticket1

    r2 = client.post("/ingest", json=payload)
    assert r2.status_code == 200
    body2 = r2.json()
    ticket2 = body2["result"]["ticket"]

    assert ticket1["ticket_id"] == ticket2["ticket_id"]
    stored = get_ticket(payload["id"])
    assert stored["ticket_id"] == ticket1["ticket_id"]
