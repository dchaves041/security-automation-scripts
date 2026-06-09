import os
from store_sqlite import init_db, get_ticket
from simple_playbook import enrich_alert, get_or_create_ticket

DB_FILE = os.path.join(os.path.dirname(__file__), "playbook_store.db")


def setup_function():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    init_db()


def test_idempotent_ticket_creation():
    alert = {"id": "test-123", "title": "Normal login",
             "user": "alice@example.com", "ip": "1.2.3.4"}
    enriched = enrich_alert(alert)

    t1 = get_or_create_ticket(alert["id"], enriched)
    t2 = get_or_create_ticket(alert["id"], enriched)

    assert t1["ticket_id"] == t2["ticket_id"]
    stored = get_ticket(alert["id"])
    assert stored["ticket_id"] == t1["ticket_id"]
