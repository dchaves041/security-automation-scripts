import time
import httpx
import pytest
from fastapi import status
from multiprocessing import Process
import uvicorn

APP_MODULE = "app:app"
BASE_URL = "http://127.0.0.1:9002"

def run_server():
    uvicorn.run(APP_MODULE, host="127.0.0.1", port=9002, log_level="info")

@pytest.fixture(scope="module")
def server():
    p = Process(target=run_server, daemon=True)
    p.start()
    time.sleep(1.5)
    yield
    p.terminate()
    p.join()

def test_idempotency_creates_single_ticket(server):
    payload = {"id": "test-idempotency-1", "title": "Idempotency test", "user": "tester", "ip": "1.2.3.4"}
    with httpx.Client(timeout=10.0) as c:
        r1 = c.post(f"{BASE_URL}/ingest", json=payload)
        assert r1.status_code == status.HTTP_200_OK
        body1 = r1.json()
        ticket1 = body1["result"].get("ticket") or {}

        r2 = c.post(f"{BASE_URL}/ingest", json=payload)
        assert r2.status_code == status.HTTP_200_OK
        body2 = r2.json()
        ticket2 = body2["result"].get("ticket") or {}

        assert ticket1.get("ticket_id") == ticket2.get("ticket_id")

def test_circuit_breaker_and_retries(server):
    payload = {"id": "cb-test-1", "title": "CB test", "user": "tester", "ip": "1.2.3.4"}
    with httpx.Client(timeout=10.0) as c:
        for i in range(4):
            r = c.post(f"{BASE_URL}/ingest", json=payload)
            assert r.status_code == status.HTTP_200_OK

        m = c.get(f"{BASE_URL}/metrics").text
        assert "playbook_outbound_retries_total" in m
        assert "playbook_circuit_breaker_state" in m
