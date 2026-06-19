import json
from typing import Dict, Any, Optional
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from time import monotonic
import enum

from .observability import OUTBOUND_RETRIES, CB_STATE, log_warning, log_info

class CBState(enum.IntEnum):
    CLOSED = 0
    OPEN = 1
    HALF_OPEN = 2

class SimpleCircuitBreaker:
    def __init__(self, name: str, fail_max: int = 3, reset_timeout: int = 30):
        self.name = name
        self.fail_max = fail_max
        self.reset_timeout = reset_timeout
        self.fail_count = 0
        self.state = CBState.CLOSED
        self.open_until = 0.0

    def _now(self) -> float:
        return monotonic()

    def record_success(self):
        self.fail_count = 0
        if self.state != CBState.CLOSED:
            self.state = CBState.CLOSED
            CB_STATE.labels(target=self.name).set(float(CBState.CLOSED))
            log_info("cb_closed", target=self.name)

    def record_failure(self):
        self.fail_count += 1
        if self.fail_count >= self.fail_max and self.state != CBState.OPEN:
            self.state = CBState.OPEN
            self.open_until = self._now() + self.reset_timeout
            CB_STATE.labels(target=self.name).set(float(CBState.OPEN))
            log_warning("cb_open", target=self.name, fail_count=self.fail_count)

    def allow_request(self) -> bool:
        now = self._now()
        if self.state == CBState.CLOSED:
            return True
        if self.state == CBState.OPEN:
            if now >= self.open_until:
                self.state = CBState.HALF_OPEN
                CB_STATE.labels(target=self.name).set(float(CBState.HALF_OPEN))
                log_info("cb_half_open", target=self.name)
                return True
            return False
        if self.state == CBState.HALF_OPEN:
            return True
        return True

_breakers = {
    "test_unreachable": SimpleCircuitBreaker(name="test_unreachable", fail_max=3, reset_timeout=30)
}

def get_breaker(target: str) -> Optional[SimpleCircuitBreaker]:
    return _breakers.get(target)

async_client: Optional[httpx.AsyncClient] = None

def set_async_client(client: httpx.AsyncClient):
    global async_client
    async_client = client

@retry(stop=stop_after_attempt(4),
       wait=wait_exponential(multiplier=1, min=1, max=10),
       retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)))
async def post_with_retry(url: str, payload: Dict[str, Any], target_label: str = "external"):
    cb = get_breaker(target_label)
    if cb and not cb.allow_request():
        OUTBOUND_RETRIES.labels(target=target_label).inc()
        log_warning("cb_reject", target=target_label)
        raise Exception(f"circuit open for target {target_label}")

    try:
        if async_client:
            resp = await async_client.post(url, json=payload)
        else:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, json=payload)
        resp.raise_for_status()
        if cb:
            cb.record_success()
        return resp.json() if resp.content else {}
    except Exception as e:
        OUTBOUND_RETRIES.labels(target=target_label).inc()
        log_warning("outbound_failed", target=target_label, error=str(e))
        if cb:
            cb.record_failure()
        raise
