from prometheus_client import Counter, Gauge, Histogram, REGISTRY
import logging

# --- Helpers para crear o reutilizar métricas ---


def get_or_create_counter(name, description, labels=None):
    if name in REGISTRY._names_to_collectors:
        return REGISTRY._names_to_collectors[name]
    return Counter(name, description, labels) if labels else Counter(name, description)


def get_or_create_gauge(name, description, labels=None):
    if name in REGISTRY._names_to_collectors:
        return REGISTRY._names_to_collectors[name]
    return Gauge(name, description, labels) if labels else Gauge(name, description)


def get_or_create_histogram(name, description, labels=None):
    if name in REGISTRY._names_to_collectors:
        return REGISTRY._names_to_collectors[name]
    return Histogram(name, description, labels) if labels else Histogram(name, description)


# --- Métricas con los nombres que la app espera ---
# Request metrics
REQUEST_COUNTER = get_or_create_counter(
    "playbook_requests_total",
    "Total number of requests",
    labels=["path", "method", "status"]
)

REQUEST_LATENCY = get_or_create_histogram(
    "playbook_request_latency_seconds",
    "Request latency in seconds",
    labels=["path"]
)

# Outbound retries / circuit breaker
OUTBOUND_RETRIES = get_or_create_counter(
    "playbook_outbound_retries_total",
    "Total outbound retries",
    labels=["target"]
)

CB_STATE = get_or_create_gauge(
    "playbook_circuit_breaker_state",
    "Circuit breaker state 0=closed 1=open"
)

# También exporto los nombres alternativos que añadí antes
playbook_outbound_retries_total = OUTBOUND_RETRIES
playbook_circuit_breaker_state = CB_STATE

# --- Logging helpers (simples) ---
logger = logging.getLogger("playbook_service")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def log_info(msg, **kwargs):
    logger.info(msg + (" | " + str(kwargs) if kwargs else ""))


def log_warning(msg, **kwargs):
    logger.warning(msg + (" | " + str(kwargs) if kwargs else ""))


def log_error(msg, **kwargs):
    logger.error(msg + (" | " + str(kwargs) if kwargs else ""))
