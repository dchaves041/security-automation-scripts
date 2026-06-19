from prometheus_client import Counter, Gauge, REGISTRY

def get_or_create_counter(name, description, labels=None):
    if name in REGISTRY._names_to_collectors:
        return REGISTRY._names_to_collectors[name]
    if labels:
        return Counter(name, description, labels)
    return Counter(name, description)

def get_or_create_gauge(name, description, labels=None):
    if name in REGISTRY._names_to_collectors:
        return REGISTRY._names_to_collectors[name]
    if labels:
        return Gauge(name, description, labels)
    return Gauge(name, description)

# Define the metrics used by tests
playbook_outbound_retries_total = get_or_create_counter(
    "playbook_outbound_retries_total",
    "Total outbound retries",
    labels=["target"]
)

playbook_circuit_breaker_state = get_or_create_gauge(
    "playbook_circuit_breaker_state",
    "Circuit breaker state 0=closed 1=open"
)
print("observability patch created")
