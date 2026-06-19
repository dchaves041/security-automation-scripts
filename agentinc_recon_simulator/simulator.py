# This module generates synthetic reconnaissance events.
# It does NOT perform any offensive actions. It only simulates
# realistic patterns that an agentic system might produce.

import random
from datetime import datetime
from patterns import RECON_PATTERNS


class ReconSimulator:

    # Generates a single reconnaissance event based on a random pattern
    def generate_event(self):
        pattern = random.choice(RECON_PATTERNS)
        timestamp = datetime.utcnow().isoformat()

        # Simulated DNS reconnaissance event
        if pattern["type"] == "dns_lookup":
            return {
                "type": pattern["type"],
                "domain": random.choice(["internal.api", "prod.db", "auth.service"]),
                "resolver": "8.8.8.8",
                "timestamp": timestamp
            }

        # Simulated low-noise port probing event
        if pattern["type"] == "port_probe":
            return {
                "type": pattern["type"],
                "ip": "10.0.0." + str(random.randint(1, 50)),
                "port": random.choice([22, 80, 443, 3306]),
                "protocol": "tcp",
                "timestamp": timestamp
            }

        # Simulated cloud API enumeration event
        if pattern["type"] == "cloud_api_enum":
            return {
                "type": pattern["type"],
                "api_call": random.choice(["ListRoles", "GetPolicy", "ListBuckets"]),
                "resource": random.choice(["IAM", "S3", "EC2"]),
                "timestamp": timestamp
            }

        # Simulated identity probing event
        if pattern["type"] == "identity_probe":
            return {
                "type": pattern["type"],
                "role": random.choice(["DevRole", "AppRole", "LambdaRole"]),
                "action": random.choice(["AssumeRole", "GetCallerIdentity"]),
                "timestamp": timestamp
            }

    # Generates a batch of events for testing or log simulation
    def generate_batch(self, count=10):
        return [self.generate_event() for _ in range(count)]
