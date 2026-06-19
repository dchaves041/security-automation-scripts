# This file defines the different reconnaissance patterns
# that the simulator can generate. These patterns represent
# typical behaviors seen during reconnaissance activities
# performed by autonomous agents or attackers.

RECON_PATTERNS = [
    {
        "type": "dns_lookup",
        "description": "Agent performing DNS reconnaissance",
        "fields": ["domain", "resolver", "timestamp"]
    },
    {
        "type": "port_probe",
        "description": "Low-noise port probing activity",
        "fields": ["ip", "port", "protocol", "timestamp"]
    },
    {
        "type": "cloud_api_enum",
        "description": "Cloud API enumeration using legitimate calls",
        "fields": ["api_call", "resource", "timestamp"]
    },
    {
        "type": "identity_probe",
        "description": "Identity-based reconnaissance (role probing)",
        "fields": ["role", "action", "timestamp"]
    }
]
