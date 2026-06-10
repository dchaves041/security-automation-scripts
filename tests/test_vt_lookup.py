import respx, httpx
from threat_intel.vt_ip_checker import lookup_ip

@respx.mock
def test_lookup_ip():
    ip = "8.8.8.8"
    respx.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}").mock(
        return_value=httpx.Response(200, json={"data": {"id": ip}})
    )
    resp = lookup_ip(ip)
    assert resp["data"]["id"] == ip
