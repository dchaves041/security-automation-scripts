import requests

# ---------------------------------------------
# Function: check_ip_reputation
# Description: Retrieves reputation information
#              about a specific IP address.
# ---------------------------------------------


def check_ip_reputation(ip_address, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return f"Error: API returned status code {response.status_code}"

    data = response.json()
    attributes = data.get("data", {}).get("attributes", {})

    # Extract useful information
    last_analysis_stats = attributes.get("last_analysis_stats", {})
    country = attributes.get("country", "N/A")
    asn = attributes.get("asn", "N/A")
    whois = attributes.get("whois", "No WHOIS data available")

    return {
        "ip": ip_address,
        "country": country,
        "asn": asn,
        "whois": whois[:300] + "...",
        "malicious": last_analysis_stats.get("malicious", 0),
        "suspicious": last_analysis_stats.get("suspicious", 0),
        "undetected": last_analysis_stats.get("undetected", 0),
        "harmless": last_analysis_stats.get("harmless", 0)
    }


# ---------------------------------------------
# Function: analyze_domain
# Description: Retrieves reputation information
#              about a specific domain.
# ---------------------------------------------
def analyze_domain(domain, api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return f"Error: API returned status code {response.status_code}"

    data = response.json()
    attributes = data.get("data", {}).get("attributes", {})

    # Extract useful information
    reputation = attributes.get("reputation", "N/A")
    country = attributes.get("country", "N/A")
    asn = attributes.get("asn", "N/A")
    whois = attributes.get("whois", "No WHOIS data available")
    last_analysis_stats = attributes.get("last_analysis_stats", {})

    return {
        "domain": domain,
        "reputation": reputation,
        "country": country,
        "asn": asn,
        "whois": whois[:300] + "...",
        "malicious": last_analysis_stats.get("malicious", 0),
        "suspicious": last_analysis_stats.get("suspicious", 0),
        "undetected": last_analysis_stats.get("undetected", 0),
        "harmless": last_analysis_stats.get("harmless", 0)
    }


# ---------------------------------------------
# Main execution block
# ---------------------------------------------
if __name__ == "__main__":
    API_KEY = "YOUR_API_KEY_HERE"

    print("Choose an option:")
    print("1 - Analyze IP")
    print("2 - Analyze Domain")

    choice = input("Option: ")

    if choice == "1":
        ip_to_check = input("Enter IP: ")
        result = check_ip_reputation(ip_to_check, API_KEY)
        print("\n=== IP Analysis Result ===")
        print(result)

    elif choice == "2":
        domain_to_check = input("Enter domain: ")
        result = analyze_domain(domain_to_check, API_KEY)
        print("\n=== Domain Analysis Result ===")
        print(result)

    else:
        print("Invalid option.")
