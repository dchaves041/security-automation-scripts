import requests

# ---------------------------------------------
# Function: check_ip_reputation
# Description: Sends a request to VirusTotal API
#              to retrieve reputation information
#              about a specific IP address.
# ---------------------------------------------


def check_ip_reputation(ip_address, api_key):
    # VirusTotal endpoint for IP reputation
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

    # Headers required by VirusTotal API
    headers = {
        "x-apikey": api_key
    }

    # Send GET request to VirusTotal
    response = requests.get(url, headers=headers)

    # If the request fails, return error
    if response.status_code != 200:
        return f"Error: API returned status code {response.status_code}"

    # Convert response to JSON
    data = response.json()

    # Extract useful information
    attributes = data.get("data", {}).get("attributes", {})
    last_analysis_stats = attributes.get("last_analysis_stats", {})

    # Return formatted result
    return {
        "ip": ip_address,
        "malicious": last_analysis_stats.get("malicious", 0),
        "suspicious": last_analysis_stats.get("suspicious", 0),
        "undetected": last_analysis_stats.get("undetected", 0),
        "harmless": last_analysis_stats.get("harmless", 0)
    }


# ---------------------------------------------
# Main execution block
# ---------------------------------------------
if __name__ == "__main__":
    # Replace with your own VirusTotal API key
    API_KEY = "YOUR_API_KEY_HERE"

    # IP address to analyze
    ip_to_check = "8.8.8.8"

    # Call the function
    result = check_ip_reputation(ip_to_check, API_KEY)

    # Print the result
    print("VirusTotal IP Reputation Result:")
    print(result)
