"""
Attack pattern definitions for the Security Automation Suite.
These regex patterns are used by the log analyzer to detect common web attacks.
"""

attack_patterns = {
    # SQL Injection
    "SQL Injection": r"(union(\s+all)?\s+select|select\s+\*|insert\s+into|drop\s+table|or\s+1=1|--|#)",

    # Cross-Site Scripting (XSS)
    "XSS": r"(<script>|</script>|javascript:|onerror=|onload=)",


    # Command Injection
    "Command Injection": r"(;|\||&&|\$\(|`|\bcat\b|\bwget\b|\bcurl\b)",

    # Brute Force
    "Brute Force": r"(failed\s+login|authentication\s+failed|invalid\s+password)",

    # Bots / Scanners
    "Suspicious User-Agent": r"(sqlmap|nmap|nikto|curl|wget|dirbuster|fuzzer)",


}
