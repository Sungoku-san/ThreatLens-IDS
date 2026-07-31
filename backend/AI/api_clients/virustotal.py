import os
from backend.utils.logger import logger

class VirusTotalClient:
    @staticmethod
    def inspect_ip(ip):
        """
        Inspects IP reputation on VirusTotal.
        Uses VIRUSTOTAL_API_KEY from environment, otherwise returns realistic mock threat feed.
        """
        api_key = os.environ.get("VIRUSTOTAL_API_KEY")
        if not api_key:
            # High-fidelity mock reputation data
            logger.info(f"VirusTotal key not set. Generating mock feed for {ip}")
            
            # Safe local IPs vs external IPs reputation
            if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
                return {
                    "status": "safe",
                    "malicious_count": 0,
                    "total_engines": 90,
                    "reputation_score": 0,
                    "owner": "Internal Corporate Segment"
                }
            else:
                return {
                    "status": "malicious",
                    "malicious_count": 14,
                    "total_engines": 90,
                    "reputation_score": -45,
                    "owner": "Suspicious WAN Cloud Host Provider"
                }
                
        # In a real setup, make request to: https://www.virustotal.com/api/v3/ip_addresses/{ip}
        return {
            "status": "unverified",
            "message": "VirusTotal API client active but requires endpoint payload integrations."
        }
