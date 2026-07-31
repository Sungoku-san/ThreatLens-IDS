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
            logger.info(f"VirusTotal key not set. Generating mock feed for {ip}")
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
                
        # Basic REST client fallback logic
        try:
            import urllib.request
            import json
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            req = urllib.request.Request(url, headers={"x-apikey": api_key})
            with urllib.request.urlopen(req, timeout=5) as response:
                res_body = json.loads(response.read().decode('utf-8'))
                stats = res_body.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                reputation = res_body.get("data", {}).get("attributes", {}).get("reputation", 0)
                owner = res_body.get("data", {}).get("attributes", {}).get("as_owner", "Unknown OSP")
                return {
                    "status": "malicious" if malicious > 0 else "safe",
                    "malicious_count": malicious,
                    "total_engines": sum(stats.values()),
                    "reputation_score": reputation,
                    "owner": owner
                }
        except Exception as e:
            logger.error(f"VirusTotal API execution failed: {str(e)}")
            return {"status": "unverified", "message": f"API request error: {str(e)}"}
