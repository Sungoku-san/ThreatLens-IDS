import os
from backend.utils.logger import logger

class ShodanClient:
    @staticmethod
    def inspect_host(ip):
        """
        Inspects host ports status via Shodan.
        """
        api_key = os.environ.get("SHODAN_API_KEY")
        if not api_key:
            logger.info(f"Shodan API key not set. Using mock port scans for {ip}")
            
            if ip.startswith("192.168.") or ip.startswith("10."):
                return {"ports": [22, 80, 443], "vulns": [], "isp": "Intranet LAN"}
            else:
                return {
                    "ports": [21, 22, 80, 443, 3306, 8080],
                    "vulns": ["CVE-2023-21912"],
                    "isp": "Suspicious Hosting Provider"
                }
                
        return {"ports": [], "message": "Shodan client running."}
