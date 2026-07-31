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
            if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
                return {"ports": [22, 80, 443], "vulns": [], "isp": "Intranet LAN"}
            else:
                return {
                    "ports": [21, 22, 80, 443, 3306, 8080],
                    "vulns": ["CVE-2023-21912"],
                    "isp": "Suspicious Hosting Provider"
                }
                
        try:
            import urllib.request
            import json
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            with urllib.request.urlopen(url, timeout=5) as response:
                res_body = json.loads(response.read().decode('utf-8'))
                return {
                    "ports": res_body.get("ports", []),
                    "vulns": res_body.get("vulns", []),
                    "isp": res_body.get("isp", "Unknown ISP")
                }
        except Exception as e:
            logger.error(f"Shodan search failed: {str(e)}")
            return {"ports": [], "vulns": [], "isp": "Unresolved Node"}
