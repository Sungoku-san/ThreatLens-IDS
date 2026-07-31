import os
import urllib.request
import json
from backend.utils.logger import logger

class AbuseIPDBClient:
    @staticmethod
    def report_status(ip):
        """
        Queries AbuseIPDB database for IP abuse stats.
        Falls back to mock logs if keys are missing.
        """
        api_key = os.environ.get("ABUSEIPDB_API_KEY")
        if not api_key:
            logger.info(f"AbuseIPDB key not set. Using mock logs check for {ip}")
            if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
                return {
                    "abuse_confidence": 0,
                    "total_reports": 0,
                    "last_reported": None,
                    "is_whitelisted": True
                }
            else:
                return {
                    "abuse_confidence": 88,
                    "total_reports": 112,
                    "last_reported": "3 minutes ago",
                    "is_whitelisted": False
                }
                
        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
            req = urllib.request.Request(
                url,
                headers={
                    "Key": api_key,
                    "Accept": "application/json"
                }
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                res_body = json.loads(response.read().decode('utf-8'))
                data = res_body.get("data", {})
                return {
                    "abuse_confidence": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "last_reported": data.get("lastReportedAt", "N/A"),
                    "is_whitelisted": data.get("isWhitelisted", False)
                }
        except Exception as e:
            logger.error(f"AbuseIPDB check failed: {str(e)}")
            return {
                "abuse_confidence": 0,
                "total_reports": 0,
                "message": f"API Error: {str(e)}"
            }
