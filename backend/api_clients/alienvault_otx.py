import os
from backend.utils.logger import logger

class AlienVaultOtxClient:
    @staticmethod
    def get_pulses(ip):
        """
        Fetches threat pulses from AlienVault OTX.
        """
        api_key = os.environ.get("ALIENVAULT_OTX_API_KEY")
        if not api_key:
            logger.info(f"OTX key not set. Using mock pulses for {ip}")
            if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
                return {"pulses_count": 0, "indicators_matched": [], "reputation": "CLEAN"}
            else:
                return {
                    "pulses_count": 3,
                    "indicators_matched": ["botnet_activity_host", "malicious_syn_flood_source"],
                    "reputation": "SUSPICIOUS"
                }
                
        # In a production context, make a request using urllib
        try:
            import urllib.request
            import json
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            req = urllib.request.Request(
                url,
                headers={"X-OTX-API-KEY": api_key}
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                res_body = json.loads(response.read().decode('utf-8'))
                pulse_info = res_body.get("pulse_info", {})
                pulses = pulse_info.get("pulses", [])
                reputation = "SUSPICIOUS" if len(pulses) > 0 else "CLEAN"
                indicators = [p.get("name", "") for p in pulses[:3]]
                return {
                    "pulses_count": len(pulses),
                    "indicators_matched": indicators,
                    "reputation": reputation
                }
        except Exception as e:
            logger.error(f"AlienVault OTX integration error: {str(e)}")
            return {"pulses_count": 0, "indicators_matched": [], "reputation": "UNVERIFIED"}
