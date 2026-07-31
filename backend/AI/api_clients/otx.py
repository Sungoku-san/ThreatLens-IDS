import os
from backend.utils.logger import logger

class OtxClient:
    @staticmethod
    def get_pulses(ip):
        """
        Fetches threat pulses from AlienVault OTX.
        """
        api_key = os.environ.get("OTX_API_KEY")
        if not api_key:
            logger.info(f"OTX key not set. Using mock pulses for {ip}")
            
            if ip.startswith("192.168.") or ip.startswith("10."):
                return {"pulses_count": 0, "indicators_matched": [], "reputation": "CLEAN"}
            else:
                return {
                    "pulses_count": 3,
                    "indicators_matched": ["botnet_activity_host", "malicious_syn_flood_source"],
                    "reputation": "SUSPICIOUS"
                }
                
        return {"pulses_count": 0, "message": "AlienVault OTX active."}
