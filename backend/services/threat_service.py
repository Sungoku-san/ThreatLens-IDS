from backend.api_clients import (
    VirusTotalClient,
    AbuseIPDBClient,
    GeoIpClient,
    ShodanClient,
    NvdCveClient,
    AlienVaultOtxClient,
    WhoisClient
)

class ThreatService:
    @staticmethod
    def compile_threat_intelligence(ip, port=None):
        """
        Gathers coordinated threat intelligence analysis across threat client libraries.
        """
        vt = VirusTotalClient.inspect_ip(ip)
        abuse = AbuseIPDBClient.report_status(ip)
        geo = GeoIpClient.locate_ip(ip)
        shodan = ShodanClient.inspect_host(ip)
        otx = AlienVaultOtxClient.get_pulses(ip)
        whois = WhoisClient.query_whois(ip)
        
        cve = None
        if port:
            cve = NvdCveClient.get_cve_by_port(port)
            
        return {
            "ip": ip,
            "port": port,
            "virustotal": vt,
            "abuseipdb": abuse,
            "geolocation": geo,
            "shodan": shodan,
            "alienvault_otx": otx,
            "whois": whois,
            "cve": cve
        }
