import os
from backend.utils.logger import logger

class CveClient:
    @staticmethod
    def get_cve_by_port(port):
        """
        Retrieves common CVEs associated with standard network service ports.
        """
        cves_map = {
            22: {
                "cve_id": "CVE-2024-6387",
                "summary": "regreSSHion: RCE vulnerability in OpenSSH's server (sshd) due to a signal handler race condition.",
                "cvss_score": 8.1,
                "severity": "HIGH"
            },
            3306: {
                "cve_id": "CVE-2023-21912",
                "summary": "MySQL Server vulnerability allows low-privileged attackers to compromise database availability.",
                "cvss_score": 7.5,
                "severity": "HIGH"
            },
            80: {
                "cve_id": "CVE-2021-41773",
                "summary": "Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49.",
                "cvss_score": 7.5,
                "severity": "HIGH"
            },
            443: {
                "cve_id": "CVE-2014-0160",
                "summary": "Heartbleed: Buffer over-read vulnerability in OpenSSL allows theft of memory contents.",
                "cvss_score": 7.5,
                "severity": "HIGH"
            }
        }
        
        return cves_map.get(int(port), {
            "cve_id": "CVE-PENDING",
            "summary": f"No active CVSS vulnerabilities registered for port {port} in baseline configuration.",
            "cvss_score": 0.0,
            "severity": "LOW"
        })
