class MitreClient:
    @staticmethod
    def get_technique_details(technique_id):
        """
        Retrieves MITRE ATT&CK technique details.
        """
        techniques = {
            "T1498": {
                "name": "Network Denial of Service",
                "description": "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block host and network availability.",
                "tactic": "Impact",
                "platform": "Linux, Windows, macOS, Network Devices"
            },
            "T1110": {
                "name": "Brute Force",
                "description": "Adversaries may use brute force authentication to attempt credentials combinations on login endpoints.",
                "tactic": "Credential Access",
                "platform": "Linux, Windows, Active Directory, Cloud Services"
            },
            "T1046": {
                "name": "Network Service Scanning",
                "description": "Adversaries may scan active ports on host systems to find running services and potential exploits.",
                "tactic": "Discovery",
                "platform": "Linux, Windows, macOS"
            },
            "T1190": {
                "name": "Exploit Public-Facing Application",
                "description": "Adversaries may exploit vulnerabilities in web servers or public services to bypass authentication or gain access.",
                "tactic": "Initial Access",
                "platform": "Web applications, Databases, SSH/FTP servers"
            }
        }
        return techniques.get(technique_id, {
            "name": "Unknown Technique",
            "description": "Information not registered in local MITRE ATT&CK database.",
            "tactic": "N/A",
            "platform": "N/A"
        })
