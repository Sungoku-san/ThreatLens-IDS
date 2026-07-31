from backend.utils.logger import logger

class KnowledgeBase:
    # Built-in enterprise cybersecurity encyclopedia
    ARTICLES = {
        "ddos": {
            "title": "Distributed Denial of Service (DDoS) Attack",
            "category": "Network Attacks",
            "overview": "A distributed denial of service attack exhausts server resources by flooding it with massive volumes of mock traffic from distributed botnets.",
            "working_principle": "Volumetric attacks like TCP SYN floods send rapid connection handshakes, keeping sockets in half-open states (SYN_RECV) until memory buffer pools overflow. Other variants include UDP reflection or HTTP GET floods.",
            "detection": "High rates of incoming packets, abnormal ratios of SYN flags with empty ACK headers, and source IP clustering.",
            "iocs": [
                "Volumetric spike in traffic from unexpected geographic zones",
                "High ratio of TCP SYN packets compared to ESTABLISHED connections",
                "High rate of requests to single URL path from multiple source IPs"
            ],
            "mitigation": "Deploy rate-limit limits, SYN Cookies, edge firewalls rules, and Cloud scrubbing interfaces.",
            "best_practices": "Implement Anycast routing, establish thresholds on load balancers, and contract DDoS mitigation services.",
            "real_world_example": "The 2016 Dyn DNS attack where Mirai botnets flooded DNS services, crashing major websites.",
            "references": "NIST SP 800-189, MITRE ATT&CK T1498",
            "related_topics": ["syn flood", "botnets", "firewalls rules"]
        },
        "port scan": {
            "title": "Port Scanning Reconnaissance",
            "category": "Network Attacks",
            "overview": "A scanning attack checks active ports on a host, mapping running services to target exploits.",
            "working_principle": "Attackers send TCP SYN, FIN, or NULL packets to a range of ports. If open, the server responds with SYN-ACK. If closed, it replies with RST.",
            "detection": "A single IP address attempting connections to multiple sequential destination ports in a short timestamp window.",
            "iocs": [
                "Repetitive TCP connection attempts across random ports from a single IP",
                "Unusual volume of ICMP Port Unreachable packets",
                "IDS alerts for TCP SYN scan signatures"
            ],
            "mitigation": "Disable unused ports, hide services behind firewalls, and block scan sources using fail2ban.",
            "best_practices": "Implement port knocking, adopt closed-by-default firewall configurations, and use rate-limiting on port probes.",
            "real_world_example": "Standard preparatory phase before major network intrusions to detect vulnerable databases.",
            "references": "MITRE ATT&CK T1046 (Network Service Scanning)",
            "related_topics": ["firewalls rules", "ids rules", "service discovery"]
        },
        "ransomware": {
            "title": "Ransomware Malware Campaigns",
            "category": "Malware",
            "overview": "Ransomware is malicious software designed to block access to a computer system or files by encrypting them until a sum of money is paid.",
            "working_principle": "Gains access via phishing, vulnerable open ports (RDP), or drive-by downloads. It deletes Volume Shadow Copies, encrypts local files using strong algorithms (AES/RSA), and displays a ransom note.",
            "detection": "High volume of file modifications/renames, deletion of backup utilities, and network connections to Tor command-and-control servers.",
            "iocs": [
                "Bulk modification of file extensions to random suffixes (.locked, .wanna)",
                "Execution of commands like 'vssadmin.exe delete shadows'",
                "Spike in disk write I/O operations"
            ],
            "mitigation": "Isolate infected machines, block C2 communication, restore from offline backups.",
            "best_practices": "Enforce rigorous backup cycles (3-2-1 rule), restrict administrative commands, and train employees on anti-phishing.",
            "real_world_example": "WannaCry ransomware attack in 2017 which infected over 200,000 computers globally by exploiting the EternalBlue vulnerability.",
            "references": "NIST SP 1800-26, MITRE ATT&CK T1486",
            "related_topics": ["phishing", "lateral movement", "backups"]
        },
        "sql injection": {
            "title": "SQL Injection (SQLi) Vulnerability",
            "category": "OWASP Top 10",
            "overview": "SQL Injection occurs when an attacker inserts malicious SQL queries into input fields, manipulating backend database queries.",
            "working_principle": "Vulnerable applications concatenate user input directly into SQL statements without sanitization. An attacker inputs control characters like single quotes `'` or double dashes `--` to alter query logic.",
            "detection": "Inspect HTTP payload headers and inputs for keywords: `UNION`, `SELECT`, `OR 1=1`, `INSERT`, `DROP`, and SQL comments `--`.",
            "iocs": [
                "HTTP request payloads containing characters like single quotes, SELECT, UNION, or OR 1=1",
                "Spikes in database syntax error codes (e.g. 500 Internal Server Errors)",
                "Unauthorized extraction of massive rows from user tables"
            ],
            "mitigation": "Use Parameterized Queries (Prepared Statements), input validation, and restrict database credentials privileges.",
            "best_practices": "Adopt ORM frameworks, deploy web application firewalls (WAF), and enforce minimum privilege access to DB connections.",
            "real_world_example": "The 2015 TalkTalk breach where SQLi was used to steal card details of 150,000 customers.",
            "references": "OWASP Top 10 A03:2021-Injection, MITRE ATT&CK T1190",
            "related_topics": ["xss", "database security", "input sanitization"]
        },
        "lateral movement": {
            "title": "MITRE ATT&CK - Lateral Movement",
            "category": "MITRE ATT&CK",
            "overview": "Lateral Movement refers to techniques adversaries use to extend access to secondary systems within a compromised network.",
            "working_principle": "Adversaries pivot across networks by reusing credentials (pass-the-hash), exploiting trust relationships, or targeting internal remote services (SSH, RDP, SMB).",
            "detection": "Anomalous internal connections, logins from administrator accounts onto non-standard hosts, and network scans originating inside the LAN.",
            "iocs": [
                "Unusual SMB share queries (e.g. Admin$) between workstations",
                "Multiple authentication failures followed by a success on internal remote access protocols",
                "Creation of remote tasks/services using psexec or powershell scripts"
            ],
            "mitigation": "Enforce Multi-Factor Authentication (MFA), restrict remote protocols, and use host-based firewalls.",
            "best_practices": "Implement network segmentation, enforce LAPS (Local Administrator Password Solution), and limit privileges for domain administrator logins.",
            "real_world_example": "The Target breach where attackers compromised vendor credentials to access internal point-of-sale servers.",
            "references": "MITRE ATT&CK T1021, T1097, T1550",
            "related_topics": ["network segmentation", "active directory", "credentials access"]
        },
        "nist framework": {
            "title": "NIST Cybersecurity Framework (CSF)",
            "category": "NIST",
            "overview": "A framework designed by NIST to help organizations manage and reduce cybersecurity risks.",
            "working_principle": "Provides a common taxonomy divided into 5 Core Functions: Identify (assets), Protect (safeguards), Detect (anomalies), Respond (incidents), and Recover (operations).",
            "detection": "Evaluated using organizational audits, gap analysis, and policy compliance assessments.",
            "iocs": [
                "N/A (Process and structural framework)"
            ],
            "mitigation": "Align organizational security operations, controls, and response plans to CSF guidelines.",
            "best_practices": "Run annual risk assessments, establish asset inventories, and conduct periodic tabletop simulation exercises.",
            "real_world_example": "Many federal agencies and global corporations structure their entire security posture under the NIST framework.",
            "references": "NIST Cybersecurity Framework Version 1.1 / 2.0",
            "related_topics": ["soc operations", "incident response", "zero trust"]
        },
        "log analysis": {
            "title": "SOC Operations - Log Analysis and Threat Hunting",
            "category": "SOC Operations",
            "overview": "The systematic review of security logs from firewalls, servers, and endpoint systems to detect potential compromises.",
            "working_principle": "Logs are ingested by a SIEM (Security Information and Event Management) system, parsed, normalized, and correlated against threat intelligence to highlight anomalies.",
            "detection": "Mismatches in traffic logs, out-of-hours activities, privilege escalation attempts, and connections to blacklisted domains.",
            "iocs": [
                "Repeated logon failures from unusual geo-locations",
                "PowerShell execution with base64 encoded command strings",
                "Clearing of security event logs (Event ID 1102 / 104)"
            ],
            "mitigation": "Automate log parsing, set up behavioral alerts, and secure logs endpoints.",
            "best_practices": "Enforce central, read-only log storage, standardize NTP clocks synchronization, and verify logging verbose settings.",
            "real_world_example": "SOC analyst detecting persistent malware callouts by correlating DNS query records.",
            "references": "NIST SP 800-92 (Guide to Computer Security Log Management)",
            "related_topics": ["siem", "incident response", "threat intelligence"]
        },
        "incident response lifecycle": {
            "title": "Incident Response (IR) Lifecycle",
            "category": "Incident Response",
            "overview": "The structured process organizations follow to prepare for, detect, contain, and recover from cybersecurity incidents.",
            "working_principle": "Divided into phases based on NIST SP 800-61: 1. Preparation, 2. Detection & Analysis, 3. Containment, Eradication & Recovery, 4. Post-Incident Activity (Lessons Learned).",
            "detection": "Initial detection from SIEM alerts, user reports, or external security feeds.",
            "iocs": [
                "Elevated threat indicators on critical servers",
                "Unauthorized lateral network flow patterns",
                "Host isolation triggers"
            ],
            "mitigation": "Coordinate containment actions (quarantining hosts), clean malware footprints, restore systems, and patch vulnerabilities.",
            "best_practices": "Prepare predefined playbooks for Ransomware/DDoS, test alert communication trees, and keep offline contact directories.",
            "real_world_example": "A corporate response team containing a network breach within hours by following a standard phishing containment playbook.",
            "references": "NIST SP 800-61 Rev 2",
            "related_topics": ["soc operations", "blue team", "mitigation"]
        },
        "blue team hardening": {
            "title": "Blue Team Hardening and Defense Strategies",
            "category": "Blue Team",
            "overview": "Defensive security tactics centered on reducing attack surfaces, auditing access, and hardening systems.",
            "working_principle": "Involves system hardening (closing unused ports, patching, disabling default credentials), configuring firewalls/IPS, and deploying Endpoint Detection and Response (EDR) agents.",
            "detection": "Continuous vulnerability scanning, configuration compliance auditing, and integrity monitoring.",
            "iocs": [
                "System configuration drifts from standard baselines",
                "Host-based firewall disabled alert",
                "Unauthorized administrative groups changes"
            ],
            "mitigation": "Enforce secure group policies, apply host hardening guidelines (CIS benchmarks), and block malicious traffic flows.",
            "best_practices": "Automate system patching, mandate least privilege access (LPA), and run continuous security posture checks.",
            "real_world_example": "Defenders thwarting exploit attempts by hardening default server configs and disabling legacy TLS versions.",
            "references": "CIS Security Controls, NIST SP 800-53",
            "related_topics": ["zero trust", "firewalls rules", "ids rules"]
        },
        "red team engagement": {
            "title": "Red Team Attack Simulations",
            "category": "Red Team",
            "overview": "Full-scope objective-driven security simulations designed to measure how well an organization's defense posture handles a real attack.",
            "working_principle": "Red Teamers mimic real threat actors, employing physical intrusion, social engineering, credential harvesting, custom malware, and stealth pivots.",
            "detection": "Detection rests on Blue Team SIEM alerts, behavioral anomaly triggers, and network telemetry analysis.",
            "iocs": [
                "Use of offensive tooling signatures (e.g. Cobalt Strike, Mimikatz)",
                "Unusual outbound egress channels (DNS/HTTPS tunneling)",
                "Physical security alerts for tailgating attempts"
            ],
            "mitigation": "Analyze simulated attack paths, address security control gaps, and train defense staff.",
            "best_practices": "Ensure engagement objectives are clearly defined, establish a secure 'deconfliction' log, and integrate findings into collaborative purple-teaming exercises.",
            "real_world_example": "A red team breaching database segments by successfully executing local privilege escalations on an unpatched intranet server.",
            "references": "MITRE ATT&CK Matrix for Enterprise",
            "related_topics": ["lateral movement", "phishing", "blue team hardening"]
        },
        "zero trust": {
            "title": "Zero Trust Security Architecture",
            "category": "Zero Trust",
            "overview": "Zero Trust is a security guideline based on 'never trust, always verify'. Every request must be authenticated, authorized, and encrypted.",
            "working_principle": "Eliminates standard perimeter-based trust. Uses micro-segmentation, identity checks, and continuous context evaluation.",
            "detection": "Monitored using identity provider logs, endpoint health scores, and network flow telemetry analysis.",
            "iocs": [
                "Logins from unknown or blacklisted client devices",
                "Attempts to bypass access proxies and talk directly to segregated workloads",
                "Unusually rapid movements between isolated security segments"
            ],
            "mitigation": "Enforce MFA, lease privileges policies, and isolate network segments dynamically.",
            "best_practices": "Implement identity-aware proxies, adopt software-defined networking (SDN), and continuously evaluate device posture.",
            "real_world_example": "Google's internal BeyondCorp implementation, shifting secure access controls from standard VPNs to continuous user-device validations.",
            "references": "NIST SP 800-207",
            "related_topics": ["mfa", "network segmentation", "microsegmentation"]
        }
    }

    @classmethod
    def search(cls, query):
        """Searches built-in articles by keyword matching."""
        query = query.lower()
        results = []
        
        # 1. First, search key keywords match
        for key, art in cls.ARTICLES.items():
            if key in query or art["title"].lower() in query or art["overview"].lower() in query:
                results.append(art)
                
        # 2. Fallback check for single words matching
        if not results:
            words = [w for w in query.split() if len(w) > 3]
            for word in words:
                for key, art in cls.ARTICLES.items():
                    if word in key or word in art["category"].lower():
                        if art not in results:
                            results.append(art)
                            
        return results
