class RecommendationEngine:
    @staticmethod
    def generate_recommendations(prediction, attack_type, src_ip="0.0.0.0", port=80):
        """
        Generates custom Firewall, IDS, IPS, Patch Priority, Network Segmentation,
        Zero Trust policies, and Incident Response steps recommendations.
        """
        if prediction == "Normal":
            return {
                "firewall_rules": [],
                "ids_rules": [],
                "ips_rules": [],
                "patch_priority": "LOW",
                "segmentation_recommendations": [
                    "Maintain baseline network isolation.",
                    "Verify workstation-to-server traffic traverses authorized access gateways."
                ],
                "zero_trust_policies": [
                    "Continuous authentication token validation.",
                    "Least privilege access for standard user credentials."
                ],
                "incident_response_steps": [
                    "No immediate remediation required.",
                    "Monitor flow logs regularly."
                ]
            }
            
        fw_rules = []
        ids_rules = []
        ips_rules = []
        segmentation = []
        zt_policies = []
        ir_steps = []
        
        # General firewall actions
        fw_rules.append(f"sudo iptables -A INPUT -s {src_ip} -j DROP")
        fw_rules.append(f"sudo iptables -A INPUT -p tcp -s {src_ip} --dport {port} -j REJECT")
        
        if "ddos" in attack_type.lower():
            patch_priority = "CRITICAL"
            
            ids_rules.append(f'alert tcp any any -> any {port} (msg:"AI-IDS Suspicious DDoS SYN Flood Detected"; flags:S; threshold:type threshold, track by_dst, count 100, seconds 10; sid:2000001; rev:1;)')
            ips_rules.append(f'drop tcp {src_ip} any -> any {port} (msg:"AI-IPS Volumetric DDoS Connection Blocked"; flags:S; sid:2000002; rev:1;)')
            
            segmentation.append(f"Quarantine the ingress target port {port} behind an active load balancer pool.")
            segmentation.append("Route high-volume inbound WAN links through a segregated traffic scrubbing subnet.")
            
            zt_policies.append("Deploy rate-limiting access controls at the Identity-Aware Proxy gateway.")
            zt_policies.append("Enforce micro-segmentation policies: limit inter-service API traffic during anomalies.")
            
            ir_steps.append("Identify primary targeting endpoints and verify if server instances are healthy.")
            ir_steps.append("Enable SYN Cookies in the host OS kernel config: 'sysctl -w net.ipv4.tcp_syncookies=1'")
            ir_steps.append("Engage upstream ISP or cloud mitigation scrubbing centers (e.g. Cloudflare).")
            
        elif "brute" in attack_type.lower() or "ssh" in attack_type.lower():
            patch_priority = "HIGH"
            
            ids_rules.append(f'alert tcp any any -> any 22 (msg:"AI-IDS SSH Authentication Brute-Force Alert"; flags:S; threshold:type threshold, track by_src, count 5, seconds 60; sid:2000003; rev:1;)')
            ips_rules.append(f'drop tcp {src_ip} any -> any 22 (msg:"AI-IPS SSH Dictionary Attack Blocked"; sid:2000004; rev:1;)')
            
            segmentation.append("Restrict direct SSH (Port 22) administrative access from the broad internet.")
            segmentation.append("Force SSH management interfaces to run on a dedicated management VLAN or jump host.")
            
            zt_policies.append("Establish strict Multi-Factor Authentication (MFA) requirements for administrative logins.")
            zt_policies.append("Require continuous endpoint security health check reports before allowing terminal access.")
            
            ir_steps.append("Isolate session hosts immediately from active administrative directory connections.")
            ir_steps.append("Audit administrative audit logs to check if the attacker successfully authenticated.")
            ir_steps.append("Deploy fail2ban daemon to dynamically block ssh brute-force IPs.")
            
        elif "scan" in attack_type.lower():
            patch_priority = "MEDIUM"
            
            ids_rules.append(f'alert tcp any any -> any any (msg:"AI-IDS Port Scanning reconnaissance probe"; flags:S; threshold:type threshold, track by_src, count 25, seconds 10; sid:2000005; rev:1;)')
            ips_rules.append(f'drop ip {src_ip} any -> any any (msg:"AI-IPS Recon Probe Dropped"; sid:2000006; rev:1;)')
            
            segmentation.append("Configure host-based firewall closed-by-default postures on local subnets.")
            segmentation.append("Block broad ICMP ping sweeps and direct host queries between guest subnets.")
            
            zt_policies.append("Enforce context-based service access: hide running ports from unauthenticated network sweeps.")
            zt_policies.append("Implement Port Knocking: require cryptographic headers sequencing before opening access ports.")
            
            ir_steps.append("Validate firewall packet filter configurations for any leaked administrative ports.")
            ir_steps.append("Establish honey-pot listening daemons on random closed ports to flag internal probing nodes.")
            
        else:
            patch_priority = "HIGH"
            
            ids_rules.append(f'alert ip {src_ip} any -> any any (msg:"AI-IDS Intrusion signature matched"; sid:2000007; rev:1;)')
            ips_rules.append(f'drop ip {src_ip} any -> any any (msg:"AI-IPS Intrusion Blocked"; sid:2000008; rev:1;)')
            
            segmentation.append("Isolate target machines in a dedicated incident sandbox VLAN.")
            
            zt_policies.append("Require credentials rotation for service accounts running on target servers.")
            zt_policies.append("Apply micro-segmentation guidelines: block cross-workload communication.")
            
            ir_steps.append("Isolate local network adapter card on target virtual machines.")
            ir_steps.append("Capture packet dump (.pcap) from adjacent switches for forensic analysis.")
            ir_steps.append("Deploy EDR script tools to execute full-disk malware scans.")
            
        return {
            "firewall_rules": fw_rules,
            "ids_rules": ids_rules,
            "ips_rules": ips_rules,
            "patch_priority": patch_priority,
            "segmentation_recommendations": segmentation,
            "zero_trust_policies": zt_policies,
            "incident_response_steps": ir_steps
        }
