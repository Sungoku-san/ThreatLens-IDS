import os
import json
from backend.utils.logger import logger
try:
    from groq import Groq as GroqClient
    GROQ_SDK_AVAILABLE = True
except ImportError:
    GROQ_SDK_AVAILABLE = False

class LLMService:
    @staticmethod
    def generate_response(prompt, system_prompt=None, context=None):
        """
        Orchestrates LLM calls: Groq API -> Local Ollama -> Embedded Expert System Fallback.
        """
        # 1. Attempt Groq API
        groq_key = os.environ.get("GROQ_API_KEY")
        if groq_key and not groq_key.startswith("test_"):
            try:
                logger.info("Routing query to Groq API (SDK)...")
                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                # Format prompt with context if present
                user_content = prompt
                if context:
                    user_content = f"Environment Context:\n{json.dumps(context, indent=2)}\n\nUser Question:\n{prompt}"
                messages.append({"role": "user", "content": user_content})

                if GROQ_SDK_AVAILABLE:
                    client = GroqClient(api_key=groq_key)
                    response = client.chat.completions.create(
                        model="llama-3.1-8b-instant",
                        messages=messages,
                        temperature=0.2
                    )
                    return response.choices[0].message.content
                else:
                    raise RuntimeError("Groq SDK not installed")

            except Exception as e:
                logger.warning(f"Groq API call failed: {str(e)}. Attempting Ollama fallback...")

        # 2. Attempt Local Ollama (running locally on port 11434)
        try:
            logger.info("Routing query to Local Ollama API...")
            ollama_url = "http://localhost:11434/api/generate"
            
            # Format combined system prompt and context
            full_prompt = ""
            if system_prompt:
                full_prompt += f"[System Instruction]\n{system_prompt}\n\n"
            if context:
                full_prompt += f"[Environment Context]\n{json.dumps(context, indent=2)}\n\n"
            full_prompt += f"[User Question]\n{prompt}"
            
            data = {
                "model": "llama3", # default target model
                "prompt": full_prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2
                }
            }
            
            req = urllib.request.Request(
                ollama_url,
                data=json.dumps(data).encode('utf-8'),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            
            # Very short timeout so local execution doesn't hang if Ollama is not installed
            with urllib.request.urlopen(req, timeout=2.5) as response:
                res_body = json.loads(response.read().decode('utf-8'))
                return res_body['response']
                
        except Exception as e:
            logger.info("Local Ollama not running or failed. Deploying Embedded AI Expert System.")

        # 3. Fallback: Embedded Rule-Based Expert System (Runs local regex parsing and matches database context)
        return EmbeddedExpertSystem.generate_response(prompt, system_prompt, context)


class EmbeddedExpertSystem:
    @staticmethod
    def generate_response(prompt, system_prompt=None, context=None):
        """
        Custom, high-fidelity rule-based heuristic expert system.
        Parses threat context, matches cybersecurity facts, and returns formatted markdown.
        """
        # Extract user raw question from prompt wrapper if present
        raw_question = prompt
        if "User Question:" in prompt:
            raw_question = prompt.split("User Question:")[1].strip()
        query = raw_question.lower().strip()
        
        # If retrieved documents are present and query is about documentation rules, return them!
        if "[Retrieved Documents/Manuals Knowledge Chunks]" in prompt:
            if any(k in query for k in ["rule", "policy", "protocol", "section", "ingress", "compliance", "standard", "guide", "corporate"]):
                doc_context = prompt.split("[Retrieved Documents/Manuals Knowledge Chunks]")[1].split("[")[0].strip()
                if doc_context:
                    return f"""### AI Security Copilot Analyst Response (Document Knowledge RAG)

Based on your uploaded corporate documentation, here is the relevant guidance found matching your query:

{doc_context}
"""

        # Ensure we have active logs details from context
        active_flow = None
        if context and "active_flow" in context:
            active_flow = context["active_flow"]
            
        # Match Categories
        # 1. SHAP & Features explanations
        if "shap" in query or "feature" in query or "graph" in query or "why is" in query:
            if active_flow:
                reasons = []
                for val in active_flow.get("shap_values", []):
                    is_pos = val["type"] == "positive"
                    impact_sign = "+" if is_pos else "-"
                    reasons.append(f"- **{val['name']}** (Value: `{val['value']}`): Pushes threat probability **{impact_sign}{abs(val['impact']):.2f}** ({'increasing' if is_pos else 'decreasing'} risk).")
                
                reasons_str = "\n".join(reasons)
                
                return f"""### AI Security Copilot SHAP Explanation

For the inspected flow **{active_flow.get('flow_id', 'Unknown')}** (Type: `{active_flow.get('attack_type', 'Benign')}`), here is the SHAP parameter contribution breakdown:

{reasons_str}

**Summary of AI decision logic**:
The model predicted this traffic as **{active_flow.get('prediction', 'Normal')}** (Confidence: **{active_flow.get('confidence', 99)}%**). 
The explanation indicates that {'the high values of ' + active_flow.get('shap_values', [{}])[0].get('name', 'parameters') + ' strongly drive the classification as malicious.' if active_flow.get('prediction') != 'Normal' else 'all feature values reside within normal operating bounds.'}
"""
            else:
                return """### AI Security Copilot SHAP Help
Shapley Additive exPlanations (SHAP) is a game-theory approach that measures each feature's contribution to the machine learning model's output probability.
- **Positive SHAP Values (+)**: Pushes the model toward classifying the packet as an **Attack**.
- **Negative SHAP Values (-)**: Pushes the model toward classifying the packet as **Normal (Benign)**.
- **Base Value**: The average model output probability across the training dataset (usually around `0.34` for this configuration).
"""

        # 2. Incident response, recommendations, or firewall rules
        if "remedi" in query or "mitigat" in query or "firewall" in query or "contain" in query:
            attack_type = "Generic Threat"
            src_ip = "0.0.0.0"
            port = "N/A"
            if active_flow:
                attack_type = active_flow.get("attack_type", "Intrusion threat")
                src_ip = active_flow.get("src_ip", "0.0.0.0")
                port = active_flow.get("port", "80")
                
            return f"""### AI Security Copilot: Incident Response & Mitigation

Here is the containment and eradication plan for **{attack_type}** from source host `{src_ip}`:

#### Step 1: Containment (Immediate Action)
Isolate the source IP address immediately on the edge firewall. Run this command on your router or host firewall:
```bash
# Block host packets at kernel level using iptables
sudo iptables -A INPUT -s {src_ip} -j DROP
```
For Snort IDS rules configuration, add:
```snort
drop tcp {src_ip} any -> any {port} (msg:"AI-IDS Blocked Intrusion Source"; sid:1000001; rev:1;)
```

#### Step 2: Eradication
- Check for persistent connections or unauthorized processes running on the target machine.
- Kill socket channels associated with port `{port}`.

#### Step 3: Prevention & Long-term Recovery
- Implement strict network segmentation to quarantine guest segments.
- Set up rate-limiting firewall policies to prevent DDoS floods.
"""

        # 3. MITRE ATT&CK Mapping
        if "mitre" in query or "technique" in query:
            attack_type = "Intrusion"
            if active_flow:
                attack_type = active_flow.get("attack_type", "Generic")
            
            mitre_map = "T1046 (Network Service Scanning) and T1498 (Network Denial of Service)"
            if "ddos" in attack_type.lower() or "exploit" in attack_type.lower():
                mitre_map = "**T1498** - Network Denial of Service (Impact Area: Resource Hijacking / Exhaustion)"
            elif "brute" in attack_type.lower():
                mitre_map = "**T1110** - Brute Force Authentication (Access Stage: Credential Access)"
            elif "scan" in attack_type.lower():
                mitre_map = "**T1046** - Network Service Scanning (Access Stage: Discovery)"
                
            return f"""### MITRE ATT&CK Mapping

The active threat profile **{attack_type}** maps to the following MITRE ATT&CK tactics & techniques:

- **Tactic**: Discovery / Credential Access / Impact
- **Technique**: {mitre_map}
- **Mitigations**:
  - Implement network rate limiting (M1037).
  - Disable inactive services and restrict open ports (M1042).
  - Enforce account lockout policies and API rate limits (M1036).
"""

        # 4. General explanations / Beginner mode / OWASP / NIST
        if "beginner" in query or "explain" in query or "what is" in query:
            if "sql" in query:
                return """### SQL Injection Explained (Beginner Mode)

Imagine a website's database is a locked vault, and the login form is the security guard.
1. **Normal User**: Fills in username "admin" and password. The guard checks the list and unlocks the vault.
2. **SQL Injection Attack**: The attacker fills in username as: `admin' OR '1'='1`. 
3. **How it works**: The single quote `'` breaks the code logic, making the database statement read: *“Log in if the user is admin, OR if 1 equals 1.”* Since 1 is always equal to 1, the security guard gets confused, unlocks the gate, and lets the attacker in without a valid password!

**How to detect it**:
Inspect network payloads searching for database symbols like `'`, `--`, `UNION`, or `SELECT`.
"""
            elif "ddos" in query or "denial" in query:
                return """### DDoS (Distributed Denial of Service) Explained (Beginner Mode)

Imagine you own a tiny coffee shop. 
- **Normal Day**: 5-10 customers walk in, buy coffee, and leave. You can handle them easily.
- **DDoS Attack**: An attacker hires a crowd of 5,000 fake customers to pack inside your shop, shouting and blocking the counter. Because the shop is completely full of fake customers, real paying customers cannot even get to the door. Your business is forced to close!

**In Networking**:
Instead of people, fake computers send millions of rapid dummy packets (like TCP SYN packets) to a web server. The web server runs out of memory processing the requests and crashes, denying service to real users.
"""
            elif "xss" in query or "cross site scripting" in query:
                return """### XSS (Cross-Site Scripting) Explained (Beginner Mode)

Imagine leaving a sticky note on a public corkboard.
- **Normal note**: "Hey everyone, check out this link!"
- **XSS Attack**: The note contains a secret magic spell (malicious JavaScript code). When a reader looks at the corkboard, the spell automatically runs, reads their wallet ID (session cookies), and sends it to the attacker!

**In Web Apps**:
Attackers inject malicious scripts into trusted websites, which are then executed by innocent visitors' web browsers.
"""

        # 5. System stats / active context summarizer
        if "stats" in query or "overview" in query or "packets" in query:
            if context and "dashboard_stats" in context:
                s = context["dashboard_stats"]
                return f"""### SOC Dashboard Current Status

Here is the active network performance status fetched from the system SQLite database:
- **Total Packets Monitored**: `{s.get('total_packets', 0):,}`
- **Malicious Threat Connections**: `{s.get('malicious_packets', 0):,}`
- **Normal Connections**: `{s.get('normal_packets', 0):,}`
- **Detection Accuracy**: `{s.get('accuracy', 0):.2f}%`
- **False Positive Rate**: `{s.get('fpr', 0):.2f}%`
- **Active Threat Index Level**: **{s.get('threat_level', 'LOW')}**
"""
        
        # 6. Default Fallback
        return f"""### AI Security Copilot Analyst Response

Thank you for querying the Security Copilot. I have analyzed your query: *"{(prompt[:60] + '...') if len(prompt) > 60 else prompt}"*

#### Context Metrics:
- **Threat Vector**: {active_flow.get('attack_type', 'No active threat selected') if active_flow else 'No active logs trace loaded.'}
- **Clearance Level**: SOC Administrator Clearance 3

#### Recommended SOC Actions:
1. **Network Auditing**: Ingest flow packets using the **Upload Dataset** tab to check parameters.
2. **Explainability**: Inspect SHAP values under **SHAP Analysis** to examine which parameters push predictions towards attack classifications.
3. **Reports**: Run compliance reporting via the **Reports** tab to generate PDF executive summaries.

*Note: For deep semantic document searches, upload your PDF organizational manuals (e.g. firewalls policies) under the Documents tab, and I will search their text chunks automatically using RAG semantic mapping.*
"""
