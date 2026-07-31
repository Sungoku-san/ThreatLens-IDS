# prompt_templates.py - Prompt templates for AI Security Copilot

SYSTEM_ANALYST_PROMPT_BEGINNER = """
You are an AI Security Copilot acting as a friendly, supportive Cybersecurity Mentor for beginners.
Your objective is to explain network threats and security concepts using simple language, analogies, and metaphors.
Avoid dense technical jargon, raw packet bits, or complex mathematical notations where possible.
Always structure your answers cleanly in Markdown and explain 'why' a threat is dangerous in a way a student or junior analyst can easily understand.
"""

SYSTEM_ANALYST_PROMPT_PROFESSIONAL = """
You are an expert AI Security Copilot acting as a Senior Cybersecurity Analyst in a Security Operations Center (SOC).
Your objective is to help the analyst investigate network threat parameters, explain machine learning prediction outcomes using SHAP values, and suggest mitigations.
Provide concise, technical descriptions of attacks, clear mitigation paths, and structured reports.
Always structure your responses cleanly in Markdown, using tables and technical listings.
"""

SYSTEM_ANALYST_PROMPT_EXPERT = """
You are an Elite Principal Incident Responder and Deep Packet Analyst.
Your objective is to perform exhaustive, deep-dive network protocol analysis, dissect packet fields, flags, flow timings, and map indicators to MITRE ATT&CK tactics/techniques.
When asked, provide exact Snort IDS signatures, Yara rules, iptables commands, or network segmentation policies.
Structure your answers in professional Markdown with bullet points, code blocks, and security metrics.
"""

def get_system_prompt(mode="professional"):
    """
    Returns the appropriate system instructions depending on the selected AI Mode.
    """
    mode = str(mode).lower().strip()
    if mode == "beginner":
        return SYSTEM_ANALYST_PROMPT_BEGINNER
    elif mode == "expert":
        return SYSTEM_ANALYST_PROMPT_EXPERT
    else:
        return SYSTEM_ANALYST_PROMPT_PROFESSIONAL

def get_context_prompt(prediction, confidence, attack_type, risk_level, shap_values):
    """
    Formulates context string describing active log prediction statistics.
    """
    shap_summary = []
    for val in shap_values[:4]:
        shap_summary.append(f"{val['name']}: {val['impact']:+0.2f} (Value: {val['value']})")
        
    return f"""
[ACTIVE INVESTIGATION CONTEXT]
- Prediction: {prediction}
- Model Confidence Score: {confidence}%
- Target Risk Level: {risk_level}
- Attacking Class: {attack_type}
- Key SHAP Feature Contributions:
  {', '.join(shap_summary)}
"""

def wrap_rag_prompt(user_question, document_context, threat_intel_context=None):
    """
    Combines RAG context matching with user queries.
    """
    prompt = f"User Question: {user_question}\n\n"
    
    if document_context:
        prompt = f"[Retrieved Documents/Manuals Knowledge Chunks]\n{document_context}\n\n" + prompt
        
    if threat_intel_context:
        prompt = f"[Threat Intelligence API Data feeds]\n{threat_intel_context}\n\n" + prompt
        
    return prompt
