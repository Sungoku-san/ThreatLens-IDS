from backend.AI.embedding_service import EmbeddingService
from backend.AI.vector_store import VectorStore
from backend.AI.llm_service import LLMService
from backend.AI.prompt_templates import get_system_prompt, wrap_rag_prompt, get_context_prompt
from backend.api_clients.virustotal import VirusTotalClient
from backend.api_clients.abuseipdb import AbuseIPDBClient
from backend.api_clients.geoip import GeoIpClient
from backend.api_clients.shodan import ShodanClient
from backend.utils.logger import logger

class RagEngine:
    @staticmethod
    def answer_query(query, active_flow=None, session_history=None, dashboard_stats=None, mode="professional"):
        """
        Coordinates full RAG pipeline: retrieves matches -> fetches threat intel -> calls LLM.
        """
        logger.info(f"RAG Engine: Processing user query: '{query}' in Mode: '{mode}'")
        
        # 1. Document retrieval from vector index
        doc_context = ""
        try:
            q_vector = EmbeddingService.get_embedding(query)
            matches = VectorStore.query(q_vector, top_k=2)
            if matches:
                doc_context = "\n---\n".join([m["text"] for m in matches])
                logger.info(f"RAG Engine: Retrieved {len(matches)} matching document chunks.")
        except Exception as e:
            logger.error(f"RAG Engine: Document retrieval failed: {str(e)}")

        # 2. Threat Intel APIs lookup
        intel_context = ""
        if active_flow:
            src_ip = active_flow.get("src_ip", "0.0.0.0")
            port = active_flow.get("port", 80)
            
            # Run IP reputation lookups
            vt = VirusTotalClient.inspect_ip(src_ip)
            abuse = AbuseIPDBClient.report_status(src_ip)
            geo = GeoIpClient.locate_ip(src_ip)
            shodan = ShodanClient.inspect_host(src_ip)
            
            intel_context = f"""
IP Threat Intelligence Summary for '{src_ip}':
- Geolocation: {geo.get('city')}, {geo.get('country')} (ISP: {geo.get('isp')})
- VirusTotal Status: Detected by {vt.get('malicious_count')}/{vt.get('total_engines')} security engines.
- AbuseIPDB Score: {abuse.get('abuse_confidence')}% abuse confidence score with {abuse.get('total_reports')} reports.
- Shodan scan details: Open ports: {shodan.get('ports')}. Detected vulns: {shodan.get('vulns')}
"""
            logger.info("RAG Engine: Integrated Threat Intelligence APIs feed.")

        # 3. Contextual flow logs injections
        flow_context = None
        if active_flow:
            flow_context = get_context_prompt(
                active_flow.get("prediction", "Normal"),
                active_flow.get("confidence", 99.0),
                active_flow.get("attack_type", "Benign"),
                active_flow.get("risk_level", "Low"),
                active_flow.get("shap_values", [])
            )

        # 4. Formulate prompts based on Mode
        full_system_prompt = get_system_prompt(mode)
        if session_history:
            # Append conversation history to prompt context
            history_str = "\n".join([f"{m['role'].upper()}: {m['message']}" for m in session_history])
            full_system_prompt += f"\n\n[Conversation History Memory]\n{history_str}"
            
        context_data = {
            "mode": mode
        }
        if active_flow:
            context_data["active_flow"] = active_flow
        if dashboard_stats:
            context_data["dashboard_stats"] = dashboard_stats

        # Wrap question using prompt builders
        user_prompt = wrap_rag_prompt(query, doc_context, intel_context)
        
        # 5. Call LLM Service
        response = LLMService.generate_response(
            prompt=user_prompt,
            system_prompt=full_system_prompt,
            context=context_data
        )
        
        return response
