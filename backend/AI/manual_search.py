from backend.AI.embedding_service import EmbeddingService
from backend.AI.vector_store import VectorStore
from backend.AI.knowledge_base import KnowledgeBase
from backend.utils.helpers import get_db_connection, row_to_dict
from backend.utils.logger import logger

class ManualSearch:
    @staticmethod
    def search_manuals(query, top_k=5):
        """
        Runs vector semantic query search over ingested document library manuals.
        """
        logger.info(f"ManualSearch: Searching manuals for query: '{query}'")
        try:
            # Generate search query embedding
            q_vector = EmbeddingService.get_embedding(query)
            
            # Query vector database index
            matches = VectorStore.query(q_vector, top_k=top_k)
            return matches
        except Exception as e:
            logger.error(f"ManualSearch: Semantic search encountered error: {str(e)}")
            return []

    @staticmethod
    def global_search(query):
        """
        Executes a global smart search across:
        1. Ingested organizational manuals & uploaded documents (Semantic Vector search)
        2. Threat references & MITRE/OWASP knowledge base articles (Lexical search)
        3. Network flow anomaly predictions log database (SQL search)
        """
        logger.info(f"ManualSearch: Global smart search initiated for: '{query}'")
        
        results = {
            "manuals_and_documents": [],
            "knowledge_base": [],
            "threats_and_predictions": []
        }
        
        # 1. Semantic search on uploaded documents
        try:
            results["manuals_and_documents"] = ManualSearch.search_manuals(query, top_k=3)
        except Exception as e:
            logger.error(f"ManualSearch: Global search failed on manuals chunking: {str(e)}")
            
        # 2. Search MITRE/OWASP/NIST cybersecurity articles
        try:
            results["knowledge_base"] = KnowledgeBase.search(query)
        except Exception as e:
            logger.error(f"ManualSearch: Global search failed on knowledge base lookup: {str(e)}")
            
        # 3. Query prediction database logs
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            search_like = f"%{query}%"
            cursor.execute('''
                SELECT id, flow_id, src_ip, dst_ip, proto, port, prediction, confidence, attack_type, risk_level, timestamp
                FROM predictions
                WHERE flow_id LIKE ? 
                OR src_ip LIKE ? 
                OR dst_ip LIKE ? 
                OR prediction LIKE ? 
                OR attack_type LIKE ?
                ORDER BY id DESC LIMIT 5
            ''', (search_like, search_like, search_like, search_like, search_like))
            rows = cursor.fetchall()
            results["threats_and_predictions"] = [row_to_dict(r) for r in rows]
            conn.close()
        except Exception as e:
            logger.error(f"ManualSearch: Global search failed on prediction tables lookup: {str(e)}")
            
        return results
