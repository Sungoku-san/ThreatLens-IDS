import numpy as np
from backend.utils.logger import logger

TRANSFORMERS_AVAILABLE = False
_EMBED_MODEL = None

try:
    from sentence_transformers import SentenceTransformer
    TRANSFORMERS_AVAILABLE = True
    logger.info("SentenceTransformers package loaded successfully.")
except ImportError:
    logger.warning("SentenceTransformers not found. Activating TF-IDF fallback vectorizer.")

class EmbeddingService:
    @staticmethod
    def get_embedding(text):
        """Generates embedding vector for text using SentenceTransformers or TF-IDF fallback."""
        global _EMBED_MODEL
        
        # 1. Real Embeddings
        if TRANSFORMERS_AVAILABLE:
            try:
                if _EMBED_MODEL is None:
                    # Load smallest, fastest model
                    _EMBED_MODEL = SentenceTransformer('all-MiniLM-L6-v2')
                return _EMBED_MODEL.encode(text).tolist()
            except Exception as e:
                logger.error(f"Failed to calculate SentenceTransformers embedding: {str(e)}")

        # 2. Heuristic TF-IDF Vector Fallback (generates a 128-dimensional vector based on word counts)
        return EmbeddingService._generate_tfidf_fallback_vector(text)

    @staticmethod
    def get_embeddings(texts):
        """Batch generates list of embeddings."""
        return [EmbeddingService.get_embedding(t) for t in texts]

    @staticmethod
    def _generate_tfidf_fallback_vector(text):
        """
        Generates a deterministic 128-dimension vector by mapping text characters hash 
        to word bins (hash trick / bag-of-words simulation).
        """
        vector = np.zeros(128)
        words = text.lower().split()
        
        if not words:
            return vector.tolist()
            
        for w in words:
            # Hash trick mapping
            bin_idx = hash(w) % 128
            # Simple TF count
            vector[bin_idx] += 1.0
            
        # L2 Normalization
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector = vector / norm
            
        return vector.tolist()
