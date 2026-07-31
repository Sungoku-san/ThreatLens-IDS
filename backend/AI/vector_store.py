import os
import json
import numpy as np
from backend.config import Config
from backend.utils.logger import logger

class VectorStore:
    # In-memory index cache
    # Structure: [{"text": str, "vector": list, "metadata": dict}]
    _INDEX = []
    _INDEX_PATH = os.path.join(os.path.dirname(Config.DATABASE_PATH), 'vector_store.json')

    @classmethod
    def save_index(cls):
        """Saves memory index to local JSON file for persistence."""
        try:
            with open(cls._INDEX_PATH, 'w') as f:
                json.dump(cls._INDEX, f, indent=2)
            logger.info(f"Vector store successfully saved to {cls._INDEX_PATH}")
        except Exception as e:
            logger.error(f"Failed to save vector store index: {str(e)}")

    @classmethod
    def load_index(cls):
        """Loads index from local JSON file."""
        if not os.path.exists(cls._INDEX_PATH):
            cls._INDEX = []
            return
        try:
            with open(cls._INDEX_PATH, 'r') as f:
                cls._INDEX = json.load(f)
            logger.info(f"Vector store successfully loaded {len(cls._INDEX)} text chunks.")
        except Exception as e:
            logger.error(f"Failed to load vector store index: {str(e)}")
            cls._INDEX = []

    @classmethod
    def add_document_chunks(cls, chunks, embeddings, metadata_list):
        """Adds text chunks with their computed vectors into the index."""
        # Make sure index is loaded
        if not cls._INDEX:
            cls.load_index()
            
        for chunk, vector, meta in zip(chunks, embeddings, metadata_list):
            cls._INDEX.append({
                "text": chunk,
                "vector": vector,
                "metadata": meta
            })
        cls.save_index()

    @classmethod
    def query(cls, query_vector, top_k=3):
        """
        Executes Cosine Similarity search over the stored vectors list.
        Returns closest text matches.
        """
        if not cls._INDEX:
            cls.load_index()

        if not cls._INDEX:
            return []

        q_vec = np.array(query_vector)
        q_norm = np.linalg.norm(q_vec)
        
        if q_norm == 0:
            return []

        results = []
        for idx, item in enumerate(cls._INDEX):
            doc_vec = np.array(item["vector"])
            doc_norm = np.linalg.norm(doc_vec)
            
            if doc_norm == 0:
                continue
                
            # Cosine similarity formula
            sim = np.dot(q_vec, doc_vec) / (q_norm * doc_norm)
            
            results.append({
                "text": item["text"],
                "similarity": float(sim),
                "metadata": item["metadata"]
            })
            
        # Sort by similarity descending
        results.sort(key=lambda x: x["similarity"], reverse=True)
        return results[:top_k]

    @classmethod
    def clear_index(cls):
        """Wipes vectors index database."""
        cls._INDEX = []
        if os.path.exists(cls._INDEX_PATH):
            try:
                os.remove(cls._INDEX_PATH)
            except:
                pass
        logger.info("Vector store index wiped.")
