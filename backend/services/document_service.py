import os
from datetime import datetime
from werkzeug.utils import secure_filename
from backend.config import Config
from backend.AI.document_loader import DocumentLoader
from backend.AI.embedding_service import EmbeddingService
from backend.AI.vector_store import VectorStore
from backend.utils.helpers import get_db_connection
from backend.utils.logger import logger

class DocumentService:
    @staticmethod
    def process_and_index_manual(file):
        """
        Ingests cybersecurity manuals, extracts text, chunks it,
        calculates embeddings, indexes them, and writes document log to SQLite.
        """
        if not file or file.filename == '':
            return False, "No file selected."
            
        filename = secure_filename(file.filename)
        manuals_dir = os.path.join(Config.UPLOAD_FOLDER, 'manuals')
        os.makedirs(manuals_dir, exist_ok=True)
        
        filepath = os.path.join(manuals_dir, filename)
        
        try:
            # 1. Save file to disk
            file.save(filepath)
            logger.info(f"Manual saved to {filepath}")
            
            # 2. Extract plain text
            text = DocumentLoader.extract_text(filepath)
            
            # 3. Chunk text
            chunks = DocumentLoader.chunk_text(text)
            logger.info(f"Extracted document. Partitioned into {len(chunks)} chunks.")
            
            if not chunks:
                return False, "Failed to extract readable text from document."
                
            # 4. Generate embeddings
            embeddings = EmbeddingService.get_embeddings(chunks)
            
            # 5. Index chunks in vector store
            metadata = [{"source": filename, "chunk_idx": idx} for idx in range(len(chunks))]
            VectorStore.add_document_chunks(chunks, embeddings, metadata)
            
            # 6. Save document record in SQLite DB
            conn = get_db_connection()
            cursor = conn.cursor()
            
            uploaded_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute('''
                INSERT INTO uploaded_manuals (filename, filepath, uploaded_at, chunks_count)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(filename) DO UPDATE SET
                    filepath=excluded.filepath,
                    uploaded_at=excluded.uploaded_at,
                    chunks_count=excluded.chunks_count
            ''', (filename, filepath, uploaded_at, len(chunks)))
            
            conn.commit()
            conn.close()
            
            return True, {
                "filename": filename,
                "chunks": len(chunks),
                "uploaded_at": uploaded_at
            }
            
        except Exception as e:
            logger.error(f"Failed to process manual upload: {str(e)}")
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except:
                    pass
            return False, f"Failed to ingest manual: {str(e)}"

    @staticmethod
    def get_manuals_list():
        """Returns list of ingested documents from DB."""
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT filename, uploaded_at, chunks_count FROM uploaded_manuals ORDER BY id DESC")
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to fetch manuals list: {str(e)}")
            return []
        finally:
            conn.close()
