import os
import zipfile
import xml.etree.ElementTree as ET
import re
from backend.utils.logger import logger

PYPDF_AVAILABLE = False
try:
    import pypdf
    PYPDF_AVAILABLE = True
except ImportError:
    try:
        import PyPDF2 as pypdf
        PYPDF_AVAILABLE = True
    except ImportError:
        pass

class DocumentLoader:
    @staticmethod
    def extract_text(filepath):
        """Extracts plain text from PDF, DOCX, TXT, or MD files."""
        ext = filepath.rsplit('.', 1)[1].lower() if '.' in filepath else ''
        
        if ext in ['txt', 'md', 'markdown']:
            return DocumentLoader._read_txt(filepath)
        elif ext == 'docx':
            return DocumentLoader._read_docx(filepath)
        elif ext == 'pdf':
            return DocumentLoader._read_pdf(filepath)
        else:
            raise ValueError(f"Unsupported file format: {ext}")

    @staticmethod
    def chunk_text(text, chunk_size=800, overlap=150):
        """
        Splits long document text into overlapping segments (chunks)
        for semantic embeddings injection.
        """
        if not text:
            return []
            
        chunks = []
        start = 0
        text_len = len(text)
        
        while start < text_len:
            end = min(start + chunk_size, text_len)
            chunk = text[start:end]
            chunks.append(chunk.strip())
            
            # Slide start index by chunk_size - overlap
            start += (chunk_size - overlap)
            
        return chunks

    @staticmethod
    def _read_txt(filepath):
        """Reads plain text file."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read TXT file {filepath}: {str(e)}")
            raise e

    @staticmethod
    def _read_docx(filepath):
        """
        Extracts paragraphs text from DOCX file using Python's built-in zipfile 
        and XML parsers. Requires zero external dependencies.
        """
        try:
            paragraphs = []
            with zipfile.ZipFile(filepath) as docx:
                # DOCX standard stores XML paragraphs under word/document.xml
                xml_content = docx.read('word/document.xml')
                root = ET.fromstring(xml_content)
                
                # Namespace tags mappings
                namespaces = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
                for paragraph in root.findall('.//w:p', namespaces):
                    texts = [node.text for node in paragraph.findall('.//w:t', namespaces) if node.text]
                    if texts:
                        paragraphs.append("".join(texts))
                        
            return "\n".join(paragraphs)
        except Exception as e:
            logger.error(f"Failed to extract DOCX text: {str(e)}")
            raise e

    @staticmethod
    def _read_pdf(filepath):
        """Extracts text from PDF. Uses pypdf if installed, otherwise basic text extraction."""
        if PYPDF_AVAILABLE:
            try:
                text_content = []
                with open(filepath, 'rb') as f:
                    reader = pypdf.PdfReader(f)
                    for page in reader.pages:
                        extracted = page.extract_text()
                        if extracted:
                            text_content.append(extracted)
                return "\n".join(text_content)
            except Exception as e:
                logger.error(f"PyPDF loader failed on {filepath}: {str(e)}")
                # Continue to regex fallback
        
        # Pure Python Regex Stream Fallback
        return DocumentLoader._pdf_regex_fallback(filepath)

    @staticmethod
    def _pdf_regex_fallback(filepath):
        """
        Pure Python fallback to extract ASCII text streams from PDF files.
        Resilient backup when no PyPDF binaries are available.
        """
        try:
            text_runs = []
            with open(filepath, 'rb') as f:
                content = f.read()
                
            # PDFs store page contents in /Filter /FlateDecode streams or plain text parentheses blocks
            # Find elements enclosed in parentheses inside streams
            # Standard PDF text block is BT (Begin Text) -> ET (End Text)
            # Text strings are defined within parentheses, e.g., (Hello World) Tj
            stream_blocks = re.findall(rb'BT\s+.*?\s+ET', content, re.DOTALL)
            
            for block in stream_blocks:
                strings = re.findall(rb'\((.*?)\)', block)
                for s in strings:
                    try:
                        text_runs.append(s.decode('ascii', errors='ignore'))
                    except:
                        pass
                        
            if text_runs:
                return " ".join(text_runs)
            
            # Simple file bytes decode fallback
            return content.decode('ascii', errors='ignore')
        except Exception as e:
            logger.error(f"PDF regex fallback loader failed: {str(e)}")
            raise RuntimeError("PDF parser failed. Please run: pip install pypdf")
