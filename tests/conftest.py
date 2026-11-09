import os
import tempfile

# Los tests deben ser deterministas y sin red: fija el RAG en TF-IDF puro (desactiva el
# modo automatico que encenderia embeddings/expansion si hay un modelo local levantado).
os.environ.setdefault("BINORACLE_RAG_AUTO", "0")
os.environ.setdefault("BINORACLE_RAG_EMBED", "0")
os.environ.setdefault("BINORACLE_RAG_EXPAND", "0")
os.environ.setdefault("BINORACLE_RAG_RERANK", "0")
# Cache aislada: los tests no escriben en el ~/.cache del usuario.
os.environ.setdefault("BINORACLE_CACHE_DIR", tempfile.mkdtemp(prefix="binoracle-test-"))
