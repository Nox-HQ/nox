"""Example RAG ingest pipeline — DELIBERATELY VULNERABLE.

Demonstrates AI-EMBED-* family findings. Embedding secrets or raw
HTTP bodies into a vector store is a permanent exfiltration path —
once written, the data persists in retrieval results forever.
"""

import os
import openai
import pinecone
from flask import request

client = openai.OpenAI()
index = pinecone.Index("production")


def ingest_record():
    # AI-EMBED-001: embedding sink consumes a literal secret env var.
    # The secret becomes part of the vector and cannot be selectively
    # forgotten without re-indexing the entire collection.
    embedding = client.embeddings.create(
        model="text-embedding-3-small",
        input=os.getenv("STRIPE_SECRET"),
    )
    index.upsert(vectors=[{"id": "stripe", "values": embedding.data[0].embedding}])


def ingest_request():
    # AI-EMBED-003: vector DB write receives raw HTTP request body
    # without filtering — the entire untrusted payload, including any
    # PII or attacker-controlled content, lands in retrieval.
    embedding = client.embeddings.create(
        model="text-embedding-3-small",
        input=str(request.json),
    )
    index.upsert(
        vectors=[{"id": "req", "values": embedding.data[0].embedding}]
    )
