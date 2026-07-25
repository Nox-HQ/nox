"""Same shape as agent.py / ingest.py / tools.py but without the
findings. This is what the operator's code should look like after
nox flags the issues.
"""

import os
from flask import Flask, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI()


@app.post("/chat")
def chat():
    # User input stays in the user role; system content is static. nox models
    # role placement, so this recommended pattern is not flagged (no waiver needed).
    user_q = request.json.get("question", "")
    if len(user_q) > 4000:
        return {"error": "input too long"}, 400
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "Answer the user's question concisely."},
            {"role": "user", "content": user_q},
        ],
    )
    return response.choices[0].message.content


def ingest_record_safe():
    # Embed only the data the retrieval pipeline needs. Never the
    # credential that protects the upstream system.
    payload = request.json.get("text", "")
    if not payload:
        return
    api_key = os.environ["STRIPE_SECRET"]  # used by stripe SDK, not embedded
    # ... fetch records from stripe using api_key ...
    sanitized = redact_pii(payload)  # imagined helper
    # nox:ignore TAINT-AI-002 -- input passes redact_pii(); an illustrative sanitiser nox cannot verify
    embedding = client.embeddings.create(
        model="text-embedding-3-small", input=sanitized,
    )
    # ... upsert ...


def redact_pii(text: str) -> str:
    return text  # placeholder
