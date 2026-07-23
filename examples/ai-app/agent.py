"""Example LangChain agent — DELIBERATELY VULNERABLE.

This file demonstrates the prompt-injection patterns nox detects under
the AI-PI-* rule family. Each function is a textbook anti-pattern.
Don't deploy code that looks like this.
"""

from flask import Flask, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI()


@app.post("/chat")
def chat():
    # AI-PI-001: untrusted source flows into LLM call via f-string.
    user_q = request.json["question"]
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "user", "content": f"Answer this user question: {request.json['question']}"},
        ],
    )
    return response.choices[0].message.content


@app.post("/personalize")
def personalize():
    # AI-PI-002: tainted value flows into the system role — the model
    # is trained to defer to system content, so this inverts the trust
    # boundary entirely.
    persona = request.json["persona"]
    # nox:ignore AGENTFLOW-001,TAINT-AI-001 -- deliberate; safe.py is the fixed form
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": f"You are a {persona} assistant."},
            {"role": "user", "content": "Hello"},
        ],
    )
    return response.choices[0].message.content
