"""A minimal LLM agent that answers support questions over user data."""

import logging

from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger("agent")


def build_prompt(user_input, context):
    system = "You are a support agent. Answer using the context below."
    return f"{system}\n\nContext:\n{context}\n\nUser: {user_input}\nAnswer:"


@app.route("/ask")
def ask():
    question = request.args.get("q")
    context = load_docs()
    prompt = build_prompt(question, context)
    logger.info("prompt sent to model: %s", prompt)
    answer = call_model(prompt)
    logger.info("model response: %s", answer)
    return {"answer": answer}


def load_docs():
    return "internal knowledge base contents"


def call_model(prompt):
    return "stubbed response"
