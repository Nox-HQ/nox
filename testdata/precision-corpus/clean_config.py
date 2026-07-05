# Clean sample: safe, idiomatic config loading. Secrets come from the
# environment, prompts use structured message arrays, and no user input
# reaches a code-execution sink. Any finding here is a FALSE POSITIVE.

import os


def openai_key():
    return os.environ["OPENAI_API_KEY"]


def build_messages(user_input):
    return [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": user_input},
    ]
