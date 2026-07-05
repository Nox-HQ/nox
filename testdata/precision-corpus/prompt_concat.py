# True-positive sample: user input concatenated directly into an LLM
# prompt (a classic prompt-injection boundary failure). The scan MUST
# flag the f-string that interpolates user_input into the system prompt.


def build_prompt(user_input):
    prompt = f"You are a helpful assistant. {user_input}"  # nox-expect: AI-002
    return prompt


def build_prompt_format(user_message):
    prompt = "System: stay on task. %s" % user_message  # nox-expect: AI-002
    return prompt
