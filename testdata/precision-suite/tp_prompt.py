def build(user_input, system_prompt):
    prompt = f"{system_prompt}\nUser said: {user_input}"  # nox-expect: AI-002
    return prompt + user_input
