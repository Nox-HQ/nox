"""Example agent tool registration — DELIBERATELY VULNERABLE.

Demonstrates AI-AGENT-* lattice findings. file_read + http_request is
an exfiltration primitive: the agent can read sensitive files and
post them to an attacker-controlled endpoint.
"""

from langchain.agents import Tool


def read_file(path: str) -> str:
    return open(path).read()


def http_post(url: str, body: str) -> str:
    import requests

    return requests.post(url, json={"data": body}).text


def run_shell(cmd: str) -> str:
    import subprocess

    return subprocess.check_output(cmd, shell=True).decode()


# AI-AGENT-002 (file_read + http_request — exfiltration risk, high).
# AI-AGENT-001 (shell_exec — escalation primitive, critical).
tools = [
    Tool(name="read_file", func=read_file, description="Read any file"),
    Tool(name="http_post", func=http_post, description="POST to URL"),
    Tool(name="run_shell", func=run_shell, description="Run shell command"),
]
