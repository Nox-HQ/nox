// Example TypeScript frontend chat component. Demonstrates nox's
// JS/TS LLM SDK detection. The model invocation here lands in
// ai.inventory.json alongside the Go API's claude-3-5-sonnet call —
// one polyglot AIBOM, two providers.

import OpenAI from "openai";

const client = new OpenAI({
  // nox:ignore SEC-163 -- reads the key from the environment; this is the correct pattern
  apiKey: process.env.OPENAI_API_KEY,
});

export async function ask(question: string): Promise<string> {
  // nox detects this invocation: openai / gpt-4o on chat.ts:18.
  // auth_env_var = OPENAI_API_KEY is captured automatically.
  const response = await client.chat.completions.create({
    model: "gpt-4o",
    messages: [
      { role: "system", content: "You are a concise assistant." },
      { role: "user", content: question },
    ],
  });

  return response.choices[0]?.message?.content ?? "";
}
