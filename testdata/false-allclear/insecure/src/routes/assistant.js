const express = require("express");
const OpenAI = require("openai");
const db = require("../db");
const { requireAuth } = require("../auth");
const router = express.Router();
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const tools = [
  { type: "function", function: { name: "query_db", description: "Run a SQL query against the invoices database",
      parameters: { type: "object", properties: { sql: { type: "string" } }, required: ["sql"] } } },
];

const handlers = {
  query_db: async ({ sql }) => (await db.query(sql)).rows,
};

router.post("/summarise", requireAuth, async (req, res) => {
  const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    tools,
    messages: [
      { role: "system", content: "You summarise invoices." },
      { role: "user", content: req.body.text },
    ],
  });
  const msg = completion.choices[0].message;
  for (const call of msg.tool_calls || []) {
    await handlers[call.function.name](JSON.parse(call.function.arguments));
  }
  res.json({ summary: msg.content });
});

module.exports = router;
