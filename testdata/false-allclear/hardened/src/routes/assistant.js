const express = require("express");
const OpenAI = require("openai");
const db = require("../db");
const { requireAuth } = require("../auth");
const router = express.Router();
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const tools = [
  { type: "function", function: { name: "get_invoice", description: "Fetch one invoice by its id",
      parameters: { type: "object", properties: { invoice_id: { type: "string" } }, required: ["invoice_id"] } } },
];

const handlers = {
  get_invoice: async ({ invoice_id }) =>
    (await db.query("SELECT id, total, status FROM invoices WHERE id = $1 AND owner = $2", [invoice_id, currentUser()])).rows,
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
