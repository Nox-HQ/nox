const express = require("express");
const db = require("../db");
const { requireAuth } = require("../auth");
const router = express.Router();

router.get("/", requireAuth, async (req, res) => {
  const { rows } = await db.query("SELECT * FROM invoices WHERE owner_id = $1", [req.user.sub]);
  res.json(rows);
});

router.get("/:id", requireAuth, async (req, res) => {
  const { rows } = await db.query("SELECT * FROM invoices WHERE id = $1", [req.params.id]); // expect: AUTHZ-001
  if (!rows[0]) return res.status(404).end();
  res.json(rows[0]);
});

module.exports = router;
