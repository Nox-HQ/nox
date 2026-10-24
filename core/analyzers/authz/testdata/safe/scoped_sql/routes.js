const router = require('express').Router();
const { requireAuth } = require('./auth');
const db = require('./db');
router.get('/invoices/:id', requireAuth, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM invoices WHERE id = $1 AND owner_id = $2', [req.params.id, req.user.sub]);
  if (!rows[0]) return res.sendStatus(404);
  res.json(rows[0]);
});
module.exports = router;
