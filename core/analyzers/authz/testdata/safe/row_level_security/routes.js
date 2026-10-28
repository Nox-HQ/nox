const router = require('express').Router();
const { requireAuth } = require('./auth');
const db = require('./db');
router.get('/notes/:id', requireAuth, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM notes WHERE id = $1', [req.params.id]);
  res.json(rows[0]);
});
module.exports = router;
