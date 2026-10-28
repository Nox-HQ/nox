const router = require('express').Router();
const { requireAuth } = require('./auth');
const Statement = require('./models/statement');

router.get('/statements/download', requireAuth, async (req, res) => {
  const statement = await Statement.findById(req.query.statementId); // expect: AUTHZ-001
  res.json(statement);
});

module.exports = router;
