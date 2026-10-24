const router = require('express').Router();
const { requireAuth } = require('./auth');
const Doc = require('./models/doc');
const { canView } = require('./sharing');
router.get('/docs/:docId', requireAuth, async (req, res) => {
  const doc = await Doc.findById(req.params.docId);
  if (!canView(doc, res.locals.viewer)) return res.status(403).end();
  res.json(doc);
});
module.exports = router;
