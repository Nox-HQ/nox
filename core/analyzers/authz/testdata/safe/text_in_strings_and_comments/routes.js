const router = require('express').Router();
const { requireAuth } = require('./auth');
// router.get('/invoices/:id', requireAuth, (req, res) => Invoice.findById(req.params.id))
const docs = "router.get('/x/:id', requireAuth, (req, res) => X.findById(req.params.id))";
router.get('/health', (req, res) => res.json({ ok: true, docs }));
module.exports = router;
