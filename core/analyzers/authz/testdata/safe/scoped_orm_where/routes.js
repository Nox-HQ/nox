const router = require('express').Router();
const { requireAuth } = require('./auth');
const { Invoice } = require('./models');
router.get('/invoices/:id', requireAuth, async (req, res) => {
  const invoice = await Invoice.findOne({ where: { id: req.params.id, userId: req.user.id } });
  if (!invoice) return res.sendStatus(404);
  res.json(invoice);
});
module.exports = router;
