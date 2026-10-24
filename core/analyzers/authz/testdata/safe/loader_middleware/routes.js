const router = require('express').Router();
const { requireAuth } = require('./auth');
const { loadInvoiceForUser } = require('./loaders');
const Invoice = require('./models/invoice');
router.put('/invoices/:id', requireAuth, loadInvoiceForUser, async (req, res) => {
  const invoice = await Invoice.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(invoice);
});
module.exports = router;
