const router = require('express').Router();
const { requireAuth } = require('./auth');
const invoiceService = require('./services/invoices');
router.get('/invoices/:id', requireAuth, async (req, res) => {
  res.json(await invoiceService.getInvoice(req.params.id, req.user.id));
});
module.exports = router;
