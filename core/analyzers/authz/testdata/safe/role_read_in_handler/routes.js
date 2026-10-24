const router = require('express').Router();
const { requireAuth } = require('./auth');
const Ticket = require('./models/ticket');
router.get('/tickets/:id', requireAuth, async (req, res) => {
  const ticket = await Ticket.findById(req.params.id);
  if (req.user.role !== 'support' && String(ticket.requester) !== req.user.id) return res.sendStatus(404);
  res.json(ticket);
});
module.exports = router;
