const router = require('express').Router();
const { requireAuth } = require('./auth');
router.get('/tickets/:ticketId', requireAuth, async (req, res) => {
  const ticket = await req.db.ticket.findUnique({ where: { id: req.params.ticketId } });
  res.json(ticket);
});
module.exports = router;
