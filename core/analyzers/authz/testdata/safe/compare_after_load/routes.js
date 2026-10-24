const router = require('express').Router();
const { protect } = require('./auth');
const Order = require('./models/order');
router.get('/orders/:id', protect, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order || order.user.toString() !== req.user._id.toString()) {
    return res.status(404).json({ message: 'Order not found' });
  }
  res.json(order);
});
module.exports = router;
