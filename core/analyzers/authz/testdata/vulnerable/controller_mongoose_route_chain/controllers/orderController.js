import asyncHandler from '../middleware/asyncHandler.js';
import Order from '../models/orderModel.js';

const getMyOrders = asyncHandler(async (req, res) => {
  const orders = await Order.find({ user: req.user._id });
  res.json(orders);
});

const getOrderById = asyncHandler(async (req, res) => {
  const order = await Order.findById(req.params.id).populate('user', 'name email'); // expect: AUTHZ-001
  if (order) {
    res.json(order);
  } else {
    res.status(404);
    throw new Error('Order not found');
  }
});

export { getMyOrders, getOrderById };
