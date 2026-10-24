const router = require('express').Router();
const { requireAuth, requireRole } = require('./auth');
const User = require('./models/user');
router.get('/admin/users/:userId', requireAuth, requireRole('admin'), async (req, res) => {
  res.json(await User.findById(req.params.userId));
});
module.exports = router;
