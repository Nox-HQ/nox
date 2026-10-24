const router = require('express').Router();
const User = require('../models/user');
const { verifyToken } = require('../middleware/jwt');

router.post('/profile/update', verifyToken, async (req, res) => {
  const user = await User.findByIdAndUpdate(req.body.userId, { bio: req.body.bio }, { new: true }); // expect: AUTHZ-001
  res.json(user);
});

module.exports = router;
