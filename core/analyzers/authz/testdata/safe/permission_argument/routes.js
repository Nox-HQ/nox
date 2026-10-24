const router = require('express').Router();
const auth = require('./middlewares/auth');
const userService = require('./services/user');
router.route('/:userId').get(auth('getUsers'), async (req, res) => {
  res.send(await userService.getUserById(req.params.userId));
});
module.exports = router;
