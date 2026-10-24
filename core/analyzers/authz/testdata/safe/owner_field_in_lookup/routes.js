const router = require('express').Router();
const { isAuthorized, appendUserId } = require('./security');
const { AddressModel } = require('./models');
router.get('/addresses/:id', isAuthorized(), appendUserId(), async (req, res) => {
  const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } });
  res.json(address);
});
module.exports = router;
