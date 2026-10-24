const router = require('express').Router();
const { authenticate } = require('./auth');
const { ItemsService } = require('./services/items');
router.get('/items/:pk', authenticate, async (req, res) => {
  const service = new ItemsService({ accountability: req.accountability });
  res.json(await service.readOne(req.params.pk));
});
module.exports = router;
