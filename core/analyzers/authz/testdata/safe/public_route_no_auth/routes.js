const router = require('express').Router();
const Product = require('./models/product');
router.get('/products/:id', async (req, res) => {
  res.json(await Product.findById(req.params.id));
});
module.exports = router;
