const router = require('express').Router();
const { requireAuth } = require('./auth');
const Article = require('./models/article');
router.get('/articles/:slug', requireAuth, async (req, res) => {
  res.json(await Article.findOne({ slug: req.params.slug }));
});
module.exports = router;
