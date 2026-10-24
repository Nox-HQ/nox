const router = require('express').Router();
const { requireSignin } = require('./auth');
const { postByID } = require('./post.controller');
const Post = require('./models/post');
router.param('postId', postByID);
router.get('/posts/:postId', requireSignin, async (req, res) => {
  res.json(await Post.findById(req.params.postId));
});
module.exports = router;
