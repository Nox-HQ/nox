const router = require('express').Router();
const { protect } = require('./auth');
const Post = require('./models/post');
router.delete('/posts/:postId', protect, async (req, res) => {
  const post = await Post.findById(req.params.postId);
  if (!post.author.equals(req.user._id)) return res.sendStatus(404);
  await post.deleteOne();
  res.sendStatus(204);
});
module.exports = router;
