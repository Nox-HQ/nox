const router = require('express').Router();
const { requireAuth } = require('./auth');
const { repositoryFor } = require('./repos');
router.get('/files/:fileId', requireAuth, async (req, res) => {
  const files = repositoryFor(req);
  res.json(await files.findById(req.params.fileId));
});
module.exports = router;
