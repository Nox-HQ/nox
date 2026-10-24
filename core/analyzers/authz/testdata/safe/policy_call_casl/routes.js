const router = require('express').Router();
const { requireAuth } = require('./auth');
const { Project } = require('./models');
const { ForbiddenError } = require('@casl/ability');
router.get('/projects/:id', requireAuth, async (req, res) => {
  const project = await Project.findByPk(req.params.id);
  ForbiddenError.from(req.ability).throwUnlessCan('read', project);
  res.json(project);
});
module.exports = router;
