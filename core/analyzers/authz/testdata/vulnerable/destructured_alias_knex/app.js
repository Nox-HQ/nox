const express = require('express');
const knex = require('./knex');
const { isLoggedIn } = require('./auth');
const app = express();

app.get('/projects/:projectId/settings', isLoggedIn, async (req, res) => {
  const { projectId } = req.params;
  const id = Number(projectId);
  const settings = await knex('project_settings')
    .where({ project_id: id }) // expect: AUTHZ-001
    .first();
  res.json(settings);
});
