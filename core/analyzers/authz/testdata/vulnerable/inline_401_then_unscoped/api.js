const express = require('express');
const db = require('./db');
const app = express();

app.get('/api/messages/:messageId', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'unauthorized' });
  const message = await db.Message.findByPk(req.params.messageId); // expect: AUTHZ-001
  res.json(message);
});
