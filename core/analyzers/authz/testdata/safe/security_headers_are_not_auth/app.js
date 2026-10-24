const express = require('express');
const helmet = require('helmet');
const csrf = require('csurf');
const Invoice = require('./models/invoice');
const app = express();
app.use(helmet.frameguard());
app.use(csrf({ cookie: true }));
app.get('/invoices/:id', async (req, res) => {
  res.json(await Invoice.findById(req.params.id));
});
