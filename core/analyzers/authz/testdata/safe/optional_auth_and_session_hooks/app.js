const express = require('express');
const session = require('express-session');
const passportjs = require('passport');
const auth = require('./auth');
const Article = require('./models/article');
const app = express();
app.use(session({ secret: process.env.SECRET }));
app.use(passportjs.initialize());
app.use(passportjs.session());
app.get('/articles/:articleId', auth.optional, async (req, res) => {
  res.json(await Article.findById(req.params.articleId));
});
