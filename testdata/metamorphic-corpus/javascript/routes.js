const express = require("express");
const { exec } = require("child_process");

const app = express();

app.get("/render", (req, res) => {
  const name = req.query.name;
  res.send("<h1>Hello " + name + "</h1>");
});

app.get("/lookup", (req, res) => {
  const domain = req.query.domain;
  exec("nslookup " + domain, (err, stdout) => {
    res.send(stdout);
  });
});

app.get("/eval", (req, res) => {
  const expr = req.query.expr;
  const result = eval(expr);
  res.json({ result });
});

module.exports = app;
