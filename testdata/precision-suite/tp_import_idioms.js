// True positives for the ordinary Node import idioms.
//
// The corpus tested only `const child_process = require("child_process")` — the
// one shape where the local name equals the module name. A destructured require
// and an ESM import are how Node is normally written, and both were silently
// missed. Four of five idioms produced nothing before import resolution landed.
const { exec } = require("child_process");
const cp = require("child_process");

function destructuredRequire(req) {
  const user = req.query.cmd;
  exec("sh -c " + user); // nox-expect: TAINT-002
}

function aliasedRequire(req) {
  const user = req.query.cmd;
  cp.exec("sh -c " + user); // nox-expect: TAINT-002
}
