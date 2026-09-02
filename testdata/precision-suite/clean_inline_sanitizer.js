// Clean: the sanitizer wraps the source on the line that binds it. A finding
// on any line here is a false positive.
const child_process = require('child_process');

function sleepFor(req, res) {
  const n = parseInt(req.query.n);
  child_process.execSync('sleep ' + n);
}

function countTo(req, res) {
  const limit = Number(req.body.limit);
  child_process.exec('seq ' + limit);
}
