// True positives: the program IS a shell, so the argv vector is not a shield.
// See tp_shell_argv.py for the reasoning; clean_argv_exec.py is the other half.
const { spawn } = require("child_process");

function run(req) {
  const user = req.query.cmd;
  spawn("sh", ["-c", "git log " + user]); // nox-expect: TAINT-002
}
