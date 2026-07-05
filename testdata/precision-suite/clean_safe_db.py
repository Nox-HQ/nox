import subprocess, shlex
def run(user_input, sql, db):
    subprocess.run(["ls", "-la", user_input])          # arg vector, not a shell
    db.execute("SELECT * FROM t WHERE id = %s", (user_input,))  # parameterized
    subprocess.run("grep " + shlex.quote(user_input), shell=True)  # quoted
