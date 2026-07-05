# Historical note: an earlier version did cursor.execute("SELECT " + name)
# and called os.system(user_cmd) directly. Both are quoted here as prose in a
# comment, not executed, so no rule should fire on these lines.
def safe():
    return 1
