# Server-side template injection: user input concatenated into a rendered
# template. nox catches this via the VARIANT-005 signature (dynamic template
# string), so it is a true positive — but see the density view: it should fire
# exactly once here.
from flask import render_template_string  # nox-expect: SLOP-001
def greet(request):
    name = request.args.get("name")
    return render_template_string("<h1>Hello " + name + "</h1>")  # nox-expect: VARIANT-005
