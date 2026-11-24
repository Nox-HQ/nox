package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// Python mass assignment: the whole request mapping merged into a dict or an
// object, splatted into a constructor or ORM call, or iterated into setattr
// with names the client chose.
func TestMassAssignmentPython(t *testing.T) {
	flask := "from flask import request\n\n"
	django := "import json\n\n"
	cases := []struct {
		name, src string
		want      bool
	}{
		{"dict update from the JSON body", django + "def v(request):\n    payload = json.loads(request.body.decode('utf-8') or '{}')\n    workset = {'role': 'viewer'}\n    workset.update(payload)\n", true},
		{"POST dict into an update", django + "def v(request):\n    data = request.POST.dict()\n    profile.update(data)\n", true},
		{"model constructed from the JSON", flask + "def v():\n    data = request.get_json()\n    user = User(**data)\n", true},
		{"ORM create from the form inline", django + "def v(request):\n    Profile.objects.create(**request.POST.dict())\n", true},
		{"object dict updated", flask + "def v():\n    current_user.__dict__.update(request.json)\n", true},
		{"setattr with request names", flask + "def v():\n    for key, value in request.json.items():\n        setattr(user, key, value)\n", true},
		{"setattr over a parsed body", django + "def v(request):\n    data = json.loads(request.body)\n    for k, v in data.items():\n        setattr(obj, k, v)\n", true},
		// Not mass assignment.
		{"setattr over a validated model dump", "from fastapi import APIRouter\n\n@router.put(\"/x\")\ndef upd(payload: LeaseIn):\n    data = payload.model_dump(exclude_unset=True)\n    for field, value in data.items():\n        setattr(lease, field, value)\n", false},
		{"a field read by name", flask + "def v():\n    data = request.get_json()\n    user = User(name=data['name'])\n", false},
		{"a dict of chosen fields", django + "def v(request):\n    payload = json.loads(request.body)\n    workset.update({'name': payload['name']})\n", false},
		{"setattr with a fixed name", flask + "def v():\n    name = request.json['name']\n    setattr(user, 'name', name)\n", false},
		{"one value splatted from config", flask + "def v():\n    opts = load_options()\n    client = Client(**opts)\n", false},
	}
	for _, c := range cases {
		if got := slices.Contains(analyzeRuleIDs(t, "views.py", lexctx.LangPython, c.src), "TAINT-014"); got != c.want {
			t.Errorf("%s: TAINT-014 reported=%v, want %v", c.name, got, c.want)
		}
	}
}

// A Python for loop binds its target names from the iterated value. It bound
// nothing, so a request value iterated into a sink was never tainted.
func TestPythonForLoopBindsItsTargets(t *testing.T) {
	src := "import os\nfrom flask import request\n\ndef v():\n    for name in request.args.getlist('f'):\n        os.system('cat ' + name)\n"
	if !slices.Contains(analyzeRuleIDs(t, "views.py", lexctx.LangPython, src), "TAINT-002") {
		t.Errorf("single target: the iterated request value reached no sink")
	}
	src = "import os\nfrom flask import request\n\ndef v():\n    for (k, v) in request.args.items():\n        os.system('echo ' + v)\n"
	if !slices.Contains(analyzeRuleIDs(t, "views.py", lexctx.LangPython, src), "TAINT-002") {
		t.Errorf("tuple target: the iterated request value reached no sink")
	}
	src = "import os\n\ndef v():\n    for name in ['a', 'b']:\n        os.system('cat ' + name)\n"
	if slices.Contains(analyzeRuleIDs(t, "views.py", lexctx.LangPython, src), "TAINT-002") {
		t.Errorf("a fixed list was reported")
	}
}
