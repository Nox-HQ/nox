package authz

import "testing"

// Python routes are inventoried like JavaScript ones, and the authentication
// the lead logic already recognises (decorators, Depends() parameters, router
// and include_router dependencies) is recorded as Authn, not as ownership.
func TestPythonRoutesAreInventoriedWithTheirAuthentication(t *testing.T) {
	rs := routesOf(t, map[string]string{
		"flask_api.py": "from flask import Flask, jsonify\nfrom flask_login import login_required\nfrom flask_jwt_extended import jwt_required\nimport db\n" +
			"app = Flask(__name__)\n\n" +
			"@app.route(\"/api/v3/orders/<int:order_id>\")\n@login_required\ndef get_order(order_id):\n    return jsonify(db.query(\"SELECT 1\", (order_id,)))\n\n" +
			"@app.route(\"/api/v3/me\", methods=[\"POST\"])\n@jwt_required()\ndef me():\n    return jsonify({})\n\n" +
			"@app.route(\"/health\")\ndef health():\n    return \"ok\"\n",
		"fastapi_api.py": "from fastapi import FastAPI, APIRouter, Depends\nfrom auth import get_current_user, require_admin, get_db\n" +
			"app = FastAPI()\nrouter = APIRouter(prefix=\"/api/v4\", dependencies=[Depends(get_current_user)])\n\n" +
			"@app.get(\"/api/v4/documents/{doc_id}\")\nasync def read_doc(doc_id: int, user=Depends(get_current_user)):\n    return {}\n\n" +
			"@router.get(\"/reports\")\nasync def reports():\n    return {}\n\n" +
			"@app.get(\"/api/v4/public\")\nasync def public(db=Depends(get_db)):\n    return {}\n\n" +
			"@app.delete(\"/api/v4/admin/{uid}\", dependencies=[Depends(require_admin)])\nasync def drop(uid: int):\n    return {}\n\n" +
			"app.include_router(router)\n",
	})
	type want struct{ authn, authz string }
	wants := map[string]want{
		"GET /api/v3/orders/<int:order_id>": {"login_required", ""},
		"POST /api/v3/me":                   {"jwt_required()", ""},
		"GET /health":                       {"", ""},
		"GET /api/v4/documents/{doc_id}":    {"Depends(get_current_user)", ""},
		"GET /api/v4/reports":               {"Depends(get_current_user)", ""},
		"GET /api/v4/public":                {"", ""},
		"DELETE /api/v4/admin/{uid}":        {"", "Depends(require_admin)"},
	}
	if len(rs) != len(wants) {
		t.Fatalf("got %d routes, want %d: %+v", len(rs), len(wants), rs)
	}
	for _, r := range rs {
		w, ok := wants[r.Method+" "+r.Path]
		if !ok {
			t.Errorf("unexpected route %s %s", r.Method, r.Path)
			continue
		}
		if r.Authn != w.authn || r.Authz != w.authz {
			t.Errorf("%s %s: authn=%q authz=%q, want authn=%q authz=%q", r.Method, r.Path, r.Authn, r.Authz, w.authn, w.authz)
		}
		if r.Line == 0 || r.FilePath == "" {
			t.Errorf("%s %s has no location: %+v", r.Method, r.Path, r)
		}
	}
}
