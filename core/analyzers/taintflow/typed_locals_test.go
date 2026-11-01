package taintflow

import (
	"slices"
	"testing"
)

// A type annotation on a local is not a different program. For every language
// the engine reads, `id: T = source` must bind taint exactly as `id = source`
// does. Measured 2026-11-01 on v1.55.11: Python `host: str = request.args.get(...)`
// and TypeScript `const host: string = req.query.host` were silent where the
// unannotated line fired, the dominant idiom in typed Python and TypeScript.
//
// Each case is three files. The untyped one guards the premise (the source and
// sink are ones the engine knows), the typed one is the claim, and the typed
// constant shows the typed binding does not fire on its own.
func TestTypedLocalBindsTaintLikeUntyped(t *testing.T) {
	cases := []struct {
		lang, file             string
		untyped, typed, constT string
	}{
		{"python", "app.py",
			"def h():\n    uid = request.args.get(\"id\")\n    cursor.execute(\"SELECT * FROM t WHERE id = \" + uid)\n",
			"def h():\n    uid: str = request.args.get(\"id\")\n    cursor.execute(\"SELECT * FROM t WHERE id = \" + uid)\n",
			"def h():\n    uid: str = \"42\"\n    cursor.execute(\"SELECT * FROM t WHERE id = \" + uid)\n"},
		{"python optional", "app.py",
			"def h():\n    uid = request.args.get(\"id\")\n    cursor.execute(\"SELECT * FROM t WHERE id = \" + uid)\n",
			"def h():\n    uid: Optional[str] = request.args.get(\"id\")\n    cursor.execute(\"SELECT * FROM t WHERE id = \" + uid)\n",
			"def h():\n    uid: Optional[str] = \"42\"\n    cursor.execute(\"SELECT * FROM t WHERE id = \" + uid)\n"},
		{"typescript", "app.ts",
			"app.get('/u', (req, res) => {\n  const id = req.query.id;\n  db.query(\"SELECT * FROM t WHERE id = \" + id);\n});\n",
			"app.get('/u', (req, res) => {\n  const id: string = req.query.id as string;\n  db.query(\"SELECT * FROM t WHERE id = \" + id);\n});\n",
			"app.get('/u', (req, res) => {\n  const id: string = \"42\";\n  db.query(\"SELECT * FROM t WHERE id = \" + id);\n});\n"},
		{"typescript union", "app.ts",
			"app.get('/u', (req, res) => {\n  let id = req.query.id;\n  db.query(\"SELECT * FROM t WHERE id = \" + id);\n});\n",
			"app.get('/u', (req, res) => {\n  let id: string | undefined = req.query.id;\n  db.query(\"SELECT * FROM t WHERE id = \" + id);\n});\n",
			"app.get('/u', (req, res) => {\n  let id: string | undefined = \"42\";\n  db.query(\"SELECT * FROM t WHERE id = \" + id);\n});\n"},
		{"typescript generic", "app.ts",
			"app.get('/u', (req, res) => {\n  const id = req.query.id;\n  db.query(\"SELECT * FROM t WHERE id = \" + id);\n});\n",
			"app.get('/u', (req, res) => {\n  const id: Record<string, string> = req.query.id;\n  db.query(\"SELECT * FROM t WHERE id = \" + id);\n});\n",
			"app.get('/u', (req, res) => {\n  const id: Record<string, string> = \"42\";\n  db.query(\"SELECT * FROM t WHERE id = \" + id);\n});\n"},
		{"kotlin", "App.kt",
			"fun h(request: HttpServletRequest, conn: Connection) {\n    val id = request.getParameter(\"id\")\n    conn.createStatement().executeQuery(\"SELECT * FROM t WHERE id = \" + id)\n}\n",
			"fun h(request: HttpServletRequest, conn: Connection) {\n    val id: String = request.getParameter(\"id\")\n    conn.createStatement().executeQuery(\"SELECT * FROM t WHERE id = \" + id)\n}\n",
			"fun h(request: HttpServletRequest, conn: Connection) {\n    val id: String = \"42\"\n    conn.createStatement().executeQuery(\"SELECT * FROM t WHERE id = \" + id)\n}\n"},
		{"swift", "App.swift",
			"func h(_ req: Request, db: OpaquePointer) throws {\n    let id = req.query[\"id\"] ?? \"\"\n    sqlite3_exec(db, \"SELECT * FROM t WHERE id = \" + id, nil, nil, nil)\n}\n",
			"func h(_ req: Request, db: OpaquePointer) throws {\n    let id: String = req.query[\"id\"] ?? \"\"\n    sqlite3_exec(db, \"SELECT * FROM t WHERE id = \" + id, nil, nil, nil)\n}\n",
			"func h(_ req: Request, db: OpaquePointer) throws {\n    let id: String = \"42\"\n    sqlite3_exec(db, \"SELECT * FROM t WHERE id = \" + id, nil, nil, nil)\n}\n"},
		{"rust", "main.rs",
			"async fn h(q: web::Query<String>, pool: sqlx::PgPool) {\n    let id = q.into_inner();\n    sqlx::query(&format!(\"SELECT * FROM t WHERE id = {}\", id)).execute(&pool).await;\n}\n",
			"async fn h(q: web::Query<String>, pool: sqlx::PgPool) {\n    let id: String = q.into_inner();\n    sqlx::query(&format!(\"SELECT * FROM t WHERE id = {}\", id)).execute(&pool).await;\n}\n",
			"async fn h(q: web::Query<String>, pool: sqlx::PgPool) {\n    let id: String = String::from(\"42\");\n    sqlx::query(&format!(\"SELECT * FROM t WHERE id = {}\", id)).execute(&pool).await;\n}\n"},
		{"go", "main.go",
			"package main\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tid := r.URL.Query().Get(\"id\")\n\tdb.Query(\"SELECT * FROM t WHERE id = \" + id)\n}\n",
			"package main\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tvar id string = r.URL.Query().Get(\"id\")\n\tdb.Query(\"SELECT * FROM t WHERE id = \" + id)\n}\n",
			"package main\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tvar id string = \"42\"\n\tdb.Query(\"SELECT * FROM t WHERE id = \" + id)\n}\n"},
		{"csharp", "App.cs",
			"public class C : Controller {\n  public void Sql() {\n    var id = Request.Query[\"id\"];\n    var cmd = new SqlCommand(\"SELECT * FROM t WHERE id = \" + id);\n    cmd.ExecuteReader();\n  }\n}\n",
			"public class C : Controller {\n  public void Sql() {\n    string id = Request.Query[\"id\"];\n    var cmd = new SqlCommand(\"SELECT * FROM t WHERE id = \" + id);\n    cmd.ExecuteReader();\n  }\n}\n",
			"public class C : Controller {\n  public void Sql() {\n    string id = \"42\";\n    var cmd = new SqlCommand(\"SELECT * FROM t WHERE id = \" + id);\n    cmd.ExecuteReader();\n  }\n}\n"},
	}
	for _, c := range cases {
		t.Run(c.lang, func(t *testing.T) {
			if !slices.Contains(scan(t, writeArtifact(t, t.TempDir(), c.file, c.untyped)), "TAINT-001") {
				t.Fatalf("premise: the untyped flow does not fire, so this case tests nothing:\n%s", c.untyped)
			}
			if !slices.Contains(scan(t, writeArtifact(t, t.TempDir(), c.file, c.typed)), "TAINT-001") {
				t.Errorf("annotating the local lost the taint:\n%s", c.typed)
			}
			if ids := scan(t, writeArtifact(t, t.TempDir(), c.file, c.constT)); slices.Contains(ids, "TAINT-001") {
				t.Errorf("a typed constant fired %v:\n%s", ids, c.constT)
			}
		})
	}
}
