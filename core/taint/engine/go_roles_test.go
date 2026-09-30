package engine

import (
	"strings"
	"testing"
)

// goCase is one Go source under the full same-file pipeline and the rule IDs it
// must report (nil: none).
type goCase struct {
	name string
	src  string
	want []string
}

func runGoCases(t *testing.T, cases []goCase) {
	t.Helper()
	for _, c := range cases {
		got := analyzeGoFile(t, c.src)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

const goImports = "package h\n\nimport (\n\t\"database/sql\"\n\t\"net/http\"\n\t\"os/exec\"\n)\n\n"

// TestGoReceiverRoles: sources and sinks match by declared type, not by the
// variable happening to be named r, db or w.
func TestGoReceiverRoles(t *testing.T) {
	runGoCases(t, []goCase{
		{"request and db under other names", goImports + `func h(resp http.ResponseWriter, req *http.Request, conn *sql.DB) {
	id := req.URL.Query().Get("id")
	conn.Query("SELECT * FROM t WHERE id = '" + id + "'")
}`, []string{"TAINT-001"}},
		{"sql.Open result is a db", goImports + `func h(w http.ResponseWriter, req *http.Request) {
	store, _ := sql.Open("mysql", dsn)
	store.Exec("DELETE FROM t WHERE id = " + req.FormValue("id"))
}`, []string{"TAINT-001"}},
		{"package-level db", goImports + `var store *sql.DB

func h(w http.ResponseWriter, req *http.Request) {
	id := req.Header.Get("X-Id")
	store.Query("SELECT " + id)
}`, []string{"TAINT-001"}},
		{"beego controller", goImports + `type Ctl struct {
	web.Controller
}

func (c *Ctl) Post() {
	p := c.Ctx.Request.Header.Get("X")
	q := c.GetString("q")
	exec.Command("sh", "-c", "ls "+p).Run()
	db, _ := sql.Open("mysql", dsn)
	db.Query("SELECT " + q)
}`, []string{"TAINT-001", "TAINT-002"}},
		{"gin handler", goImports + `func h(c *gin.Context, conn *sql.DB) {
	conn.Query("SELECT " + c.Query("id"))
}`, []string{"TAINT-001"}},
		{"echo handler", goImports + `func h(c echo.Context, conn *sql.DB) error {
	id := c.QueryParam("id")
	conn.Query("SELECT " + id)
	return nil
}`, []string{"TAINT-001"}},
		{"alias of the beego response writer", goImports + `type Ctl struct {
	beego.Controller
}

func (c *Ctl) Get() {
	out := c.Ctx.ResponseWriter
	name := c.GetString("name")
	out.Write([]byte(name))
}`, []string{"TAINT-003"}},
		{"a request-named variable of another type stays unknown", goImports + `func h(req *Thing, conn *sql.DB) {
	conn.Query("SELECT " + req.URL.Query().Get("id"))
}`, nil},
		{"cookies ranged over", goImports + `func h(w http.ResponseWriter, req *http.Request, conn *sql.DB) {
	v := "none"
	for _, ck := range req.Cookies() {
		if ck.Name == "sid" {
			v = ck.Value
		}
	}
	conn.Query("SELECT " + v)
}`, []string{"TAINT-001"}},
	})
}

// TestGoBranchModel: branch bodies are weak updates, constant conditions are
// resolved, and an assignment every arm makes is definite.
func TestGoBranchModel(t *testing.T) {
	runGoCases(t, []goCase{
		{"one arm may overwrite", goImports + `func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	p := r.FormValue("id")
	if len(p) > 3 {
		p = "safe"
	}
	db.Query("SELECT " + p)
}`, []string{"TAINT-001"}},
		{"both arms overwrite", goImports + `func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	p := r.FormValue("id")
	if len(p) > 3 {
		p = "a"
	} else {
		p = "b"
	}
	db.Query("SELECT " + p)
}`, nil},
		{"constant condition takes the safe arm", goImports + `func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	p := r.FormValue("id")
	bar := p
	num := 86
	if (7*42)-num > 200 {
		bar = "safe"
	}
	db.Query("SELECT " + bar)
}`, nil},
		{"constant condition takes the tainted arm", goImports + `func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	p := r.FormValue("id")
	bar := "safe"
	num := 106
	if (7*18)-num > 200 {
		bar = "no"
	} else {
		bar = p
	}
	db.Query("SELECT " + bar)
}`, []string{"TAINT-001"}},
		{"constant switch on a string byte", goImports + `func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	p := r.FormValue("id")
	guess := "ABC"
	var bar string
	switch guess[1] {
	case 'A':
		bar = p
	case 'B':
		bar = "bob"
	default:
		bar = p
	}
	db.Query("SELECT " + bar)
}`, nil},
		{"a non-constant local keeps the condition unknown", goImports + `func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	p := r.FormValue("id")
	num := 86
	num = len(p)
	bar := p
	if num > 200 {
		bar = "safe"
	}
	db.Query("SELECT " + bar)
}`, []string{"TAINT-001"}},
	})
}

// TestGoMethodSummaryBinding: a method's summary binds the call's positional
// arguments to its parameters; the receiver is not one of them.
func TestGoMethodSummaryBinding(t *testing.T) {
	helper := `type T struct{}

func (t *T) pick(param string) string {
	bar := ""
	num := 106
	if (7*18)+num > 200 {
		bar = "safe"
	} else {
		bar = param
	}
	return bar
}

func (t *T) pass(param string) string { return param }

`
	runGoCases(t, []goCase{
		{"method returning a constant", goImports + helper + `func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	bar := new(T).pick(r.FormValue("id"))
	db.Query("SELECT " + bar)
}`, nil},
		{"method returning its argument", goImports + helper + `func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	bar := new(T).pass(r.FormValue("id"))
	db.Query("SELECT " + bar)
}`, []string{"TAINT-001"}},
	})
}

// TestGoRawWriteShapes: a string written as bytes is reflected output; bytes
// that are already bytes (command output) stay gated.
func TestGoRawWriteShapes(t *testing.T) {
	runGoCases(t, []goCase{
		{"string converted and written", goImports + `func h(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	w.Write([]byte(name))
}`, []string{"TAINT-003"}},
		{"escaped first", goImports + `func h(w http.ResponseWriter, r *http.Request) {
	name := html.EscapeString(r.FormValue("name"))
	w.Write([]byte(name))
}`, nil},
		{"command output written", goImports + `func h(w http.ResponseWriter, r *http.Request) {
	out, _ := exec.Command("ls", r.FormValue("dir")).Output()
	w.Write(out)
}`, nil},
	})
}

// TestGoSliceLiteralElements: constant reads of a slice literal resolve to the
// element they name; anything the model cannot follow stays container-level.
func TestGoSliceLiteralElements(t *testing.T) {
	runGoCases(t, []goCase{
		{"re-sliced, then a safe element", goImports + `func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	p := r.FormValue("id")
	bar := "alsosafe"
	if p != "" {
		valuesList := []string{"safe", p, "moresafe"}
		valuesList = valuesList[1:]
		bar = valuesList[1]
	}
	db.Query("SELECT " + bar)
}`, nil},
		{"re-sliced, then the tainted element", goImports + `func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	p := r.FormValue("id")
	valuesList := []string{"safe", p, "moresafe"}
	valuesList = valuesList[1:]
	bar := valuesList[0]
	db.Query("SELECT " + bar)
}`, []string{"TAINT-001"}},
		{"appended element", goImports + `func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	p := r.FormValue("id")
	parts := []string{"a"}
	parts = append(parts, p)
	db.Query("SELECT " + parts[1])
}`, []string{"TAINT-001"}},
		{"variable index stays container-level", goImports + `func h(w http.ResponseWriter, r *http.Request, db *sql.DB, i int) {
	p := r.FormValue("id")
	parts := []string{"a", p}
	db.Query("SELECT " + parts[i])
}`, []string{"TAINT-001"}},
		{"passed on whole stays container-level", goImports + `func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	p := r.FormValue("id")
	parts := []string{"a", p}
	s := strings.Join(parts, ",")
	db.Query("SELECT " + parts[0] + s)
}`, []string{"TAINT-001"}},
	})
}

// TestGoFileSinksAndMapKeys covers the file-system sinks and ranging over the
// keys of a request map.
func TestGoFileSinksAndMapKeys(t *testing.T) {
	runGoCases(t, []goCase{
		{"os.Create of a request path", goImports + `func h(w http.ResponseWriter, r *http.Request) {
	os.Create("/data/" + r.FormValue("name"))
}`, []string{"TAINT-004"}},
		{"ServeFile with a constant name", goImports + `func h(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/index.html")
}`, nil},
		{"ServeFile with a request name", goImports + `func h(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("f")
	http.ServeFile(w, r, name)
}`, []string{"TAINT-004"}},
		{"query parameter names", goImports + `func h(w http.ResponseWriter, r *http.Request) {
	names := r.URL.Query()
	p := ""
	for name, values := range names {
		if len(values) > 0 {
			p = name
		}
	}
	os.Open(p)
}`, []string{"TAINT-004"}},
		{"slice index keys are not bound", goImports + `func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	parts := strings.Split(r.FormValue("ids"), ",")
	for i := range parts {
		db.Query("SELECT * FROM t LIMIT " + strconv.Itoa(i))
	}
}`, nil},
	})
}
